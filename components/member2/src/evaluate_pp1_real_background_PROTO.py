#!/usr/bin/env python3
"""Read-only batch scoring of collected CloudTrail background activity.

Do not convert source rows to verified benign without independent provenance.
Uses the frozen PP1 four-model checkpoint and EXACT training feature routines.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from infer_pp1_cloudtrail import load_models, training_provenance, MODEL_NAMES
from train_pp1_binary_stack import FEATURES, MAX_SEQ, SEQ_DIM, featureize_group, pad_sequences, lstm_predict

CSV_COLS = [
    'window_id', 'window_start_utc', 'actor_hash', 'actor_grouping',
    'event_count', 'first_event_time', 'last_event_time', 'api_operations',
    'aws_services', 'unique_api_count', 'error_count', 'write_count',
    'score_rf', 'score_lightgbm', 'score_xgboost', 'score_lstm',
    'stacking_score', 'predicted_binary', 'predicted_activity',
    'source_ground_truth', 'model_score_scope'
]


def utc(raw):
    value = datetime.fromisoformat(str(raw).replace('Z', '+00:00'))
    if value.tzinfo is None:
        raise ValueError('Event timestamp has no timezone')
    return value.astimezone(timezone.utc)


def is_readonly(raw):
    raw = str(raw).strip().lower()
    if raw in ('1', 'true'):
        return 'true'
    if raw in ('0', 'false'):
        return 'false'
    raise ValueError('Missing or invalid read_only value; refusing to guess')


def validate_background_row(r, n):
    fields = ('event_time','event_name','event_source','source_ip_address','read_only','aws_region')
    missing = [x for x in fields if not str(r.get(x,'')).strip()]
    if missing:
        raise ValueError(f'Row {n} missing required fields: {missing}')
    if r.get('label_binary','').strip() not in ('','-1'):
        raise ValueError(f'Row {n} carries a label; this pipeline only handles unlabeled background')
    if r.get('ground_truth_status','unlabeled').strip().lower() not in ('','unlabeled','unverified'):
        raise ValueError(f'Row {n} has a ground-truth status outside unlabeled/unverified')
    if r.get('exclude_from_training','1').strip() not in ('1','true','True'):
        raise ValueError(f'Row {n} is unexpectedly marked usable for training')
    if r.get('review_bucket','background_candidate_unverified') not in ('','background_candidate_unverified'):
        raise ValueError(f'Row {n} is not in the background candidate review bucket')
    return utc(r['event_time']), is_readonly(r['read_only'])


def load_background(path:Path, max_events=250000):
    """Return normalized rows, keeping principal reconstruction strictly IP-only."""
    normalized = []
    dups = 0
    seen_hash = set()
    ip_set = set()
    with path.open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        required = {'event_time','event_name','event_source','source_ip_address','read_only','aws_region',
                    'ground_truth_status','review_bucket','label_binary','exclude_from_training'}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError(f'Input CSV schema mismatch; missing: {sorted(required-set(reader.fieldnames or []))}')
        for n, r in enumerate(reader, 1):
            if n > max_events:
                raise ValueError(f'Maximum {max_events} records allowed')
            dt, ro = validate_background_row(r,n)
            actor_ip = r['source_ip_address'].strip()
            ip_set.add(actor_ip)
            actor_hash=hashlib.sha256(('ip-only\x1f'+actor_ip).encode()).hexdigest()[:20]
            source_row_id = r.get('row_hash','') or (r.get('source_file','')+'|'+r.get('record_index',''))
            if not source_row_id:
                source_row_id = f'{n}|{dt.isoformat()}|{r["event_name"]}'
            if source_row_id in seen_hash:
                dups += 1
                continue
            seen_hash.add(source_row_id)
            normalized.append({
                'event_id': 'background-'+hashlib.sha256(source_row_id.encode()).hexdigest()[:24],
                'event_time':dt.isoformat().replace('+00:00','Z'),
                'event_name':r['event_name'].strip(),
                'event_source':r['event_source'].strip(),
                'aws_region':r['aws_region'].strip(),
                'read_only':ro,'error_code':r.get('error_code','').strip(),
                '_actor_hash':actor_hash,
                '_source_row':r.get('record_index','') or str(n),
            })
    if not normalized:
        raise ValueError('No eligible background records')
    stats = {
        'input_events':len(normalized)+dups,
        'eligible_events':len(normalized),
        'exact_source_row_duplicates_skipped':dups,
        'source_ips_pseudonymized':len(ip_set),
        'first_event_utc':min(r['event_time'] for r in normalized),
        'last_event_utc':max(r['event_time'] for r in normalized),
        'source_ground_truth':'unlabeled_background_candidate',
    }
    return normalized, stats


def windows_for_scoring(rows,minutes=5):
    if minutes < 1 or 60 % minutes:
        raise ValueError('window-minutes must be a positive divisor of 60')
    groups=defaultdict(list)
    for r in rows:
        dt=utc(r['event_time'])
        slot=dt.replace(minute=dt.minute//minutes*minutes,second=0,microsecond=0)
        groups[(r['_actor_hash'],slot)].append(r)
    features=[];sequences=[];windows=[]
    for (actor,start),events in sorted(groups.items(),key=lambda it:(it[0][1],it[0][0])):
        events.sort(key=lambda r:(r['event_time'],r['event_id']))
        feat,seq=featureize_group(events,minutes)
        features.append(feat)
        sequences.append(seq)
        windows.append({
            'window_id':hashlib.sha256((actor+'|'+start.isoformat()).encode()).hexdigest()[:24],
            'window_start_utc':start.isoformat().replace('+00:00','Z'),
            'actor_hash':actor,
            'actor_grouping':'source_ip_only',
            'event_count':len(events),
            'first_event_time':events[0]['event_time'],
            'last_event_time':events[-1]['event_time'],
            'api_operations':json.dumps(dict(Counter(e['event_name'] for e in events)),sort_keys=True),
            'aws_services':json.dumps(sorted(set(e['event_source'] for e in events))),
            'unique_api_count':feat['unique_api_count'],
            'error_count':feat['error_count'],
            'write_count':feat['write_count'],
            'source_ground_truth':'unlabeled_background_candidate',
            'model_score_scope':'exploratory_unlabeled_screening',
            '_row_ids':[e['_source_row'] for e in events],
        })
    x=np.asarray([[f[k] for k in FEATURES] for f in features],dtype=float)
    sequence_tensor,lengths=pad_sequences(sequences)
    if sequence_tensor.shape[1:] != (MAX_SEQ,SEQ_DIM):
        raise ValueError('Sequence dimension mismatch')
    return windows,x,sequence_tensor,lengths


def generate_review_queue(scored, top_n=20, baseline_n=20,seed=4010):
    # Important: queue rows are unverified investigation prompts, not ground-truth labels.
    top=sorted(scored,key=lambda r:(-r['stacking_score'],r['window_id']))[:top_n]
    used={r['window_id'] for r in top}
    low=[r for r in scored if r['window_id'] not in used and r['stacking_score']<.5]
    random.Random(seed).shuffle(low)
    selected=[('highest_model_score',r) for r in top]+[('baseline_sample',r) for r in low[:baseline_n]]
    out=[]
    for purpose,r in selected:
        out.append({
            'window_id':r['window_id'], 'selection_reason':purpose,
            'window_start_utc':r['window_start_utc'], 'actor_hash':r['actor_hash'],
            'event_count':r['event_count'], 'stacking_score':r['stacking_score'],
            'api_operations':r['api_operations'],
            'review_decision':'PENDING',
            'evidence_reference':'', 'reviewer_notes':'',
        })
    return out


def score(csv_path,models_dir,out_dir,minutes=5,threshold=.5,top_n=20,baseline_n=20):
    if not (0 < threshold < 1):
        raise ValueError('Threshold must be between 0 and 1')
    rows,summary=load_background(Path(csv_path))
    windows,x,seq,lengths=windows_for_scoring(rows,minutes)
    models,meta,lstm=load_models(Path(models_dir))
    base=np.column_stack([models[name].predict_proba(x)[:,1] for name in MODEL_NAMES[:3]]+[lstm_predict(lstm,seq,lengths)])
    stack=meta.predict_proba(base)[:,1]
    for w,b,s in zip(windows,base,stack):
        w.update({
            'score_rf':float(b[0]),'score_lightgbm':float(b[1]),
            'score_xgboost':float(b[2]),'score_lstm':float(b[3]),
            'stacking_score':float(s),'predicted_binary':int(s>=threshold),
            'predicted_activity':'MALICIOUS_PATTERN' if s>=threshold else 'BENIGN_PATTERN',
        })
    out_dir=Path(out_dir);out_dir.mkdir(parents=True,exist_ok=True)
    result=pd.DataFrame([{c:r[c] for c in CSV_COLS} for r in windows])
    result.to_csv(out_dir/'sandbox_window_scores_PROTO.csv',index=False,encoding='utf-8-sig')
    review=generate_review_queue(windows,top_n,baseline_n)
    pd.DataFrame(review).to_csv(out_dir/'sandbox_review_queue_PROTO.csv',index=False,encoding='utf-8-sig')
    alerted=int((stack>=threshold).sum())
    singleton=sum(w['event_count']==1 for w in windows)
    report={
        'experiment':'PP1 collected CloudTrail background screening',
        'model_provenance':training_provenance(Path(models_dir)),
        'source_file':str(csv_path),
        'ground_truth':'unlabeled_background_candidates',
        'classification_metrics_available':False,
        'precision_recall_f1_false_positive_rate':'not_estimated_unlabeled_data',
        'feature_engineering':'frozen_features_from_train_pp1_binary_stack',
        'actor_grouping':'source IP only; no principal identity available',
        'window_minutes':minutes,'threshold':threshold,
        **summary,
        'screened_windows':len(windows),
        'single_event_windows':singleton,
        'windows_flagged_for_review':alerted,
        'flagged_window_fraction':alerted/len(windows),
        'score_summary':{'min':float(np.min(stack)),'median':float(np.median(stack)),
                         'p90':float(np.percentile(stack,90)),'p99':float(np.percentile(stack,99)),
                         'max':float(np.max(stack))},
        'review_queue_windows':len(review),
        'limitations':[
            'No confirmed benign labels; flagged window fraction is NOT a false-positive rate.',
            'Source-IP-only grouping is an approximation, not reconstructed AWS sessions.',
            'The model is trained on a mixed collected/generated dataset; differing source distributions may affect scores.',
            'All review decisions remain pending until legitimate activity is independently corroborated.',
            'Model scores have not been externally calibrated as incident probabilities.',
        ],
    }
    (out_dir/'sandbox_screening_report_PROTO.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('PP1 collected CloudTrail background screening completed')
    print(f'  Records: {len(rows)} | Windows: {len(windows)} | Source-IP groups: {summary["source_ips_pseudonymized"]}')
    print(f'  Windows flagged for review: {alerted}/{len(windows)} ({100*alerted/len(windows):.1f}%)')
    print(f'  Review queue: {len(review)} windows (high-score + baseline sample)')
    print('  Label status: unverified background; alert fraction is not a false-positive rate')
    print('Output:',out_dir)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sandbox',type=Path,default=Path('Data/Interim/integration_review/sandbox.csv'))
    p.add_argument('--models-dir',type=Path,default=Path('Data/Experiments/pp1_mixed_PROTO'))
    p.add_argument('--output-dir',type=Path,default=Path('Data/Experiments/pp1_real_background_PROTO'))
    p.add_argument('--window-minutes',type=int,default=5)
    p.add_argument('--threshold',type=float,default=.5)
    p.add_argument('--top-n',type=int,default=20)
    p.add_argument('--baseline-n',type=int,default=20)
    a=p.parse_args()
    try:
        score(a.sandbox,a.models_dir,a.output_dir,a.window_minutes,a.threshold,a.top_n,a.baseline_n)
    except (ValueError,KeyError,FileNotFoundError) as ex:
        p.exit(2,f'ERROR: {ex}\n')

if __name__=='__main__':main()
