#!/usr/bin/env python3
"""Audit and prepare high-evidence Splunk CloudTrail candidates for TRAINING-ONLY experiments.

Scenario-associated rows are review-only. Missing read_only is quarantined.
The publisher TestOn file is used only to check native event-ID overlap and is not
used for labels, features, threshold selection, or model fitting.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

NEEDED_SPLUNK = {
    'event_id','event_time','event_name','event_source','read_only',
    'identity_arn','source_ip_address','scenario_id','research_class','label_binary',
    'exclude_from_training','label_scope','label_confidence'
}
NEEDED_ARIEL = {
    'event_id','session_id','event_time','event_name','event_source',
    'read_only','source_split','observed_positive_flag'
}
EXT_FIELDS = [
    'session_id','event_id','event_time','event_name','event_source','read_only',
    'error_code','aws_region','observed_positive_flag','candidate_attack_class',
    'data_origin','evidence_tier','scenario_id','source_row_id','actor_group_kind',
    'source_archive','source_split','label_scope','label_confidence',
]


def load(path: Path, required: set[str]):
    if not path.is_file():
        raise FileNotFoundError(f'Input does not exist: {path}')
    with path.open('r',encoding='utf-8-sig',newline='') as h:
        reader=csv.DictReader(h)
        missing=required-set(reader.fieldnames or [])
        if missing: raise ValueError(f'{path}: missing columns: {sorted(missing)}')
        return list(reader), reader.fieldnames or []


def save(path: Path, rows, fields):
    with path.open('w',encoding='utf-8-sig',newline='') as h:
        wr=csv.DictWriter(h,fieldnames=fields,extrasaction='ignore')
        wr.writeheader(); wr.writerows(rows)


def utc(value: str):
    if not value or not value.strip(): raise ValueError('missing event_time')
    dt=datetime.fromisoformat(value.strip().replace('Z','+00:00'))
    if dt.tzinfo is None: raise ValueError('timestamp has no timezone')
    return dt.astimezone(timezone.utc)


def bool_readonly(text: str):
    v=(text or '').strip().lower()
    if v in ('true','1'): return 'true'
    if v in ('false','0'): return 'false'
    raise ValueError('read_only missing or invalid')


def actor_session(r):
    arn=(r.get('identity_arn') or '').strip()
    ip=(r.get('source_ip_address') or '').strip()
    if arn: kind, source='identity_arn',arn
    elif ip: kind,source='source_ip_proxy',ip
    else: raise ValueError('missing actor ARN and source IP')
    digest=hashlib.sha256((kind+'\x1f'+source).encode()).hexdigest()[:24]
    return 'splunk_actor__'+digest,kind


def hashed_file(path):
    digest=hashlib.sha256()
    with path.open('rb') as h:
        for block in iter(lambda:h.read(1024*1024),b''):
            digest.update(block)
    return digest.hexdigest()


def prepared(r):
    session,kind=actor_session(r)
    tm=utc(r['event_time']).strftime('%Y-%m-%dT%H:%M:%SZ')
    if not (r['event_id'].strip() and r['event_name'].strip() and r['event_source'].strip()):
        raise ValueError('missing event ID/name/source')
    return {
        'session_id':session,'event_id':r['event_id'].strip(), 'event_time':tm,
        'event_name':r['event_name'].strip(),'event_source':r['event_source'].strip(),
        'read_only':bool_readonly(r.get('read_only','')),
        'error_code':r.get('error_code',''), 'aws_region':r.get('aws_region',''),
        'observed_positive_flag':'1', 'candidate_attack_class':r.get('research_class',''),
        'data_origin':'Splunk Attack Data',
        'evidence_tier':'high_confidence_event_rule_candidate',
        'scenario_id':r['scenario_id'].strip(), 'source_row_id':r.get('record_index',''),
        'actor_group_kind':kind, 'source_archive':r.get('source_file',''),
        'source_split':'train', 'label_scope':'event_rule','label_confidence':'high',
    }


def audit(splunk_path:Path, ariel_train:Path, ariel_test:Path, out:Path):
    s,_=load(splunk_path,NEEDED_SPLUNK)
    a,original_ariel_cols=load(ariel_train,NEEDED_ARIEL)
    t,_=load(ariel_test,NEEDED_ARIEL)
    if not all(r['source_split']=='train' for r in a):raise ValueError('Ariel TrainOn split mismatch')
    if not all(r['source_split']=='test' for r in t):raise ValueError('Ariel TestOn split mismatch')
    if not s or not a or not t: raise ValueError('Input dataset unexpectedly empty')
    ariel_train_ids={r['event_id'] for r in a}
    ariel_test_ids={r['event_id'] for r in t}
    if len(ariel_train_ids)!=len(a) or len(ariel_test_ids)!=len(t):
        raise ValueError('Ariel event-ID duplicates; stop and correct importer first')
    if ariel_train_ids & ariel_test_ids:raise ValueError('Ariel TrainOn/TestOn event-ID overlap')

    eligible=[]; quarantined=[]; inventory=[]; duplicate_ids=Counter()
    counts=Counter(); per_scenario=defaultdict(Counter)
    for ix,r in enumerate(s,2):
        scen=r['scenario_id'].strip(); scope=r['label_scope'].strip().lower()
        conf=r['label_confidence'].strip().lower(); label=r['label_binary'].strip()
        exclude=r['exclude_from_training'].strip().lower()
        if not scen: raise ValueError(f'Splunk row {ix} lacks scenario_id')
        per_scenario[scen]['total']+=1
        per_scenario[scen]['event_rule' if scope=='event_rule' else 'scenario_label']+=1
        if label!='1' or exclude not in ('0','false'):
            status='EXCLUDED_BY_SOURCE'
        elif scope!='event_rule' or conf!='high':
            status='REVIEW_SCENARIO_LABEL'
        else:
            try: candidate=prepared(r)
            except (ValueError,TypeError) as exc:
                status='QUARANTINE_MISSING_OR_INVALID_FIELDS'
                quarantined.append({'source_row':ix,'event_id':r['event_id'],
                                    'scenario_id':scen,'reason':str(exc)})
            else:
                status='CANDIDATE_HIGH_EVENT_RULE'
                eligible.append(candidate)
                duplicate_ids[candidate['event_id']]+=1
        counts[status]+=1;per_scenario[scen][status]+=1
    duplicates={k for k,v in duplicate_ids.items() if v>1}
    splunk_overlap_train={r['event_id'] for r in eligible}&ariel_train_ids
    splunk_overlap_test={r['event_id'] for r in eligible}&ariel_test_ids
    issues=[]
    if duplicates:issues.append(f'Splunk candidate event-ID repeats: {len(duplicates)}')
    if splunk_overlap_train:issues.append(f'Splunk candidate IDs in Ariel TrainOn: {len(splunk_overlap_train)}')
    if splunk_overlap_test:issues.append(f'Splunk candidate IDs in Ariel TestOn: {len(splunk_overlap_test)}')
    merged_ids=Counter(r['event_id'] for r in a+eligible)
    if any(n>1 for n in merged_ids.values()):issues.append('Merged train event IDs are not unique')
    # External high-confidence event-rule candidates are still scenario-context evidence,
    # not independent confirmation that every operation is a successful compromise.
    for scenario,stat in sorted(per_scenario.items()):
        inventory.append({'scenario_id':scenario,'total_source_events':stat['total'],
                          'high_event_rule_candidates':stat['CANDIDATE_HIGH_EVENT_RULE'],
                          'quarantined':stat['QUARANTINE_MISSING_OR_INVALID_FIELDS'],
                          'scenario_associated_review':stat['REVIEW_SCENARIO_LABEL'],
                          'excluded':stat['EXCLUDED_BY_SOURCE']})
    def groups(rows):
        return {r['session_id']+'__'+r['event_time'][:10] for r in rows if r['observed_positive_flag']=='1'}
    positive_ariel_groups=groups(a)
    positive_splunk_groups=groups(eligible)
    report={
        'stage':'train-only input eligibility and source audit; no models fitted',
        'splunk_input_events':len(s),'ariel_train_events':len(a),'ariel_test_events_checked_ids_only':len(t),
        'counts':dict(counts),'high_event_rule_usable_events':len(eligible),
        'high_event_rule_quarantined_events':len(quarantined),
        'high_event_rule_scenarios':len({r['scenario_id'] for r in eligible}),
        'ariel_positive_actor_day_groups':len(positive_ariel_groups),
        'additional_splunk_positive_actor_day_groups':len(positive_splunk_groups),
        'combined_positive_actor_day_groups':len(positive_ariel_groups|positive_splunk_groups),
        'train_test_event_id_overlap':len(splunk_overlap_test),
        'ariel_train_event_id_overlap':len(splunk_overlap_train),
        'duplicated_high_candidate_event_ids':len(duplicates),
        'ready_for_next_review':not issues,
        'splunk_sha256':hashed_file(splunk_path),
        'ariel_train_sha256':hashed_file(ariel_train),
        'ariel_test_sha256':hashed_file(ariel_test),
        'limitations':[
            'Splunk event-rule candidates are associated with documented attack scenarios; API names alone do not prove harmful intent.',
            'Scenario-associated records are excluded from eligible training events pending ground-truth review.',
            'Records lacking an explicit read_only field are quarantined rather than assigned an assumed value.',
            'Splunk contributes only positive candidates; merging changes the source-label distribution and requires source-aware validation.',
            'Publisher TestOn labels and scores are not read. TrainOn/TestOn original files remain unmodified.',
            'Expanded training input is for future candidate training only; no performance is asserted.',
        ],'issues':issues,
    }
    out.mkdir(parents=True,exist_ok=True)
    save(out/'splunk_source_eligibility_PROTO.csv',inventory,list(inventory[0]))
    save(out/'splunk_rule_quarantine_PROTO.csv',quarantined,
         ['source_row','event_id','scenario_id','reason'])
    save(out/'splunk_high_rule_training_candidates_PROTO.csv',eligible,EXT_FIELDS)
    (out/'splunk_extension_audit_PROTO.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('PP1 Splunk attack-evidence eligibility audit completed')
    print(f'  Input Splunk events: {len(s)} | scenario-label review: {counts["REVIEW_SCENARIO_LABEL"]}')
    print(f'  High-confidence event-rule usable: {len(eligible)} | quarantined: {len(quarantined)}')
    print(f'  Independent positive actor-day groups: Ariel={len(positive_ariel_groups)}, '
          f'Splunk added={len(positive_splunk_groups)}, combined={len(positive_ariel_groups|positive_splunk_groups)}')
    print(f'  Event-ID overlap: Ariel TrainOn={len(splunk_overlap_train)}; TestOn={len(splunk_overlap_test)}')
    print(f'  Ready for next review: {not issues}')
    print(f'  Output: {out}')
    if issues: raise ValueError('; '.join(issues))
    # Write only AFTER integrity checks; preserve original fields plus additive provenance.
    all_fields=list(dict.fromkeys(original_ariel_cols+EXT_FIELDS))
    save(out/'expanded_train_candidates_PROTO.csv',a+eligible,all_fields)
    print(f'  Prepared expanded train input: {len(a)+len(eligible)} records (no training performed)')
    return report


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--splunk',required=True,type=Path)
    ap.add_argument('--ariel-train',required=True,type=Path)
    ap.add_argument('--ariel-test',required=True,type=Path,help='Used for event-ID overlap check only')
    ap.add_argument('--output-dir',required=True,type=Path)
    args=ap.parse_args()
    audit(args.splunk,args.ariel_train,args.ariel_test,args.output_dir)

if __name__=='__main__':main()
