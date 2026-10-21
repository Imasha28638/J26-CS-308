#!/usr/bin/env python3
"""Read-only PP1 public CloudTrail per-model attack-scenario window recall report.

Uses saved publisher TestOn window scores. Does not fit models, adjust thresholds,
modify model files, or infer multiclass predictions. A positive window can belong
 to multiple publisher attack scenarios.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

THRESHOLD = 0.5
BASE_COLS = {
    'Random Forest': 'prob_Random_Forest',
    'LightGBM': 'prob_LightGBM',
    'XGBoost': 'prob_XGBoost',
    'LSTM': 'prob_LSTM',
    'Stacking ensemble': 'stacked_malicious_score',
}
VOTING = ('Hard voting (3-of-4)', 'Soft voting')
CANDIDATE_NAME = 'Weighted stacking candidate'
KEYS = ['session_id', 'window_start']


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def load_base(base_dir: Path):
    pred_path = base_dir / 'public_test_predictions_PROTO.csv'
    rep_path = base_dir / 'public_experiment_report_PROTO.json'
    original_path = base_dir / 'public_attack_scenario_recall_PROTO.csv'
    for p in (pred_path, rep_path, original_path):
        if not p.is_file():
            raise FileNotFoundError(f'Missing baseline output: {p}')
    df = pd.read_csv(pred_path, encoding='utf-8-sig', keep_default_na=False)
    rep = json.loads(rep_path.read_text(encoding='utf-8'))
    columns = set(KEYS + ['label_binary','publisher_attack_scenarios','predicted_binary'] + list(BASE_COLS.values()))
    missing = columns - set(df.columns)
    if missing:
        raise ValueError(f'Baseline prediction file missing columns: {sorted(missing)}')
    if df.empty or df[KEYS].duplicated().any():
        raise ValueError('Empty or duplicate actor/window keys in baseline predictions')
    if df[KEYS].eq('').any().any():
        raise ValueError('Blank actor or time key')
    y = pd.to_numeric(df['label_binary'], errors='raise').to_numpy(dtype=int)
    if not set(np.unique(y)).issubset({0,1}) or len(np.unique(y)) != 2:
        raise ValueError('Expected binary labels with both classes')
    if len(df) != rep['test_windows'] or int(y.sum()) != rep['positive_test_windows']:
        raise ValueError('Baseline report does not reconcile with test predictions')
    base_scores = {}
    for name,col in BASE_COLS.items():
        a = pd.to_numeric(df[col], errors='raise').to_numpy(dtype=float)
        if not np.isfinite(a).all() or (a < 0).any() or (a > 1).any():
            raise ValueError(f'Invalid probability values: {col}')
        base_scores[name] = a
    recorded = pd.to_numeric(df['predicted_binary'], errors='raise').to_numpy(dtype=int)
    if not np.array_equal(recorded, (base_scores['Stacking ensemble'] >= THRESHOLD).astype(int)):
        raise ValueError('Saved predicted_binary does not match stacking scores at 0.5')
    original = pd.read_csv(original_path, encoding='utf-8-sig', keep_default_na=False)
    expected_cols = {'scenario','positive_test_windows','detected_positive_windows'}
    if not expected_cols.issubset(original.columns):
        raise ValueError('Original scenario report missing expected columns')
    return df, rep, original, y, base_scores, pred_path


def load_weighted(candidate_dir: Path, baseline: pd.DataFrame):
    path = candidate_dir / 'weighted_public_test_predictions_PROTO.csv'
    if not path.is_file():
        raise FileNotFoundError(f'Weighted candidate predictions not found: {path}')
    w = pd.read_csv(path, encoding='utf-8-sig', keep_default_na=False)
    needed = set(KEYS + ['label_binary','candidate_stacking_score','stacked_malicious_score'])
    if needed - set(w.columns):
        raise ValueError(f'Weighted file missing columns: {sorted(needed - set(w.columns))}')
    if len(w) != len(baseline) or w[KEYS].duplicated().any():
        raise ValueError('Weighted output has different count or duplicate actor/window keys')
    a = baseline[KEYS + ['label_binary','stacked_malicious_score']].merge(
        w[KEYS + ['label_binary','stacked_malicious_score','candidate_stacking_score']],
        on=KEYS, how='outer', indicator=True, suffixes=('_base', '_candidate'), validate='one_to_one')
    if not (a['_merge']=='both').all():
        raise ValueError('Weighted predictions and baseline have different window keys')
    if not np.array_equal(a['label_binary_base'].astype(int),a['label_binary_candidate'].astype(int)):
        raise ValueError('Weighted file label mismatch')
    diff=np.max(abs(a['stacked_malicious_score_base'].astype(float)-a['stacked_malicious_score_candidate'].astype(float)))
    if diff > 1e-8:
        raise ValueError(f'Weighted file baseline stacking score disagreement: {diff}')
    aligned = baseline[KEYS].merge(w[KEYS+['candidate_stacking_score']],on=KEYS,how='left',validate='one_to_one')
    vals=aligned['candidate_stacking_score'].to_numpy(dtype=float)
    if not np.isfinite(vals).all() or (vals<0).any() or (vals>1).any():
        raise ValueError('Candidate scores outside [0,1]')
    return vals,path


def tokens(v) -> set[str]:
    return {x.strip() for x in str(v).split('|') if x.strip()}


def scores_and_predictions(base_scores, candidate_scores=None):
    scoremap=dict(base_scores)
    base_four=np.stack([base_scores[n] for n in ('Random Forest','LightGBM','XGBoost','LSTM')],axis=1)
    scoremap['Hard voting (3-of-4)']=(np.sum(base_four >= THRESHOLD,axis=1)>=3).astype(float)
    scoremap['Soft voting']=base_four.mean(axis=1)
    if candidate_scores is not None:
        scoremap[CANDIDATE_NAME]=candidate_scores
    return scoremap


def classify(y, score):
    p=(score>=THRESHOLD).astype(int)
    tn,fp,fn,tp=confusion_matrix(y,p,labels=[0,1]).ravel().tolist()
    precision,recall,f1,_=precision_recall_fscore_support(y,p,average='binary',zero_division=0)
    return {'tp':int(tp),'fp':int(fp),'fn':int(fn),'tn':int(tn),
            'precision':float(precision),'recall':float(recall),'f1':float(f1)}


def run(base_dir: Path, output_dir: Path, weighted_dir: Path|None = None):
    base_dir=base_dir.resolve()
    output_dir=output_dir.resolve()
    if output_dir==base_dir or base_dir in output_dir.parents:
        raise ValueError('Output directory must not be inside baseline checkpoint')
    if weighted_dir is not None and (output_dir==weighted_dir.resolve() or weighted_dir.resolve() in output_dir.parents):
        raise ValueError('Output directory must not be inside weighted checkpoint')
    base,rep,orig,y,base_scores,source_path=load_base(base_dir)
    weighted_path=None
    weighted_scores=None
    if weighted_dir is not None:
        weighted_scores,weighted_path=load_weighted(weighted_dir,base)
    scoremap=scores_and_predictions(base_scores,weighted_scores)
    models=list(BASE_COLS)+list(VOTING)+([CANDIDATE_NAME] if weighted_scores is not None else [])
    scenarios_by_window=[tokens(s) for s in base['publisher_attack_scenarios']]
    if any(bool(names)!=bool(label) for names,label in zip(scenarios_by_window,y)):
        raise ValueError('Publisher scenario annotations do not agree with positive window labels')
    names=sorted(set().union(*scenarios_by_window))
    seen=set(rep.get('scenarios_seen_in_training',[]))
    if not names: raise ValueError('No publisher scenario annotations available')
    rows=[]
    wide=[]
    for sc in names:
        indices=np.array([i for i,ns in enumerate(scenarios_by_window) if sc in ns],dtype=int)
        w={'scenario':sc,'seen_in_training':sc in seen,'positive_test_windows':len(indices)}
        for model in models:
            det=int(np.sum(scoremap[model][indices] >= THRESHOLD))
            rows.append({'scenario':sc,'seen_in_training':sc in seen,'model':model,
                         'positive_test_windows':len(indices),
                         'detected_positive_windows':det,
                         'missed_positive_windows':len(indices)-det,
                         'window_recall':round(det/len(indices),6),
                         'decision_threshold':THRESHOLD})
            w[model+' detected']=det
            w[model+' recall']=round(det/len(indices),6)
        wide.append(w)
    original_map={str(row['scenario']):row for _,row in orig.iterrows()}
    if set(original_map)!=set(names):
        raise ValueError('Original scenario CSV covers different attack scenarios')
    for r in rows:
        if r['model']!='Stacking ensemble':continue
        previous=original_map[r['scenario']]
        if (int(previous['positive_test_windows'])!=r['positive_test_windows'] or
            int(previous['detected_positive_windows'])!=r['detected_positive_windows']):
            raise ValueError(f'Baseline stacking scenario report mismatch for {r["scenario"]}')
    metric_rows=[]
    for model in models:
        m=classify(y,scoremap[model]);m={'model':model,**m}
        metric_rows.append(m)
        published=rep.get('model_metrics',{}).get(model)
        if published and any(abs(m[k]-float(published[k]))>1e-6 for k in ('precision','recall','f1')):
            raise ValueError(f'Published overall model metrics mismatch: {model}')
    output_dir.mkdir(parents=True,exist_ok=True)
    pd.DataFrame(rows).to_csv(output_dir/'public_attack_scenario_by_model_PROTO.csv',index=False,encoding='utf-8-sig')
    pd.DataFrame(wide).to_csv(output_dir/'public_attack_scenario_comparison_wide_PROTO.csv',index=False,encoding='utf-8-sig')
    pd.DataFrame(metric_rows).to_csv(output_dir/'public_model_metrics_verified_PROTO.csv',index=False,encoding='utf-8-sig')
    counts=Counter(sc for s in scenarios_by_window for sc in s)
    report={'report':'Per-model binary window detection by publisher-labeled attack scenario',
            'decision_threshold':THRESHOLD,'baseline_predictions_sha256':sha256(source_path),
            'weighted_predictions_sha256':sha256(weighted_path) if weighted_path else None,
            'test_windows':len(base),'unique_attack_containing_windows':int(y.sum()),
            'scenario_window_occurrences':sum(counts.values()),
            'number_of_scenarios':len(names),'models_reported':models,
            'model_metrics':metric_rows,
            'methodology_notes':[
                'The original public_attack_scenario_recall_PROTO.csv covers the original stacking ensemble only.',
                'All displayed detection rates apply to binary actor/time-window predictions, not attack-category predictions.',
                'A single window can contain events from multiple publisher scenarios, so scenario window totals can exceed distinct positive windows.',
                'The same fixed decision threshold 0.5 is used for model comparisons; no threshold tuning or model fitting occurs.',
                'All results use the already-evaluated publisher TestOn split; results are descriptive, not new independent validation.',
            ]}
    (output_dir/'public_scenario_model_report_PROTO.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('PP1 public CloudTrail multi-model scenario report completed')
    print(f"  Test windows: {len(base)} | Distinct attack-containing windows: {int(y.sum())}")
    print(f"  Scenario-window occurrences: {sum(counts.values())} across {len(names)} scenarios (some windows have multiple scenarios)")
    print('  Original per-scenario report: ORIGINAL STACKING ONLY (verified)')
    for m in metric_rows:
        print(f"  {m['model']:27s} TP={m['tp']:2d} FP={m['fp']:3d} FN={m['fn']:2d} F1={m['f1']:.3f}")
    print('  Independent model files were not modified; no retraining performed.')
    print('  Output:',output_dir)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--models-dir',type=Path,default=Path('Data/Experiments/pp1_public_cloudtrail_PROTO'))
    parser.add_argument('--output-dir',type=Path,default=Path('Data/Experiments/pp1_public_scenario_models_PROTO'))
    parser.add_argument('--weighted-dir',type=Path,default=None,
                        help='Optional directory containing weighted_public_test_predictions_PROTO.csv')
    args=parser.parse_args()
    run(args.models_dir,args.output_dir,args.weighted_dir)

if __name__=='__main__':
    main()
