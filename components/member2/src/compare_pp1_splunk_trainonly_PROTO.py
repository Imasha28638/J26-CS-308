#!/usr/bin/env python3
"""Paired Ariel TrainOn-only LightGBM validation: Ariel baseline versus Ariel + reviewed Splunk events.

This intentionally does NOT open Ariel TestOn. Held-out validation consists exclusively
of Ariel actor-day groups. The same folds are used in both conditions. Existing
trained model files are not touched.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, average_precision_score, roc_auc_score

from train_pp1_public_cloudtrail_PROTO import read_import, make_windows, group_keys, check_folds
from train_pp1_binary_stack import FEATURES, construct_models

META_COLUMNS = {
    'session_id', 'event_id', 'source_split', 'source_archive', 'source_row_id',
    'scenario_id', 'observed_positive_flag', 'data_origin', 'label_scope',
    'label_confidence', 'evidence_tier', 'candidate_attack_class',
}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for piece in iter(lambda: f.read(1024 * 1024), b''):
            h.update(piece)
    return h.hexdigest()


def validate_expansion(ariel: list[dict], expanded: list[dict]) -> list[dict]:
    by_id = {r['event_id']: r for r in ariel}
    ex_by_id = {r['event_id']: r for r in expanded}
    if len(by_id) != len(ariel) or len(ex_by_id) != len(expanded):
        raise ValueError('Repeated event IDs in prepared inputs')
    if not set(by_id).issubset(ex_by_id):
        raise ValueError('Expanded file omits one or more Ariel TrainOn event IDs')
    core = ['session_id','event_time','event_name','event_source','read_only',
            'error_code','aws_region','observed_positive_flag','scenario_id',
            'source_archive','source_split']
    for eid, a in by_id.items():
        b = ex_by_id[eid]
        for key in core:
            if a.get(key, '') != b.get(key, ''):
                raise ValueError(f'An original Ariel training value changed: event ID {eid}, field {key}')
    extras = [r for r in expanded if r['event_id'] not in by_id]
    if not extras:
        raise ValueError('No eligible Splunk rows found in expanded input')
    for r in extras:
        if (r.get('data_origin') != 'Splunk Attack Data'
            or r.get('label_scope') != 'event_rule'
            or r.get('label_confidence') != 'high'
            or r.get('evidence_tier') != 'high_confidence_event_rule_candidate'
            or r['observed_positive_flag'] != '1'
            or not r['session_id'].startswith('splunk_actor__')
            or r['source_split'] != 'train'):
            raise ValueError('Expanded input contains a row not qualifying as reviewed Splunk event-rule evidence')
    if set(x['session_id'] for x in extras) & set(x['session_id'] for x in ariel):
        raise ValueError('Actor grouping collision between sources')
    return extras


def align_publisher_baseline(ariel_windows: pd.DataFrame, prior_csv: Path) -> pd.DataFrame:
    # 4313 windows from the previously audited public model, after overlapping
    # actor/time training windows were omitted. We retain the identical row set.
    expected = pd.read_csv(prior_csv, encoding='utf-8-sig')
    keys = ['session_id','window_start']
    need = set(keys + ['label_binary'] + FEATURES)
    if not need.issubset(expected.columns):
        raise ValueError('Previously saved baseline windows are missing required columns')
    if expected.duplicated(keys).any() or ariel_windows.duplicated(keys).any():
        raise ValueError('Duplicate actor/time windows')
    m = ariel_windows.merge(expected, on=keys, how='inner', validate='one_to_one', suffixes=('', '_saved'))
    if len(m) != len(expected):
        raise ValueError(f'Published-model baseline mismatch: {len(m)} reconstructed vs {len(expected)} saved')
    if not np.array_equal(m['label_binary'].to_numpy(int), m['label_binary_saved'].to_numpy(int)):
        raise ValueError('Mismatch in target labels for saved baseline window keys')
    for col in FEATURES:
        left = m[col].to_numpy(float)
        right = m[col+'_saved'].to_numpy(float)
        if not np.allclose(left, right, rtol=1e-6, atol=1e-6):
            raise ValueError(f'Feature mismatch with saved baseline: {col}')
    return ariel_windows.merge(expected[keys], on=keys, how='inner', validate='one_to_one').sort_values(keys).reset_index(drop=True)


def model_for_seed(seed: int):
    return dict(construct_models(seed))['LightGBM']


def metrics(y, scores):
    pred = (np.asarray(scores) >= .5).astype(int)
    out = {
        'tp': int(((pred == 1) & (y == 1)).sum()),
        'fp': int(((pred == 1) & (y == 0)).sum()),
        'tn': int(((pred == 0) & (y == 0)).sum()),
        'fn': int(((pred == 0) & (y == 1)).sum()),
        'precision': float(precision_score(y, pred, zero_division=0)),
        'recall': float(recall_score(y, pred, zero_division=0)),
        'f1': float(f1_score(y, pred, zero_division=0)),
        'average_precision': float(average_precision_score(y, scores)),
        'roc_auc': float(roc_auc_score(y, scores)) if len(set(y)) == 2 else None,
    }
    return out


def compare(ariel_path: Path, expanded_path: Path, saved_path: Path,
            outdir: Path, minutes: int, folds: int, seed: int):
    if minutes < 1 or 60 % minutes: raise ValueError('window minutes must divide 60')
    if folds < 3: raise ValueError('At least 3 grouped folds are required')
    for p in [ariel_path, expanded_path, saved_path]:
        if not p.exists(): raise FileNotFoundError(p)
    ariel = read_import(ariel_path, 'train')
    expanded = read_import(expanded_path, 'train')
    extras = validate_expansion(ariel, expanded)
    all_windows, _, _ = make_windows(ariel, minutes)
    base = align_publisher_baseline(all_windows, saved_path)
    splunk_windows, _, _ = make_windows(extras, minutes)
    if not len(splunk_windows) or int(splunk_windows.label_binary.min()) != 1:
        raise ValueError('Splunk-only window set has empty/negative labels')
    if set(zip(base.session_id,base.window_start)) & set(zip(splunk_windows.session_id,splunk_windows.window_start)):
        raise ValueError('Source actor/window collision')
    if not set(FEATURES).isdisjoint(META_COLUMNS):
        raise AssertionError('Provenance or label feature leakage detected')
    x = base[FEATURES].to_numpy(float)
    y = base.label_binary.to_numpy(int)
    groups = group_keys(base, 'actor-day')
    splits, actual_seed = check_folds(x, y, groups, folds, seed)
    add_x = splunk_windows[FEATURES].to_numpy(float)
    add_y = splunk_windows.label_binary.to_numpy(int)
    predictions = {'Ariel-only': np.full(len(base), np.nan), 'Ariel-plus-Splunk': np.full(len(base), np.nan)}
    fold_results = []
    for fold, (tr, va) in enumerate(splits, 1):
        if set(groups[tr]) & set(groups[va]):
            raise ValueError('Actor-day fold leakage')
        if len(set(y[tr])) != 2 or len(set(y[va])) != 2:
            raise ValueError('Grouped CV fold lacks both classes')
        for condition in ('Ariel-only','Ariel-plus-Splunk'):
            if condition == 'Ariel-only':
                fit_x, fit_y = x[tr], y[tr]
            else:
                fit_x = np.concatenate((x[tr], add_x), axis=0)
                fit_y = np.concatenate((y[tr], add_y), axis=0)
            clf = model_for_seed(seed+fold)
            clf.fit(fit_x,fit_y)
            pred = clf.predict_proba(x[va])[:,1]
            predictions[condition][va] = pred
            met = metrics(y[va], pred)
            fold_results.append({'fold':fold,'condition':condition,'train_ariel_windows':len(tr),
                                 'train_splunk_windows':len(add_x) if condition == 'Ariel-plus-Splunk' else 0,
                                 'validation_ariel_windows':len(va), 'validation_positive_windows':int(y[va].sum()), **met})
        print(f'  Group-separated paired fold {fold}/{len(splits)} finished: '+
              f'Ariel validation windows={len(va)}, positive={int(y[va].sum())}')
    combined = []
    for condition in predictions:
        if np.isnan(predictions[condition]).any(): raise ValueError('Missing out-of-fold scores')
        combined.append({'condition':condition, 'validation_scope':'Ariel TrainOn groups only',
                         'n_validation_windows':len(base), 'n_positive_windows':int(y.sum()),
                         **metrics(y, predictions[condition])})
    outdir.mkdir(parents=True,exist_ok=True)
    pd.DataFrame(combined).to_csv(outdir/'trainonly_expansion_comparison_PROTO.csv',index=False)
    pd.DataFrame(fold_results).to_csv(outdir/'trainonly_expansion_folds_PROTO.csv',index=False)
    out = base[['session_id','window_start','label_binary']].copy()
    out['actor_day_group'] = groups
    out['score_ariel_only'] = predictions['Ariel-only']
    out['score_ariel_plus_splunk'] = predictions['Ariel-plus-Splunk']
    out.to_csv(outdir/'trainonly_expansion_oof_PROTO.csv',index=False)
    report = {
        'experiment':'Paired training-only LightGBM comparison, controlled Ariel actor-day CV',
        'ariel_training_events':len(ariel), 'splunk_eligible_events':len(extras),
        'ariel_validation_window_population':len(base), 'ariel_positive_validation_windows':int(y.sum()),
        'splunk_added_training_windows':len(splunk_windows),
        'splunk_added_actor_days':len(set(group_keys(splunk_windows,'actor-day'))),
        'splunk_scenarios':dict(Counter(r['scenario_id'] for r in extras)),
        'feature_names':FEATURES,'model':'LightGBM','seed':seed,'fold_seed':actual_seed,
        'folds':folds,'window_minutes':minutes,
        'all_added_splunk_windows_training_only':True,
        'all_validation_windows_ariel_only':True,
        'publisher_teston_accessed':False,
        'data_integrity':{
            'ariel_input_sha256':digest(ariel_path), 'expanded_input_sha256':digest(expanded_path),
            'baseline_window_sha256':digest(saved_path)},
        'results':combined,
        'limitations':[
            'Training-only group validation, with only a few independent positive Ariel groups.',
            'All Splunk additions are positive event-rule candidates; source-label confounding remains possible.',
            'Added actor-day groups do not necessarily represent independent attacks.',
            'Ariel TrainOn validation is reused to guide design; avoid claims from repeated tuning.',
            'The preexisting baseline window selection removed publisher train/test actor-time overlaps.',
            'No new four-model or stacked model was trained; no publisher TestOn metrics were computed.'
        ],
    }
    (outdir/'trainonly_expansion_audit_PROTO.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('PP1 training-only Splunk extension comparison completed')
    print(f'  Ariel windows in paired CV: {len(base)}; positive={int(y.sum())}')
    print(f'  Additional Splunk: {len(extras)} events, {len(splunk_windows)} positive windows, '+
          f'{report["splunk_added_actor_days"]} actor-day groups')
    for item in combined:
        print(f'  {item["condition"]:20s} F1={item["f1"]:.3f} P={item["precision"]:.3f} '+
              f'R={item["recall"]:.3f} FP={item["fp"]} AP={item["average_precision"]:.3f}')
    print(f'  Validation source: Ariel TrainOn only; publisher TestOn not read')
    print(f'  Results: {outdir}')
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--ariel-train',required=True,type=Path)
    ap.add_argument('--expanded-train',required=True,type=Path)
    ap.add_argument('--saved-baseline-windows',required=True,type=Path)
    ap.add_argument('--output-dir',required=True,type=Path)
    ap.add_argument('--window-minutes',type=int,default=5)
    ap.add_argument('--folds',type=int,default=3)
    ap.add_argument('--seed',type=int,default=4010)
    args = ap.parse_args()
    compare(args.ariel_train,args.expanded_train,args.saved_baseline_windows,
            args.output_dir,args.window_minutes,args.folds,args.seed)

if __name__ == '__main__':main()
