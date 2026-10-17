#!/usr/bin/env python3
"""PP1: train-only, actor-day-separated LightGBM window/feature study.

Does not read publisher TestOn, fit final deployment models, or alter checkpoints.
Feature study is exploratory: the test split has already been examined upstream.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)

from train_pp1_binary_stack import FEATURES, timeparse
from train_pp1_public_cloudtrail_PROTO import (
    check_folds, group_keys, make_windows, read_import,
)
from lightgbm import LGBMClassifier

S3_FAMILIES = (
    's3_get_object', 's3_put_object', 's3_delete_object',
    's3_bucket_read', 's3_bucket_mutation', 's3_list',
)
CONTEXT_COLS = (
    'past15_event_count', 'past15_write_count', 'past15_error_count',
    'past15_unique_api_count', 'past15_s3_get_object_count',
    'past15_s3_put_object_count', 'past15_s3_delete_object_count',
)


def sha256_file(path: Path):
    sha = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024*1024), b''):
            sha.update(block)
    return sha.hexdigest()


def operation_family(event_name: str, event_source: str) -> str | None:
    if str(event_source).lower() != 's3.amazonaws.com':
        return None
    n = str(event_name)
    if n.startswith(('GetObject', 'HeadObject', 'SelectObject')):
        return 's3_get_object'
    if n.startswith(('PutObject', 'UploadPart', 'CompleteMultipartUpload', 'CreateMultipartUpload')):
        return 's3_put_object'
    if n.startswith(('DeleteObject', 'AbortMultipartUpload')):
        return 's3_delete_object'
    if n.startswith(('GetBucket', 'HeadBucket')):
        return 's3_bucket_read'
    if n.startswith(('PutBucket', 'DeleteBucket', 'CreateBucket')):
        return 's3_bucket_mutation'
    if n.startswith(('List', 'GetPublicAccessBlock')):
        return 's3_list'
    return None


def s3_values(events: list[dict]) -> dict:
    result = {'s3_' + 'total_count': 0, 's3_unique_api_count': 0}
    result.update({fam + '_count': 0 for fam in S3_FAMILIES})
    api_names = set()
    for row in events:
        if str(row['event_source']).lower() != 's3.amazonaws.com':
            continue
        result['s3_total_count'] += 1
        api_names.add(row['event_name'])
        family = operation_family(row['event_name'], row['event_source'])
        if family:
            result[family + '_count'] += 1
    result['s3_unique_api_count'] = len(api_names)
    result['s3_object_change_count'] = (
        result['s3_put_object_count'] + result['s3_delete_object_count']
    )
    return result


def add_features(train_rows: list[dict], windows: pd.DataFrame, minutes: int, use_s3: bool, use_context: bool):
    # Only train-source rows, indexed by (actor, actor-day). A historical feature
    # never crosses the actor-day boundary used for CV grouping.
    grouped = defaultdict(list)
    for row in train_rows:
        ts = timeparse(row['event_time'])
        key = (row['session_id'], ts.strftime('%Y-%m-%d'))
        grouped[key].append((ts, row))
    for key in grouped:
        grouped[key].sort(key=lambda p: (p[0], p[1]['event_id']))
    extras = []
    for _, win in windows.iterrows():
        start = timeparse(win['window_start'])
        end = start + timedelta(minutes=minutes)
        key = (win['session_id'], start.strftime('%Y-%m-%d'))
        items = grouped.get(key, ())
        current = [row for ts, row in items if start <= ts < end]
        if not current:
            raise ValueError('Feature audit: no matching actor/date events for a window')
        values = {}
        if use_s3:
            values.update(s3_values(current))
        if use_context:
            begin = max(start - timedelta(minutes=15),
                        start.replace(hour=0, minute=0, second=0, microsecond=0))
            past = [r for ts, r in items if begin <= ts < start]
            counts = s3_values(past)
            values.update({
                'past15_event_count': len(past),
                'past15_write_count': sum(str(r['read_only']).lower() == 'false' for r in past),
                'past15_error_count': sum(bool(r['error_code']) for r in past),
                'past15_unique_api_count': len({r['event_name'] for r in past}),
                'past15_s3_get_object_count': counts['s3_get_object_count'],
                'past15_s3_put_object_count': counts['s3_put_object_count'],
                'past15_s3_delete_object_count': counts['s3_delete_object_count'],
            })
        extras.append(values)
    if not use_s3 and not use_context:
        return windows.copy(), []
    extra_frame = pd.DataFrame(extras, index=windows.index)
    if extra_frame.isna().any().any():
        raise ValueError('Feature audit: missing values in derived features')
    if use_context and any(extra_frame['past15_event_count'] < 0):
        raise ValueError('Negative context count')
    return pd.concat([windows.copy(), extra_frame], axis=1), list(extra_frame.columns)


def lightgbm(seed: int):
    return LGBMClassifier(
        n_estimators=90, learning_rate=.06, max_depth=4, num_leaves=15,
        min_child_samples=8, random_state=seed, verbosity=-1,
        n_jobs=2, class_weight='balanced',
    )


def evaluate_oof(y, scores):
    pred = (scores >= .5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel().tolist()
    return {
        'tp': int(tp), 'fp': int(fp), 'fn': int(fn), 'tn': int(tn),
        'precision': float(precision_score(y, pred, zero_division=0)),
        'recall': float(recall_score(y, pred, zero_division=0)),
        'f1': float(f1_score(y, pred, zero_division=0)),
        'average_precision': float(average_precision_score(y, scores)),
        'roc_auc': float(roc_auc_score(y, scores)),
        'false_alerts_per_1000_benign_windows': float(1000 * fp / max(1, fp+tn)),
    }


def run_study(train_events: str, output_dir: str, folds: int=3, seed: int=4010):
    path = Path(train_events)
    rows = read_import(path, 'train')
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    # Same 2-minute folds for all 2-minute variants. Never evaluate on TestOn here.
    configs = [
        ('baseline_5min', 5, False, False),
        ('baseline_2min', 2, False, False),
        ('s3_2min', 2, True, False),
        ('context_2min', 2, False, True),
        ('s3_context_2min', 2, True, True),
    ]
    audit = {
        'training_file': str(path), 'sha256': sha256_file(path),
        'train_event_count': len(rows),
        'positive_events': sum(r['observed_positive_flag']=='1' for r in rows),
        'scope': 'Publisher TrainOn only; no TestOn labels, scores, or models accessed',
        'group_policy': 'actor-day, context blocked across actor-day boundary',
        'caveat': 'Positive windows may share attack sequences. Models selected after inspecting previous TestOn results remain exploratory until external confirmation.',
        'configs': [],
    }
    score_tables=[]
    for config_name, minutes, use_s3, use_context in configs:
        windows, _, _ = make_windows(rows, minutes)
        full, extra_cols = add_features(rows, windows, minutes, use_s3, use_context)
        cols = list(FEATURES) + extra_cols
        x = full[cols].to_numpy(dtype=float)
        y = full['label_binary'].to_numpy(dtype=int)
        groups = group_keys(full, 'actor-day')
        plans, fold_seed = check_folds(x, y, groups, folds, seed)
        preds = np.full(len(full), np.nan)
        for fold_num, (fit_idx, val_idx) in enumerate(plans, 1):
            if set(groups[fit_idx]) & set(groups[val_idx]):
                raise ValueError('Fatal: train/validation group overlap')
            model = lightgbm(seed + fold_num)
            model.fit(x[fit_idx], y[fit_idx])
            preds[val_idx] = model.predict_proba(x[val_idx])[:, 1]
        if not np.isfinite(preds).all():
            raise ValueError('Fatal: missing OOF scores')
        metrics = evaluate_oof(y, preds)
        row = {
            'configuration': config_name, 'window_minutes': minutes,
            'positive_windows': int(y.sum()), 'total_windows': len(y),
            'positive_actor_day_groups': len(set(groups[y==1])),
            'independent_oof_groups': len(set(groups)),
            'cv_fold_seed': fold_seed, 'feature_count': len(cols),
            **metrics,
        }
        audit['configs'].append(row)
        score_tables.append(pd.DataFrame({
            'configuration': config_name, 'actor_day': groups,
            'session_id': full['session_id'].values,
            'window_start': full['window_start'].values,
            'label_binary': y, 'oof_score': preds,
        }))
        print(f"  {config_name:<19} windows={len(y):5d}, pos={int(y.sum()):2d}, "
              f"F1={metrics['f1']:.3f}, P={metrics['precision']:.3f}, "
              f"R={metrics['recall']:.3f}, FP={metrics['fp']}, AP={metrics['average_precision']:.3f}")
    pd.DataFrame(audit['configs']).to_csv(output/'training_only_feature_comparison_PROTO.csv', index=False, encoding='utf-8-sig')
    pd.concat(score_tables, ignore_index=True).to_csv(output/'training_only_oof_scores_PROTO.csv', index=False, encoding='utf-8-sig')
    (output/'training_only_feature_study_PROTO.json').write_text(json.dumps(audit, indent=2), encoding='utf-8')
    print('  Train-only feature comparison complete. Existing models unchanged.')
    print('  Output:', output)
    return audit


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--train-events', required=True)
    p.add_argument('--output-dir', required=True)
    p.add_argument('--folds', type=int, default=3)
    p.add_argument('--seed', type=int, default=4010)
    a=p.parse_args()
    run_study(a.train_events,a.output_dir,a.folds,a.seed)


if __name__ == '__main__':
    main()
