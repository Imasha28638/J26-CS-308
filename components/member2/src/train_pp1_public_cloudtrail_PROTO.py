#!/usr/bin/env python3
"""Publisher-split CloudTrail binary detection: RF, LightGBM, XGBoost, LSTM, OOF stacking.

Uses already-imported Ariel CloudTrail CSVs. Training uses only publisher TrainOn.
TestOn is never used for fitting or hyperparameter selection. Labels are used only
for target construction and final evaluation. Preserves previous model artifacts.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold

from train_pp1_binary_stack import (
    FEATURES, MAX_SEQ, SEQ_DIM, construct_models, evaluate,
    featureize_group, floor_t, lstm_predict, pad_sequences, train_lstm,
)

NAMES = ['Random Forest', 'LightGBM', 'XGBoost', 'LSTM']
REQUIRED = {
    'session_id', 'event_id', 'event_time', 'event_name', 'event_source',
    'read_only', 'error_code', 'aws_region', 'observed_positive_flag',
    'candidate_attack_class', 'scenario_id', 'source_archive', 'source_split',
}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def read_import(path: Path, expected_split: str) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(f'Missing importer output: {path}')
    with path.open('r', newline='', encoding='utf-8-sig') as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f'{path.name}: missing required fields: {sorted(missing)}')
        rows = list(reader)
    if not rows:
        raise ValueError(f'{path.name}: empty source file')
    ids = set()
    for n, r in enumerate(rows, 2):
        if r['source_split'] != expected_split:
            raise ValueError(f'{path.name}:{n}: source_split mismatch: {r["source_split"]}')
        if r['observed_positive_flag'] not in ('0', '1'):
            raise ValueError(f'{path.name}:{n}: unexpected event label')
        if not r['session_id'] or not r['event_id']:
            raise ValueError(f'{path.name}:{n}: missing actor group or event ID')
        if r['event_id'] in ids:
            raise ValueError(f'{path.name}:{n}: repeated native event ID')
        ids.add(r['event_id'])
        if r['read_only'].lower() not in ('true', 'false'):
            raise ValueError(f'{path.name}:{n}: invalid read_only')
    return rows


def make_windows(rows, minutes):
    buckets = defaultdict(list)
    for row in rows:
        time = floor_t(row['event_time'], minutes).strftime('%Y-%m-%dT%H:%M:%SZ')
        buckets[(row['session_id'], time)].append(row)
    frames, sequences, scenarios = [], [], []
    for (actor, start), group in sorted(buckets.items()):
        feat, sequence = featureize_group(group, minutes)
        positives = [r for r in group if r['observed_positive_flag'] == '1']
        present_scenarios = sorted({r['scenario_id'] for r in positives if r['scenario_id']})
        if positives and len(present_scenarios) == 0:
            raise ValueError('Positive event without scenario name')
        frames.append({
            'session_id': actor, 'window_start': start,
            'label_binary': int(bool(positives)),
            'positive_event_count': len(positives),
            'publisher_attack_scenarios': '|'.join(present_scenarios),
            'window_event_count': len(group),
            **feat,
        })
        sequences.append(sequence)
        scenarios.append(Counter(r['scenario_id'] for r in positives))
    return pd.DataFrame(frames), sequences, scenarios


def group_keys(df, strategy):
    if strategy == 'actor':
        return df.session_id.to_numpy(dtype=str)
    if strategy == 'actor-day':
        return (df.session_id + '__' + df.window_start.str[:10]).to_numpy(dtype=str)
    raise ValueError('Unsupported group policy')


def check_folds(x, y, groups, n_splits, seed):
    unique = Counter(zip(groups, y))
    positive_groups = len(set(groups[y == 1])); negative_groups = len(set(groups[y == 0]))
    if positive_groups < n_splits or negative_groups < n_splits:
        raise ValueError(f'OOF grouping cannot form {n_splits} folds: '
                         f'positive actor-groups={positive_groups}, benign actor-groups={negative_groups}. '
                         f'Run --audit-only, consider --oof-grouping actor-day, or obtain more independent groups.')
    # Try multiple seeded configurations to handle highly uneven actor activity.
    for offset in range(25):
        splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed + offset)
        plans = list(splitter.split(x, y, groups))
        if all(len(set(y[t])) == 2 and len(set(y[v])) == 2 and
               not set(groups[t]).intersection(set(groups[v])) for t, v in plans):
            return plans, seed + offset
    raise ValueError('Cannot form group-separated folds with both classes after 25 attempts. '
                     'Inspect actor/group distribution using --audit-only; do not fall back to random window folds.')


def audit_inputs(input_dir: Path, out_dir: Path, minutes: int, strategy: str, overlap_policy: str):
    manifest_path = input_dir / 'ariel_ingestion_manifest_PROTO.json'
    if not manifest_path.exists():
        raise FileNotFoundError(f'Importer manifest not found: {manifest_path}')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest.get('ready_for_experiment') is not True or manifest.get('train_test_event_id_overlap') != 0:
        raise ValueError('Importer manifest does not confirm a clean publisher train/test split')
    train_path = input_dir / 'ariel_train_events_PROTO.csv'
    test_path = input_dir / 'ariel_test_events_PROTO.csv'
    train = read_import(train_path, 'train')
    test = read_import(test_path, 'test')
    ids_train = {r['event_id'] for r in train}
    ids_test = {r['event_id'] for r in test}
    if ids_train & ids_test:
        raise ValueError('FATAL: train/test event-ID overlap in imported CSVs')
    a, a_seq, a_scenarios = make_windows(train, minutes)
    b, b_seq, b_scenarios = make_windows(test, minutes)
    a_keys = set(zip(a.session_id, a.window_start))
    b_keys = set(zip(b.session_id, b.window_start))
    overlapping_windows = a_keys & b_keys
    removed_train_windows = 0
    if overlapping_windows and overlap_policy == 'drop-train':
        mask = ~pd.Series(list(zip(a.session_id, a.window_start))).isin(overlapping_windows).to_numpy()
        removed_train_windows = int((~mask).sum())
        a = a.loc[mask].reset_index(drop=True)
        a_seq = [s for s, keep in zip(a_seq, mask) if keep]
        a_scenarios = [s for s, keep in zip(a_scenarios, mask) if keep]
    positive_train_groups = len(set(group_keys(a, strategy)[a.label_binary.to_numpy() == 1]))
    positive_test_windows = int(b.label_binary.sum())
    report = {
        'dataset': 'Ariel Cyber Cloud Log Sampling, publisher-defined TrainOn/TestOn',
        'train_events': len(train), 'train_positive_events': sum(r['observed_positive_flag']=='1' for r in train),
        'test_events': len(test), 'test_positive_events': sum(r['observed_positive_flag']=='1' for r in test),
        'train_windows_used': len(a), 'train_positive_windows_used': int(a.label_binary.sum()),
        'test_windows': len(b), 'test_positive_windows': positive_test_windows,
        'unique_train_actors': a.session_id.nunique(), 'unique_test_actors': b.session_id.nunique(),
        'actors_in_both_publisher_splits': len(set(a.session_id) & set(b.session_id)),
        'original_overlapping_actor_time_windows': len(overlapping_windows),
        'overlap_policy': overlap_policy, 'removed_training_windows': removed_train_windows,
        'oof_grouping': strategy, 'positive_oof_groups': positive_train_groups,
        'all_oof_groups': len(set(group_keys(a, strategy))),
        'train_csv_sha256': sha256_file(train_path), 'test_csv_sha256': sha256_file(test_path),
        'event_id_overlap': 0,
        'note': 'Window labels are 1 if >=1 publisher-positive event occurred in that actor/5-minute window. '
                'One actor may occur in both publisher splits; OOF actor-day grouping is not actor-disjoint. '
                'Event-level labels are not predictions by these window classifiers.',
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'public_split_audit_PROTO.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('PP1 public CloudTrail audit')
    print(f"  Train events: {len(train)}, positive: {report['train_positive_events']} | "
          f"Test events: {len(test)}, positive: {report['test_positive_events']}")
    print(f"  Train windows: {len(a)}, positive: {int(a.label_binary.sum())} | "
          f"Test windows: {len(b)}, positive: {positive_test_windows}")
    print(f"  Positive OOF groups: {positive_train_groups} ({strategy})")
    print(f"  Overlap: event IDs=0; actor/time windows={len(overlapping_windows)}; "
          f"actors appearing in both splits={report['actors_in_both_publisher_splits']}")
    print('  Audit:', out_dir / 'public_split_audit_PROTO.json')
    if overlapping_windows and overlap_policy == 'fail':
        print('  ACTION REQUIRED: overlapping actor/time windows exist; training blocked. '
              'Use --overlap-policy drop-train to discard overlapping training windows (test remains untouched).')
    return a, a_seq, a_scenarios, b, b_seq, b_scenarios, report


def train(input_dir, out_dir, minutes=5, epochs=4, folds=3, seed=4010,
          grouping='actor-day', overlap_policy='fail', audit_only=False):
    torch.set_num_threads(max(1, min(2, torch.get_num_threads())))
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    a, aseq, train_scenarios, b, bseq, b_scenarios, audit = audit_inputs(
        input_dir, out_dir, minutes, grouping, overlap_policy)
    if audit_only:
        print('  Audit-only complete. No models were trained.')
        return audit
    if audit['original_overlapping_actor_time_windows'] and overlap_policy == 'fail':
        raise ValueError('Publisher train/test actor-window overlap; model fitting intentionally blocked. '
                         'Review public_split_audit_PROTO.json; optionally use --overlap-policy drop-train.')
    xtr = a[FEATURES].to_numpy(dtype=float); ytr = a.label_binary.to_numpy(dtype=int)
    xte = b[FEATURES].to_numpy(dtype=float); yte = b.label_binary.to_numpy(dtype=int)
    if len(set(ytr)) != 2 or len(set(yte)) != 2:
        raise ValueError('Train/test windows must include both classes')
    seqtr, lentr = pad_sequences(aseq)
    seqte, lente = pad_sequences(bseq)
    groups = group_keys(a, grouping)
    plan, fold_seed = check_folds(xtr, ytr, groups, folds, seed)
    oof = np.zeros((len(a), 4), dtype=float)
    test_probs = np.zeros((len(b), 4), dtype=float)
    for number, (fit_idx, val_idx) in enumerate(plan, 1):
        for j, (name, model) in enumerate(construct_models(seed + number)):
            model.fit(xtr[fit_idx], ytr[fit_idx])
            oof[val_idx, j] = model.predict_proba(xtr[val_idx])[:, 1]
        lstm = train_lstm(seqtr[fit_idx], lentr[fit_idx], ytr[fit_idx], seed + number, epochs)
        oof[val_idx, 3] = lstm_predict(lstm, seqtr[val_idx], lentr[val_idx])
        print(f'  Group-separated OOF fold {number}/{folds} finished')
    base = {}
    for j, (name, model) in enumerate(construct_models(seed)):
        model.fit(xtr, ytr)
        test_probs[:, j] = model.predict_proba(xte)[:, 1]
        base[name] = model
        print(f'  Trained {name}')
    lstm = train_lstm(seqtr, lentr, ytr, seed, epochs)
    test_probs[:, 3] = lstm_predict(lstm, seqte, lente)
    meta = LogisticRegression(C=.7, max_iter=2000, random_state=seed)
    meta.fit(oof, ytr)
    stack = meta.predict_proba(test_probs)[:, 1]
    hard_votes = (test_probs >= .5).sum(axis=1)
    hard = (hard_votes >= 3).astype(float)  # conservative tie => benign, explicit 3-of-4 majority
    soft = test_probs.mean(axis=1)
    metrics = {name: evaluate(yte, test_probs[:, j]) for j, name in enumerate(NAMES)}
    metrics['Stacking ensemble'] = evaluate(yte, stack)
    metrics['Hard voting (3-of-4)'] = evaluate(yte, hard)
    metrics['Soft voting'] = evaluate(yte, soft)
    predictions = b[['session_id', 'window_start', 'label_binary', 'positive_event_count',
                     'publisher_attack_scenarios', 'window_event_count']].copy()
    for j, name in enumerate(NAMES):
        predictions['prob_' + name.replace(' ', '_')] = test_probs[:, j]
    predictions['stacked_malicious_score'] = stack
    predictions['predicted_binary'] = (stack >= .5).astype(int)
    predictions.to_csv(out_dir / 'public_test_predictions_PROTO.csv', index=False, encoding='utf-8-sig')
    oof_frame = a[['session_id', 'window_start', 'label_binary']].copy()
    oof_frame['oof_group'] = groups
    for j, name in enumerate(NAMES):
        oof_frame['oof_' + name.replace(' ', '_')] = oof[:, j]
    oof_frame.to_csv(out_dir / 'public_oof_meta_training_PROTO.csv', index=False, encoding='utf-8-sig')
    a.assign(source_split='train').to_csv(out_dir / 'public_train_window_features_PROTO.csv', index=False, encoding='utf-8-sig')
    b.assign(source_split='test').to_csv(out_dir / 'public_test_window_features_PROTO.csv', index=False, encoding='utf-8-sig')
    scenario_report = []
    seen_train_scenarios = set(s for group in train_scenarios for s in group)
    all_scenarios = sorted(set(s for group in b_scenarios for s in group))
    for name in all_scenarios:
        indices = [i for i, count in enumerate(b_scenarios) if count.get(name, 0)>0]
        detected = int(np.sum(stack[indices] >= .5))
        covered_events = int(sum(b_scenarios[i][name] for i in indices if stack[i] >= .5))
        total_events = int(sum(b_scenarios[i][name] for i in indices))
        scenario_report.append({
            'scenario': name, 'seen_in_training': name in seen_train_scenarios,
            'positive_test_windows': len(indices),
            'detected_positive_windows': detected,
            'window_recall': round(detected/len(indices), 6),
            'publisher_positive_events_in_scenario': total_events,
            'events_in_detected_windows': covered_events,
            'event_coverage_by_window': round(covered_events/total_events, 6),
        })
    pd.DataFrame(scenario_report).to_csv(
        out_dir / 'public_attack_scenario_recall_PROTO.csv', index=False, encoding='utf-8-sig')
    joblib.dump({'models': base, 'meta': meta, 'features': FEATURES},
                out_dir / 'tree_models_and_meta_PROTO.joblib')
    torch.save({'state_dict': lstm.state_dict(), 'sequence_dim': SEQ_DIM, 'max_seq': MAX_SEQ},
               out_dir / 'lstm_PROTO.pt')
    (out_dir / 'feature_whitelist.json').write_text(json.dumps({
        'numeric_features': FEATURES,
        'excluded': ['observed_positive_flag', 'candidate_attack_class', 'scenario_id',
                     'source_archive', 'source_split', 'session_id', 'event_id', 'source_row_id',
                     'publisher_attack_scenarios', 'window_start', 'positive_event_count']
    }, indent=2), encoding='utf-8')
    report = {
        'experiment': 'PP1 Ariel public AWS CloudTrail publisher-split supervised window detection',
        'source_url': 'https://github.com/ArielCyber/cloud_log_sampling',
        'window_minutes': minutes, 'seed': seed,
        'training_events': audit['train_events'], 'test_events': audit['test_events'],
        'train_windows': len(a), 'test_windows': len(b),
        'positive_train_windows': int(ytr.sum()), 'positive_test_windows': int(yte.sum()),
        'publisher_train_test_event_overlap': 0,
        'actor_overlap_between_splits': audit['actors_in_both_publisher_splits'],
        'original_actor_window_overlap': audit['original_overlapping_actor_time_windows'],
        'removed_train_windows': audit['removed_training_windows'],
        'out_of_fold_grouping': grouping, 'fold_split_seed': fold_seed,
        'model_count': 4, 'meta_model': 'LogisticRegression trained on group-separated OOF predictions',
        'model_metrics': metrics,
        'scenarios_seen_in_training': sorted(seen_train_scenarios),
        'test_only_scenarios': sorted(set(all_scenarios) - seen_train_scenarios),
        'scenario_wise_detection': scenario_report,
        'metric_scope': 'Actor/time-window binary task; not event-level attack classifier performance',
        'limitations': [
            'Labels are supplied by the dataset publisher; the repository describes should_sample=true as attack events.',
            'Positive window target means at least one positive event; window metrics are not record-level metrics.',
            'Seven attack scenarios present only in the test split; per-scenario recall is essential.',
            'Publisher train/test event IDs do not overlap; some actor identities may overlap between splits.',
            'Actor-day OOF separation (when selected) does not imply actor-disjoint folds.',
            'The trained model has not been calibrated for a deployment alert threshold.',
            'Models predict binary windows, not the attack class name.',
        ]
    }
    (out_dir / 'public_experiment_report_PROTO.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('PP1 public CloudTrail training completed')
    for name, metric in metrics.items():
        print(f"  {name:23s} F1={metric['f1']:.3f}  Precision={metric['precision']:.3f}  Recall={metric['recall']:.3f}")
    print(f"  Per-scenario report: {out_dir / 'public_attack_scenario_recall_PROTO.csv'}")
    print(f'  Model artifacts: {out_dir}')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input-dir', type=Path, default=Path('Data/Interim/pp1_public_cloudtrail_PROTO'))
    p.add_argument('--output-dir', type=Path, default=Path('Data/Experiments/pp1_public_cloudtrail_PROTO'))
    p.add_argument('--window-minutes', type=int, default=5)
    p.add_argument('--lstm-epochs', type=int, default=4)
    p.add_argument('--folds', type=int, default=3)
    p.add_argument('--seed', type=int, default=4010)
    p.add_argument('--oof-grouping', choices=['actor-day', 'actor'], default='actor-day')
    p.add_argument('--overlap-policy', choices=['fail', 'drop-train'], default='fail')
    p.add_argument('--audit-only', action='store_true')
    args = p.parse_args()
    if args.window_minutes < 1 or 60 % args.window_minutes != 0:
        p.error('--window-minutes must be a positive divisor of 60')
    if args.lstm_epochs < 1 or args.folds < 3:
        p.error('--lstm-epochs >=1 and --folds >=3 required')
    train(args.input_dir, args.output_dir, args.window_minutes, args.lstm_epochs,
          args.folds, args.seed, args.oof_grouping, args.overlap_policy, args.audit_only)


if __name__ == '__main__':
    main()
