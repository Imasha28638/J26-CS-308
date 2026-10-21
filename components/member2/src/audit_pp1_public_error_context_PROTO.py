#!/usr/bin/env python3
"""Read-only, event-grounded audit of LightGBM test-window errors.

Uses publisher-provided event labels; creates context reports without changing
models, labels, thresholds, or the publisher-defined train/test partition.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def read_csv(path: Path, required: set[str]) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(f'Missing required input: {path}')
    with path.open('r', newline='', encoding='utf-8-sig') as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f'{path.name}: missing columns {sorted(missing)}')
        result = list(reader)
    if not result:
        raise ValueError(f'{path.name}: input is empty')
    return result


def parse_utc(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError(f'Timestamp without timezone: {s}')
    return dt.astimezone(timezone.utc)


def window_start(s: str, minutes: int) -> str:
    t = parse_utc(s)
    t = t.replace(minute=(t.minute // minutes) * minutes, second=0, microsecond=0)
    return t.strftime('%Y-%m-%dT%H:%M:%SZ')


def write_csv(path: Path, rows: list[dict], columns: list[str]):
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)


def stable_json(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)


def operation_counts(rows: list[dict], positive: str | None = None):
    filtered = rows if positive is None else [r for r in rows if r['observed_positive_flag'] == positive]
    return dict(sorted(Counter(r['event_name'] for r in filtered).items()))


def audit(test_events: Path, predictions: Path, output_dir: Path, minutes: int = 5,
          neighborhood_minutes: int = 30, threshold: float = 0.5):
    if minutes < 1 or 60 % minutes or neighborhood_minutes < 0:
        raise ValueError('window minutes must divide 60; neighborhood must be >=0')
    events = read_csv(test_events, {
        'session_id', 'event_id', 'event_time', 'event_name', 'event_source',
        'observed_positive_flag', 'read_only', 'error_code', 'scenario_id', 'source_split',
    })
    preds = read_csv(predictions, {
        'session_id','window_start','label_binary','positive_event_count',
        'window_event_count','publisher_attack_scenarios','prob_LightGBM',
        'prob_Random_Forest','prob_XGBoost','prob_LSTM','stacked_malicious_score',
    })
    by_window = defaultdict(list)
    for event in events:
        if event['source_split'] != 'test':
            raise ValueError('Only publisher test events are permitted for this audit')
        if event['observed_positive_flag'] not in ('0', '1'):
            raise ValueError('Malformed publisher event label')
        key = (event['session_id'], window_start(event['event_time'], minutes))
        by_window[key].append(event)
    by_pred = {}
    for p in preds:
        key = (p['session_id'], p['window_start'])
        if key in by_pred:
            raise ValueError(f'Repeated prediction window: {key}')
        by_pred[key] = p
    if set(by_window) != set(by_pred):
        missing = len(set(by_window) - set(by_pred))
        unexpected = len(set(by_pred) - set(by_window))
        raise ValueError(f'Window reconciliation failed: {missing} event windows without predictions; '
                         f'{unexpected} predictions without event windows')
    for key, rows in by_window.items():
        p = by_pred[key]
        positives = [r for r in rows if r['observed_positive_flag'] == '1']
        scenarios = '|'.join(sorted({r['scenario_id'] for r in positives if r['scenario_id']}))
        if (int(p['label_binary']) != int(bool(positives)) or
            int(p['window_event_count']) != len(rows) or
            int(p['positive_event_count']) != len(positives) or
            p['publisher_attack_scenarios'] != scenarios):
            raise ValueError(f'Label/count/scenario mismatch for {key}; do not reinterpret publisher labels')
    actor_windows = defaultdict(list)
    for actor, start in by_window:
        actor_windows[actor].append(start)
    for starts in actor_windows.values():
        starts.sort()
    error_rows, nearby_keys = [], set()
    timeline_rows = []
    for key, p in sorted(by_pred.items()):
        label = int(p['label_binary'])
        flag = float(p['prob_LightGBM']) >= threshold
        if flag == bool(label):
            continue
        actor, start = key
        failure = 'FALSE_NEGATIVE' if label else 'FALSE_POSITIVE'
        t = parse_utc(start)
        neighbors = [(actor, other) for other in actor_windows[actor]
                     if abs((parse_utc(other) - t).total_seconds()) <= neighborhood_minutes * 60]
        nearby_keys.update(neighbors)
        attack_neighbor_keys = [item for item in neighbors if int(by_pred[item]['label_binary']) == 1]
        other_attack_keys = [item for item in attack_neighbor_keys if item != key]
        near_attack_keys = [(actor, other) for other in actor_windows[actor]
                            if int(by_pred[(actor, other)]['label_binary']) == 1]
        closest = min(near_attack_keys,
                      key=lambda k: abs((parse_utc(k[1]) - t).total_seconds()), default=None)
        rows = by_window[key]
        ro = Counter(r['read_only'].strip().lower() for r in rows)
        unknown_ro = sum(v for k, v in ro.items() if k not in ('true', 'false'))
        if unknown_ro:
            raise ValueError(f'Invalid read_only in {key}')
        error_rows.append({
            'error_type': failure,
            'session_id': actor,
            'window_start': start,
            'event_count': len(rows),
            'positive_event_count': int(p['positive_event_count']),
            'publisher_attack_scenarios': p['publisher_attack_scenarios'],
            'read_only_count': ro['true'], 'write_count': ro['false'],
            'error_event_count': sum(bool(r['error_code']) for r in rows),
            'unique_api_count': len({r['event_name'] for r in rows}),
            'api_operations': stable_json(operation_counts(rows)),
            'publisher_attack_operations': stable_json(operation_counts(rows, '1')),
            'publisher_other_operations': stable_json(operation_counts(rows, '0')),
            'nearest_same_actor_attack_window': closest[1] if closest else '',
            'nearest_attack_window_offset_minutes': round((parse_utc(closest[1])-t).total_seconds()/60, 2) if closest else '',
            'other_attack_windows_within_context': len(other_attack_keys),
            'other_attack_events_within_context': sum(int(by_pred[x]['positive_event_count']) for x in other_attack_keys),
            'prob_LightGBM': p['prob_LightGBM'],
            'prob_Random_Forest': p['prob_Random_Forest'],
            'prob_XGBoost': p['prob_XGBoost'],
            'prob_LSTM': p['prob_LSTM'],
            'stacked_malicious_score': p['stacked_malicious_score'],
        })
    # Include the contextual windows for affected actors; no unrelated test records exported.
    error_keys = {(r['session_id'], r['window_start']) for r in error_rows}
    for key in sorted(nearby_keys):
        p = by_pred[key]
        rows = by_window[key]
        timeline_rows.append({
            'session_id': key[0], 'window_start': key[1],
            'is_error_window': int(key in error_keys),
            'publisher_label_binary': p['label_binary'],
            'event_count': len(rows),
            'publisher_attack_event_count': p['positive_event_count'],
            'publisher_attack_scenarios': p['publisher_attack_scenarios'],
            'read_only_count': sum(r['read_only'].lower() == 'true' for r in rows),
            'write_count': sum(r['read_only'].lower() == 'false' for r in rows),
            'api_operations': stable_json(operation_counts(rows)),
            'prob_LightGBM': p['prob_LightGBM'],
            'stacked_malicious_score': p['stacked_malicious_score'],
        })
    output_dir.mkdir(parents=True, exist_ok=True)
    error_fields = [
        'error_type','session_id','window_start','event_count','positive_event_count',
        'publisher_attack_scenarios','read_only_count','write_count','error_event_count',
        'unique_api_count','api_operations','publisher_attack_operations',
        'publisher_other_operations','nearest_same_actor_attack_window',
        'nearest_attack_window_offset_minutes','other_attack_windows_within_context',
        'other_attack_events_within_context','prob_LightGBM','prob_Random_Forest',
        'prob_XGBoost','prob_LSTM','stacked_malicious_score'
    ]
    timeline_fields = [
        'session_id','window_start','is_error_window','publisher_label_binary',
        'event_count','publisher_attack_event_count','publisher_attack_scenarios',
        'read_only_count','write_count','api_operations','prob_LightGBM',
        'stacked_malicious_score'
    ]
    write_csv(output_dir / 'public_lightgbm_error_context_PROTO.csv', error_rows, error_fields)
    write_csv(output_dir / 'public_lightgbm_actor_timeline_PROTO.csv', timeline_rows, timeline_fields)
    counts = Counter(r['error_type'] for r in error_rows)
    report = {
        'scope':'Read-only inspection of held-out publisher TestOn window errors',
        'test_events':len(events), 'test_windows':len(preds),
        'lightgbm_threshold':threshold,
        'false_negative_windows':counts['FALSE_NEGATIVE'],
        'false_positive_windows':counts['FALSE_POSITIVE'],
        'error_windows_with_other_attack_windows_within_context':sum(r['other_attack_windows_within_context']>0 for r in error_rows),
        'context_minutes_each_side':neighborhood_minutes,
        'timeline_windows':len(timeline_rows),
        'event_count_checks':'all reconciled',
        'interpretation':'Publisher benign window labels are retained; temporal proximity is evidence for review, not permission to relabel.',
        'evaluation_rule':'No threshold or feature selection on this publisher test set. Any changes require training-only selection and independent confirmation.',
    }
    (output_dir / 'public_lightgbm_error_context_report_PROTO.json').write_text(
        json.dumps(report, indent=2), encoding='utf-8')
    print('PP1 public CloudTrail error-context audit completed')
    print(f'  Reconciled test events: {len(events)} | Test windows: {len(preds)}')
    print(f"  LightGBM false negatives: {counts['FALSE_NEGATIVE']} | false positives: {counts['FALSE_POSITIVE']}")
    print('  Error windows with other attack windows within', neighborhood_minutes,
          f"minutes: {report['error_windows_with_other_attack_windows_within_context']}")
    print(f'  Contextual actor-timeline windows: {len(timeline_rows)}')
    print('  Original publisher labels and model scores preserved')
    print('  Output:', output_dir)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--test-events', type=Path, default=Path('Data/Interim/pp1_public_cloudtrail_PROTO/ariel_test_events_PROTO.csv'))
    p.add_argument('--predictions', type=Path, default=Path('Data/Experiments/pp1_public_cloudtrail_PROTO/public_test_predictions_PROTO.csv'))
    p.add_argument('--output-dir', type=Path, default=Path('Data/Experiments/pp1_public_error_context_PROTO'))
    p.add_argument('--window-minutes', type=int, default=5)
    p.add_argument('--context-minutes', type=int, default=30)
    a = p.parse_args()
    audit(a.test_events, a.predictions, a.output_dir, a.window_minutes, a.context_minutes)


if __name__ == '__main__':
    main()
