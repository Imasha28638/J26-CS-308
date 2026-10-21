#!/usr/bin/env python3
"""Training-only audit for window sparsity, S3 API coverage, and prior actor context.

Reads publisher TrainOn events only; never reads TestOn, predicts, relabels,
fits models, or changes current evaluation artifacts.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from statistics import median

REQUIRED = {'session_id','event_id','event_time','event_name','event_source',
            'observed_positive_flag','scenario_id','source_split','read_only'}
WINDOWS = (1, 2, 5, 10, 15)


def parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('CloudTrail time requires explicit timezone')
    return dt.astimezone(timezone.utc)


def bucket_time(t: datetime, minutes: int) -> datetime:
    return t.replace(minute=(t.minute // minutes) * minutes, second=0, microsecond=0)


def read_train(path: Path) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(f'Missing TrainOn file: {path}')
    with path.open(newline='', encoding='utf-8-sig') as file:
        reader = csv.DictReader(file)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f'TrainOn CSV missing {sorted(missing)}')
        rows = list(reader)
    if not rows:
        raise ValueError('TrainOn input is empty')
    seen = set()
    for i, r in enumerate(rows, 2):
        if r['source_split'] != 'train':
            raise ValueError(f'Row {i}: expected publisher TrainOn only')
        if r['observed_positive_flag'] not in ('0','1'):
            raise ValueError(f'Row {i}: invalid positive flag')
        if not r['event_id'] or not r['session_id']:
            raise ValueError(f'Row {i}: missing event ID or actor ID')
        if r['event_id'] in seen:
            raise ValueError(f'Row {i}: duplicate event ID')
        seen.add(r['event_id'])
        if r['read_only'].strip().lower() not in ('true', 'false'):
            raise ValueError(f'Row {i}: invalid read_only value')
        r['_dt'] = parse_time(r['event_time'])
    return rows


def write_rows(path: Path, fields: list[str], rows: list[dict]):
    with path.open('w', newline='', encoding='utf-8-sig') as file:
        writer=csv.DictWriter(file, fieldnames=fields, extrasaction='ignore')
        writer.writeheader(); writer.writerows(rows)


def analyze(train_csv: Path, out_dir: Path, minute_options=WINDOWS, context_minutes=15):
    if context_minutes < 1 or not minute_options or any(m < 1 or 60 % m for m in minute_options):
        raise ValueError('Window lengths must divide 60; context must be positive')
    rows = read_train(train_csv)
    by_actor = defaultdict(list)
    api_counts=Counter()
    pos_api_counts=Counter()
    s3_counts = Counter()
    s3_positive = Counter()
    for r in rows:
        by_actor[r['session_id']].append(r)
        api = (r['event_source'], r['event_name'])
        api_counts[api] += 1
        if r['observed_positive_flag'] == '1':
            pos_api_counts[api] += 1
        if 's3' in r['event_source'].lower():
            s3_counts[r['event_name']] += 1
            if r['observed_positive_flag'] == '1':
                s3_positive[r['event_name']] += 1
    for actor in by_actor:
        by_actor[actor].sort(key=lambda r: r['_dt'])
    sweep=[]
    five_positive=[]
    for minutes in minute_options:
        bins=defaultdict(list)
        for r in rows:
            bins[(r['session_id'], bucket_time(r['_dt'], minutes))].append(r)
        pos_windows = [(key, ev) for key,ev in bins.items()
                       if any(r['observed_positive_flag'] == '1' for r in ev)]
        counts = [len(ev) for _,ev in pos_windows]
        pos_groups = {(key[0], key[1].strftime('%Y-%m-%d')) for key,ev in pos_windows}
        sweep.append({
            'window_minutes': minutes,
            'total_train_windows': len(bins),
            'attack_containing_windows':len(pos_windows),
            'non_attack_windows':len(bins) - len(pos_windows),
            'attack_window_fraction':round(len(pos_windows)/len(bins),6),
            'positive_actor_day_groups':len(pos_groups),
            'attack_windows_with_at_most_2_events':sum(n <= 2 for n in counts),
            'median_events_in_attack_window':median(counts) if counts else 0,
            'positive_events_in_training':sum(r['observed_positive_flag']=='1' for r in rows),
        })
        if minutes == 5:
            five_positive=pos_windows
    context_rows=[]
    for (actor, start), events in sorted(five_positive):
        previous=[r for r in by_actor[actor]
                  if start - timedelta(minutes=context_minutes) <= r['_dt'] < start]
        current_positive=[r for r in events if r['observed_positive_flag']=='1']
        scenarios=sorted({r['scenario_id'] for r in current_positive if r['scenario_id']})
        context_rows.append({
            'session_id':actor,
            'window_start_utc':start.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'attack_window_event_count':len(events),
            'publisher_positive_events':len(current_positive),
            'publisher_attack_scenarios':'|'.join(scenarios),
            'current_api_operations':json.dumps(dict(sorted(Counter(r['event_name'] for r in events).items()))),
            'prior_context_minutes':context_minutes,
            'preceding_event_count':len(previous),
            'preceding_write_count':sum(r['read_only'].lower()=='false' for r in previous),
            'preceding_api_operations':json.dumps(dict(sorted(Counter(r['event_name'] for r in previous).items()))),
        })
    api_rows=[]
    for (source,name),count in sorted(api_counts.items(), key=lambda p:(-p[1],p[0])):
        pos=pos_api_counts[(source,name)]
        api_rows.append({'event_source':source,'event_name':name,
                         'training_events':count,'publisher_positive_events':pos,
                         'publisher_non_positive_events':count-pos,
                         'positive_event_fraction':round(pos/count,6)})
    out_dir.mkdir(parents=True, exist_ok=True)
    write_rows(out_dir/'training_window_sweep_PROTO.csv', list(sweep[0]), sweep)
    if context_rows:
        write_rows(out_dir/'training_positive_window_context_PROTO.csv',list(context_rows[0]),context_rows)
    else:
        write_rows(out_dir/'training_positive_window_context_PROTO.csv',
                   ['session_id','window_start_utc','attack_window_event_count','publisher_positive_events',
                    'publisher_attack_scenarios','current_api_operations','prior_context_minutes',
                    'preceding_event_count','preceding_write_count','preceding_api_operations'],[])
    write_rows(out_dir/'training_api_label_distribution_PROTO.csv',list(api_rows[0]),api_rows)
    report={
        'scope':'Publisher TrainOn ONLY; neither test data nor stored predictions read',
        'source_file':str(train_csv),
        'source_sha256':hashlib.sha256(train_csv.read_bytes()).hexdigest(),
        'training_events':len(rows),
        'training_publisher_positive_events':sum(r['observed_positive_flag']=='1' for r in rows),
        'positive_actor_days':len({(r['session_id'],r['_dt'].date()) for r in rows if r['observed_positive_flag']=='1'}),
        'window_sweep':sweep,
        'positive_five_min_windows_with_preceding_context':sum(bool(r['preceding_event_count']) for r in context_rows),
        'positive_five_min_windows_total':len(context_rows),
        's3_training_events':sum(s3_counts.values()),
        's3_publisher_positive_events':sum(s3_positive.values()),
        's3_publisher_positive_api_operations':dict(s3_positive.most_common()),
        'next_step_rule':'Use training-only group-separated validation to select a window/context/feature design. Hold TestOn untouched until design is frozen.',
    }
    (out_dir/'training_feature_audit_PROTO.json').write_text(json.dumps(report, indent=2),encoding='utf-8')
    print('PP1 publisher TrainOn behavioral-feature audit completed')
    print(f"  Training events: {report['training_events']} | positive events: {report['training_publisher_positive_events']}")
    print(f"  Positive actor-day groups: {report['positive_actor_days']}")
    for r in sweep:
        print(f"  {r['window_minutes']:>2}-min windows: total={r['total_train_windows']:>5} "
              f"positive={r['attack_containing_windows']:>3} "
              f"positive actor-day groups={r['positive_actor_day_groups']}")
    print(f"  5-min positive windows with preceding {context_minutes}-min actor context: "
          f"{report['positive_five_min_windows_with_preceding_context']}/{len(context_rows)}")
    print('  Publisher TestOn not read. Existing checkpoints unchanged.')
    print('  Output:', out_dir)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--train-events',type=Path,default=Path('Data/Interim/pp1_public_cloudtrail_PROTO/ariel_train_events_PROTO.csv'))
    p.add_argument('--output-dir',type=Path,default=Path('Data/Experiments/pp1_public_training_audit_PROTO'))
    p.add_argument('--context-minutes',type=int,default=15)
    a=p.parse_args()
    analyze(a.train_events,a.output_dir,context_minutes=a.context_minutes)

if __name__ == '__main__':
    main()
