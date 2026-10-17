#!/usr/bin/env python3
"""Reconcile unlabeled CloudTrail window alerts to input records; export evidence review.

Does not change labels, model scores, thresholds or model files.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PATTERN = frozenset({
    'DescribeInstances', 'DescribeInternetGateways', 'DescribeNatGateways',
    'DescribeNetworkAcls', 'DescribeRouteTables', 'DescribeSecurityGroups',
    'DescribeSubnets', 'GetCallerIdentity', 'LookupEvents'
})
DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(x) for x in (
    '192.0.2.0/24','198.51.100.0/24','203.0.113.0/24'
))


def parse_utc(value):
    dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError(f'Timestamp missing timezone: {value!r}')
    return dt.astimezone(timezone.utc)


def window_start(value, minutes):
    dt = parse_utc(value)
    return dt.replace(minute=(dt.minute//minutes)*minutes, second=0, microsecond=0).isoformat().replace('+00:00','Z')


def actor_hash(ip):
    return hashlib.sha256(('ip-only\x1f'+ip).encode()).hexdigest()[:20]


def read_rows(path):
    with Path(path).open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError(f'Empty CSV: {path}')
        yield from reader


def load_background(path, minutes):
    required = ('event_time', 'event_name', 'source_ip_address', 'read_only', 'row_hash')
    grouped = defaultdict(list)
    seen = set()
    duplicates = 0
    source_count = 0
    ips = set()
    for row in read_rows(path):
        source_count += 1
        missing = [k for k in required if not row.get(k, '').strip()]
        if missing:
            raise ValueError(f'Background row {source_count} lacks fields: {missing}')
        if row.get('ground_truth_status', 'unlabeled').lower() not in ('', 'unlabeled', 'unverified'):
            raise ValueError('Review source unexpectedly contains adjudicated ground truth')
        source_id = row['row_hash']
        if source_id in seen:
            duplicates += 1
            continue
        seen.add(source_id)
        ip = row['source_ip_address'].strip()
        ips.add(ip)
        key = (actor_hash(ip), window_start(row['event_time'], minutes))
        grouped[key].append(row)
    return grouped, source_count, duplicates, ips


def documentation_address(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in DOCUMENTATION_NETWORKS)
    except ValueError:
        return False


def family(ops):
    s = set(ops)
    if len(ops) == 9 and len(s) == 9 and s == PATTERN:
        return 'full_nine_operation_inventory'
    if 7 <= len(ops) <= 8 and len(s) == len(ops) and 'LookupEvents' in s and s.issubset(PATTERN):
        return 'partial_inventory_seven_eight'
    return 'other_behavior'


def reconcile(scores_path, background_path, output_dir, minutes=5, seed=4010):
    if minutes < 1 or 60 % minutes:
        raise ValueError('Window size must divide 60 minutes')
    groups, raw_count, dup_count, ips = load_background(background_path, minutes)
    scored = list(read_rows(scores_path))
    if not scored:
        raise ValueError('No scored windows')
    keys = set()
    enriched = []
    family_counts = Counter()
    family_flagged = Counter()
    for idx, r in enumerate(scored, 1):
        required_score = ('actor_hash','window_start_utc','event_count','api_operations','predicted_binary',
                          'stacking_score','score_rf','score_lightgbm','score_xgboost','score_lstm')
        if any(k not in r for k in required_score):
            raise ValueError(f'Score CSV schema missing fields; required: {required_score}')
        key = (r['actor_hash'], r['window_start_utc'])
        if key in keys:
            raise ValueError(f'Duplicate scored window: {key}')
        keys.add(key)
        events = groups.get(key)
        if events is None:
            raise ValueError(f'Window {key} has no matching raw records')
        if len(events) != int(r['event_count']):
            raise ValueError(f'Event count mismatch for {key}: score {r["event_count"]}, raw {len(events)}')
        names = Counter(e['event_name'] for e in events)
        try:
            described = json.loads(r['api_operations'])
        except json.JSONDecodeError as exc:
            raise ValueError(f'Invalid API summary in scored window {key}') from exc
        if names != described:
            raise ValueError(f'API operation summary mismatch for {key}')
        ops = [e['event_name'] for e in sorted(events, key=lambda x: (parse_utc(x['event_time']), x['event_name']))]
        fam = family(ops)
        if r['predicted_binary'].strip() not in ('0', '1'):
            raise ValueError('Invalid prediction value')
        flagged = int(r['predicted_binary'])
        family_counts[fam] += 1
        family_flagged[fam] += flagged
        non_read = sum(e['read_only'].strip().lower() not in ('true', '1') for e in events)
        errors = sum(bool(e.get('error_code','').strip()) for e in events)
        principal_count = sum(bool(e.get('identity_arn','').strip()) for e in events)
        event_id_count = sum(bool(e.get('event_id','').strip()) for e in events)
        actor_ips = set(e['source_ip_address'] for e in events)
        enriched.append({
            'window_start_utc':r['window_start_utc'],
            'actor_hash':r['actor_hash'],
            'event_count':len(events),
            'pattern_family':fam,
            'event_sequence':json.dumps(ops),
            'unique_services':len(set(e.get('event_source','') for e in events)),
            'non_read_only_count':non_read,
            'error_count':errors,
            'native_event_id_count':event_id_count,
            'principal_arn_count':principal_count,
            'actor_source_ip_count':len(actor_ips),
            'score_rf':r['score_rf'],
            'score_lightgbm':r['score_lightgbm'],
            'score_xgboost':r['score_xgboost'],
            'score_lstm':r['score_lstm'],
            'stacking_score':r['stacking_score'],
            'predicted_binary':flagged,
            'review_status':'PENDING',
            'verified_activity':'',
            'evidence_reference':'',
            'reviewer_notes':'',
        })
    if set(groups) != keys:
        raise ValueError(f'Unscored source windows: {len(set(groups)-keys)}; score windows missing source: {len(keys-set(groups))}')
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    fields = list(enriched[0])
    with (output_dir/'background_pattern_context_PROTO.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields)
        writer.writeheader()
        writer.writerows(enriched)
    flagged_by_fam = defaultdict(list)
    for item in enriched:
        if item['predicted_binary']:
            flagged_by_fam[item['pattern_family']].append(item)
    low=[r for r in enriched if not r['predicted_binary']]
    random.Random(seed).shuffle(low)
    sample = []
    for fam, rows in sorted(flagged_by_fam.items()):
        picks=sorted(rows,key=lambda x:-float(x['stacking_score']))[:3]
        sample.extend(picks)
    sample.extend(low[:6])
    with (output_dir/'background_evidence_review_PROTO.csv').open('w', encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields)
        writer.writeheader()
        writer.writerows(sample)
    doc_ips=sorted(ip for ip in ips if documentation_address(ip))
    report={
        'purpose':'Background discovery workflow investigation; no ground truth inferred',
        'source_rows':raw_count,
        'exact_source_rows_skipped':dup_count,
        'reconciled_source_events':sum(len(x) for x in groups.values()),
        'scored_windows':len(enriched),
        'flagged_windows':sum(r['predicted_binary'] for r in enriched),
        'pattern_windows':dict(sorted(family_counts.items())),
        'flagged_by_pattern':dict(sorted(family_flagged.items())),
        'source_ip_group_count':len(ips),
        'documentation_range_source_ip_count':len(doc_ips),
        'documentation_range_addresses_present':len(doc_ips)>0,
        'event_rows_with_native_event_id':sum(int(e['native_event_id_count']) for e in enriched),
        'event_rows_with_principal_arn':sum(int(e['principal_arn_count']) for e in enriched),
        'event_rows_with_non_read_only':sum(int(e['non_read_only_count']) for e in enriched),
        'event_rows_with_error':sum(int(e['error_count']) for e in enriched),
        'review_sample_windows':len(sample),
        'limitations':[
            'Input background labels are unverified; no benign/attack label assigned by this audit.',
            'Documentation-range IPs may reflect privacy masking; the original source must establish collection provenance.',
            'IP-only grouping does not establish AWS principal or session identity.',
            'Review counts are not measured false-positive rates.',
        ]
    }
    (output_dir/'background_pattern_audit_PROTO.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('PP1 background workflow evidence audit completed')
    print(f'  Source rows: {raw_count} | Deduplicated events: {report["reconciled_source_events"]} | Scored windows: {len(enriched)}')
    print(f'  Flagged windows: {report["flagged_windows"]}')
    for fam,n in sorted(family_counts.items()):
        print(f'  {fam}: {n} windows, {family_flagged[fam]} flagged')
    print(f'  Native event IDs present: {report["event_rows_with_native_event_id"]} | Principal ARN fields present: {report["event_rows_with_principal_arn"]}')
    print(f'  Documentation-range source addresses present: {bool(doc_ips)}')
    print(f'  Review worksheet: {output_dir / "background_evidence_review_PROTO.csv"}')
    print('  Ground truth: requires human review and source evidence')
    return report


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--sandbox',type=Path,default=Path('Data/Interim/integration_review/sandbox.csv'))
    ap.add_argument('--scores',type=Path,default=Path('Data/Experiments/pp1_real_background_PROTO/sandbox_window_scores_PROTO.csv'))
    ap.add_argument('--output-dir',type=Path,default=Path('Data/Experiments/pp1_background_workflow_audit_PROTO'))
    ap.add_argument('--window-minutes',type=int,default=5)
    args=ap.parse_args()
    reconcile(args.scores,args.sandbox,args.output_dir,args.window_minutes)

if __name__=='__main__':
    main()
