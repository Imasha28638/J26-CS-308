#!/usr/bin/env python3
"""Import an external labeled AWS CloudTrail corpus, preserving publisher train/test splits.

The binary target is derived only from the publisher's should_sample field.
The target and attack_name are never included in numeric model inputs.
The code does not touch previous experiments or source archives.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

FILES = {
    'train_benign': 'base_a.zip',
    'train_labeled': 'train_labeled_a.zip',
    'test_labeled': 'labeled_cloudtrail_a.zip',
}
FIELDS = [
    'session_id','event_id','event_time','event_name','event_source',
    'read_only','error_code','aws_region','observed_positive_flag',
    'candidate_attack_class','data_origin','evidence_tier','scenario_id',
    'source_row_id','actor_group_kind','source_archive','source_split',
]
DUP_FIELDS = [
    'scope','event_id','first_archive','first_row','repeated_archive','repeated_row',
    'first_label','repeated_label','raw_record_matches','action',
]



def find_archive(root: Path, name: str) -> Path:
    paths = [p for p in root.rglob(name) if p.is_file()]
    if len(paths) != 1:
        raise ValueError(f'Expected exactly one {name} under {root}; found {len(paths)}. Check the extracted repository.')
    return paths[0]


def load_zip_records(path: Path) -> list[dict]:
    with zipfile.ZipFile(path) as z:
        members = [x for x in z.infolist() if x.filename.lower().endswith('.json') and not x.is_dir() and not x.filename.startswith('__MACOSX')]
        if len(members) != 1:
            raise ValueError(f'{path.name}: expected one CloudTrail JSON member, got {len(members)}')
        with z.open(members[0]) as stream:
            payload = json.load(stream)
    if not isinstance(payload, dict) or not isinstance(payload.get('Records'), list):
        raise ValueError(f'{path.name}: expected JSON object containing a Records list')
    if not payload['Records']:
        raise ValueError(f'{path.name}: Records list is empty')
    return payload['Records']


def normal_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError('missing eventTime')
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('eventTime has no timezone')
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def actor_group(e: dict, event_id: str) -> tuple[str,str]:
    identity = e.get('userIdentity') if isinstance(e.get('userIdentity'),dict) else {}
    for kind, raw in (
        ('identity_arn', identity.get('arn')),
        ('principal_id', identity.get('principalId')),
        ('source_ip_proxy', e.get('sourceIPAddress')),
        ('event_id_only', event_id),
    ):
        if raw is not None and str(raw).strip():
            h = hashlib.sha256(f'{kind}\x1f{raw}'.encode('utf-8')).hexdigest()[:24]
            return f'ariel_actor__{h}', kind
    raise ValueError('cannot construct actor grouping')


def convert(e: dict, archive: str, split: str, index: int) -> dict:
    if not isinstance(e, dict):
        raise ValueError('record is not a JSON object')
    label = e.get('should_sample')
    if type(label) is not bool:
        raise ValueError('should_sample must be boolean')
    scenario = e.get('attack_name')
    if label and (not isinstance(scenario, str) or not scenario.strip()):
        raise ValueError('attack event missing attack_name')
    if not label and scenario not in (None, ''):
        raise ValueError('benign event unexpectedly has attack_name')
    event_id = e.get('eventID')
    if not isinstance(event_id, str) or not event_id.strip():
        raise ValueError('missing native eventID')
    event_name, event_source = e.get('eventName'),e.get('eventSource')
    if not isinstance(event_name, str) or not event_name.strip():
        raise ValueError('missing eventName')
    if not isinstance(event_source, str) or not event_source.strip():
        raise ValueError('missing eventSource')
    ro = e.get('readOnly')
    if type(ro) is bool: ro_txt = str(ro).lower()
    elif isinstance(ro,str) and ro.lower() in ('true','false'):ro_txt=ro.lower()
    else:raise ValueError('missing or invalid readOnly; cannot safely build write features')
    error = e.get('errorCode')
    if error is not None and not isinstance(error,str):
        raise ValueError('errorCode must be string or null')
    sid, kind = actor_group(e,event_id)
    return {
        'session_id':sid,
        'event_id':event_id.strip(),
        'event_time':normal_timestamp(e.get('eventTime')),
        'event_name':event_name.strip(),
        'event_source':event_source.strip(),
        'read_only':ro_txt,
        'error_code':error or '',
        'aws_region':str(e.get('awsRegion') or ''),
        'observed_positive_flag':str(int(label)),
        'candidate_attack_class':scenario if label else '',
        'data_origin':'Ariel Cyber CloudTrail',
        'evidence_tier':'publisher_record_label',
        'scenario_id':scenario if label else '',
        'source_row_id':str(index),
        'actor_group_kind':kind,
        'source_archive':archive,
        'source_split':split,
    }


def write_csv(dest: Path, records: list[dict], fields: list[str]):
    with dest.open('w',newline='',encoding='utf-8-sig') as fp:
        writer=csv.DictWriter(fp,fieldnames=fields,extrasaction='ignore')
        writer.writeheader();writer.writerows(records)


def raw_digest(e: dict) -> str:
    """Fingerprint *all* original event fields, including provenance labels.

    A matching eventID alone is insufficient to decide that two records are equal.
    """
    return hashlib.sha256(json.dumps(e, ensure_ascii=False, sort_keys=True,
        separators=(',', ':'), default=str).encode('utf-8')).hexdigest()


def import_dataset(input_dir: Path, output_dir: Path) -> dict:
    if not input_dir.is_dir():
        raise FileNotFoundError(f'Dataset folder not found: {input_dir}')

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    all_rows = {}
    archive_stats = {}
    issues = []
    duplicate_audit = []
    globally_seen = {}  # ID -> (raw SHA256, source ZIP, source-row index, label, split)
    test_cross_split_ids = set()

    for key, name in FILES.items():
        zpath = find_archive(input_dir, name)
        original_events = load_zip_records(zpath)
        if len(original_events) > 200_000:
            raise ValueError(f'{name}: unexpected record count; refusing oversized archive')

        rows = []
        archive_seen = {}
        actor_kinds = Counter()
        scenario_counts = Counter()
        errors = []
        invalid_count = 0
        repeated_identical = 0
        repeated_conflicting = 0
        between_train_archive_duplicates = 0
        split = 'test' if key == 'test_labeled' else 'train'

        for i, e in enumerate(original_events, 1):
            try:
                row = convert(e, name, split, i)
            except (ValueError, TypeError) as exc:
                invalid_count += 1
                if len(errors) < 12:
                    errors.append(f'{name} row {i}: {exc}')
                continue

            event_id = row['event_id']
            digest = raw_digest(e)
            first_in_archive = archive_seen.get(event_id)
            prev = globally_seen.get(event_id)
            if prev is not None:
                first_sha, first_archive, first_row, first_label, first_split = prev
                identical = digest == first_sha
                if first_split != split:
                    scope = 'TRAIN_TEST_OVERLAP'
                    action = 'REJECT_OVERLAP'
                    test_cross_split_ids.add(event_id)
                elif first_in_archive is not None:
                    scope = 'WITHIN_ARCHIVE'
                    action = 'DROP_IDENTICAL_REPEAT' if identical else 'REJECT_CONFLICT'
                    if identical:
                        repeated_identical += 1
                    else:
                        repeated_conflicting += 1
                else:
                    scope = 'BETWEEN_TRAIN_ARCHIVES'
                    action = 'DROP_IDENTICAL_REPEAT' if identical else 'REJECT_CONFLICT'
                    between_train_archive_duplicates += 1
                    if not identical:
                        repeated_conflicting += 1

                duplicate_audit.append({
                    'scope': scope, 'event_id': event_id,
                    'first_archive': first_archive, 'first_row': first_row,
                    'repeated_archive': name, 'repeated_row': i,
                    'first_label': first_label,
                    'repeated_label': row['observed_positive_flag'],
                    'raw_record_matches': str(identical).lower(), 'action': action,
                })
                # Avoid leaking train events into test under any circumstances.
                # Never keep two copies of one event or silently select a conflicting label.
                if action != 'DROP_IDENTICAL_REPEAT':
                    if len(issues) < 30:
                        issues.append(f'{scope}: {event_id}, first={first_archive} row {first_row}, repeated={name} row {i}: {action}')
                continue

            globally_seen[event_id] = (digest, name, i, row['observed_positive_flag'], split)
            archive_seen[event_id] = (digest, i)
            actor_kinds[row['actor_group_kind']] += 1
            if row['observed_positive_flag'] == '1':
                scenario_counts[row['scenario_id']] += 1
            rows.append(row)

        if invalid_count:
            issues.append(f'{name}: {invalid_count} invalid input records; see sample_errors')

        archive_stats[key] = {
            'archive': str(zpath),
            'archive_sha256': hashlib.sha256(zpath.read_bytes()).hexdigest(),
            'input_events': len(original_events),
            'unique_kept_events': len(rows),
            'invalid_events': invalid_count,
            'identical_repeats_within_archive_removed': repeated_identical,
            'conflicting_repeats': repeated_conflicting,
            'between_train_archive_repetitions': between_train_archive_duplicates,
            'attack_events_after_dedup': sum(x['observed_positive_flag'] == '1' for x in rows),
            'benign_events_after_dedup': sum(x['observed_positive_flag'] == '0' for x in rows),
            'actor_grouping': dict(actor_kinds),
            'attack_scenarios': dict(sorted(scenario_counts.items())),
            'sample_errors': errors,
        }
        all_rows[key] = rows

    # Fail if benign-only archive contains any attack label.
    if any(r['observed_positive_flag'] != '0' for r in all_rows['train_benign']):
        issues.append('base_a.zip unexpectedly contains positive labels')

    tr = all_rows['train_benign'] + all_rows['train_labeled']
    te = all_rows['test_labeled']
    train_ids = {r['event_id'] for r in tr}
    test_ids = {r['event_id'] for r in te}
    overlap = train_ids & test_ids
    if overlap:
        issues.append(f'Train/test native event-ID overlap: {len(overlap)}')

    exact_repeat_count = sum(x['action'] == 'DROP_IDENTICAL_REPEAT' for x in duplicate_audit)
    conflict_count = sum(x['action'] == 'REJECT_CONFLICT' for x in duplicate_audit)
    crossover_count = sum(x['scope'] == 'BETWEEN_TRAIN_ARCHIVES' for x in duplicate_audit)
    cross_split_count = sum(x['scope'] == 'TRAIN_TEST_OVERLAP' for x in duplicate_audit)
    report = {
        'dataset': 'Cloud Log Sampling — Ariel Cyber Innovation Center',
        'source_url': 'https://github.com/ArielCyber/cloud_log_sampling',
        'split_policy': 'Publisher TrainOn/TestOn separation retained; any train/test event-ID overlap is fatal',
        'label_policy': 'should_sample event labels; a grouped window is positive if it contains >=1 positive event',
        'duplicate_policy': 'Only identical complete JSON record values (canonicalized object key order) sharing an event ID are collapsed. Conflicts and train/test overlap fail closed.',
        'grouping_policy': 'SHA256 pseudonym of IAM arn/principal; source-IP fallback is a proxy',
        'train_total_after_dedup': len(tr),
        'train_attack_events_after_dedup': sum(r['observed_positive_flag'] == '1' for r in tr),
        'test_total_after_dedup': len(te),
        'test_attack_events_after_dedup': sum(r['observed_positive_flag'] == '1' for r in te),
        'unique_train_actors': len({r['session_id'] for r in tr}),
        'unique_test_actors': len({r['session_id'] for r in te}),
        'train_test_event_id_overlap': len(overlap) or len(test_cross_split_ids),
        'train_archive_cross_repetitions': crossover_count,
        'exact_duplicate_rows_removed': exact_repeat_count,
        'conflicting_duplicate_rows': conflict_count,
        'cross_split_duplicate_rows': cross_split_count,
        'archive_raw_record_total': sum(x['input_events'] for x in archive_stats.values()),
        'archives': archive_stats,
        'issues': issues,
        'ready_for_experiment': not issues,
    }
    write_csv(out / 'ariel_duplicate_event_audit_PROTO.csv', duplicate_audit, DUP_FIELDS)
    (out / 'ariel_ingestion_manifest_PROTO.json').write_text(
        json.dumps(report, indent=2), encoding='utf-8')

    if issues:
        # Prevent stale imports from being treated as the successful output of this run.
        for name in ('ariel_train_events_PROTO.csv', 'ariel_test_events_PROTO.csv', 'ariel_attack_scenarios_PROTO.csv'):
            (out / name).unlink(missing_ok=True)
        raise ValueError('Dataset audit requires review; see ariel_ingestion_manifest_PROTO.json and ariel_duplicate_event_audit_PROTO.csv: ' + '; '.join(issues[:5]))

    write_csv(out / 'ariel_train_events_PROTO.csv', tr, FIELDS)
    write_csv(out / 'ariel_test_events_PROTO.csv', te, FIELDS)
    summary = []
    for group, split in [(tr, 'train'), (te, 'test')]:
        counts = Counter(r['scenario_id'] for r in group if r['observed_positive_flag'] == '1')
        for scenario, n in sorted(counts.items()):
            summary.append({'split': split, 'attack_scenario': scenario, 'attack_event_count': n})
    write_csv(out / 'ariel_attack_scenarios_PROTO.csv', summary, ['split', 'attack_scenario', 'attack_event_count'])

    print('PP1 public CloudTrail ingestion completed')
    print(f"  Original archive events: {report['archive_raw_record_total']}")
    print(f"  Identical repeated records removed: {exact_repeat_count}")
    print(f"  Actual repeated event IDs between training archives: {crossover_count}")
    print(f"  Train: {len(tr)} unique records, attack: {report['train_attack_events_after_dedup']}")
    print(f"  Test:  {len(te)} unique records, attack: {report['test_attack_events_after_dedup']}")
    print(f"  Train/test event-ID overlap: {report['train_test_event_id_overlap']}")
    print('  Publisher-defined train/test separation preserved')
    print('  Manifest:', out / 'ariel_ingestion_manifest_PROTO.json')
    print('  Duplicate audit:', out / 'ariel_duplicate_event_audit_PROTO.csv')
    print('  Output:', out)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset-dir',type=Path,default=Path('Data/Raw/cloud_log_sampling'))
    p.add_argument('--output-dir',type=Path,default=Path('Data/Interim/pp1_public_cloudtrail_PROTO'))
    a=p.parse_args()
    import_dataset(a.dataset_dir,a.output_dir)

if __name__=='__main__':main()
