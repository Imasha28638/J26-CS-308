#!/usr/bin/env python3
"""Convert validated Member 2 window-level handoff to Member 4's proposed v2 fields.

Uses original CloudTrail bytes for evidence references and resource ARN extraction.
No ML inference, score calibration, or training occurs here. Standard library only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from collections import Counter
from datetime import datetime
from pathlib import Path

V1 = 'member2_to_member4_proto_v1'
V2 = 'member2_to_member4_proto_v2'
SCORE_TYPE = 'uncalibrated_model_score'
PREDICTIONS = {0: ('BENIGN_PATTERN', 'Benign'), 1: ('MALICIOUS_PATTERN', 'Malicious')}
SERVICE_NAMES = {'cloudtrail':'CloudTrail', 's3':'S3', 'iam':'IAM', 'sts':'STS', 'ec2':'EC2',
                 'cloudwatch':'CloudWatch', 'logs':'CloudWatch Logs', 'organizations':'Organizations',
                 'kms':'KMS', 'lambda':'Lambda', 'ssm':'Systems Manager', 'signin':'AWS Sign-in'}


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def is_probability(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1


def utc_timestamp(s):
    if not isinstance(s, str) or not s.endswith('Z'):
        return False
    try:
        dt = datetime.fromisoformat(s[:-1] + '+00:00')
        return dt.utcoffset().total_seconds() == 0
    except (TypeError, ValueError, AttributeError):
        return False


def load_cloudtrail_events(path):
    path = Path(path)
    raw = path.read_text(encoding='utf-8-sig')
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        try:
            data = [json.loads(line) for line in raw.splitlines() if line.strip()]
        except json.JSONDecodeError as e:
            raise ValueError('Invalid CloudTrail JSON or JSONL: ' + str(e)) from e
    if isinstance(data, dict) and isinstance(data.get('Records'), list):
        events = data['Records']
    elif isinstance(data, dict) and all(k in data for k in ('eventTime', 'eventName', 'eventSource')):
        events = [data]
    elif isinstance(data, list):
        events = data
    else:
        raise ValueError('Expected a CloudTrail Records object, event object, array or JSONL')
    if not events or not all(isinstance(x, dict) for x in events):
        raise ValueError('CloudTrail source has no usable event objects')
    return events


def normalized_service(source):
    if not isinstance(source, str) or not source.strip():
        raise ValueError('Event service missing')
    s = source.strip()
    prefix = s.removesuffix('.amazonaws.com').split('.')[0].lower()
    return SERVICE_NAMES.get(prefix, s)


def event_resource_arns(event):
    resources = event.get('resources', [])
    if not isinstance(resources, list):
        return []
    arns = []
    for res in resources:
        if not isinstance(res, dict):
            continue
        arn = res.get('ARN') or res.get('arn')
        if isinstance(arn, str) and arn.startswith('arn:'):
            arns.append(arn)
    return arns


def check_v1_and_report(v1, report, events):
    if not isinstance(v1, dict) or v1.get('schema_version') != V1:
        raise ValueError('Not a Member 2 v1 handoff')
    if v1.get('score_type') != SCORE_TYPE:
        raise ValueError('Expected explicit uncalibrated_model_score in v1 handoff')
    fs, ws = v1.get('findings'), report.get('windows')
    if not isinstance(fs, list) or not isinstance(ws, list) or len(fs) != len(ws):
        raise ValueError('Handoff and inference report must have matching findings/windows')
    if report.get('source_record_count') != len(events):
        raise ValueError('Original source-event count differs from the inference report')
    by_id = {w.get('window_id'):w for w in ws if isinstance(w, dict)}
    if len(by_id) != len(ws):
        raise ValueError('Missing or duplicate inference window IDs')
    used = []
    seen = set()
    for f in fs:
        if not isinstance(f, dict):
            raise ValueError('Malformed v1 finding')
        fid = f.get('finding_id')
        if not isinstance(fid, str) or not fid or fid in seen or fid not in by_id:
            raise ValueError('Missing, duplicate or unmatched finding ID')
        seen.add(fid)
        w = by_id[fid]
        for vk, wk in (('event_window_start_utc','window_start_utc'),('actor_hash','actor_hash'),
                       ('predicted_binary','predicted_binary'),('activity','predicted_activity'),
                       ('api_operations','api_operations'),('aws_services','aws_services'),
                       ('event_count','event_count'),('evidence_record_numbers','source_record_numbers')):
            if f.get(vk) != w.get(wk):
                raise ValueError(f'Finding {fid}: {vk} does not match inference report')
        for k in ('stacking_score','model_disagreement'):
            if not is_probability(f.get(k)) or not is_probability(w.get(k)) or abs(f[k]-w[k]) > 1e-6:
                raise ValueError(f'Finding {fid}: {k} differs from inference report')
        binary = f.get('predicted_binary')
        if type(binary) is not int or binary not in PREDICTIONS or f.get('activity') != PREDICTIONS[binary][0]:
            raise ValueError(f'Finding {fid}: inconsistent binary activity')
        if f.get('attack_category') is not None:
            raise ValueError('Binary model does not produce an attack category')
        if not utc_timestamp(f.get('event_window_start_utc')):
            raise ValueError(f'Finding {fid}: invalid UTC timestamp')
        nums = f.get('evidence_record_numbers')
        if not isinstance(nums, list) or len(nums) != f.get('event_count') or any(type(n) is not int or n < 1 or n > len(events) for n in nums):
            raise ValueError(f'Finding {fid}: invalid original evidence indices')
        if len(set(nums)) != len(nums):
            raise ValueError(f'Finding {fid}: repeated original evidence indices')
        used += nums
        actual_ops = dict(Counter(events[n-1].get('eventName') for n in nums))
        actual_services = sorted(set(events[n-1].get('eventSource') for n in nums))
        if actual_ops != f.get('api_operations') or actual_services != sorted(f.get('aws_services', [])):
            raise ValueError(f'Finding {fid}: source events do not match API operations/services')
    if len(set(used)) != len(used) or sorted(used) != list(range(1, len(events)+1)):
        raise ValueError('Evidence indices do not cover the source exactly once')


def make_reference(source_reference, nums):
    anchor = 'record=' + str(nums[0]) if len(nums) == 1 else 'records=' + ','.join(str(x) for x in nums)
    return source_reference + '#' + anchor


def convert(v1, report, events, source_reference, source_file_hash):
    check_v1_and_report(v1, report, events)
    if not isinstance(source_reference, str) or not source_reference.strip():
        raise ValueError('A nonempty CloudTrail source reference is required')
    out_findings = []
    for f in v1['findings']:
        nums = f['evidence_record_numbers']
        relevant = [events[n-1] for n in nums]
        ops = f['api_operations']
        # Representative operation only; full observed operation counts remain available.
        event_name = sorted(ops, key=lambda name: (-ops[name], name))[0]
        matching = [e for e in relevant if e.get('eventName') == event_name]
        source = matching[0].get('eventSource')
        all_arns = sorted({arn for e in relevant for arn in event_resource_arns(e)})
        resource_id = all_arns[0] if len(all_arns) == 1 else None
        ids = list(dict.fromkeys(str(e['eventID']) for e in relevant if e.get('eventID')))
        binary = f['predicted_binary']
        out_findings.append({
            'finding_id': f['finding_id'],
            'timestamp': f['event_window_start_utc'],
            'timestamp_type': 'window_start_utc',
            'entity_id': 'actor_hash:' + f['actor_hash'],
            'entity_id_type': 'pseudonymous_actor_group',
            'resource_id': resource_id,
            'resource_ids': all_arns,
            'service': normalized_service(source),
            'event_source': source,
            'event_name': event_name,
            'event_name_type': 'sole_operation' if len(ops) == 1 else 'representative_highest_count',
            'prediction': PREDICTIONS[binary][1],
            'predicted_binary': binary,
            'confidence': f['stacking_score'],
            'confidence_type': SCORE_TYPE,
            'evidence_reference': make_reference(source_reference, nums),
            'evidence_record_numbers': nums,
            'evidence_event_ids': ids,
            'api_operations': ops,
            'aws_services': f['aws_services'],
            'event_count': f['event_count'],
            'model_disagreement': f['model_disagreement'],
            'attack_category': None,
        })
    return {
        'schema_version': V2,
        'status': v1.get('status', 'PROTO_EVALUATION'),
        'source': v1.get('source', 'member2_pp1_binary_stacking'),
        'score_type': SCORE_TYPE,
        'model_output_task': 'binary_benign_vs_malicious',
        'evidence_source': source_reference,
        'evidence_source_sha256': source_file_hash,
        'findings': out_findings,
    }


def validate_v2(data):
    errors = []
    if not isinstance(data, dict):
        return ['Expected object']
    if data.get('schema_version') != V2 or data.get('score_type') != SCORE_TYPE:
        errors.append('Incorrect contract version or score type')
    if not isinstance(data.get('evidence_source'), str) or not data['evidence_source'].strip():
        errors.append('Missing evidence_source path')
    sha = data.get('evidence_source_sha256')
    if not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
        errors.append('Missing or malformed source SHA256')
    fs = data.get('findings')
    if not isinstance(fs, list):
        return errors+['Expected findings array']
    ids = set()
    for i, f in enumerate(fs):
        p = f'findings[{i}]'
        if not isinstance(f, dict):
            errors.append(p + ': expected object')
            continue
        for field in ('finding_id', 'timestamp','entity_id','resource_id','service','event_name',
                      'prediction','confidence','evidence_reference'):
            if field not in f:
                errors.append(f'{p}: missing {field}')
        fid = f.get('finding_id')
        if not isinstance(fid, str) or not fid or fid in ids:
            errors.append(f'{p}: empty/duplicate finding_id')
        ids.add(fid)
        if not utc_timestamp(f.get('timestamp')):
            errors.append(f'{p}: invalid timestamp')
        if f.get('timestamp_type') != 'window_start_utc':
            errors.append(f'{p}: incorrect timestamp semantics')
        if not isinstance(f.get('entity_id'), str) or not f['entity_id'].startswith('actor_hash:'):
            errors.append(f'{p}: entity_id should be an explicitly identified actor hash')
        if f.get('entity_id_type') != 'pseudonymous_actor_group':
            errors.append(f'{p}: entity_id_type mismatch')
        if f.get('resource_id') is not None and (not isinstance(f['resource_id'], str) or not f['resource_id'].startswith('arn:')):
            errors.append(f'{p}: resource_id must be ARN or null')
        if f.get('resource_id') is not None and f['resource_id'] not in f.get('resource_ids', []):
            errors.append(f'{p}: resource_id missing from resource_ids')
        for key in ('service', 'event_name', 'event_source', 'evidence_reference'):
            if not isinstance(f.get(key), str) or not f[key].strip():
                errors.append(f'{p}: invalid {key}')
        b = f.get('predicted_binary')
        if type(b) is not int or b not in PREDICTIONS or f.get('prediction') != PREDICTIONS[b][1]:
            errors.append(f'{p}: inconsistent prediction')
        if not is_probability(f.get('confidence')) or f.get('confidence_type') != SCORE_TYPE:
            errors.append(f'{p}: invalid uncalibrated score or score semantics')
        if f.get('attack_category') is not None:
            errors.append(f'{p}: unexpected attack category for binary classifier')
        nums = f.get('evidence_record_numbers')
        if not isinstance(nums, list) or not nums or any(type(n) is not int or n < 1 for n in nums):
            errors.append(f'{p}: malformed evidence record indices')
        if isinstance(nums, list) and nums and isinstance(data.get('evidence_source'), str) and isinstance(f.get('evidence_reference'), str) and f.get('evidence_reference') != make_reference(data['evidence_source'], nums):
            errors.append(f'{p}: evidence reference does not agree with source')
        ops = f.get('api_operations')
        if not isinstance(ops, dict) or not ops or any(type(c) is not int or c < 1 for c in ops.values()):
            errors.append(f'{p}: malformed API operations')
        elif type(f.get('event_count')) is not int or sum(ops.values()) != f['event_count']:
            errors.append(f'{p}: event counts do not reconcile')
        elif f.get('event_name') not in ops:
            errors.append(f'{p}: selected API operation absent from evidence')
    return errors


def run(handoff_path, report_path, source_path, output_path, source_reference=None):
    handoff = read_json(handoff_path)
    report = read_json(report_path)
    source_path = Path(source_path)
    events = load_cloudtrail_events(source_path)
    if source_reference is None:
        # Use relative path given on CLI, not a full machine-specific drive path.
        source_reference = source_path.name if source_path.is_absolute() else source_path.as_posix()
    source_bytes = source_path.read_bytes()
    result = convert(handoff, report, events, source_reference, hashlib.sha256(source_bytes).hexdigest())
    errors = validate_v2(result)
    if errors:
        raise ValueError('Converted handoff failed validation: ' + '; '.join(errors))
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print('PP1 Member 4 field mapping completed')
    print(f'  Contract: {V2}')
    print(f'  Findings: {len(result["findings"])}')
    print(f'  Resources with verified ARN: {sum(f["resource_id"] is not None for f in result["findings"])}')
    print('  Confidence semantics: uncalibrated_model_score')
    print(f'  Output: {out}')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--handoff', type=Path, required=True, help='Original Member 2 v1 handoff JSON')
    p.add_argument('--inference-report', type=Path, required=True, help='Matching full inference report')
    p.add_argument('--source-events', type=Path, required=True, help='Original CloudTrail JSON/JSONL evidence')
    p.add_argument('--source-reference', help='Optional portable source path/reference to put in JSON')
    p.add_argument('--output', type=Path, required=True, help='New Member 4 v2 handoff JSON')
    args = p.parse_args()
    try:
        run(args.handoff, args.inference_report, args.source_events, args.output, args.source_reference)
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        p.exit(2, 'ERROR: ' + str(exc) + '\n')

if __name__ == '__main__':
    main()
