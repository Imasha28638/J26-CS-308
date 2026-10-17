#!/usr/bin/env python3
"""Build audit-only, scenario-run evidence from Invictus CloudTrail JSON batches.

No benign or malicious labels are created. Simulator UUIDs and behavior clues are
provenance metadata, never model features or independent evidence of an attack.
"""
from __future__ import annotations
import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

RUN_ID = re.compile(r"stratus-red-team_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)

# Candidate behavior groups are review prompts, NOT attack class labels.
BEHAVIOR_NAMES = {
    'Defense Evasion candidate': {
        'StopLogging','DeleteTrail','DeleteLogGroup','UpdateTrail',
        'DeleteDetector','DeleteWebACL','DeleteRule','DeleteLogStream'
    },
    'Identity / policy modification candidate': {
        'CreateUser','CreateAccessKey','CreateLoginProfile','AttachUserPolicy',
        'AttachRolePolicy','PutRolePolicy','CreateRole','UpdateAssumeRolePolicy',
        'CreatePolicyVersion','SetDefaultPolicyVersion','CreateVirtualMFADevice'
    },
    'Credential / secrets access candidate': {
        'GetSecretValue','GetParameter','GetParameters','Decrypt','GetPasswordData',
        'AssumeRole'
    },
    'Infrastructure change / access candidate': {
        'RunInstances','SendCommand','ModifyInstanceAttribute','ModifyImageAttribute',
        'ModifySnapshotAttribute','PutBucketPolicy'
    },
}
NAME_TO_GROUP = {name: group for group, names in BEHAVIOR_NAMES.items() for name in names}

# Whitelist only identifiers for manual correlation. Never export arbitrary request
# payloads, secrets, password fields, policy documents or response elements.
SAFE_REQUEST_FIELDS = [
    'roleName','userName','policyName','policyArn','trailName','name',
    'logGroupName','secretId','instanceId','bucketName','keyId','parameterName',
    'profileName','resourceName','roleArn','targetId'
]


def get_events(path: Path):
    with path.open('r', encoding='utf-8-sig') as f:
        value = json.load(f)
    if isinstance(value, dict) and isinstance(value.get('Records'), list):
        events = value['Records']
    elif isinstance(value, list):
        events = value
    elif isinstance(value, dict):
        events = [value]
    else:
        raise ValueError('Unsupported JSON structure: ' + str(path))
    for index, event in enumerate(events, 1):
        if not isinstance(event, dict):
            raise ValueError(f'{path}: record #{index} is not an object')
        yield index, event


def actor(event):
    ident = event.get('userIdentity')
    if not isinstance(ident, dict): return ''
    return str(ident.get('arn') or ident.get('principalId') or ident.get('type') or '')


def safe_targets(event):
    req = event.get('requestParameters')
    if not isinstance(req, dict): return ''
    vals = []
    for key in SAFE_REQUEST_FIELDS:
        value = req.get(key)
        if isinstance(value, (str, int, float)) and value != '':
            txt = str(value)[:120].replace('\\n', ' ')
            vals.append(f'{key}={txt}')
    return ' | '.join(vals)[:600]


def user_agent_family(ua):
    u = ua.lower()
    if 'terraform' in u: return 'terraform-related'
    if 'stratus-red-team' in u: return 'stratus-related'
    if 'aws-cli' in u: return 'aws-cli'
    if 'aws internal' in u or 'aws-internal' in u: return 'aws-internal'
    return 'other'


def write_csv(path, rows, columns):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input-dir', type=Path, required=True)
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    files = sorted(args.input_dir.rglob('*.json'))
    if not files:
        raise SystemExit('No JSON files found: ' + str(args.input_dir))
    rows = []
    for file in files:
        for idx, e in get_events(file):
            ua = str(e.get('userAgent') or '')
            found = RUN_ID.search(ua)
            run_id = found.group(1).lower() if found else ''
            arn = actor(e)
            row = {
                'source_file': str(file.relative_to(args.input_dir)),
                'record_index': idx,
                'event_id': str(e.get('eventID') or ''),
                'event_time': str(e.get('eventTime') or ''),
                'event_name': str(e.get('eventName') or ''),
                'event_source': str(e.get('eventSource') or ''),
                'actor_arn': arn,
                'identity_type': str((e.get('userIdentity') or {}).get('type') or '') if isinstance(e.get('userIdentity'), dict) else '',
                'source_ip': str(e.get('sourceIPAddress') or ''),
                'user_agent_family': user_agent_family(ua),
                'simulator_run_id': run_id,
                'role_simulator_marker': int('stratus-red-team' in arn.lower()),
                'error_code': str(e.get('errorCode') or ''),
                'safe_request_targets': safe_targets(e),
                'behavior_family_hint': NAME_TO_GROUP.get(str(e.get('eventName') or ''), ''),
                'ground_truth_status': 'unverified',
                'label_binary': '',
                'attack_class': '',
            }
            rows.append(row)

    rows.sort(key=lambda r:(r['event_time'],r['source_file'],r['record_index']))
    columns = list(rows[0]) if rows else []
    out = args.output_dir
    write_csv(out/'all_event_evidence_unlabeled.csv', rows, columns)
    marked = [r for r in rows if r['simulator_run_id']]
    write_csv(out/'simulator_sequence_events_unlabeled.csv',marked,columns)
    sensitive = [r for r in rows if r['behavior_family_hint']]
    write_csv(out/'candidate_action_review_unlabeled.csv',sensitive,columns)
    write_csv(out/'unmarked_candidate_actions_unlabeled.csv',
              [r for r in sensitive if not r['simulator_run_id']],columns)

    groups = defaultdict(list)
    for r in marked: groups[r['simulator_run_id']].append(r)
    run_summary = []
    review_template = []
    for run_id, group in sorted(groups.items(), key=lambda kv: min(r['event_time'] for r in kv[1])):
        names = Counter(r['event_name'] for r in group)
        actions = [r for r in group if r['behavior_family_hint']]
        summary = {
            'simulator_run_id': run_id,
            'first_event_utc': min(r['event_time'] for r in group),
            'last_event_utc': max(r['event_time'] for r in group),
            'marked_event_count': len(group),
            'candidate_action_count': len(actions),
            'failed_event_count': sum(bool(r['error_code']) for r in group),
            'distinct_actors': len({r['actor_arn'] for r in group}),
            'api_names_with_counts': ' | '.join(f'{n}:{c}' for n,c in names.most_common(15)),
            'behavior_hints': ' | '.join(sorted({r['behavior_family_hint'] for r in actions})),
            'ground_truth_status':'needs_scenario_execution_evidence',
        }
        run_summary.append(summary)
        review_template.append({
            'simulator_run_id': run_id,
            'first_event_utc': summary['first_event_utc'],
            'last_event_utc': summary['last_event_utc'],
            'observed_events': len(group),
            'manual_scenario_name':'',
            'manual_mitre_technique':'',
            'research_class_after_review':'',
            'execution_evidence_reference':'',
            'confirmed_attack_start_utc':'',
            'confirmed_attack_end_utc':'',
            'setup_attack_cleanup_distinction':'',
            'reviewer_decision':'UNREVIEWED',
            'reviewer_notes':'',
        })

    write_csv(out/'simulator_run_summary.csv',run_summary,
              list(run_summary[0]) if run_summary else [])
    write_csv(out/'manual_ground_truth_review_template.csv',review_template,
              list(review_template[0]) if review_template else [])

    report = {
        'files_parsed':len(files),
        'events_parsed':len(rows),
        'events_with_simulator_run_id':len(marked),
        'distinct_simulator_run_ids':len(groups),
        'events_with_behavior_family_hint':len(sensitive),
        'unmarked_candidate_actions':sum(not r['simulator_run_id'] for r in sensitive),
        'events_labeled':0,
        'warning':'No simulator-marked or candidate event is automatically considered malicious or benign. Some are infrastructure setup, cleanup, attempts, or service activity.',
        'next_step':'Use manual review template and execution evidence to link scenarios and phases, then apply reviewed labels.'
    }
    (out/'stage2_summary.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('\nInvictus evidence reconstruction complete')
    for k, v in report.items():
        if k not in ('warning','next_step'): print(f'{k}: {v}')
    print('Output directory:',out)


if __name__=='__main__':
    main()
