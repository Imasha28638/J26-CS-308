#!/usr/bin/env python3
"""Validate a proposed Member 4 v2 handoff, including original evidence integrity.

Self-contained standard-library validator. Optionally checks v2 values against
original Member 2 v1 inference report and CloudTrail evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
from convert_pp1_member4_v2_PROTO import (
    SCORE_TYPE, convert, load_cloudtrail_events, read_json, validate_v2,
)


def check(payload, source_events=None, report=None, handoff=None):
    errors = validate_v2(payload)
    if source_events is not None:
        source = Path(source_events)
        if payload.get('evidence_source_sha256') != hashlib.sha256(source.read_bytes()).hexdigest():
            errors.append('Original source file hash does not match the handoff')
        if report is not None and handoff is not None:
            try:
                expected = convert(read_json(handoff), read_json(report), load_cloudtrail_events(source),
                                   payload.get('evidence_source', ''), payload.get('evidence_source_sha256', ''))
            except (ValueError, KeyError, TypeError) as exc:
                errors.append('Original evidence reconciliation failed: ' + str(exc))
            else:
                if payload != expected:
                    errors.append('Handoff values do not match original source, report and v1 findings')
    elif report is not None or handoff is not None:
        errors.append('Use --source-events when checking original inference report/handoff')
    return errors


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--handoff', required=True, type=Path, help='Member 4 v2 JSON to validate')
    p.add_argument('--source-events', type=Path, help='Original evidence file for hash verification')
    p.add_argument('--inference-report', type=Path)
    p.add_argument('--original-handoff', type=Path, help='Original Member 2 v1 JSON')
    p.add_argument('--output', type=Path, help='Optional validation result JSON')
    a = p.parse_args()
    if bool(a.inference_report) != bool(a.original_handoff):
        p.exit(2, 'ERROR: --inference-report and --original-handoff must be provided together\n')
    try:
        data = read_json(a.handoff)
        errors = check(data, a.source_events, a.inference_report, a.original_handoff)
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        p.exit(2, 'ERROR: ' + str(exc) + '\n')
    result = {'schema_version':data.get('schema_version'), 'validation':'FAIL' if errors else 'PASS',
              'finding_count':len(data.get('findings', [])),
              'original_evidence_checked':a.source_events is not None,
              'full_reconciliation':a.original_handoff is not None, 'errors':errors}
    if a.output:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('PP1 Member 4 v2 contract validation')
    print('  Validation:', result['validation'])
    print('  Findings:', result['finding_count'])
    print('  Source evidence checked:', result['original_evidence_checked'])
    print('  Full reconciliation:', result['full_reconciliation'])
    for e in errors:
        print('  ISSUE:', e)
    if a.output:
        print('  Report:', a.output)
    if errors:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
