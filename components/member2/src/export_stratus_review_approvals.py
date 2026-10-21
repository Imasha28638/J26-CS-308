#!/usr/bin/env python3
"""Convert *manually reviewed* Stratus candidate decisions into unify_cloudtrail.py approvals.

PENDING and REJECT records are not exported. This script cannot independently validate
whether the evidence_reference is truthful; the human reviewer must do so.
"""
from __future__ import annotations
import argparse
import csv
from pathlib import Path

VALID_CLASSES = {"Credential Abuse", "Discovery", "Privilege Escalation", "Persistence", "Defense Evasion"}
APPROVAL_FIELDS = ["record_key","decision","approved_binary","approved_attack_class","evidence_reference","reviewer_notes"]


def load(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def run():
    ap=argparse.ArgumentParser()
    ap.add_argument('--review',required=True)
    ap.add_argument('--audit',required=True)
    ap.add_argument('--output',required=True)
    args=ap.parse_args()

    reviewed=load(args.review)
    audit_rows=load(args.audit)
    audited={r['record_key']:r for r in audit_rows}
    if len(audited)!=len(audit_rows):
        raise SystemExit('Audit record_key collision')
    approvals=[];seen=set();pending=0;rejected=0
    for r in reviewed:
        key=(r.get('record_key') or '').strip()
        if not key: raise SystemExit('Blank record_key in review file')
        if key in seen: raise SystemExit(f'Duplicate key in review file: {key}')
        seen.add(key)
        base=audited.get(key)
        if not base or base.get('source_key')!='stratus':
            raise SystemExit(f'Key missing from unified Stratus audit: {key}')
        for original,normalized in [('scenario_id','scenario_id'),('event_time','event_time'),('event_name','event_name')]:
            if (r.get(original) or '').strip() != (base.get(normalized) or '').strip():
                raise SystemExit(f'Review row does not match audit for {key}: {original}')
        action=(r.get('review_decision') or 'PENDING').strip().upper()
        if action in ('PENDING','HOLD',''):
            pending+=1;continue
        if action=='REJECT':
            rejected+=1;continue
        if action!='APPROVE':
            raise SystemExit(f'Unsupported review_decision={action} for {key}; use APPROVE, REJECT, or PENDING')
        cls=(r.get('proposed_attack_class') or '').strip()
        if cls not in VALID_CLASSES:raise SystemExit(f'Invalid class {cls} for {key}')
        if cls!=base.get('source_attack_class'):
            raise SystemExit(f'Class does not match source candidate for {key}')
        reference=(r.get('evidence_reference') or '').strip()
        notes=(r.get('reviewer_notes') or '').strip()
        if len(reference)<25 or len(notes)<12:
            raise SystemExit(f'APPROVE requires specific evidence_reference (>=25 chars) and reviewer_notes (>=12 chars) for {key}')
        if (r.get('simulator_marker') or '').lower()=='no' and 'marker' not in notes.lower():
            raise SystemExit(f'No simulator marker for {key}: note explicitly how phase was verified and mention marker in reviewer_notes')
        approvals.append({
            'record_key':key,'decision':'approve','approved_binary':'1',
            'approved_attack_class':cls,'evidence_reference':reference,'reviewer_notes':notes
        })
    if not approvals:
        print(f'No APPROVE decisions. {pending} pending, {rejected} rejected; no approvals file generated.')
        return
    out=Path(args.output);out.parent.mkdir(parents=True,exist_ok=True)
    if out.exists():
        raise SystemExit(f'Output already exists, refusing to overwrite prior approvals: {out}')
    with out.open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=APPROVAL_FIELDS)
        writer.writeheader();writer.writerows(approvals)
    print(f'Exported {len(approvals)} reviewed Stratus attack-event approvals -> {out}')
    print(f'Rejected: {rejected}, Pending: {pending}')
    print('Reminder: evidence validity, benign ground truth, scenario splits, and source confounding remain research decisions.')

if __name__=='__main__':run()
