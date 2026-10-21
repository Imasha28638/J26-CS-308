#!/usr/bin/env python3
"""Reconcile reviewer-approved Stratus event IDs with mixed PP1 external recall.

This audit is read-only for inputs; writes an event-level reconciliation CSV.
It does not change labels, model predictions or training artifacts.
"""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


def read_csv(path):
    with Path(path).open(encoding='utf-8-sig',newline='') as f:
        return list(csv.DictReader(f))


def bucket(t, minutes):
    dt=datetime.fromisoformat(t.replace('Z','+00:00'))
    dt=dt.replace(minute=(dt.minute//minutes)*minutes,second=0,microsecond=0)
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def run(review, evidence, windows, output, minutes=5):
    reviews=read_csv(review)
    ext=read_csv(evidence)
    results=read_csv(windows)
    if not reviews or not ext or not results:
        raise ValueError('One of the input CSV files is empty')
    needed_review={'event_id','scenario_id','review_decision'}
    needed_ext={'event_id','scenario_id','session_id','event_time','observed_positive_flag','candidate_attack_class'}
    needed_result={'session_id','window_start','event_count','predicted_binary'}
    for title, rows, fields in [('Review',reviews,needed_review),('Evidence',ext,needed_ext),('Window report',results,needed_result)]:
        missing=fields-set(rows[0]);
        if missing: raise ValueError(f'{title} missing columns: {sorted(missing)}')
    approved=[r for r in reviews if r.get('review_decision','').strip().upper()=='APPROVE']
    reviews_by_id={}
    for r in approved:
        key=r['event_id'].strip()
        if not key:raise ValueError('Blank approved event ID')
        if key in reviews_by_id:raise ValueError(f'Duplicate approved event ID: {key}')
        reviews_by_id[key]=r
    by_id=defaultdict(list)
    for r in ext:
        by_id[r['event_id'].strip()].append(r)
    window_lookup={(r['session_id'],r['window_start']):r for r in results}
    if len(window_lookup)!=len(results):raise ValueError('Duplicate window report group/time')
    rows=[];issues=[];key_counts=Counter();approved_windows=set()
    for key,r in sorted(reviews_by_id.items(),key=lambda p:(p[1]['scenario_id'],p[0])):
        evidence_rows=by_id.get(key,[])
        if len(evidence_rows)!=1:
            issues.append(f'{key}: expected exactly one evidence record; found {len(evidence_rows)}')
            continue
        e=evidence_rows[0]
        expected_session='stratus_external__'+r['scenario_id']
        expected_source_scenario=r['scenario_id']
        actual_scenario=e['scenario_id']
        window=(e['session_id'],bucket(e['event_time'],minutes))
        found_window=window_lookup.get(window)
        if actual_scenario!=expected_source_scenario:
            issues.append(f'{key}: review scenario {expected_source_scenario!r} differs from evidence scenario {actual_scenario!r}')
        if e['session_id']!=expected_session:
            issues.append(f'{key}: expected session {expected_session!r}, evidence session {e["session_id"]!r}')
        if e['observed_positive_flag']!='1':
            issues.append(f'{key}: external evidence record lacks approved positive marker')
        if found_window is None:
            issues.append(f'{key}: no external scored window found for {window}')
        else:
            approved_windows.add(window)
        key_counts[e['session_id']]+=1
        rows.append({
            'event_id':key,'review_scenario_id':r['scenario_id'],
            'evidence_scenario_id':actual_scenario,'evidence_session_id':e['session_id'],
            'event_time':e['event_time'],'event_name':e.get('event_name',''),
            'approved_flag_in_evidence':e['observed_positive_flag'],
            'evidence_attack_class':e.get('candidate_attack_class',''),
            'window_start':window[1],
            'scored_window_found':str(found_window is not None),
            'window_event_count':found_window['event_count'] if found_window else '',
            'window_predicted_binary':found_window['predicted_binary'] if found_window else '',
            'window_stacking_score':found_window.get('stacked_malicious_score','') if found_window else '',
            'scenario_match':str(actual_scenario==expected_source_scenario),
        })
    pos_groups=set()
    for r in ext:
        if r['observed_positive_flag']=='1':
            pos_groups.add((r['session_id'],bucket(r['event_time'],minutes)))
            if r['event_id'].strip() not in reviews_by_id:
                issues.append(f'Unapproved event flagged positive in evidence: {r["event_id"]}')
    if pos_groups!=approved_windows:
        issues.append(f'Positive external groups ({len(pos_groups)}) differ from approved-matched groups ({len(approved_windows)})')
    if approved_windows!=set(window_lookup):
        issues.append('Scored windows do not exactly match groups containing approved event IDs')
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    fields=['event_id','review_scenario_id','evidence_scenario_id','evidence_session_id','event_time','event_name',
            'approved_flag_in_evidence','evidence_attack_class','window_start','scored_window_found',
            'window_event_count','window_predicted_binary','window_stacking_score','scenario_match']
    with output.open('w',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=fields)
        writer.writeheader();writer.writerows(rows)
    print('PP1 Stratus evidence-to-window reconciliation')
    print('  Approved review event IDs:',len(reviews_by_id))
    print('  Approved IDs resolved in external evidence:',len(rows))
    print('  Approved event-bearing windows:',len(approved_windows))
    print('  External scored windows:',len(results))
    print('  Unique approved scenario IDs:',len({r['scenario_id'] for r in approved}))
    print('  Distinct scored session IDs:',len({r['session_id'] for r in results}))
    print('  Output:',output)
    if issues:
        print('  RECONCILIATION ISSUES:')
        for item in issues:print('   -',item)
    else:
        print('  All event IDs, scenarios and positive-scored windows reconcile.')
    return len(issues)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--review',type=Path,default=Path('Data/Interim/label_review/stratus_review_candidates.csv'))
    p.add_argument('--evidence',type=Path,default=Path('Data/Interim/pp1_mixed_PROTO/stratus_external_evidence_PROTO.csv'))
    p.add_argument('--window-report',type=Path,default=Path('Data/Experiments/pp1_mixed_PROTO/stratus_approved_attack_recall_PROTO.csv'))
    p.add_argument('--output',type=Path,default=Path('Data/Experiments/pp1_mixed_PROTO/stratus_event_reconciliation_PROTO.csv'))
    p.add_argument('--window-minutes',type=int,default=5)
    args=p.parse_args()
    try:issue_count=run(args.review,args.evidence,args.window_report,args.output,args.window_minutes)
    except (ValueError,FileNotFoundError,KeyError) as ex:p.exit(2,f'ERROR: {ex}\n')
    if issue_count:p.exit(1,f'Reconciliation completed with {issue_count} issue(s); review CSV for details.\n')

if __name__=='__main__':main()
