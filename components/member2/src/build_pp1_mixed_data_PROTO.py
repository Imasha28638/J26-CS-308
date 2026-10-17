#!/usr/bin/env python3
"""Prepare PP1 mixed-source CloudTrail event inputs with explicit provenance.

Splunk events = scenario-associated attack CANDIDATES (not confirmed event labels).
Generated benign = normal activity by generator intent (not observed benign).
Approved Stratus = held-out attack-emulation evidence (not training records).
Other real background data stays unlabeled and is excluded from supervised training.
"""
import argparse
import csv
import hashlib
import json
import random
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

OUTPUT_FIELDS = [
    'session_id','event_id','event_time','event_name','event_source','read_only',
    'error_code','aws_region','observed_positive_flag','candidate_attack_class',
    'data_origin','evidence_tier','scenario_id','source_row_id',
]

def csv_read(path):
    with Path(path).open('r',encoding='utf-8-sig',newline='') as f:
        return list(csv.DictReader(f))


def csv_write(path, rows, fields=OUTPUT_FIELDS):
    path=Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)


def valid_utc(s):
    try:
        datetime.fromisoformat(s.replace('Z','+00:00'))
        return bool(s)
    except (TypeError,ValueError,AttributeError):
        return False


def safe_eid(r):
    key=(r.get('event_id') or '').strip()
    if key:return key
    fingerprint='|'.join(str(r.get(x,'')) for x in ('source_file','record_index','event_time','event_name'))
    return 'missing-id-'+hashlib.sha256(fingerprint.encode('utf-8')).hexdigest()[:24]


def build(splunk_path,benign_path,stratus_path,review_path,controlled_path,output_dir,max_windows_per_scenario=35,seed=4010):
    import datetime as dt
    splunk=csv_read(splunk_path)
    benign=csv_read(benign_path)
    stratus=csv_read(stratus_path)
    review=csv_read(review_path)
    controlled=csv_read(controlled_path)
    if not splunk or not benign or not stratus or not review or not controlled:
        raise ValueError('One or more input files are empty')
    required_splunk={'scenario_id','event_time','event_name','event_source','exclude_from_training','label_binary'}
    required_benign={'simulation_session_id','event_time','event_name','event_source','label_binary'}
    required_stratus={'event_id','scenario_id','event_time','event_name','event_source'}
    required_review={'event_id','review_decision'}
    required_controlled={'simulation_session_id','event_time','event_name','event_source','injected_attack_event','label_binary'}
    for rows, required, label in ((splunk,required_splunk,'Splunk'),(benign,required_benign,'generated benign'),(stratus,required_stratus,'Stratus'),(review,required_review,'review'),(controlled,required_controlled,'controlled events')):
        missing=required-set(rows[0]);
        if missing:raise ValueError(f'{label} missing columns: {sorted(missing)}')
    if any(r['label_binary']!='0' or r.get('exclude_from_approved_training','1')!='1' for r in benign):
        raise ValueError('Generated benign file failed provenance/label checks')
    reviewed={r['event_id'] for r in review if r['review_decision'].strip().upper()=='APPROVE'}
    if not reviewed:raise ValueError('No approved Stratus evidence found')
    counts=Counter()
    attack_candidate_rows=defaultdict(list)
    for r in splunk:
        counts['splunk_total']+=1
        if r.get('exclude_from_training','').strip() not in ('0','false','False','') or r.get('label_binary')!='1':
            counts['splunk_excluded']+=1;continue
        if not r.get('scenario_id') or not valid_utc(r.get('event_time')):
            counts['splunk_invalid']+=1;continue
        sid='splunk_attack__'+r['scenario_id']
        attack_candidate_rows[sid].append({
            'session_id':sid,'event_id':safe_eid(r),'event_time':r['event_time'],
            'event_name':r['event_name'],'event_source':r['event_source'],
            'read_only':r.get('read_only',''),'error_code':r.get('error_code',''),
            'aws_region':r.get('aws_region',''),
            'observed_positive_flag':'1','candidate_attack_class':r.get('attack_class',''),
            'data_origin':'Splunk Attack Data','evidence_tier':'scenario_associated_candidate',
            'scenario_id':r['scenario_id'],'source_row_id':str(r.get('record_index',''))
        })
    # Select whole five-minute windows, not individual records. Cap highly repetitive
    # scenario activity without overweighting long scanner traces.
    attack_rows=[]
    sampled_scenario_summary=[]
    rng=random.Random(seed)
    for sid,source_rows in sorted(attack_candidate_rows.items()):
        grouped=defaultdict(list)
        for r in source_rows:
            dtm=dt.datetime.fromisoformat(r['event_time'].replace('Z','+00:00'))
            grouped[dtm.replace(minute=dtm.minute//5*5,second=0,microsecond=0).isoformat()].append(r)
        keys=sorted(grouped)
        if len(keys)>max_windows_per_scenario:
            keys=sorted(rng.sample(keys,max_windows_per_scenario))
        for key in keys:attack_rows.extend(grouped[key])
        sampled_scenario_summary.append({
            'source':'Splunk Attack Data','scenario_id':sid.replace('splunk_attack__','',1),
            'original_events':len(source_rows),'selected_events':sum(len(grouped[k]) for k in keys),
            'selected_windows':len(keys),'label_tier':'scenario_associated_candidate',
        })
    good_benign=[]
    for r in benign:
        if not valid_utc(r.get('event_time')):
            counts['generated_invalid']+=1;continue
        good_benign.append({
            'session_id':'generated_benign__'+r['simulation_session_id'],
            'event_id':safe_eid(r),'event_time':r['event_time'],
            'event_name':r['event_name'],'event_source':r['event_source'],
            'read_only':r.get('read_only',''),'error_code':r.get('error_code',''),
            'aws_region':r.get('aws_region',''), 'observed_positive_flag':'0',
            'candidate_attack_class':'', 'data_origin':'Generated CloudTrail',
            'evidence_tier':'generated_benign_intent','scenario_id':r.get('scenario_id',''),
            'source_row_id':str(r.get('record_index','')),
        })
    # Use only the additional controlled attack sessions. Normal sessions already
    # appear in the standalone benign input, so skip them to prevent duplicates.
    controlled_rows=[]
    for r in controlled:
        sid=r.get('simulation_session_id','')
        if not sid.startswith('synthetic_attack_'):
            continue
        if not valid_utc(r.get('event_time')):
            counts['controlled_invalid']+=1;continue
        flagged=(r.get('injected_attack_event')=='1')
        if flagged!=(r.get('label_binary')=='1'):
            raise ValueError('Controlled attack evidence flags disagree with record labels')
        controlled_rows.append({
            'session_id':'generated_controlled__'+sid,
            'event_id':safe_eid(r),'event_time':r['event_time'],
            'event_name':r['event_name'],'event_source':r['event_source'],
            'read_only':r.get('read_only',''),'error_code':r.get('error_code',''),
            'aws_region':r.get('aws_region',''),
            'observed_positive_flag':'1' if flagged else '0',
            'candidate_attack_class':r.get('attack_session_class','') if flagged else '',
            'data_origin':'Generated CloudTrail','evidence_tier':'controlled_attack_injection' if flagged else 'generated_benign_intent',
            'scenario_id':r.get('scenario_id',''),'source_row_id':str(r.get('record_index','')),
        })
    if not controlled_rows or not any(r['observed_positive_flag']=='1' for r in controlled_rows):
        raise ValueError('No generated attack-session events found')
    if len({r['event_id'] for r in controlled_rows})!=len(controlled_rows):
        raise ValueError('Generated controlled attack session IDs are duplicated')
    holdout=[]; matched=set()
    for r in stratus:
        if not valid_utc(r.get('event_time')):continue
        eid=r.get('event_id','')
        if eid in reviewed:matched.add(eid)
        holdout.append({
            'session_id':'stratus_external__'+r['scenario_id'],
            'event_id':safe_eid(r),'event_time':r['event_time'],
            'event_name':r['event_name'],'event_source':r['event_source'],
            'read_only':r.get('read_only',''),'error_code':r.get('error_code',''),
            'aws_region':r.get('aws_region',''),
            'observed_positive_flag':'1' if eid in reviewed else '',
            'candidate_attack_class':r.get('attack_class','') if eid in reviewed else '',
            'data_origin':'Stratus Red Team','evidence_tier':'approved_attack_emulation' if eid in reviewed else 'unreviewed_not_for_scoring',
            'scenario_id':r['scenario_id'],'source_row_id':str(r.get('record_index','')),
        })
    if matched!=reviewed:
        raise ValueError(f'Approved Stratus event IDs missing from source: {len(reviewed-matched)}')
    if len({r['event_id'] for r in attack_rows})!=len(attack_rows):
        raise ValueError('Splunk selected attack events contain duplicate event IDs')
    if len({r['event_id'] for r in good_benign})!=len(good_benign):
        raise ValueError('Generated benign events contain duplicate event IDs')
    mixed=sorted(attack_rows+good_benign+controlled_rows,key=lambda x:(x['session_id'],x['event_time'],x['event_id']))
    out=Path(output_dir);out.mkdir(parents=True,exist_ok=True)
    csv_write(out/'mixed_training_events_PROTO.csv',mixed)
    csv_write(out/'stratus_external_evidence_PROTO.csv',holdout)
    csv_write(out/'splunk_scenario_selection_PROTO.csv',sampled_scenario_summary,
              list(sampled_scenario_summary[0]))
    report={
        'purpose':'PP1 mixed-source proof of concept',
        'attack_source':'Splunk attack-scenario event candidates',
        'benign_source':'Generated CloudTrail with normal activity intent',
        'additional_positive_source':'Generated CloudTrail with documented attack injections',
        'external_attack_source':'Stratus reviewed attack-emulation events',
        'splunk_attack_candidate_events_selected':len(attack_rows),
        'splunk_attack_scenarios':len(attack_candidate_rows),
        'generated_benign_events':len(good_benign),
        'controlled_activity_events':len(controlled_rows),
        'controlled_attack_events':sum(r['observed_positive_flag']=='1' for r in controlled_rows),
        'controlled_attack_sessions':len({r['session_id'] for r in controlled_rows}),
        'generated_benign_sessions':len({r['session_id'] for r in good_benign}),
        'stratus_records_context':len(holdout),'stratus_approved_events':len(matched),
        'excluded_unlabeled_sandbox':True,'excluded_unverified_invictus':True,
        'source_confounding_warning':True,
        'limitations':[
            'Splunk positives use attack-scenario association rather than independent per-event verification.',
            'Generated normal activity has known generator intent, not real benign ground truth.',
            'The attack class is associated with collection source, and generated attack patterns differ from real operations; external validity is not established.',
            'Stratus positive-only external check measures approved attack-event recall only, not precision or false-positive rate.',
        ],
    }
    (out/'dataset_manifest_PROTO.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('PP1 mixed-source data preparation completed')
    print('  Splunk scenario-associated attack candidates:',len(attack_rows))
    print('  Splunk attack scenarios:',len(attack_candidate_rows))
    print('  Generated benign events:',len(good_benign))
    print('  Controlled generated attack-session events:',len(controlled_rows))
    print('  Controlled generated injected attack events:',sum(r['observed_positive_flag']=='1' for r in controlled_rows))
    print('  Stratus approved attack evidence held out:',len(matched))
    print('  Output:',out)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--splunk',type=Path,default=Path('Data/Interim/integration_review/splunk.csv'))
    p.add_argument('--benign',type=Path,default=Path('Data/Synthetic/benign_pp1/synthetic_benign_events.csv'))
    p.add_argument('--controlled-events',type=Path,default=Path('Data/Synthetic/pp1_experiment/synthetic_experiment_events.csv'))
    p.add_argument('--stratus',type=Path,default=Path('Data/Interim/integration_review/stratus.csv'))
    p.add_argument('--review',type=Path,default=Path('Data/Interim/label_review/stratus_review_candidates.csv'))
    p.add_argument('--output-dir',type=Path,default=Path('Data/Interim/pp1_mixed_PROTO'))
    p.add_argument('--max-windows-per-scenario',type=int,default=35)
    p.add_argument('--seed',type=int,default=4010)
    a=p.parse_args()
    if a.max_windows_per_scenario<1:raise SystemExit('max-windows-per-scenario must be >= 1')
    build(a.splunk,a.benign,a.stratus,a.review,a.controlled_events,a.output_dir,a.max_windows_per_scenario,a.seed)

if __name__=='__main__':main()
