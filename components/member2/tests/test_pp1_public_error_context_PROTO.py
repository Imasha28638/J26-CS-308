from __future__ import annotations
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SRC = Path(__file__).resolve().parents[1]/'src'/'audit_pp1_public_error_context_PROTO.py'

def write(p, fields, rows):
    with p.open('w', newline='', encoding='utf-8') as f:
        wr=csv.DictWriter(f,fieldnames=fields); wr.writeheader(); wr.writerows(rows)

def run():
    with tempfile.TemporaryDirectory() as td:
        d=Path(td)
        ef=['session_id','event_id','event_time','event_name','event_source','observed_positive_flag','read_only','error_code','scenario_id','source_split']
        pf=['session_id','window_start','label_binary','positive_event_count','window_event_count','publisher_attack_scenarios','prob_LightGBM','prob_Random_Forest','prob_XGBoost','prob_LSTM','stacked_malicious_score']
        events=[
            dict(zip(ef,['actorA','e1','2026-04-04T16:00:10Z','PutObject','s3.amazonaws.com','1','false','','MassPut','test'])),
            dict(zip(ef,['actorA','e2','2026-04-04T16:00:20Z','PutObject','s3.amazonaws.com','1','false','','MassPut','test'])),
            dict(zip(ef,['actorA','e3','2026-04-04T16:15:10Z','ListObjects','s3.amazonaws.com','0','true','','','test'])),
            dict(zip(ef,['actorB','e4','2026-04-04T16:20:10Z','GetObject','s3.amazonaws.com','0','true','','','test']))]
        preds=[
            dict(zip(pf,['actorA','2026-04-04T16:00:00Z','1','2','2','MassPut','0.002','0.01','0.02','0.05','0.04'])),
            dict(zip(pf,['actorA','2026-04-04T16:15:00Z','0','0','1','','0.95','0.8','0.7','0.2','0.9'])),
            dict(zip(pf,['actorB','2026-04-04T16:20:00Z','0','0','1','','0.1','0.2','0.1','0.1','0.1']))]
        write(d/'events.csv',ef,events); write(d/'preds.csv',pf,preds)
        p=subprocess.run([sys.executable,str(SRC),'--test-events',str(d/'events.csv'),'--predictions',str(d/'preds.csv'),'--output-dir',str(d/'output')],capture_output=True,text=True)
        assert p.returncode==0,p.stderr
        report=json.loads((d/'output/public_lightgbm_error_context_report_PROTO.json').read_text())
        assert report['false_negative_windows']==1, report
        assert report['false_positive_windows']==1, report
        assert report['error_windows_with_other_attack_windows_within_context']==1,report
        with (d/'output/public_lightgbm_error_context_PROTO.csv').open(encoding='utf-8-sig') as f:
            rows=list(csv.DictReader(f))
        assert len(rows)==2
        fp=next(r for r in rows if r['error_type']=='FALSE_POSITIVE')
        assert fp['nearest_attack_window_offset_minutes']=='-15.0',fp
        assert json.loads(fp['publisher_other_operations'])=={'ListObjects':1}
        # Fail closed on inconsistent original event labels.
        preds[0]['positive_event_count']='0'
        write(d/'preds.csv',pf,preds)
        q=subprocess.run([sys.executable,str(SRC),'--test-events',str(d/'events.csv'),'--predictions',str(d/'preds.csv'),'--output-dir',str(d/'bad')],capture_output=True,text=True)
        assert q.returncode != 0 and 'Label/count/scenario mismatch' in q.stderr,q.stderr
        print('PASS: error identification, actor context, event label reconciliation, and inconsistent-data rejection')
if __name__=='__main__':run()
