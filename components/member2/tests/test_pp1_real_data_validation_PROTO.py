import csv
import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd

SRC = Path(__file__).resolve().parents[1]/'src'
sys.path.insert(0,str(SRC))
from evaluate_pp1_real_background_PROTO import (
    is_readonly,load_background,windows_for_scoring,generate_review_queue
)
from audit_pp1_source_bias_PROTO import audit


def background_row(*,row_id='1',at='2026-01-10T10:01:00Z',label='',bucket='background_candidate_unverified',ro='1'):
    return {'event_time':at,'event_name':'ListBuckets','event_source':'s3.amazonaws.com',
            'source_ip_address':'198.51.100.14','read_only':ro,'aws_region':'us-east-1',
            'ground_truth_status':'unlabeled','review_bucket':bucket,'label_binary':label,
            'exclude_from_training':'1','row_hash':'hash-'+row_id,'record_index':row_id,
            'error_code':''}


def write_rows(path,rows):
    with path.open('w',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)

class PP1RealBackgroundTests(unittest.TestCase):
    def test_readonly_is_explicit(self):
        self.assertEqual(is_readonly('1'),'true')
        self.assertEqual(is_readonly('0'),'false')
        with self.assertRaises(ValueError):is_readonly('')

    def test_input_labels_not_assumed_benign(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'unlabeled.csv'
            write_rows(p,[background_row(label='0')])
            with self.assertRaises(ValueError):load_background(p)
            write_rows(p,[background_row(bucket='quarantine_incident')])
            with self.assertRaises(ValueError):load_background(p)

    def test_dedup_and_actor_window(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'unlabeled.csv'
            write_rows(p,[background_row(),background_row(),background_row(row_id='2',at='2026-01-10T10:01:30Z'),
                          background_row(row_id='3',at='2026-01-10T10:06:00Z')])
            rows,summary=load_background(p)
            self.assertEqual(len(rows),3)
            self.assertEqual(summary['exact_source_row_duplicates_skipped'],1)
            windows,x,seq,length=windows_for_scoring(rows)
            self.assertEqual(len(windows),2)
            self.assertEqual(x.shape[0],2)
            self.assertEqual(seq.shape[0],2)
            self.assertEqual(sorted(w['event_count'] for w in windows),[1,2])

    def test_review_queue_is_pending_only(self):
        items=[{'window_id':str(i),'stacking_score':i/10,
                'window_start_utc':'2026-01-10T10:00:00Z','actor_hash':'a',
                'event_count':5,'api_operations':'{}'} for i in range(5)]
        q=generate_review_queue(items,top_n=2,baseline_n=2)
        self.assertEqual(len(q),4)
        self.assertTrue(all(x['review_decision']=='PENDING' for x in q))
        self.assertEqual(len({x['window_id'] for x in q}),4)

    def test_source_origin_audit_group_disjoint(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            frame=pd.DataFrame([
                ('s1','2026-01-01T00:00:00Z',1,'Splunk Attack Data'),
                ('s2','2026-01-01T00:00:00Z',1,'Splunk Attack Data'),
                ('g1','2026-01-01T00:00:00Z',0,'Generated CloudTrail'),
                ('g2','2026-01-01T00:00:00Z',0,'Generated CloudTrail')
            ],columns=['session_id','window_start','label_binary','data_origin'])
            frame.to_csv(root/'features.csv',index=False)
            test=frame.iloc[[1,3]][['session_id','window_start','label_binary']].copy()
            test['stacked_malicious_score']=[.9,.1]
            test.to_csv(root/'test.csv',index=False)
            report=audit(root/'features.csv',root/'test.csv',root/'out')
            self.assertEqual(report['train_sessions'],2)
            self.assertEqual(report['test_sessions'],2)
            self.assertIn('source_only_baseline',report)

if __name__=='__main__':unittest.main()
