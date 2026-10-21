from __future__ import annotations
import csv, json, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from prepare_pp1_splunk_extension_PROTO import audit, bool_readonly


def write(p,rows):
    with p.open('w',newline='',encoding='utf-8') as f:
        wr=csv.DictWriter(f,fieldnames=list(rows[0]));wr.writeheader();wr.writerows(rows)


def ariel(id,split,label='0'):
    return dict(event_id=id,session_id='ariel_actor__foo',event_time='2026-04-28T10:00:00Z',
                event_name='ListBuckets',event_source='s3.amazonaws.com',read_only='true',
                source_split=split,observed_positive_flag=label)

def splunk(id,scope='event_rule',confidence='high',ro='0'):
    return dict(event_id=id,event_time='2022-05-04T10:00:00Z',event_name='DeleteTrail',
                event_source='cloudtrail.amazonaws.com',read_only=ro,identity_arn='arn:aws:iam::1:user/a',
                source_ip_address='1.2.3.4',scenario_id='test_scenario',research_class='Defense Evasion',
                label_binary='1',exclude_from_training='0',label_scope=scope,label_confidence=confidence,
                source_file='sample.json',record_index='1',error_code='',aws_region='us-east-1')

class TestEligibility(unittest.TestCase):
    def test_boolean(self):
        self.assertEqual(bool_readonly('1'),'true');self.assertEqual(bool_readonly('False'),'false')
        with self.assertRaises(ValueError):bool_readonly('')

    def fixtures(self,t,s):
        write(t/'a.csv',[ariel('A','train')]);write(t/'b.csv',[ariel('B','test')]);write(t/'s.csv',s)
        return t/'s.csv',t/'a.csv',t/'b.csv',t/'output'

    def test_review_scopes_quarantine(self):
        with tempfile.TemporaryDirectory() as d:
            t=Path(d);args=self.fixtures(t,[splunk('C'),splunk('D',scope='scenario'),
                           splunk('E',ro=''),splunk('F',scope='scenario',confidence='medium')])
            report=audit(*args)
            self.assertEqual(report['high_event_rule_usable_events'],1)
            self.assertEqual(report['high_event_rule_quarantined_events'],1)
            self.assertEqual(report['counts']['REVIEW_SCENARIO_LABEL'],2)
            with (args[-1]/'expanded_train_candidates_PROTO.csv').open(encoding='utf-8-sig') as h:
                rows=list(csv.DictReader(h))
            self.assertEqual(len(rows),2)
            self.assertEqual(rows[-1]['data_origin'],'Splunk Attack Data')

    def test_test_overlap_blocks_merged_file(self):
        with tempfile.TemporaryDirectory() as d:
            t=Path(d);args=self.fixtures(t,[splunk('B')])
            with self.assertRaisesRegex(ValueError,'TestOn'):
                audit(*args)
            self.assertFalse((args[-1]/'expanded_train_candidates_PROTO.csv').exists())

    def test_missing_identity_quarantined(self):
        with tempfile.TemporaryDirectory() as d:
            t=Path(d);bad=splunk('C');bad['identity_arn']='';bad['source_ip_address']=''
            args=self.fixtures(t,[bad]); report=audit(*args)
            self.assertEqual(report['high_event_rule_usable_events'],0)
            self.assertEqual(report['high_event_rule_quarantined_events'],1)

    def test_duplicate_id_fails(self):
        with tempfile.TemporaryDirectory() as d:
            t=Path(d);args=self.fixtures(t,[splunk('C'),splunk('C')])
            with self.assertRaisesRegex(ValueError,'repeat'):
                audit(*args)

if __name__=='__main__': unittest.main()
