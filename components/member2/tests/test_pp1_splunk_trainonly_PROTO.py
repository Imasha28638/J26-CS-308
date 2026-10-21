"""Local fixture tests for the paired training-only comparison."""
from pathlib import Path
import tempfile
import sys
import csv
import unittest

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from compare_pp1_splunk_trainonly_PROTO import compare, validate_expansion
from train_pp1_public_cloudtrail_PROTO import make_windows

COLS = [
    'session_id','event_id','event_time','event_name','event_source',
    'read_only','error_code','aws_region','observed_positive_flag',
    'candidate_attack_class','scenario_id','source_archive','source_split',
    'data_origin','evidence_tier','label_scope','label_confidence'
]


def rows_fixture():
    a=[]
    for actor in range(24):
        for ix in range(9):
            positive = actor < 6 and ix == 3
            a.append({
                'session_id': f'ariel_actor__test{actor:03}',
                'event_id': f'ariel-event-{actor}-{ix}',
                'event_time': f'2026-04-28T10:{ix*5:02}:12Z',
                'event_name': 'DeleteTrail' if positive else 'DescribeInstances',
                'event_source': 'cloudtrail.amazonaws.com' if positive else 'ec2.amazonaws.com',
                'read_only': 'false' if positive else 'true',
                'error_code':'', 'aws_region':'us-east-1',
                'observed_positive_flag': '1' if positive else '0',
                'candidate_attack_class': 'Defense Evasion' if positive else '',
                'scenario_id': 'case_a' if positive else '',
                'source_archive':'fixture.zip','source_split':'train',
                'data_origin':'Ariel','evidence_tier':'publisher','label_scope':'publisher',
                'label_confidence':'publisher',
            })
    s=[]
    for ix in range(15):
        s.append({
            'session_id': f'splunk_actor__test{ix:03}',
            'event_id': f'splunk-event-{ix}',
            'event_time': f'2022-01-01T10:{(ix%10)*5:02}:25Z',
            'event_name':'StopLogging', 'event_source':'cloudtrail.amazonaws.com',
            'read_only':'false', 'error_code':'', 'aws_region':'us-east-1',
            'observed_positive_flag':'1', 'candidate_attack_class':'Defense Evasion',
            'scenario_id':f'TEST_CASE_{ix%3}', 'source_archive':'splunk_test.json',
            'source_split':'train','data_origin':'Splunk Attack Data',
            'evidence_tier':'high_confidence_event_rule_candidate',
            'label_scope':'event_rule','label_confidence':'high',
        })
    return a,s


def save_csv(path, rows):
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=COLS)
        writer.writeheader();writer.writerows(rows)


class TestSplunkComparison(unittest.TestCase):
    def test_reject_tampered_ariel(self):
        a,s=rows_fixture()
        b=[dict(r) for r in a+s]
        b[0]['event_name']='StopLogging'
        self.assertEqual(len(validate_expansion(a,a+s)),len(s))
        with self.assertRaisesRegex(ValueError,'changed'):
            validate_expansion(a,b)

    def test_reject_non_rule(self):
        a,s=rows_fixture()
        x=[dict(r) for r in s]
        x[0]['label_scope']='scenario'
        with self.assertRaisesRegex(ValueError,'not qualifying'):
            validate_expansion(a,a+x)

    def test_paired_training_runs_and_preserves_sources(self):
        a,s=rows_fixture()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            a_path=root/'train.csv';x_path=root/'expanded.csv';b_path=root/'baseline.csv'
            save_csv(a_path,a);save_csv(x_path,a+s)
            df,_,_=make_windows(a,5)
            df.to_csv(b_path,index=False)
            result=compare(a_path,x_path,b_path,root/'out',5,3,4010)
            self.assertFalse(result['publisher_teston_accessed'])
            self.assertTrue(result['all_validation_windows_ariel_only'])
            self.assertEqual(result['splunk_eligible_events'],len(s))
            compare_table=pd.read_csv(root/'out'/'trainonly_expansion_comparison_PROTO.csv')
            self.assertEqual(set(compare_table.condition),{'Ariel-only','Ariel-plus-Splunk'})
            all_oof=pd.read_csv(root/'out'/'trainonly_expansion_oof_PROTO.csv')
            self.assertEqual(len(all_oof),len(df))
            self.assertTrue(all_oof.score_ariel_plus_splunk.notna().all())


if __name__=='__main__':unittest.main()
