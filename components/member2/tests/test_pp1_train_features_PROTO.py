import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(root))
from study_pp1_train_features_PROTO import operation_family, s3_values, add_features
import pandas as pd

class TrainingFeatureTests(unittest.TestCase):
    def test_s3_families(self):
        self.assertEqual(operation_family('GetObject', 's3.amazonaws.com'), 's3_get_object')
        self.assertEqual(operation_family('PutObject', 's3.amazonaws.com'), 's3_put_object')
        self.assertEqual(operation_family('DeleteObject', 's3.amazonaws.com'), 's3_delete_object')
        self.assertEqual(operation_family('GetBucketLogging', 's3.amazonaws.com'), 's3_bucket_read')
        self.assertEqual(operation_family('PutObject', 'ec2.amazonaws.com'), None)

    def test_s3_operation_features(self):
        events = [
            {'event_source':'s3.amazonaws.com','event_name':'PutObject'},
            {'event_source':'s3.amazonaws.com','event_name':'GetBucketLogging'},
            {'event_source':'sts.amazonaws.com','event_name':'AssumeRole'},
        ]
        got=s3_values(events)
        self.assertEqual(got['s3_total_count'],2)
        self.assertEqual(got['s3_put_object_count'],1)
        self.assertEqual(got['s3_bucket_read_count'],1)
        self.assertEqual(got['s3_object_change_count'],1)

    def test_preceding_context_excludes_current_and_future(self):
        rows = [
            {'session_id':'a','event_id':'0','event_time':'2026-04-28T04:55:00Z','event_name':'GetObject','event_source':'s3.amazonaws.com','read_only':'true','error_code':''},
            {'session_id':'a','event_id':'1','event_time':'2026-04-28T05:00:00Z','event_name':'GetObject','event_source':'s3.amazonaws.com','read_only':'true','error_code':''},
            {'session_id':'a','event_id':'2','event_time':'2026-04-28T05:01:00Z','event_name':'PutObject','event_source':'s3.amazonaws.com','read_only':'false','error_code':''},
            {'session_id':'a','event_id':'3','event_time':'2026-04-28T05:04:00Z','event_name':'DeleteObject','event_source':'s3.amazonaws.com','read_only':'false','error_code':''},
        ]
        win=pd.DataFrame([{'session_id':'a','window_start':'2026-04-28T05:00:00Z'}])
        out, cols=add_features(rows,win,2,True,True)
        self.assertEqual(out['past15_event_count'].iloc[0],1)
        self.assertEqual(out['past15_s3_get_object_count'].iloc[0],1)
        self.assertEqual(out['s3_put_object_count'].iloc[0],1)
        self.assertEqual(out['s3_delete_object_count'].iloc[0],0)

    def test_actor_day_history_blocked(self):
        rows = [
            {'session_id':'a','event_id':'0','event_time':'2026-04-27T23:59:00Z','event_name':'GetObject','event_source':'s3.amazonaws.com','read_only':'true','error_code':''},
            {'session_id':'a','event_id':'1','event_time':'2026-04-28T00:00:00Z','event_name':'GetObject','event_source':'s3.amazonaws.com','read_only':'true','error_code':''},
        ]
        win=pd.DataFrame([{'session_id':'a','window_start':'2026-04-28T00:00:00Z'}])
        out, cols=add_features(rows,win,2,False,True)
        self.assertEqual(out['past15_event_count'].iloc[0],0)

if __name__=='__main__': unittest.main()
