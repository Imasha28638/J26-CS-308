import sys
import unittest
from pathlib import Path
import numpy as np

SCRIPTS=Path(__file__).resolve().parents[1]/'src'
sys.path.insert(0,str(SCRIPTS))
# Existing user's src directory supplies train_pp1_binary_stack.py in the project
try:
    from train_pp1_mixed_PROTO import grouped_folds,make_windows
except ImportError:
    # User tests should be executed after extracting into their project root;
    # this fallback supports local kit testing with PYTHONPATH specified.
    raise

class TestMixedGroupedSplits(unittest.TestCase):
    def test_no_session_overlap(self):
        group=np.array(['attack-a']*3+['attack-b']*4+['attack-c']*3+['normal-a']*5+['normal-b']*4+['normal-c']*4)
        y=np.array([1]*10+[0]*13)
        folds=list(grouped_folds(group,y,3,seed=4010))
        self.assertEqual(len(folds),3)
        for tr,val in folds:
            self.assertTrue(set(group[tr]).isdisjoint(group[val]))
            self.assertEqual(set(y[tr]),{0,1})
            self.assertEqual(set(y[val]),{0,1})

    def test_mixed_event_window_label(self):
        base={'session_id':'generated_controlled__attack_1',
              'event_time':'2026-01-01T10:00:00Z','event_source':'cloudtrail.amazonaws.com',
              'aws_region':'us-east-1','error_code':'','read_only':'true',
              'data_origin':'Generated CloudTrail','candidate_attack_class':''}
        a=dict(base,event_id='1',event_name='DescribeTrails',observed_positive_flag='0')
        b=dict(base,event_id='2',event_name='PutEventSelectors',read_only='false',observed_positive_flag='1',candidate_attack_class='Defense Evasion')
        df,seq=make_windows([a,b],5)
        self.assertEqual(len(df),1)
        self.assertEqual(df.iloc[0].label_binary,1)
        self.assertEqual(len(seq[0]),2)

if __name__=='__main__':unittest.main()
