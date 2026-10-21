import csv
import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/'src'/'audit_pp1_public_training_context_PROTO.py'
spec=importlib.util.spec_from_file_location('auditcontext',SCRIPT)
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
FIELDS=['session_id','event_id','event_time','event_name','event_source','observed_positive_flag','scenario_id','source_split','read_only']

class TestTrainingAudit(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
    def write(self, rows):
        p=self.root/'train.csv'
        with p.open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=FIELDS); w.writeheader();w.writerows(rows)
        return p
    def entry(self,i,t,name,positive='0',split='train',actor='A',source='s3.amazonaws.com'):
        return {'session_id':actor,'event_id':str(i),'event_time':t,'event_name':name,
                'event_source':source,'observed_positive_flag':positive,
                'scenario_id':'Scenario' if positive=='1' else '',
                'source_split':split,'read_only':'true' if name.startswith('Get') else 'false'}
    def test_counts_and_context(self):
        rows=[self.entry(1,'2026-04-04T10:00:00Z','GetBucketLogging'),
              self.entry(2,'2026-04-04T10:03:00Z','PutObject','1'),
              self.entry(3,'2026-04-04T10:06:00Z','PutObject','1'),
              self.entry(4,'2026-04-04T10:03:00Z','GetBucketAcl','0',actor='B')]
        report=mod.analyze(self.write(rows),self.root/'out')
        assert report['training_events']==4
        assert report['training_publisher_positive_events']==2
        assert report['positive_actor_days']==1
        five=next(x for x in report['window_sweep'] if x['window_minutes']==5)
        assert five['attack_containing_windows']==2
        assert five['positive_actor_day_groups']==1
        assert report['positive_five_min_windows_with_preceding_context']==1
    def test_rejects_test_split(self):
        p=self.write([self.entry(1,'2026-04-04T10:00:00Z','GetObject',split='test')])
        with self.assertRaisesRegex(ValueError,'TrainOn'):
            mod.analyze(p,self.root/'out')
    def test_rejects_duplicate_id(self):
        p=self.write([self.entry(1,'2026-04-04T10:00:00Z','GetObject'),
                      self.entry(1,'2026-04-04T10:02:00Z','GetObject')])
        with self.assertRaisesRegex(ValueError,'duplicate'):
            mod.analyze(p,self.root/'out')
    def test_rejects_timezone_less(self):
        p=self.write([self.entry(1,'2026-04-04T10:00:00','GetObject')])
        with self.assertRaisesRegex(ValueError,'timezone'):
            mod.analyze(p,self.root/'out')
    def test_not_restrict_to_s3(self):
        p=self.write([self.entry(1,'2026-04-04T10:00:00Z','AssumeRole','1',source='sts.amazonaws.com')])
        report=mod.analyze(p,self.root/'out')
        assert report['s3_training_events']==0

if __name__=='__main__':unittest.main()
