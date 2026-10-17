import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

MOD=Path(__file__).resolve().parents[1]/'src'/'import_pp1_public_cloudtrail_PROTO.py'
spec=importlib.util.spec_from_file_location('public_import',MOD)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def event(index,label=False,attack=None):
    r={'eventTime':f'2026-04-04T00:00:{index:02d}Z',
       'eventName':'GetCallerIdentity' if not label else 'DeleteTrail',
       'eventSource':'sts.amazonaws.com' if not label else 'cloudtrail.amazonaws.com',
       'eventID':f'00000000-0000-0000-0000-{index:012d}',
       'readOnly':not label,
       'userIdentity':{'arn':f'arn:aws:iam::123456789012:user/fixture{index%2}'},
       'should_sample':label}
    if label:r['attack_name']=attack or 'FixtureAttack'
    return r

def put(root,folder,name,records):
    p=root/folder/name;p.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(p,'w') as f:
        f.writestr('nested/events.json',json.dumps({'Records':records}))

class Tests(unittest.TestCase):
    def test_split_and_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            put(root,'TrainOn','base_a.zip',[event(1),event(2)])
            put(root,'TrainOn','train_labeled_a.zip',[event(3),event(4,True)])
            put(root,'TestOn','labeled_cloudtrail_a.zip',[event(5),event(6,True)])
            rep=m.import_dataset(root,root/'out')
            self.assertEqual((rep['train_total_after_dedup'],rep['test_total_after_dedup']), (4,2))
            self.assertEqual((rep['train_attack_events_after_dedup'],rep['test_attack_events_after_dedup']), (1,1))
            self.assertEqual(rep['train_test_event_id_overlap'],0)
            self.assertTrue((root/'out/ariel_train_events_PROTO.csv').exists())
    def test_exact_repeats_removed_and_audited(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            put(root,'TrainOn','base_a.zip',[event(1),event(1),event(2)])
            put(root,'TrainOn','train_labeled_a.zip',[event(3),event(4,True)])
            put(root,'TestOn','labeled_cloudtrail_a.zip',[event(5),event(5),event(6,True)])
            rep=m.import_dataset(root,root/'out')
            self.assertEqual(rep['exact_duplicate_rows_removed'],2)
            self.assertEqual((rep['train_total_after_dedup'],rep['test_total_after_dedup']), (4,2))
            self.assertEqual(rep['train_archive_cross_repetitions'],0)
            self.assertEqual(rep['train_test_event_id_overlap'],0)
            self.assertEqual(len((root/'out/ariel_duplicate_event_audit_PROTO.csv').read_text().splitlines()),3)

    def test_different_payload_same_id_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            altered=event(1);altered['eventName']='DescribeInstances'
            put(root,'TrainOn','base_a.zip',[event(1),altered])
            put(root,'TrainOn','train_labeled_a.zip',[event(3,True)])
            put(root,'TestOn','labeled_cloudtrail_a.zip',[event(5)])
            with self.assertRaisesRegex(ValueError,'REJECT_CONFLICT'):
                m.import_dataset(root,root/'out')
            rep=json.loads((root/'out/ariel_ingestion_manifest_PROTO.json').read_text())
            self.assertEqual(rep['conflicting_duplicate_rows'],1)
            self.assertFalse(rep['ready_for_experiment'])
            self.assertFalse((root/'out/ariel_train_events_PROTO.csv').exists())

    def test_train_archives_exact_duplicate_is_separately_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            put(root,'TrainOn','base_a.zip',[event(1),event(2)])
            put(root,'TrainOn','train_labeled_a.zip',[event(2),event(3,True)])
            put(root,'TestOn','labeled_cloudtrail_a.zip',[event(5)])
            rep=m.import_dataset(root,root/'out')
            self.assertEqual(rep['train_archive_cross_repetitions'],1)
            self.assertEqual(rep['exact_duplicate_rows_removed'],1)
            self.assertEqual(rep['train_total_after_dedup'],3)

    def test_conflicting_label_same_id_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            attack=event(1,True)
            put(root,'TrainOn','base_a.zip',[event(1)])
            put(root,'TrainOn','train_labeled_a.zip',[attack])
            put(root,'TestOn','labeled_cloudtrail_a.zip',[event(5)])
            with self.assertRaisesRegex(ValueError,'REJECT_CONFLICT'):
                m.import_dataset(root,root/'out')

    def test_overlap_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            put(root,'TrainOn','base_a.zip',[event(1)])
            put(root,'TrainOn','train_labeled_a.zip',[event(2,True)])
            put(root,'TestOn','labeled_cloudtrail_a.zip',[event(1)])
            with self.assertRaisesRegex(ValueError,'Dataset audit requires review'):
                m.import_dataset(root,root/'out')
            self.assertFalse((root/'out/ariel_train_events_PROTO.csv').exists())
            self.assertTrue((root/'out/ariel_ingestion_manifest_PROTO.json').exists())
            rep=json.loads((root/'out/ariel_ingestion_manifest_PROTO.json').read_text())
            self.assertEqual(rep['cross_split_duplicate_rows'],1)
    def test_missing_readonly_fails(self):
        e=event(11);del e['readOnly']
        with self.assertRaisesRegex(ValueError,'readOnly'):
            m.convert(e,'base_a.zip','train',1)
    def test_invalid_attack_label_fails(self):
        e=event(12);e['should_sample']='true'
        with self.assertRaisesRegex(ValueError,'should_sample'):
            m.convert(e,'base_a.zip','train',1)

if __name__=='__main__':unittest.main()
