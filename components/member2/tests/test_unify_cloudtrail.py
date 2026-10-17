import importlib.util
import pathlib
import unittest
from datetime import datetime, timezone

FILE=pathlib.Path(__file__).resolve().parents[1]/'src'/'unify_cloudtrail.py'
spec=importlib.util.spec_from_file_location('unify_cloudtrail',FILE)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def src_row(**patch):
    b={'source_file':'some.json','record_index':'1','event_id':'id1',
       'event_time':'2026-01-01T00:00:00Z','event_name':'StopLogging',
       'event_source':'cloudtrail.amazonaws.com','label_binary':'1',
       'attack_class':'Defense Evasion','label_scope':'event_rule',
       'identity_arn':'arn:aws:iam::000000000000:user/alpha'}
    b.update(patch)
    return b


class UnificationTests(unittest.TestCase):
    def test_review_candidate_is_not_approved(self):
        r=mod.normalize(src_row(label_status='review_candidate',exclude_from_training='1'),'stratus')
        self.assertEqual(r['source_label_binary'],'1')
        self.assertEqual(r['approval_status'],'unapproved')
        self.assertEqual(r['approved_binary'],'')
        self.assertEqual(r['source_excluded_from_training'],'1')

    def test_invictus_unlabeled(self):
        r=mod.normalize(src_row(actor_arn='arn:aws:iam::123:user/test',source_ip='10.0.0.2',
                     label_binary='1',attack_class='Discovery'),'invictus')
        self.assertEqual(r['source_label_binary'],'')
        self.assertEqual(r['source_attack_class'],'')
        self.assertEqual(r['source_ip_address'],'10.0.0.2')
        self.assertEqual(r['identity_arn'],'arn:aws:iam::123:user/test')

    def test_sandbox_benign_is_not_inferred(self):
        r=mod.normalize(src_row(label_binary='0',attack_class='Benign'),'sandbox')
        self.assertEqual(r['source_label_binary'],'')
        self.assertEqual(r['approved_binary'],'')
        self.assertEqual(r['read_only'],'')

    def test_collision_blocks_approval(self):
        a=mod.normalize(src_row(),'splunk')
        b=mod.normalize(src_row(record_index='2',source_file='other.json'),'stratus')
        overlaps=mod.collate_collisions([a,b])
        self.assertEqual(len(overlaps),1)
        self.assertEqual(a['cross_source_event_id_overlap'],'1')
        with self.assertRaises(ValueError):
            mod.apply_approvals([a,b],{a['record_key']:('1','Defense Evasion','operator audit log')})

    def test_homogeneous_window_needs_all_events_approved(self):
        a=mod.normalize(src_row(),'splunk')
        b=mod.normalize(src_row(record_index='2',event_id='id2',event_time='2026-01-01T00:00:01Z'),'splunk')
        windows, approved, seq, manifest = mod.windows_and_sequences([a,b],5)
        self.assertEqual(len(windows),1)
        self.assertEqual(windows[0]['window_label_status'],'not_approved')
        self.assertEqual(len(approved),0)
        mod.apply_approvals([a,b],{
            a['record_key']:('1','Defense Evasion','documented attack run 1'),
            b['record_key']:('1','Defense Evasion','documented attack run 1')
        })
        windows, approved, seq, manifest = mod.windows_and_sequences([a,b],5)
        self.assertEqual(len(approved),1)
        self.assertEqual(approved[0]['window_approved_binary'],'1')
        self.assertEqual(len(seq),2)

    def test_only_shared_features_whitelisted(self):
        self.assertNotIn('unknown_readonly_count',mod.SHARED_TABULAR_FEATURES)
        self.assertNotIn('unique_regions',mod.SHARED_TABULAR_FEATURES)
        self.assertNotIn('is_read_unknown',mod.SHARED_SEQUENCE_FEATURES)
        self.assertNotIn('source_key',mod.SHARED_TABULAR_FEATURES)

if __name__=='__main__':unittest.main()
