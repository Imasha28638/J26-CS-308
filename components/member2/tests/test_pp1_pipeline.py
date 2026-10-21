import csv
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]/'src'
sys.path.insert(0,str(SCRIPTS))
from generate_benign_cloudtrail_pp1 import generate, CSV_FIELDS
from prepare_pp1_experiment import prepare
from train_pp1_binary_stack import prepare_windows, FEATURES, MAX_SEQ, SEQ_DIM, pad_sequences


class ControlledDemoTests(unittest.TestCase):
    def test_generated_synthetic_sessions_are_unique(self):
        _,rows,manifest,_=generate(sessions=5,seed=15)
        self.assertEqual(len(manifest),5)
        self.assertEqual(len(rows),len(set(r['event_id'] for r in rows)))

    def test_binary_window_labels_use_injection_not_source(self):
        _,b,_,_=generate(sessions=20,seed=5)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with (root/'benign.csv').open('w',newline='',encoding='utf-8-sig') as f:
                w=csv.DictWriter(f,fieldnames=CSV_FIELDS);w.writeheader();w.writerows(b)
            stats=prepare(root/'benign.csv',root/'out',attack_sessions=20,seed=6)
            with (root/'out'/'synthetic_experiment_events.csv').open('r',newline='',encoding='utf-8-sig') as f:
                rows=list(csv.DictReader(f))
            self.assertEqual(len(rows),stats['total_events'])
            self.assertTrue(all(r['event_origin']=='controlled_synthetic' for r in rows))
            self.assertTrue(all(r['injected_attack_event']=='0' for r in rows if r['simulation_session_id'].startswith('synthetic_benign_')))
            window_df,seqs=prepare_windows(rows,5)
            self.assertGreater(window_df.label_binary.sum(),0)
            self.assertGreater((window_df.label_binary==0).sum(),0)
            seq_arr,lengths=pad_sequences(seqs)
            self.assertEqual(seq_arr.shape,(len(window_df),MAX_SEQ,SEQ_DIM))
            self.assertTrue((lengths>0).all())
            self.assertNotIn('event_origin',FEATURES)
            self.assertNotIn('injected_attack_event',FEATURES)


if __name__=='__main__': unittest.main()
