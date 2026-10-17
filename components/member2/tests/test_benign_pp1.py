import importlib.util
import unittest
from pathlib import Path

P = Path(__file__).resolve().parents[1]/"src"/"generate_benign_cloudtrail_pp1.py"
spec = importlib.util.spec_from_file_location("benign", P)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class TestBenignGenerator(unittest.TestCase):
    def test_counts_unique_ids(self):
        es, rows, manifest, counts = mod.generate(sessions=12, seed=4010)
        self.assertEqual(len(manifest), 12)
        self.assertTrue(12*15 <= len(es) <= 12*45)
        self.assertEqual(len(set(e['eventID'] for e in es)),len(es))
        self.assertEqual(len(es), len(rows))
        self.assertTrue(all(r['label_binary']=='0' and r['exclude_from_approved_training']=='1' for r in rows))
        self.assertTrue(all(e['eventCategory']=='Management' for e in es))

    def test_repeatable(self):
        a=mod.generate(sessions=6,seed=100)
        b=mod.generate(sessions=6,seed=100)
        self.assertEqual(a[0],b[0])

    def test_good_and_errors(self):
        es,*_=mod.generate(sessions=120,seed=10)
        self.assertGreater(sum(bool(e.get('errorCode')) for e in es),0)
        self.assertGreater(sum(not e['readOnly'] for e in es),0)
        self.assertGreater(sum(bool(e['readOnly']) for e in es),0)

if __name__=='__main__': unittest.main()
