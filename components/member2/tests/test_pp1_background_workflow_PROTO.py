import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from audit_pp1_background_workflow_PROTO import family, PATTERN, actor_hash, documentation_address, window_start

class PatternAuditTests(unittest.TestCase):
    def test_full_family(self):
        self.assertEqual(family(list(PATTERN)), 'full_nine_operation_inventory')
    def test_partial_family(self):
        self.assertEqual(family(sorted(PATTERN)[:7]+['LookupEvents']) if 'LookupEvents' not in sorted(PATTERN)[:7] else family(sorted(PATTERN)[:8]), 'partial_inventory_seven_eight')
    def test_other(self):
        self.assertEqual(family(['StopLogging']), 'other_behavior')
        self.assertEqual(family(['LookupEvents']*9), 'other_behavior')
    def test_doc_ip(self):
        self.assertTrue(documentation_address('203.0.113.42'))
        self.assertFalse(documentation_address('8.8.8.8'))
    def test_start(self):
        self.assertEqual(window_start('2026-02-03T11:07:01Z',5),'2026-02-03T11:05:00Z')
    def test_hash(self):
        self.assertEqual(len(actor_hash('203.0.113.42')),20)

if __name__=='__main__':
    unittest.main()
