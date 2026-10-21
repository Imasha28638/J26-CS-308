import copy
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "validate_pp1_member4_handoff_PROTO.py"
spec = importlib.util.spec_from_file_location("handoff_validator", SRC)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
EXAMPLE = json.loads((ROOT / "examples" / "stratus_stop_handoff_example_PROTO.json").read_text())

class TestHandoffContract(unittest.TestCase):
    def test_valid_input(self):
        self.assertEqual(mod.validate_handoff(EXAMPLE), [])

    def test_empty_findings_allowed(self):
        data = copy.deepcopy(EXAMPLE)
        data["findings"] = []
        self.assertEqual(mod.validate_handoff(data), [])

    def test_inconsistent_activity_rejected(self):
        data = copy.deepcopy(EXAMPLE)
        data["findings"][0]["activity"] = "BENIGN_PATTERN"
        self.assertTrue(any("inconsistent" in e for e in mod.validate_handoff(data)))

    def test_missing_evidence_rejected(self):
        data = copy.deepcopy(EXAMPLE)
        data["findings"][0]["evidence_record_numbers"] = []
        self.assertTrue(any("count must match" in e for e in mod.validate_handoff(data)))

    def test_category_must_be_null(self):
        data = copy.deepcopy(EXAMPLE)
        data["findings"][0]["attack_category"] = "Defense Evasion"
        self.assertTrue(any("requires null" in e for e in mod.validate_handoff(data)))

    def test_bad_score_rejected(self):
        data = copy.deepcopy(EXAMPLE)
        data["findings"][0]["stacking_score"] = float("nan")
        self.assertTrue(any("finite" in e for e in mod.validate_handoff(data)))

    def test_crosscheck_passes(self):
        f = EXAMPLE["findings"][0]
        w = {
            "window_id": f["finding_id"],
            "window_start_utc": f["event_window_start_utc"],
            "actor_hash": f["actor_hash"],
            "predicted_activity": f["activity"],
            "predicted_binary": f["predicted_binary"],
            "stacking_score": f["stacking_score"],
            "model_disagreement": f["model_disagreement"],
            "api_operations": f["api_operations"],
            "aws_services": f["aws_services"],
            "event_count": f["event_count"],
            "source_record_numbers": f["evidence_record_numbers"],
        }
        report = {"windows": [w], "source_record_count": 1, "decision_threshold": 0.5}
        self.assertEqual(mod.reconcile(EXAMPLE, report), [])
        report["windows"][0]["stacking_score"] = 0.2
        self.assertTrue(any("stacking_score" in e for e in mod.reconcile(EXAMPLE, report)))

    def test_duplicate_record_between_findings_rejected(self):
        data = copy.deepcopy(EXAMPLE)
        extra = copy.deepcopy(data["findings"][0])
        extra["finding_id"] = "other_finding"
        data["findings"].append(extra)
        self.assertTrue(any("another finding" in e for e in mod.validate_handoff(data)))

if __name__ == "__main__":
    unittest.main()
