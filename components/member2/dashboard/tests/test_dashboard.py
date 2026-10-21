"""Unit and integration tests for Member 2 PP1 CloudShield dashboard.

Verifies:
1. Model directory and checkpoint resolution across all three model variants
   (pp1_public_weighted_meta_PROTO, pp1_public_cloudtrail_PROTO, pp1_mixed_PROTO).
2. Saved decision policy resolution and audit compliance.
3. Immutability of original baseline public benchmark metrics (F1 = 0.000).
4. Accuracy and repeatability of the weighted stacking candidate (F1 = 0.3357, Recall = 0.9231).
5. Exact probability vector ordering [RF, LGBM, XGB, LSTM] into meta-learner.
6. Automatic decision policy threshold resolution vs. manual override tracking in inference.
7. Member 4 v2 envelope handoff schema and semantic validation.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

import joblib
import jsonschema
import numpy as np
import pandas as pd

TESTS_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = TESTS_DIR.parent
MEMBER2_DIR = DASHBOARD_DIR.parent
PROJECT_ROOT = MEMBER2_DIR.parents[3]
SRC_DIR = MEMBER2_DIR / "src"

sys.path.insert(0, str(DASHBOARD_DIR))
sys.path.insert(0, str(SRC_DIR))

from services.inference import run_inference, get_model_directory
from services.data_loader import (
    MODEL_VARIANTS,
    SAVED_OUTPUTS,
    get_report_for_variant,
    get_saved_predictions_for_variant,
    get_verified_comparison_csv,
    get_source_bias_report,
    get_decision_policy,
    get_scenario_detection_table,
    get_feature_whitelist,
    get_contract_files,
)
import validate_pp1_member4_v2_PROTO as val


class DashboardInferenceTests(unittest.TestCase):
    def setUp(self):
        self.attack_path = PROJECT_ROOT / "Data" / "Demo" / "pp1_heldout_attack_PROTO.json"
        self.benign_path = PROJECT_ROOT / "Data" / "Demo" / "pp1_heldout_benign_PROTO.json"
        self.example_path = PROJECT_ROOT / "Data" / "Demo" / "example_cloudtrail_synthetic.json"
        schema_path, _ = get_contract_files()
        self.schema = json.loads(schema_path.read_text(encoding="utf-8-sig"))

    def test_model_directory_resolution(self):
        # 1. Original public baseline
        dir_public = get_model_directory("pp1_public_cloudtrail_PROTO")
        self.assertTrue((dir_public / "tree_models_and_meta_PROTO.joblib").is_file())
        self.assertTrue((dir_public / "lstm_PROTO.pt").is_file())
        self.assertTrue((dir_public / "decision_policy.json").is_file())

        # 2. Mixed prototype
        dir_mixed = get_model_directory("pp1_mixed_PROTO")
        self.assertTrue((dir_mixed / "tree_models_and_meta_PROTO.joblib").is_file())
        self.assertTrue((dir_mixed / "lstm_PROTO.pt").is_file())
        self.assertTrue((dir_mixed / "decision_policy.json").is_file())

        # 3. Improved weighted stacking candidate
        dir_weighted = get_model_directory("pp1_public_weighted_meta_PROTO")
        self.assertTrue((dir_weighted / "tree_models_and_meta_PROTO.joblib").is_file())
        self.assertTrue((dir_weighted / "lstm_PROTO.pt").is_file())
        self.assertTrue((dir_weighted / "feature_whitelist.json").is_file())
        self.assertTrue((dir_weighted / "decision_policy.json").is_file())
        self.assertTrue((dir_weighted / "weighted_meta_experiment_report_PROTO.json").is_file())
        self.assertTrue((dir_weighted / "meta_candidate_protocol_PROTO.json").is_file())

    def test_meta_learner_probability_vector_order(self):
        """Verify the 4 base model probabilities enter the meta-learner in exact verified order."""
        for variant in ["pp1_public_weighted_meta_PROTO", "pp1_public_cloudtrail_PROTO", "pp1_mixed_PROTO"]:
            model_dir = get_model_directory(variant)
            ckpt = joblib.load(model_dir / "tree_models_and_meta_PROTO.joblib")
            policy, _ = get_decision_policy(variant)
            self.assertIsNotNone(policy)
            
            # Check policy documents exact probability ordering
            expected_order = ["Random Forest", "LightGBM", "XGBoost", "LSTM"]
            self.assertEqual(
                policy["meta_learner"]["probability_input_order"],
                expected_order,
                f"Feature ordering mismatch in policy for {variant}",
            )
            # Check meta learner expects 4 input features
            meta_learner = ckpt["meta"]
            self.assertEqual(meta_learner.coef_.shape[1], 4)
            self.assertEqual(meta_learner.n_features_in_, 4)

    def test_automatic_policy_threshold_resolution(self):
        """Verify default inference uses decision policy threshold and marks override=False."""
        data = self.attack_path.read_bytes()
        res = run_inference(data, self.attack_path.name, "pp1_public_weighted_meta_PROTO", threshold=None)
        summary = res["summary"]
        self.assertEqual(summary["decision_threshold"], 0.50)
        self.assertEqual(summary["threshold_source"], "saved_decision_policy")
        self.assertFalse(summary["is_manual_override"])

    def test_manual_threshold_override_tracking(self):
        """Verify passing an explicit threshold marks is_manual_override=True."""
        data = self.attack_path.read_bytes()
        res = run_inference(data, self.attack_path.name, "pp1_public_weighted_meta_PROTO", threshold=0.35)
        summary = res["summary"]
        self.assertEqual(summary["decision_threshold"], 0.35)
        self.assertEqual(summary["threshold_source"], "manual_override")
        self.assertTrue(summary["is_manual_override"])

    def test_run_inference_attack_heldout_mixed(self):
        data = self.attack_path.read_bytes()
        res = run_inference(data, self.attack_path.name, "pp1_mixed_PROTO")

        self.assertIn("predictions", res)
        self.assertIn("summary", res)
        self.assertIn("handoff", res)

        df = res["predictions"]
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 3)

        expected_cols = [
            "window_start_utc", "event_count", "prob_Random_Forest",
            "prob_LightGBM", "prob_XGBoost", "prob_LSTM",
            "stacked_malicious_score", "predicted_activity", "predicted_binary",
        ]
        for col in expected_cols:
            self.assertIn(col, df.columns)

        summary = res["summary"]
        self.assertEqual(summary["source_record_count"], 36)
        self.assertEqual(summary["window_count"], 3)
        self.assertEqual(summary["malicious_windows"], 1)
        self.assertEqual(summary["benign_windows"], 2)
        self.assertEqual(summary["member4_v2_contract_status"], "PASS")

        # Validate against schema
        handoff = res["handoff"]
        jsonschema.validate(handoff, self.schema)
        val_errors = val.validate_v2(handoff)
        self.assertEqual(val_errors, [])

    def test_run_inference_attack_heldout_weighted_candidate(self):
        """Run inference on the improved public candidate with heldout attack data."""
        data = self.attack_path.read_bytes()
        res = run_inference(data, self.attack_path.name, "pp1_public_weighted_meta_PROTO")

        self.assertIn("predictions", res)
        self.assertIn("summary", res)
        self.assertIn("handoff", res)

        df = res["predictions"]
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 3)

        summary = res["summary"]
        self.assertEqual(summary["source_record_count"], 36)
        self.assertEqual(summary["window_count"], 3)
        self.assertEqual(summary["member4_v2_contract_status"], "PASS")

        # Validate Member 4 v2 contract envelope
        handoff = res["handoff"]
        jsonschema.validate(handoff, self.schema)
        val_errors = val.validate_v2(handoff)
        self.assertEqual(val_errors, [])

    def test_run_inference_benign_heldout(self):
        data = self.benign_path.read_bytes()
        res = run_inference(data, self.benign_path.name, "pp1_mixed_PROTO")

        summary = res["summary"]
        self.assertEqual(summary["malicious_windows"], 0)
        self.assertEqual(summary["benign_windows"], 5)
        self.assertEqual(summary["member4_v2_contract_status"], "PASS")

        handoff = res["handoff"]
        jsonschema.validate(handoff, self.schema)
        val_errors = val.validate_v2(handoff)
        self.assertEqual(val_errors, [])

    def test_run_inference_public_cloudtrail_model(self):
        data = self.example_path.read_bytes()
        res = run_inference(data, self.example_path.name, "pp1_public_cloudtrail_PROTO")

        summary = res["summary"]
        self.assertEqual(summary["window_count"], 1)
        self.assertEqual(summary["malicious_windows"], 0)
        self.assertEqual(summary["member4_v2_contract_status"], "PASS")

        handoff = res["handoff"]
        jsonschema.validate(handoff, self.schema)

    def test_rejection_of_empty_and_unsupported(self):
        with self.assertRaises(ValueError):
            run_inference(b"", "empty.json", "pp1_mixed_PROTO")

        with self.assertRaisesRegex(ValueError, "Direct CSV inference is not supported"):
            run_inference(b"col1,col2\n1,2\n", "test.csv", "pp1_mixed_PROTO")

        with self.assertRaisesRegex(ValueError, "Unsupported file format"):
            run_inference(b"some text", "test.txt", "pp1_mixed_PROTO")


class DashboardDataLoaderTests(unittest.TestCase):
    def test_variant_reports_exist(self):
        for v in MODEL_VARIANTS:
            report, path = get_report_for_variant(v)
            self.assertIsNotNone(report, f"Report missing for {v}")
            self.assertTrue(path.is_file(), f"Report path missing for {v}")

    def test_saved_predictions_exist(self):
        for v in MODEL_VARIANTS:
            df, path = get_saved_predictions_for_variant(v)
            self.assertIsNotNone(df, f"Saved predictions missing for {v}")
            self.assertFalse(df.empty)

    def test_verified_comparison_csv_preserves_baseline_and_models(self):
        """Verify baseline benchmark file is intact and shows original Stacking F1=0.000."""
        df, path = get_verified_comparison_csv()
        self.assertIsNotNone(df)
        self.assertIn("model", df.columns)
        self.assertIn("f1", df.columns)

        stacking_row = df[df["model"] == "Stacking ensemble"]
        self.assertFalse(stacking_row.empty)
        self.assertAlmostEqual(float(stacking_row["f1"].iloc[0]), 0.000, places=4)

        lgbm_row = df[df["model"] == "LightGBM"]
        self.assertFalse(lgbm_row.empty)
        self.assertAlmostEqual(float(lgbm_row["f1"].iloc[0]), 0.8070, places=3)

    def test_weighted_candidate_test_repeatability(self):
        """Verify weighted candidate test predictions CSV matches exact frozen benchmark."""
        df, path = get_saved_predictions_for_variant("pp1_public_weighted_meta_PROTO")
        self.assertIsNotNone(df)
        self.assertEqual(len(df), 1120)

        # Ground truth and predicted columns
        y_true = df["label_binary"].values
        y_pred = df["candidate_predicted_binary"].values
        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))
        tn = int(np.sum((y_true == 0) & (y_pred == 0)))

        self.assertEqual(tp, 24, "Candidate must detect 24 of 26 attack windows")
        self.assertEqual(fp, 93, "Candidate FP must be exactly 93")
        self.assertEqual(fn, 2, "Candidate FN must be exactly 2")
        self.assertEqual(tn, 1001, "Candidate TN must be exactly 1001")

        precision = tp / (tp + fp)
        recall = tp / (tp + fn)
        f1 = 2 * precision * recall / (precision + recall)
        self.assertAlmostEqual(precision, 0.205128, places=4)
        self.assertAlmostEqual(recall, 0.923077, places=4)
        self.assertAlmostEqual(f1, 0.335664, places=4)

    def test_decision_policies_all_exist_and_conform(self):
        """Verify decision_policy.json is present and valid for all 3 variants."""
        for v in MODEL_VARIANTS:
            policy, path = get_decision_policy(v)
            self.assertIsNotNone(policy, f"Missing decision policy for {v}")
            self.assertTrue(path.is_file())
            self.assertIn("decision_threshold", policy)
            self.assertIn("scoring_objective", policy)
            self.assertIn("calibration_warning", policy)
            self.assertIn("artifact_sha256", policy)
            self.assertEqual(policy["decision_threshold"], 0.50)
            self.assertFalse(policy.get("test_set_used_for_tuning", True))

    def test_meta_candidate_protocol_guarantees_zero_test_leakage(self):
        """Audit the protocol JSON to confirm zero publisher test leakage."""
        protocol_path = (
            MEMBER2_DIR / "models" / "pp1_public_weighted_meta_PROTO" / "meta_candidate_protocol_PROTO.json"
        )
        self.assertTrue(protocol_path.is_file())
        protocol = json.loads(protocol_path.read_text(encoding="utf-8-sig"))

        self.assertTrue(protocol.get("no_publisher_test_based_model_selection"))
        self.assertEqual(protocol.get("fit_rows"), 4313)
        self.assertEqual(protocol.get("fit_positives"), 13)
        self.assertEqual(protocol.get("train_positive_groups"), 6)
        self.assertEqual(protocol.get("threshold"), 0.5)
        self.assertEqual(protocol.get("class_weight"), "balanced")

    def test_scenario_detection_tables(self):
        """Verify per-scenario detection tables for public variants."""
        df_w, label_w = get_scenario_detection_table("pp1_public_weighted_meta_PROTO")
        self.assertIsNotNone(df_w)
        self.assertEqual(len(df_w), 10)
        # Note: 29 scenario-window occurrences across 10 scenarios (due to multi-scenario windows)
        self.assertEqual(int(df_w["positive_test_windows"].sum()), 29)
        self.assertEqual(int(df_w["detected_positive_windows"].sum()), 27)
        self.assertEqual(len(df_w[df_w["window_recall"] == 1.0]), 8)

        df_b, label_b = get_scenario_detection_table("pp1_public_cloudtrail_PROTO")
        self.assertIsNotNone(df_b)
        self.assertEqual(len(df_b), 10)
        self.assertEqual(int(df_b["detected_positive_windows"].sum()), 0)
        self.assertEqual(len(df_b[df_b["window_recall"] == 0.0]), 10)

    def test_source_bias_report(self):
        data, path = get_source_bias_report()
        self.assertIsNotNone(data)
        self.assertIn("stacking_ensemble", data)

    def test_saved_outputs_all_exist(self):
        for label, item in SAVED_OUTPUTS.items():
            path = item["path"]
            self.assertTrue(path.is_file(), f"Saved output missing: {label} -> {path}")

    def test_contract_schema_and_canonical_example(self):
        schema_path, example_path = get_contract_files()
        self.assertTrue(schema_path.is_file())
        self.assertTrue(example_path.is_file())

        schema = json.loads(schema_path.read_text(encoding="utf-8-sig"))
        example = json.loads(example_path.read_text(encoding="utf-8-sig"))
        jsonschema.validate(example, schema)
        self.assertEqual(val.validate_v2(example), [])


if __name__ == "__main__":
    unittest.main()


