"""Member 2 PP1 Dashboard Data Loader Service.

Provides safe, cached access to verified experimental results, reports,
prediction files, decision policies, and contract schemas.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

SERVICES_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = SERVICES_DIR.parent
MEMBER2_DIR = DASHBOARD_DIR.parent
GROUP_DIR = MEMBER2_DIR.parents[1]       # Development/J26-CS-308
PROJECT_ROOT = MEMBER2_DIR.parents[3]    # Research Project
GROUP_RESULTS = GROUP_DIR / "results" / "member2"
EXPERIMENTS_DIR = PROJECT_ROOT / "Data" / "Experiments"

MODEL_VARIANTS = {
    "pp1_public_weighted_meta_PROTO": {
        "label": "Improved Public Candidate (Balanced Stacking)",
        "track_category": "Improved Public Experimental Candidate",
        "provenance": "Publisher Ariel CloudTrail benchmark with class_weight='balanced' meta-learner (C=0.7, threshold=0.5)",
        "report": MEMBER2_DIR / "models" / "pp1_public_weighted_meta_PROTO" / "weighted_meta_experiment_report_PROTO.json",
        "prediction_csv": EXPERIMENTS_DIR / "pp1_public_weighted_meta_PROTO" / "weighted_public_test_predictions_PROTO.csv",
        "model_dir": MEMBER2_DIR / "models" / "pp1_public_weighted_meta_PROTO",
        "decision_policy": MEMBER2_DIR / "models" / "pp1_public_weighted_meta_PROTO" / "decision_policy.json",
    },
    "pp1_public_cloudtrail_PROTO": {
        "label": "Original Public Baseline (Unweighted Stacking)",
        "track_category": "Original Public Baseline",
        "provenance": "Publisher Ariel CloudTrail benchmark; unweighted Logistic Regression stacking (F1=0.000 baseline at 0.5)",
        "report": MEMBER2_DIR / "models" / "pp1_public_cloudtrail_PROTO" / "public_experiment_report_PROTO.json",
        "prediction_csv": EXPERIMENTS_DIR / "pp1_public_cloudtrail_PROTO" / "public_test_predictions_PROTO.csv",
        "model_dir": MEMBER2_DIR / "models" / "pp1_public_cloudtrail_PROTO",
        "decision_policy": MEMBER2_DIR / "models" / "pp1_public_cloudtrail_PROTO" / "decision_policy.json",
    },
    "pp1_mixed_PROTO": {
        "label": "Mixed-Source Prototype (Splunk + Synthetic + Stratus)",
        "track_category": "Mixed/Synthetic PP1 Prototype",
        "provenance": "Mixed-source: Splunk scenario candidates, generated normal baseline, controlled attack injection",
        "report": MEMBER2_DIR / "models" / "pp1_mixed_PROTO" / "mixed_experiment_report_PROTO.json",
        "prediction_csv": EXPERIMENTS_DIR / "pp1_mixed_PROTO" / "test_predictions_PROTO.csv",
        "model_dir": MEMBER2_DIR / "models" / "pp1_mixed_PROTO",
        "decision_policy": MEMBER2_DIR / "models" / "pp1_mixed_PROTO" / "decision_policy.json",
    },
}

SAVED_OUTPUTS = {
    "Viva: benign inference": {
        "path": EXPERIMENTS_DIR / "viva_final_20261020" / "benign_inference_PROTO.json",
        "type": "Inference Report",
        "provenance": "Viva final 2026-10-20 benchmark: held-out benign session",
    },
    "Viva: Stratus StopLogging inference": {
        "path": EXPERIMENTS_DIR / "viva_final_20261020" / "stratus_stop_inference_PROTO.json",
        "type": "Inference Report",
        "provenance": "Viva final 2026-10-20 benchmark: Stratus detonation StopLogging",
    },
    "Viva: Member 4 handoff": {
        "path": EXPERIMENTS_DIR / "viva_final_20261020" / "stratus_stop_member4_v2_PROTO.json",
        "type": "Member 4 Handoff (v2)",
        "provenance": "Viva final 2026-10-20 validated contract envelope",
    },
    "Saved attack predictions": {
        "path": EXPERIMENTS_DIR / "pp1_inference" / "attack_predictions_PROTO.json",
        "type": "Inference Report",
        "provenance": "PP1 synthetic attack session inference output",
    },
    "Saved benign predictions": {
        "path": EXPERIMENTS_DIR / "pp1_inference" / "benign_predictions_PROTO.json",
        "type": "Inference Report",
        "provenance": "PP1 synthetic benign session inference output",
    },
    "Member 2: handoff example": {
        "path": MEMBER2_DIR / "examples" / "stratus_stop_member4_v2_PROTO.json",
        "type": "Member 4 Handoff (v2)",
        "provenance": "Member 2 canonical contract v2 example for Stratus StopLogging",
    },
}


def relative_location(path: Path) -> str:
    """Format path relative to Research Project root for portable display."""
    try:
        return str(path.relative_to(PROJECT_ROOT)).replace("\\", "/")
    except ValueError:
        return path.name


@st.cache_data(show_spinner=False, ttl=60)
def load_csv(path_string: str) -> pd.DataFrame:
    return pd.read_csv(path_string, low_memory=False)


@st.cache_data(show_spinner=False, ttl=60)
def load_json(path_string: str) -> Any:
    return json.loads(Path(path_string).read_text(encoding="utf-8-sig"))


def get_decision_policy(variant: str) -> tuple[dict[str, Any] | None, Path | None]:
    """Retrieve decision policy specifying validated threshold and protocol."""
    candidates = [
        MEMBER2_DIR / "models" / variant / "decision_policy.json",
        GROUP_RESULTS / variant / "decision_policy.json",
        EXPERIMENTS_DIR / variant / "decision_policy.json",
    ]
    for p in candidates:
        if p.is_file():
            try:
                return load_json(str(p)), p
            except Exception:
                pass
    return None, None


def get_report_for_variant(variant: str) -> tuple[dict[str, Any] | None, Path]:
    meta = MODEL_VARIANTS.get(variant, {})
    path = meta.get("report")
    if path is None:
        return None, Path("unknown")
    if not path.is_file():
        export = GROUP_RESULTS / variant / path.name
        path = export if export.is_file() else path
    if not path.is_file():
        exp_fallback = EXPERIMENTS_DIR / variant / path.name
        path = exp_fallback if exp_fallback.is_file() else path
    if not path.is_file():
        return None, path
    try:
        content = load_json(str(path))
        return content if isinstance(content, dict) else {"report": content}, path
    except Exception:
        return None, path


def get_saved_predictions_for_variant(variant: str) -> tuple[pd.DataFrame | None, Path]:
    meta = MODEL_VARIANTS.get(variant, {})
    path = meta.get("prediction_csv")
    if path is None or not path.is_file():
        return None, path or Path("unknown")
    try:
        return load_csv(str(path)), path
    except Exception:
        return None, path


def get_verified_comparison_csv() -> tuple[pd.DataFrame | None, Path | None]:
    candidates = [
        GROUP_RESULTS / "pp1_public_scenario_models_PROTO" / "public_model_metrics_verified_PROTO.csv",
        EXPERIMENTS_DIR / "pp1_public_scenario_models_PROTO" / "public_model_metrics_verified_PROTO.csv",
        EXPERIMENTS_DIR / "viva_readiness_20261017" / "all_model_scenarios" / "public_model_metrics_verified_PROTO.csv",
    ]
    for p in candidates:
        if p.is_file():
            try:
                return load_csv(str(p)), p
            except Exception:
                pass
    return None, None


def get_source_bias_report() -> tuple[dict[str, Any] | None, Path | None]:
    candidates = [
        GROUP_RESULTS / "pp1_source_bias_PROTO" / "source_bias_report_PROTO.json",
        EXPERIMENTS_DIR / "pp1_source_bias_PROTO" / "source_bias_report_PROTO.json",
    ]
    for p in candidates:
        if p.is_file():
            try:
                return load_json(str(p)), p
            except Exception:
                pass
    return None, None


def get_scenario_detection_table(variant: str) -> tuple[pd.DataFrame | None, str]:
    """Retrieve per-scenario detection metrics for the variant."""
    if variant == "pp1_public_weighted_meta_PROTO":
        candidates = [
            GROUP_RESULTS / "pp1_public_weighted_meta_PROTO" / "weighted_attack_scenario_recall_PROTO.csv",
            EXPERIMENTS_DIR / "pp1_public_weighted_meta_PROTO" / "weighted_attack_scenario_recall_PROTO.csv",
        ]
        for p in candidates:
            if p.is_file():
                return load_csv(str(p)), "Balanced Stacking Candidate (10 Test Scenarios)"
        report, _ = get_report_for_variant(variant)
        if report and "per_scenario_candidate" in report:
            return pd.DataFrame(report["per_scenario_candidate"]), "Balanced Stacking Candidate (10 Test Scenarios)"
    elif variant == "pp1_public_cloudtrail_PROTO":
        report, _ = get_report_for_variant(variant)
        if report and "scenario_wise_detection" in report:
            df = pd.DataFrame(report["scenario_wise_detection"])
            return df, "Original Public CloudTrail Test Split Scenarios"
        scenario_csv = EXPERIMENTS_DIR / "pp1_public_cloudtrail_PROTO" / "public_attack_scenario_recall_PROTO.csv"
        if scenario_csv.is_file():
            return load_csv(str(scenario_csv)), "Saved public_attack_scenario_recall_PROTO.csv"
    elif variant == "pp1_mixed_PROTO":
        report, _ = get_report_for_variant(variant)
        if report and "external_stratus_approved_positive_windows" in report:
            data = [{
                "Dataset / Scenario": "External Stratus Detonations (Approved)",
                "Approved Positive Windows": report.get("external_stratus_approved_positive_windows"),
                "Detected Windows": report.get("external_stratus_detected_positive_windows"),
                "Recall": report.get("external_stratus_positive_recall", 1.0),
                "Scope": "Positive-only recall check (specificity not measurable)",
            }]
            return pd.DataFrame(data), "External Stratus Approved Positive Recall"
    return None, "No scenario table available"


def get_feature_whitelist(variant: str) -> tuple[dict[str, Any] | None, Path | None]:
    path = MEMBER2_DIR / "models" / variant / "feature_whitelist.json"
    if not path.is_file():
        path = GROUP_RESULTS / variant / "feature_whitelist.json"
    if not path.is_file():
        path = EXPERIMENTS_DIR / variant / "feature_whitelist.json"
    if path.is_file():
        try:
            return load_json(str(path)), path
        except Exception:
            pass
    return None, None


def get_contract_files() -> tuple[Path, Path]:
    schema = MEMBER2_DIR / "contracts" / "member2_to_member4_proto_v2.schema.json"
    example = MEMBER2_DIR / "examples" / "stratus_stop_member4_v2_PROTO.json"
    return schema, example
