"""Member 2 PP1 CloudShield Inference Service Adapter.

Connects the dashboard directly to the verified Member 2 inference pipeline:
- Development/J26-CS-308/components/member2/src/infer_pp1_cloudtrail.py
- Development/J26-CS-308/components/member2/src/convert_pp1_member4_v2_PROTO.py
- Development/J26-CS-308/components/member2/src/validate_pp1_member4_v2_PROTO.py

Executes real inference using saved models without stubs or fabricated scores.
Generates genuine Member 4 v2 contract envelopes with hash integrity.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
from typing import Any

import pandas as pd

# Resolve repository paths
SERVICES_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = SERVICES_DIR.parent
MEMBER2_DIR = DASHBOARD_DIR.parent
GROUP_DIR = MEMBER2_DIR.parents[1]       # Development/J26-CS-308
PROJECT_ROOT = MEMBER2_DIR.parents[3]    # Research Project
SRC_DIR = MEMBER2_DIR / "src"

# Ensure member2/src is on sys.path for direct imports
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    import infer_pp1_cloudtrail as inf
    import convert_pp1_member4_v2_PROTO as conv
    import validate_pp1_member4_v2_PROTO as val
except ImportError as exc:
    raise ImportError(
        f"Failed to load Member 2 inference pipeline from {SRC_DIR}: {exc}"
    ) from exc


def get_model_directory(model_variant: str) -> Path:
    """Resolve the directory containing verified saved checkpoints."""
    candidates = [
        MEMBER2_DIR / "models" / model_variant,
        PROJECT_ROOT / "Data" / "Experiments" / model_variant,
        GROUP_DIR / "results" / "member2" / model_variant,
    ]
    for candidate in candidates:
        if (candidate / inf.MODEL_FILENAME).is_file() and (candidate / inf.LSTM_FILENAME).is_file():
            return candidate
    raise FileNotFoundError(
        f"Saved model artifacts for variant '{model_variant}' were not found. "
        f"Checked: {[str(c) for c in candidates]}"
    )


def run_inference(
    log_bytes: bytes,
    filename: str,
    model_variant: str,
    window_minutes: int = 5,
    threshold: float | None = None,
    on_missing_readonly: str = "error",
) -> dict[str, Any]:
    """Execute the verified Member 2 inference pipeline on raw log bytes.

    Parameters:
        log_bytes: Raw bytes of the uploaded CloudTrail log file.
        filename: Original filename (used for extension check and provenance reference).
        model_variant: Key identifying the model directory.
        window_minutes: Window size in minutes (must divide 60, default 5).
        threshold: Binary decision threshold for the meta-learner (None loads saved decision policy).
        on_missing_readonly: 'error' (strict) or 'assume-read' (exploratory demo).

    Returns:
        dict with:
            'predictions': pandas.DataFrame containing window predictions and base model scores.
            'summary': dict with execution metrics, provenance, threshold policy, and contract status.
            'handoff': dict containing the validated Member 4 v2 envelope payload.
    """
    if not log_bytes or not log_bytes.strip():
        raise ValueError("Uploaded file is empty.")

    lower_name = filename.lower()
    if lower_name.endswith(".csv"):
        raise ValueError(
            "Direct CSV inference is not supported by the CloudTrail event parser. "
            "Please provide an AWS CloudTrail JSON ('Records': [...]), a JSON array, "
            "a single event JSON, or JSONL log file."
        )

    if not (lower_name.endswith(".json") or lower_name.endswith(".jsonl")):
        raise ValueError(
            f"Unsupported file format '{filename}'. Supported formats: .json, .jsonl"
        )

    models_dir = get_model_directory(model_variant)
    source_sha256 = hashlib.sha256(log_bytes).hexdigest()

    # Read decision policy if available
    policy_file = models_dir / "decision_policy.json"
    policy_data = {}
    if policy_file.is_file():
        try:
            policy_data = json.loads(policy_file.read_text(encoding="utf-8-sig"))
        except Exception:
            pass

    policy_threshold = float(policy_data.get("decision_threshold", 0.5))
    if threshold is None:
        active_threshold = policy_threshold
        threshold_source = "saved_decision_policy"
    else:
        active_threshold = float(threshold)
        threshold_source = "saved_decision_policy" if abs(active_threshold - policy_threshold) < 1e-5 else "manual_override"

    # Use an isolated temporary directory to prevent output collisions across runs
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        input_suffix = ".jsonl" if lower_name.endswith(".jsonl") else ".json"
        input_path = temp_dir / f"input{input_suffix}"
        input_path.write_bytes(log_bytes)

        report_path = temp_dir / "inference_report_PROTO.json"

        # 1. Run real base learners + stacking inference
        report, handoff_v1_path = inf.run(
            input_path=input_path,
            models_dir=models_dir,
            output_path=report_path,
            minutes=window_minutes,
            threshold=active_threshold,
            on_missing_readonly=on_missing_readonly,
            include_event_ids=True,
        )

        # 2. Parse events for Member 4 v2 conversion
        events = conv.load_cloudtrail_events(input_path)
        v1_handoff = json.loads(handoff_v1_path.read_text(encoding="utf-8-sig"))

        # 3. Convert to Member 4 v2 envelope
        source_reference = filename
        v2_handoff = conv.convert(
            v1=v1_handoff,
            report=report,
            events=events,
            source_reference=source_reference,
            source_file_hash=source_sha256,
        )

        # 4. Formally validate against Member 4 v2 contract rules
        validation_errors = val.check(
            payload=v2_handoff,
            source_events=input_path,
            report=report_path,
            handoff=handoff_v1_path,
        )

    # 5. Build structured predictions DataFrame
    rows = []
    for w in report.get("windows", []):
        scores = w.get("model_scores", {})
        rows.append({
            "window_id": w.get("window_id"),
            "window_start_utc": w.get("window_start_utc"),
            "actor_hash": w.get("actor_hash"),
            "actor_grouping_method": w.get("actor_grouping_method"),
            "event_count": w.get("event_count"),
            "prob_Random_Forest": scores.get("Random Forest", float("nan")),
            "prob_LightGBM": scores.get("LightGBM", float("nan")),
            "prob_XGBoost": scores.get("XGBoost", float("nan")),
            "prob_LSTM": scores.get("LSTM", float("nan")),
            "stacked_malicious_score": w.get("stacking_score", float("nan")),
            "model_disagreement": w.get("model_disagreement", float("nan")),
            "predicted_activity": w.get("predicted_activity"),
            "predicted_binary": w.get("predicted_binary"),
            "api_operations": json.dumps(w.get("api_operations", {})),
            "aws_services": ", ".join(w.get("aws_services", [])),
            "sample_api_names": ", ".join(w.get("sample_api_names", [])),
            "source_record_numbers": str(w.get("source_record_numbers", [])),
            "evidence_event_ids": ", ".join(w.get("event_ids", [])),
        })

    predictions_df = pd.DataFrame(rows)

    # 6. Build execution summary
    summary = {
        "input_filename": filename,
        "model_variant": model_variant,
        "models_directory": str(models_dir),
        "source_record_count": report.get("source_record_count", 0),
        "window_count": report.get("window_count", 0),
        "malicious_windows": int(sum(w.get("predicted_binary", 0) for w in report.get("windows", []))),
        "benign_windows": int(sum(1 for w in report.get("windows", []) if w.get("predicted_binary", 0) == 0)),
        "decision_threshold": active_threshold,
        "threshold_source": threshold_source,
        "validated_policy_threshold": policy_threshold,
        "is_manual_override": (threshold_source == "manual_override"),
        "decision_policy_name": policy_data.get("policy_name", "unspecified"),
        "calibration_status": policy_data.get("calibration_status", "uncalibrated_model_scores"),
        "window_minutes": window_minutes,
        "model_status": report.get("model_status"),
        "validation_status": report.get("validation_status"),
        "training_sources": report.get("training_provenance", {}).get("training_sources", []),
        "warnings": report.get("warnings", []),
        "member4_v2_contract_status": "PASS" if not validation_errors else "FAIL",
        "member4_v2_validation_errors": validation_errors,
        "member4_findings_count": len(v2_handoff.get("findings", [])),
        "source_file_sha256": source_sha256,
    }

    return {
        "predictions": predictions_df,
        "summary": summary,
        "handoff": v2_handoff,
    }
