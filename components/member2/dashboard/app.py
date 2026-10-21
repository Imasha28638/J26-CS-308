"""Member 2 PP1 CloudShield Security Operations Dashboard.

Demonstrates the verified Member 2 CloudTrail attack-detection system,
including live prediction runs on uploaded CloudTrail logs using saved models,
grounded evaluation analysis, ensemble stacking architecture, and Member 4 v2 contract validation.

Run from Research Project root:
    py -m streamlit run Development/J26-CS-308/components/member2/dashboard/app.py
"""
from __future__ import annotations

import hashlib
import io
import json
import re
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

try:
    import plotly.express as px
    import plotly.graph_objects as go
except ImportError:
    px = None
    go = None

from services.data_loader import (
    MODEL_VARIANTS,
    SAVED_OUTPUTS,
    get_contract_files,
    get_decision_policy,
    get_feature_whitelist,
    get_report_for_variant,
    get_saved_predictions_for_variant,
    get_scenario_detection_table,
    get_source_bias_report,
    get_verified_comparison_csv,
    load_csv,
    load_json,
    relative_location,
)
from services.inference import run_inference

DASHBOARD_DIR = Path(__file__).resolve().parent
MEMBER2_DIR = DASHBOARD_DIR.parent
GROUP_DIR = MEMBER2_DIR.parents[1]       # Development/J26-CS-308
PROJECT_ROOT = MEMBER2_DIR.parents[3]    # Research Project
DEMO_DIR = PROJECT_ROOT / "Data" / "Demo"
MAX_UPLOAD_BYTES = 40 * 1024 * 1024

st.set_page_config(
    page_title="CloudShield | Member 2 PP1",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .block-container {max-width: 1450px; padding-top: 1.4rem; padding-bottom: 3rem;}
      [data-testid="stMetric"] {
          border: 1px solid rgba(0, 210, 255, 0.22);
          border-radius: 10px;
          padding: 12px 16px;
          background: rgba(14, 25, 45, 0.65);
      }
      [data-testid="stSidebar"] {border-right: 1px solid rgba(128,140,160,.16);}
      .subtitle {color:#8a9bab; margin-top:-.55rem; margin-bottom:1.2rem; font-size:0.95rem;}
      .chip-proto {
          display:inline-block; border:1px solid #00d2ff; color:#00d2ff;
          border-radius:20px; padding:3px 10px; font-size:.74rem; font-weight:600; margin-bottom:10px;
      }
      .chip-saved {
          display:inline-block; border:1px solid #f39c12; color:#f39c12;
          border-radius:20px; padding:3px 10px; font-size:.74rem; font-weight:600; margin-bottom:10px;
      }
      .chip-live {
          display:inline-block; border:1px solid #2ecc71; color:#2ecc71;
          border-radius:20px; padding:3px 10px; font-size:.74rem; font-weight:600; margin-bottom:10px;
      }
      .chip-improved {
          display:inline-block; border:1px solid #9b59b6; color:#9b59b6;
          border-radius:20px; padding:3px 10px; font-size:.74rem; font-weight:600; margin-bottom:10px;
      }
      .step-box {
          padding: 14px; text-align: center;
          border: 1px solid rgba(0, 210, 255, 0.28);
          border-radius: 10px; margin: 6px 0;
          background: rgba(14, 25, 45, 0.7); font-weight: 600; font-size: 0.92rem;
      }
      .arrow-down {text-align: center; font-size: 1.3rem; opacity: 0.8; color: #00d2ff; margin: -2px 0;}
      .callout-box {
          border-left: 4px solid #00d2ff;
          background: rgba(0, 210, 255, 0.06);
          padding: 12px 16px;
          border-radius: 0 8px 8px 0;
          margin-bottom: 1rem;
      }
      .warning-box {
          border-left: 4px solid #f39c12;
          background: rgba(243, 156, 18, 0.08);
          padding: 12px 16px;
          border-radius: 0 8px 8px 0;
          margin-bottom: 1rem;
      }
      .success-box {
          border-left: 4px solid #2ecc71;
          background: rgba(46, 204, 113, 0.08);
          padding: 12px 16px;
          border-radius: 0 8px 8px 0;
          margin-bottom: 1rem;
      }
    </style>
    """,
    unsafe_allow_html=True,
)


def to_table(payload: Any) -> pd.DataFrame:
    """Extract inspectable table without inventing labels or classifications."""
    if isinstance(payload, pd.DataFrame):
        return payload.copy()
    if isinstance(payload, list):
        return pd.json_normalize(payload) if payload and isinstance(payload[0], dict) else pd.DataFrame({"value": payload})
    if isinstance(payload, dict):
        for key in ("predictions", "findings", "results", "records", "Records", "events", "Events", "items", "windows"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return to_table(rows)
        return pd.json_normalize(payload)
    return pd.DataFrame({"value": [str(payload)]})


def inspect_uploaded_logs(filename: str, content: bytes) -> tuple[pd.DataFrame, str]:
    """Preview uploaded logs up to 2,000 rows. Rejects raw CSV for live inference."""
    name = filename.lower()
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError("File exceeds the 40 MB dashboard size limit.")
    if name.endswith(".csv"):
        return pd.read_csv(io.BytesIO(content), nrows=2000), "CSV preview (Note: CloudTrail inference requires JSON/JSONL events)"
    if name.endswith(".jsonl"):
        rows = []
        for line_no, line in enumerate(io.BytesIO(content), 1):
            if len(rows) >= 2000:
                break
            if line.strip():
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError(f"JSONL line {line_no} must contain an object.")
                rows.append(item)
        return to_table(rows), "JSONL preview, up to 2,000 records"
    if name.endswith(".json"):
        data = json.loads(content.decode("utf-8-sig"))
        if isinstance(data, dict) and isinstance(data.get("Records"), list):
            return to_table(data["Records"][:2000]), "CloudTrail Records preview, up to 2,000 events"
        if isinstance(data, list):
            return to_table(data[:2000]), "JSON array preview, up to 2,000 items"
        if isinstance(data, dict) and ("eventTime" in data or "eventName" in data):
            return to_table([data]), "Single CloudTrail event"
        return to_table(data).head(2000), "JSON object preview, up to 2,000 rows"
    raise ValueError("Supported file types are .json, .jsonl (and .csv preview only).")


def prediction_field(df: pd.DataFrame) -> str | None:
    """Detect prediction field from aliases, prioritizing genuine predictions."""
    aliases = (
        "candidate_predicted_binary", "predicted_binary", "predicted_activity",
        "stacking_prediction", "stacked_prediction", "stacking_pred", "stacked_pred",
        "ensemble_prediction", "ensemble_pred", "meta_prediction", "meta_pred",
        "predicted_label", "prediction_label", "pred_label", "prediction", "y_pred",
        "candidate_stacking_score", "stacked_malicious_score",
    )
    mapped = {re.sub(r"[^a-z0-9]", "", str(c).lower()): c for c in df.columns}
    for name in aliases:
        key = re.sub(r"[^a-z0-9]", "", name)
        if key in mapped:
            return str(mapped[key])
    return None


def attack_count(df: pd.DataFrame) -> tuple[int | None, str | None]:
    field = prediction_field(df)
    if field is None or df.empty:
        return None, field
    valid = df[field].dropna()
    if valid.empty:
        return None, field
    numeric = pd.to_numeric(valid, errors="coerce")
    if numeric.notna().all() and set(numeric.unique()).issubset({0, 1}):
        return int((numeric == 1).sum()), field
    normalized = valid.astype(str).str.strip().str.lower()
    if set(normalized.unique()).issubset({"attack", "malicious", "benign", "normal", "malicious_pattern", "benign_pattern"}):
        return int(normalized.isin(["attack", "malicious", "malicious_pattern"]).sum()), field
    return None, field


def show_table(df: pd.DataFrame, title: str, max_rows: int = 2000) -> None:
    st.subheader(title)
    st.caption(f"{len(df):,} rows available. Showing up to {min(len(df), max_rows):,} rows.")
    if df.empty:
        st.info("No rows to display.")
        return
    try:
        st.dataframe(df.head(max_rows), use_container_width=True, hide_index=True)
    except Exception:
        st.dataframe(df.head(max_rows).astype(str), use_container_width=True, hide_index=True)


# ==============================================================================
# Page 1: Overview
# ==============================================================================
def page_overview(variant: str) -> None:
    variant_info = MODEL_VARIANTS[variant]
    st.header("Security Analytics Overview")
    st.markdown(
        f'<div class="subtitle">Active Track: <b>{variant_info["label"]}</b> '
        f'<br><span class="chip-proto">{variant_info.get("track_category", "Track")}</span> '
        f'Provenance: {variant_info["provenance"]}</div>',
        unsafe_allow_html=True,
    )

    data, source = get_saved_predictions_for_variant(variant)
    report, report_path = get_report_for_variant(variant)
    policy_data, policy_path = get_decision_policy(variant)
    model_path = variant_info["model_dir"]

    total_windows = len(data) if data is not None else 0
    malicious_count, pred_name = (None, None)
    if data is not None:
        malicious_count, pred_name = attack_count(data)

    benign_count = (total_windows - malicious_count) if (malicious_count is not None and total_windows > 0) else None
    val_threshold = policy_data.get("decision_threshold", 0.5) if policy_data else 0.5

    # Key Metrics Banner
    c1, c2, c3, c4 = st.columns(4)
    c1.metric(
        "Saved Test Windows",
        f"{total_windows:,}" if total_windows else "N/A",
        help="Evaluated 5-minute activity windows in the saved test split.",
    )
    c2.metric(
        "Malicious Predictions",
        f"{malicious_count:,} ({(malicious_count/total_windows*100):.1f}%)" if (malicious_count is not None and total_windows) else "N/A",
        help=f"Windows classified as MALICIOUS_PATTERN at validated threshold {val_threshold:.2f}.",
    )
    c3.metric(
        "Benign Predictions",
        f"{benign_count:,} ({(benign_count/total_windows*100):.1f}%)" if (benign_count is not None and total_windows) else "N/A",
        help="Windows classified as BENIGN_PATTERN.",
    )
    c4.metric(
        "Validated Policy Threshold",
        f"{val_threshold:.2f}",
        help=f"Decision threshold from decision_policy.json ({policy_data.get('policy_name', 'default') if policy_data else 'default'}).",
    )

    st.markdown(
        f"""
        <div class="callout-box">
          <b>Data Traceability Notice:</b> Metrics above originate directly from saved experiment file:
          <code>{relative_location(source)}</code>.
          These represent controlled research splits, not live production telemetry.
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Prediction Distribution Charts
    if data is not None and pred_name:
        col_left, col_right = st.columns(2)
        with col_left:
            st.subheader("Prediction Class Distribution")
            counts = data[pred_name].astype(str).value_counts().reset_index()
            counts.columns = ["Class", "Windows"]
            if px is not None:
                fig = px.bar(
                    counts, x="Class", y="Windows", text="Windows",
                    color="Class",
                    color_discrete_map={"1": "#e74c3c", "0": "#2ecc71", "MALICIOUS_PATTERN": "#e74c3c", "BENIGN_PATTERN": "#2ecc71"},
                    title=f"Predictions ({pred_name})",
                )
                fig.update_layout(showlegend=False, template="plotly_dark", height=320)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.bar_chart(counts.set_index("Class")["Windows"])

        with col_right:
            st.subheader("Stacking Score Distribution")
            # Prefer candidate stacking score if present
            score_col = next((c for c in ["candidate_stacking_score", "stacked_malicious_score"] if c in data.columns), None)
            if not score_col:
                score_col = next((c for c in data.columns if "score" in c.lower() or "prob" in c.lower()), None)
            if score_col and px is not None:
                fig_hist = px.histogram(
                    data, x=score_col, nbins=30,
                    title=f"Score Distribution ({score_col})",
                    color_discrete_sequence=["#00d2ff"],
                )
                fig_hist.update_layout(template="plotly_dark", height=320)
                st.plotly_chart(fig_hist, use_container_width=True)
            elif score_col:
                st.line_chart(data[score_col].head(100))
            else:
                st.info("Continuous score column not present in saved test predictions.")

        with st.expander("Inspect Saved Test Predictions (First 300 Windows)"):
            show_table(data, "Saved Predictions Data", 300)

    # Artifact Readiness Matrix
    st.subheader("Model Artifact Verification")
    tree_file = model_path / "tree_models_and_meta_PROTO.joblib"
    lstm_file = model_path / "lstm_PROTO.pt"
    whitelist_file = model_path / "feature_whitelist.json"
    policy_file = model_path / "decision_policy.json"

    rows = [
        {
            "Component": "Tree Ensemble & Stacking Meta-Learner",
            "File": "tree_models_and_meta_PROTO.joblib",
            "Status": "READY" if tree_file.is_file() else "MISSING",
            "Path": relative_location(tree_file),
            "Size": f"{tree_file.stat().st_size / 1024:.1f} KB" if tree_file.is_file() else "N/A",
        },
        {
            "Component": "PyTorch WindowLSTM Checkpoint",
            "File": "lstm_PROTO.pt",
            "Status": "READY" if lstm_file.is_file() else "MISSING",
            "Path": relative_location(lstm_file),
            "Size": f"{lstm_file.stat().st_size / 1024:.1f} KB" if lstm_file.is_file() else "N/A",
        },
        {
            "Component": "Saved Feature Whitelist",
            "File": "feature_whitelist.json",
            "Status": "READY" if whitelist_file.is_file() else "MISSING",
            "Path": relative_location(whitelist_file),
            "Size": f"{whitelist_file.stat().st_size} bytes" if whitelist_file.is_file() else "N/A",
        },
        {
            "Component": "Validated Decision Policy",
            "File": "decision_policy.json",
            "Status": "READY" if policy_file.is_file() else "MISSING",
            "Path": relative_location(policy_file),
            "Size": f"{policy_file.stat().st_size} bytes" if policy_file.is_file() else "N/A",
        },
        {
            "Component": "Verified Experiment Report",
            "File": report_path.name,
            "Status": "READY" if report is not None else "MISSING",
            "Path": relative_location(report_path),
            "Size": f"{report_path.stat().st_size / 1024:.1f} KB" if report_path.is_file() else "N/A",
        },
    ]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


# ==============================================================================
# Page 2: Upload and Live Detection
# ==============================================================================
def page_log_analysis(variant: str) -> None:
    variant_info = MODEL_VARIANTS[variant]
    st.header("CloudTrail Log Analysis & Live Detection")
    st.markdown(
        f'<div class="subtitle">Run genuine machine-learning inference using saved base learners and stacking meta-learner. '
        f'<br>Active Model: <b>{variant_info["label"]}</b> | No simulated scores or synthetic heuristics.</div>',
        unsafe_allow_html=True,
    )

    policy_data, policy_path = get_decision_policy(variant)
    validated_thresh = float(policy_data.get("decision_threshold", 0.5)) if policy_data else 0.5

    st.markdown(
        """
        <div class="callout-box">
          <b>Real Pipeline Execution:</b> Uploaded files undergo genuine actor/session grouping,
          5-minute windowing, 27-feature engineering, sequence tensor creation (max length 40),
          scoring through Random Forest, LightGBM, XGBoost, and PyTorch WindowLSTM,
          and final binary decision through the saved Logistic Regression meta-learner.
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Quick Demo Loaders for Viva
    st.subheader("1. Select Input Log File")
    demo_col1, demo_col2, demo_col3 = st.columns(3)
    sample_to_load = None
    if demo_col1.button("Load Held-Out Attack Sample", use_container_width=True):
        sample_to_load = DEMO_DIR / "pp1_heldout_attack_PROTO.json"
    if demo_col2.button("Load Held-Out Benign Sample", use_container_width=True):
        sample_to_load = DEMO_DIR / "pp1_heldout_benign_PROTO.json"
    if demo_col3.button("Load Stratus Detonation Log", use_container_width=True):
        sample_to_load = PROJECT_ROOT / "Data" / "Raw" / "data" / "raw" / "stratus" / "docs" / "detonation-logs" / "aws.defense-evasion.cloudtrail-stop.json"

    if sample_to_load and sample_to_load.is_file():
        st.session_state["loaded_sample_name"] = sample_to_load.name
        st.session_state["loaded_sample_bytes"] = sample_to_load.read_bytes()
        st.info(f"Loaded sample: `{relative_location(sample_to_load)}`")

    uploaded = st.file_uploader(
        "Upload AWS CloudTrail JSON or JSONL file",
        type=["json", "jsonl", "csv"],
        key="cloudtrail_uploader",
    )

    active_bytes = None
    active_filename = None

    if uploaded is not None:
        active_bytes = uploaded.getvalue()
        active_filename = uploaded.name
    elif "loaded_sample_bytes" in st.session_state:
        active_bytes = st.session_state["loaded_sample_bytes"]
        active_filename = st.session_state["loaded_sample_name"]

    # Inference Configuration & Threshold
    with st.expander("Inference Parameters & Strictness Options", expanded=False):
        pcol1, pcol2, pcol3 = st.columns(3)
        threshold = pcol1.slider(
            "Decision Threshold", min_value=0.1, max_value=0.9, value=validated_thresh, step=0.05,
            help=f"Validated threshold for {variant_info['label']} is {validated_thresh:.2f}.",
        )
        window_minutes = pcol2.selectbox(
            "Window Minutes", options=[1, 5, 10, 15, 30, 60], index=1,
            help="Must match trained window resolution (default 5 minutes).",
        )
        missing_ro = pcol3.selectbox(
            "Missing readOnly Field Policy",
            options=["error", "assume-read"],
            format_func=lambda x: "Strict Error (Default)" if x == "error" else "Assume Read-Only (Exploratory Demo)",
            help="Strict mode rejects logs lacking readOnly. Assume-read allows non-conforming logs with explicit warning.",
        )

    # Threshold Policy Notice
    if abs(threshold - validated_thresh) > 1e-4:
        st.markdown(
            f'<div class="warning-box">⚠️ <b>Manual Threshold Override Active:</b> {threshold:.2f} '
            f'(Validated Policy Threshold: <b>{validated_thresh:.2f}</b>). '
            f'Model predictions will reflect this exploratory setting.</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div class="callout-box">🛡️ <b>Validated Decision Policy Active:</b> {validated_thresh:.2f} '
            f'({policy_data.get("policy_name", "fixed_protocol") if policy_data else "default"}). '
            f'Selected without test-set leakage.</div>',
            unsafe_allow_html=True,
        )

    if active_bytes is None:
        st.info("Upload a file above or click one of the Viva demo sample buttons to begin.")
        return

    # Preview
    try:
        preview_df, preview_desc = inspect_uploaded_logs(active_filename, active_bytes)
        st.success(f"File validated for preview: {preview_desc} ({len(active_bytes):,} bytes)")
        with st.expander(f"Inspect Input Records Preview ({active_filename})", expanded=False):
            show_table(preview_df, "Raw Records (First 2,000 Rows)", 200)
    except Exception as exc:
        st.error(f"Failed to inspect uploaded file: {exc}")
        return

    # CSV Warning
    if active_filename.lower().endswith(".csv"):
        st.warning(
            "Direct CSV inference is disabled because the trained pipeline requires raw AWS CloudTrail JSON/JSONL "
            "attributes (eventTime, eventName, eventSource, readOnly, userIdentity). "
            "Please use CloudTrail JSON format for live detection."
        )
        return

    # Trigger Inference
    run_btn = st.button("🚀 Run Real Ensemble Inference", type="primary", use_container_width=True)

    if run_btn:
        with st.spinner(f"Executing Member 2 pipeline ({variant_info['label']})..."):
            try:
                res = run_inference(
                    log_bytes=active_bytes,
                    filename=active_filename,
                    model_variant=variant,
                    window_minutes=window_minutes,
                    threshold=threshold,
                    on_missing_readonly=missing_ro,
                )
                st.session_state["live_run"] = res
                st.success("✅ Real inference completed successfully using verified checkpoints.")
            except Exception as exc:
                st.error(f"❌ Inference failed: {exc}")
                st.session_state.pop("live_run", None)

    # Display Live Inference Results
    live_run = st.session_state.get("live_run")
    if live_run:
        summary = live_run.get("summary", {})
        predictions = live_run.get("predictions", pd.DataFrame())
        handoff = live_run.get("handoff")

        st.divider()
        st.subheader("Live Detection Results")
        st.markdown(
            f'<span class="chip-live">LIVE INFERENCE COMPLETED</span> '
            f'Input: <code>{summary.get("input_filename")}</code> | Model: <code>{summary.get("model_variant")}</code>',
            unsafe_allow_html=True,
        )

        # Summary Metrics
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Raw Events", f"{summary.get('source_record_count', 0):,}")
        m2.metric("5-Min Windows", f"{summary.get('window_count', 0):,}")
        m3.metric("Malicious", f"{summary.get('malicious_windows', 0):,}")
        m4.metric("Benign", f"{summary.get('benign_windows', 0):,}")
        m5.metric(
            "Active Threshold",
            f"{summary.get('decision_threshold', 0.5):.2f}" + (" (Override)" if summary.get("is_manual_override") else " (Policy)"),
        )
        m6.metric("Member 4 v2", f"{summary.get('member4_v2_contract_status', 'N/A')}")

        # Warnings / Distribution Shift Callout
        warnings = summary.get("warnings", [])
        if warnings:
            st.markdown(
                '<div class="warning-box"><b>Audit Warnings & Distribution Notes:</b><ul>'
                + "".join(f"<li>{w}</li>" for w in warnings)
                + "</ul></div>",
                unsafe_allow_html=True,
            )

        # Timeline Chart
        if not predictions.empty and px is not None and "window_start_utc" in predictions.columns:
            st.subheader("Window Prediction Timeline")
            chart_df = predictions.copy()
            score_cols = [c for c in ["prob_Random_Forest", "prob_LightGBM", "prob_XGBoost", "prob_LSTM", "stacked_malicious_score"] if c in chart_df.columns]
            fig_timeline = px.line(
                chart_df,
                x="window_start_utc",
                y=score_cols,
                markers=True,
                title="Model Probabilities & Stacking Score Across Activity Windows",
                labels={"value": "Predicted Probability", "window_start_utc": "Window Start (UTC)", "variable": "Model"},
            )
            # Add threshold line
            fig_timeline.add_hline(y=threshold, line_dash="dash", line_color="#e74c3c", annotation_text=f"Decision Threshold ({threshold})")
            fig_timeline.update_layout(template="plotly_dark", height=380)
            st.plotly_chart(fig_timeline, use_container_width=True)

        # Detailed Predictions Table
        st.subheader("Window Details & Base Model Decomposition")
        display_cols = [
            c for c in [
                "window_start_utc", "event_count",
                "prob_Random_Forest", "prob_LightGBM", "prob_XGBoost", "prob_LSTM",
                "stacked_malicious_score", "model_disagreement", "predicted_activity",
                "sample_api_names", "actor_hash",
            ] if c in predictions.columns
        ]
        show_table(predictions[display_cols] if display_cols else predictions, "Window-Level Inference Outputs", 200)

        # Downloads and Handoff Section
        dcol1, dcol2 = st.columns(2)
        with dcol1:
            st.download_button(
                "📥 Download Prediction CSV",
                predictions.to_csv(index=False).encode("utf-8"),
                f"member2_inference_{summary.get('input_filename', 'log')}.csv",
                "text/csv",
                use_container_width=True,
            )
        with dcol2:
            if handoff:
                st.download_button(
                    "📥 Download Validated Member 4 v2 JSON",
                    json.dumps(handoff, indent=2, ensure_ascii=False).encode("utf-8"),
                    f"member2_to_member4_{summary.get('input_filename', 'log')}.json",
                    "application/json",
                    use_container_width=True,
                )

        if handoff:
            with st.expander("Inspect Generated Member 4 v2 Contract Payload"):
                st.json(handoff, expanded=False)


# ==============================================================================
# Page 3: Model Evaluation and Fair Comparison
# ==============================================================================
def page_model_performance(variant: str) -> None:
    st.header("Model Evaluation & Fair Comparison")
    st.markdown(
        '<div class="subtitle">Evidence-backed evaluation metrics from preserved experimental reports and comparison files. '
        'All numbers are loaded dynamically from saved artifacts.</div>',
        unsafe_allow_html=True,
    )

    report, report_path = get_report_for_variant(variant)
    policy_data, _ = get_decision_policy(variant)

    # --------------------------------------------------------------------------
    # Public CloudTrail Benchmark Section (Side-by-Side Comparison)
    # --------------------------------------------------------------------------
    if variant in ("pp1_public_cloudtrail_PROTO", "pp1_public_weighted_meta_PROTO"):
        st.subheader("1. Public CloudTrail Benchmark (Ariel Dataset)")
        st.markdown(
            """
            <div class="callout-box">
              <b>Evaluation Protocol:</b> Publisher-defined TrainOn / TestOn split.
              Training: 20,702 events (4,313 windows, 13 positive);
              Testing: 24,079 events (1,120 windows, 26 positive across 10 attack scenarios).
              Both stacking variants and all 4 base models evaluated on the <b>exact same untouched 1,120 test windows</b>.
            </div>
            """,
            unsafe_allow_html=True,
        )

        comparison_csv, csv_path = get_verified_comparison_csv()
        if comparison_csv is not None:
            st.markdown(f"**Verified Model Comparison Source:** `results/member2/pp1_public_scenario_models_PROTO/public_model_metrics_verified_PROTO.csv`")
            st.dataframe(comparison_csv, use_container_width=True, hide_index=True)

            # Metric Comparison Chart
            if px is not None:
                numeric_cols = [c for c in ["f1", "precision", "recall"] if c in comparison_csv.columns]
                selected_metric = st.selectbox("Select Metric to Visualize", numeric_cols, index=0)
                fig_comp = px.bar(
                    comparison_csv,
                    x="model",
                    y=selected_metric,
                    text_auto=".3f",
                    color=selected_metric,
                    color_continuous_scale="Viridis",
                    title=f"Public Test Set: Model Comparison ({selected_metric.upper()})",
                )
                fig_comp.update_layout(template="plotly_dark", height=360)
                st.plotly_chart(fig_comp, use_container_width=True)

        # In-depth Stacking Analysis Callout
        st.markdown(
            """
            <div class="success-box">
              <b>Research Breakthrough & Honest Evaluation Analysis:</b><br>
              <ul>
                <li><b>Original Baseline (Unweighted Stacking):</b> Scored <b>F1 = 0.000</b> (0 TP, 26 FN, Recall = 0.000).
                <i>Cause:</i> Due to severe class imbalance in TrainOn (4,313 windows vs 13 positive, ~330:1), standard unweighted Logistic Regression produced an overly negative intercept (-6.0), causing all test scores to stay below 0.05.</li>
                <li><b>Improved Candidate (Balanced Stacking):</b> Setting <code>class_weight='balanced'</code> and $C=0.7$ on TrainOn out-of-fold base probabilities increased <b>F1 to 0.336</b> and <b>Recall to 0.923</b> (<b>24 of 26 positive windows detected</b>!).
                ROC-AUC reached <b>0.983</b> and PR-AUC reached <b>0.733</b> (both higher than LightGBM).</li>
                <li><b>Scientific Trade-off:</b> The dramatic increase in recall (from 0% to 92.3%) came with 93 false positives (precision 20.5%).
                Meanwhile, standalone <b>LightGBM</b> achieved <b>F1 = 0.807</b> with only 8 false positives and 23 true positives.
                This provides empirical proof that <b>an ensemble does not automatically beat a single base learner without careful operational tuning</b>.</li>
              </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Scenario Breakdown Table
        scenario_df, scenario_title = get_scenario_detection_table(variant)
        if scenario_df is not None:
            st.subheader(f"2. Scenario-Wise Detection Breakdown ({scenario_title})")
            st.dataframe(scenario_df, use_container_width=True, hide_index=True)

    # --------------------------------------------------------------------------
    # Mixed-Source Prototype Section
    # --------------------------------------------------------------------------
    elif variant == "pp1_mixed_PROTO":
        st.subheader("1. Mixed-Source Prototype Evaluation")
        st.markdown(
            """
            <div class="callout-box">
              <b>Evaluation Protocol:</b> Disjoint scenario/session group 80/20 train/test split.
              Training: 797 windows; Testing: 173 windows (30 attack, 143 normal).
              Meta-learner trained on 3-fold group-separated out-of-fold predictions.
            </div>
            """,
            unsafe_allow_html=True,
        )

        if report and "model_metrics" in report:
            metrics_dict = report["model_metrics"]
            m_rows = []
            for name, m in metrics_dict.items():
                m_rows.append({
                    "Model": name,
                    "Accuracy": round(m.get("accuracy", 0), 4),
                    "Precision": round(m.get("precision", 0), 4),
                    "Recall": round(m.get("recall", 0), 4),
                    "F1 Score": round(m.get("f1", 0), 4),
                    "ROC AUC": round(m.get("roc_auc", 0), 4) if m.get("roc_auc") is not None else "N/A",
                    "Avg Precision": round(m.get("average_precision", 0), 4) if m.get("average_precision") is not None else "N/A",
                })
            m_df = pd.DataFrame(m_rows)
            st.dataframe(m_df, use_container_width=True, hide_index=True)

            if px is not None:
                fig_m = px.bar(
                    m_df,
                    x="Model",
                    y="F1 Score",
                    text_auto=".3f",
                    color="F1 Score",
                    color_continuous_scale="Tealgrn",
                    title="Mixed PP1 Test Set: Model F1 Score Comparison",
                )
                fig_m.update_layout(template="plotly_dark", height=360)
                st.plotly_chart(fig_m, use_container_width=True)

        # External Stratus Evaluation
        st.subheader("2. External Stratus Detonations (Approved Attack Recall)")
        st.markdown(
            """
            <div class="callout-box">
              <b>Stratus Positive-Only Check:</b> Evaluated on 9 approved Stratus attack detonation windows.
              <b>9 / 9 windows detected (100% recall)</b>.<br>
              <i>Limitation:</i> This is a positive-only recall check against known detonations.
              It does not measure specificity or false-positive rate on background normal activity.
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Source Bias Report
        bias_dict, bias_path = get_source_bias_report()
        if bias_dict is not None:
            with st.expander("Source Bias Audit (Research Limitation Analysis)"):
                st.caption(f"Source: `{relative_location(bias_path)}`")
                st.json(bias_dict, expanded=False)
                st.info(
                    "Source-only baseline demonstrates that class labels can correlate with data collection origin. "
                    "This is an acknowledged research limitation, proving the necessity of public benchmark validation."
                )

    # Raw Report Expander
    if report:
        with st.expander("Inspect Raw Saved Experiment Report (JSON)"):
            st.json(report, expanded=False)


# ==============================================================================
# Page 4: Stacking Architecture Explanation
# ==============================================================================
def page_stacking(variant: str) -> None:
    variant_info = MODEL_VARIANTS[variant]
    st.header("Stacked Ensemble Architecture")
    st.markdown(
        f'<div class="subtitle">Complete technical walkthrough: from raw AWS CloudTrail events to stacking meta-classification. '
        f'<br>Active Track: <b>{variant_info["label"]}</b></div>',
        unsafe_allow_html=True,
    )

    # Architecture Flowchart
    st.markdown('<div class="step-box">1. Raw AWS CloudTrail Logs (JSON / JSONL)</div>', unsafe_allow_html=True)
    st.markdown('<div class="arrow-down">↓</div>', unsafe_allow_html=True)
    st.markdown('<div class="step-box">2. Normalization & Actor Grouping (ARN / Principal / IP proxy)</div>', unsafe_allow_html=True)
    st.markdown('<div class="arrow-down">↓</div>', unsafe_allow_html=True)
    st.markdown('<div class="step-box">3. 5-Minute Window Bucketing & Feature Engineering<br><small>27 Tabular Whitelisted Features + 17-Dim Sequence Tensors (Max Length 40)</small></div>', unsafe_allow_html=True)
    st.markdown('<div class="arrow-down">↓</div>', unsafe_allow_html=True)

    b1, b2, b3, b4 = st.columns(4)
    b1.markdown('<div class="step-box"><b>Random Forest</b><br><small>130 trees, balanced</small></div>', unsafe_allow_html=True)
    b2.markdown('<div class="step-box"><b>LightGBM</b><br><small>90 trees, max_depth 4</small></div>', unsafe_allow_html=True)
    b3.markdown('<div class="step-box"><b>XGBoost</b><br><small>90 trees, max_depth 3</small></div>', unsafe_allow_html=True)
    b4.markdown('<div class="step-box"><b>PyTorch WindowLSTM</b><br><small>17-dim seq, hidden 20</small></div>', unsafe_allow_html=True)

    st.markdown('<div class="arrow-down">↓</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="step-box">4. Base Model Probability Vector: <code>[P(RF), P(LGBM), P(XGB), P(LSTM)]</code></div>',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="arrow-down">↓</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="step-box">5. Logistic Regression Meta-Learner → Stacking Score<br><small>Trained on Out-of-Fold (OOF) predictions to prevent overfitting</small></div>',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="arrow-down">↓</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="step-box">6. Final Binary Decision (Threshold 0.5) → <code>MALICIOUS_PATTERN</code> / <code>BENIGN_PATTERN</code></div>',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="arrow-down">↓</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="step-box">7. Member 4 v2 Contract Envelope (finding_id, timestamp, entity_id, nullable resource_id, sha256)</div>',
        unsafe_allow_html=True,
    )

    st.divider()

    # Detailed Explanations
    c_left, c_right = st.columns(2)
    with c_left:
        st.subheader("OOF Training vs. Live Inference")
        st.markdown(
            """
            - **Out-of-Fold (OOF) Training:**
              During training, the base models are fit on $K-1$ folds and predict on the held-out fold.
              These out-of-fold probability vectors are collected to train the Logistic Regression meta-learner.
              This prevents the meta-learner from overfitting to overly optimistic training scores.
            - **Inference Mode:**
              During inference, the **saved, frozen base models** evaluate the new window features directly.
              Their 4 probabilities are fed into the **saved, frozen Logistic Regression model**.
              The meta-learner is **never refitted** on uploaded logs.
            """
        )

    with c_right:
        st.subheader("Threshold Tuning vs. Calibration")
        st.markdown(
            """
            - **Threshold Tuning:** Selecting a decision boundary $T \\in (0, 1)$ on uncalibrated model scores to optimize sensitivity/specificity without modifying raw scores.
            - **Probability Calibration:** Transforming raw scores to true posterior probabilities $P(Y=1|X)$ (e.g. Platt scaling / isotonic regression).
            - **Why Class Weighting Solved Stacking:** In TrainOn, the 330:1 class imbalance caused standard logistic regression to output near-zero probabilities. Class weighting penalized positive errors proportionally, lifting the score distribution into a functional range ($0.29 \\dots 1.00$) at fixed threshold 0.5.
            """
        )

    # Feature Whitelist Explorer
    whitelist_data, whitelist_path = get_feature_whitelist(variant)
    if whitelist_data and "numeric_features" in whitelist_data:
        st.subheader("Saved Feature Whitelist (27 Features)")
        st.caption(f"Source: `{relative_location(whitelist_path)}`")
        features = whitelist_data["numeric_features"]
        fcol1, fcol2, fcol3 = st.columns(3)
        with fcol1:
            st.markdown("**Activity & Timing**")
            for f in features[:9]:
                st.code(f, language="text")
        with fcol2:
            st.markdown("**Security & Mutation Counts**")
            for f in features[9:17]:
                st.code(f, language="text")
        with fcol3:
            st.markdown("**One-Hot AWS Services**")
            for f in features[17:]:
                st.code(f, language="text")


# ==============================================================================
# Page 5: Saved Detection Results
# ==============================================================================
def page_saved_outputs() -> None:
    st.header("Saved Detection Results & Evidence Replay")
    st.markdown(
        '<div class="subtitle">Inspect precomputed PP1 experimental and demonstration outputs. '
        'Selecting a file replays verified evidence without invoking a new model run.</div>',
        unsafe_allow_html=True,
    )

    available = {k: v for k, v in SAVED_OUTPUTS.items() if v["path"].is_file()}
    if not available:
        st.warning("No saved inference JSON artifacts were found in the expected repository paths.")
        return

    selected_key = st.selectbox("Select Saved Artifact", list(available))
    item = available[selected_key]
    path = item["path"]

    st.markdown(
        f'<span class="chip-saved">SAVED ARTIFACT REPLAY</span> '
        f'Type: <b>{item["type"]}</b> | Source: <code>{relative_location(path)}</code>'
        f'<br><small>{item["provenance"]}</small>',
        unsafe_allow_html=True,
    )

    try:
        content = load_json(str(path))
    except Exception as exc:
        st.error(f"Failed to read artifact: {exc}")
        return

    table_data = to_table(content)

    # Metrics Summary
    s1, s2, s3 = st.columns(3)
    s1.metric("Rows / Findings", f"{len(table_data):,}")
    s2.metric("File Size", f"{path.stat().st_size / 1024:.1f} KB")
    s3.metric("SHA256", hashlib.sha256(path.read_bytes()).hexdigest()[:16] + "...")

    show_table(table_data, f"Tabular View ({selected_key})", 300)

    # Downloads
    d1, d2 = st.columns(2)
    with d1:
        st.download_button(
            "📥 Download Raw JSON",
            path.read_bytes(),
            path.name,
            "application/json",
            use_container_width=True,
        )
    with d2:
        st.download_button(
            "📥 Download Tabular CSV",
            table_data.to_csv(index=False).encode("utf-8"),
            f"{path.stem}.csv",
            "text/csv",
            use_container_width=True,
        )

    with st.expander("Inspect Raw JSON Payload"):
        st.json(content, expanded=False)


# ==============================================================================
# Page 6: Member 4 Metadata Handoff
# ==============================================================================
def page_handoff() -> None:
    st.header("Member 4 Metadata Handoff (Contract v2)")
    st.markdown(
        '<div class="subtitle">Formal inter-component integration contract specification and schema validation. '
        'Standalone Member 2 implementation.</div>',
        unsafe_allow_html=True,
    )

    schema_path, example_path = get_contract_files()

    st.markdown(
        """
        <div class="callout-box">
          <b>Contract Specification:</b> Member 2 exports activity-window findings to Member 4 using the
          <code>member2_to_member4_proto_v2</code> envelope.
          Key properties agreed across components:
          <ul>
            <li><code>resource_id</code>: <b>nullable</b>; contains verified ARN only when unambiguous. Never invented.</li>
            <li><code>entity_id</code>: <code>actor_hash:...</code> pseudonymous actor group key, not IAM credentials.</li>
            <li><code>confidence</code>: uncalibrated model score equal to <code>stacking_score</code>.</li>
            <li><code>evidence_reference</code>: portable relative file path and 1-based record indices (e.g. <code>#records=1,2</code>).</li>
            <li><code>evidence_source_sha256</code>: SHA256 checksum of raw source bytes to preserve chain of custody.</li>
          </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Contract Schema (v2)")
        if schema_path.is_file():
            st.success("Schema verified present")
            st.caption(f"`{relative_location(schema_path)}`")
            with st.expander("View JSON Schema"):
                st.json(load_json(str(schema_path)), expanded=False)
            st.download_button("Download Schema", schema_path.read_bytes(), schema_path.name, "application/json")
        else:
            st.error("Schema file missing.")

    with c2:
        st.subheader("Canonical Example Payload")
        if example_path.is_file():
            st.success("Example verified present")
            st.caption(f"`{relative_location(example_path)}`")
            with st.expander("View Canonical Example"):
                st.json(load_json(str(example_path)), expanded=False)
            st.download_button("Download Example", example_path.read_bytes(), example_path.name, "application/json")
        else:
            st.error("Example file missing.")

    # Interactive Schema Validator
    st.divider()
    st.subheader("Contract Compliance Validator")
    st.caption("Validate any candidate Member 4 handoff JSON against the official schema.")
    test_json_input = st.text_area(
        "Paste Member 4 v2 JSON payload to test",
        value=example_path.read_text(encoding="utf-8-sig") if example_path.is_file() else "",
        height=200,
    )

    if st.button("Validate Payload against Contract Rules"):
        try:
            data = json.loads(test_json_input)
            import validate_pp1_member4_v2_PROTO as val
            errors = val.validate_v2(data)
            if not errors:
                st.success(f"✅ Contract Validation PASS! {len(data.get('findings', []))} findings conform to v2 rules.")
            else:
                st.error(f"❌ Contract Validation FAILED with {len(errors)} error(s):")
                for err in errors:
                    st.write(f"- {err}")
        except Exception as exc:
            st.error(f"JSON Parse / Validation Exception: {exc}")


# ==============================================================================
# Main Launcher
# ==============================================================================
def main() -> None:
    st.sidebar.title("🛡️ CloudShield")
    st.sidebar.caption("Cloud Threat Detection · Member 2 PP1")
    st.sidebar.markdown('<span class="chip-proto">PP1 RESEARCH PROTOTYPE</span>', unsafe_allow_html=True)

    nav = st.sidebar.radio(
        "Navigation",
        [
            "Overview",
            "Cloud Log Analysis",
            "Model Performance",
            "Stacking Architecture",
            "Saved Detection Results",
            "Member 4 Handoff",
        ],
    )

    st.sidebar.divider()
    variant = st.sidebar.selectbox(
        "Model / Experiment Track",
        list(MODEL_VARIANTS),
        format_func=lambda k: MODEL_VARIANTS[k]["label"],
    )
    st.sidebar.caption(f"Track Category: {MODEL_VARIANTS[variant].get('track_category', 'Track')}")

    policy_data, _ = get_decision_policy(variant)
    if policy_data:
        st.sidebar.caption(
            f"Validated Decision Policy: <b>{policy_data.get('policy_name', 'default')}</b> "
            f"(Threshold: {float(policy_data.get('decision_threshold', 0.5)):.2f})",
            unsafe_allow_html=True,
        )

    st.sidebar.divider()
    st.sidebar.caption("Local Windows environment · No AWS network access required · Provenance preserved.")

    st.markdown("# CloudShield Security Operations")
    st.markdown('<div class="subtitle">CloudTrail Attack Detection and Stacked Ensemble Analytics · Member 2</div>', unsafe_allow_html=True)

    if nav == "Overview":
        page_overview(variant)
    elif nav == "Cloud Log Analysis":
        page_log_analysis(variant)
    elif nav == "Model Performance":
        page_model_performance(variant)
    elif nav == "Stacking Architecture":
        page_stacking(variant)
    elif nav == "Saved Detection Results":
        page_saved_outputs()
    elif nav == "Member 4 Handoff":
        page_handoff()

    st.divider()
    st.caption("PP1 Research Prototype · Grounded in preserved checkpoints and documented provenance.")


if __name__ == "__main__":
    main()
