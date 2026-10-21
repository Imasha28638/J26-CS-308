#!/usr/bin/env python3
"""Summarize PP1 prototype experiment; add hard/soft voting post-hoc baselines.

Consumes held-out test predictions produced by train_pp1_binary_stack.py.
Does NOT retrain models or evaluate real AWS attack detection.
"""
import argparse
import csv
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, average_precision_score,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)

COLS = {
    "Random Forest": "prob_Random_Forest",
    "LightGBM": "prob_LightGBM",
    "XGBoost": "prob_XGBoost",
    "LSTM": "prob_LSTM",
    "Stacking": "stacked_malicious_score",
}


def evaluate(y, p, hard_override=None):
    label = (np.asarray(p) >= 0.5).astype(int) if hard_override is None else np.asarray(hard_override, dtype=int)
    tn, fp, fn, tp = confusion_matrix(y, label, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y, label)),
        "precision": float(precision_score(y, label, zero_division=0)),
        "recall": float(recall_score(y, label, zero_division=0)),
        "f1": float(f1_score(y, label, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else None,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else None,
        "average_precision": float(average_precision_score(y, p)) if len(set(y)) > 1 else None,
        "roc_auc": float(roc_auc_score(y, p)) if len(set(y)) > 1 else None,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def analyze(input_csv, output_dir):
    df = pd.read_csv(input_csv)
    required = {"label_binary", "session_id", "true_injected_class", *COLS.values()}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing test-prediction columns: {sorted(missing)}")
    if df.empty or df[sorted(required)].isna().any().any():
        # true_injected_class is naturally empty for negatives, so except this field.
        core = required - {"true_injected_class"}
        if df.empty or df[list(core)].isna().any().any():
            raise ValueError("Missing model probabilities or labels in test predictions")
    labels = df["label_binary"].to_numpy(dtype=int)
    if set(labels) != {0, 1}:
        raise ValueError("Both synthetic test labels 0 and 1 are required")
    probs = {k:df[c].to_numpy(dtype=float) for k,c in COLS.items()}
    for name,p in probs.items():
        if not np.isfinite(p).all() or (p < 0).any() or (p > 1).any():
            raise ValueError(f"Invalid probability values for {name}")

    base = np.column_stack([probs[n] for n in ("Random Forest","LightGBM","XGBoost","LSTM")])
    probs["Soft voting"] = base.mean(axis=1)
    vote_count = (base >= 0.5).sum(axis=1)
    # Four voters: 2-2 ties resolved as benign; positive requires >=3 positive votes.
    hard = (vote_count >= 3).astype(int)
    probs["Hard voting"] = vote_count / 4.0

    models = ["Random Forest", "LightGBM", "XGBoost", "LSTM", "Hard voting", "Soft voting", "Stacking"]
    result = {}
    for model in models:
        result[model] = evaluate(labels, probs[model], hard_override=hard if model == "Hard voting" else None)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = pd.DataFrame([{"model":m, **result[m]} for m in models])
    summary.to_csv(output_dir / "pp1_model_and_voting_comparison.csv", index=False, encoding="utf-8-sig")
    error_frame = df[[c for c in ("session_id","window_start","true_injected_class","label_binary") if c in df.columns]].copy()
    for model in models:
        pred = hard if model == "Hard voting" else (probs[model] >= .5).astype(int)
        error_frame[model.replace(" ", "_") + "_pred"] = pred
        error_frame[model.replace(" ", "_") + "_error"] = (pred != labels).astype(int)
    error_frame.to_csv(output_dir / "pp1_test_error_audit.csv", index=False, encoding="utf-8-sig")

    cat_rows = []
    for group, frame in df.loc[labels == 1].groupby("true_injected_class", dropna=False):
        idx = frame.index.to_numpy()
        # CSV is loaded in 0-based RangeIndex; all idx positions are reliable.
        for model in models:
            pred = hard[idx] if model == "Hard voting" else (probs[model][idx] >= .5).astype(int)
            cat_rows.append({
                "injected_synthetic_class":str(group), "model":model,
                "positive_windows":int(len(idx)),"detected_windows":int(pred.sum()),
                "missed_windows":int((1-pred).sum()),
                "binary_recall_within_synthetic_injection_class":round(float(pred.mean()), 6)
            })
    pd.DataFrame(cat_rows).to_csv(output_dir / "pp1_recall_by_synthetic_attack_class.csv", index=False, encoding="utf-8-sig")

    xgb_pred = (probs["XGBoost"] >= .5).astype(int)
    stack_pred = (probs["Stacking"] >= .5).astype(int)
    disagreement = df.loc[xgb_pred != stack_pred, [c for c in ("session_id","window_start","label_binary","true_injected_class","prob_XGBoost","stacked_malicious_score") if c in df.columns]].copy()
    disagreement["xgboost_prediction"] = xgb_pred[xgb_pred != stack_pred]
    disagreement["stacking_prediction"] = stack_pred[xgb_pred != stack_pred]
    disagreement.to_csv(output_dir / "pp1_xgboost_vs_stacking_disagreements.csv", index=False, encoding="utf-8-sig")

    report = {
        "evaluation_type":"CONTROLLED_SYNTHETIC_HELD_OUT_SESSION_TEST_ONLY",
        "test_windows":int(len(df)),
        "test_sessions":int(df.session_id.nunique()),
        "positive_windows":int(labels.sum()),
        "negative_windows":int((labels==0).sum()),
        "hard_vote_tie_rule":"2-2 tie -> benign; >=3 votes -> malicious",
        "hard_vote_auc_caution":"ROC-AUC and average precision for hard vote are based on 0/0.25/0.5/0.75/1.0 vote fraction, not a calibrated probability",
        "model_results":result,
        "stack_minus_xgb_f1":float(result["Stacking"]["f1"]-result["XGBoost"]["f1"]),
        "warning":"All source events and attacks were generated synthetically. These scores do not validate real AWS CloudTrail attack detection. Class-wise table measures binary detection on known injection categories, not multiclass prediction.",
    }
    (output_dir / "pp1_analysis_summary.json").write_text(json.dumps(report,indent=2), encoding="utf-8")
    print("PP1 PROTOTYPE TEST COMPARISON (NOT REAL-WORLD):")
    print("Test windows:",len(df),"| Positive:",int(labels.sum()),"| Independent test sessions:",df.session_id.nunique())
    for m in models:
        r=result[m]
        print(f" {m:17} F1={r['f1']:.3f} Precision={r['precision']:.3f} Recall={r['recall']:.3f} FP={r['fp']} FN={r['fn']}")
    if result["Stacking"]["f1"] < result["XGBoost"]["f1"]:
        print("NOTE: XGBoost outperforms stacking on F1 in this prototype test. Do not claim stacking superiority.")
    print("Outputs:",output_dir)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--predictions",type=Path, default=Path("Data/Experiments/pp1_binary/test_predictions_RESEARCH_DEMO.csv"))
    p.add_argument("--output-dir",type=Path, default=Path("Data/Experiments/pp1_binary/analysis"))
    a=p.parse_args()
    analyze(a.predictions,a.output_dir)

if __name__ == "__main__":
    main()
