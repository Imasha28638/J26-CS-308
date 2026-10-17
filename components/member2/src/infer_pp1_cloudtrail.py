#!/usr/bin/env python3
"""PP1 CloudTrail binary inference from Records JSON, a JSON list, or JSONL.

Uses the training code's featureize_group and pad_sequences unchanged.
Scores are uncalibrated outputs; provenance is read from the selected model experiment report.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import sys

import joblib
import numpy as np
import torch

# This file must be extracted alongside the user's ORIGINAL training script.
try:
    from train_pp1_binary_stack import (
        FEATURES, SEQ_DIM, MAX_SEQ, WindowLSTM, featureize_group,
        pad_sequences, lstm_predict,
    )
except ImportError as exc:
    raise SystemExit(
        "Could not load src/train_pp1_binary_stack.py and its dependencies. "
        "Keep the original script in src/ and install requirements_pp1.txt. "
        f"Underlying import error: {exc}"
    ) from exc

MODEL_NAMES = ("Random Forest", "LightGBM", "XGBoost", "LSTM")
MODEL_FILENAME = "tree_models_and_meta_PROTO.joblib"
LSTM_FILENAME = "lstm_PROTO.pt"


def utc_dt(raw: object) -> datetime:
    try:
        text = str(raw)
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if value.tzinfo is None:
            raise ValueError("timezone is missing")
        return value.astimezone(timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid timezone-aware eventTime: {raw!r}") from exc


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_cloudtrail(path: Path) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(f"CloudTrail input was not found: {path}")
    if path.stat().st_size > 40 * 1024 * 1024:
        raise ValueError("Input exceeds 40 MiB size limit. Select a smaller file.")
    content = path.read_text(encoding="utf-8-sig")
    if not content.strip():
        raise ValueError("Input file is empty")
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        payload = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at line {line_no}: {exc}") from exc
    if isinstance(payload, dict):
        if isinstance(payload.get("Records"), list):
            events = payload["Records"]
        elif "eventTime" in payload and "eventName" in payload:
            events = [payload]
        else:
            raise ValueError("Expected {'Records': [...]}, an event object, a JSON array, or JSONL")
    elif isinstance(payload, list):
        events = payload
    else:
        raise ValueError("CloudTrail input must be a JSON object, array, or JSONL")
    if not events:
        raise ValueError("No CloudTrail events were found")
    if len(events) > 100_000:
        raise ValueError("Maximum supported input: 100,000 events")
    if not all(isinstance(e, dict) for e in events):
        raise ValueError("Some CloudTrail records are not JSON objects")
    return events


def normalize(events: list[dict], on_missing_readonly="error") -> tuple[list[dict], list[str]]:
    """Normalize to the EXACT column schema consumed by training featureize_group.

    Actor/session grouping is approximate because CloudTrail does not generally
    guarantee that an ARN is one activity session; never describe this as a
    validated login-session reconstruction.
    """
    normalized = []
    warnings = []
    missing_identity = 0
    generated_event_ids = 0
    assumed_readonly = 0
    for i, event in enumerate(events, start=1):
        for required in ("eventTime", "eventName", "eventSource"):
            if not isinstance(event.get(required), str) or not event[required].strip():
                raise ValueError(f"Record {i}: missing or invalid required field {required}")
        stamp = iso(utc_dt(event["eventTime"]))
        ro = event.get("readOnly")
        if isinstance(ro, bool):
            read_only = str(ro).lower()
        elif isinstance(ro, str) and ro.lower() in ("true", "false"):
            read_only = ro.lower()
        elif on_missing_readonly == "assume-read":
            read_only = "true"
            assumed_readonly += 1
        else:
            raise ValueError(
                f"Record {i} ({event['eventName']}): readOnly missing or invalid. "
                "The saved models treat unknown readOnly as a write. "
                "Use --on-missing-readonly assume-read only when explicitly accepting this assumption."
            )
        identity = event.get("userIdentity") or {}
        if not isinstance(identity, dict):
            identity = {}
        actor = identity.get("arn") or identity.get("principalId")
        if actor:
            actor_type = "identity_arn_or_principal"
            actor_value = str(actor)
        elif event.get("sourceIPAddress"):
            actor_type = "source_ip_proxy"
            actor_value = str(event["sourceIPAddress"])
            missing_identity += 1
        else:
            actor_type = "unknown_actor_single_record"
            actor_value = f"record_{i:08d}"
            missing_identity += 1
        # Hash identifiers for output and group key. Never include as features.
        actor_key = hashlib.sha256((actor_type + "\x1f" + actor_value).encode()).hexdigest()[:20]
        raw_id = event.get("eventID")
        if raw_id is None or str(raw_id).strip() == "":
            raw_id = f"missing-{i:08d}"
            generated_event_ids += 1
        code = event.get("errorCode")
        if code is not None and not isinstance(code, str):
            raise ValueError(f"Record {i}: errorCode must be a string or null")
        normalized.append({
            "event_id": str(raw_id), "event_time": stamp,
            "event_name": event["eventName"].strip(),
            "event_source": event["eventSource"].strip(),
            "aws_region": str(event.get("awsRegion") or ""),
            "read_only": read_only, "error_code": code or "",
            "_actor_key": actor_key, "_actor_type": actor_type,
            "_source_record_number": i,
        })
    if missing_identity:
        warnings.append(f"{missing_identity} event(s) lack a principal/ARN. IP or single-record grouping is only a proxy.")
    if generated_event_ids:
        warnings.append(f"{generated_event_ids} event(s) lack eventID; temporary ordering IDs were assigned.")
    if assumed_readonly:
        warnings.append(f"{assumed_readonly} event(s) lack readOnly; treated as read-only by explicit option. Feature values may differ from the original events.")
    if len({(r["_actor_key"], r["event_id"]) for r in normalized}) < len(normalized):
        warnings.append("Repeated actor/eventID combination detected. Check source duplication; events retained.")
    return normalized, warnings


def build_windows(records: list[dict], minutes=5):
    if minutes < 1 or 60 % minutes:
        raise ValueError("Window minutes must divide 60, e.g. 1, 5, 10, 15, 30, or 60")
    grouped = defaultdict(list)
    for r in records:
        dt = utc_dt(r["event_time"])
        bucket = dt.replace(minute=dt.minute // minutes * minutes, second=0, microsecond=0)
        grouped[(r["_actor_key"], bucket)].append(r)
    windows, x_rows, sequences = [], [], []
    for (actor_key, start), group in sorted(grouped.items(), key=lambda p: (p[0][1],p[0][0])):
        group = sorted(group, key=lambda r: (r["event_time"], r["event_id"]))
        features, seq = featureize_group(group, minutes)
        x_rows.append(features)
        sequences.append(seq)
        src_type = Counter(x["_actor_type"] for x in group).most_common(1)[0][0]
        # These are audit metadata only, excluded from inference features.
        windows.append({
            "window_id": hashlib.sha256((actor_key + "|" + iso(start)).encode()).hexdigest()[:24],
            "window_start_utc": iso(start),
            "actor_hash": actor_key,
            "actor_grouping_method": src_type,
            "event_count": len(group),
            "first_event_time": group[0]["event_time"],
            "last_event_time": group[-1]["event_time"],
            "api_operations": dict(Counter(x["event_name"] for x in group)),
            "aws_services": sorted({x["event_source"] for x in group}),
            "sample_api_names": [x["event_name"] for x in group[:8]],
            "_event_record_numbers": [x["_source_record_number"] for x in group],
            "_raw_event_ids": [x["event_id"] for x in group],
        })
    matrix = np.asarray([[values[f] for f in FEATURES] for values in x_rows], dtype=float)
    padded, lengths = pad_sequences(sequences)
    if matrix.shape != (len(windows),len(FEATURES)):
        raise ValueError("Feature matrix unexpectedly changed")
    if padded.shape[1:] != (MAX_SEQ,SEQ_DIM):
        raise ValueError("LSTM sequence dimensions unexpectedly changed")
    return windows, matrix, padded, lengths


def load_models(folder: Path):
    tree_path = folder / MODEL_FILENAME
    lstm_path = folder / LSTM_FILENAME
    if not tree_path.is_file():
        raise FileNotFoundError(f"Missing saved model: {tree_path}")
    if not lstm_path.is_file():
        raise FileNotFoundError(f"Missing saved model: {lstm_path}")
    # joblib/pickle is unsafe from unknown sources. Load only own training artifacts.
    tree_data = joblib.load(tree_path)
    if set(tree_data.get("models", {})) != set(MODEL_NAMES[:3]):
        raise ValueError("Model keys in joblib file do not match training script")
    if tree_data.get("features") != FEATURES:
        raise ValueError("Saved tree-model feature order differs from current training script")
    checkpoint = torch.load(lstm_path, map_location="cpu", weights_only=True)
    if int(checkpoint.get("sequence_dim", -1)) != SEQ_DIM or int(checkpoint.get("max_seq", -1)) != MAX_SEQ:
        raise ValueError("Saved LSTM dimensions differ from the current training script")
    model = WindowLSTM()
    model.load_state_dict(checkpoint["state_dict"],strict=True)
    model.eval()
    return tree_data["models"], tree_data["meta"], model


def training_provenance(models_dir: Path) -> dict:
    """Read provenance from local model outputs; do not infer it from a filename."""
    mixed_report = models_dir / "mixed_experiment_report_PROTO.json"
    if mixed_report.is_file():
        metadata = json.loads(mixed_report.read_text(encoding="utf-8-sig"))
        return {
            "training_sources": [
                metadata.get("training_attacks", "Unspecified attack records"),
                metadata.get("training_normal", "Unspecified background records"),
                metadata.get("training_additional_attack", "Unspecified additional attack records"),
            ],
            "evaluation_scope": metadata.get("interpretation", "Mixed-source research evaluation"),
            "external_attack_recall": {
                "approved_attack_windows": metadata.get("external_stratus_approved_positive_windows"),
                "detected_attack_windows": metadata.get("external_stratus_detected_positive_windows"),
            },
            "model_status": "PROTO_MIXED_SOURCE_TRAINING",
        }
    public_report = models_dir / "public_experiment_report_PROTO.json"
    if public_report.is_file():
        metadata = json.loads(
            public_report.read_text(encoding="utf-8-sig")
        )
        return {
            "training_sources": [
                "Publisher-labeled AWS CloudTrail TrainOn collection",
                f"Dataset source: {metadata.get('source_url', 'Not recorded')}",
            ],
            "evaluation_scope": (
                "Publisher-defined TrainOn/TestOn evaluation; "
                "actor overlap and other limitations are documented "
                "in the public experiment report"
            ),
            "external_attack_recall": None,
            "model_status": "PROTO_PUBLIC_CLOUDTRAIL_TRAINING",
        }

    experiment = models_dir / "experiment_report.json"
    if experiment.is_file():
        metadata = json.loads(experiment.read_text(encoding="utf-8-sig"))
        return {
            "training_sources": ["Generated CloudTrail controlled activity"],
            "evaluation_scope": metadata.get("dataset_type", "Controlled research experiment"),
            "external_attack_recall": None,
            "model_status": "PROTO_CONTROLLED_TRAINING",
        }
    return {
        "training_sources": ["Unknown: experiment report not found"],
        "evaluation_scope": "Provenance metadata unavailable",
        "external_attack_recall": None,
        "model_status": "PROTO_PROVENANCE_UNAVAILABLE",
    }


def run(input_path, models_dir, output_path, minutes=5, threshold=0.5,
        on_missing_readonly="error", include_event_ids=False):
    if not 0 < threshold < 1:
        raise ValueError("Threshold must be greater than 0 and less than 1")
    raw = parse_cloudtrail(input_path)
    clean, warnings = normalize(raw, on_missing_readonly)
    known_services = {
        "iam.amazonaws.com", "sts.amazonaws.com", "ec2.amazonaws.com",
        "cloudtrail.amazonaws.com", "s3.amazonaws.com", "signin.amazonaws.com",
        "secretsmanager.amazonaws.com", "kms.amazonaws.com", "ssm.amazonaws.com",
        "lambda.amazonaws.com",
    }
    unfamiliar = sum(r["event_source"] not in known_services for r in clean)
    if unfamiliar:
        warnings.append(
            f"{unfamiliar} event(s) have AWS services outside the LSTM's trained one-hot service list."
        )
    missing_regions = sum(not r["aws_region"] for r in clean)
    if missing_regions:
        warnings.append(f"{missing_regions} event(s) lack awsRegion; distribution shift may affect prediction.")
    training_report_path = models_dir / "experiment_report.json"
    if training_report_path.is_file():
        try:
            training_report = json.loads(training_report_path.read_text(encoding="utf-8-sig"))
            trained_window_minutes = int(training_report.get("window_minutes", 5))
            if trained_window_minutes != minutes:
                warnings.append(
                    f"Requested {minutes}-minute windows, but saved models were trained on "
                    f"{trained_window_minutes}-minute windows; scores are not comparable."
                )
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            warnings.append("Could not validate training window size against experiment_report.json.")
    provenance = training_provenance(models_dir)
    windows, x, padded, lengths = build_windows(clean, minutes)
    model_dict, meta, lstm = load_models(models_dir)
    base = np.column_stack([
        model_dict[name].predict_proba(x)[:,1] for name in MODEL_NAMES[:3]
    ] + [lstm_predict(lstm,padded,lengths)])
    if base.shape != (len(windows),4):
        raise ValueError("Unexpected base model score matrix size")
    stacked = meta.predict_proba(base)[:,1]
    for i,(w, scores, meta_score) in enumerate(zip(windows,base,stacked)):
        w["model_scores"] = {name:round(float(score),6) for name,score in zip(MODEL_NAMES,scores)}
        w["stacking_score"] = round(float(meta_score),6)
        w["predicted_binary"] = int(meta_score >= threshold)
        w["predicted_activity"] = "MALICIOUS_PATTERN" if meta_score >= threshold else "BENIGN_PATTERN"
        w["model_disagreement"] = round(float(np.std(scores)),6)
        w["research_attack_category"] = None  # Binary-only model
        w["sequence_length_used"] = int(lengths[i])
        w["sequence_truncated"] = bool(w["event_count"] > MAX_SEQ)
        if include_event_ids:
            w["event_ids"] = w.pop("_raw_event_ids")
            w["source_record_numbers"] = w.pop("_event_record_numbers")
        else:
            del w["_raw_event_ids"]
            # Record ordinals are safe and let the user trace within local JSON.
            w["source_record_numbers"] = w.pop("_event_record_numbers")
    if any(w["event_count"] == 1 for w in windows):
        warnings.append("Single-event window detected; temporal sequence context is limited.")
    if len(windows) > 0 and all(w["predicted_binary"] == 0 for w in windows):
        warnings.append("All window scores are below the configured detection threshold.")
    result = {
        "schema_version":"pp1_inference_proto_v1",
        "model_status":provenance["model_status"],
        "validation_status":"EVALUATION_IN_PROGRESS",
        "training_provenance":provenance,
        "input_filename":input_path.name,
        "source_record_count":len(clean), "window_count":len(windows),
        "window_minutes":minutes,"decision_threshold":threshold,
        "classification_task":"binary_benign_vs_malicious",
        "attack_category_prediction_supported":False,
        "score_interpretation":"Uncalibrated model scores; external CloudTrail evaluation is in progress.",
        "actor_grouping_note":"Identity/IP grouping approximates activity sessions; it is not a verified login-session reconstruction.",
        "warnings":warnings,
        "windows":windows,
    }
    output_path.parent.mkdir(parents=True,exist_ok=True)
    output_path.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
    # File for Member 4. Contains only compact metadata, opaque actor hash and
    # prototype score; do not describe as validated security finding.
    handoff_path = output_path.with_name(output_path.stem + "_member4_PROTO.json")
    handoff = {
        "schema_version":"member2_to_member4_proto_v1",
        "status":"PROTO_EVALUATION",
        "source":"member2_pp1_binary_stacking",
        "score_type":"uncalibrated_model_score",
        "findings":[{
            "finding_id":w["window_id"],
            "event_window_start_utc":w["window_start_utc"],
            "actor_hash":w["actor_hash"],
            "activity":w["predicted_activity"],
            "predicted_binary":w["predicted_binary"],
            "stacking_score":w["stacking_score"],
            "model_disagreement":w["model_disagreement"],
            "api_operations":w["api_operations"],
            "aws_services":w["aws_services"],
            "event_count":w["event_count"],
            "evidence_record_numbers":w["source_record_numbers"],
            "attack_category":None,
        } for w in windows]
    }
    handoff_path.write_text(json.dumps(handoff,indent=2,ensure_ascii=False),encoding="utf-8")
    return result, handoff_path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input",type=Path,required=True,help="AWS CloudTrail Records JSON, event list, single event, or JSONL")
    ap.add_argument("--models-dir",type=Path,default=Path("Data/Experiments/pp1_binary"))
    ap.add_argument("--output",type=Path,default=Path("Data/Experiments/pp1_inference/pp1_predictions_PROTO.json"))
    ap.add_argument("--window-minutes",type=int,default=5)
    ap.add_argument("--threshold",type=float,default=0.5)
    ap.add_argument("--on-missing-readonly",choices=("error","assume-read"),default="error")
    ap.add_argument("--include-event-ids",action="store_true",help="Include original CloudTrail IDs in JSON output")
    args = ap.parse_args()
    try:
        report, handoff = run(args.input,args.models_dir,args.output,args.window_minutes,args.threshold,args.on_missing_readonly,args.include_event_ids)
    except (ValueError,FileNotFoundError,ImportError,KeyError) as exc:
        ap.exit(2,f"ERROR: {exc}\n")
    print("PP1 CloudTrail inference completed")
    print(f"  Source events: {report['source_record_count']}")
    print(f"  Behavioral windows: {report['window_count']}")
    print(f"  Predicted malicious-pattern windows: {sum(w['predicted_binary'] for w in report['windows'])}")
    print(f"  Predicted benign-pattern windows: {sum(not w['predicted_binary'] for w in report['windows'])}")
    for w in report["windows"][:8]:
        print(f"  {w['window_start_utc']}  n={w['event_count']}  "
              f"stack={w['stacking_score']:.3f}  {w['predicted_activity']}")
    for warning in report["warnings"]:
        print("  Note:", warning)
    print("  JSON report:",args.output)
    print("  Member 4 handoff:",handoff)
    print("  Training sources:", "; ".join(report["training_provenance"]["training_sources"]))


if __name__ == "__main__":
    main()
