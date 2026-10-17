#!/usr/bin/env python3
"""Validate Member 2 -> Member 4 PROTO v1 handoffs and optional inference report.

No third-party dependencies. Does not change input JSON or trained models.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "member2_to_member4_proto_v1"
ACTIVITY = {0: "BENIGN_PATTERN", 1: "MALICIOUS_PATTERN"}
REQUIRED_ROOT = ("schema_version", "status", "source", "score_type", "findings")
REQUIRED_FINDING = (
    "finding_id", "event_window_start_utc", "actor_hash", "activity",
    "predicted_binary", "stacking_score", "model_disagreement",
    "api_operations", "aws_services", "event_count",
    "evidence_record_numbers", "attack_category",
)


def is_int(v):
    return type(v) is int


def is_num(v):
    return type(v) in (int, float) and math.isfinite(v)


def parse_utc(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        dt = datetime.fromisoformat(value[:-1] + "+00:00")
        return dt.utcoffset().total_seconds() == 0
    except (ValueError, TypeError, AttributeError):
        return False


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def validate_handoff(payload):
    errors = []
    if not isinstance(payload, dict):
        return ["$: expected a JSON object"]
    for key in REQUIRED_ROOT:
        if key not in payload:
            errors.append(f"$.{key}: missing required field")
    for name, target in (
        ("schema_version", SCHEMA_VERSION),
        ("status", "PROTO_EVALUATION"),
        ("source", "member2_pp1_binary_stacking"),
        ("score_type", "uncalibrated_model_score"),
    ):
        if name in payload and payload[name] != target:
            errors.append(f"$.{name}: expected {target!r} for this version")
    fs = payload.get("findings")
    if not isinstance(fs, list):
        errors.append("$.findings: expected an array")
        return errors

    seen_findings, seen_record_numbers = set(), set()
    for i, f in enumerate(fs):
        p = f"$.findings[{i}]"
        if not isinstance(f, dict):
            errors.append(f"{p}: expected an object")
            continue
        for key in REQUIRED_FINDING:
            if key not in f:
                errors.append(f"{p}.{key}: missing required field")
        fid = f.get("finding_id")
        if not isinstance(fid, str) or not fid.strip():
            errors.append(f"{p}.finding_id: expected a nonempty string")
        elif fid in seen_findings:
            errors.append(f"{p}.finding_id: duplicate finding ID")
        else:
            seen_findings.add(fid)
        if not parse_utc(f.get("event_window_start_utc")):
            errors.append(f"{p}.event_window_start_utc: expected UTC ISO-8601 ending Z")
        actor = f.get("actor_hash")
        if not isinstance(actor, str) or not actor.strip():
            errors.append(f"{p}.actor_hash: expected a nonempty pseudonym")
        binary = f.get("predicted_binary")
        if not is_int(binary) or binary not in ACTIVITY:
            errors.append(f"{p}.predicted_binary: expected integer 0 or 1")
        elif f.get("activity") != ACTIVITY[binary]:
            errors.append(f"{p}.activity: inconsistent with predicted_binary")
        for field in ("stacking_score", "model_disagreement"):
            value = f.get(field)
            if not is_num(value) or not 0 <= value <= 1:
                errors.append(f"{p}.{field}: expected finite number between 0 and 1")
        n = f.get("event_count")
        if not is_int(n) or n < 1:
            errors.append(f"{p}.event_count: expected positive integer")
        ops = f.get("api_operations")
        if not isinstance(ops, dict) or not ops:
            errors.append(f"{p}.api_operations: expected nonempty object")
        else:
            if any(not isinstance(k, str) or not k or not is_int(v) or v < 1 for k, v in ops.items()):
                errors.append(f"{p}.api_operations: expected operation -> positive integer count")
            elif is_int(n) and sum(ops.values()) != n:
                errors.append(f"{p}.api_operations: operation counts must total event_count")
        services = f.get("aws_services")
        if not isinstance(services, list) or not services or any(not isinstance(v, str) or not v.strip() for v in services):
            errors.append(f"{p}.aws_services: expected array of nonempty service names")
        elif len(set(services)) != len(services):
            errors.append(f"{p}.aws_services: repeated service name")
        records = f.get("evidence_record_numbers")
        if not isinstance(records, list) or any(not is_int(v) or v < 1 for v in records):
            errors.append(f"{p}.evidence_record_numbers: expected positive 1-based integers")
        else:
            if is_int(n) and len(records) != n:
                errors.append(f"{p}.evidence_record_numbers: count must match event_count")
            if len(set(records)) != len(records):
                errors.append(f"{p}.evidence_record_numbers: duplicate ordinals within finding")
            for record in records:
                if record in seen_record_numbers:
                    errors.append(f"{p}.evidence_record_numbers: ordinal {record} used in another finding")
                seen_record_numbers.add(record)
        if "attack_category" in f and f["attack_category"] is not None:
            errors.append(f"{p}.attack_category: binary-only PROTO v1 requires null")
    return errors


def reconcile(handoff, report):
    """Compare handoff fields to actual inference report: independent of ML weights."""
    errors = []
    if not isinstance(report, dict) or not isinstance(report.get("windows"), list):
        return ["inference report: expected object with windows array"]
    hs = handoff.get("findings", []) if isinstance(handoff, dict) else []
    ws = report["windows"]
    if len(hs) != len(ws):
        errors.append(f"inference report: {len(ws)} windows versus {len(hs)} handoff findings")
    by_id = {}
    for w in ws:
        if isinstance(w, dict) and w.get("window_id") is not None:
            if w["window_id"] in by_id:
                errors.append("inference report: duplicate window_id")
            by_id[w["window_id"]] = w
    for i, f in enumerate(hs):
        if not isinstance(f, dict):
            continue
        fid = f.get("finding_id")
        w = by_id.get(fid)
        if w is None:
            errors.append(f"finding {i}: no corresponding inference window")
            continue
        mapping = {
            "event_window_start_utc": "window_start_utc",
            "actor_hash": "actor_hash",
            "predicted_binary": "predicted_binary",
            "activity": "predicted_activity",
            "api_operations": "api_operations",
            "aws_services": "aws_services",
            "event_count": "event_count",
            "evidence_record_numbers": "source_record_numbers",
        }
        for handoff_field, report_field in mapping.items():
            a, b = f.get(handoff_field), w.get(report_field)
            if handoff_field in ("aws_services", "evidence_record_numbers"):
                if isinstance(a, list) and isinstance(b, list):
                    if sorted(a) != sorted(b):
                        errors.append(f"finding {i}: {handoff_field} disagrees with inference report")
                else:
                    errors.append(f"finding {i}: {handoff_field} absent/malformed in inference report")
            elif a != b:
                errors.append(f"finding {i}: {handoff_field} disagrees with inference report")
        for key in ("stacking_score", "model_disagreement"):
            if not is_num(f.get(key)) or not is_num(w.get(key)) or abs(f[key]-w[key]) > 1e-6:
                errors.append(f"finding {i}: {key} disagrees with inference report")
    count = report.get("source_record_count")
    if is_int(count) and count > 0:
        ordinals = [n for f in hs if isinstance(f, dict) for n in f.get("evidence_record_numbers", []) if is_int(n)]
        if any(n > count for n in ordinals):
            errors.append("inference report: evidence record ordinal exceeds source_record_count")
        if len(ordinals) != count:
            errors.append("inference report: source event count does not equal all referenced record ordinals")
    threshold = report.get("decision_threshold")
    if is_num(threshold) and 0 < threshold < 1:
        for i, f in enumerate(hs):
            if isinstance(f, dict) and is_num(f.get("stacking_score")) and is_int(f.get("predicted_binary")):
                if int(f["stacking_score"] >= threshold) != f["predicted_binary"] and abs(f["stacking_score"] - threshold) > 1e-6:
                    errors.append(f"finding {i}: classification inconsistent with recorded threshold")
    return errors


def run(handoff_path, inference_report_path=None, output=None):
    payload = load_json(handoff_path)
    errors = validate_handoff(payload)
    if inference_report_path:
        report = load_json(inference_report_path)
        errors += reconcile(payload, report)
    findings = payload.get("findings", []) if isinstance(payload, dict) else []
    breakdown = Counter(f.get("activity", "UNKNOWN") for f in findings if isinstance(f, dict))
    result = {
        "contract": SCHEMA_VERSION,
        "validation": "PASS" if not errors else "FAIL",
        "finding_count": len(findings) if isinstance(findings, list) else 0,
        "malicious_pattern_count": breakdown["MALICIOUS_PATTERN"],
        "benign_pattern_count": breakdown["BENIGN_PATTERN"],
        "crosschecked_inference_report": bool(inference_report_path),
        "errors": errors,
    }
    if output:
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("PP1 Member 2 to Member 4 handoff validation")
    print(f"  Contract: {SCHEMA_VERSION}")
    print(f"  Findings: {result['finding_count']} | Malicious={result['malicious_pattern_count']} | Benign={result['benign_pattern_count']}")
    print(f"  Inference reconciliation: {'RUN' if inference_report_path else 'NOT REQUESTED'}")
    print(f"  Validation: {result['validation']}")
    if output:
        print(f"  Report: {output}")
    for error in errors:
        print("  ISSUE:", error)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--inference-report", type=Path, help="Optional full inference report for reconciliation")
    parser.add_argument("--output", type=Path, help="Optional JSON validation report")
    args = parser.parse_args()
    try:
        result = run(args.handoff, args.inference_report, args.output)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        parser.exit(2, f"ERROR: Unable to validate JSON files: {exc}\n")
    if result["errors"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
