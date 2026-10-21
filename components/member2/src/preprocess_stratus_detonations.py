#!/usr/bin/env python3
"""Conservative Stratus AWS CloudTrail detonation-log ingestion and QC.

No events are assigned benign labels. Selected rows are REVIEW CANDIDATES,
not final validated training rows. Standard-library only.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# Reuse the naming convention from the earlier Splunk preprocessing kit.
BASE_COLUMNS = [
    "dataset_source", "source_file", "record_index", "scenario_id", "research_class",
    "event_version", "event_time", "event_name", "event_source", "aws_region",
    "source_ip_address", "user_agent", "event_type", "event_category", "management_event", "read_only",
    "identity_type", "identity_principal_id", "identity_arn", "identity_user_name",
    "identity_access_key_id", "identity_account_id", "session_issuer_arn",
    "session_issuer_user_name", "session_mfa_authenticated", "session_creation_date",
    "error_code", "error_message", "request_id", "event_id", "recipient_account_id",
    "resource_arns", "resource_types", "request_parameters_json", "response_elements_json",
    "additional_event_data_json", "target_user", "actor_user", "attack_success",
    "label_binary", "attack_class", "attack_technique", "label_scope", "label_confidence",
    "label_rule", "ground_truth_source", "row_hash", "is_exact_duplicate", "event_id_conflict",
    "exclude_from_training", "exclusion_reason", "global_exact_duplicate",
    "global_event_id_conflict", "global_label_conflict"
]
EXTRA_COLUMNS = [
    "label_status", "execution_phase", "outcome", "tactic_from_filename", "requires_manual_review",
    "cross_source_event_id_overlap", "label_comment"
]
COLUMNS = BASE_COLUMNS + EXTRA_COLUMNS


def canonical_json(value: Any) -> str:
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def identity_user(ident: dict) -> str:
    if ident.get("userName"):
        return str(ident["userName"])
    arn = ident.get("arn", "")
    if isinstance(arn, str) and arn:
        return arn.rsplit("/", 1)[-1]
    return ""


def as_bool_or_blank(value: Any) -> Any:
    if value is True: return 1
    if value is False: return 0
    if isinstance(value, str):
        if value.lower() == "true": return 1
        if value.lower() == "false": return 0
    return "" if value is None else value


def parse_events(path: Path) -> list[dict]:
    obj = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(obj, list):
        seq = obj
    elif isinstance(obj, dict) and isinstance(obj.get("Records"), list):
        seq = obj["Records"]
    else:
        raise ValueError(f"Expected a JSON array or a Records array: {path}")
    if not all(isinstance(x, dict) for x in seq):
        raise ValueError(f"Non-object event in {path}")
    return seq


def normalize(event: dict, path: Path, idx: int) -> dict:
    ident = event.get("userIdentity") or {}
    if not isinstance(ident, dict): ident = {}
    session = ident.get("sessionContext") or {}
    if not isinstance(session, dict): session = {}
    issuer = session.get("sessionIssuer") or {}
    if not isinstance(issuer, dict): issuer = {}
    attrs = session.get("attributes") or {}
    if not isinstance(attrs, dict): attrs = {}
    req = event.get("requestParameters") or {}
    if not isinstance(req, dict): req = {}
    resources = event.get("resources") or []
    if not isinstance(resources, list): resources = []
    resp = event.get("responseElements") or {}
    if not isinstance(resp, dict): resp = {}
    resource_arns = []
    resource_types = []
    for resource in resources:
        if isinstance(resource, dict):
            a = resource.get("ARN") or resource.get("arn")
            t = resource.get("type")
            if a: resource_arns.append(str(a))
            if t: resource_types.append(str(t))
    target_user = str(req.get("userName") or "")
    if not target_user and isinstance(resp.get("accessKey"), dict):
        target_user = str(resp["accessKey"].get("userName") or "")
    digest = hashlib.sha256(canonical_json(event).encode("utf-8")).hexdigest()
    scenario = path.stem
    error = str(event.get("errorCode") or "")
    row = {c: "" for c in COLUMNS}
    row.update({
        "dataset_source": "Stratus Red Team published detonation logs",
        "source_file": str(path), "record_index": idx,
        "scenario_id": scenario,
        "event_version": event.get("eventVersion", ""),
        "event_time": event.get("eventTime", ""),
        "event_name": event.get("eventName", ""),
        "event_source": event.get("eventSource", ""),
        "aws_region": event.get("awsRegion", ""),
        "source_ip_address": event.get("sourceIPAddress", ""),
        "user_agent": event.get("userAgent", ""),
        "event_type": event.get("eventType", ""),
        "event_category": event.get("eventCategory", ""),
        "management_event": as_bool_or_blank(event.get("managementEvent")),
        "read_only": as_bool_or_blank(event.get("readOnly")),
        "identity_type": ident.get("type", ""),
        "identity_principal_id": ident.get("principalId", ""),
        "identity_arn": ident.get("arn", ""),
        "identity_user_name": ident.get("userName", ""),
        "identity_access_key_id": ident.get("accessKeyId", ""),
        "identity_account_id": ident.get("accountId", ""),
        "session_issuer_arn": issuer.get("arn", ""),
        "session_issuer_user_name": issuer.get("userName", ""),
        "session_mfa_authenticated": as_bool_or_blank(attrs.get("mfaAuthenticated")),
        "session_creation_date": attrs.get("creationDate", ""),
        "error_code": error,
        "error_message": event.get("errorMessage", ""),
        "request_id": event.get("requestID", ""),
        "event_id": event.get("eventID", ""),
        "recipient_account_id": event.get("recipientAccountId", ""),
        "resource_arns": "|".join(resource_arns),
        "resource_types": "|".join(resource_types),
        "request_parameters_json": canonical_json(event.get("requestParameters")),
        "response_elements_json": canonical_json(event.get("responseElements")),
        "additional_event_data_json": canonical_json(event.get("additionalEventData")),
        "target_user": target_user,
        "actor_user": identity_user(ident),
        "attack_success": 0 if error else 1,  # API response only; not objective success.
        "row_hash": digest,
        "is_exact_duplicate": 0,
        "event_id_conflict": 0,
        "exclude_from_training": 1,  # Always require downstream review before training.
        "global_exact_duplicate": 0,
        "global_event_id_conflict": 0,
        "global_label_conflict": 0,
        "label_status": "unreviewed",
        "execution_phase": "unknown",  # warm-up vs detonation vs cleanup is not fully proven by filename.
        "outcome": "api_error" if error else "api_no_error_reported",
        "tactic_from_filename": scenario.split(".")[1] if "." in scenario else "",
        "requires_manual_review": 1,
        "cross_source_event_id_overlap": 0,
        "label_comment": "Detonation file includes collection context; manual phase validation required"
    })
    return row


def write_csv(path: Path, rows: list[dict], columns: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def audit_and_classify(rows: list[dict], rules: dict) -> None:
    """Mark rule candidates, but do not declare any row training-ready."""
    seen_hashes = set()
    id_hashes = defaultdict(set)
    for r in rows:
        h = r["row_hash"]
        if h in seen_hashes:
            r["is_exact_duplicate"] = 1
        else:
            seen_hashes.add(h)
        if r["event_id"]:
            id_hashes[str(r["event_id"])].add(h)

    bad_ids = {k for k, v in id_hashes.items() if len(v) > 1}
    for row in rows:
        if row["is_exact_duplicate"]:
            row["exclusion_reason"] = "exact_duplicate"
            row["label_status"] = "excluded"
            continue
        if row["event_id"] and str(row["event_id"]) in bad_ids:
            row["event_id_conflict"] = 1
            row["exclusion_reason"] = "event_id_conflict"
            row["label_status"] = "excluded"
            continue
        scenario_rule = rules.get(row["scenario_id"])
        if not scenario_rule:
            row["exclusion_reason"] = "outside_selected_research_classes_or_not_mapped"
            row["label_status"] = "not_selected"
            continue
        if row["event_name"] not in set(scenario_rule["event_names"]):
            row["exclusion_reason"] = "supporting_api_not_in_detonation_rule"
            row["label_status"] = "not_selected"
            continue
        row.update({
            "research_class": scenario_rule["research_class"],
            "label_binary": 1,
            "attack_class": scenario_rule["research_class"],
            "attack_technique": "",  # Do not infer MITRE ID from tactic name.
            "label_scope": "scenario_plus_api_operation_review_candidate",
            "label_confidence": "medium_provisional",
            "label_rule": "scenario=" + row["scenario_id"] + " AND eventName=" + str(row["event_name"]),
            "ground_truth_source": "Stratus named detonation log and API-operation match",
            "label_status": "review_candidate",
            "exclusion_reason": "pending_execution_phase_validation",
            "label_comment": "API operation matches a named Stratus scenario; not yet training-approved",
        })


def cross_source_compare(rows: list[dict], csv_path: Path) -> list[dict]:
    if not csv_path.exists():
        raise FileNotFoundError(csv_path)
    prior_by_id = defaultdict(list)
    with csv_path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "event_id" not in reader.fieldnames:
            raise ValueError("Comparison CSV is missing event_id column")
        for prior in reader:
            if prior.get("event_id"):
                prior_by_id[str(prior["event_id"])].append(prior)
    overlaps = []
    for row in rows:
        evt_id = str(row.get("event_id") or "")
        if not evt_id or evt_id not in prior_by_id:
            continue
        row["cross_source_event_id_overlap"] = 1
        row["label_status"] = "cross_source_review_required"
        row["exclusion_reason"] = "cross_source_event_id_overlap_review"
        for other in prior_by_id[evt_id]:
            overlaps.append({
                "event_id": evt_id,
                "stratus_scenario": row["scenario_id"],
                "stratus_event_name": row["event_name"],
                "stratus_hash": row["row_hash"],
                "other_scenario": other.get("scenario_id", ""),
                "other_event_name": other.get("event_name", ""),
                "other_hash": other.get("row_hash", ""),
                "comparison_note": "same event ID in different sources; raw-event hashes may be non-comparable due to anonymization"
            })
    return overlaps


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir", type=Path, required=True)
    ap.add_argument("--config", type=Path, default=Path("config/stratus_event_rules.json"))
    ap.add_argument("--output-dir", type=Path, default=Path("Data/Interim/stratus_preprocessed"))
    ap.add_argument("--compare-with", type=Path, default=None, help="Optional earlier canonical CSV to check event ID overlaps")
    args = ap.parse_args()

    ruleset = json.loads(args.config.read_text(encoding="utf-8-sig"))
    rules = ruleset["scenarios"]
    files = sorted(args.input_dir.glob("aws.*.json"))
    if not files:
        raise SystemExit(f"No AWS detonation JSON files found in {args.input_dir}")

    all_rows = []
    counts = Counter()
    file_errors = []
    for file_path in files:
        try:
            events = parse_events(file_path)
            all_rows.extend(normalize(e, file_path, i) for i, e in enumerate(events, 1))
            counts[file_path.stem] += len(events)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            file_errors.append({"path": str(file_path), "error": str(exc)})
            print(f"ERROR {file_path}: {exc}")
    if file_errors:
        raise SystemExit("Stopping because at least one file failed. No partial outputs written.")

    audit_and_classify(all_rows, rules)
    overlaps = cross_source_compare(all_rows, args.compare_with) if args.compare_with else []
    candidates = [r for r in all_rows if r["label_status"] == "review_candidate"]
    excluded = [r for r in all_rows if r["label_status"] != "review_candidate"]
    write_csv(args.output_dir / "stratus_canonical_audit.csv", all_rows, COLUMNS)
    write_csv(args.output_dir / "stratus_review_candidates.csv", candidates, COLUMNS)
    write_csv(args.output_dir / "stratus_not_selected.csv", excluded, COLUMNS)
    write_csv(args.output_dir / "cross_source_event_id_overlaps.csv", overlaps,
              ["event_id", "stratus_scenario", "stratus_event_name", "stratus_hash", "other_scenario", "other_event_name", "other_hash", "comparison_note"])

    summary_rows = []
    for sid in sorted(counts):
        scoped = [r for r in all_rows if r["scenario_id"] == sid]
        summary_rows.append({
            "scenario_id": sid,
            "raw_events": len(scoped),
            "research_class": rules.get(sid, {}).get("research_class", "Not mapped"),
            "review_candidates": sum(r["label_status"] == "review_candidate" for r in scoped),
            "not_selected_or_overlap": sum(r["label_status"] != "review_candidate" for r in scoped),
            "api_errors": sum(bool(r["error_code"]) for r in scoped),
            "event_names": " | ".join(f"{k}:{v}" for k, v in Counter(r["event_name"] for r in scoped).most_common()),
        })
    write_csv(args.output_dir / "stratus_scenario_summary.csv", summary_rows,
              ["scenario_id", "raw_events", "research_class", "review_candidates", "not_selected_or_overlap", "api_errors", "event_names"])

    cls = Counter(r["attack_class"] for r in candidates)
    report = {
        "files_parsed": len(files),
        "total_raw_events": len(all_rows),
        "review_candidates_not_training_approved": len(candidates),
        "not_selected_or_overlapping": len(excluded),
        "candidate_counts_by_research_class": dict(cls),
        "candidate_api_error_count": sum(bool(r["error_code"]) for r in candidates),
        "exact_duplicates_in_raw": sum(bool(r["is_exact_duplicate"]) for r in all_rows),
        "local_event_id_conflict_rows": sum(bool(r["event_id_conflict"]) for r in all_rows),
        "cross_source_overlap_rows": sum(bool(r["cross_source_event_id_overlap"]) for r in all_rows),
        "file_errors": file_errors,
        "non_mapped_tactics": ["credential-access", "initial-access", "execution", "lateral-movement", "impact", "exfiltration"],
        "important_limitation": "The collected files can include warmup/cleanup despite being named detonation logs. API selection is only a provisional proxy for detonation phase. No benign rows are assigned; no row is training-approved.",
        "next_step": "Manually review candidate operations and phase evidence; resolve overlaps; consolidate with a separately validated benign source."
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "stratus_qc_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("Stratus review preprocessing finished")
    print(f"Files parsed: {len(files)}")
    print(f"Raw events: {len(all_rows)}")
    print(f"Rule-based review candidates: {len(candidates)}")
    for cls_name, total in sorted(cls.items()):
        print(f"  {cls_name}: {total}")
    print(f"Candidate events with API errors: {report['candidate_api_error_count']}")
    print(f"Other/unselected events: {len(excluded)}")
    print(f"Cross-source event ID overlap rows: {report['cross_source_overlap_rows']}")
    print(f"Output: {args.output_dir}")
    print("NOTE: REVIEW CANDIDATES ONLY. Do not merge directly with training data.")


if __name__ == "__main__":
    main()
