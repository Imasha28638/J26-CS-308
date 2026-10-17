#!/usr/bin/env python3
"""Audit and canonically normalize an unlabeled nine-column AWS CloudTrail CSV.

No benign/attack labels are inferred. Importing outputs into supervised training
without independent ground truth is not supported.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REQUIRED = ["eventtime", "eventsource", "eventname", "awsregion", "readonly",
            "managementevent", "sourceipaddress", "errorcode", "useragent"]

# Matches the field names used in the existing Splunk batch canonical dataset.
CANONICAL = [
    "dataset_source", "source_file", "record_index", "scenario_id", "research_class",
    "event_version", "event_time", "event_name", "event_source", "aws_region",
    "source_ip_address", "user_agent", "event_type", "event_category",
    "management_event", "read_only", "identity_type", "identity_principal_id",
    "identity_arn", "identity_user_name", "identity_access_key_id", "identity_account_id",
    "session_issuer_arn", "session_issuer_user_name", "session_mfa_authenticated",
    "session_creation_date", "error_code", "error_message", "request_id", "event_id",
    "recipient_account_id", "resource_arns", "resource_types", "request_parameters_json",
    "response_elements_json", "additional_event_data_json", "target_user", "actor_user",
    "attack_success", "label_binary", "attack_class", "attack_technique", "label_scope",
    "label_confidence", "label_rule", "ground_truth_source", "row_hash",
    "is_exact_duplicate", "event_id_conflict", "exclude_from_training", "exclusion_reason",
    "global_exact_duplicate", "global_event_id_conflict", "global_label_conflict",
]
EXTRA = ["ground_truth_status", "review_bucket", "actor_grouping_method",
         "background_candidate_unverified", "time_parse_valid"]
FIELDS = CANONICAL + EXTRA


def iso(s: str):
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return None
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def dt_arg(value: str) -> datetime:
    dt = iso(value)
    if dt is None:
        raise argparse.ArgumentTypeError("Expected an ISO8601 datetime with timezone (e.g., 2026-01-26T03:00:00Z)")
    return dt


def boolean(value):
    v = str(value).strip().lower()
    if v == "true":
        return 1
    if v == "false":
        return 0
    return ""


def write_csv(path, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--operator-ip", default="203.0.113.42", help="Anonymized operator address identified in source README")
    ap.add_argument("--quarantine-start", type=dt_arg, default=iso("2026-01-26T03:00:00Z"))
    ap.add_argument("--quarantine-end", type=dt_arg, default=iso("2026-01-26T04:00:00Z"))
    args = ap.parse_args()
    if not args.quarantine_start < args.quarantine_end:
        ap.error("--quarantine-end must be later than --quarantine-start")
    if not args.input.is_file():
        ap.error(f"Input does not exist: {args.input}")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    records = []
    time_problem = []
    quarantined = []
    background_candidates = []
    errors = Counter()
    ip_counts = Counter()
    event_counts = Counter()
    source_counts = Counter()
    equivalent_rows = Counter()
    anchors = []
    seen_anchor_names = {"AssumeRole", "StopLogging", "DeleteTrail"}
    with args.input.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        missing = sorted(set(REQUIRED).difference(reader.fieldnames or []))
        if missing:
            ap.error("Missing mandatory columns: " + ", ".join(missing))
        for idx, raw in enumerate(reader, 1):
            dt = iso(raw["eventtime"])
            in_quarantine = (dt is not None and args.quarantine_start <= dt < args.quarantine_end)
            operator = raw["sourceipaddress"] == args.operator_ip
            read_only = boolean(raw["readonly"])
            management = boolean(raw["managementevent"])
            errored = bool(str(raw["errorcode"] or "").strip())
            is_background_candidate = bool(dt and not in_quarantine and operator
                                           and read_only == 1 and management == 1 and not errored)
            # Events with identical nine-column representations may still be different
            # API calls. Track them for review, but NEVER deduplicate without eventID.
            normalized_raw = json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            h = hashlib.sha256(normalized_raw.encode("utf-8")).hexdigest()
            equivalent_rows[h] += 1

            review_bucket = ("invalid_timestamp" if dt is None else
                             "incident_hour_quarantine" if in_quarantine else
                             "background_candidate_unverified" if is_background_candidate else
                             "other_unverified")
            row = {field: "" for field in FIELDS}
            row.update({
                "dataset_source": "CloudTrail Real Sandbox",
                "source_file": str(args.input),
                "record_index": idx,
                "event_time": raw["eventtime"],
                "event_name": raw["eventname"],
                "event_source": raw["eventsource"],
                "aws_region": raw["awsregion"],
                "source_ip_address": raw["sourceipaddress"],
                "user_agent": raw["useragent"],
                "management_event": management,
                "read_only": read_only,
                "error_code": raw["errorcode"],
                "row_hash": h,
                # All entries remain excluded from supervised training because
                # the source is unlabeled. Unverified != benign.
                "exclude_from_training": 1,
                "exclusion_reason": "no_verified_ground_truth",
                "ground_truth_status": "unlabeled",
                "review_bucket": review_bucket,
                "actor_grouping_method": "source_ip_only_no_principal_available",
                "background_candidate_unverified": int(is_background_candidate),
                "time_parse_valid": int(dt is not None),
            })
            records.append(row)
            if dt is None:
                time_problem.append(row)
            if in_quarantine:
                quarantined.append(row)
                if raw["eventname"] in seen_anchor_names and errored:
                    anchors.append({"time": raw["eventtime"], "event_name":raw["eventname"],
                                    "error_code":raw["errorcode"],
                                    "source_ip_address":raw["sourceipaddress"]})
            if is_background_candidate:
                background_candidates.append(row)
            ip_counts[raw["sourceipaddress"]] += 1
            errors[raw["errorcode"] or "NoError"] += 1
            event_counts[raw["eventname"]] += 1
            source_counts[raw["eventsource"]] += 1

    write_csv(args.output_dir / "sandbox_canonical_unlabeled.csv", records)
    write_csv(args.output_dir / "incident_hour_quarantine.csv", quarantined)
    write_csv(args.output_dir / "background_candidates_unverified.csv", background_candidates)
    write_csv(args.output_dir / "invalid_timestamps.csv", time_problem)
    report = {
        "input_file": str(args.input),
        "total_events": len(records),
        "output_label_count": 0,
        "quarantine_start_utc": args.quarantine_start.isoformat(),
        "quarantine_end_utc": args.quarantine_end.isoformat(),
        "incident_hour_quarantine_rows": len(quarantined),
        "candidate_background_rows_UNVERIFIED": len(background_candidates),
        "invalid_timestamp_rows": len(time_problem),
        "identical_nine_field_fingerprints_extra_rows_NOT_DEDUPLICATED": sum(v-1 for v in equivalent_rows.values() if v > 1),
        "operator_ip": args.operator_ip,
        "operator_total_events": ip_counts[args.operator_ip],
        "top_source_ip_counts": ip_counts.most_common(15),
        "top_api_names": event_counts.most_common(20),
        "top_event_sources": source_counts.most_common(15),
        "error_code_counts": dict(errors),
        "quarantine_failed_api_anchors": anchors,
        "limitations": [
            "This CSV lacks event IDs, IAM principals, session IDs, request parameters and resource ARNs.",
            "Unverified background candidates are NOT benign ground truth.",
            "IP-based grouping is only a proxy for actors; multiple identities can share IPs.",
            "Raw same-field fingerprints are not safe to deduplicate because event IDs are absent.",
            "Anonymized source IPs are not appropriate features for cross-source generalization.",
        ],
    }
    (args.output_dir/"sandbox_qc_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("CloudTrail Real Sandbox preprocessing completed")
    print(f"Input events:                     {len(records)}")
    print(f"Incident-hour quarantined:       {len(quarantined)}")
    print(f"Background candidates (UNVERIFIED): {len(background_candidates)}")
    print(f"Invalid timestamps:              {len(time_problem)}")
    print(f"Potential anchor events:         {len(anchors)}")
    for a in anchors:
        print(f"  {a['time']} | {a['event_name']} | {a['error_code']} | {a['source_ip_address']}")
    print("Assigned benign/malicious labels: 0")
    print(f"Outputs: {args.output_dir}")


if __name__ == "__main__":
    main()
