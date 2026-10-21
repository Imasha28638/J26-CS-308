#!/usr/bin/env python3
"""
Preprocess Splunk Attack Data AWS CloudTrail JSON/JSONL into a canonical,
auditable, labeled CSV for ML research.

Pipeline:
Raw JSON/JSONL
 -> canonical event rows
 -> normalized row hash
 -> exact duplicate removal
 -> eventID conflict detection
 -> scenario-specific ground-truth labeling
 -> clean labeled CSV
 -> QC report

Designed initially for:
- T1562.008 / stop_delete_cloudtrail
- T1078 / aws_createaccesskey
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml
except ImportError:
    print("Missing dependency: PyYAML. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


CANONICAL_COLUMNS = [
    # provenance
    "dataset_source",
    "source_file",
    "record_index",
    "scenario_id",

    # core CloudTrail event fields
    "event_version",
    "event_time",
    "event_name",
    "event_source",
    "aws_region",
    "source_ip_address",
    "user_agent",
    "event_type",
    "event_category",
    "management_event",
    "read_only",

    # identity
    "identity_type",
    "identity_principal_id",
    "identity_arn",
    "identity_user_name",
    "identity_access_key_id",
    "identity_account_id",
    "session_issuer_arn",
    "session_issuer_user_name",
    "session_mfa_authenticated",
    "session_creation_date",

    # event result / IDs
    "error_code",
    "error_message",
    "request_id",
    "event_id",
    "recipient_account_id",

    # resources / nested payloads
    "resource_arns",
    "resource_types",
    "request_parameters_json",
    "response_elements_json",
    "additional_event_data_json",

    # extracted helper fields
    "target_user",
    "actor_user",
    "attack_success",

    # labeling
    "label_binary",
    "attack_class",
    "attack_technique",
    "label_scope",
    "label_confidence",
    "label_rule",
    "ground_truth_source",

    # quality / exclusion
    "row_hash",
    "is_exact_duplicate",
    "event_id_conflict",
    "exclude_from_training",
    "exclusion_reason",
]


def compact_json(value: Any) -> str:
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def normalized_event_json(event: Dict[str, Any]) -> str:
    """Stable full-event representation used for exact duplicate detection."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def event_hash(event: Dict[str, Any]) -> str:
    return hashlib.sha256(normalized_event_json(event).encode("utf-8")).hexdigest()


def bool_or_blank(value: Any) -> Any:
    if isinstance(value, bool):
        return int(value)
    if value is None:
        return ""
    if isinstance(value, str):
        low = value.lower().strip()
        if low == "true":
            return 1
        if low == "false":
            return 0
    return value


def parse_json_file(path: Path) -> List[Dict[str, Any]]:
    """
    Supports:
    - CloudTrail wrapper: {"Records":[...]}
    - JSON array
    - single JSON object
    - JSONL / NDJSON
    """
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []

    # Try normal JSON first.
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and isinstance(obj.get("Records"), list):
            return [x for x in obj["Records"] if isinstance(x, dict)]
        if isinstance(obj, list):
            return [x for x in obj if isinstance(x, dict)]
        if isinstance(obj, dict):
            return [obj]
    except json.JSONDecodeError:
        pass

    # Fall back to JSONL / NDJSON.
    rows: List[Dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON on line {line_no} of {path}: {exc}"
            ) from exc
        if not isinstance(obj, dict):
            raise ValueError(
                f"Expected JSON object on line {line_no} of {path}, got {type(obj).__name__}"
            )
        rows.append(obj)
    return rows


def identity_actor_user(event: Dict[str, Any]) -> str:
    """
    Returns a human-readable acting identity for audit/rule comparison.

    Preference:
    1. userIdentity.userName
    2. assumed-role session name from ARN
    3. final ARN component
    """
    ident = event.get("userIdentity") or {}
    username = ident.get("userName")
    if username:
        return str(username)

    arn = ident.get("arn")
    if isinstance(arn, str) and arn:
        # arn:aws:sts::acct:assumed-role/role/session
        if ":assumed-role/" in arn:
            parts = arn.split("/")
            if len(parts) >= 3:
                return parts[-1]
        return arn.rsplit("/", 1)[-1]

    return ""


def extract_target_user(event: Dict[str, Any]) -> str:
    req = event.get("requestParameters")
    if isinstance(req, dict):
        user = req.get("userName")
        if user:
            return str(user)

    resp = event.get("responseElements")
    if isinstance(resp, dict):
        ak = resp.get("accessKey")
        if isinstance(ak, dict) and ak.get("userName"):
            return str(ak["userName"])

    return ""


def canonicalize(
    event: Dict[str, Any],
    *,
    dataset_source: str,
    source_file: str,
    record_index: int,
    scenario_id: str,
) -> Dict[str, Any]:
    ident = event.get("userIdentity") or {}
    session_context = ident.get("sessionContext") or {}
    session_issuer = session_context.get("sessionIssuer") or {}
    session_attrs = session_context.get("attributes") or {}

    resources = event.get("resources") or []
    resource_arns: List[str] = []
    resource_types: List[str] = []
    if isinstance(resources, list):
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            arn = resource.get("ARN") or resource.get("arn")
            typ = resource.get("type")
            if arn:
                resource_arns.append(str(arn))
            if typ:
                resource_types.append(str(typ))

    actor_user = identity_actor_user(event)
    target_user = extract_target_user(event)
    error_code = event.get("errorCode")

    row = {
        "dataset_source": dataset_source,
        "source_file": source_file,
        "record_index": record_index,
        "scenario_id": scenario_id,

        "event_version": event.get("eventVersion", ""),
        "event_time": event.get("eventTime", ""),
        "event_name": event.get("eventName", ""),
        "event_source": event.get("eventSource", ""),
        "aws_region": event.get("awsRegion", ""),
        "source_ip_address": event.get("sourceIPAddress", ""),
        "user_agent": event.get("userAgent", ""),
        "event_type": event.get("eventType", ""),
        "event_category": event.get("eventCategory", ""),
        "management_event": bool_or_blank(event.get("managementEvent")),
        "read_only": bool_or_blank(event.get("readOnly")),

        "identity_type": ident.get("type", ""),
        "identity_principal_id": ident.get("principalId", ""),
        "identity_arn": ident.get("arn", ""),
        "identity_user_name": ident.get("userName", ""),
        "identity_access_key_id": ident.get("accessKeyId", ""),
        "identity_account_id": ident.get("accountId", ""),
        "session_issuer_arn": session_issuer.get("arn", ""),
        "session_issuer_user_name": session_issuer.get("userName", ""),
        "session_mfa_authenticated": bool_or_blank(session_attrs.get("mfaAuthenticated")),
        "session_creation_date": session_attrs.get("creationDate", ""),

        "error_code": error_code or "",
        "error_message": event.get("errorMessage", ""),
        "request_id": event.get("requestID", ""),
        "event_id": event.get("eventID", ""),
        "recipient_account_id": event.get("recipientAccountId", ""),

        "resource_arns": "|".join(resource_arns),
        "resource_types": "|".join(resource_types),
        "request_parameters_json": compact_json(event.get("requestParameters")),
        "response_elements_json": compact_json(event.get("responseElements")),
        "additional_event_data_json": compact_json(event.get("additionalEventData")),

        "target_user": target_user,
        "actor_user": actor_user,
        "attack_success": 0 if error_code else 1,

        "label_binary": "",
        "attack_class": "",
        "attack_technique": "",
        "label_scope": "",
        "label_confidence": "",
        "label_rule": "",
        "ground_truth_source": "",

        "row_hash": event_hash(event),
        "is_exact_duplicate": 0,
        "event_id_conflict": 0,
        "exclude_from_training": 0,
        "exclusion_reason": "",
    }

    return row


def apply_rule(row: Dict[str, Any], cfg: Dict[str, Any]) -> Tuple[bool, str]:
    rule = cfg.get("rule", {})
    rule_type = rule.get("type")

    if rule_type == "event_name_in":
        expected_source = rule.get("event_source")
        allowed_names = set(rule.get("event_names", []))
        match = (
            row["event_source"] == expected_source
            and row["event_name"] in allowed_names
        )
        desc = (
            f'event_source=="{expected_source}" AND '
            f'event_name IN {sorted(allowed_names)}'
        )
        return match, desc

    if rule_type == "cross_user_api_call":
        expected_source = rule.get("event_source")
        expected_name = rule.get("event_name")
        actor = str(row.get("actor_user") or "").strip()
        target = str(row.get("target_user") or "").strip()

        match = (
            row["event_source"] == expected_source
            and row["event_name"] == expected_name
            and bool(actor)
            and bool(target)
            and actor.lower() != target.lower()
        )
        desc = (
            f'event_source=="{expected_source}" AND '
            f'event_name=="{expected_name}" AND target_user exists AND '
            f'actor_user exists AND target_user!=actor_user'
        )
        return match, desc

    raise ValueError(f"Unsupported rule type: {rule_type}")


def mark_exact_duplicates(rows: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """
    Keep the first copy of an exact normalized JSON event.
    Later identical rows are marked and excluded from clean output.
    """
    first_seen: Dict[str, int] = {}
    exact_duplicates = 0

    for idx, row in enumerate(rows):
        h = row["row_hash"]
        if h in first_seen:
            row["is_exact_duplicate"] = 1
            row["exclude_from_training"] = 1
            row["exclusion_reason"] = append_reason(
                row["exclusion_reason"], "exact_duplicate"
            )
            exact_duplicates += 1
        else:
            first_seen[h] = idx

    return rows, exact_duplicates


def mark_event_id_conflicts(rows: List[Dict[str, Any]]) -> int:
    """
    After exact duplicate marking, identify eventIDs that map to >1 distinct full-event hash.
    All variants of that eventID are excluded from training.
    """
    id_to_hashes: Dict[str, set] = defaultdict(set)
    for row in rows:
        if row["is_exact_duplicate"]:
            continue
        event_id = str(row.get("event_id") or "").strip()
        if event_id:
            id_to_hashes[event_id].add(row["row_hash"])

    conflicting_ids = {eid for eid, hashes in id_to_hashes.items() if len(hashes) > 1}

    for row in rows:
        if row.get("event_id") in conflicting_ids:
            row["event_id_conflict"] = 1
            row["exclude_from_training"] = 1
            row["exclusion_reason"] = append_reason(
                row["exclusion_reason"], "event_id_conflict"
            )

    return len(conflicting_ids)


def append_reason(existing: str, reason: str) -> str:
    if not existing:
        return reason
    parts = existing.split("|")
    if reason not in parts:
        parts.append(reason)
    return "|".join(parts)


def apply_labels(rows: List[Dict[str, Any]], cfg: Dict[str, Any]) -> Dict[str, int]:
    labeled = 0
    unmatched = 0
    conflict_excluded = 0
    duplicate_excluded = 0

    for row in rows:
        # Exact duplicates remain in audit output only.
        if row["is_exact_duplicate"]:
            duplicate_excluded += 1
            continue

        # Conflicting event IDs are never used for training.
        if row["event_id_conflict"]:
            conflict_excluded += 1
            continue

        match, rule_desc = apply_rule(row, cfg)

        if match:
            row["label_binary"] = 1
            row["attack_class"] = cfg["attack_class"]
            row["attack_technique"] = cfg["attack_technique"]
            row["label_scope"] = cfg.get("label_scope", "event_rule")
            row["label_confidence"] = cfg.get("label_confidence", "high")
            row["label_rule"] = rule_desc
            row["ground_truth_source"] = cfg.get(
                "ground_truth_source",
                "Splunk Attack Data YAML metadata",
            )
            labeled += 1
        else:
            row["exclude_from_training"] = 1
            row["exclusion_reason"] = append_reason(
                row["exclusion_reason"], "not_matched_by_ground_truth_rule"
            )
            unmatched += 1

    return {
        "labeled_malicious": labeled,
        "unmatched_excluded": unmatched,
        "conflict_rows_excluded": conflict_excluded,
        "duplicate_rows_excluded": duplicate_excluded,
    }


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CANONICAL_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({col: row.get(col, "") for col in CANONICAL_COLUMNS})


def load_config(path: Path, scenario: str) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    scenarios = data.get("scenarios") or {}
    if scenario not in scenarios:
        available = ", ".join(sorted(scenarios))
        raise KeyError(
            f"Scenario '{scenario}' not found in {path}. Available: {available}"
        )
    cfg = scenarios[scenario]
    cfg["scenario_id"] = scenario
    return cfg


def build_qc_report(
    *,
    input_path: Path,
    scenario: str,
    raw_count: int,
    rows: List[Dict[str, Any]],
    exact_duplicates: int,
    conflicting_event_ids: int,
    label_stats: Dict[str, int],
) -> Dict[str, Any]:
    unique_after_exact_dedup = raw_count - exact_duplicates
    clean_training_rows = [
        r for r in rows
        if not r["exclude_from_training"] and r["label_binary"] != ""
    ]

    event_names = Counter(r["event_name"] for r in rows)
    event_sources = Counter(r["event_source"] for r in rows)
    exclusion_reasons = Counter()
    for r in rows:
        reason = r.get("exclusion_reason") or ""
        for part in reason.split("|"):
            if part:
                exclusion_reasons[part] += 1

    return {
        "input_file": str(input_path),
        "scenario_id": scenario,
        "raw_record_count": raw_count,
        "exact_duplicate_rows": exact_duplicates,
        "unique_rows_after_exact_dedup": unique_after_exact_dedup,
        "conflicting_event_id_count": conflicting_event_ids,
        "clean_labeled_training_rows": len(clean_training_rows),
        "label_stats": label_stats,
        "top_event_names": dict(event_names.most_common(20)),
        "top_event_sources": dict(event_sources.most_common(20)),
        "exclusion_reasons": dict(exclusion_reasons),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="CloudTrail JSON/JSONL input")
    parser.add_argument("--scenario", required=True, help="Scenario ID from config")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/splunk_scenarios.yml"),
        help="Scenario YAML configuration",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/interim/preprocessed"),
        help="Output directory",
    )
    parser.add_argument(
        "--dataset-source",
        default="Splunk Attack Data",
        help="Dataset source label",
    )

    args = parser.parse_args()

    cfg = load_config(args.config, args.scenario)
    events = parse_json_file(args.input)

    rows = [
        canonicalize(
            event,
            dataset_source=args.dataset_source,
            source_file=str(args.input),
            record_index=i,
            scenario_id=args.scenario,
        )
        for i, event in enumerate(events, start=1)
    ]

    rows, exact_duplicates = mark_exact_duplicates(rows)
    conflicting_event_ids = mark_event_id_conflicts(rows)
    label_stats = apply_labels(rows, cfg)

    out_dir = args.output_dir / args.scenario
    audit_csv = out_dir / "canonical_audit.csv"
    clean_csv = out_dir / "labeled_clean.csv"
    excluded_csv = out_dir / "excluded_rows.csv"
    qc_json = out_dir / "qc_report.json"

    write_csv(audit_csv, rows)

    clean_rows = [
        r for r in rows
        if not r["exclude_from_training"] and r["label_binary"] != ""
    ]
    write_csv(clean_csv, clean_rows)

    excluded_rows = [r for r in rows if r["exclude_from_training"]]
    write_csv(excluded_csv, excluded_rows)

    report = build_qc_report(
        input_path=args.input,
        scenario=args.scenario,
        raw_count=len(events),
        rows=rows,
        exact_duplicates=exact_duplicates,
        conflicting_event_ids=conflicting_event_ids,
        label_stats=label_stats,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    qc_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\nPreprocessing complete")
    print(f"Scenario:                  {args.scenario}")
    print(f"Raw records:               {len(events)}")
    print(f"Exact duplicate rows:      {exact_duplicates}")
    print(f"Conflicting event IDs:     {conflicting_event_ids}")
    print(f"Labeled clean rows:        {len(clean_rows)}")
    print(f"Excluded rows:             {len(excluded_rows)}")
    print(f"\nAudit CSV:                 {audit_csv}")
    print(f"Clean labeled CSV:         {clean_csv}")
    print(f"Excluded rows CSV:         {excluded_csv}")
    print(f"QC report:                 {qc_json}")


if __name__ == "__main__":
    main()
