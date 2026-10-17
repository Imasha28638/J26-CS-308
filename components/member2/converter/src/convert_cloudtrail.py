#!/usr/bin/env python3
"""
Convert common AWS CloudTrail JSON/JSONL/log files into a canonical event-level CSV.

Important:
- This creates an INTERMEDIATE event table, not the final ML feature table.
- Do not assign labels unless the whole input file/directory has reliable ground truth.
- Provenance and label columns are kept for auditability, but must be excluded from model features.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List

SUPPORTED_SUFFIXES = {".json", ".jsonl", ".ndjson", ".log", ".gz"}

FIELDS = [
    "dataset_source",
    "source_file",
    "record_index",
    "event_time",
    "event_name",
    "event_source",
    "aws_region",
    "source_ip_address",
    "user_agent",
    "identity_type",
    "identity_principal_id",
    "identity_arn",
    "identity_user_name",
    "identity_access_key_id",
    "session_issuer_arn",
    "session_issuer_user_name",
    "event_type",
    "event_category",
    "management_event",
    "read_only",
    "error_code",
    "error_message",
    "request_id",
    "event_id",
    "recipient_account_id",
    "resource_arns",
    "resource_types",
    "request_parameters_json",
    "response_elements_json",
    "additional_event_data_json",
    "label_binary",
    "attack_class",
    "attack_technique",
    "scenario_id",
    "ground_truth_source",
]

def nested_get(obj: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    cur: Any = obj
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur

def json_compact(value: Any) -> str:
    if value is None:
        return ""
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    except Exception:
        return str(value)

def open_text(path: Path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("rt", encoding="utf-8", errors="replace")

def yield_from_loaded(data: Any) -> Iterator[Dict[str, Any]]:
    if isinstance(data, dict):
        if isinstance(data.get("Records"), list):
            for record in data["Records"]:
                if isinstance(record, dict):
                    yield record
        else:
            yield data
    elif isinstance(data, list):
        for record in data:
            if isinstance(record, dict):
                yield record

def iter_events(path: Path) -> Iterator[Dict[str, Any]]:
    """
    Supports:
      1) Standard CloudTrail {"Records": [...]}
      2) JSON arrays [...]
      3) Single JSON event {...}
      4) JSONL/NDJSON, one JSON object per line
    """
    with open_text(path) as f:
        text = f.read()

    stripped = text.strip()
    if not stripped:
        return

    # First try a complete JSON document.
    try:
        data = json.loads(stripped)
        yield from yield_from_loaded(data)
        return
    except json.JSONDecodeError:
        pass

    # Then try line-delimited JSON.
    bad = 0
    for line_no, line in enumerate(stripped.splitlines(), start=1):
        s = line.strip()
        if not s:
            continue
        # Tolerate lines copied from arrays/envelopes.
        if s in {"[", "]", "{", "}", '{"Records":[', "]}"}:
            continue
        s = s.rstrip(",")
        try:
            data = json.loads(s)
        except json.JSONDecodeError:
            bad += 1
            continue
        yield from yield_from_loaded(data)

    if bad:
        print(f"[WARN] {path}: skipped {bad} non-JSON line(s)", file=sys.stderr)

def resources(record: Dict[str, Any]) -> tuple[str, str]:
    r = record.get("resources")
    if not isinstance(r, list):
        return "", ""
    arns: List[str] = []
    types: List[str] = []
    for item in r:
        if not isinstance(item, dict):
            continue
        arn = item.get("ARN") or item.get("arn")
        typ = item.get("type")
        if arn:
            arns.append(str(arn))
        if typ:
            types.append(str(typ))
    return "|".join(arns), "|".join(types)

def canonical_row(
    record: Dict[str, Any],
    *,
    dataset: str,
    source_file: str,
    record_index: int,
    label_binary: str,
    attack_class: str,
    attack_technique: str,
    scenario_id: str,
    ground_truth_source: str,
) -> Dict[str, Any]:
    arns, types = resources(record)
    return {
        "dataset_source": dataset,
        "source_file": source_file,
        "record_index": record_index,
        "event_time": record.get("eventTime", ""),
        "event_name": record.get("eventName", ""),
        "event_source": record.get("eventSource", ""),
        "aws_region": record.get("awsRegion", ""),
        "source_ip_address": record.get("sourceIPAddress", ""),
        "user_agent": record.get("userAgent", ""),
        "identity_type": nested_get(record, "userIdentity", "type"),
        "identity_principal_id": nested_get(record, "userIdentity", "principalId"),
        "identity_arn": nested_get(record, "userIdentity", "arn"),
        "identity_user_name": nested_get(record, "userIdentity", "userName"),
        "identity_access_key_id": nested_get(record, "userIdentity", "accessKeyId"),
        "session_issuer_arn": nested_get(
            record, "userIdentity", "sessionContext", "sessionIssuer", "arn"
        ),
        "session_issuer_user_name": nested_get(
            record, "userIdentity", "sessionContext", "sessionIssuer", "userName"
        ),
        "event_type": record.get("eventType", ""),
        "event_category": record.get("eventCategory", ""),
        "management_event": record.get("managementEvent", ""),
        "read_only": record.get("readOnly", ""),
        "error_code": record.get("errorCode", ""),
        "error_message": record.get("errorMessage", ""),
        "request_id": record.get("requestID", record.get("requestId", "")),
        "event_id": record.get("eventID", record.get("eventId", "")),
        "recipient_account_id": record.get("recipientAccountId", ""),
        "resource_arns": arns,
        "resource_types": types,
        "request_parameters_json": json_compact(record.get("requestParameters")),
        "response_elements_json": json_compact(record.get("responseElements")),
        "additional_event_data_json": json_compact(record.get("additionalEventData")),
        "label_binary": label_binary,
        "attack_class": attack_class,
        "attack_technique": attack_technique,
        "scenario_id": scenario_id,
        "ground_truth_source": ground_truth_source,
    }

def discover_files(input_path: Path) -> List[Path]:
    if input_path.is_file():
        return [input_path]
    files = [
        p for p in input_path.rglob("*")
        if p.is_file() and p.suffix.lower() in SUPPORTED_SUFFIXES
    ]
    return sorted(files)

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="Input JSON/JSONL/log file or directory")
    parser.add_argument("output_csv", type=Path, help="Output canonical CSV")
    parser.add_argument("--dataset", required=True, help="Dataset/source name")

    # Only use label arguments if the supplied input has homogeneous, verified ground truth.
    parser.add_argument("--label-binary", default="", choices=["", "0", "1"],
                        help="0=benign, 1=malicious. Leave blank if not safely known.")
    parser.add_argument("--attack-class", default="",
                        help="e.g. Credential Abuse, Discovery, Privilege Escalation, Persistence, Defense Evasion")
    parser.add_argument("--attack-technique", default="",
                        help="MITRE/Stratus technique identifier when reliably known")
    parser.add_argument("--scenario-id", default="")
    parser.add_argument("--ground-truth-source", default="")
    args = parser.parse_args()

    files = discover_files(args.input)
    if not files:
        raise SystemExit(f"No supported input files found under: {args.input}")

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    file_stats = []
    with args.output_csv.open("w", newline="", encoding="utf-8-sig") as out:
        writer = csv.DictWriter(out, fieldnames=FIELDS)
        writer.writeheader()

        for path in files:
            count = 0
            try:
                for i, event in enumerate(iter_events(path)):
                    row = canonical_row(
                        event,
                        dataset=args.dataset,
                        source_file=str(path),
                        record_index=i,
                        label_binary=args.label_binary,
                        attack_class=args.attack_class,
                        attack_technique=args.attack_technique,
                        scenario_id=args.scenario_id,
                        ground_truth_source=args.ground_truth_source,
                    )
                    writer.writerow(row)
                    count += 1
                    total += 1
            except Exception as exc:
                print(f"[ERROR] {path}: {exc}", file=sys.stderr)
            file_stats.append((str(path), count))
            print(f"[OK] {path}: {count:,} event(s)")

    summary = {
        "dataset": args.dataset,
        "output_csv": str(args.output_csv),
        "total_events": total,
        "files": [{"file": f, "events": n} for f, n in file_stats],
        "label_binary_applied": args.label_binary,
        "attack_class_applied": args.attack_class,
        "attack_technique_applied": args.attack_technique,
        "scenario_id": args.scenario_id,
        "ground_truth_source": args.ground_truth_source,
    }
    summary_path = args.output_csv.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nDone: {total:,} event(s)")
    print(f"CSV: {args.output_csv}")
    print(f"Summary: {summary_path}")

if __name__ == "__main__":
    main()
