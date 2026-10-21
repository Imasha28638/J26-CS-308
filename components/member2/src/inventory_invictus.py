#!/usr/bin/env python3
"""Audit the contents of local Invictus Sigma-AWS CloudTrail JSON files.

This is an inventory and quality-control step ONLY, not an attack labeler.
Compatible with normal Python 3.9+ standard library, including JSON objects
containing keys that differ only by letter case (e.g. Tag/tag).
"""

import argparse
import csv
import hashlib
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def json_decoder_and_collisions():
    case_collision_counts = Counter()
    exact_duplicate_key_counts = Counter()

    def object_pairs_hook(pairs):
        obj = {}
        case_insensitive = {}
        for key, value in pairs:
            if key in obj:
                exact_duplicate_key_counts[key] += 1
            lower = key.casefold()
            if lower in case_insensitive and case_insensitive[lower] != key:
                pair = tuple(sorted((case_insensitive[lower], key)))
                case_collision_counts[f"{pair[0]} / {pair[1]}"] += 1
            else:
                case_insensitive[lower] = key
            obj[key] = value
        return obj

    return object_pairs_hook, case_collision_counts, exact_duplicate_key_counts


def load_events(path):
    hook, case_collisions, exact_key_dupes = json_decoder_and_collisions()
    with path.open("r", encoding="utf-8-sig") as handle:
        obj = json.load(handle, object_pairs_hook=hook)
    if isinstance(obj, dict) and isinstance(obj.get("Records"), list):
        rows = obj["Records"]
        shape = "CloudTrail Records wrapper"
    elif isinstance(obj, list):
        rows = obj
        shape = "JSON array"
    elif isinstance(obj, dict) and "eventName" in obj:
        rows = [obj]
        shape = "single event"
    else:
        raise ValueError("File does not have a recognized CloudTrail event layout")
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("Events must be JSON objects")
    return rows, shape, case_collisions, exact_key_dupes


def fingerprint(event):
    normalized = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def write_csv(path, columns, rows):
    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_count_csv(path, name, counts):
    write_csv(path, [name, "count"], [{name: key, "count": count} for key, count in counts.most_common()])


def main():
    parser = argparse.ArgumentParser(description="Audit Invictus Sigma-AWS CloudTrail event files without assigning labels")
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("Data/Interim/invictus_inventory"))
    args = parser.parse_args()

    if not args.input_dir.is_dir():
        parser.error(f"Input directory not found: {args.input_dir}")
    paths = sorted(args.input_dir.rglob("*.json"))
    if not paths:
        parser.error(f"No .json files found under: {args.input_dir}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    names = Counter()
    sources = Counter()
    errors = Counter()
    identity_types = Counter()
    user_agents = Counter()
    timed_buckets = Counter()
    case_collisions_total = Counter()
    exact_key_dupes_total = Counter()
    file_reports = []
    all_rows = 0
    parsed_files = 0
    failures = []
    internal_source_ip = 0
    private_source_ip = 0
    valid_dates = []
    hashes = Counter()
    id_hashes = defaultdict(set)
    id_files = defaultdict(set)

    for path in paths:
        report = {
            "file": path.name, "size_bytes": path.stat().st_size,
            "status": "", "shape": "", "records": 0,
            "first_event_time": "", "last_event_time": "",
            "case_only_key_collisions": 0, "exact_duplicate_json_keys": 0,
            "error": "",
        }
        try:
            events, shape, case_counts, key_dupes = load_events(path)
            report["shape"] = shape
            report["case_only_key_collisions"] = sum(case_counts.values())
            report["exact_duplicate_json_keys"] = sum(key_dupes.values())
            case_collisions_total.update(case_counts)
            exact_key_dupes_total.update(key_dupes)
            times = []
            for event in events:
                event_name = str(event.get("eventName") or "<missing>")
                event_source = str(event.get("eventSource") or "<missing>")
                names[event_name] += 1
                sources[event_source] += 1
                if event.get("errorCode"):
                    errors[str(event["errorCode"])] += 1
                identity = event.get("userIdentity") or {}
                if isinstance(identity, dict):
                    identity_types[str(identity.get("type") or "<missing>")] += 1
                agent = str(event.get("userAgent") or "<missing>")
                user_agents[agent] += 1
                ip = str(event.get("sourceIPAddress") or "")
                if ip.lower() == "aws internal":
                    internal_source_ip += 1
                else:
                    try:
                        if ipaddress.ip_address(ip).is_private:
                            private_source_ip += 1
                    except ValueError:
                        pass
                et = str(event.get("eventTime") or "")
                if et:
                    try:
                        moment = datetime.fromisoformat(et.replace("Z", "+00:00"))
                        if moment.tzinfo is None:
                            moment = moment.replace(tzinfo=timezone.utc)
                        moment = moment.astimezone(timezone.utc)
                        valid_dates.append(moment)
                        times.append(moment)
                        bucket = moment.replace(minute=(moment.minute // 5) * 5, second=0, microsecond=0)
                        timed_buckets[bucket.strftime("%Y-%m-%dT%H:%M:%SZ")] += 1
                    except ValueError:
                        pass
                h = fingerprint(event)
                hashes[h] += 1
                eid = event.get("eventID")
                if eid:
                    eid = str(eid)
                    id_hashes[eid].add(h)
                    id_files[eid].add(path.name)
            report["status"] = "OK"
            report["records"] = len(events)
            report["first_event_time"] = min(times).isoformat() if times else ""
            report["last_event_time"] = max(times).isoformat() if times else ""
            all_rows += len(events)
            parsed_files += 1
        except Exception as exc:
            report["status"] = "ERROR"
            report["error"] = str(exc)
            failures.append({"file": path.name, "reason": str(exc)})
        file_reports.append(report)

    duplicate_rows = sum(c - 1 for c in hashes.values() if c > 1)
    conflicting_ids = {eid for eid, hs in id_hashes.items() if len(hs) > 1}
    same_id_different_files = sum(1 for eid, files in id_files.items() if len(files) > 1)
    summary = {
        "inventory_only_not_ground_truth": True,
        "input_dir": str(args.input_dir),
        "json_files_found": len(paths),
        "json_files_parsed": parsed_files,
        "json_files_failed": len(failures),
        "total_events": all_rows,
        "distinct_event_ids": len(id_hashes),
        "exact_duplicate_full_event_rows": duplicate_rows,
        "event_id_conflicts": len(conflicting_ids),
        "event_ids_spanning_multiple_files": same_id_different_files,
        "case_sensitive_key_collisions_seen": dict(case_collisions_total.most_common()),
        "duplicate_exact_json_keys_seen": dict(exact_key_dupes_total.most_common()),
        "aws_internal_source_ip_events": internal_source_ip,
        "private_source_ip_events": private_source_ip,
        "first_event_time_utc": min(valid_dates).isoformat() if valid_dates else None,
        "last_event_time_utc": max(valid_dates).isoformat() if valid_dates else None,
        "top_20_event_names": dict(names.most_common(20)),
        "top_15_services": dict(sources.most_common(15)),
        "top_15_error_codes": dict(errors.most_common(15)),
        "identity_types": dict(identity_types.most_common()),
        "file_errors": failures,
        "warning": "Do not label all events as malicious. AWS Internal and background management events may be present. An attack execution timeline and actor mapping are needed before event-level ground-truth assignment.",
    }

    write_csv(args.output_dir / "per_file_inventory.csv",
              ["file", "size_bytes", "status", "shape", "records", "first_event_time",
               "last_event_time", "case_only_key_collisions", "exact_duplicate_json_keys", "error"], file_reports)
    write_count_csv(args.output_dir / "event_name_counts.csv", "event_name", names)
    write_count_csv(args.output_dir / "event_source_counts.csv", "event_source", sources)
    write_count_csv(args.output_dir / "error_code_counts.csv", "error_code", errors)
    write_count_csv(args.output_dir / "five_minute_event_counts.csv", "five_minute_bucket_utc", timed_buckets)
    (args.output_dir / "inventory_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\nInvictus CloudTrail inventory complete")
    print(f"JSON files found:                 {len(paths)}")
    print(f"JSON files parsed:                {parsed_files}")
    print(f"JSON files failed:                {len(failures)}")
    print(f"Total events:                     {all_rows}")
    print(f"Exact duplicate event rows:       {duplicate_rows}")
    print(f"Conflicting event IDs:            {len(conflicting_ids)}")
    print(f"IDs spanning multiple files:      {same_id_different_files}")
    print(f"Case-only JSON key collisions:    {sum(case_collisions_total.values())}")
    print(f"Exact duplicate JSON keys:        {sum(exact_key_dupes_total.values())}")
    print(f"AWS Internal source IP events:    {internal_source_ip}")
    print(f"Private IP source events:         {private_source_ip}")
    print(f"First event (UTC):                {summary['first_event_time_utc']}")
    print(f"Last event (UTC):                 {summary['last_event_time_utc']}")
    print("\nTop 15 event names:")
    for k, v in names.most_common(15):
        print(f"  {v:>6}  {k}")
    print("\nTop 10 AWS services:")
    for k, v in sources.most_common(10):
        print(f"  {v:>6}  {k}")
    if failures:
        print("\nFiles requiring attention:")
        for f in failures:
            print(f"  {f['file']}: {f['reason']}")
    print(f"\nReports written to: {args.output_dir}")


if __name__ == "__main__":
    main()
