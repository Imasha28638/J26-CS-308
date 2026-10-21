#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml
except ImportError:
    raise SystemExit("Missing dependency: PyYAML. Run: py -m pip install pyyaml")


def parse_json_file(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
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

    rows = []
    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: invalid JSON on line {line_no}: {exc}") from exc
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def row_hash(event: Dict[str, Any]) -> str:
    normalized = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def is_lfs_pointer(path: Path) -> bool:
    try:
        if path.stat().st_size > 1000:
            return False
        head = path.read_text(encoding="utf-8", errors="ignore")[:300]
        return "git-lfs.github.com/spec/v1" in head
    except Exception:
        return False


def choose_cloudtrail_file(folder: Path) -> Path | None:
    preferred = [
        "aws_cloudtrail_events.json",
        "cloudtrail.json",
        "aws_security_scanner.json",
        "aws_iam_accessdenied_discovery_events.json",
        "aws_iam_excessive_list_command_usage.json",
        "aws_iam_assume_role_policy_brute_force.json",
    ]
    for name in preferred:
        p = folder / name
        if p.exists() and not is_lfs_pointer(p):
            return p

    candidates = []
    for p in folder.glob("*.json"):
        lower = p.name.lower()
        if any(x in lower for x in ["security_lake", "ocsf", "asl_", "risk", "bedrock"]):
            continue
        if not is_lfs_pointer(p):
            candidates.append(p)
    return candidates[0] if candidates else None


def extract_yaml(folder: Path) -> Dict[str, Any]:
    files = sorted(list(folder.glob("*.yml")) + list(folder.glob("*.yaml")))
    if not files:
        return {}
    with files[0].open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    data["_yaml_file"] = str(files[0])
    return data


def summarize_scenario(repo: Path, spec: Dict[str, Any]) -> Dict[str, Any]:
    folder = repo / spec["relative_path"]
    result = {
        "research_class": spec["research_class"],
        "scenario_key": spec["scenario_key"],
        "relative_path": spec["relative_path"],
        "folder_exists": folder.exists(),
        "yaml_file": "",
        "mitre_technique_yaml": "",
        "description": "",
        "json_file": "",
        "json_exists": False,
        "lfs_pointer": False,
        "record_count": "",
        "unique_full_rows": "",
        "exact_duplicate_rows": "",
        "conflicting_event_id_count": "",
        "event_names": "",
        "event_sources": "",
        "error_codes": "",
        "identity_types": "",
        "parse_error": "",
    }

    if not folder.exists():
        return result

    meta = extract_yaml(folder)
    result["yaml_file"] = meta.get("_yaml_file", "")
    techniques = meta.get("mitre_technique") or []
    if isinstance(techniques, list):
        result["mitre_technique_yaml"] = "|".join(str(x) for x in techniques)
    else:
        result["mitre_technique_yaml"] = str(techniques)
    result["description"] = str(meta.get("description", "")).replace("\n", " ").strip()

    data_file = choose_cloudtrail_file(folder)
    if data_file is None:
        return result

    result["json_file"] = str(data_file)
    result["json_exists"] = True
    result["lfs_pointer"] = is_lfs_pointer(data_file)
    if result["lfs_pointer"]:
        return result

    try:
        events = parse_json_file(data_file)
    except Exception as exc:
        result["parse_error"] = str(exc)
        return result

    hashes = [row_hash(e) for e in events]
    hash_counts = Counter(hashes)
    exact_dups = sum(c - 1 for c in hash_counts.values() if c > 1)

    event_id_to_hashes = defaultdict(set)
    for event, h in zip(events, hashes):
        eid = event.get("eventID")
        if eid:
            event_id_to_hashes[str(eid)].add(h)
    conflict_count = sum(1 for hs in event_id_to_hashes.values() if len(hs) > 1)

    names = Counter(str(e.get("eventName", "")) for e in events)
    sources = Counter(str(e.get("eventSource", "")) for e in events)
    errors = Counter(str(e.get("errorCode", "")) for e in events if e.get("errorCode"))
    identity_types = Counter(
        str((e.get("userIdentity") or {}).get("type", ""))
        for e in events
        if isinstance(e.get("userIdentity"), dict)
    )

    result.update({
        "record_count": len(events),
        "unique_full_rows": len(hash_counts),
        "exact_duplicate_rows": exact_dups,
        "conflicting_event_id_count": conflict_count,
        "event_names": " | ".join(f"{k}:{v}" for k, v in names.most_common()),
        "event_sources": " | ".join(f"{k}:{v}" for k, v in sources.most_common()),
        "error_codes": " | ".join(f"{k}:{v}" for k, v in errors.most_common()),
        "identity_types": " | ".join(f"{k}:{v}" for k, v in identity_types.most_common()),
    })
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("config/selected_splunk_scenarios.yml"))
    parser.add_argument("--output-dir", type=Path, default=Path("Data/Interim/inventory"))
    args = parser.parse_args()

    with args.config.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    specs = cfg.get("scenarios") or []
    results = [summarize_scenario(args.repo, spec) for spec in specs]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.output_dir / "splunk_scenario_inventory.csv"
    json_path = args.output_dir / "splunk_scenario_inventory.json"

    fieldnames = list(results[0].keys()) if results else []
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("\nScenario inventory complete")
    print(f"Scenarios requested: {len(specs)}")
    print(f"CSV report:          {csv_path}")
    print(f"JSON report:         {json_path}")
    print("\nSummary:")
    for r in results:
        status = "OK"
        if not r["folder_exists"]:
            status = "MISSING FOLDER"
        elif not r["json_exists"]:
            status = "NO NATIVE JSON"
        elif r["lfs_pointer"]:
            status = "LFS POINTER"
        elif r["parse_error"]:
            status = "PARSE ERROR"
        print(
            f"- {r['scenario_key']}: {status}, "
            f"records={r['record_count']}, "
            f"dups={r['exact_duplicate_rows']}, "
            f"conflicts={r['conflicting_event_id_count']}"
        )


if __name__ == "__main__":
    main()
