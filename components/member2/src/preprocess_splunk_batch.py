#!/usr/bin/env python3
"""
Batch preprocess selected Splunk Attack Data CloudTrail scenarios.

Conservative design:
- parse JSON / JSONL
- canonicalize
- exact-duplicate detection
- eventID conflict detection
- scenario-specific ground-truth rules
- per-scenario audit/clean/excluded outputs
- global cross-scenario deduplication/conflict checks
- merged clean malicious dataset

This script does NOT create benign labels.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    import yaml
except ImportError:
    raise SystemExit("Missing dependency: PyYAML. Run: py -m pip install pyyaml")


COLUMNS = [
    "dataset_source","source_file","record_index","scenario_id","research_class",
    "event_version","event_time","event_name","event_source","aws_region",
    "source_ip_address","user_agent","event_type","event_category","management_event","read_only",
    "identity_type","identity_principal_id","identity_arn","identity_user_name",
    "identity_access_key_id","identity_account_id","session_issuer_arn",
    "session_issuer_user_name","session_mfa_authenticated","session_creation_date",
    "error_code","error_message","request_id","event_id","recipient_account_id",
    "resource_arns","resource_types","request_parameters_json","response_elements_json",
    "additional_event_data_json","target_user","actor_user","attack_success",
    "label_binary","attack_class","attack_technique","label_scope","label_confidence",
    "label_rule","ground_truth_source","row_hash","is_exact_duplicate","event_id_conflict",
    "exclude_from_training","exclusion_reason",
    "global_exact_duplicate","global_event_id_conflict","global_label_conflict",
]


def compact_json(v: Any) -> str:
    if v is None:
        return ""
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def norm_json(e: Dict[str, Any]) -> str:
    return json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(e: Dict[str, Any]) -> str:
    return hashlib.sha256(norm_json(e).encode("utf-8")).hexdigest()


def boolish(v: Any) -> Any:
    if isinstance(v, bool):
        return int(v)
    if v is None:
        return ""
    if isinstance(v, str):
        x = v.strip().lower()
        if x == "true": return 1
        if x == "false": return 0
    return v


def parse_json(path: Path) -> List[Dict[str, Any]]:
    txt = path.read_text(encoding="utf-8-sig").strip()
    if not txt:
        return []
    try:
        obj = json.loads(txt)
        if isinstance(obj, dict) and isinstance(obj.get("Records"), list):
            return [x for x in obj["Records"] if isinstance(x, dict)]
        if isinstance(obj, list):
            return [x for x in obj if isinstance(x, dict)]
        if isinstance(obj, dict):
            return [obj]
    except json.JSONDecodeError:
        pass

    out = []
    for n, line in enumerate(txt.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: invalid JSON on line {n}: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"{path}: line {n} is not a JSON object")
        out.append(obj)
    return out


def actor_user(event: Dict[str, Any]) -> str:
    ident = event.get("userIdentity") or {}
    if ident.get("userName"):
        return str(ident["userName"])
    arn = ident.get("arn")
    if isinstance(arn, str) and arn:
        if ":assumed-role/" in arn:
            parts = arn.split("/")
            if len(parts) >= 3:
                return parts[-1]
        return arn.rsplit("/", 1)[-1]
    return ""


def target_user(event: Dict[str, Any]) -> str:
    req = event.get("requestParameters")
    if isinstance(req, dict) and req.get("userName"):
        return str(req["userName"])
    resp = event.get("responseElements")
    if isinstance(resp, dict):
        ak = resp.get("accessKey")
        if isinstance(ak, dict) and ak.get("userName"):
            return str(ak["userName"])
    return ""


def canonicalize(event: Dict[str, Any], spec: Dict[str, Any], source_file: str, idx: int) -> Dict[str, Any]:
    ident = event.get("userIdentity") or {}
    sess = ident.get("sessionContext") or {}
    issuer = sess.get("sessionIssuer") or {}
    attrs = sess.get("attributes") or {}

    r_arns, r_types = [], []
    for r in event.get("resources") or []:
        if isinstance(r, dict):
            arn = r.get("ARN") or r.get("arn")
            typ = r.get("type")
            if arn: r_arns.append(str(arn))
            if typ: r_types.append(str(typ))

    ec = event.get("errorCode")
    row = {c:"" for c in COLUMNS}
    row.update({
        "dataset_source":"Splunk Attack Data",
        "source_file":source_file,
        "record_index":idx,
        "scenario_id":spec["scenario_id"],
        "research_class":spec["attack_class"],
        "event_version":event.get("eventVersion",""),
        "event_time":event.get("eventTime",""),
        "event_name":event.get("eventName",""),
        "event_source":event.get("eventSource",""),
        "aws_region":event.get("awsRegion",""),
        "source_ip_address":event.get("sourceIPAddress",""),
        "user_agent":event.get("userAgent",""),
        "event_type":event.get("eventType",""),
        "event_category":event.get("eventCategory",""),
        "management_event":boolish(event.get("managementEvent")),
        "read_only":boolish(event.get("readOnly")),
        "identity_type":ident.get("type",""),
        "identity_principal_id":ident.get("principalId",""),
        "identity_arn":ident.get("arn",""),
        "identity_user_name":ident.get("userName",""),
        "identity_access_key_id":ident.get("accessKeyId",""),
        "identity_account_id":ident.get("accountId",""),
        "session_issuer_arn":issuer.get("arn",""),
        "session_issuer_user_name":issuer.get("userName",""),
        "session_mfa_authenticated":boolish(attrs.get("mfaAuthenticated")),
        "session_creation_date":attrs.get("creationDate",""),
        "error_code":ec or "",
        "error_message":event.get("errorMessage",""),
        "request_id":event.get("requestID",""),
        "event_id":event.get("eventID",""),
        "recipient_account_id":event.get("recipientAccountId",""),
        "resource_arns":"|".join(r_arns),
        "resource_types":"|".join(r_types),
        "request_parameters_json":compact_json(event.get("requestParameters")),
        "response_elements_json":compact_json(event.get("responseElements")),
        "additional_event_data_json":compact_json(event.get("additionalEventData")),
        "target_user":target_user(event),
        "actor_user":actor_user(event),
        "attack_success":0 if ec else 1,
        "row_hash":sha(event),
        "is_exact_duplicate":0,
        "event_id_conflict":0,
        "exclude_from_training":0,
        "exclusion_reason":"",
        "global_exact_duplicate":0,
        "global_event_id_conflict":0,
        "global_label_conflict":0,
    })
    return row


def add_reason(row: Dict[str, Any], reason: str):
    cur = str(row.get("exclusion_reason") or "")
    parts = [x for x in cur.split("|") if x]
    if reason not in parts:
        parts.append(reason)
    row["exclusion_reason"] = "|".join(parts)


def local_qc(rows: List[Dict[str, Any]]) -> Tuple[int,int]:
    seen = set()
    dups = 0
    for r in rows:
        h = r["row_hash"]
        if h in seen:
            r["is_exact_duplicate"] = 1
            r["exclude_from_training"] = 1
            add_reason(r, "exact_duplicate")
            dups += 1
        else:
            seen.add(h)

    eid_hashes = defaultdict(set)
    for r in rows:
        if r["is_exact_duplicate"]:
            continue
        eid = str(r.get("event_id") or "").strip()
        if eid:
            eid_hashes[eid].add(r["row_hash"])
    conflict_ids = {eid for eid, hs in eid_hashes.items() if len(hs) > 1}
    for r in rows:
        if r.get("event_id") in conflict_ids:
            r["event_id_conflict"] = 1
            r["exclude_from_training"] = 1
            add_reason(r, "event_id_conflict")
    return dups, len(conflict_ids)


def matches(row: Dict[str, Any], rule: Dict[str, Any]) -> Tuple[bool,str]:
    typ = rule["type"]

    if typ == "all_events":
        return True, "all non-duplicate/non-conflicting events in curated scenario"

    if typ == "event_match":
        sources = set(rule.get("event_sources") or [])
        names = set(rule.get("event_names") or [])
        ok_source = (not sources) or row["event_source"] in sources
        ok_name = (not names) or row["event_name"] in names
        return ok_source and ok_name, f"event_source in {sorted(sources)} AND event_name in {sorted(names)}"

    if typ == "cross_user_api_call":
        source = rule["event_source"]
        name = rule["event_name"]
        a = str(row.get("actor_user") or "").strip()
        t = str(row.get("target_user") or "").strip()
        ok = row["event_source"] == source and row["event_name"] == name and a and t and a.lower() != t.lower()
        return bool(ok), f'event_source=="{source}" AND event_name=="{name}" AND actor_user!=target_user'

    raise ValueError(f"Unsupported rule type: {typ}")


def label_rows(rows: List[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str,int]:
    stats = Counter()
    for r in rows:
        if r["exclude_from_training"]:
            stats["qc_excluded"] += 1
            continue
        ok, desc = matches(r, spec["rule"])
        if not ok:
            r["exclude_from_training"] = 1
            add_reason(r, "not_matched_by_ground_truth_rule")
            stats["rule_excluded"] += 1
            continue

        r["label_binary"] = 1
        r["attack_class"] = spec["attack_class"]
        r["attack_technique"] = spec.get("attack_technique","")
        r["label_scope"] = spec.get("label_scope","event_rule")
        r["label_confidence"] = spec.get("label_confidence","high")
        r["label_rule"] = desc
        r["ground_truth_source"] = spec.get("ground_truth_source","Splunk Attack Data scenario metadata")
        stats["labeled"] += 1
    return dict(stats)


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({c:r.get(c,"") for c in COLUMNS})


def resolve_input(repo: Path, spec: Dict[str, Any]) -> Path:
    return repo / spec["relative_path"] / spec["input_file"]


def global_qc(rows: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str,int]]:
    """
    Global quality control after per-scenario labeling.
    - exact same event in multiple scenarios: keep first if same label, exclude later copies
    - same exact event with different class: exclude all copies as global label conflict
    - same eventID with different row hashes: exclude all variants globally
    """
    stats = Counter()

    hash_rows = defaultdict(list)
    for r in rows:
        hash_rows[r["row_hash"]].append(r)

    for h, group in hash_rows.items():
        classes = {g["attack_class"] for g in group}
        if len(classes) > 1:
            for g in group:
                g["global_label_conflict"] = 1
                g["exclude_from_training"] = 1
                add_reason(g, "global_label_conflict")
            stats["global_label_conflict_rows"] += len(group)
        elif len(group) > 1:
            for g in group[1:]:
                g["global_exact_duplicate"] = 1
                g["exclude_from_training"] = 1
                add_reason(g, "global_exact_duplicate")
                stats["global_duplicate_rows"] += 1

    eid_hashes = defaultdict(set)
    eid_rows = defaultdict(list)
    for r in rows:
        eid = str(r.get("event_id") or "").strip()
        if eid:
            eid_hashes[eid].add(r["row_hash"])
            eid_rows[eid].append(r)

    conflict_ids = {eid for eid, hs in eid_hashes.items() if len(hs) > 1}
    for eid in conflict_ids:
        for r in eid_rows[eid]:
            r["global_event_id_conflict"] = 1
            r["exclude_from_training"] = 1
            add_reason(r, "global_event_id_conflict")
    stats["global_conflicting_event_ids"] = len(conflict_ids)

    clean = [r for r in rows if not r["exclude_from_training"] and r["label_binary"] == 1]
    excluded = [r for r in rows if r["exclude_from_training"]]
    stats["global_clean_rows"] = len(clean)
    stats["global_excluded_rows"] = len(excluded)
    return clean, excluded, dict(stats)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--config", type=Path, default=Path("config/splunk_batch_rules.yml"))
    ap.add_argument("--output-dir", type=Path, default=Path("Data/Interim/batch_preprocessed"))
    args = ap.parse_args()

    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}
    specs = cfg.get("scenarios") or []

    args.output_dir.mkdir(parents=True, exist_ok=True)
    scenario_summary = []
    all_labeled = []

    for spec in specs:
        sid = spec["scenario_id"]
        if not spec.get("enabled", True):
            scenario_summary.append({
                "scenario_id":sid,
                "attack_class":spec.get("attack_class",""),
                "status":"SKIPPED",
                "raw_records":0,"exact_duplicates":0,"local_conflicting_event_ids":0,
                "labeled_rows":0,"excluded_rows":0,
                "note":spec.get("review_note","")
            })
            print(f"- {sid}: SKIPPED")
            continue

        inp = resolve_input(args.repo, spec)
        if not inp.exists():
            scenario_summary.append({
                "scenario_id":sid,"attack_class":spec.get("attack_class",""),
                "status":"MISSING INPUT","raw_records":0,"exact_duplicates":0,
                "local_conflicting_event_ids":0,"labeled_rows":0,"excluded_rows":0,
                "note":str(inp)
            })
            print(f"- {sid}: MISSING INPUT")
            continue

        events = parse_json(inp)
        rows = [canonicalize(e,spec,str(inp),i) for i,e in enumerate(events,1)]
        dups, local_conflicts = local_qc(rows)
        label_stats = label_rows(rows,spec)

        folder = args.output_dir / "scenarios" / sid
        write_csv(folder/"canonical_audit.csv", rows)
        clean_local = [r for r in rows if not r["exclude_from_training"] and r["label_binary"] == 1]
        excluded_local = [r for r in rows if r["exclude_from_training"]]
        write_csv(folder/"labeled_clean.csv", clean_local)
        write_csv(folder/"excluded_rows.csv", excluded_local)

        qc = {
            "scenario_id":sid,
            "attack_class":spec["attack_class"],
            "attack_technique":spec.get("attack_technique",""),
            "raw_records":len(events),
            "exact_duplicates":dups,
            "local_conflicting_event_ids":local_conflicts,
            "labeled_clean_rows":len(clean_local),
            "excluded_rows":len(excluded_local),
            "label_stats":label_stats,
            "event_names":dict(Counter(r["event_name"] for r in rows)),
            "event_sources":dict(Counter(r["event_source"] for r in rows)),
            "review_note":spec.get("review_note",""),
        }
        (folder/"qc_report.json").write_text(json.dumps(qc,indent=2),encoding="utf-8")

        scenario_summary.append({
            "scenario_id":sid,
            "attack_class":spec["attack_class"],
            "status":"OK",
            "raw_records":len(events),
            "exact_duplicates":dups,
            "local_conflicting_event_ids":local_conflicts,
            "labeled_rows":len(clean_local),
            "excluded_rows":len(excluded_local),
            "note":spec.get("review_note","")
        })
        all_labeled.extend(clean_local)
        print(f"- {sid}: raw={len(events)}, labeled={len(clean_local)}, excluded={len(excluded_local)}")

    # global merge / cross-scenario checks
    merged_clean, global_excluded, global_stats = global_qc(all_labeled)
    write_csv(args.output_dir/"merged_labeled_clean.csv", merged_clean)
    write_csv(args.output_dir/"global_excluded_rows.csv", global_excluded)

    # summary CSV
    summary_path = args.output_dir/"scenario_summary.csv"
    fields = ["scenario_id","attack_class","status","raw_records","exact_duplicates",
              "local_conflicting_event_ids","labeled_rows","excluded_rows","note"]
    with summary_path.open("w",newline="",encoding="utf-8-sig") as f:
        w=csv.DictWriter(f,fieldnames=fields)
        w.writeheader()
        w.writerows(scenario_summary)

    class_counts = Counter(r["attack_class"] for r in merged_clean)
    batch_report = {
        "scenario_count_configured":len(specs),
        "scenario_summary":scenario_summary,
        "global_qc":global_stats,
        "merged_class_counts":dict(class_counts),
        "important_note":"This output contains malicious labels only. Do not create benign labels from excluded rows."
    }
    (args.output_dir/"batch_qc_report.json").write_text(json.dumps(batch_report,indent=2),encoding="utf-8")

    print("\nBatch complete")
    print(f"Merged clean rows: {len(merged_clean)}")
    print("Class counts:")
    for k,v in class_counts.items():
        print(f"  {k}: {v}")
    print(f"\nSummary: {summary_path}")
    print(f"Merged:  {args.output_dir/'merged_labeled_clean.csv'}")
    print(f"QC:      {args.output_dir/'batch_qc_report.json'}")


if __name__ == "__main__":
    main()
