#!/usr/bin/env python3
"""Unify four existing CloudTrail audit exports without inventing labels.

Standard-library only. Generates audit, review, window/sequence feature files.
Explicit manual evidence is required for any training-approved record.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

SOURCES = {
    "splunk": "splunk.csv",
    "stratus": "stratus.csv",
    "invictus": "invictus.csv",
    "sandbox": "sandbox.csv",
}
CLASSES = {"Credential Abuse", "Discovery", "Privilege Escalation", "Persistence", "Defense Evasion"}
UNIFIED_COLS = [
    "record_key", "source_key", "dataset_source", "source_file", "source_record_index",
    "scenario_id", "simulator_run_id", "event_id", "event_time", "event_name", "event_source",
    "aws_region", "read_only", "management_event", "error_code", "source_ip_address", "identity_type",
    "identity_arn", "actor_user", "actor_group_id", "actor_group_method", "split_group_id",
    "request_id", "row_hash", "source_label_binary", "source_attack_class", "label_scope",
    "ground_truth_source", "ground_truth_status", "source_excluded_from_training", "source_label_status",
    "source_attack_success_field", "approval_status", "approved_binary", "approved_attack_class",
    "approval_evidence", "review_reasons", "cross_source_event_id_overlap", "cross_source_hash_overlap",
    "timestamp_valid"
]
FEATURE_COLS = [
    "event_count", "unique_api_names", "unique_services", "unique_regions",
    "error_count", "error_ratio", "known_read_count", "known_write_count", "unknown_readonly_count",
    "write_ratio_known", "list_calls", "describe_calls", "get_calls", "create_calls", "delete_calls",
    "update_calls", "put_calls", "auth_related_calls", "logging_change_calls", "policy_change_calls",
    "credential_related_calls", "service_switches", "max_events_same_second", "max_same_api_streak",
    "event_span_seconds", "mean_gap_seconds", "p95_gap_seconds", "api_entropy"
]
# Conservative shared-feature subsets. Fields with systematic source-specific
# missingness, such as read_only and aws_region, are retained for audit but NOT
# whitelisted for predictive training by default.
SHARED_TABULAR_FEATURES = [x for x in FEATURE_COLS if x not in {
    "unique_regions", "known_read_count", "known_write_count",
    "unknown_readonly_count", "write_ratio_known"
}]
WINDOW_META = [
    "window_id", "window_start_utc", "window_end_utc", "actor_group_id", "actor_group_method",
    "split_group_id", "source_key", "scenario_id", "window_label_status", "window_approved_binary",
    "window_approved_attack_class", "proposed_attack_classes", "approved_event_count", "unapproved_event_count"
]
SEQ_COLS = ["window_id", "record_key", "position", "gap_seconds", "seconds_from_window_start",
            "is_error", "is_read_known", "is_write_known", "is_read_unknown", "api_is_list",
            "api_is_describe", "api_is_get", "api_is_create", "api_is_delete", "api_is_update",
            "api_is_put", "api_auth_related", "api_logging_change", "api_credential_related"]

# These deliberately omit read_only signals absent from the Invictus CSV.
SHARED_SEQUENCE_FEATURES = [x for x in SEQ_COLS[3:] if x not in {
    "is_read_known", "is_write_known", "is_read_unknown"
}]

REQUIRED = {
    "splunk": {"source_file","record_index","event_time","event_name","event_source","label_binary","attack_class","event_id"},
    "stratus": {"source_file","record_index","event_time","event_name","event_source","label_binary","attack_class","label_status"},
    "invictus": {"source_file","record_index","event_time","event_name","event_source","ground_truth_status"},
    "sandbox": {"source_file","record_index","event_time","event_name","event_source","ground_truth_status"}
}


def digest(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()


def read_csv(path: Path, source=None):
    if not path.is_file():
        raise FileNotFoundError(f"Missing input: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"Missing CSV header in {path}")
        if source in REQUIRED and not REQUIRED[source].issubset(set(reader.fieldnames)):
            raise ValueError(f"Incorrect schema in {path}; missing: {sorted(REQUIRED[source]-set(reader.fieldnames))}")
        for i, row in enumerate(reader, 2):
            if None in row:
                raise ValueError(f"Malformed CSV row in {path}: line {i}")
            yield row


def val(x):
    return "" if x is None else str(x).strip()


def parse_time(s):
    try:
        return datetime.fromisoformat(val(s).replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def truth_bool(s):
    s = val(s).lower()
    return "1" if s in ("1", "true") else "0" if s in ("0", "false") else ""


def safe_group(row, source):
    # grouping identifiers are hashed, never predictive columns
    if row.get("identity_arn"):
        typ, ident = "arn", row["identity_arn"]
    elif row.get("actor_user"):
        typ, ident = "user", row["actor_user"]
    elif row.get("source_ip_address"):
        typ, ident = "source_ip_only", row["source_ip_address"]
    else:
        typ, ident = "no_actor_scenario_file", row.get("source_file") or "unknown"
    # The scenario boundary prevents unrelated test runs from becoming one sequence.
    scenario = row.get("scenario_id") or row.get("simulator_run_id") or "unassigned"
    group = digest(source, scenario, typ, ident)[:24]
    if source in ("splunk", "stratus"):
        split_group = digest(source, scenario)[:24]
    elif source == "invictus":
        split_group = digest(source, row.get("simulator_run_id") or "unmarked_actor", ident)[:24]
    else:
        split_group = digest(source, ident)[:24]
    return group, typ, split_group


def normalize(row, source):
    inv = source == "invictus"
    name = {
        "splunk": "Splunk Attack Data", "stratus": "Stratus Red Team",
        "invictus": "Invictus Sigma-AWS", "sandbox": "CloudTrail Real Sandbox"
    }[source]
    file = val(row.get("source_file"))
    idx = val(row.get("record_index"))
    eid = val(row.get("event_id"))
    scenario = val(row.get("scenario_id"))
    proposed_binary = val(row.get("label_binary")) if not inv else ""
    proposed_class = val(row.get("attack_class")) if not inv else ""
    if source in ("invictus", "sandbox"):
        proposed_binary, proposed_class = "", ""
    elif proposed_binary not in ("", "1", "0"):
        raise ValueError(f"Unexpected label_binary from {source}: {proposed_binary}")
    if proposed_class and proposed_class not in CLASSES:
        raise ValueError(f"Unexpected attack_class from {source}: {proposed_class}")

    obj = {k:"" for k in UNIFIED_COLS}
    obj.update({
        "record_key":digest(source,file,idx,eid)[:32],
        "source_key":source, "dataset_source":name,"source_file":file,
        "source_record_index":idx,"scenario_id":scenario,
        "simulator_run_id":val(row.get("simulator_run_id")),
        "event_id":eid,"event_time":val(row.get("event_time")),
        "event_name":val(row.get("event_name")),"event_source":val(row.get("event_source")),
        "aws_region":val(row.get("aws_region")),
        "read_only":truth_bool(row.get("read_only")),
        "management_event":truth_bool(row.get("management_event")),
        "error_code":val(row.get("error_code")),
        "source_ip_address":val(row.get("source_ip" if inv else "source_ip_address")),
        "identity_type":val(row.get("identity_type")),
        "identity_arn":val(row.get("actor_arn" if inv else "identity_arn")),
        "actor_user":val(row.get("actor_user")),
        "request_id":val(row.get("request_id")),"row_hash":val(row.get("row_hash")),
        "source_label_binary":proposed_binary,
        "source_attack_class":proposed_class,
        "label_scope":val(row.get("label_scope")),
        "ground_truth_source":val(row.get("ground_truth_source")),
        "source_excluded_from_training":truth_bool(row.get("exclude_from_training")),
        "source_label_status":val(row.get("label_status")),
        "source_attack_success_field":val(row.get("attack_success")),
        "approval_status":"unapproved", "approved_binary":"", "approved_attack_class":"",
        "approval_evidence":"", "review_reasons":"", "cross_source_event_id_overlap":"0",
        "cross_source_hash_overlap":"0",
    })
    if source == "splunk":
        obj["ground_truth_status"] = "scenario_or_rule_proxy_not_independently_verified"
        obj["review_reasons"] = "source_label_is_provisional"
    elif source == "stratus":
        obj["ground_truth_status"] = "attack_operation_review_candidate"
        obj["review_reasons"] = "detonation_phase_not_verified"
    elif source == "invictus":
        obj["ground_truth_status"] = "unverified"
        obj["review_reasons"] = "missing_event_level_ground_truth"
    else:
        obj["ground_truth_status"] = "background_candidate_unverified"
        obj["review_reasons"] = "no_verified_benign_ground_truth"
    obj["timestamp_valid"] = "1" if parse_time(obj["event_time"]) is not None else "0"
    obj["actor_group_id"], obj["actor_group_method"],obj["split_group_id"] = safe_group(obj, source)
    if obj["timestamp_valid"] == "0":
        obj["review_reasons"] += "|invalid_timestamp"
    return obj


def collate_collisions(rows):
    for field, output, keyname in (("event_id", "cross_source_event_id_overlap", "event_id"),
                                   ("row_hash", "cross_source_hash_overlap", "row_hash")):
        groups = defaultdict(list)
        for r in rows:
            value = r.get(field)
            if value:
                groups[value].append(r)
        overlap = []
        for v, rs in groups.items():
            if len(set(r["source_key"] for r in rs)) > 1:
                for r in rs:
                    r[output] = "1"
                    r["review_reasons"] += "|cross_source_overlap"
                overlap.append({"identifier_type":keyname,"identifier":v,
                                "count":len(rs),"sources":"|".join(sorted({r['source_key'] for r in rs})),
                                "records":"|".join(r['record_key'] for r in rs)})
        if field == "event_id":
            combined = overlap
        else:
            combined.extend(overlap)
    return combined


def read_approvals(path):
    if path is None:
        return {}
    decisions = {}
    for d in read_csv(path):
        k = val(d.get("record_key"))
        if not k: continue
        if k in decisions: raise ValueError(f"Repeated approval for record_key={k}")
        if val(d.get("decision")).lower() != "approve":
            raise ValueError(f"Expected decision=approve for {k}; do not use blank/reject rows in approvals.csv")
        binary = val(d.get("approved_binary"))
        cls = val(d.get("approved_attack_class"))
        evidence = val(d.get("evidence_reference"))
        if binary not in ("0", "1"):
            raise ValueError(f"Invalid approved_binary for {k}")
        if binary == "1" and cls not in CLASSES:
            raise ValueError(f"Invalid approved_attack_class for {k}")
        if binary == "0" and cls not in ("", "Benign"):
            raise ValueError(f"Benign approval should have empty class/Benign for {k}")
        if len(evidence) < 8:
            raise ValueError(f"Insufficient evidence_reference for {k}; document exact source and context")
        decisions[k] = (binary, cls if binary == "1" else "Benign", evidence)
    return decisions


def apply_approvals(rows, approvals):
    index = {r["record_key"]:r for r in rows}
    if len(index) != len(rows):
        raise ValueError("record_key collision inside normalized data")
    for k, (binary, cls, evidence) in approvals.items():
        if k not in index: raise ValueError(f"Approval references missing record: {k}")
        r = index[k]
        if r["timestamp_valid"] != "1":
            raise ValueError(f"Cannot approve invalid timestamp: {k}")
        if r["cross_source_event_id_overlap"] == "1" or r["cross_source_hash_overlap"] == "1":
            raise ValueError(f"Cannot approve record with cross-source collision: {k}")
        if r["source_key"] in ("splunk", "stratus") and r["source_label_binary"] not in ("", binary):
            raise ValueError(f"Approval contradicts source's proposed binary label for {k}")
        if r["source_key"] in ("splunk", "stratus") and binary == "1" and r["source_attack_class"] not in ("", cls):
            raise ValueError(f"Approval contradicts source's proposed attack class for {k}")
        r["approval_status"] = "approved_with_documented_evidence"
        r["approved_binary"] = binary
        r["approved_attack_class"] = cls
        r["approval_evidence"] = evidence


def api_family(n):
    lower=n.lower()
    categories = ["list", "describe", "get", "create", "delete", "update", "put"]
    for c in categories:
        if lower.startswith(c): return c
    return "other"


def event_flags(r):
    name = r["event_name"].lower()
    auth = name in {"consolelogin", "assumerole", "getfederationtoken", "getcalleridentity"}
    logging = name in {"stoplogging", "deletetrail", "updateTrail".lower(), "puteventselectors", "deleteloggroup", "deleteflowlogs", "deleteresolverquerylogconfig"}
    policy = "policy" in name or "permission" in name or "trust" in name
    credential = any(w in name for w in ("accesskey", "secret", "credential", "loginprofile", "virtualmfa", "federationtoken"))
    return auth, logging, policy, credential


def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("w",encoding="utf-8-sig", newline="") as f:
        wr=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore")
        wr.writeheader()
        for r in rows: wr.writerow({k:r.get(k,"") for k in fields})


def make_features(events):
    names=[r["event_name"] for r in events]
    secs=[parse_time(r["event_time"]) for r in events]
    gaps=[max(0,(b-a).total_seconds()) for a,b in zip(secs,secs[1:])]
    cnt=Counter(names)
    is_read=[r["read_only"] for r in events]
    known=sum(r in ("0","1") for r in is_read)
    reads=sum(r=="1" for r in is_read)
    writes=sum(r=="0" for r in is_read)
    fam=Counter(api_family(n) for n in names)
    fn=[event_flags(r) for r in events]
    per_second=Counter(s.isoformat() for s in secs)
    api_streak=max_streak=0
    last_api=None
    for n in names:
        api_streak=api_streak+1 if n==last_api else 1
        max_streak=max(max_streak,api_streak)
        last_api=n
    ent=-sum((c/len(names))*math.log2(c/len(names)) for c in cnt.values())
    return {
        "event_count":len(events), "unique_api_names":len(cnt),
        "unique_services":len(set(e["event_source"] for e in events if e["event_source"])),
        "unique_regions":len(set(e["aws_region"] for e in events if e["aws_region"])),
        "error_count":sum(bool(e["error_code"]) for e in events),
        "error_ratio":round(sum(bool(e["error_code"]) for e in events)/len(events),6),
        "known_read_count":reads,"known_write_count":writes,
        "unknown_readonly_count":len(events)-known,"write_ratio_known":round(writes/known,6) if known else "",
        "list_calls":fam["list"],"describe_calls":fam["describe"],"get_calls":fam["get"],
        "create_calls":fam["create"],"delete_calls":fam["delete"],
        "update_calls":fam["update"],"put_calls":fam["put"],
        "auth_related_calls":sum(f[0] for f in fn),
        "logging_change_calls":sum(f[1] for f in fn),
        "policy_change_calls":sum(f[2] for f in fn),
        "credential_related_calls":sum(f[3] for f in fn),
        "service_switches":sum(a["event_source"]!=b["event_source"] for a,b in zip(events,events[1:])),
        "max_events_same_second":max(per_second.values()),
        "max_same_api_streak":max_streak,
        "event_span_seconds":round((secs[-1]-secs[0]).total_seconds(),3),
        "mean_gap_seconds":round(statistics.mean(gaps),3) if gaps else 0,
        "p95_gap_seconds":round(sorted(gaps)[min(len(gaps)-1,math.ceil(.95*len(gaps))-1)],3) if gaps else 0,
        "api_entropy":round(ent,6),
    }


def windows_and_sequences(rows, minutes):
    groups=defaultdict(list)
    for r in rows:
        dt=parse_time(r["event_time"])
        if dt is None: continue
        epoch=int(dt.timestamp())
        bucket=epoch//(minutes*60)*(minutes*60)
        groups[(r["actor_group_id"],r["split_group_id"],bucket)].append(r)
    windows=[]; approved_windows=[]; seq=[]; manifest=[]
    for (actor,split,bucket), events in sorted(groups.items(), key=lambda x:(x[0][2],x[0][0])):
        events.sort(key=lambda r:(r["event_time"],r["record_key"]))
        wid=digest(actor,split,str(bucket))[:28]
        approved=[e for e in events if e["approval_status"]=="approved_with_documented_evidence"]
        classes=set((r["approved_binary"],r["approved_attack_class"]) for r in approved)
        if len(approved)==len(events) and len(classes)==1:
            status="approved_homogeneous"
            binary, cls=next(iter(classes))
        elif len(approved):
            status="mixed_or_partial_approval"
            binary=cls=""
        else:
            status="not_approved"
            binary=cls=""
        prop=sorted(set(e["source_attack_class"] for e in events if e["source_attack_class"]))
        start=datetime.fromtimestamp(bucket,tz=timezone.utc)
        row={
            "window_id":wid,"window_start_utc":start.isoformat(),
            "window_end_utc":(start+timedelta(minutes=minutes)).isoformat(),
            "actor_group_id":actor,"actor_group_method":events[0]["actor_group_method"],
            "split_group_id":split,"source_key":events[0]["source_key"],
            "scenario_id":events[0]["scenario_id"],"window_label_status":status,
            "window_approved_binary":binary,"window_approved_attack_class":cls,
            "proposed_attack_classes":"|".join(prop),
            "approved_event_count":len(approved),"unapproved_event_count":len(events)-len(approved),
            **make_features(events)
        }
        windows.append(row)
        if status=="approved_homogeneous":approved_windows.append(row)
        last=None
        for pos,e in enumerate(events):
            cur=parse_time(e["event_time"])
            family=api_family(e["event_name"])
            auth,logging,policy,cred=event_flags(e)
            seq.append({
                "window_id":wid,"record_key":e["record_key"],"position":pos,
                "gap_seconds":round((cur-last).total_seconds(),3) if last else 0,
                "seconds_from_window_start":round((cur-start).total_seconds(),3),
                "is_error":int(bool(e["error_code"])),
                "is_read_known":int(e["read_only"]=="1"),
                "is_write_known":int(e["read_only"]=="0"),
                "is_read_unknown":int(e["read_only"]==""),
                "api_is_list":int(family=="list"),"api_is_describe":int(family=="describe"),
                "api_is_get":int(family=="get"),"api_is_create":int(family=="create"),
                "api_is_delete":int(family=="delete"),"api_is_update":int(family=="update"),
                "api_is_put":int(family=="put"),"api_auth_related":int(auth),
                "api_logging_change":int(logging),"api_credential_related":int(cred),
            })
            last=cur
        manifest.append({"window_id":wid,"ordered_record_keys_json":json.dumps([e["record_key"] for e in events]),
                         "event_count":len(events),"split_group_id":split,"window_label_status":status})
    return windows,approved_windows,seq,manifest


def review_queue(rows):
    # Intentional small triage list, not a proposed training set.
    pergroup=defaultdict(list)
    for r in rows:
        if r["source_key"]=="invictus":
            group=("invictus",r["simulator_run_id"] or "unmarked")
            if not r["simulator_run_id"]: continue
        elif r["source_key"]=="sandbox":
            group=("sandbox","sample")
        else:
            group=(r["source_key"],r["scenario_id"])
        pergroup[group].append(r)
    queue=[]
    for (source, group), es in sorted(pergroup.items()):
        if source=="invictus" and len(queue)>400: break
        n=3 if source=="invictus" else 8 if source=="sandbox" else 5
        for r in es[:n]:
            queue.append({"record_key":r["record_key"],"source_key":source,
                          "scenario_or_run":group,"event_time":r["event_time"],
                          "event_name":r["event_name"],"proposed_attack_class":r["source_attack_class"],
                          "ground_truth_status":r["ground_truth_status"],
                          "review_note":"Inspect original event + scenario execution evidence; do not use source label alone"})
    return queue


def run(args):
    input_dir=Path(args.input_dir);out=Path(args.output_dir)
    out.mkdir(parents=True,exist_ok=True)
    allrows=[];source_counts=Counter()
    for source, fname in SOURCES.items():
        for raw in read_csv(input_dir/fname, source=source):
            allrows.append(normalize(raw,source));source_counts[source]+=1
    overlaps=collate_collisions(allrows)
    decisions=read_approvals(Path(args.approvals) if args.approvals else None)
    apply_approvals(allrows,decisions)
    write_csv(out/"unified_events_audit.csv",UNIFIED_COLS,allrows)
    write_csv(out/"approved_events_only.csv",UNIFIED_COLS,
              [r for r in allrows if r["approval_status"]=="approved_with_documented_evidence"])
    write_csv(out/"cross_source_overlap_review.csv",
              ["identifier_type","identifier","count","sources","records"],overlaps)
    windows,approved_windows,seq,manifest=windows_and_sequences(allrows,args.window_minutes)
    write_csv(out/"behavioral_windows_REVIEW_ONLY.csv",WINDOW_META+FEATURE_COLS,windows)
    write_csv(out/"behavioral_windows_APPROVED_ONLY.csv",WINDOW_META+FEATURE_COLS,approved_windows)
    write_csv(out/"lstm_event_sequences_REVIEW_ONLY.csv",SEQ_COLS,seq)
    write_csv(out/"sequence_manifest_REVIEW_ONLY.csv",
              ["window_id","ordered_record_keys_json","event_count","split_group_id","window_label_status"],manifest)
    write_csv(out/"event_review_queue.csv",
              ["record_key","source_key","scenario_or_run","event_time","event_name","proposed_attack_class","ground_truth_status","review_note"],
              review_queue(allrows))
    write_csv(out/"approval_template.csv",
              ["record_key","decision","approved_binary","approved_attack_class","evidence_reference","reviewer_notes"],[])
    (out/"model_feature_whitelist.json").write_text(json.dumps({
        "tabular_model_numeric_features":SHARED_TABULAR_FEATURES,
        "lstm_numeric_event_features":SHARED_SEQUENCE_FEATURES,
        "audit_feature_columns_not_all_safe_to_train":FEATURE_COLS,
        "sequence_audit_columns_not_all_safe_to_train":SEQ_COLS[3:],
        "excluded_metadata":"Every non-whitelisted column, especially source_key, scenario_id, principal identifiers, timestamps, run identifiers, labels, record IDs, and simulator markers.",
        "caution":"Approved only does not imply leakage-free evaluation. Group by split_group_id, verify label coverage, and assess source confounding."
    },indent=2),encoding="utf-8")
    stat={
        "source_counts":dict(source_counts),"total_events":len(allrows),
        "source_label_counts":dict(Counter(r["source_label_binary"] or "unlabeled" for r in allrows)),
        "proposed_attack_classes":dict(Counter(r["source_attack_class"] for r in allrows if r["source_attack_class"])),
        "approved_event_count":len(decisions),
        "cross_source_event_id_overlap_records":sum(r["cross_source_event_id_overlap"]=="1" for r in allrows),
        "cross_source_hash_overlap_records":sum(r["cross_source_hash_overlap"]=="1" for r in allrows),
        "invalid_timestamp_rows":sum(r["timestamp_valid"]!="1" for r in allrows),
        "behavioral_review_windows":len(windows),
        "approved_homogeneous_windows":len(approved_windows),
        "window_sources":dict(Counter(w["source_key"] for w in windows)),
        "window_label_statuses":dict(Counter(w["window_label_status"] for w in windows)),
        "sequence_event_rows":len(seq),
        "repeated_source_hash_rows_beyond_first":sum(
            max(0, n-1) for (src,h), n in Counter((r["source_key"],r["row_hash"]) for r in allrows if r["row_hash"]).items()
        ),
        "source_cautions":[
            "Splunk labels are scenario/rule proxies, not independently verified event-level ground truth.",
            "Stratus review candidates include source_label_binary=1 but are not training-approved.",
            "Real Sandbox has no verified benign ground truth and lacks stable IAM actor identity.",
            "Invictus is unlabeled; simulator markers cannot independently establish malicious behavior.",
            "CloudTrail Reconstruction v6 is intentionally excluded from training integration as a held-out benchmark.",
            "LogSimv2 generated events are not part of this integration and should remain source tagged.",
            "Same-source event duplication is not re-evaluated here; use earlier source QC reports.",
            "Source-specific label bias and scenario leakage remain unresolved until experimental design and review.",
            "Splunk and Stratus have many single-event windows; these alone do not support LSTM training.",
            "Sandbox event IDs are absent; identical field-level hashes can correspond to distinct real calls and must not be auto-deduplicated."
        ]
    }
    (out/"integration_qc_report.json").write_text(json.dumps(stat,indent=2),encoding="utf-8")
    print("CloudTrail integration completed")
    for k,v in source_counts.items():print(f"  {k}: {v:,} events")
    print(f"Total: {len(allrows):,}")
    print(f"Approved events: {len(decisions):,}")
    print(f"Cross-source eventID overlaps (records): {stat['cross_source_event_id_overlap_records']:,}")
    print(f"Cross-source raw-hash overlaps (records): {stat['cross_source_hash_overlap_records']:,}")
    print(f"Review windows ({args.window_minutes}min): {len(windows):,}")
    print(f"Approved homogeneous windows: {len(approved_windows):,}")
    print("No model training is performed. Unapproved rows remain non-training data.")
    print(f"Output: {out}")
    return stat


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir", required=True,help="Directory containing splunk.csv, stratus.csv, invictus.csv, sandbox.csv")
    ap.add_argument("--output-dir",default="Data/Interim/unified_preprocessed")
    ap.add_argument("--window-minutes",type=int,default=5)
    ap.add_argument("--approvals",help="Optional evidence-backed manual approval CSV; see approval_template.csv")
    args=ap.parse_args()
    if not 1 <= args.window_minutes <= 1440: ap.error("window-minutes must be 1..1440")
    run(args)

if __name__=="__main__": main()
