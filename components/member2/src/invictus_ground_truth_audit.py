#!/usr/bin/env python3
"""Audit Invictus Sigma-AWS CloudTrail events for potential ground-truth clues.

No benign/malicious labels are assigned. All candidate flags are investigative
hints only, not verified evidence of attacks.
"""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import csv
import json
from pathlib import Path
import re

# Investigation shortlist. These operations can be legitimate too.
CANDIDATE_APIS = {
    "StopLogging", "DeleteTrail", "UpdateTrail", "DeleteLogGroup",
    "DeleteDetector", "DeleteRule", "DeleteWebACL", "DeleteIPSet",
    "CreateAccessKey", "UpdateAccessKey", "CreateUser", "CreateLoginProfile",
    "UpdateLoginProfile", "AttachUserPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutRolePolicy", "UpdateAssumeRolePolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion", "CreateRole",
    "AddUserToGroup", "PutBucketPolicy", "PutBucketAcl", "PutPublicAccessBlock",
    "DeletePublicAccessBlock", "GetSecretValue", "GetPasswordData",
    "AssumeRole", "SendCommand", "StartSession", "CreateVirtualMFADevice",
    "DeactivateMFADevice", "DeleteVirtualMFADevice", "EnableMFADevice",
    "PutRolePolicy", "GetParameter", "GetParameters", "GetParametersByPath",
    "Decrypt", "ModifySnapshotAttribute", "ModifyImageAttribute",
    "ModifyInstanceAttribute", "RunInstances", "Invoke", "UpdateFunctionCode",
}

SIMULATOR_RE = re.compile(r"stratus[-_ ]?red[-_ ]?team|atomic[-_ ]?red[-_ ]?team", re.IGNORECASE)


def parse_utc(s):
    if not s:
        return None
    try:
        t = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return t.astimezone(timezone.utc)
    except ValueError:
        return None


def save_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        w = csv.DictWriter(stream, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input-dir", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--repo-dir", type=Path, help="Optional parent Invictus repository for README clues")
    a = p.parse_args()
    a.output_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(a.input_dir.rglob("*.json"))
    if not files:
        raise SystemExit(f"No .json files found in: {a.input_dir}")

    errors = []
    events = []
    for path in files:
        try:
            obj = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(obj, dict) or not isinstance(obj.get("Records"), list):
                raise ValueError("Expected object with Records array")
            for idx, item in enumerate(obj["Records"], 1):
                if not isinstance(item, dict):
                    raise ValueError(f"Record {idx} not an object")
                events.append((path.name, idx, item))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append({"file": path.name, "error": str(exc)})

    if errors:
        (a.output_dir / "parse_errors.json").write_text(json.dumps(errors, indent=2), encoding="utf-8")
        raise SystemExit(f"Stopped: {len(errors)} files failed parsing. See parse_errors.json")

    candidate_rows = []
    timeline = Counter()
    api_counts = Counter()
    actor_records = defaultdict(lambda: {"events":0, "candidate_events":0, "ips":set(), "apis":Counter(), "first":None, "last":None})
    marker_count = 0
    sources = Counter()

    for fname, idx, e in events:
        when = parse_utc(e.get("eventTime"))
        ename = str(e.get("eventName") or "")
        svc = str(e.get("eventSource") or "")
        agent = str(e.get("userAgent") or "")
        ip = str(e.get("sourceIPAddress") or "")
        ident = e.get("userIdentity") or {}
        if not isinstance(ident, dict):
            ident = {}
        actor = str(ident.get("arn") or ident.get("principalId") or ident.get("type") or "<unknown>")
        is_candidate = ename in CANDIDATE_APIS
        is_marker = bool(SIMULATOR_RE.search(agent))
        marker_count += int(is_marker)
        api_counts[ename] += 1
        sources[svc] += 1

        if when:
            five = when.replace(minute=(when.minute // 5)*5, second=0, microsecond=0)
            timeline[five.isoformat()] += 1
        state = actor_records[actor]
        state["events"] += 1
        state["candidate_events"] += int(is_candidate)
        if ip:
            state["ips"].add(ip)
        state["apis"][ename] += 1
        if when and (state["first"] is None or when < state["first"]):
            state["first"] = when
        if when and (state["last"] is None or when > state["last"]):
            state["last"] = when

        if is_candidate or is_marker:
            candidate_rows.append({
                "source_file":fname,
                "record_index":idx,
                "event_time":str(e.get("eventTime") or ""),
                "event_id":str(e.get("eventID") or ""),
                "event_name":ename,
                "event_source":svc,
                "identity_type":str(ident.get("type") or ""),
                "actor_arn":str(ident.get("arn") or ""),
                "source_ip":ip,
                "user_agent":agent,
                "error_code":str(e.get("errorCode") or ""),
                "candidate_api_flag":int(is_candidate),
                "simulator_marker_flag":int(is_marker),
                "label_binary":"",  # always unknown
                "attack_class":"",  # always unknown
                "ground_truth_status":"unverified_candidate",
            })

    actor_rows = []
    for key, state in actor_records.items():
        actor_rows.append({
            "actor_arn_or_id":key,
            "total_events":state["events"],
            "candidate_events":state["candidate_events"],
            "distinct_source_ips":len(state["ips"]),
            "first_utc":state["first"].isoformat() if state["first"] else "",
            "last_utc":state["last"].isoformat() if state["last"] else "",
            "top_api_names":" | ".join(f"{k}:{n}" for k,n in state["apis"].most_common(8)),
        })
    actor_rows.sort(key=lambda r: (-r["candidate_events"],-r["total_events"]))

    save_csv(a.output_dir/"candidate_events_unlabeled.csv", candidate_rows,
             ["source_file","record_index","event_time","event_id","event_name","event_source","identity_type","actor_arn","source_ip","user_agent","error_code","candidate_api_flag","simulator_marker_flag","label_binary","attack_class","ground_truth_status"])
    save_csv(a.output_dir/"actor_activity.csv", actor_rows,
             ["actor_arn_or_id","total_events","candidate_events","distinct_source_ips","first_utc","last_utc","top_api_names"])
    save_csv(a.output_dir/"five_minute_activity.csv", [{"five_minute_utc":t,"count":n} for t,n in sorted(timeline.items())],
             ["five_minute_utc","count"])
    save_csv(a.output_dir/"api_counts.csv", [{"event_name":k,"count":v} for k,v in api_counts.most_common()],
             ["event_name","count"])

    readme_matches = []
    if a.repo_dir:
        rpath = a.repo_dir/"README.md"
        if rpath.exists():
            for lineno, line in enumerate(rpath.read_text(encoding="utf-8",errors="replace").splitlines(),1):
                if re.search(r"stratus|technique|timestamp|attack|CloudTrail",line,re.IGNORECASE):
                    readme_matches.append({"line":lineno,"text":line[:500]})
    (a.output_dir/"readme_clues.json").write_text(json.dumps(readme_matches,indent=2),encoding="utf-8")

    report = {
        "files_parsed":len(files),
        "events_parsed":len(events),
        "candidate_or_marker_events":len(candidate_rows),
        "candidate_api_events":sum(r["candidate_api_flag"] for r in candidate_rows),
        "simulator_marker_events":marker_count,
        "actors_seen":len(actor_records),
        "all_events_unlabeled":True,
        "note":"API calls and simulator markers are review clues, not verified malicious/benign labels",
        "top_event_names":dict(api_counts.most_common(15)),
    }
    (a.output_dir/"ground_truth_audit_summary.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    print("Invictus ground-truth discovery audit complete")
    print(f"Files parsed:              {len(files)}")
    print(f"Events parsed:             {len(events)}")
    print(f"Candidate API events:      {report['candidate_api_events']}")
    print(f"Simulator marker events:   {marker_count}")
    print(f"Distinct actors:           {len(actor_records)}")
    print("Labels assigned:           0 (intentional)")
    print(f"Reports saved to:          {a.output_dir}")


if __name__ == "__main__":
    main()
