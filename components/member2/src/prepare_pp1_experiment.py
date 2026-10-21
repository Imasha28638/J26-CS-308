#!/usr/bin/env python3
"""Prepare SYNTHETIC ONLY PP1 binary attack demo data.

Loads existing synthetic benign CSV and generates equal-format synthetic
background sessions, injecting synthetic attack-pattern events. All events
are synthetic. No real-world accuracy claims are supported.
"""
import argparse
import csv
import json
import random
import sys
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Reuse the benign generator the user already extracted into their project.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from generate_benign_cloudtrail_pp1 import generate, CSV_FIELDS
except ImportError as ex:
    raise SystemExit("Missing src/generate_benign_cloudtrail_pp1.py. Extract the benign starter kit first.") from ex

CLASSES = ["Credential Abuse", "Discovery", "Privilege Escalation", "Persistence", "Defense Evasion"]
ATTACK_CHAINS = {
    "Credential Abuse": [
        ("signin.amazonaws.com", "ConsoleLogin", True, {"authAttempt": "unauthorized_session"}),
        ("sts.amazonaws.com", "AssumeRole", False, {"roleArn": "arn:aws:iam::000000000000:role/example-operator"}),
        ("iam.amazonaws.com", "GetUser", True, {}),
    ],
    "Discovery": [
        ("iam.amazonaws.com", "ListRoles", True, {}),
        ("ec2.amazonaws.com", "DescribeInstances", True, {}),
        ("ec2.amazonaws.com", "DescribeSecurityGroups", True, {}),
        ("cloudtrail.amazonaws.com", "DescribeTrails", True, {}),
        ("s3.amazonaws.com", "ListBuckets", True, {}),
    ],
    "Privilege Escalation": [
        ("iam.amazonaws.com", "GetPolicy", True, {}),
        ("iam.amazonaws.com", "CreatePolicyVersion", False, {"setAsDefault": True}),
        ("iam.amazonaws.com", "AttachUserPolicy", False, {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
    ],
    "Persistence": [
        ("iam.amazonaws.com", "CreateUser", False, {"userName": "example-controlled-user"}),
        ("iam.amazonaws.com", "CreateAccessKey", False, {"userName": "example-controlled-user"}),
        ("iam.amazonaws.com", "CreateLoginProfile", False, {"userName": "example-controlled-user"}),
    ],
    "Defense Evasion": [
        ("cloudtrail.amazonaws.com", "DescribeTrails", True, {}),
        ("cloudtrail.amazonaws.com", "PutEventSelectors", False, {"eventSelectors":[{"readWriteType":"ReadOnly","includeManagementEvents":False}]}),
        ("cloudtrail.amazonaws.com", "StopLogging", False, {"name":"example-audit-trail"}),
    ],
}
FIELDS = list(CSV_FIELDS) + ["event_origin", "injected_attack_event", "attack_session_class"]


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def prepare(benign_csv, out_dir, attack_sessions=125, seed=4011):
    benign = read_csv(Path(benign_csv))
    if not benign:
        raise ValueError("Benign CSV empty")
    required = set(CSV_FIELDS)
    if not required.issubset(benign[0]):
        raise ValueError("Synthetic benign CSV schema mismatch")
    if any(r.get("label_binary") != "0" for r in benign):
        raise ValueError("Benign input contains nonzero or missing labels")
    rng = random.Random(seed + 738)

    for row in benign:
        row["event_origin"] = "controlled_synthetic"
        row["injected_attack_event"] = "0"
        row["attack_session_class"] = ""

    if attack_sessions < 15:
        raise ValueError("At least 15 synthetic attack sessions needed for split demonstration")
    _, backgrounds, _, _ = generate(sessions=attack_sessions, seed=seed)
    by_session = defaultdict(list)
    for row in backgrounds:
        sid = row["simulation_session_id"].replace("synthetic_benign_", "synthetic_attack_")
        row["simulation_session_id"] = sid
        row["dataset_source"] = "PP1 Controlled Synthetic (same format)"
        row["source_file"] = "synthetic_attack_records.json"
        row["event_origin"] = "controlled_synthetic"
        row["injected_attack_event"] = "0"
        row["attack_session_class"] = ""
        by_session[sid].append(row)

    attack_rows = []
    synthetic_manifest = []
    counts = Counter()
    class_assignment = [CLASSES[i % len(CLASSES)] for i in range(attack_sessions)]
    rng.shuffle(class_assignment)
    for sid, clazz in zip(sorted(by_session), class_assignment):
        background = sorted(by_session[sid], key=lambda x: x["event_time"])
        pivot_index = rng.randint(max(1, len(background)//4), max(2, 3*len(background)//4))
        pivot_index = min(pivot_index, len(background)-1)
        pivot = datetime.fromisoformat(background[pivot_index]["event_time"].replace("Z", "+00:00"))
        anchor = background[pivot_index]
        chain = list(ATTACK_CHAINS[clazz])
        # Vary chain lengths and context while retaining the planned behavior.
        if clazz == "Discovery":
            chain = rng.sample(chain, len(chain))
        if clazz == "Credential Abuse" and rng.random() < .4:
            chain.insert(1, ("signin.amazonaws.com", "ConsoleLogin", True, {"authAttempt":"retry"}))
        if clazz == "Defense Evasion" and rng.random() < .35:
            chain = chain[:2]  # Event-selectors-only variant
        if clazz == "Persistence" and rng.random() < .3:
            chain = chain[:2]  # Credential persistence variant
        for i, (source, name, read_only, request) in enumerate(chain):
            new = anchor.copy()
            new["event_id"] = str(uuid.UUID(int=rng.getrandbits(128), version=4))
            new["event_time"] = iso(pivot + timedelta(seconds=4*i + rng.randint(0, 2)))
            new["event_source"] = source
            new["event_name"] = name
            new["read_only"] = str(read_only).lower()
            new["request_parameters_json"] = json.dumps(request, sort_keys=True)
            new["event_origin"] = "controlled_synthetic"
            new["injected_attack_event"] = "1"
            new["attack_session_class"] = clazz
            new["attack_class"] = clazz
            new["label_binary"] = "1"  # Event is injected synthetic malicious action
            new["scenario_id"] = "simulated_" + clazz.lower().replace(" ", "_")
            new["source_file"] = "synthetic_attack_records.json"
            new["ground_truth_source"] = "explicit_synthetic_attack_injection_manifest"
            new["ground_truth_status"] = "synthetic_attack_by_design_NOT_real_ground_truth"
            new["error_code"] = rng.choice(["AccessDenied", ""]) if rng.random() < .24 else ""
            new["exclude_from_approved_training"] = "1"
            attack_rows.append(new)
            counts[clazz] += 1
        synthetic_manifest.append({
            "simulation_session_id":sid,"attack_class":clazz,
            "injected_event_count":len(chain),"first_injection_utc":iso(pivot),
            "scenario_ground_truth":"controlled_synthetic_injection_only",
        })
    all_rows = benign + backgrounds + attack_rows
    all_rows.sort(key=lambda r: (r["simulation_session_id"],r["event_time"],r["event_id"]))
    if len(set(r["event_id"] for r in all_rows)) != len(all_rows):
        raise ValueError("Event ID collision")
    write_csv(out_dir/"synthetic_experiment_events.csv", all_rows, FIELDS)
    write_csv(out_dir/"synthetic_attack_session_manifest.csv", synthetic_manifest,
              list(synthetic_manifest[0]))

    # Provide matching CloudTrail-shaped JSON for injected attack actions.
    records = []
    for r in attack_rows:
        records.append({
            "eventVersion":"1.09", "eventTime":r["event_time"],
            "eventSource":r["event_source"], "eventName":r["event_name"],
            "awsRegion":r["aws_region"], "sourceIPAddress":r["source_ip_address"],
            "userAgent":"aws-cli/2.15.0 ExampleSyntheticResearchGenerator",
            "eventID":r["event_id"], "managementEvent":True,
            "readOnly":r["read_only"]=="true", "eventCategory":"Management",
            "eventType":"AwsApiCall", "recipientAccountId":"000000000000",
            "userIdentity":{"type":r["identity_type"],"arn":r["identity_arn"]},
            "requestParameters":json.loads(r["request_parameters_json"]),
        })
        if r["error_code"]:
            records[-1]["errorCode"] = r["error_code"]
    (out_dir/"synthetic_injected_attack_records.json").write_text(
        json.dumps({"Records":records},indent=1),encoding="utf-8")
    report = {
        "benign_sessions":len(set(r["simulation_session_id"] for r in benign)),
        "attack_sessions":attack_sessions,
        "benign_input_events":len(benign),
        "synthetic_background_events_for_attack_sessions":len(backgrounds),
        "injected_attack_events":len(attack_rows),
        "total_events":len(all_rows),
        "injected_attack_events_by_class":dict(counts),
        "all_events_synthetic":True,
        "label_scope":"event label 1 only for explicitly injected attacks; window label 1 if any injected attack in window",
        "limitations":[
            "Not a validated real-world benign or attack dataset.",
            "Synthetic attacks have modeled behavioral signatures; performance may be optimistic.",
            "The binary model cannot infer a malicious action's true intent from a single API call.",
            "Never mix with approved real attack training or claim cross-domain detection accuracy.",
        ],
    }
    (out_dir/"synthetic_experiment_report.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    print("PP1 controlled synthetic data prepared")
    for k in ("benign_sessions","attack_sessions","benign_input_events","synthetic_background_events_for_attack_sessions","injected_attack_events","total_events"):
        print(f"  {k}: {report[k]}")
    print("  NOTE: simulation-only training/evaluation, not real-world labels")
    print("Output:", out_dir)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign-csv",type=Path,default=Path("Data/Synthetic/benign_pp1/synthetic_benign_events.csv"))
    parser.add_argument("--attack-sessions",type=int,default=125)
    parser.add_argument("--seed",type=int,default=4011)
    parser.add_argument("--output-dir",type=Path,default=Path("Data/Synthetic/pp1_experiment"))
    args=parser.parse_args()
    args.output_dir.mkdir(parents=True,exist_ok=True)
    prepare(args.benign_csv,args.output_dir,args.attack_sessions,args.seed)

if __name__=="__main__":
    main()
