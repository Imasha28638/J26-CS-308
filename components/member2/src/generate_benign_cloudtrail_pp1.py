#!/usr/bin/env python3
"""Offline, reproducible, SYNTHETIC benign AWS CloudTrail-like event generator.

All labels are simulated intent, NOT verified natural benign ground truth.
Do not merge into approved-only research datasets or report its metrics as real-world.
Standard library only.
"""
import argparse
import csv
import json
import random
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

# No real account credentials, internet or AWS calls are used.
ACCOUNT = "000000000000"
CATALOG = {
  "inventory": [
    ("ec2.amazonaws.com", "DescribeInstances", True),
    ("ec2.amazonaws.com", "DescribeVpcs", True),
    ("ec2.amazonaws.com", "DescribeSubnets", True),
    ("ec2.amazonaws.com", "DescribeRouteTables", True),
    ("ec2.amazonaws.com", "DescribeSecurityGroups", True),
    ("ec2.amazonaws.com", "DescribeVolumes", True),
    ("ec2.amazonaws.com", "DescribeRegions", True),
    ("rds.amazonaws.com", "DescribeDBInstances", True),
    ("s3.amazonaws.com", "ListBuckets", True),
    ("s3.amazonaws.com", "GetBucketLocation", True),
    ("lambda.amazonaws.com", "ListFunctions20150331", True),
    ("sts.amazonaws.com", "GetCallerIdentity", True),
  ],
  "iam_review": [
    ("iam.amazonaws.com", "ListUsers", True),
    ("iam.amazonaws.com", "ListRoles", True),
    ("iam.amazonaws.com", "GetAccountSummary", True),
    ("iam.amazonaws.com", "ListPolicies", True),
    ("iam.amazonaws.com", "GetUser", True),
    ("iam.amazonaws.com", "GetPolicy", True),
    ("iam.amazonaws.com", "ListAttachedUserPolicies", True),
    ("sts.amazonaws.com", "GetCallerIdentity", True),
    ("iam.amazonaws.com", "CreateAccessKey", False),
    ("iam.amazonaws.com", "CreateLoginProfile", False),
    ("iam.amazonaws.com", "AttachUserPolicy", False),
  ],
  "security_review": [
    ("cloudtrail.amazonaws.com", "DescribeTrails", True),
    ("cloudtrail.amazonaws.com", "GetTrailStatus", True),
    ("cloudtrail.amazonaws.com", "GetEventSelectors", True),
    ("cloudtrail.amazonaws.com", "ListTrails", True),
    ("logs.amazonaws.com", "DescribeLogGroups", True),
    ("config.amazonaws.com", "DescribeConfigurationRecorders", True),
    ("kms.amazonaws.com", "ListKeys", True),
    ("guardduty.amazonaws.com", "ListDetectors", True),
    ("cloudtrail.amazonaws.com", "PutEventSelectors", False),
    ("cloudtrail.amazonaws.com", "UpdateTrail", False),
  ],
  "maintenance": [
    ("ssm.amazonaws.com", "DescribeParameters", True),
    ("ssm.amazonaws.com", "GetParameter", True),
    ("ssm.amazonaws.com", "PutParameter", False),
    ("lambda.amazonaws.com", "ListFunctions20150331", True),
    ("lambda.amazonaws.com", "GetFunction20150331", True),
    ("lambda.amazonaws.com", "UpdateFunctionConfiguration20150331v2", False),
    ("ec2.amazonaws.com", "DescribeInstances", True),
    ("ec2.amazonaws.com", "StartInstances", False),
    ("ec2.amazonaws.com", "StopInstances", False),
    ("s3.amazonaws.com", "PutBucketTagging", False),
    ("sts.amazonaws.com", "AssumeRole", False),
  ],
  "app_operations": [
    ("s3.amazonaws.com", "ListBuckets", True),
    ("s3.amazonaws.com", "GetBucketAcl", True),
    ("secretsmanager.amazonaws.com", "ListSecrets", True),
    ("secretsmanager.amazonaws.com", "GetSecretValue", True),
    ("kms.amazonaws.com", "Decrypt", True),
    ("kms.amazonaws.com", "DescribeKey", True),
    ("sts.amazonaws.com", "AssumeRole", False),
    ("ec2.amazonaws.com", "DescribeSecurityGroups", True),
    ("rds.amazonaws.com", "DescribeDBInstances", True),
  ],
}

CSV_FIELDS = [
    "dataset_source","source_file","record_index","scenario_id","simulation_session_id",
    "event_id","event_time","event_name","event_source","aws_region","read_only",
    "management_event","source_ip_address","identity_type","identity_arn","actor_user",
    "error_code","request_parameters_json","label_binary","attack_class","ground_truth_source",
    "ground_truth_status","exclude_from_approved_training","generation_seed",
]


def new_uuid(rng):
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def request_for(event_name, actor):
    # Target equals actor for self-service credentials; privileged ops are only
    # emitted under a known authorized-maintenance scenario in this simulator.
    if event_name == "CreateAccessKey":
        return {"userName": actor}
    if event_name == "CreateLoginProfile":
        return {"userName": "example-approved-new-hire", "passwordResetRequired": True}
    if event_name == "AttachUserPolicy":
        return {"userName": "example-approved-new-hire", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
    if event_name == "PutEventSelectors":
        return {"trailName": "example-audit-trail", "eventSelectors": [
            {"readWriteType": "All", "includeManagementEvents": True}]}
    if event_name == "UpdateTrail":
        return {"name": "example-audit-trail", "isMultiRegionTrail": True}
    if event_name == "AssumeRole":
        return {"roleArn": f"arn:aws:iam::{ACCOUNT}:role/example-approved-deployment-role", "roleSessionName": "authorized-automation"}
    if event_name == "PutParameter":
        return {"name": "/example/app/config", "type": "String", "overwrite": True}
    return {}


def generate(sessions=100, seed=4010, start_date="2026-07-01", min_events=15, max_events=45):
    if sessions < 1 or min_events < 2 or max_events < min_events:
        raise ValueError("Invalid sessions or min/max event count")
    rng = random.Random(seed)
    start = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    user_names = [f"sample_user_{i:02d}" for i in range(1, 19)]
    services = Counter()
    events, rows, manifests = [], [], []
    for s in range(sessions):
        scenario = rng.choice(list(CATALOG))
        actor = rng.choice(user_names)
        session_id = f"synthetic_benign_{s:05d}"
        role = rng.choice(["IAMUser", "AssumedRole"])
        actor_arn = (
            f"arn:aws:iam::{ACCOUNT}:user/{actor}" if role == "IAMUser"
            else f"arn:aws:sts::{ACCOUNT}:assumed-role/example-operator/{actor}"
        )
        rng_day = rng.randrange(21)
        hour = rng.randint(7, 20)
        t = start + timedelta(days=rng_day, hours=hour, minutes=rng.randrange(60))
        ip = f"198.51.100.{rng.randrange(11, 230)}"  # reserved documentation IPs
        region = rng.choice(["us-east-1", "us-west-2", "ap-south-1"])
        n = rng.randint(min_events, max_events)
        start_event = len(events)
        for j in range(n):
            # Nonconstant temporal gaps, including short bursts and breaks.
            t += timedelta(seconds=rng.randint(2, 25) if rng.random() < .70 else rng.randint(26, 100))
            source, name, read = rng.choice(CATALOG[scenario])
            # A few legitimate mistakes/permission failures occur in benign activity too.
            err = rng.choice(["AccessDenied", "ResourceNotFoundException", "ValidationException"]) if rng.random() < .055 else ""
            rid = new_uuid(rng)
            eid = new_uuid(rng)
            record = {
                "eventVersion": "1.09",
                "userIdentity": {
                    "type": role, "principalId": f"EXAMPLEPRINCIPAL{user_names.index(actor)+1:03d}",
                    "arn": actor_arn, "accountId": ACCOUNT, "userName": actor if role == "IAMUser" else None,
                    "sessionContext": {"attributes": {"mfaAuthenticated": "true"}}
                },
                "eventTime": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventSource": source, "eventName": name, "awsRegion": region,
                "sourceIPAddress": ip, "userAgent": "aws-cli/2.15.0 ExampleSyntheticResearchGenerator",
                "requestParameters": request_for(name, actor), "responseElements": None,
                "eventID": eid, "requestID": rid, "eventType": "AwsApiCall",
                "eventCategory": "Management", "managementEvent": True,
                "readOnly": read, "recipientAccountId": ACCOUNT,
            }
            if err:
                record["errorCode"] = err
                record["errorMessage"] = f"Synthetic example {err} response"
            events.append(record)
            services[source] += 1
            rows.append({
                "dataset_source":"PP1 Controlled Synthetic Benign",
                "source_file":"synthetic_benign_records.json",
                "record_index":len(events),"scenario_id":scenario,
                "simulation_session_id":session_id,"event_id":eid,
                "event_time":record["eventTime"],"event_name":name,"event_source":source,
                "aws_region":region,"read_only":str(read).lower(),"management_event":"true",
                "source_ip_address":ip,"identity_type":role,"identity_arn":actor_arn,
                "actor_user":actor,"error_code":err,
                "request_parameters_json":json.dumps(record["requestParameters"],sort_keys=True),
                "label_binary":"0", "attack_class":"Benign",
                "ground_truth_source":"controlled_simulator_intent",
                "ground_truth_status":"synthetic_benign_by_design_NOT_real_ground_truth",
                "exclude_from_approved_training":"1",
                "generation_seed":seed,
            })
        manifests.append({
            "simulation_session_id":session_id,"scenario_type":scenario,"actor":actor,
            "first_event_time":events[start_event]["eventTime"],"last_event_time":events[-1]["eventTime"],
            "event_count":len(events)-start_event,
            "source":"synthetic", "intended_activity":"benign",
            "evidence":"generator rule specification, not observed real-world authorization",
        })
    if len({r['event_id'] for r in rows}) != len(rows):
        raise RuntimeError("Duplicate event IDs generated")
    return events,rows,manifests,services


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sessions",type=int,default=100)
    ap.add_argument("--seed",type=int,default=4010)
    ap.add_argument("--start-date",default="2026-07-01")
    ap.add_argument("--min-events",type=int,default=15)
    ap.add_argument("--max-events",type=int,default=45)
    ap.add_argument("--output-dir",type=Path,default=Path("Data/Synthetic/benign_pp1"))
    args=ap.parse_args()
    es,rows,manifest,services=generate(args.sessions,args.seed,args.start_date,args.min_events,args.max_events)
    out=args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    (out/'synthetic_benign_records.json').write_text(json.dumps({"Records":es},indent=1),encoding='utf-8')
    with (out/'synthetic_benign_events.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=CSV_FIELDS)
        w.writeheader();w.writerows(rows)
    with (out/'synthetic_benign_session_manifest.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(manifest[0]))
        w.writeheader();w.writerows(manifest)
    report={
        "source":"PP1 Controlled Synthetic Benign", "intent":"benign", "verified_real_benign":False,
        "events":len(es),"sessions":len(manifest),"unique_event_ids":len({e['eventID'] for e in es}),
        "errors":sum(bool(e.get('errorCode')) for e in es),
        "read_only":sum(e['readOnly'] for e in es),
        "writes":sum(not e['readOnly'] for e in es),
        "scenario_sessions":dict(Counter(m['scenario_type'] for m in manifest)),
        "services":dict(services),"seed":args.seed,
        "limitations":[
            "Simulated benign intent is not independently verified real benign ground truth.",
            "Do not train/evaluate source-confounded synthetic-benign-vs-real-attack accuracy as a deployment result.",
            "Simulator string, source, synthetic user/ARN/IP and session identifiers are non-predictive metadata.",
            "No real AWS API calls were made; API success/permissions are simulated.",
        ]
    }
    (out/'synthetic_benign_qc_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('Synthetic benign CloudTrail generation completed')
    print(f'  Sessions: {len(manifest)}')
    print(f'  CloudTrail-like events: {len(es)}')
    print(f'  Unique event IDs: {report["unique_event_ids"]}')
    print(f'  Read-only events: {report["read_only"]}')
    print(f'  Write events: {report["writes"]}')
    print(f'  Events with simulated API errors: {report["errors"]}')
    print('  Dataset label: simulated benign by design (NOT verified real benign)')
    print(f'Output: {out}')

if __name__=='__main__': main()
