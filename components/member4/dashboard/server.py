"""TetraTrace — Member 4 (IaC layer) investigator dashboard server.

Run:   uvicorn server:app --port 8000
Open:  http://localhost:8000
Needs m4_scanner_bundle.joblib next to this file (exported from Colab, Cell 45).
"""
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Literal

import sklearn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from m4_scanner import TerraformScanner

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = os.path.join(HERE, "m4_scanner_bundle.joblib")
REVIEWS = os.path.join(HERE, "reviews.jsonl")   # human review log: one JSON record per line, never edited
MAX_CHARS = 500_000
_review_lock = threading.Lock()
# finding fields copied into each review record, so the log can be read on its own
SNAPSHOT_FIELDS = ("finding_id", "file", "predicted_rule", "severity", "decision", "what_it_means",
                   "calibrated_probability", "threshold_low", "threshold_high",
                   "model_version", "policy_version", "evidence_reference")

SAMPLES = {
    "open-ssh-public-s3": {
        "title": "Open SSH + unprotected S3 bucket",
        "file": "network_storage.tf",
        "code": '''resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "my-company-logs"
}
''',
    },
    "public-eks": {
        "title": "EKS cluster exposed to the internet",
        "file": "eks_cluster.tf",
        "code": '''resource "aws_eks_cluster" "main" {
  name     = "prod-cluster"
  role_arn = aws_iam_role.eks.arn
  version  = "1.29"

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]
  }
}
''',
    },
    "unencrypted-rds": {
        "title": "Unencrypted RDS database",
        "file": "database.tf",
        "code": '''resource "aws_db_instance" "app" {
  identifier          = "app-db"
  engine              = "postgres"
  engine_version      = "15"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = var.db_user
  password            = var.db_password
  skip_final_snapshot = true
}
''',
    },
    "iam-wildcard": {
        "title": "IAM policy with wildcards",
        "file": "iam.tf",
        "code": '''resource "aws_iam_policy" "admin" {
  name = "app-admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
''',
    },
}

app = FastAPI(title="TetraTrace · IaC layer (Member 4)")
scanner = TerraformScanner(BUNDLE) if os.path.exists(BUNDLE) else None


class TfFile(BaseModel):
    name: str = Field(default="input.tf", max_length=200)
    code: str


class ScanRequest(BaseModel):
    files: list[TfFile]
    policy: str = "v1"


@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "web", "index.html"))


@app.get("/api/meta")
def meta():
    if scanner is None:
        return {"online": False, "reason": "m4_scanner_bundle.joblib not found next to server.py"}
    v = scanner.versions
    return {"online": True, "rules": len(scanner.rules), "versions": v,
            "sklearn_installed": sklearn.__version__, "sklearn_match": v["sklearn"] == sklearn.__version__,
            "policies": {k: scanner.policy_label(k) for k in ("v1", "v2")},
            "samples": [{"id": k, "title": s["title"], "file": s["file"]} for k, s in SAMPLES.items()]}


@app.get("/api/samples/{sample_id}")
def sample(sample_id: str):
    if sample_id not in SAMPLES:
        raise HTTPException(404, "unknown sample")
    return SAMPLES[sample_id]


@app.post("/api/scan")
def scan(req: ScanRequest):
    if scanner is None:
        raise HTTPException(503, "Model bundle not loaded")
    if req.policy not in ("v1", "v2"):
        raise HTTPException(400, "policy must be v1 or v2")
    files = {}
    for f in req.files:
        if len(f.code) > MAX_CHARS:
            raise HTTPException(413, f"{f.name} is larger than {MAX_CHARS:,} characters")
        name, k = f.name or "input.tf", 2
        while name in files:
            name, k = f"{f.name} ({k})", k + 1
        files[name] = f.code
    if not any(c.strip() for c in files.values()):
        raise HTTPException(400, "No Terraform code received")
    out = scanner.scan_detailed(files, policy=req.policy)
    out["warnings"] = []
    for n, c in files.items():
        if c.strip() and "aws_" not in c:
            out["warnings"].append(f"{n}: no aws_ resources found — this model only covers AWS rules.")
        if len(c) > 3000:
            out["warnings"].append(f"{n}: long file ({len(c):,} chars) — accuracy is lower on long files.")
    return out


# ---------------- human review ----------------
class ReviewIn(BaseModel):
    review_key: str = Field(min_length=3, max_length=300)      # evidence_reference|rule: same code + rule = same key
    human_decision: Literal["confirmed", "not_a_problem"]
    reviewer: str = Field(min_length=1, max_length=80)
    note: str = Field(default="", max_length=1000)
    finding: dict = Field(default_factory=dict)


def _read_reviews() -> list[dict]:
    if not os.path.exists(REVIEWS):
        return []
    rows = []
    with open(REVIEWS, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue   # a damaged line is skipped, never crashes the dashboard
    return rows


@app.post("/api/review")
def add_review(r: ReviewIn):
    if not r.reviewer.strip():
        raise HTTPException(400, "Enter the reviewer's name")
    if r.finding.get("decision") != "REVIEW":
        raise HTTPException(400, "Only REVIEW findings need a human decision")
    rec = {
        "review_id": str(uuid.uuid4()),
        "review_key": r.review_key,
        "human_decision": r.human_decision,
        "reviewer": r.reviewer.strip(),
        "review_note": r.note.strip(),
        "reviewed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **{k: r.finding.get(k) for k in SNAPSHOT_FIELDS},
    }
    with _review_lock, open(REVIEWS, "a", encoding="utf-8") as fh:   # append only: earlier decisions stay as an audit trail
        fh.write(json.dumps(rec, default=str) + "\n")
    return rec


@app.get("/api/reviews")
def list_reviews():
    log = _read_reviews()
    latest = {}
    for rec in log:                      # the newest decision for each finding wins
        latest[rec.get("review_key")] = rec
    return {"latest": latest, "log": log, "count": len(log)}
