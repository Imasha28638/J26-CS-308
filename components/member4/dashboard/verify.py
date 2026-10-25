"""Check that the running dashboard gives the same answers as the Colab model.

1. Start the server:   uvicorn server:app --port 8000
2. In a second window: python verify.py
Needs reference_check.json (exported from Colab Cell 46) next to this file.
Uses only the Python standard library.
"""
import json
import os
import sys
import urllib.error
import urllib.request

URL = os.environ.get("DASHBOARD_URL", "http://localhost:8000")
HERE = os.path.dirname(os.path.abspath(__file__))
results = []


def call(path, body=None):
    req = urllib.request.Request(URL + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="GET" if body is None else "POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


# 1. server and model
try:
    status, meta = call("/api/meta")
except Exception as e:
    print(f"[FAIL] cannot reach {URL}: {e}\n       Start the server first: uvicorn server:app --port 8000")
    sys.exit(1)
check("server reachable", status == 200)
check("model loaded", meta.get("online") is True, meta.get("reason", ""))
if not meta.get("online"):
    sys.exit(1)
check("60 rules loaded", meta.get("rules") == 60, str(meta.get("rules")))
check("scikit-learn version matches the bundle", meta.get("sklearn_match") is True,
      f"installed {meta.get('sklearn_installed')}, bundle {meta['versions']['sklearn']}")

# 2. same answers as Colab on files the model never saw
ref_path = os.path.join(HERE, "reference_check.json")
if not os.path.exists(ref_path):
    check("reference_check.json present", False, "export it with Colab Cell 46")
else:
    ref = json.load(open(ref_path))
    files = ref["files"]
    status, out = call("/api/scan", {"files": [{"name": f["name"], "code": f["code"]} for f in files],
                                     "policy": ref["policy"]})
    check("scan request succeeded", status == 200, str(out.get("detail", "")))
    got = {}
    for fnd in out.get("findings", []):
        got.setdefault(fnd["file"], {})[fnd["predicted_rule"]] = (fnd["decision"], fnd["calibrated_probability"])
    total = same = 0
    max_diff = 0.0
    mismatches = []
    for f in files:
        g = got.get(f["name"], {})
        for rule in set(f["expected"]) | set(g):
            total += 1
            exp, dec = f["expected"].get(rule, "NO ALERT"), g.get(rule, ("NO ALERT", None))[0]
            if exp == dec:
                same += 1
            else:
                mismatches.append(f"{f['name']} {rule}: Colab {exp}, dashboard {dec}")
        for rule, (dec, p) in g.items():
            if rule in f["probabilities"]:
                max_diff = max(max_diff, abs(p - f["probabilities"][rule]))
    check(f"decisions identical to Colab on {len(files)} unseen gold files", same == total,
          f"{same}/{total} match")
    check("probabilities identical to Colab (difference < 0.001)", max_diff < 1e-3, f"max difference {max_diff:.5f}")
    for m in mismatches[:5]:
        print("       ", m)

# 3. behaviour checks
status, out = call("/api/scan", {"files": [{"name": "empty.tf", "code": "   "}], "policy": "v1"})
check("empty input is rejected", status == 400)
status, out = call("/api/scan", {"files": [{"name": "gcp.tf", "code": 'resource "google_storage_bucket" "b" {\n  name = "x"\n}\n'}], "policy": "v1"})
check("non-AWS code gives a warning", status == 200 and any("aws_" in w for w in out.get("warnings", [])))
eks = call("/api/samples/public-eks")[1]
status, out = call("/api/scan", {"files": [{"name": eks["file"], "code": eks["code"]}], "policy": "v1"})
rules = {f["predicted_rule"]: f["decision"] for f in out.get("findings", [])}
check("known case: public EKS -> AVD-AWS-0040 ACT", rules.get("AVD-AWS-0040") == "ACT", str(rules))
status, out = call("/api/scan", {"files": [{"name": eks["file"], "code": eks["code"]}], "policy": "v2"})
check("policy v2 runs", status == 200 and out.get("policy") == "v2")
status, out = call("/api/scan", {"files": [{"name": "x.tf", "code": "a"}], "policy": "v9"})
check("invalid policy is rejected", status == 400)

print(f"\n{sum(results)}/{len(results)} checks passed" + ("  ✔ dashboard matches the trained model" if all(results) else ""))
sys.exit(0 if all(results) else 1)
