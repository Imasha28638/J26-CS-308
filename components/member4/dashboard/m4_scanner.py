"""Member 4 scanner core: Terraform code in -> rule findings out.

Loads the bundle exported from Colab (m4_scanner_bundle.joblib) and applies:
TF-IDF (word + char) -> linear SVM scores -> per-rule isotonic calibration
-> per-rule thresholds -> ACT / REVIEW / NO ALERT.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
DECISION_ORDER = {"ACT": 0, "REVIEW": 1, "NO ALERT": 2}


class TerraformScanner:
    def __init__(self, bundle_path: str):
        self.b = joblib.load(bundle_path)
        self.rules = self.b["rules"]
        self.versions = self.b["versions"]

    def policy_label(self, policy: str) -> str:
        return self.b["policies"][policy]["label"]

    def _probabilities(self, codes: list[str]):
        X = hstack([self.b["word_vec"].transform(codes), self.b["char_vec"].transform(codes)]).tocsr()
        S = np.asarray(X @ self.b["W"].T + self.b["b"])
        P = np.column_stack([np.interp(S[:, j], self.b["iso_x"][j], self.b["iso_y"][j])
                             for j in range(len(self.rules))])
        return S, P

    def scan(self, files: dict[str, str], policy: str = "v1", include_no_alert: bool = False) -> pd.DataFrame:
        """files: {file_name: terraform_code}. Each file is scanned on its own (the model is file-level)."""
        names = [n for n, c in files.items() if c and c.strip()]
        if not names:
            return pd.DataFrame()
        S, P = self._probabilities([files[n] for n in names])
        pol = self.b["policies"][policy]
        lo, hi = np.array(pol["t_low"], dtype=float), np.array(pol["t_high"], dtype=float)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        rows = []
        for i, name in enumerate(names):
            digest = hashlib.sha256(files[name].encode()).hexdigest()[:12]
            for j, rule in enumerate(self.rules):
                p = float(P[i, j])
                decision = "ACT" if p >= hi[j] else ("REVIEW" if p >= lo[j] else "NO ALERT")
                if decision == "NO ALERT" and not include_no_alert:
                    continue
                rows.append({
                    "finding_id": str(uuid.uuid4()),
                    "source_component": "M4",
                    "file": name,
                    "decision": decision,
                    "severity": self.b["severity"][j],
                    "predicted_rule": rule,
                    "scanner_family": self.b["scanner"][j],
                    "what_it_means": str(self.b["title"][j]).strip().strip('"'),
                    "calibrated_probability": round(p, 4),
                    "raw_score": round(float(S[i, j]), 4),
                    "threshold_low": None if np.isinf(lo[j]) else round(float(lo[j]), 4),
                    "threshold_high": None if np.isinf(hi[j]) else round(float(hi[j]), 4),
                    "review_required": decision == "REVIEW",
                    "model_version": self.versions["model_version"],
                    "policy_version": f"policy_{policy}",
                    "scan_timestamp": now,
                    "evidence_reference": f"{name}#sha256:{digest}",
                })
        df = pd.DataFrame(rows)
        if df.empty:
            return df
        return df.sort_values(
            ["decision", "severity", "calibrated_probability"],
            key=lambda c: c.map(DECISION_ORDER) if c.name == "decision"
            else (c.map(SEVERITY_ORDER) if c.name == "severity" else -c),
        ).reset_index(drop=True)

    def scan_detailed(self, files: dict[str, str], policy: str = "v1", top_tokens: int = 5) -> dict:
        """Like scan(), plus pipeline statistics and, per finding, the code tokens that pushed the score up."""
        import time
        t0 = time.perf_counter()
        names = [n for n, c in files.items() if c and c.strip()]
        if not names:
            return {"findings": [], "stages": {}, "files": []}
        codes = [files[n] for n in names]
        Xw, Xc = self.b["word_vec"].transform(codes), self.b["char_vec"].transform(codes)
        X = hstack([Xw, Xc]).tocsr()
        t_feat = time.perf_counter()
        S = np.asarray(X @ self.b["W"].T + self.b["b"])
        t_svm = time.perf_counter()
        P = np.column_stack([np.interp(S[:, j], self.b["iso_x"][j], self.b["iso_y"][j]) for j in range(len(self.rules))])
        t_cal = time.perf_counter()
        df = self.scan(files, policy=policy)
        t_pol = time.perf_counter()
        if not hasattr(self, "_word_names"):
            self._word_names = self.b["word_vec"].get_feature_names_out()
        n_word = len(self._word_names)
        findings = []
        for _, r in df.iterrows():
            i, j = names.index(r["file"]), self.rules.index(r["predicted_rule"])
            row = Xw[i].tocoo()
            contrib = row.data * self.b["W"][j, row.col]
            order = np.argsort(-contrib)
            toks = [str(self._word_names[row.col[k]]) for k in order[:top_tokens * 3]
                    if contrib[k] > 0 and row.col[k] < n_word][:top_tokens]
            rec = {k: (None if isinstance(v, float) and not np.isfinite(v) else v) for k, v in r.to_dict().items()}
            rec = {k: (v.item() if isinstance(v, np.generic) else v) for k, v in rec.items()}
            rec["evidence_tokens"] = toks
            findings.append(rec)
        ms = lambda a, b: round((b - a) * 1000, 1)
        stages = {
            "ingest": {"files": len(names), "chars": int(sum(len(c) for c in codes)),
                       "resources": int(sum(c.count('resource "') for c in codes))},
            "features": {"nonzero": int(X.nnz), "dimensions": int(X.shape[1]), "ms": ms(t0, t_feat)},
            "model": {"rules_scored": int(S.shape[1] * S.shape[0]), "max_score": round(float(S.max()), 3), "ms": ms(t_feat, t_svm)},
            "calibration": {"probabilities": int(P.size), "above_0_5": int((P >= 0.5).sum()), "ms": ms(t_svm, t_cal)},
            "policy": {"act": int((df["decision"] == "ACT").sum()) if len(df) else 0,
                       "review": int((df["decision"] == "REVIEW").sum()) if len(df) else 0,
                       "no_alert": int(P.size - len(df)), "ms": ms(t_cal, t_pol)},
            "total_ms": ms(t0, t_pol),
        }
        return {"findings": findings, "stages": stages, "files": names,
                "policy": policy, "policy_label": self.policy_label(policy), "versions": self.versions}

    @staticmethod
    def to_json(df: pd.DataFrame) -> str:
        clean = df.astype(object).where(df.notna(), None)
        return json.dumps(clean.to_dict(orient="records"), indent=2, default=str)
