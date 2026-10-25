# Member 4 · Risk-calibrated Terraform misconfiguration detection

**Shimar Z A M · IT23215092 · J26-CS-308 (IaC layer)**

For each Terraform file, the model predicts which of 60 AWS security rules
(46 tfsec/Trivy, 14 Terrascan) are broken, gives a calibrated probability for
each, and decides **ACT** (fix), **REVIEW** (an analyst decides) or **NO ALERT**.

Pipeline: word + character TF-IDF → one-vs-rest Linear SVM (C = 0.5) →
per-rule isotonic calibration → per-rule thresholds (policy v1 / v2).

## Folders
- `dashboard/` – TetraTrace investigator dashboard (FastAPI + web page), human review, verify script
- `notebooks/` – Google Colab training and evaluation notebook (Cells 1–52)

## Model file
`m4_scanner_bundle.joblib` (about 40 MB) is **not in Git**: the team `.gitignore`
excludes `*.joblib`. Download it from the shared Google Drive
(`m4_terraform/models/`) and put it in `dashboard/`. Built with scikit-learn 1.6.1.

## Run
In `dashboard/`, double-click `start.bat` (Python 3.12), open http://localhost:8050,
then `verify.bat` should report 12/12 checks passed.

## Key results (clean gold, 578 unseen files)
False automatic alerts per 100 files 20.2 → 14.4 (95% CI −9.34 to −2.77);
recall 0.792 → 0.873 (95% CI +0.056 to +0.107); about 0.9 REVIEW items per file.
