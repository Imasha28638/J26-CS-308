# CloudTrail Research Step 1: Dataset Acquisition and Canonical Conversion

This starter kit implements only the first implementation stage:

**raw datasets -> canonical event-level CSV**

It does NOT yet create the final Random Forest / LightGBM / XGBoost feature matrix or the LSTM sequences.

## 1. Recommended folder layout

```text
RP_CloudTrail_ML/
├── data/
│   ├── raw/
│   │   ├── stratus/
│   │   ├── splunk_attack_data/
│   │   ├── invictus_sigma_aws/
│   │   ├── cloudtrail_v6/
│   │   ├── flaws/
│   │   └── controlled_benign/
│   ├── interim/
│   │   └── canonical_events/
│   └── processed/
├── metadata/
│   ├── dataset_registry.csv
│   └── label_manifest.csv
├── src/
│   ├── convert_cloudtrail.py
│   └── inspect_canonical.py
└── notebooks/
```

## 2. Python environment

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install:

```bash
pip install -r requirements.txt
```

## 3. Convert raw CloudTrail data

Unlabelled conversion:

```bash
python src/convert_cloudtrail.py \
  data/raw/invictus_sigma_aws/CloudTrail \
  data/interim/canonical_events/invictus_events.csv \
  --dataset "Invictus Sigma-AWS"
```

Known malicious Stratus detonation file:

```bash
python src/convert_cloudtrail.py \
  data/raw/stratus/example-technique.json \
  data/interim/canonical_events/stratus_example.csv \
  --dataset "Stratus Red Team" \
  --label-binary 1 \
  --attack-class "Persistence" \
  --attack-technique "aws.persistence.iam-create-admin-user" \
  --scenario-id "stratus_iam_create_admin_user" \
  --ground-truth-source "Stratus public detonation log"
```

Known controlled benign logs:

```bash
python src/convert_cloudtrail.py \
  data/raw/controlled_benign \
  data/interim/canonical_events/controlled_benign.csv \
  --dataset "Controlled Benign CloudTrail" \
  --label-binary 0 \
  --attack-class "Benign" \
  --scenario-id "benign_run_001" \
  --ground-truth-source "Researcher-controlled benign AWS activity"
```

## 4. Inspect the result

```bash
python src/inspect_canonical.py data/interim/canonical_events/invictus_events.csv
```

## 5. Critical research rules

1. Do not label a whole dataset malicious simply because an attack took place somewhere in it.
2. Do not label flAWS records benign. The public flAWS archive is attack-rich and does not contain reliable event-level benign/malicious labels.
3. Keep raw data unchanged. Write converted data to `data/interim/`.
4. Keep `dataset_source`, `source_file`, `attack_technique`, `scenario_id`, and ground-truth columns for provenance, but never use them as model features.
5. Treat obvious simulator markers as leakage. For example, `userAgent` values containing `stratus-red-team` can reveal the class directly. Preserve them for audit/ground truth, then remove or sanitize them before model training.
6. Keep the final test set scenario/session-separated from the development set.
7. The tree-based models will later use window/session-level engineered features. LSTM will later use ordered event sequences. Do not train the final models directly on this canonical event CSV yet.
