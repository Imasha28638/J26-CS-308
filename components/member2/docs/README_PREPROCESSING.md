# Splunk CloudTrail preprocessing v2

This stage converts raw Splunk Attack Data CloudTrail JSON/JSONL into an auditable canonical CSV, removes exact duplicates, detects conflicting `eventID` values, applies scenario-specific ground-truth rules, and produces a clean labeled CSV.

## 1. Install dependency

From your project root:

```powershell
pip install pyyaml
```

## 2. Suggested project layout

```text
Research Project/
├─ Data/
│  ├─ Raw/
│  │  └─ data/raw/splunk_attack_data/...
│  └─ Interim/
├─ src/
│  └─ preprocess_splunk_cloudtrail.py
└─ config/
   └─ splunk_scenarios.yml
```

You can also keep the generated `data/interim/preprocessed` path if you prefer.

## 3. Run the Defense Evasion test case

From the folder where `src/` and `config/` exist:

```powershell
python src/preprocess_splunk_cloudtrail.py `
  "Data/Raw/data/raw/splunk_attack_data/datasets/attack_techniques/T1562.008/stop_delete_cloudtrail/aws_cloudtrail_events.json" `
  --scenario "T1562.008_stop_delete_cloudtrail" `
  --config "config/splunk_scenarios.yml" `
  --output-dir "Data/Interim/preprocessed"
```

Expected raw record count: 3.

## 4. Run the CreateAccessKey test case

```powershell
python src/preprocess_splunk_cloudtrail.py `
  "Data/Raw/data/raw/splunk_attack_data/datasets/attack_techniques/T1078/aws_createaccesskey/aws_cloudtrail_events.json" `
  --scenario "T1078_aws_createaccesskey" `
  --config "config/splunk_scenarios.yml" `
  --output-dir "Data/Interim/preprocessed"
```

Expected raw record count: 75.

## 5. Output files

Each scenario gets its own folder:

```text
Data/Interim/preprocessed/<scenario_id>/
├─ canonical_audit.csv
├─ labeled_clean.csv
├─ excluded_rows.csv
└─ qc_report.json
```

### canonical_audit.csv
Contains every original record with quality-control and labeling flags.

### labeled_clean.csv
Contains only non-duplicate, non-conflicting records that satisfy the scenario's ground-truth rule.

### excluded_rows.csv
Contains duplicate, conflicting, or unmatched records. These are retained for research auditability but should not be used for model training.

### qc_report.json
Summarizes row counts, duplicates, event-ID conflicts, labels, event names, event sources, and exclusion reasons.

## 6. Important research rule

Do not treat unmatched records as benign.

A record that fails an attack ground-truth rule is marked `exclude_from_training=1`. The benign class should come from a separately validated benign source or controlled benign AWS activity.

## 7. Leakage warning

The canonical audit data deliberately retains provenance and identity fields for traceability.

Before ML training, do not directly use fields such as:

- `source_file`
- `scenario_id`
- `attack_technique`
- `ground_truth_source`
- `label_rule`
- `event_id`
- `request_id`
- `identity_access_key_id`
- `identity_principal_id`
- raw ARNs
- obvious simulator strings in `user_agent`

Those fields can create data leakage or memorization.

## 8. Next stage

After both test cases produce sensible QC reports, add the remaining Splunk scenarios to `config/splunk_scenarios.yml`, then batch-run the same script.

After that, build:
1. validated benign event collection
2. session/window construction
3. behavioral feature extraction for RF, LightGBM, and XGBoost
4. ordered sequence construction for LSTM
