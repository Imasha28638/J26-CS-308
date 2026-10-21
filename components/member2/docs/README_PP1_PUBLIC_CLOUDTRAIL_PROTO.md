# PP1 Public CloudTrail Import — PROTO

## Purpose

Import the **Cloud Log Sampling** AWS CloudTrail dataset published by the Ariel Cyber Innovation Center. The dataset's records were emitted by AWS CloudTrail for activity exercised in an AWS deployment and were anonymized by its publisher. The publisher documents record-level `should_sample` labels: `true` for attack-associated events and `false` for benign events.

Source: https://github.com/ArielCyber/cloud_log_sampling

The importer **does not download data for you**. Obtain the dataset from the publisher. This kit has been checked using local test archives, but the full external publisher archives were not available in this environment. Inspect the importer report after running it locally before using the output for an experiment.

## 1. Get original dataset

From the Research Project root in PowerShell:

```powershell
git clone https://github.com/ArielCyber/cloud_log_sampling.git "Data/Raw/cloud_log_sampling"
```

Alternatively, use **Code → Download ZIP** at the repository and extract it under `Data/Raw/cloud_log_sampling/`. Nested extraction directories are supported.

You should have the following three ZIP files somewhere under that folder:

- `TrainOn/base_a.zip`
- `TrainOn/train_labeled_a.zip`
- `TestOn/labeled_cloudtrail_a.zip`

If downloaded files are Git LFS pointers rather than ZIP archives, get Git LFS and run `git lfs pull` inside the cloned repository.

## 2. Install script

Extract this development kit into your Research Project root so it adds `src/import_pp1_public_cloudtrail_PROTO.py` and `tests/test_pp1_public_cloudtrail_import_PROTO.py`. It does not overwrite the existing training or inference scripts.

## 3. Import and audit

```powershell
py src/import_pp1_public_cloudtrail_PROTO.py `
  --dataset-dir "Data/Raw/cloud_log_sampling" `
  --output-dir "Data/Interim/pp1_public_cloudtrail_PROTO"
```

On success the importer prints event counts and creates:

- `ariel_train_events_PROTO.csv` — publisher's 2 training archives combined
- `ariel_test_events_PROTO.csv` — publisher's independent test archive, unmodified membership
- `ariel_attack_scenarios_PROTO.csv` — scenario counts by train/test
- `ariel_ingestion_manifest_PROTO.json` — audit report, provenance, principal grouping, split overlap

Read the ingestion manifest before using the data in supervised learning.

Expected totals based on publisher's description:

| Split | Total events | Benign | Attack |
|---|---:|---:|---:|
| Train | 20,711 | 20,170 | 541 |
| Test | 24,087 | 21,502 | 2,585 |

If any records have missing/invalid labels, timestamps, event IDs, readOnly values, or if event IDs repeat across train/test, the importer writes the audit JSON and **does not create training CSV files**. Investigate the audit rather than coercing the missing values.

## 4. Run import tests

```powershell
py tests/test_pp1_public_cloudtrail_import_PROTO.py
```

## 5. Critical experimental safeguards

- Keep **publisher test data out of training**, feature selection, model choice, and threshold tuning.
- `should_sample` and `attack_name` provide labels and diagnostic classes, **not input features**.
- For your 5-minute behavioral detector, derive a positive **window** when one or more included records carry a positive publisher label. Report event- and window-level evaluation separately.
- `session_id` is based on a hashed ARN/principal when available, otherwise an IP-based proxy. It is **not independently verified login-session reconstruction**.
- The existing `train_pp1_mixed_PROTO.py` is not designed for this dataset: it explicitly expects the previous two source names and makes its own internal split. **Do not reuse it unchanged.** We will create a split-preserving four-model trainer next, after the import succeeds.
- Keep `Data/Experiments/pp1_mixed_PROTO` unchanged as the existing reference checkpoint.
- Preserve dataset citation, source URL, provenance and checksums; confirm publisher reuse terms before redistributing any dataset records in your own GitHub repository. Prefer publishing ingestion scripts and dataset download instructions instead of mirroring the ZIP archives.

## Scope

These are AWS CloudTrail records from a controlled AWS deployment. They are valuable for a reproducible PP1 experiment, but not a substitute for later testing with authorized, independently collected logs from your own AWS account.
