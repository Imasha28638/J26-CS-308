# PP1 Public CloudTrail: Publisher-Split Model Training

A separate supervised experiment using the imported Ariel Cyber CloudTrail dataset. Does **not** modify the existing `Data/Experiments/pp1_mixed_PROTO` model directory.

## Prerequisites

* Already imported `ariel_train_events_PROTO.csv`, `ariel_test_events_PROTO.csv`, and `ariel_ingestion_manifest_PROTO.json` in `Data/Interim/pp1_public_cloudtrail_PROTO`.
* Existing `src/train_pp1_binary_stack.py` from your earlier working project. The new script imports only its unchanged feature engineering, RF/LightGBM/XGBoost, and LSTM definitions; it never calls that file's original training workflow.
* Python dependencies already used by your existing PP1 model: `pandas`, `numpy`, `scikit-learn`, `joblib`, `lightgbm`, `xgboost`, `torch`.

## Installation

Extract this ZIP at the Research Project root, adding:

```
src/train_pp1_public_cloudtrail_PROTO.py
tests/test_pp1_public_cloudtrail_train_PROTO.py
README_PP1_PUBLIC_TRAIN_PROTO.md
```

## Step 1: Audit before training

```powershell
py src/train_pp1_public_cloudtrail_PROTO.py `
  --input-dir "Data/Interim/pp1_public_cloudtrail_PROTO" `
  --output-dir "Data/Experiments/pp1_public_cloudtrail_PROTO" `
  --window-minutes 5 `
  --audit-only
```

Review `public_split_audit_PROTO.json`. This reports event counts, positive window counts, positive OOF groups, event-ID overlap, same-actor/5-minute-window overlap, and actors reused across publisher splits. Original publisher labels are record-level; a behavioral window is labeled positive if at least one of its events is labeled positive.

**Important:** The importer already showed *zero native event-ID overlap*, but that does not establish *zero actor/time-window overlap*. If there is same-actor/window overlap, the default training command will refuse to run. Send the audit output for analysis first; `--overlap-policy drop-train` is an explicitly available documented option that discards training windows overlapping the publisher's test window keys. It never modifies the publisher's test records.

## Step 2: Train and evaluate (only if audit is acceptable)

```powershell
py src/train_pp1_public_cloudtrail_PROTO.py `
  --input-dir "Data/Interim/pp1_public_cloudtrail_PROTO" `
  --output-dir "Data/Experiments/pp1_public_cloudtrail_PROTO" `
  --window-minutes 5 `
  --lstm-epochs 4 `
  --folds 3 `
  --oof-grouping actor-day
```

The training data come exclusively from the publisher `TrainOn` archives. The original `TestOn` records are evaluated once after model fitting. Four base models are fitted; a logistic regression meta-learner is trained using out-of-fold predictions from group-separated folds. `actor-day` keeps all activity from the same actor *on the same UTC day* in one meta-training fold; it is **not** actor-disjoint over multiple days. To require actor-disjoint folds, use `--oof-grouping actor`; this requires enough positive actor groups. If positive groups are insufficient, the script stops rather than silently using window-random folds.

The publisher test set contains scenarios absent from training. Results are produced at the actor/time-window level, with separate reports showing attack-window recall by scenario and event coverage by detected windows. **Event coverage is not event-level attack classification accuracy.** Hard voting uses a documented 3-of-4 majority threshold.

## Outputs

Location: `Data/Experiments/pp1_public_cloudtrail_PROTO/`

* `public_split_audit_PROTO.json` — train/test input and grouping integrity.
* `public_experiment_report_PROTO.json` — performance for 7 configurations, per-scenario data, methodology notes.
* `public_attack_scenario_recall_PROTO.csv` — scenario detection recall, including whether the scenario appeared in training.
* `public_test_predictions_PROTO.csv` — four probabilities, stacking scores, original window labels.
* `public_oof_meta_training_PROTO.csv` — meta-learner training scores and fold group keys.
* `public_train_window_features_PROTO.csv`, `public_test_window_features_PROTO.csv` — window-level features and labels.
* `tree_models_and_meta_PROTO.joblib`, `lstm_PROTO.pt`, `feature_whitelist.json` — compatible model artifact layout with the current inference script.

## Scientific scope

The source is an anonymized, AWS-generated public corpus with ground-truth labels supplied by the publisher. We have not independently audited its original AWS accounts. These results constitute evaluation on the public dataset, not deployment performance on your own AWS account. The original publisher split remains the basis for test evaluation; actors can appear in both splits, which is audited. The positive class refers to publisher-designated attack events. A window positive label does not imply every constituent event is malicious. The current classifier produces **binary window predictions**, not attack-category predictions.

If a file or dependency is missing, do not replace it with generated measurements. Fix the import or packaging problem and rerun the audit.

## Tests

```powershell
py tests/test_pp1_public_cloudtrail_train_PROTO.py
```

The kit was tested locally with six input/split tests and one end-to-end four-model model-save exercise on a small constructed fixture. The actual downloaded publisher archives and your Windows environment have not been tested from here; your command outputs determine compatibility and results.
