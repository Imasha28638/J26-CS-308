# PP1 Mixed-Source CloudTrail Model Training (PROTO)

This is the **next development track**. It does not overwrite the earlier training experiment, inference script, or model files.

## Data sources and label quality

| Role | Local input | Label/evidence quality |
|---|---|---|
| Collected attack candidates | `Data/Interim/integration_review/splunk.csv` | Scenario-associated positive candidates; event-level verification incomplete |
| Generated normal operations | `Data/Synthetic/benign_pp1/synthetic_benign_events.csv` | Normal by generator intent, not independently authenticated normal operations |
| Controlled generated attack sequences | `Data/Synthetic/pp1_experiment/synthetic_experiment_events.csv` | Event-level attack-injection flags; both normal context events and injected attack operations |
| External collected attack evidence | `Data/Interim/integration_review/stratus.csv` + `Data/Interim/label_review/stratus_review_candidates.csv` | Only `review_decision=APPROVE` positive event IDs are included in scored windows; all other Stratus rows remain unreviewed context |

**Not used as labeled training data:** 13,641 real-sandbox background candidates and 2,900 Invictus records; neither currently has verified benign/attack labels.

The collected Splunk attack scenarios and generated CloudTrail operations have different distributions. Training and evaluation scores may reflect this collection difference, even with session-disjoint train/test splits. Do not claim deployment accuracy from these scores. An external positive-only Stratus check is included to provide a better indication of missed known attack operations. It does **not** measure precision, specificity, or a general real-world detection rate.

## Installation

Extract the ZIP into:

`RESEARCH_PROJECT_ROOT`

The two scripts are placed in `src/`. They rely on your existing `src/train_pp1_binary_stack.py`, which is not overwritten.

Dependencies were installed during previous training. If needed, install the same `requirements_pp1.txt` as your existing models.

## Step 1. Prepare mixed-source inputs

```powershell
py src/build_pp1_mixed_data_PROTO.py `
  --splunk "Data/Interim/integration_review/splunk.csv" `
  --benign "Data/Synthetic/benign_pp1/synthetic_benign_events.csv" `
  --controlled-events "Data/Synthetic/pp1_experiment/synthetic_experiment_events.csv" `
  --stratus "Data/Interim/integration_review/stratus.csv" `
  --review "Data/Interim/label_review/stratus_review_candidates.csv" `
  --output-dir "Data/Interim/pp1_mixed_PROTO"
```

Expected output includes:

- `mixed_training_events_PROTO.csv`: development events from attack-scenario files and controlled generated operations, with source and label-quality tiers.
- `stratus_external_evidence_PROTO.csv`: all Stratus review candidates as context, only approved attack events used for positive-only external scoring.
- `splunk_scenario_selection_PROTO.csv`: capped, whole-window selections for scanner-heavy Splunk scenarios.
- `dataset_manifest_PROTO.json`: counts, provenance, and limitations.

A reproducible selection seed and whole-window cap prevent the two dominant discovery scenarios from overwhelming the experiment. All records of one scenario remain in one partition at training time.

## Step 2. Train four models and out-of-fold stacking

```powershell
py src/train_pp1_mixed_PROTO.py `
  --mixed-events "Data/Interim/pp1_mixed_PROTO/mixed_training_events_PROTO.csv" `
  --stratus-evidence "Data/Interim/pp1_mixed_PROTO/stratus_external_evidence_PROTO.csv" `
  --output-dir "Data/Experiments/pp1_mixed_PROTO" `
  --window-minutes 5 `
  --lstm-epochs 4
```

Training and tests use *disjoint session/scenario groups*. The meta-learner is trained on three-fold group-separated out-of-fold predictions. Results include all four models, hard voting, soft voting, and stacking. The result also includes a **positive-only** Stratus approved-evidence recall check. This separate track saves a new model pair in `Data/Experiments/pp1_mixed_PROTO`.

### Output files

- `mixed_experiment_report_PROTO.json`: scores, counts, and limitations
- `test_predictions_PROTO.csv`: held-out mixed-source activity-window predictions
- `stratus_approved_attack_recall_PROTO.csv`: independent Stratus approved attack-window scores
- `oof_meta_training_PROTO.csv`: stacking meta-learner out-of-fold features
- `tree_models_and_meta_PROTO.joblib`
- `lstm_PROTO.pt`
- `feature_whitelist.json`

### Step 3. Check saved models with existing inference CLI

Your `infer_pp1_cloudtrail.py` can point to the new model directory without replacing old files:

```powershell
py src/infer_pp1_cloudtrail.py `
  --input "Data/Raw/data/raw/stratus/docs/detonation-logs/aws.defense-evasion.cloudtrail-stop.json" `
  --models-dir "Data/Experiments/pp1_mixed_PROTO" `
  --output "Data/Experiments/pp1_mixed_PROTO/stratus_stop_inference_PROTO.json" `
  --window-minutes 5
```

This repeated Stratus example is a sanity check; the script already reports approved attack-window recall for the full reviewed subset. Keep any manually examined scenario or threshold separate from model-selection claims.

## Repo guidance

- Keep original filenames under the existing `Data/Synthetic/` directory if old scripts refer to them. Changing visible terminology does not require erasing record provenance.
- Commit Python source, READMEs, dependency versions, quality-control manifests, and redacted aggregate results.
- Do not publicly commit account IDs, AWS credentials, access keys, source-IP/personally-identifying information, unreviewed private raw logs, or large binary model checkpoints without inspecting their provenance and permissions.
- Avoid claiming that source-correlated binary accuracy proves AWS attack-detection accuracy; report external evidence recall separately.

## Test the wrapper

```powershell
py -m unittest discover -s tests -p "test_pp1_mixed_PROTO.py" -v
```
