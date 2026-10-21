# PP1 CloudTrail Binary Detection Prototype

**Important: this is an all-synthetic engineering demonstration.** The generated data contains simulated legitimate activity and explicitly injected synthetic attack sequences. It does **not** measure real-world cloud intrusion-detection accuracy. Do not combine it with the approved-only Stratus training data or call the synthetic labels independently verified ground truth.

## Requirements

Use Python 3.10–3.12 on Windows where possible. Create and activate a virtual environment if you want to isolate dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements_pp1.txt
```

Or use your existing Python installation:

```powershell
py -m pip install -r requirements_pp1.txt
```

**PyTorch can be a substantial download.** If its installation fails, consult its official Windows installation instructions appropriate to your hardware and Python version.

## Step 1. Your benign dataset

You already completed this:

```powershell
py src/generate_benign_cloudtrail_pp1.py --sessions 100 --seed 4010 --output-dir "Data/Synthetic/benign_pp1"
```

## Step 2. Create controlled synthetic attack sessions

```powershell
py src/prepare_pp1_experiment.py `
  --benign-csv "Data/Synthetic/benign_pp1/synthetic_benign_events.csv" `
  --attack-sessions 125 `
  --seed 4011 `
  --output-dir "Data/Synthetic/pp1_experiment"
```

This creates **125 additional background sessions using the same benign generator**. It injects **simulated** Credential Abuse, Discovery, Privilege Escalation, Persistence and Defense Evasion attack chains into these sessions. Each injected event is explicitly identified in the audit CSV. The synthetic event logs and session manifest are saved separately. These records are never placed into approved real-event research training outputs.

## Step 3. Train RF, LightGBM, XGBoost, LSTM and OOF stack

```powershell
py src/train_pp1_binary_stack.py `
  --data "Data/Synthetic/pp1_experiment/synthetic_experiment_events.csv" `
  --output-dir "Data/Experiments/pp1_binary" `
  --window-minutes 5 `
  --lstm-epochs 4
```

On first execution this can take a few minutes, depending on your CPU. The model code uses a **session-disjoint** 80/20 train/test split. The final test sessions are never included in model training. The stacking meta-learner is trained only using **three-fold session-disjoint out-of-fold (OOF) base-model predictions**, not base-model in-sample predictions.

Features are five-minute window event counts, error rates, API/service diversity, IAM/logging/API behavior categories, etc. LSTM receives event sequences and inter-event timing, padded to up to 40 events. Predictive features **exclude** user names, source identifiers, simulation markers, ground-truth columns, scenario IDs, and dates.

## Main outputs

- `Data/Synthetic/pp1_experiment/synthetic_experiment_report.json`: how the entirely synthetic samples were generated.
- `Data/Synthetic/pp1_experiment/synthetic_experiment_events.csv`: full synthetic event audit with explicit injection flags.
- `Data/Synthetic/pp1_experiment/synthetic_injected_attack_records.json`: CloudTrail-style `Records` of injected synthetic operations.
- `Data/Experiments/pp1_binary/window_features_RESEARCH_DEMO.csv`: ML tabular window features and audit labels.
- `Data/Experiments/pp1_binary/experiment_report.json`: performance comparison and stated validity limits.
- `Data/Experiments/pp1_binary/test_predictions_RESEARCH_DEMO.csv`: independent *synthetic session* test predictions.
- `Data/Experiments/pp1_binary/oof_meta_training_RESEARCH_DEMO.csv`: leakage-reduced stacking meta-features.
- `Data/Experiments/pp1_binary/tree_models_and_meta_DEMO.joblib`, `lstm_DEMO.pt`: saved prototype models.
- `Data/Experiments/pp1_binary/member4_findings_DEMO_ONLY.csv`: draft handoff schema, *not actual detection findings*.

## Tests

```powershell
py -m unittest discover -s tests -p "test_pp1_pipeline.py" -v
```

## Honest PP1 presentation framing

- **Implemented**: multi-source real log ingestion and QA, separate approved Stratus examples, a fully reproducible synthetic controlled experiment, four base models, a regularized logistic-regression OOF stack, and a demonstration handoff to Member 4.
- **Not yet validated**: actual benign ground truth; generalization across real cloud accounts; independent external attack detection; attack-category classification; calibration and deployment security.
- **Do not say**: “My system detects real AWS attacks at X% accuracy” on this evidence. Say: “The prototype reaches X on a held-out *synthetic-session* test set; real-world validation remains ongoing.”

The source-specific dataset integration at `Data/Interim/unified_reviewed_v3` remains untouched. We do not use the 10 approved Stratus events to train this simulator prototype.
