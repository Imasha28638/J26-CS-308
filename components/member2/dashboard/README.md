# CloudShield Security Operations Dashboard (Member 2 PP1)

Individual research dashboard demonstrating the Member 2 AWS CloudTrail attack-detection system for the PP1 viva defense.

---

## 1. Quick Launch Command

Run from the **Research Project root** in Windows PowerShell:

```powershell
py -m streamlit run Development/J26-CS-308/components/member2/dashboard/app.py
```

The application runs locally without internet access, external API dependencies, or live AWS credentials.

---

## 2. Dashboard Structure and Features

### Screen 1: Security Analytics Overview
- Displays traceable metrics from the selected saved experiment split (total evaluated windows, malicious predictions, benign predictions, base learner count).
- Shows class distribution and stacking score histograms using Plotly.
- Artifact verification matrix checking the presence and file sizes of the ensemble (`tree_models_and_meta_PROTO.joblib`), LSTM weights (`lstm_PROTO.pt`), feature whitelist (`feature_whitelist.json`), and verified experiment reports.

### Screen 2: CloudTrail Log Analysis (Live Inference Engine)
- **Genuine ML Pipeline Execution:** Upload AWS CloudTrail logs (JSON `Records`, JSON array, single event, or JSONL) and run real inference using the saved checkpoints.
- **Preprocessing & Windowing:** Implements genuine actor/session grouping, 5-minute temporal windowing, 27 whitelisted tabular features, and 17-dimensional bounded LSTM sequence tensors (sequence length capped at 40).
- **Four Base Learners:** Evaluates Random Forest, LightGBM, XGBoost, and PyTorch WindowLSTM.
- **Stacking Meta-Learner:** Combines base probabilities via Logistic Regression into a final stacking score.
- **Member 4 Contract v2 Integration:** Automatically generates the formal `member2_to_member4_proto_v2` envelope, validated in real time against contract rules and SHA256 source file integrity.
- **Viva Demo Loaders:** One-click loader buttons to instantly load verified viva samples without browsing local disk paths.
- **Exports:** Download predictions CSV and validated Member 4 v2 JSON.

### Screen 3: Model Evaluation & Fair Comparison
- **Public CloudTrail Benchmark (`pp1_public_cloudtrail_PROTO`):**
  - Displays the verified comparison table across 8 model configurations: Random Forest, LightGBM, XGBoost, LSTM, Stacking Ensemble, Hard Voting (3-of-4), Soft Voting, and Weighted Stacking candidate.
  - Interactive metric comparison charts (F1, Precision, Recall).
  - Scenario-wise detection recall table (`public_attack_scenario_recall_PROTO.csv`).
  - **Key Viva Defense Insight:** Highlights why the uncalibrated Stacking Ensemble scored F1 = 0.000 at the default 0.5 threshold while LightGBM scored F1 = 0.807, demonstrating the critical impact of extreme class imbalance and threshold calibration in cloud intrusion detection.
- **Mixed-Source Prototype (`pp1_mixed_PROTO`):**
  - Displays metrics for all base models and ensembles on the mixed test split.
  - Reports external Stratus positive-only recall check (9/9 approved attack windows detected, 100% recall).
  - Source bias report explaining the risk of collection-origin confounding.

### Screen 4: Stacked Ensemble Architecture Walkthrough
- Step-by-step visual pipeline: Raw logs → Temporal Normalization → 5-Min Windowing → 27 Whitelisted Features & Sequence Tensors → 4 Base Models → Probability Vector `[P(RF), P(LGBM), P(XGB), P(LSTM)]` → Logistic Regression Meta-Learner → Binary Classification → Member 4 v2 Envelope.
- Out-of-fold (OOF) training vs. inference-time execution.
- Categorized feature whitelist explorer (Event activity, security mutations, time gaps, and one-hot AWS services).

### Screen 5: Saved Detection Results
- Evidence replay of verified PP1 artifacts (`viva_final_20261020`, `pp1_inference`, `examples`).
- Clearly badged as saved/replayed data (never disguised as live activity).
- Searchable and filterable tables with JSON/CSV downloaders.

### Screen 6: Member 4 Metadata Handoff
- Full specification of the proposed `member2_to_member4_proto_v2` contract.
- Interactive schema validator checking finding IDs, UTC window timestamps, pseudonymous actor hashes, nullable resource ARNs, uncalibrated score types, and evidence locators.
- View and download canonical contract schema and example payload (`stratus_stop_member4_v2_PROTO.json`).

---

## 3. Recommended Files for the Viva Demonstration

For a crisp 4-minute viva demonstration, use the following two verified files:

1. **Known Attack File:**  
   `Data/Demo/pp1_heldout_attack_PROTO.json`  
   - **What it is:** A held-out test session containing injected synthetic AWS attack operations (including `StopLogging`).
   - **Demonstration Result:** 36 raw events grouped into 3 five-minute behavioral windows. The middle window (`2026-07-03T19:25:00Z`) correctly triggers `MALICIOUS_PATTERN` with stacking score `0.527`, while context windows remain `BENIGN_PATTERN`. Member 4 v2 contract status validates `PASS`.
2. **Known Benign File:**  
   `Data/Demo/pp1_heldout_benign_PROTO.json`  
   - **What it is:** A held-out benign operational session consisting of routine operational CloudTrail events.
   - **Demonstration Result:** Processed into 5 five-minute behavioral windows. All 5 windows score well below threshold (0 malicious windows, 5 benign windows), demonstrating false-positive suppression on standard activity.

*(Optional Third File for Cloud Defense Detonations):*  
`Data/Raw/data/raw/stratus/docs/detonation-logs/aws.defense-evasion.cloudtrail-stop.json`  
- Demonstrates execution on real Stratus Red Team detonation telemetry.

---

## 4. Dependencies

Pre-installed in the research virtual environment:
- `streamlit>=1.35.0`
- `pandas>=2.0.0`
- `plotly>=5.20.0`
- `jsonschema>=4.20.0`
- `torch>=2.1.0`
- `scikit-learn>=1.3.0`
- `lightgbm>=4.0.0`
- `xgboost>=2.0.0`
- `joblib>=1.3.0`

---

## 5. Research Limitations & Integrity Statement

- **Engineering Prototype:** Models were evaluated on controlled research datasets (Ariel Cyber Innovation Center public dataset and controlled synthetic experiments). They are not certified for unmonitored automated blocking in production accounts.
- **Binary Classification Scope:** The pipeline classifies activity windows strictly as `BENIGN_PATTERN` or `MALICIOUS_PATTERN`. Attack category names in reports are ground-truth diagnostic annotations, never model-predicted multiclass outputs.
- **Score Calibration:** Confidence scores represent raw model outputs, not calibrated Bayesian probabilities of security compromise.
- **Actor Grouping:** Session grouping relies on hashed identity ARNs or source IP proxies, which approximate user activity sessions but do not constitute authenticated login-session tracking.
