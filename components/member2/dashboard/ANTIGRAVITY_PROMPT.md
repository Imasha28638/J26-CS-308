# Antigravity task: Complete the Member 2 PP1 CloudShield dashboard

You are an experienced Python machine-learning engineer and Streamlit application developer. Work in my **existing Windows research repository**, not in a newly created project. The deadline is the PP1 viva. I need an **individual Member 2 dashboard** that demonstrates my existing CloudTrail attack-detection system, including an actual prediction run using saved models.

## Repository and boundary

Current project root:
`C:\Users\USER\Desktop\RP\Research Project`

Dashboard location (create/use this folder):
`Development/J26-CS-308/components/member2/dashboard/`

`dashboard/app.py` is supplied as a starting point. **Read it first and preserve working screens.** You may create additional supporting files inside `dashboard/`, such as `services/inference.py`, `services/__init__.py`, `pages/`, tests, `.streamlit/config.toml`, and `requirements.txt`. Work in this dashboard directory by default. Only touch other Member 2 files if absolutely necessary, with a clear explanation and a minimal change. Do not change anything under other members' components, `integration/dashboard`, the raw datasets, saved model weights, source evaluation results, or JSON contracts.

## Inspect before editing

Read all relevant existing code and documentation rather than guessing function names, CLI arguments, model formats, features or evaluation values. In particular, inspect:

- `Development/J26-CS-308/components/member2/docs/README_PP1_INFERENCE.md`
- `Development/J26-CS-308/components/member2/docs/README_PP1_MIXED_PROTO.md`
- `Development/J26-CS-308/components/member2/docs/README_PP1_PUBLIC_CLOUDTRAIL_PROTO.md`
- `Development/J26-CS-308/components/member2/docs/README_PP1_MEMBER4_V2_PROTO.md`
- `Development/J26-CS-308/components/member2/src/infer_pp1_cloudtrail.py`
- Relevant feature-extraction, training, validation and preprocessing scripts in `member2/src/`
- `member2/tests/test_inference.py` and related tests
- `member2/models/pp1_mixed_PROTO/{feature_whitelist.json,tree_models_and_meta_PROTO.joblib,lstm_PROTO.pt,mixed_experiment_report_PROTO.json}`
- `member2/models/pp1_public_cloudtrail_PROTO/{feature_whitelist.json,tree_models_and_meta_PROTO.joblib,lstm_PROTO.pt,public_experiment_report_PROTO.json}`
- `Development/J26-CS-308/results/member2/pp1_public_scenario_models_PROTO/public_model_metrics_verified_PROTO.csv`
- `Development/J26-CS-308/results/member2/pp1_source_bias_PROTO/source_bias_report_PROTO.json`
- `member2/contracts/member2_to_member4_proto_v2.schema.json`
- `member2/examples/stratus_stop_member4_v2_PROTO.json`
- Sample input and precomputed saved inference outputs under top-level `Data/Demo/`, `Data/Experiments/pp1_inference/` and `Data/Experiments/viva_final_20261020/` if present

**Important:** The existing root-level `src/` and top-level `Data/` may differ from the staged Member 2 version. Prefer the staged `member2/` implementation. Use top-level artifacts only when they are confirmed relevant and compatible. Report any missing paths without inventing replacements.

## What the dashboard must do

### 1. Dashboard overview
Create a polished, readable security-operations-style UI with a dark-friendly layout, sidebar, clean navigation and clear labels. Show genuine totals for the **selected, clearly identified saved result or completed current upload**, not a fictional live cloud feed. Explain which experiment variant and file supplied each metric. Add helpful graphs, but do not sacrifice inference correctness for decoration.

### 2. Upload and live detection (highest priority)
Support file upload for actual formats handled by the existing pipeline, especially AWS CloudTrail JSON with `Records`, plus supported JSON/JSONL/CSV only if the project code can really infer on them. Validate file type, event schema, timestamps and size. For new uploads, connect and execute the existing inference logic using the existing saved models. Respect the exact trained feature names and order, actor/session grouping, the original **five-minute window configuration where actually specified**, and LSTM sequence processing. Do not implement a new simplistic heuristic or train substitute models. Display the true generated output, confidence or scores only if produced by the genuine pipeline, and the count of events versus windows clearly.

The provided `app.py` looks for an optional adapter:

```python
# dashboard/services/inference.py

def run_inference(log_bytes: bytes, filename: str, model_variant: str) -> dict:
    """Call the verified Member 2 inference pipeline.

    Return {
        'predictions': pandas.DataFrame | list[dict],
        'summary': dict,
        'handoff': dict | list | None,
    }
    """
```

Implement this adapter by inspecting the real existing inference script, functions, CLI and tests. You may use a safe `subprocess.run` invocation **only after verifying the exact CLI parameters**, with `sys.executable`, argument arrays (never `shell=True`), a suitable timeout and temporary files. Otherwise import reusable inference functions. Ensure Windows paths work and outputs are not mixed across runs. Load saved checkpoints once or cache safely where possible. Give clear errors and do not fabricate a result when inference fails.

### 3. Saved inference results
Allow selecting and viewing known, pre-existing benign and malicious PP1 inference outputs. Label these explicitly as **saved/replayed inference**, not predictions generated by the current upload. Provide filterable tables and JSON/CSV exports of the actual result.

### 4. Model evaluation and fair comparison
Read metrics from the saved reports and verified comparison CSV. Display the four base learners (Random Forest, LightGBM, XGBoost and LSTM) and the Logistic Regression stacking meta-learner if those are exactly the deployed artifact's models. Show genuine precision, recall, F1-score, confusion matrix, per-scenario detection and other fields only when supported by the saved evaluation. Keep different experiment variants, train/test sources and protocols distinct. Mark unavailable metrics as unavailable. Do not use training scores as test scores or mix precomputed public-model comparison values with mixed-model results.

### 5. Stacking explanation
Include a clear visual explanation of:
CloudTrail input → preprocessing → window/sequence features → four base learners → their output scores → Logistic Regression meta-learner → binary benign/malicious result → report/metadata.
Explain the difference between **out-of-fold predictions used for meta-learner training** and **saved base-model outputs used at inference**. Verify the actual ensemble probability order and classification threshold from the code. Never assume four models improve the score unless the saved evaluation demonstrates it. Clearly distinguish binary detection from any optional attack-category labels.

### 6. Export and contract with Member 4
Reproduce the existing validated JSON handoff format using the real schema `member2_to_member4_proto_v2.schema.json` and the existing validated code or schema validator. Provide genuine model evidence and metadata, without inventing IDs, classifications or attack names. Permit downloading both predictions and handoff JSON. The dashboard itself must remain a standalone Member 2 app, not integrated with Member 4.

### 7. Credibility and safety
Preserve data provenance. Identify public captured/attack-emulation, sandbox, and generated data accurately where the source documentation establishes it. Do not claim that every log is an incident observed in a production account. Do not show fabricated dashboards, live AWS connectivity, detection rates, timestamps, model confidences, API ingestion or validated handoff status. Do not load arbitrary user-provided pickle/joblib/torch files. Only load the repository's trusted saved artifacts. Keep original models and research evidence unchanged. Avoid hard-coded machine-specific absolute paths except in setup guidance.

## Delivery procedure

1. Inspect the relevant files and show a concise integration plan with the **actual confirmed model variant, input CLI/functions, input schema, output schema and feature handling**. Then implement without waiting for further approval.
2. Keep `app.py` as the launcher and split complex inference/data-loading functions into `dashboard/services/` as useful.
3. Create/update a dashboard-specific `requirements.txt` and `README.md` with a Windows PowerShell launch command from the Research Project root. Prefer the dependencies already installed by `requirements_pp1.txt`. Do not upgrade PyTorch or other heavy ML libraries casually.
4. Start the Streamlit app locally and fix import, layout, JSON/CSV display and compatibility errors. Test with at least one known benign and one known attack example using the **existing saved checkpoints**. Compare dashboard results to direct command-line inference for the same input and selected variant.
5. Run relevant existing tests plus new dashboard tests. Report exactly what passed and what did not.
6. Finish by writing a short summary of changed files, the exact terminal command to launch the dashboard, the two files suitable for the viva demonstration and any remaining limitations.

## Acceptance criteria

- App launches locally from `member2/dashboard/app.py` without accessing the internet.
- Actual saved experimental files are displayed with correctly labelled provenance.
- New file upload invokes **real existing saved-model inference** for the supported format, without retraining or a stub, and fails honestly when unsupported.
- Real outputs contain the final stacking classification, with model-specific scores only if actually available.
- Selected model variant is never silently changed or mixed with an incompatible experiment.
- Generated Member 4 payload validates against the real v2 schema, or the dashboard clearly marks the export as unavailable.
- App handles malformed JSON, missing files and invalid inputs without crashing.
- Dashboard styling is professional and easy to explain in a four-minute viva.

**Priority order:** working real inference, verified output and metadata, grounded model performance, reliable demo, then visual polish. Do not replace the research pipeline with a fake UI.
