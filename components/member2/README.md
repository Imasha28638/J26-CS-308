# Member 2 - AWS CloudTrail Malicious Activity Detection (PP1)

## Overview

This component develops an AWS CloudTrail behavioral detection pipeline using Random Forest, LightGBM, XGBoost and LSTM. Logistic-regression stacking combines their outputs, while hard and soft voting are evaluated as baselines.

The primary classification task is benign versus malicious activity. Attack-category classification is secondary and requires reliable class-level ground truth.

## Repository Contents

- src/: preprocessing, training, evaluation and inference scripts.
- config/: event-processing and labeling rules.
- contracts/: Member 2 to Member 4 interface schemas.
- converter/: CloudTrail conversion utilities.
- tests/: automated tests.
- docs/: methodology and experiment documentation.
- examples/: example findings and handoff records.
- Data/Demo/: a small CloudTrail test fixture.
- models/: two PP1 model checkpoints and experiment reports.
- ../../results/member2/: selected research evaluation results.

## Model Architecture

Four base learners are evaluated: Random Forest, LightGBM, XGBoost and LSTM. Logistic regression serves as the stacking meta-learner.

Included checkpoints:

1. models/pp1_mixed_PROTO
   Exploratory mixed-source model trained with generated activity and selected attack-scenario records.

2. models/pp1_public_cloudtrail_PROTO
   Model associated with the publisher-labeled Ariel CloudTrail collection.

Each checkpoint includes tree and meta-model artifacts, LSTM weights, a feature whitelist and an experiment report.

Only load serialized model files from trusted sources.

## Setup and Testing

Run commands from the components/member2 directory.

Create an environment with `py -m venv .venv`, then install dependencies using `.\.venv\Scripts\python.exe -m pip install -r requirements_pp1.txt`.

Install pytest using `.\.venv\Scripts\python.exe -m pip install pytest`.

Run the tests with `.\.venv\Scripts\python.exe -m pytest -q tests --tb=short`.

The staged PP1 component previously passed 85 automated tests on the local Windows research environment. A fresh environment should be tested separately.

## CloudTrail Inference

The inference entry point is src/infer_pp1_cloudtrail.py.

Example command, from the component directory:

`py src/infer_pp1_cloudtrail.py --input Data/Demo/example_cloudtrail_synthetic.json --models-dir models/pp1_mixed_PROTO --output outputs/mixed_inference_PROTO.json --window-minutes 5 --threshold 0.5 --on-missing-readonly error`

Create the outputs directory before running the command.

The input may contain CloudTrail Records JSON, a JSON event list, an individual event or JSONL records.

Inference produces a JSON report and a separate Member 4 handoff file. Scores are uncalibrated and must not be interpreted as verified probabilities of compromise.

## Dataset Provenance

Original datasets and downloaded third-party repositories are not included in this Git checkout.

Research sources include:

- ArielCyber CloudTrail: https://github.com/ArielCyber/cloud_log_sampling
- Splunk Attack Data
- Stratus Red Team
- Controlled generated CloudTrail activity

Data acquisition, labeling and processing must follow the documented source-specific procedures. Redistribution rights and licensing require separate review.

## Evaluation and Limitations

On the publisher-defined public CloudTrail test split, LightGBM achieved an F1-score of approximately 0.807. Group-separated training validation was substantially weaker.

The stacking ensemble did not consistently outperform the strongest base learner. The publisher split is not fully actor-disjoint, and the number of independent positive groups is small.

Mixed-source experiments may contain source-specific signals. Current results do not demonstrate reliable generalization across unseen AWS environments.

Training reproduction requires the original datasets and additional data preparation steps, which are not fully bundled in this Git checkout.

## Project Status

PP1 includes preprocessing, four-model training experiments, ensemble evaluation, inference, automated component tests and Member 4 findings handoff validation.

Further work includes independent evaluation, robustness studies and integration testing.
