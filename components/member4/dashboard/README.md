# TetraTrace · Member 4 (IaC layer) investigator dashboard

Input Terraform → Member 4 ML model → findings live on the page:
TF-IDF features → Linear SVM (60 AWS rules) → per-rule isotonic calibration → ACT / REVIEW / NO ALERT.

## Quick start (Windows)
Double-click `start.bat` (needs Python 3.12; first run installs packages), then open http://localhost:8050 .
To check it matches the Colab model, keep it running and double-click `verify.bat` (12 checks).

## Files
- `server.py` — FastAPI server: serves the dashboard and the `/api/scan` endpoint
- `web/index.html` — the TetraTrace investigator page (brand colours, fonts, logo)
- `m4_scanner.py` — scanner core (model loading, scoring, explanations)
- `app.py` — simpler Streamlit version (optional)
- `m4_scanner_bundle.joblib` — the trained model: NOT included. Export it from Colab Cell 45 and
  download it from Google Drive `m4_terraform/models/` into this folder.

## Run (Windows, Command Prompt)
```
cd "D:\Y4S1_Works\Reserach Works\m4_dashboard"
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install scikit-learn==<version printed by Colab Cell 45>
uvicorn server:app --port 8000
```
Open http://localhost:8000 . To open it on your phone, run `uvicorn server:app --host 0.0.0.0 --port 8000`
and visit http://<your-laptop-IP>:8000 on the same Wi-Fi.

## API
- `GET /api/meta` — model status, versions, sample cases
- `POST /api/scan` — body `{"files":[{"name":"main.tf","code":"..."}], "policy":"v1"}` → findings, pipeline stages, warnings
- `POST /api/review` — body `{"review_key":"...","human_decision":"confirmed"|"not_a_problem","reviewer":"Name","note":"...","finding":{...}}` → saved review record
- `GET /api/reviews` — `{"latest": {review_key: record}, "log": [every record], "count": n}`

## Human review
Only **REVIEW** findings (the uncertain ones) get **Real problem** / **Not a problem** buttons
and an optional note. ACT findings are already confident, so they have no review step.
Type your name in the **Reviewer** box first. Decisions are appended to `reviews.jsonl`
in this folder (one JSON record per line, never overwritten, so it is an audit trail;
the newest decision for a finding is the one shown). The same code + same rule is
recognised again on a later scan. CSV/JSON exports gain `human_decision`, `reviewer`,
`reviewed_at` and `review_note`; **Review log** downloads every decision as CSV.
The model's own `decision` is never changed by a review.

Decision support only: covers 60 AWS rules and does not replace Trivy or Checkov.
