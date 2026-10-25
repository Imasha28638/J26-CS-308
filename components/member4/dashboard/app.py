"""Member 4 dashboard: Risk-Calibrated Terraform Misconfiguration Detection.

Run:  streamlit run app.py
Needs m4_scanner_bundle.joblib in the same folder (exported from Colab, Cell 45).
"""
import os

import pandas as pd
import sklearn
import streamlit as st

from m4_scanner import TerraformScanner

BUNDLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "m4_scanner_bundle.joblib")
LONG_FILE_CHARS = 3000

EXAMPLE = '''resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "my-company-logs"
}
'''

st.set_page_config(page_title="Terraform Security Scanner", page_icon="🛡️", layout="wide")


@st.cache_resource(show_spinner="Loading model...")
def load_scanner():
    return TerraformScanner(BUNDLE)


if not os.path.exists(BUNDLE):
    st.error("m4_scanner_bundle.joblib not found. Download it from Google Drive "
             "(m4_terraform/models/) and put it next to app.py.")
    st.stop()

scanner = load_scanner()

# ---------------- sidebar ----------------
with st.sidebar:
    st.header("Settings")
    policy = st.radio(
        "Decision policy",
        options=["v1", "v2"],
        format_func=lambda p: {"v1": "Policy v1 — gold-tested (default)",
                               "v2": "Policy v2 — risk-aware (eval only)"}[p],
    )
    st.caption(scanner.policy_label(policy))
    show_all = st.checkbox("Also list NO ALERT rules", value=False)
    st.divider()
    st.markdown("**Decisions**")
    st.markdown("🔴 **ACT** — confident violation, fix it  \n"
                "🟡 **REVIEW** — uncertain, a person should check  \n"
                "⚪ **NO ALERT** — no evidence found")
    st.divider()
    v = scanner.versions
    st.caption(f"Model: `{v['model_version']}`  \nBuilt: {v['created'][:10]}  \n"
               f"scikit-learn: bundle {v['sklearn']}, installed {sklearn.__version__}")
    if v["sklearn"] != sklearn.__version__:
        st.warning(f"Install scikit-learn=={v['sklearn']} to match the trained model.")

# ---------------- main ----------------
st.title("🛡️ Terraform Security Scanner")
st.write("Predicts which of **60 AWS security rules** (tfsec/Trivy and Terrascan) a Terraform file breaks, "
         "with a calibrated probability and an **ACT / REVIEW / NO ALERT** decision.")

tab_paste, tab_upload = st.tabs(["Paste code", "Upload .tf files"])
files = {}
with tab_paste:
    if st.button("Load example"):
        st.session_state["code"] = EXAMPLE
    code = st.text_area("Terraform code", key="code", height=320,
                        placeholder='resource "aws_s3_bucket" "example" { ... }')
    if code.strip():
        files["pasted_code.tf"] = code
with tab_upload:
    uploads = st.file_uploader("One or more .tf files", type=["tf"], accept_multiple_files=True)
    for f in uploads or []:
        files[f.name] = f.read().decode("utf-8", errors="replace")

if st.button("Scan", type="primary", disabled=not files):
    with st.spinner("Scanning..."):
        st.session_state["result"] = scanner.scan(files, policy=policy, include_no_alert=show_all)
        st.session_state["files"] = files

result = st.session_state.get("result")
if result is not None:
    scanned = st.session_state["files"]
    for name, c in scanned.items():
        if "aws_" not in c:
            st.info(f"{name}: no `aws_` resources found — this model only knows AWS rules.")
        if len(c) > LONG_FILE_CHARS:
            st.warning(f"{name}: long file ({len(c):,} characters). Accuracy is lower on long files; "
                       "consider scanning modules separately.")

    if result.empty:
        st.success("No rule reached the REVIEW or ACT threshold.")
    else:
        act = int((result["decision"] == "ACT").sum())
        rev = int((result["decision"] == "REVIEW").sum())
        crit_high = int(result[result["decision"] != "NO ALERT"]["severity"].isin(["CRITICAL", "HIGH"]).sum())
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Files scanned", len(scanned))
        c2.metric("ACT", act)
        c3.metric("REVIEW", rev)
        c4.metric("CRITICAL / HIGH findings", crit_high)

        view = result[["file", "decision", "severity", "predicted_rule", "what_it_means",
                       "calibrated_probability", "threshold_low", "threshold_high"]].rename(columns={
            "predicted_rule": "rule", "what_it_means": "what it means",
            "calibrated_probability": "probability", "threshold_low": "t_low", "threshold_high": "t_high"})
        if len(scanned) == 1:
            view = view.drop(columns="file")

        def colour(row):
            bg = {"ACT": "background-color: rgba(220,38,38,0.15)",
                  "REVIEW": "background-color: rgba(234,179,8,0.18)"}.get(row["decision"], "")
            return [bg] * len(row)

        st.dataframe(view.style.apply(colour, axis=1).format({"probability": "{:.3f}",
                                                              "t_low": "{:.3f}", "t_high": "{:.3f}"},
                                                             na_rep="never"),
                     use_container_width=True, hide_index=True,
                     height=min(36 * (len(view) + 1) + 4, 640),
                     column_config={"what it means": st.column_config.TextColumn(width="large")})

        d1, d2 = st.columns(2)
        d1.download_button("Download CSV (Terraform_Security_Findings.csv)",
                           result.to_csv(index=False).encode(), "Terraform_Security_Findings.csv", "text/csv")
        d2.download_button("Download JSON", TerraformScanner.to_json(result).encode(),
                           "Terraform_Security_Findings.json", "application/json")

st.divider()
st.caption("Decision support only. Predictions come from learned code patterns, not proof: the model can be "
           "fooled by commented-out code and may miss setting values. It covers only the 60 trained rules and "
           "does not replace scanners such as Trivy or Checkov.")
