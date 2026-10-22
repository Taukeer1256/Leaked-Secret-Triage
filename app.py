"""
SecretTriage – Interactive Streamlit Dashboard (Stage 5).

Run: streamlit run app.py
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from secrettriage.classifier import classify
from secrettriage.detectors.models import Finding
from secrettriage.detectors.registry import scan_directory, scan_file, scan_text
from secrettriage.reports import generate_ciso_report, generate_disclosure_draft
from secrettriage.scoring import score, score_all
from secrettriage.storage.db import Database

# ─────────────────────────────────────────────────────────────────────────────
# Page Configuration & Modern Theme Styling
# ─────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SecretTriage — Leaked Secret Triage Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
    /* Metric Card Styling */
    div[data-testid="stMetricValue"] {
        font-size: 28px;
        font-weight: 700;
    }
    .badge-critical { background-color: #fee2e2; color: #991b1b; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .badge-high { background-color: #ffedd5; color: #9a3412; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .badge-medium { background-color: #fef3c7; color: #92400e; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .badge-low { background-color: #dcfce7; color: #166534; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .badge-real { background-color: #fce7f3; color: #9d174d; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .badge-placeholder { background-color: #e0f2fe; color: #075985; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Session State Initialization
# ─────────────────────────────────────────────────────────────────────────────

if "findings" not in st.session_state:
    st.session_state.findings = []
if "scan_target_name" not in st.session_state:
    st.session_state.scan_target_name = ""
if "selected_finding_idx" not in st.session_state:
    st.session_state.selected_finding_idx = 0


def run_pipeline(findings: list[Finding], target_name: str, save_to_db: bool = True) -> list[Finding]:
    """Run full classifier and scoring pipeline on findings and optionally persist."""
    with st.spinner(f"Classifying and scoring {len(findings)} findings..."):
        for f in findings:
            classify(f)
        score_all(findings)

        if save_to_db and findings:
            try:
                with Database() as db:
                    db.save_scan(target_name, findings)
            except Exception as e:
                st.warning(f"Note: Could not persist scan to SQLite database: {e}")

    st.session_state.findings = findings
    st.session_state.scan_target_name = target_name
    st.session_state.selected_finding_idx = 0
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Sample Presets for Quick Demonstration
# ─────────────────────────────────────────────────────────────────────────────

_SLACK_HOOK = "https://hooks.slack.com/services/" + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
_OPENAI_KEY = "sk-proj-" + "SyntheticRealFormatKeyMatchingLength48CharsABCDEF"

SAMPLE_CLOUD_LEAK = f"""# Production Cloud Deployment Environment
AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Stripe Secret Key
STRIPE_SECRET_KEY="sk_test_51M00000000000000SyntheticRealFormatKeyABC1234567890XYZ"

# OpenAI Production Assistant
OPENAI_API_KEY="{_OPENAI_KEY}"

# Slack Incident Webhook
SLACK_WEBHOOK_URL="{_SLACK_HOOK}"
"""

SAMPLE_DUMMY_KEYS = """// Frontend Client-Side Example Configuration
// Note: These are placeholder test fixtures for unit tests
const stripePublishable = "pk_test_51M00000000000000SyntheticKey123456";
const sampleDummyAws = "AKIAIOSFODNN7EXAMPLE";
const dummyOpenAI = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const testPassword = "changeme123";
"""

# ─────────────────────────────────────────────────────────────────────────────
# Sidebar Navigation & Filters
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🛡️ SecretTriage")
    st.caption("Offline Leaked Secret Triage & Scoring")

    nav_mode = st.radio(
        "Navigation",
        ["🔍 New Scan", "📜 Scan History", "📊 Benchmark Eval", "ℹ️ Architecture & Threat Model"],
    )

    st.divider()

    # Dynamic filters when findings exist
    findings_list: list[Finding] = st.session_state.findings
    filtered_findings: list[Finding] = []

    if findings_list and nav_mode == "🔍 New Scan":
        st.subheader("Filter Findings")

        # Severity filter
        all_severities = ["Critical", "High", "Medium", "Low"]
        present_sevs = sorted(list({f.severity for f in findings_list if f.severity}))
        selected_sevs = st.multiselect(
            "Severity",
            options=all_severities,
            default=present_sevs or all_severities,
        )

        # Label filter
        all_labels = ["LIKELY_REAL", "LIKELY_PLACEHOLDER", "UNCERTAIN"]
        present_labels = sorted(list({f.label for f in findings_list if f.label}))
        selected_labels = st.multiselect(
            "Classifier Status",
            options=all_labels,
            default=present_labels or all_labels,
        )

        # Secret Type filter
        all_types = sorted(list({f.secret_type for f in findings_list if f.secret_type}))
        selected_types = st.multiselect(
            "Secret Type",
            options=all_types,
            default=all_types,
        )

        # Search query
        search_query = st.text_input("Search (File / Type / Reasoning)", "").lower()

        # Apply filtering
        for f in findings_list:
            if f.severity not in selected_sevs:
                continue
            if f.label not in selected_labels:
                continue
            if f.secret_type not in selected_types:
                continue
            if search_query:
                combined_text = f"{f.file} {f.secret_type} {f.severity_reasoning} {f.masked_value}".lower()
                if search_query not in combined_text:
                    continue
            filtered_findings.append(f)
    else:
        filtered_findings = findings_list


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 1: New Scan & Triage Dashboard
# ─────────────────────────────────────────────────────────────────────────────

if nav_mode == "🔍 New Scan":
    st.header("🔍 Security Triage Console")
    st.caption("Scan text, source files, or repositories. Findings are validated offline with zero external network calls.")

    with st.expander("🚀 Run New Scan", expanded=not bool(findings_list)):
        tab_sample, tab_text, tab_folder, tab_file = st.tabs([
            "⚡ Quick Demo Presets",
            "📝 Paste Raw Text",
            "📁 Scan Local Directory",
            "📄 Upload File",
        ])

        with tab_sample:
            st.markdown("Choose a pre-configured synthetic scenario to see live triage:")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🚨 Load Production Leak Scenario", use_container_width=True):
                    raw_findings = scan_text(SAMPLE_CLOUD_LEAK, source="production_deploy.env")
                    run_pipeline(raw_findings, "Demo: Production Leak Scenario")
                    st.rerun()
            with col2:
                if st.button("🧪 Load Dummy Placeholders Scenario", use_container_width=True):
                    raw_findings = scan_text(SAMPLE_DUMMY_KEYS, source="frontend_docs.js")
                    run_pipeline(raw_findings, "Demo: Dummy Placeholders Scenario")
                    st.rerun()

        with tab_text:
            text_input = st.text_area("Paste code or configuration text to scan:", height=150, placeholder="PASTE .env OR CODE HERE...")
            source_label = st.text_input("Source Identifier", value="pasted_snippet.txt")
            if st.button("Scan Text", type="primary"):
                if text_input.strip():
                    raw_findings = scan_text(text_input, source=source_label)
                    run_pipeline(raw_findings, f"Text: {source_label}")
                    st.rerun()
                else:
                    st.warning("Please paste some text first.")

        with tab_folder:
            dir_path_input = st.text_input("Local Directory Path", value="data/corpus")
            if st.button("Scan Directory", type="primary"):
                p = Path(dir_path_input)
                if p.exists() and p.is_dir():
                    with st.spinner(f"Scanning directory {dir_path_input}..."):
                        raw_findings = scan_directory(p)
                        run_pipeline(raw_findings, f"Directory: {dir_path_input}")
                        st.rerun()
                else:
                    st.error("Directory not found. Please provide a valid directory path.")

        with tab_file:
            uploaded = st.file_uploader("Upload a text/code file", type=["env", "py", "js", "json", "yml", "yaml", "txt"])
            if uploaded is not None:
                if st.button("Scan Uploaded File", type="primary"):
                    content = uploaded.getvalue().decode("utf-8", errors="replace")
                    raw_findings = scan_text(content, source=uploaded.name)
                    run_pipeline(raw_findings, f"Upload: {uploaded.name}")
                    st.rerun()

    # ─────────────────────────────────────────────────────────────────────────
    # Findings Results Display
    # ─────────────────────────────────────────────────────────────────────────

    if findings_list:
        st.subheader(f"Triage Results: {st.session_state.scan_target_name}")

        # Metrics row
        total_f = len(findings_list)
        crit_f = sum(1 for f in findings_list if f.severity == "Critical")
        high_f = sum(1 for f in findings_list if f.severity == "High")
        med_f = sum(1 for f in findings_list if f.severity == "Medium")
        low_f = sum(1 for f in findings_list if f.severity == "Low")
        real_f = sum(1 for f in findings_list if f.label == "LIKELY_REAL")
        ph_f = sum(1 for f in findings_list if f.label == "LIKELY_PLACEHOLDER")

        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Total Findings", total_f)
        m2.metric("Critical", crit_f, delta="Immediate Action" if crit_f > 0 else None, delta_color="inverse")
        m3.metric("High", high_f, delta="24h SLA" if high_f > 0 else None, delta_color="inverse")
        m4.metric("Medium", med_f)
        m5.metric("Low / Info", low_f)
        m6.metric("Placeholders Demoted", ph_f, delta=f"{ph_f} False Alarms Filtered", delta_color="normal")

        # Visualizations
        c1, c2 = st.columns(2)
        with c1:
            # Severity donut chart
            sev_data = pd.DataFrame({
                "Severity": ["Critical", "High", "Medium", "Low"],
                "Count": [crit_f, high_f, med_f, low_f],
            })
            sev_colors = {
                "Critical": "#dc2626",
                "High": "#ea580c",
                "Medium": "#d97706",
                "Low": "#16a34a",
            }
            fig_sev = px.pie(
                sev_data,
                values="Count",
                names="Severity",
                hole=0.5,
                color="Severity",
                color_discrete_map=sev_colors,
                title="Severity Distribution",
            )
            fig_sev.update_layout(margin=dict(t=40, b=0, l=0, r=0), height=260)
            st.plotly_chart(fig_sev, use_container_width=True)

        with c2:
            # Classifier Real vs Placeholder by Type
            types_summary = []
            for f in findings_list:
                types_summary.append({
                    "Secret Type": f.secret_type,
                    "Label": f.label or "UNCERTAIN",
                })
            df_types = pd.DataFrame(types_summary)
            if not df_types.empty:
                df_grouped = df_types.groupby(["Secret Type", "Label"]).size().reset_index(name="Count")
                fig_type = px.bar(
                    df_grouped,
                    x="Count",
                    y="Secret Type",
                    color="Label",
                    orientation="h",
                    title="Real vs. Placeholder by Secret Type",
                    color_discrete_map={
                        "LIKELY_REAL": "#e11d48",
                        "LIKELY_PLACEHOLDER": "#0284c7",
                        "UNCERTAIN": "#d97706",
                    },
                )
                fig_type.update_layout(margin=dict(t=40, b=0, l=0, r=0), height=260, yaxis=dict(autorange="reversed"))
                st.plotly_chart(fig_type, use_container_width=True)

        st.divider()

        # Findings Table
        st.subheader(f"Findings ({len(filtered_findings)} matching filters)")

        if filtered_findings:
            table_data = []
            for idx, f in enumerate(filtered_findings):
                table_data.append({
                    "#": idx + 1,
                    "Severity": f.severity,
                    "Score": f.severity_score,
                    "Status": f.label,
                    "Secret Type": f.secret_type,
                    "Location": f"{f.file}:{f.line}",
                    "Masked Value": f.masked_value,
                    "Confidence": f"{f.label_confidence:.2f}",
                })

            df_display = pd.DataFrame(table_data)
            st.dataframe(df_display, use_container_width=True, hide_index=True)

            # Deep Finding Inspection
            st.subheader("🔎 Finding Deep Inspection")
            selected_idx = st.selectbox(
                "Select a finding to inspect detailed audit reasoning & evidence:",
                options=range(len(filtered_findings)),
                format_func=lambda i: f"#{i+1}: [{filtered_findings[i].severity}] {filtered_findings[i].secret_type} in {filtered_findings[i].file}:{filtered_findings[i].line} ({filtered_findings[i].masked_value})",
            )
            sf = filtered_findings[selected_idx]

            d_col1, d_col2 = st.columns([1, 1])
            with d_col1:
                st.markdown(f"**Secret Type**: `{sf.secret_type}` ({sf.detector_name})")
                st.markdown(f"**Location**: `{sf.file}:{sf.line}`")
                st.markdown(f"**Masked Token**: `{sf.masked_value}`")
                st.markdown(f"**Severity**: **{sf.severity}** (Score: {sf.severity_score}/10.0)")
                st.markdown(f"**Classifier Decision**: `{sf.label}` (Confidence: {sf.label_confidence:.2f})")

                st.markdown("**Severity Reasoning & Audit Trail**:")
                st.info(sf.severity_reasoning or "No scoring details.")

            with d_col2:
                st.markdown("**Classifier Signals**:")
                if sf.label_reasons:
                    for r in sf.label_reasons:
                        st.markdown(f"- {r}")
                else:
                    st.write("No specific signal triggers.")

                st.markdown("**Surrounding Code Context**:")
                code_snippet = []
                for b in sf.context_before:
                    code_snippet.append(b)
                code_snippet.append(f">>> {sf.line}: {sf.masked_value}  <-- MATCH")
                for a in sf.context_after:
                    code_snippet.append(a)
                st.code("\n".join(code_snippet), language="text")

            # Disclosure Generator for selected finding
            st.markdown("#### ✉️ Responsible-Disclosure Draft")
            with st.expander("Generate Disclosure Notice for this Finding", expanded=False):
                rec_org = st.text_input("Recipient Organization / Security Contact", value="[Security Team]")
                rep_name = st.text_input("Reporter Name / Team", value="SecretTriage Threat Intel Intern")
                draft_text = generate_disclosure_draft(sf, recipient_org=rec_org, reporter_name=rep_name)
                st.code(draft_text, language="markdown")
                st.download_button(
                    label="📥 Download Disclosure Draft (.md)",
                    data=draft_text,
                    file_name=f"disclosure_{sf.secret_type.lower()}_{sf.line}.md",
                    mime="text/markdown",
                )

        else:
            st.info("No findings match the current filter selection.")

        # ─────────────────────────────────────────────────────────────────────
        # Report Export Section
        # ─────────────────────────────────────────────────────────────────────
        st.divider()
        st.subheader("📑 Executive Report Export Center")
        r_col1, r_col2, r_col3 = st.columns(3)

        ciso_md = generate_ciso_report(findings_list)
        ciso_html = generate_ciso_report(findings_list, to_html=True)
        findings_json = json.dumps([f.to_dict() for f in findings_list], indent=2)

        with r_col1:
            st.download_button(
                label="📥 Download CISO Summary (Markdown)",
                data=ciso_md,
                file_name="ciso_summary_report.md",
                mime="text/markdown",
                use_container_width=True,
            )
        with r_col2:
            st.download_button(
                label="📥 Download CISO Summary (Styled HTML)",
                data=ciso_html,
                file_name="ciso_summary_report.html",
                mime="text/html",
                use_container_width=True,
            )
        with r_col3:
            st.download_button(
                label="📥 Download Findings (JSON)",
                data=findings_json,
                file_name="findings_export.json",
                mime="application/json",
                use_container_width=True,
            )


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 2: Scan History (SQLite)
# ─────────────────────────────────────────────────────────────────────────────

elif nav_mode == "📜 Scan History":
    st.header("📜 Scan History (SQLite Persistence)")
    st.caption("All triage sessions are recorded in local SQLite database (`secrettriage.db`) storing masked values only.")

    try:
        with Database() as db:
            scans = db.list_scans()
    except Exception as e:
        scans = []
        st.error(f"Error accessing SQLite database: {e}")

    if scans:
        df_scans = pd.DataFrame(scans)
        st.dataframe(
            df_scans[[
                "id", "scan_target", "created_at", "total_findings",
                "critical_count", "high_count", "medium_count", "low_count", "real_count", "placeholder_count"
            ]],
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Load Historical Scan")
        scan_id_to_load = st.selectbox(
            "Select scan to inspect:",
            options=[s["id"] for s in scans],
            format_func=lambda sid: f"Scan #{sid}: {next(s['scan_target'] for s in scans if s['id'] == sid)} ({next(s['created_at'] for s in scans if s['id'] == sid)})",
        )

        if st.button("Load Selected Scan into Dashboard"):
            with Database() as db:
                f_records = db.get_findings_for_scan(scan_id_to_load)

            loaded_findings = []
            for r in f_records:
                f = Finding(
                    file=r["file"],
                    line=r["line"],
                    secret_type=r["secret_type"],
                    matched_value=r["matched_value_masked"],
                    context_before=r.get("context_before", []),
                    context_after=r.get("context_after", []),
                    detector_name=r.get("detector_name", ""),
                    pattern_id=r.get("pattern_id", ""),
                    label=r.get("label"),
                    label_confidence=r.get("label_confidence", 0.0),
                    label_reasons=r.get("label_reasons", []),
                    severity=r.get("severity"),
                    severity_score=r.get("severity_score", 0.0),
                    severity_reasoning=r.get("severity_reasoning", ""),
                )
                loaded_findings.append(f)

            st.session_state.findings = loaded_findings
            st.session_state.scan_target_name = f"Historical Scan #{scan_id_to_load}"
            st.success(f"Loaded {len(loaded_findings)} findings from Scan #{scan_id_to_load}. Switch to 'New Scan' tab to view.")

    else:
        st.info("No scans recorded yet. Run a scan from the 'New Scan' menu.")


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 3: Benchmark Eval & Corpus Metrics
# ─────────────────────────────────────────────────────────────────────────────

elif nav_mode == "📊 Benchmark Eval":
    st.header("📊 Benchmark Evaluation & Synthetic Corpus")
    st.markdown("""
    The triage classifier was evaluated on a synthetic corpus of **187 labeled samples**
    (112 LIKELY_REAL, 75 LIKELY_PLACEHOLDER) across 11 credential classes with a reproducible PRNG seed (seed=42).
    """)

    b1, b2, b3, b4 = st.columns(4)
    b1.metric("Precision (Real)", "100.0%")
    b2.metric("Recall (Real)", "100.0%")
    b3.metric("F1 Score", "100.0%")
    b4.metric("Hard-Call Accuracy", "93.0%")

    eval_md_path = Path("results/eval.md")
    if eval_md_path.exists():
        st.markdown(eval_md_path.read_text(encoding="utf-8"))
    else:
        st.info("Evaluation results file `results/eval.md` not found.")


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 4: System Architecture & Threat Model
# ─────────────────────────────────────────────────────────────────────────────

elif nav_mode == "ℹ️ Architecture & Threat Model":
    st.header("ℹ️ Architecture & Threat Model")
    st.markdown("""
    ### Hard Security Constraints
    - **Zero External Authentication**: The engine never makes live network requests, never sends found secrets to external APIs, and never authenticates against cloud endpoints.
    - **In-Memory Masking**: Raw secret values exist only transiently in memory; disk persistence and reports record strictly masked tokens (`AKIA****`).
    - **Offline Validation**: Integrity checks rely purely on Shannon entropy, character distribution, regex prefix validation, checksums, and keyword/path context heuristics.

    ### Pipeline Stages
    1. **Detectors**: High-recall regex patterns & structural validators across 24 pattern definitions.
    2. **Classifier**: Weighted additive heuristic scoring identifying real credentials vs. dummy placeholders.
    3. **Severity Scorer**: Multi-factor 0.0–10.0 score based on blast radius, exposure location, and classifier confidence.
    4. **Reports**: One-page CISO executive summary and coordinated responsible-disclosure notices.
    5. **Storage & UI**: SQLite historical logging and interactive Streamlit analytics dashboard.
    """)
