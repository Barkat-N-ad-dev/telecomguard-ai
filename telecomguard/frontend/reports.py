"""Enterprise Reporting module (PDF, CSV, JSON, Markdown)."""

from __future__ import annotations

import streamlit as st

from telecomguard.frontend.styles import render_kpi_card, render_page_header
from telecomguard.services.report_engine import report_engine


def render() -> None:
    render_page_header(
        "Enterprise Assurance Reports",
        "Generate executive-ready AI evaluation, RAG groundedness, regression, and red-teaming reports in PDF, CSV, JSON, and Markdown.",
    )

    snapshot = report_engine.collect_snapshot()
    ex = snapshot["executive_summary"]

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_kpi_card("Evaluation Runs", str(ex["total_evaluation_runs"]), f"Pass rate: {ex['overall_pass_rate']:.1%}", "#22D3EE")
    with c2:
        render_kpi_card("Red Team Tests", str(ex["total_redteam_tests"]), f"Resistance: {ex['redteam_resistance_rate']:.1%}", "#10B981")
    with c3:
        render_kpi_card("Open Findings", str(ex["open_findings"]), "Active vulnerabilities", "#F59E0B" if ex["open_findings"] else "#10B981")
    with c4:
        render_kpi_card("RAG Similarity", f"{ex['rag_avg_similarity']:.2f}", "Average chunk score", "#06B6D4")

    st.subheader("Download Report Artifacts")
    if st.button("Generate AI Executive Narrative (Gemini)"):
        narrative = report_engine.generate_ai_executive_narrative(snapshot)
        st.session_state["ai_report_narrative"] = narrative
    if st.session_state.get("ai_report_narrative"):
        st.info(st.session_state["ai_report_narrative"])

    md_text = report_engine.export_markdown(snapshot)
    json_text = report_engine.export_json(snapshot)
    csv_text = report_engine.export_csv(snapshot)
    pdf_bytes = report_engine.export_pdf(snapshot)

    d1, d2, d3, d4 = st.columns(4)
    with d1:
        st.download_button("Download PDF Report", data=pdf_bytes, file_name="telecomguard_assurance_report.pdf", mime="application/pdf", type="primary", use_container_width=True)
    with d2:
        st.download_button("Download Markdown", data=md_text, file_name="telecomguard_assurance_report.md", mime="text/markdown", use_container_width=True)
    with d3:
        st.download_button("Download JSON", data=json_text, file_name="telecomguard_assurance_report.json", mime="application/json", use_container_width=True)
    with d4:
        st.download_button("Download CSV", data=csv_text, file_name="telecomguard_assurance_report.csv", mime="text/csv", use_container_width=True)

    st.subheader("Live Report Preview (Markdown)")
    st.markdown(md_text)
