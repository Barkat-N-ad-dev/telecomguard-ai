"""Executive Dashboard (Overview) displaying real SQLite telemetry and empty states."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from telecomguard.backend.database import get_db
from telecomguard.backend.models import (
    EvaluationResult,
    EvaluationRun,
    RedTeamRun,
    RegressionRun,
    RetrievedChunk,
    Vulnerability,
)
from telecomguard.frontend.styles import (
    plotly_dark_layout,
    render_empty_state,
    render_kpi_card,
    render_page_header,
)


def render() -> None:
    render_page_header(
        "Executive AI Assurance Overview",
        "Real-time reliability, RAG groundedness, privacy compliance, and red-team posture from executed tests.",
    )

    with get_db() as db:
        eval_runs = db.query(EvaluationRun).order_by(EvaluationRun.created_at.asc()).all()
        eval_results = db.query(EvaluationResult).all()
        rt_runs = db.query(RedTeamRun).order_by(RedTeamRun.created_at.asc()).all()
        vulns = db.query(Vulnerability).all()
        regs = db.query(RegressionRun).order_by(RegressionRun.created_at.desc()).all()
        chunks = db.query(RetrievedChunk).all()

    total_eval = len(eval_runs)
    overall_pass_rate = (
        sum(r.pass_rate for r in eval_runs) / total_eval if total_eval else None
    )
    reliability_score = (
        sum(r.avg_overall_score for r in eval_runs) / total_eval if total_eval else None
    )
    total_rt = len(rt_runs)
    critical_findings = sum(1 for v in vulns if v.severity == "Critical" and v.status != "Fixed")
    high_findings = sum(1 for v in vulns if v.severity == "High" and v.status != "Fixed")

    # RAG Groundedness / Similarity
    rag_scores = [c.similarity_score for c in chunks]
    rag_avg = (sum(rag_scores) / len(rag_scores)) if rag_scores else None

    # Privacy compliance from EvaluationResults
    privacy_scores = [
        (r.dimension_scores or {}).get("privacy")
        for r in eval_results
        if (r.dimension_scores or {}).get("privacy") is not None
    ]
    privacy_avg = (sum(privacy_scores) / len(privacy_scores)) if privacy_scores else None

    # Regression trend status
    reg_delta = regs[0].score_delta if regs else None

    # Row 1 KPIs
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        render_kpi_card("Evaluation Runs", str(total_eval), "Executed batches", "#06B6D4")
    with c2:
        val = f"{overall_pass_rate:.1%}" if overall_pass_rate is not None else "—"
        accent = "#10B981" if (overall_pass_rate or 0) >= 0.75 else "#F59E0B"
        render_kpi_card("Overall Pass Rate", val, "Across all eval runs", accent if total_eval else "#334155")
    with c3:
        val = f"{reliability_score:.2f}" if reliability_score is not None else "—"
        render_kpi_card("AI Reliability Score", val, "0.00 - 1.00 scale", "#10B981" if reliability_score else "#334155")
    with c4:
        render_kpi_card("Red Team Tests", str(total_rt), "Controlled adversarial runs", "#22D3EE")
    with c5:
        render_kpi_card(
            "Critical / High Findings",
            f"{critical_findings} / {high_findings}",
            "Unresolved vulnerabilities",
            "#EF4444" if critical_findings > 0 else ("#F59E0B" if high_findings > 0 else "#10B981"),
        )

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    # Row 2 KPIs
    d1, d2, d3 = st.columns(3)
    with d1:
        render_kpi_card(
            "RAG Groundedness / Sim",
            f"{rag_avg:.2f}" if rag_avg is not None else "—",
            f"{len(chunks)} retrieved chunks audited" if chunks else "No RAG queries run yet",
            "#06B6D4",
        )
    with d2:
        render_kpi_card(
            "Privacy Compliance",
            f"{privacy_avg:.1%}" if privacy_avg is not None else "—",
            "CPNI & PII protection score" if privacy_avg is not None else "Run AI Evaluation to measure",
            "#10B981" if (privacy_avg or 0) >= 0.85 else "#F59E0B",
        )
    with d3:
        reg_text = f"{reg_delta:+.3f}" if reg_delta is not None else "—"
        reg_sub = ("REGRESSION FLAGGED" if regs[0].regression_detected else "Healthy baseline") if regs else "No comparisons yet"
        render_kpi_card(
            "Latest Regression Delta",
            reg_text,
            reg_sub,
            "#EF4444" if (regs and regs[0].regression_detected) else "#10B981",
        )

    st.divider()

    if total_eval == 0 and total_rt == 0 and len(vulns) == 0:
        render_empty_state(
            "No Evaluation or Red-Teaming Telemetry Yet",
            "TelecomGuard AI never fabricates metrics. Navigate to 'AI Evaluation' or 'Red Team Lab' in the sidebar "
            "to execute your first test suite — live metrics and charts will populate automatically.",
        )
        return

    col_left, col_right = st.columns(2)

    # Chart 1: Evaluation performance over time
    with col_left:
        st.subheader("Evaluation Performance Over Time")
        if eval_runs:
            df_runs = pd.DataFrame(
                [
                    {
                        "Run": r.run_code,
                        "Timestamp": r.created_at,
                        "Pass Rate (%)": round(r.pass_rate * 100, 1),
                        "Avg Score (%)": round(r.avg_overall_score * 100, 1),
                        "Model": r.model_name,
                    }
                    for r in eval_runs
                ]
            )
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=df_runs["Run"], y=df_runs["Pass Rate (%)"], mode="lines+markers", name="Pass Rate %", line=dict(color="#22D3EE", width=2.5)))
            fig.add_trace(go.Scatter(x=df_runs["Run"], y=df_runs["Avg Score (%)"], mode="lines+markers", name="Reliability Score %", line=dict(color="#10B981", width=2.5)))
            st.plotly_chart(plotly_dark_layout(fig), use_container_width=True)
        else:
            render_empty_state("No Evaluation Runs", "Run a batch in AI Evaluation to view score trends.")

    # Chart 2: Security findings by severity
    with col_right:
        st.subheader("Security Findings by Severity")
        if vulns:
            sev_order = ["Critical", "High", "Medium", "Low"]
            counts = {s: sum(1 for v in vulns if v.severity == s) for s in sev_order}
            df_sev = pd.DataFrame({"Severity": list(counts.keys()), "Count": list(counts.values())})
            color_map = {"Critical": "#EF4444", "High": "#F59E0B", "Medium": "#06B6D4", "Low": "#10B981"}
            fig = px.bar(df_sev, x="Severity", y="Count", color="Severity", color_discrete_map=color_map)
            fig.update_layout(showlegend=False)
            st.plotly_chart(plotly_dark_layout(fig), use_container_width=True)
        else:
            render_empty_state("Zero Open or Historical Vulnerabilities", "Red-team findings will appear here when breaches are detected.")

    col_l2, col_r2 = st.columns(2)

    # Chart 3: Performance by evaluation category
    with col_l2:
        st.subheader("Performance by Evaluation Category")
        if eval_results:
            df_res = pd.DataFrame(
                [{"Category": r.category, "Score": r.overall_score} for r in eval_results]
            )
            df_cat = df_res.groupby("Category", as_index=False)["Score"].mean()
            fig = px.bar(df_cat, x="Score", y="Category", orientation="h", color_discrete_sequence=["#22D3EE"])
            fig.update_xaxes(range=[0, 1])
            st.plotly_chart(plotly_dark_layout(fig), use_container_width=True)
        else:
            render_empty_state("No Category Breakdown", "Execute an evaluation batch to inspect category scores.")

    # Chart 4: Risk distribution & Model comparison
    with col_r2:
        st.subheader("Red Team Resistance by Attack Category")
        if rt_runs:
            df_rt = pd.DataFrame(
                [
                    {
                        "Category": r.category,
                        "Outcome": "Resisted" if r.resisted else "Breached",
                    }
                    for r in rt_runs
                ]
            )
            df_grp = df_rt.groupby(["Category", "Outcome"]).size().reset_index(name="Count")
            fig = px.bar(
                df_grp,
                x="Category",
                y="Count",
                color="Outcome",
                barmode="stack",
                color_discrete_map={"Resisted": "#10B981", "Breached": "#EF4444"},
            )
            st.plotly_chart(plotly_dark_layout(fig), use_container_width=True)
        else:
            render_empty_state("No Red Team Runs", "Launch scenarios in Red Team Lab to map risk distribution.")

    # Chart 5: Model comparison
    st.subheader("Model Comparison Across Executed Runs")
    if eval_runs:
        df_m = pd.DataFrame(
            [
                {
                    "Model": r.model_name,
                    "Pass Rate": r.pass_rate,
                    "Avg Score": r.avg_overall_score,
                }
                for r in eval_runs
            ]
        )
        df_model = df_m.groupby("Model", as_index=False)[["Pass Rate", "Avg Score"]].mean()
        fig = go.Figure(
            data=[
                go.Bar(name="Pass Rate", x=df_model["Model"], y=df_model["Pass Rate"], marker_color="#22D3EE"),
                go.Bar(name="Reliability Score", x=df_model["Model"], y=df_model["Avg Score"], marker_color="#10B981"),
            ]
        )
        fig.update_layout(barmode="group", yaxis=dict(range=[0, 1]))
        st.plotly_chart(plotly_dark_layout(fig, height=300), use_container_width=True)
