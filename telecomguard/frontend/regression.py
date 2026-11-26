"""Automated Regression Testing UI module."""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from telecomguard.frontend.styles import plotly_dark_layout, render_empty_state, render_kpi_card, render_page_header
from telecomguard.services.evaluation_engine import evaluation_engine
from telecomguard.services.regression_engine import regression_engine


def render() -> None:
    render_page_header(
        "Regression Testing & Release Gate",
        "Compare baseline vs candidate model and prompt versions, detect score degradation, and track newly introduced vulnerabilities.",
    )

    runs = evaluation_engine.list_runs()
    if len(runs) < 2:
        render_empty_state(
            "At Least 2 Evaluation Runs Required",
            f"Currently {len(runs)} evaluation run(s) recorded. Execute two evaluation batches (e.g., different models or prompt versions) "
            "in 'AI Evaluation' to run a side-by-side regression comparison.",
        )
    else:
        run_labels = {f"{r['run_code']} | {r['model_name']} ({r['prompt_version']}) | Avg={r['avg_overall_score']:.3f}": r["run_code"] for r in runs}
        labels = list(run_labels.keys())

        c1, c2, c3 = st.columns([2, 2, 1.3])
        with c1:
            base_label = st.selectbox("Baseline Run", labels, index=min(1, len(labels) - 1))
        with c2:
            cand_label = st.selectbox("Candidate Run", labels, index=0)
        with c3:
            min_thresh = st.slider("Min Acceptance Threshold", 0.50, 0.95, 0.75, 0.05)

        if st.button("Run Regression Gate Check", type="primary", use_container_width=True):
            comp = regression_engine.compare_runs(
                baseline_run_code=run_labels[base_label],
                candidate_run_code=run_labels[cand_label],
                min_acceptance_threshold=min_thresh,
            )
            st.session_state["last_regression"] = comp

        comp = st.session_state.get("last_regression")
        if comp:
            if comp["regression_detected"]:
                st.error(comp["summary"])
            else:
                st.success(comp["summary"])

            k1, k2, k3, k4 = st.columns(4)
            with k1:
                render_kpi_card("Score Delta", f"{comp['score_delta']:+.3f}", f"{comp['baseline_score']:.3f} -> {comp['candidate_score']:.3f}", "#EF4444" if comp["score_delta"] < -0.03 else "#10B981")
            with k2:
                render_kpi_card("Pass Rate Delta", f"{comp['pass_rate_delta']:+.1%}", "Candidate vs baseline", "#22D3EE")
            with k3:
                render_kpi_card("Newly Failed Cases", str(len(comp["newly_failed_cases"])), ", ".join(comp["newly_failed_cases"]) or "None", "#EF4444" if comp["newly_failed_cases"] else "#10B981")
            with k4:
                render_kpi_card("New Open Vulns", str(comp["newly_introduced_vulnerabilities"]), "Since baseline run", "#F59E0B" if comp["newly_introduced_vulnerabilities"] else "#10B981")

            deltas = comp["dimension_deltas"]
            if deltas:
                fig = go.Figure(
                    go.Bar(
                        x=list(deltas.keys()),
                        y=list(deltas.values()),
                        marker_color=["#EF4444" if v < 0 else "#10B981" for v in deltas.values()],
                    )
                )
                fig.update_layout(title="Dimension Score Deltas (Candidate - Baseline)")
                st.plotly_chart(plotly_dark_layout(fig, height=300), use_container_width=True)

    st.subheader("Regression Comparison History")
    hist = regression_engine.list_regressions()
    if not hist:
        render_empty_state("No Regression History", "Comparisons executed above are stored in SQLite for release auditability.")
    else:
        st.dataframe(pd.DataFrame(hist), use_container_width=True, hide_index=True)
