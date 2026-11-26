"""AI Evaluation Workbench UI module."""

from __future__ import annotations

import json
import pandas as pd
import plotly.express as px
import streamlit as st

from telecomguard.config import EVALUATION_DIMENSIONS, SUPPORTED_GEMINI_MODELS, settings
from telecomguard.frontend.styles import plotly_dark_layout, render_empty_state, render_page_header
from telecomguard.services.evaluation_engine import evaluation_engine
from telecomguard.services.gemini_service import gemini_service


def render() -> None:
    render_page_header(
        "AI Evaluation Workbench",
        "Evaluate telecom AI responses across 8 dimensions combining Gemini structured judgment, deterministic assertions, and human review.",
    )

    if not gemini_service.is_configured():
        st.info(
            "GEMINI_API_KEY is not configured. Evaluation Workbench runs in Local Synthetic Demo Mode "
            "(deterministic rubric + privacy + escalation checks). Add GEMINI_API_KEY in `.env` for live Gemini LLM-as-Judge scoring."
        )

    datasets = evaluation_engine.list_datasets()
    ds_map = {f"{d['name']} ({d['case_count']} cases)": d["id"] for d in datasets}

    tab_run, tab_manage, tab_history = st.tabs(["Run Evaluation Batch", "Manage Datasets & Cases", "Run History & Human Review"])

    with tab_run:
        col1, col2, col3, col4 = st.columns([2.2, 1.4, 1.2, 1.2])
        with col1:
            selected_ds_label = st.selectbox("Evaluation Dataset", list(ds_map.keys()))
            dataset_id = ds_map[selected_ds_label]
        with col2:
            model_choice = st.selectbox("Gemini Model", SUPPORTED_GEMINI_MODELS, index=0)
        with col3:
            prompt_version = st.text_input("Prompt Version", value="v1.0-hardened")
        with col4:
            threshold = st.slider("Pass Threshold", min_value=0.50, max_value=0.95, value=float(settings.default_pass_threshold), step=0.05)

        use_gemini = st.checkbox("Use Gemini Structured Judge (when API key configured)", value=gemini_service.is_configured())

        if st.button("Execute Evaluation Batch", type="primary", use_container_width=True):
            with st.spinner("Running evaluation batch across telecom simulator and assurance checks..."):
                summary = evaluation_engine.run_evaluation(
                    dataset_id=dataset_id,
                    model_name=model_choice,
                    prompt_version=prompt_version,
                    pass_threshold=threshold,
                    use_gemini_judge=use_gemini,
                )
            st.session_state["last_eval_run_code"] = summary["run_code"]
            st.success(
                f"Completed {summary['run_code']}: {summary['passed_cases']}/{summary['total_cases']} passed "
                f"({summary['pass_rate']:.1%}) | Avg Score: {summary['avg_overall_score']:.3f} | Mode: {summary['execution_mode']}"
            )

        last_code = st.session_state.get("last_eval_run_code")
        runs = evaluation_engine.list_runs()
        if last_code or runs:
            show_code = last_code or runs[0]["run_code"]
            results = evaluation_engine.get_run_results(show_code)
            if results:
                st.subheader(f"Latest Batch Results — {show_code}")
                df = pd.DataFrame(
                    [
                        {
                            "Test ID": r["case_code"],
                            "Category": r["category"],
                            "Overall": r["overall_score"],
                            "Status": "PASS" if r["passed"] else "FAIL",
                            "Privacy": r["dimension_scores"].get("privacy", 0.0),
                            "Safety": r["dimension_scores"].get("safety", 0.0),
                            "Escalation": r["dimension_scores"].get("escalation_quality", 0.0),
                            "Review": r["human_review_status"],
                        }
                        for r in results
                    ]
                )
                st.dataframe(df, use_container_width=True, hide_index=True)

                dim_avgs = {
                    d: round(sum(r["dimension_scores"].get(d, 0.0) for r in results) / len(results), 3)
                    for d in EVALUATION_DIMENSIONS
                }
                df_dim = pd.DataFrame({"Dimension": list(dim_avgs.keys()), "Average Score": list(dim_avgs.values())})
                fig = px.bar(df_dim, x="Dimension", y="Average Score", color_discrete_sequence=["#22D3EE"])
                fig.update_yaxes(range=[0, 1])
                st.plotly_chart(plotly_dark_layout(fig, height=290), use_container_width=True)

                c_exp1, c_exp2 = st.columns(2)
                with c_exp1:
                    st.download_button(
                        "Export Results CSV",
                        data=df.to_csv(index=False),
                        file_name=f"{show_code}_results.csv",
                        mime="text/csv",
                    )
                with c_exp2:
                    st.download_button(
                        "Export Detailed JSON",
                        data=json.dumps(results, indent=2),
                        file_name=f"{show_code}_results.json",
                        mime="application/json",
                    )

    with tab_manage:
        c_up, c_add = st.columns(2)
        with c_up:
            st.subheader("Upload CSV / JSON Dataset")
            up_name = st.text_input("New Dataset Name", placeholder="e.g., Q4 Roaming Regression Set")
            uploaded = st.file_uploader("Upload .csv or .json (max 10 MB)", type=["csv", "json"])
            if st.button("Import Uploaded Dataset"):
                if not up_name.strip() or uploaded is None:
                    st.error("Provide both a dataset name and a CSV/JSON file.")
                else:
                    try:
                        _, count = evaluation_engine.import_cases_from_bytes(up_name, uploaded.name, uploaded.getvalue())
                        st.success(f"Imported {count} test cases into '{up_name}'.")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Import failed: {exc}")

        with c_add:
            st.subheader("Add Custom Test Case")
            target_ds_label = st.selectbox("Target Dataset", list(ds_map.keys()), key="add_case_ds")
            with st.form("add_eval_case_form"):
                case_code = st.text_input("Test ID", value="EVAL-CUSTOM-01")
                category = st.text_input("Category", value="Billing Inquiry")
                customer_id = st.selectbox("Synthetic Customer", ["CUST-1001", "CUST-1002", "CUST-1003", "CUST-1004", "CUST-1005", "CUST-1006"])
                user_query = st.text_area("User Query")
                expected_answer = st.text_area("Expected Answer")
                rubric = st.text_input("Scoring Rubric", value="Must be factually accurate and uphold CPNI privacy.")
                req_facts = st.text_input("Required Facts (semicolon-separated)", placeholder="$85.00;5G Unlimited Pro")
                forb_pat = st.text_input("Forbidden Patterns (semicolon-separated)", placeholder="4821;Evergreen")
                req_esc = st.checkbox("Requires Human Escalation")
                submitted = st.form_submit_button("Add Test Case")
                if submitted:
                    if not user_query.strip() or not expected_answer.strip():
                        st.error("User Query and Expected Answer are required.")
                    else:
                        evaluation_engine.add_case(
                            ds_map[target_ds_label],
                            {
                                "case_code": case_code.strip(),
                                "category": category.strip(),
                                "customer_id": customer_id,
                                "user_query": user_query.strip(),
                                "expected_answer": expected_answer.strip(),
                                "rubric": rubric.strip(),
                                "required_facts": [s.strip() for s in req_facts.split(";") if s.strip()],
                                "forbidden_patterns": [s.strip() for s in forb_pat.split(";") if s.strip()],
                                "requires_escalation": req_esc,
                            },
                        )
                        st.success(f"Added case {case_code}!")
                        st.rerun()

        st.subheader("Preview Cases in Selected Dataset")
        cases = evaluation_engine.get_dataset_cases(ds_map[selected_ds_label])
        if cases:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Test ID": c["case_code"],
                            "Category": c["category"],
                            "Customer": c["customer_id"],
                            "Query": c["user_query"][:90],
                            "Escalation Required": c["requires_escalation"],
                        }
                        for c in cases
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )

    with tab_history:
        runs = evaluation_engine.list_runs()
        if not runs:
            render_empty_state("No Evaluation History", "Execute an evaluation batch first to inspect individual results and apply human review.")
            return

        run_codes = [r["run_code"] for r in runs]
        chosen_run = st.selectbox("Select Evaluation Run", run_codes)
        results = evaluation_engine.get_run_results(chosen_run)
        for r in results:
            badge = "PASS" if r["passed"] else "FAIL"
            with st.expander(f"{r['case_code']} | {r['category']} | {badge} (Score: {r['overall_score']:.3f}) | Review: {r['human_review_status']}"):
                st.markdown(f"**User Query:** {r['user_query']}")
                st.markdown(f"**Expected Answer:** {r['expected_answer']}")
                st.markdown(f"**Actual AI Response:** {r['actual_response']}")
                st.markdown(f"**Explanation:** {r['explanation']}")
                st.markdown(f"**Evidence:** {r['evidence']}")
                st.json({"dimension_scores": r["dimension_scores"], "deterministic_checks": r["deterministic_checks"]})

                col_rv1, col_rv2, col_rv3 = st.columns([1.2, 2.5, 1.3])
                with col_rv1:
                    new_status = st.selectbox("Review Decision", ["Approved", "Overridden", "Pending"], key=f"rv_st_{r['id']}")
                with col_rv2:
                    notes = st.text_input("Reviewer Notes", value=r["human_review_notes"] or "", key=f"rv_nt_{r['id']}")
                with col_rv3:
                    override_pass = st.selectbox("Pass Override", ["Keep", "Force PASS", "Force FAIL"], key=f"rv_ov_{r['id']}")
                if st.button("Save Human Review", key=f"rv_btn_{r['id']}"):
                    ov_val = None if override_pass == "Keep" else (override_pass == "Force PASS")
                    evaluation_engine.update_human_review(r["id"], new_status, notes, ov_val)
                    st.success("Human review saved.")
                    st.rerun()
