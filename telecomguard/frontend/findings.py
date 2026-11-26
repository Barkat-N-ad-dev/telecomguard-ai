"""Findings & Remediation Center UI module."""

from __future__ import annotations

import uuid
import pandas as pd
import streamlit as st

from telecomguard.backend.database import get_db
from telecomguard.backend.models import AuditLog, RedTeamScenario, Vulnerability
from telecomguard.config import REDTEAM_CATEGORIES
from telecomguard.frontend.styles import render_empty_state, render_kpi_card, render_page_header
from telecomguard.services.redteam_engine import redteam_engine

STATUS_OPTIONS = ["Open", "In Progress", "Fixed", "Retested", "Accepted Risk"]


def render() -> None:
    render_page_header(
        "Findings & Remediation Center",
        "Track security vulnerabilities discovered in Red Team Lab, assign remediation owners, update status, and verify fixes via retesting.",
    )

    with get_db() as db:
        all_vulns = db.query(Vulnerability).order_by(Vulnerability.created_at.desc()).all()
        items = [
            {
                "id": v.id,
                "finding_code": v.finding_code,
                "title": v.title,
                "description": v.description,
                "category": v.category,
                "severity": v.severity,
                "evidence": v.evidence,
                "business_impact": v.business_impact,
                "recommended_fix": v.recommended_fix,
                "status": v.status,
                "assigned_owner": v.assigned_owner,
                "retest_result": v.retest_result,
                "source_run_code": v.source_run_code,
            }
            for v in all_vulns
        ]

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        render_kpi_card("Total Findings", str(len(items)), "All tracked vulnerabilities", "#22D3EE")
    with k2:
        open_cnt = sum(1 for i in items if i["status"] in {"Open", "In Progress"})
        render_kpi_card("Open / In Progress", str(open_cnt), "Requires action", "#F59E0B" if open_cnt else "#10B981")
    with k3:
        crit_cnt = sum(1 for i in items if i["severity"] == "Critical" and i["status"] != "Fixed")
        render_kpi_card("Unresolved Critical", str(crit_cnt), "Highest priority", "#EF4444" if crit_cnt else "#10B981")
    with k4:
        fixed_cnt = sum(1 for i in items if i["status"] in {"Fixed", "Retested"})
        render_kpi_card("Fixed / Retested", str(fixed_cnt), "Verified remediations", "#10B981")

    with st.expander("Log Manual Security Finding"):
        with st.form("manual_finding_form"):
            f_title = st.text_input("Finding Title")
            c1, c2, c3 = st.columns(3)
            with c1:
                f_cat = st.selectbox("Category", REDTEAM_CATEGORIES)
            with c2:
                f_sev = st.selectbox("Severity", ["Critical", "High", "Medium", "Low"])
            with c3:
                f_owner = st.text_input("Assigned Owner", value="AI Security Team")
            f_desc = st.text_area("Description")
            f_ev = st.text_area("Evidence")
            f_imp = st.text_input("Business Impact", value="Potential CPNI exposure or unauthorized account change.")
            f_fix = st.text_input("Recommended Fix")
            if st.form_submit_button("Create Finding"):
                if not f_title.strip() or not f_desc.strip():
                    st.error("Title and Description are required.")
                else:
                    code = f"VULN-{uuid.uuid4().hex[:6].upper()}"
                    with get_db() as db:
                        db.add(
                            Vulnerability(
                                finding_code=code,
                                title=f_title.strip(),
                                description=f_desc.strip(),
                                category=f_cat,
                                severity=f_sev,
                                evidence=f_ev.strip() or "Logged manually by security engineer.",
                                business_impact=f_imp.strip(),
                                recommended_fix=f_fix.strip() or "Apply backend RBAC & prompt guardrails.",
                                status="Open",
                                assigned_owner=f_owner.strip(),
                            )
                        )
                    st.success(f"Created finding {code}.")
                    st.rerun()

    if not items:
        render_empty_state(
            "No Vulnerabilities Logged",
            "Run Red Team Lab against 'vulnerable_baseline' to observe automated vulnerability discovery, or log a manual finding above.",
        )
        return

    c_f1, c_f2 = st.columns(2)
    with c_f1:
        sev_filter = st.selectbox("Filter by Severity", ["All", "Critical", "High", "Medium", "Low"])
    with c_f2:
        st_filter = st.selectbox("Filter by Status", ["All"] + STATUS_OPTIONS)

    filtered = [
        i
        for i in items
        if (sev_filter == "All" or i["severity"] == sev_filter)
        and (st_filter == "All" or i["status"] == st_filter)
    ]

    for item in filtered:
        with st.expander(f"{item['finding_code']} | [{item['severity']}] {item['title']} — Status: {item['status']}"):
            st.markdown(f"**Category:** {item['category']} | **Owner:** {item['assigned_owner']} | **Source Run:** `{item['source_run_code'] or 'Manual'}`")
            st.markdown(f"**Description:** {item['description']}")
            st.markdown(f"**Evidence:**\n```text\n{item['evidence']}\n```")
            st.markdown(f"**Business Impact:** {item['business_impact']}")
            st.markdown(f"**Recommended Fix:** {item['recommended_fix']}")
            st.markdown(f"**Latest Retest Result:** {item['retest_result'] or 'Not retested yet'}")

            u1, u2, u3, u4 = st.columns([1.3, 1.5, 1.1, 1.1])
            with u1:
                new_status = st.selectbox("Status", STATUS_OPTIONS, index=STATUS_OPTIONS.index(item["status"]) if item["status"] in STATUS_OPTIONS else 0, key=f"f_st_{item['id']}")
            with u2:
                new_owner = st.text_input("Owner", value=item["assigned_owner"], key=f"f_own_{item['id']}")
            with u3:
                st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
                if st.button("Update Finding", key=f"f_upd_{item['id']}", use_container_width=True):
                    with get_db() as db:
                        row = db.query(Vulnerability).filter(Vulnerability.id == item["id"]).first()
                        if row:
                            row.status = new_status
                            row.assigned_owner = new_owner.strip()
                            db.add(
                                AuditLog(
                                    actor="sec_lead",
                                    role="admin",
                                    action="finding_update",
                                    resource=row.finding_code,
                                    decision="ALLOWED",
                                    reason=f"Status updated to {new_status}",
                                )
                            )
                    st.success("Finding updated.")
                    st.rerun()
            with u4:
                st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
                if st.button("Retest Hardened", key=f"f_ret_{item['id']}", type="primary", use_container_width=True):
                    with get_db() as db:
                        sc = db.query(RedTeamScenario).filter(RedTeamScenario.category == item["category"]).first()
                    if sc:
                        rt_out = redteam_engine.run_scenarios([sc.id], target_mode="hardened")
                        r0 = rt_out[0]
                        retest_msg = f"{'PASS (Resisted)' if r0['resisted'] else 'FAIL (Breached)'} via {r0['run_code']}"
                        with get_db() as db:
                            row = db.query(Vulnerability).filter(Vulnerability.id == item["id"]).first()
                            if row:
                                row.retest_result = retest_msg
                                row.status = "Retested" if r0["resisted"] else row.status
                        st.success(f"Retest completed: {retest_msg}")
                        st.rerun()
