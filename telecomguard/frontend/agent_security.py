"""AI Agent Tool Security & Backend Authorization Inspector UI module."""

from __future__ import annotations

import json
import pandas as pd
import streamlit as st

from telecomguard.backend.database import get_db
from telecomguard.backend.models import AuditLog
from telecomguard.frontend.styles import render_empty_state, render_page_header
from telecomguard.services.tool_security import ToolContext, tool_gateway


def render() -> None:
    render_page_header(
        "AI Agent Tool Security & RBAC Gateway",
        "Verify backend allowlists, tenant isolation, confirmation gates, PIN validation, and immutable audit logs.",
    )

    tab_test, tab_policies, tab_audit = st.tabs(["Tool Authorization Tester", "Tool Policy Matrix", "Audit Logs"])

    with tab_policies:
        st.subheader("Registered Simulated Tools & Security Controls")
        st.dataframe(pd.DataFrame(tool_gateway.list_tool_policies()), use_container_width=True, hide_index=True)

    with tab_test:
        st.subheader("Test Backend Authorization Enforcement")
        col1, col2 = st.columns(2)
        with col1:
            tool_name = st.selectbox(
                "Tool to Invoke",
                [
                    "get_customer_profile",
                    "get_billing_details",
                    "check_data_balance",
                    "submit_support_ticket",
                    "request_sim_replacement",
                    "request_refund",
                ],
            )
            actor_role = st.selectbox("Authenticated Role", ["customer", "support_agent", "supervisor", "admin", "unauthenticated"])
            auth_cid = st.selectbox("Authenticated Customer Session", ["CUST-1001", "CUST-1002", "CUST-1003", "CUST-1004", "CUST-1005", "CUST-1006"])
        with col2:
            target_cid = st.text_input("Requested target customer_id param", value="CUST-1002")
            confirmed = st.checkbox("Explicit User Confirmation Provided", value=False)
            pin = st.text_input("Verification PIN (for SIM replacement)", type="password")
            refund_amt = st.number_input("Refund Amount USD (for request_refund)", min_value=-50.0, max_value=2000.0, value=150.0)

        if st.button("Execute Through Security Gateway", type="primary"):
            params = {"customer_id": target_cid.strip()}
            if tool_name == "request_refund":
                params["amount_usd"] = refund_amt
                params["reason"] = "Security gateway authorization check"
            elif tool_name == "submit_support_ticket":
                params["category"] = "Security Test"
                params["summary"] = "Gateway test ticket"

            ctx = ToolContext(
                actor_id=f"ui_tester:{actor_role}",
                actor_role=actor_role,
                authenticated_customer_id=auth_cid,
                confirmed=confirmed,
                verification_pin=pin or None,
            )
            res = tool_gateway.execute(tool_name, params, ctx)
            if res.allowed:
                st.success(f"ALLOWED (Audit #{res.audit_id}): {res.message}")
                st.json(res.data)
            else:
                st.error(f"{res.status} (Audit #{res.audit_id}): {res.message}")

    with tab_audit:
        st.subheader("Immutable Backend Security Audit Log")
        with get_db() as db:
            logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(150).all()
        if not logs:
            render_empty_state("No Audit Events Recorded", "Run a tool test, evaluation, or red-team probe to generate audit logs.")
        else:
            df = pd.DataFrame(
                [
                    {
                        "ID": l.id,
                        "Actor": l.actor,
                        "Role": l.role,
                        "Action": l.action,
                        "Resource": l.resource,
                        "Decision": l.decision,
                        "Reason": l.reason,
                        "Timestamp": l.created_at.isoformat()[:19],
                    }
                    for l in logs
                ]
            )
            st.dataframe(df, use_container_width=True, hide_index=True)
