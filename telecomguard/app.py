"""TelecomGuard AI — Main Streamlit Application Entrypoint with RBAC Session Auth."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import streamlit as st

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from telecomguard.backend.database import init_db
from telecomguard.config import settings
from telecomguard.frontend import (
    agent_security,
    dashboard,
    evaluation,
    findings,
    rag,
    redteam,
    regression,
    reports,
    settings as settings_page,
    simulator,
)
from telecomguard.frontend.styles import inject_theme
from telecomguard.services.auth_service import auth_service
from telecomguard.services.gemini_service import gemini_service

st.set_page_config(
    page_title="TelecomGuard AI | Enterprise AI Security & Evaluation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db(seed=True)
inject_theme()

NAV_PAGES = {
    "Overview": (dashboard.render, "view_dashboard"),
    "AI Evaluation": (evaluation.render, "run_evaluation"),
    "RAG Evaluation": (rag.render, "run_rag"),
    "Red Team Lab": (redteam.render, "run_redteam"),
    "Telecom Simulator": (simulator.render, "run_simulator"),
    "Agent Security": (agent_security.render, "test_tools"),
    "Regression Testing": (regression.render, "run_regression"),
    "Findings": (findings.render, "manage_findings"),
    "Reports": (reports.render, "export_reports"),
    "Settings": (settings_page.render, "manage_settings"),
}


def _render_auth_gate() -> None:
    st.markdown(
        f"<div class='tg-sandbox-banner'><strong>Sandbox Isolation Active:</strong> {settings.simulation_disclaimer}</div>",
        unsafe_allow_html=True,
    )
    col_l, col_mid, col_r = st.columns([1, 1.5, 1])
    with col_mid:
        st.title("TelecomGuard AI")
        st.caption("Enterprise AI Evaluation, Security Testing & Red Teaming Platform")
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="sec_lead / eval_engineer / auditor_viewer")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign In", type="primary", use_container_width=True)
            if submitted:
                user = auth_service.authenticate_user(username, password)
                if user:
                    st.session_state["tg_user"] = user
                    st.rerun()
                else:
                    st.error("Invalid credentials. Access denied and logged to audit trail.")

        if settings.public_demo_login_enabled():
            st.markdown("---")
            st.caption("Controlled Sandbox Quick Access (Synthetic Demo Accounts)")
            c1, c2, c3 = st.columns(3)
            with c1:
                if st.button("AI Security Lead (Admin)", use_container_width=True):
                    st.session_state["tg_user"] = auth_service.get_demo_user("sec_lead")
                    st.rerun()
            with c2:
                if st.button("Eval Engineer (Analyst)", use_container_width=True):
                    st.session_state["tg_user"] = auth_service.get_demo_user("eval_engineer")
                    st.rerun()
            with c3:
                if st.button("Compliance (Viewer)", use_container_width=True):
                    st.session_state["tg_user"] = auth_service.get_demo_user("auditor_viewer")
                    st.rerun()


def main() -> None:
    if "tg_user" not in st.session_state or st.session_state["tg_user"] is None:
        _render_auth_gate()
        return

    current_user = st.session_state["tg_user"]
    user_role = current_user.get("role", "viewer")

    allowed_pages = {
        name: fn
        for name, (fn, perm) in NAV_PAGES.items()
        if auth_service.has_permission(user_role, perm)
    }

    with st.sidebar:
        st.markdown(
            """
            <div style="padding:0.4rem 0 0.8rem 0;border-bottom:1px solid #1E293B;margin-bottom:0.8rem;">
                <div style="font-size:1.18rem;font-weight:700;color:#F8FAFC;letter-spacing:-0.01em;">
                    TelecomGuard <span style="color:#22D3EE;">AI</span>
                </div>
                <div style="font-size:0.75rem;color:#94A3B8;margin-top:2px;">
                    Enterprise LLM Assurance & Red Teaming
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        selected_page = st.radio(
            "Navigation",
            list(allowed_pages.keys()),
            label_visibility="collapsed",
        )

        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        st.markdown("---")
        mode_badge = (
            "<span class='tg-badge tg-badge-green'>Gemini Live Ready</span>"
            if gemini_service.is_configured()
            else "<span class='tg-badge tg-badge-amber'>Local Synthetic Demo</span>"
        )
        st.markdown(
            f"""
            <div style="font-size:0.78rem;color:#94A3B8;line-height:1.55;">
                <div><strong>Signed In:</strong> <code>{current_user['username']}</code> ({user_role})</div>
                <div style="margin-top:4px;"><strong>AI Provider:</strong> {mode_badge}</div>
                <div style="margin-top:4px;"><strong>Active Model:</strong> <code>{settings.gemini_model}</code></div>
                <div style="margin-top:4px;"><strong>Environment:</strong> <code>{settings.environment}</code></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Sign Out", use_container_width=True):
            st.session_state.pop("tg_user", None)
            st.rerun()

    st.markdown(
        f"<div class='tg-sandbox-banner'><strong>Sandbox Isolation Active:</strong> {settings.simulation_disclaimer}</div>",
        unsafe_allow_html=True,
    )

    allowed_pages[selected_page]()


if __name__ == "__main__":
    main()
