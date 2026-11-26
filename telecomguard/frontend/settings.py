"""Platform Settings, Gemini Configuration, Database Inspection, and Telemetry UI module."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from telecomguard.backend.database import get_db, get_schema_tables
from telecomguard.backend.models import ModelConfiguration
from telecomguard.config import SUPPORTED_GEMINI_MODELS, settings
from telecomguard.frontend.styles import render_page_header
from telecomguard.services.gemini_service import gemini_service


def render() -> None:
    render_page_header(
        "Platform Settings & Gemini Integration",
        "Inspect Gemini API status (keys never exposed), manage model configurations, and audit database health.",
    )

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Google Gemini API Status")
        is_ready = gemini_service.is_configured()
        if is_ready:
            st.success(f"Gemini API Connected — Key Status: {settings.masked_api_key_status()}")
        else:
            st.warning(
                "GEMINI_API_KEY is not configured in environment / `.env`. "
                "TelecomGuard AI is running in Local Synthetic Demo Mode."
            )
            st.code(
                "# Configure in telecomguard-ai/.env or PowerShell:\n"
                "$env:GEMINI_API_KEY='your_api_key_here'\n"
                "$env:GEMINI_MODEL='gemini-4-hydrogen'",
                language="powershell",
            )
        st.markdown(f"**Active Model:** `{settings.gemini_model}`")
        if settings.model_deprecation_notice:
            st.info(settings.model_deprecation_notice)
        if st.button("Test Gemini API Connectivity", type="primary"):
            conn = gemini_service.test_connection(settings.gemini_model)
            if conn["ok"]:
                st.success(f"Connected ({conn['model']}) in {conn['latency_ms']} ms | Tokens: {conn['tokens']} | Reply: {conn['message']}")
            else:
                st.warning(f"Gemini test result ({conn['model']}): {conn['message']}")

    with c2:
        st.subheader("Environment & Security Guardrails")
        st.json(
            {
                "environment": settings.environment,
                "database_backend": "SQLite (SQLAlchemy + Alembic)",
                "tables_initialized": len(get_schema_tables()),
                "max_upload_mb": settings.max_upload_bytes // (1024 * 1024),
                "allowed_doc_types": list(settings.allowed_doc_extensions),
                "timeout_seconds": settings.gemini_timeout_seconds,
                "max_retries": settings.gemini_max_retries,
                "simulation_isolation": "Strict Local Synthetic Sandbox",
            }
        )

    st.subheader("Model Configurations")
    with get_db() as db:
        configs = db.query(ModelConfiguration).order_by(ModelConfiguration.id.asc()).all()
        cfg_rows = [
            {
                "Name": m.name,
                "Provider": m.provider,
                "Model ID": m.model_id,
                "Prompt Version": m.prompt_version,
                "Pass Threshold": m.pass_threshold,
                "Default": m.is_default,
            }
            for m in configs
        ]
    st.dataframe(pd.DataFrame(cfg_rows), use_container_width=True, hide_index=True)

    with st.expander("Register New Model / Prompt Configuration"):
        with st.form("add_model_cfg"):
            cfg_name = st.text_input("Configuration Name", placeholder="e.g., Gemini 4 Neon Strict")
            cfg_model = st.selectbox("Model ID", SUPPORTED_GEMINI_MODELS)
            cfg_pv = st.text_input("Prompt Version", value="v1.1-strict")
            cfg_th = st.slider("Default Threshold", 0.5, 0.95, 0.80, 0.05)
            if st.form_submit_button("Save Configuration"):
                if not cfg_name.strip():
                    st.error("Configuration Name is required.")
                else:
                    with get_db() as db:
                        db.add(
                            ModelConfiguration(
                                name=cfg_name.strip(),
                                provider="gemini",
                                model_id=cfg_model,
                                prompt_version=cfg_pv.strip(),
                                pass_threshold=cfg_th,
                                is_default=False,
                            )
                        )
                    st.success(f"Saved configuration '{cfg_name}'.")
                    st.rerun()

    st.subheader("Recent Gemini Service Call Telemetry")
    if gemini_service.call_history:
        st.dataframe(pd.DataFrame(gemini_service.call_history[-25:]), use_container_width=True, hide_index=True)
    else:
        st.caption("No Gemini SDK calls recorded in this session yet.")

    st.subheader("SQLite Database Tables (14 Core Tables)")
    st.code(", ".join(get_schema_tables()), language="text")
