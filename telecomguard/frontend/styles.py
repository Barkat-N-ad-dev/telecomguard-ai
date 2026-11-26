"""Enterprise cybersecurity SaaS dark-navy CSS theme and Plotly helpers."""

from __future__ import annotations

import html
import streamlit as st


ENTERPRISE_CSS = """
<style>
    /* Global Dark Navy Canvas */
    .stApp {
        background-color: #070D19;
        color: #F8FAFC;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    [data-testid="stSidebar"] {
        background-color: #0B1324;
        border-right: 1px solid #1E293B;
    }
    [data-testid="stHeader"] {
        background-color: rgba(7, 13, 25, 0.9);
        border-bottom: 1px solid #1E293B;
    }

    /* Typography */
    h1, h2, h3, h4 {
        color: #F8FAFC !important;
        letter-spacing: -0.02em;
    }
    .tg-subtitle {
        color: #94A3B8;
        font-size: 0.92rem;
        margin-top: -0.4rem;
        margin-bottom: 1.2rem;
    }

    /* Surfaces & Cards */
    .tg-card {
        background-color: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 10px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.85rem;
    }
    .tg-kpi-card {
        background-color: #0F172A;
        border: 1px solid #1E293B;
        border-top: 2px solid #06B6D4;
        border-radius: 10px;
        padding: 0.9rem 1rem;
        min-height: 104px;
    }
    .tg-kpi-label {
        color: #94A3B8;
        font-size: 0.76rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-weight: 600;
    }
    .tg-kpi-value {
        color: #F8FAFC;
        font-size: 1.7rem;
        font-weight: 700;
        margin-top: 0.25rem;
        line-height: 1.2;
    }
    .tg-kpi-sub {
        color: #64748B;
        font-size: 0.78rem;
        margin-top: 0.25rem;
    }

    /* Status Banners & Badges */
    .tg-sandbox-banner {
        background-color: #0B1A2E;
        border: 1px solid #0E7490;
        border-left: 4px solid #22D3EE;
        border-radius: 8px;
        padding: 0.65rem 1rem;
        color: #CFFAFE;
        font-size: 0.84rem;
        margin-bottom: 1rem;
    }
    .tg-empty-state {
        background-color: #0F172A;
        border: 1px dashed #334155;
        border-radius: 10px;
        padding: 1.8rem 1.4rem;
        text-align: center;
        color: #94A3B8;
        margin: 0.8rem 0;
    }
    .tg-badge {
        display: inline-block;
        padding: 0.18rem 0.55rem;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .tg-badge-green { background-color: rgba(16, 185, 129, 0.16); color: #34D399; border: 1px solid #059669; }
    .tg-badge-amber { background-color: rgba(245, 158, 11, 0.16); color: #FBBF24; border: 1px solid #D97706; }
    .tg-badge-red { background-color: rgba(239, 68, 68, 0.16); color: #F87171; border: 1px solid #DC2626; }
    .tg-badge-cyan { background-color: rgba(6, 182, 212, 0.16); color: #22D3EE; border: 1px solid #0891B2; }

    /* Buttons & Inputs */
    .stButton > button[kind="primary"] {
        background-color: #0891B2;
        color: #FFFFFF;
        border: 1px solid #22D3EE;
        font-weight: 600;
    }
    .stButton > button[kind="primary"]:hover {
        background-color: #0E7490;
    }
    div[data-testid="stMetric"] {
        background-color: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 10px;
        padding: 0.8rem 1rem;
    }
</style>
"""


def inject_theme() -> None:
    """Inject global enterprise CSS into the Streamlit page."""
    st.markdown(ENTERPRISE_CSS, unsafe_allow_html=True)


def render_page_header(title: str, subtitle: str) -> None:
    st.title(title)
    st.markdown(f"<div class='tg-subtitle'>{html.escape(subtitle)}</div>", unsafe_allow_html=True)


def render_kpi_card(label: str, value: str, sub: str = "", accent: str = "#06B6D4") -> None:
    st.markdown(
        f"""
        <div class="tg-kpi-card" style="border-top-color:{accent};">
            <div class="tg-kpi-label">{html.escape(label)}</div>
            <div class="tg-kpi-value">{html.escape(value)}</div>
            <div class="tg-kpi-sub">{html.escape(sub)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_empty_state(title: str, body: str) -> None:
    st.markdown(
        f"""
        <div class="tg-empty-state">
            <div style="font-size:1.05rem;font-weight:600;color:#E2E8F0;margin-bottom:0.35rem;">{html.escape(title)}</div>
            <div style="font-size:0.88rem;color:#94A3B8;">{html.escape(body)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def plotly_dark_layout(fig, height: int = 340):
    """Apply consistent dark-navy enterprise styling to Plotly figures."""
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0F172A",
        plot_bgcolor="#0F172A",
        font=dict(color="#E2E8F0", family="Inter, sans-serif", size=12),
        margin=dict(l=36, r=20, t=42, b=36),
        height=height,
        legend=dict(bgcolor="rgba(15,23,42,0.7)", bordercolor="#1E293B", borderwidth=1),
    )
    fig.update_xaxes(gridcolor="#1E293B", zerolinecolor="#334155")
    fig.update_yaxes(gridcolor="#1E293B", zerolinecolor="#334155")
    return fig
