# TelecomGuard AI

**Enterprise AI Evaluation, Security Testing & Red Teaming Platform for Telecom Customer Support & Operations**

TelecomGuard AI is a modular, production-ready AI assurance platform built with **Streamlit**, **FastAPI**, **SQLAlchemy + Alembic (SQLite / PostgreSQL)**, **ChromaDB**, **Plotly**, **ReportLab**, and the official **Google Gen AI Python SDK (`google-genai`)**.

> **Sandbox Notice:** All public demo & test workflows operate exclusively on synthetic telecom customer profiles, fictional account balances, and isolated local tools. No external telecom OSS/BSS systems or real subscriber CPNI records are connected.

---

## Screenshots

| RBAC Authentication Gate | Executive Overview Dashboard |
|---|---|
| ![Authentication Gate](screenshots/01_auth_gate.png) | ![Overview Dashboard](screenshots/02_overview_dashboard.png) |

| Executive Analytics & Trends | AI Evaluation Workbench |
|---|---|
| ![Overview Charts](screenshots/03_overview_charts.png) | ![AI Evaluation Workbench](screenshots/04_ai_evaluation_workbench.png) |

| RAG Evaluation Lab | Red Teaming Laboratory |
|---|---|
| ![RAG Evaluation Lab](screenshots/05_rag_evaluation_lab.png) | ![Red Team Lab](screenshots/06_red_team_lab.png) |

| Telecom AI Simulator | Agent Tool Security & RBAC |
|---|---|
| ![Telecom Simulator](screenshots/07_telecom_simulator.png) | ![Agent Security](screenshots/08_agent_security.png) |

| Regression Testing & Release Gate | Findings & Remediation Center |
|---|---|
| ![Regression Testing](screenshots/09_regression_testing.png) | ![Findings Center](screenshots/10_findings_center.png) |

| Enterprise Assurance Reports | Platform Settings & Live Gemini |
|---|---|
| ![Reports](screenshots/11_reports.png) | ![Settings Gemini](screenshots/12_settings_gemini.png) |

---

## Core Capabilities

1. **Executive Dashboard (`Overview`)**: Live KPIs and Plotly analytics for evaluation pass rates, reliability scores, red-team resistance, critical/high findings, RAG similarity, privacy compliance, and regression deltas. Displays empty states prior to test execution.
2. **AI Evaluation Workbench (`AI Evaluation`)**: Evaluates telecom AI outputs across 8 dimensions (`accuracy`, `groundedness`, `relevance`, `completeness`, `task_completion`, `privacy`, `safety`, `escalation_quality`) combining **Gemini structured JSON scoring**, deterministic assertions, and human-in-the-loop review overrides. Supports CSV/JSON dataset upload and export.
3. **RAG Evaluation Lab (`RAG Evaluation`)**: Validates and ingests `.pdf`, `.txt`, and `.docx` documents (10 MB max, binary/path-traversal checks), generates cited answers, detects unsupported claims and missing citations, and computes **Recall@K**, **Precision@K**, **Mean Reciprocal Rank (MRR)**, context relevance, and groundedness.
4. **Red Teaming Laboratory (`Red Team Lab`)**: Executes controlled adversarial probes across 10 OWASP LLM-inspired telecom security categories (direct/indirect prompt injection, jailbreak, prompt extraction, PII extraction, cross-customer data access, unauthorized tool execution, privilege escalation, CDR disclosure, unsafe SIM/account operations) with Gemini variant generation and automatic finding creation.
5. **Telecom AI Simulator (`Telecom Simulator`)**: Interactive synthetic telecom support assistant supporting billing, SIM replacement, data balance, roaming, Fraud Hold escalation, and CPNI tenant isolation.
6. **AI Agent Tool Security (`Agent Security`)**: Backend-enforced RBAC allowlists, tenant isolation, input validation, confirmation gates, PIN verification, Fraud Hold blocks, $25 automated refund ceiling, and immutable `audit_logs` across 6 simulated tools (`get_customer_profile`, `get_billing_details`, `check_data_balance`, `submit_support_ticket`, `request_sim_replacement`, `request_refund`).
7. **Regression Testing (`Regression Testing`)**: Compares baseline vs. candidate model and prompt versions against configurable acceptance thresholds to detect score degradation or newly introduced vulnerabilities.
8. **Findings & Remediation Center (`Findings`)**: Tracks discovered vulnerabilities (`Open`, `In Progress`, `Fixed`, `Retested`, `Accepted Risk`) with evidence, business impact, owner assignment, and one-click hardened retesting.
9. **Enterprise Reporting (`Reports`)**: Generates downloadable assurance reports in **PDF**, **Markdown**, **JSON**, and **CSV**, with optional Gemini-authored executive narratives.
10. **Platform Settings (`Settings`)**: Masked Gemini API status, live Gemini connectivity tester, model configuration registry, SQLite/PostgreSQL schema overview, and LLM telemetry.

---

## Architecture Overview

```text
telecomguard-ai/
├── streamlit_app.py                # Cloud-friendly root Streamlit entrypoint
├── render.yaml                     # Render Blueprint with persistent disk & health check
├── Dockerfile / .dockerignore      # Container deployment definition
├── alembic.ini                     # Database migration config
├── requirements.txt
├── .env.example
├── .gitignore
├── screenshots/                    # Verified application UI screenshots
├── reports/                        # Example evaluation & red-teaming reports
└── telecomguard/
    ├── app.py                      # Main Streamlit UI + RBAC authentication gate
    ├── config.py                   # Env & st.secrets configuration (zero exposed secrets)
    ├── backend/
    │   ├── api.py                  # Hardened FastAPI backend (CORS, headers, token guard)
    │   ├── database.py             # SQLAlchemy engine (SQLite WAL / PostgreSQL) + seeding
    │   ├── models.py               # 14 ORM tables
    │   ├── schemas.py              # Pydantic validation & Gemini structured output schemas
    │   └── migrations/             # Alembic revision history
    ├── services/
    │   ├── auth_service.py         # PBKDF2 password hashing & RBAC permissions
    │   ├── gemini_service.py       # Official google-genai SDK adapter + retry/telemetry
    │   ├── evaluation_engine.py    # 8-dimension hybrid LLM + deterministic evaluator
    │   ├── rag_engine.py           # Document ingestion, ChromaDB/vector search, IR metrics
    │   ├── redteam_engine.py       # Adversarial runner & automatic finding logger
    │   ├── privacy_engine.py       # Deterministic PII & cross-customer CPNI scanner
    │   ├── telecom_simulator.py    # Isolated synthetic telecom customer assistant
    │   ├── tool_security.py        # RBAC tool policy gateway & audit logger
    │   ├── regression_engine.py    # Run-to-run regression gate
    │   └── report_engine.py        # PDF, CSV, JSON, Markdown exporter
    ├── data/                       # Synthetic customers, policies, eval cases, red-team suite
    └── tests/                      # Automated pytest suite
```

---

## Installation & Local Setup (Windows / Linux / macOS)

### 1. Install Dependencies

```powershell
cd telecomguard-ai
pip install -r requirements.txt
```

### 2. Configure Environment & Gemini API

```powershell
Copy-Item .env.example .env
```

Set your Google AI Studio key in `.env`:

```env
GEMINI_API_KEY=your_actual_gemini_api_key
GEMINI_MODEL=gemini-4-hydrogen
```

> **Note on Model Versions:** `gemini-4-hydrogen` is the default model (`gemini-4-neon`, `gemini-4-argon`, `gemini-4-carbon`, and `gemini-3.5-flash-lite` are also supported). Legacy `gemini-2.5-flash` strings automatically map to `gemini-4-hydrogen`.

### 3. Initialize Database & Run Migrations

```powershell
alembic upgrade head
```

### 4. Launch Locally

```powershell
streamlit run telecomguard/app.py
```

Optional FastAPI REST server:

```powershell
uvicorn telecomguard.backend.api:app --reload --port 8000
```

### 5. Run Automated Tests

```powershell
python -m pytest telecomguard/tests -v
```

---

## Production Deployment

### Option A: Streamlit Community Cloud (Recommended for Streamlit UI)

1. Push this repository (`telecomguard-ai`) to GitHub (never commit `.env` or `.streamlit/secrets.toml`).
2. Sign in to [share.streamlit.io](https://share.streamlit.io/) and click **New app**.
3. Select repository `telecomguard-ai`, branch `main`, and main file path `streamlit_app.py` (or `telecomguard/app.py`).
4. Under **Advanced settings -> Secrets**, paste your production secrets (see `.streamlit/secrets.toml.example`):
   ```toml
   GEMINI_API_KEY = "your_actual_gemini_api_key"
   GEMINI_MODEL = "gemini-4-hydrogen"
   TELECOMGUARD_ENV = "production"
   TELECOMGUARD_PUBLIC_DEMO = "true"
   TELECOMGUARD_ADMIN_PASSWORD = "your_strong_admin_password"
   # Optional external PostgreSQL URL for multi-restart cloud persistence:
   # DATABASE_URL = "postgresql://user:password@host:5432/telecomguard"
   ```
5. Click **Deploy** and verify connectivity via **Settings -> Test Gemini API Connectivity**.

> **Persistence Note for Streamlit Cloud:** Streamlit Community Cloud containers have ephemeral local storage on rebuilds. For durable production persistence across container restarts, configure `DATABASE_URL` in Streamlit Secrets pointing to a managed PostgreSQL instance (e.g., Neon, Supabase, or Cloud SQL), or deploy on **Render** using the included `render.yaml` persistent disk.

### Option B: Render (Blueprint with Persistent Disk)

1. Connect the `telecomguard-ai` GitHub repository in the Render dashboard using **New -> Blueprint** (auto-detects `render.yaml`).
2. Supply the prompted secret environment variables (`GEMINI_API_KEY`, `TELECOMGUARD_ADMIN_PASSWORD`, `TELECOMGUARD_API_TOKEN`).
3. Render mounts `/var/data` for durable SQLite (`sqlite:////var/data/telecomguard.db`) and ChromaDB persistence and monitors `/_stcore/health`.

---

## Security Hardening Summary

- **Zero Credential Exposure**: Secrets are loaded via environment variables or `st.secrets`, never rendered in UI or logs, and error messages redact any key/token patterns.
- **UI & API Authentication**: PBKDF2-HMAC-SHA256 password verification, role-based UI permissions (`admin`, `analyst`, `support_agent`, `viewer`), and `X-API-Key` / Bearer token enforcement on sensitive FastAPI endpoints.
- **Backend Tool & Tenant Isolation**: Cross-customer queries, unconfirmed refunds/SIM swaps, Fraud Hold accounts, and refunds > \$25 are blocked deterministically in backend code and recorded in `audit_logs`.
- **Upload & HTTP Hardening**: 10 MB upload cap, extension + binary null-byte validation, filename sanitization, strict `CORSMiddleware` origin allowlist, and security response headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`).
