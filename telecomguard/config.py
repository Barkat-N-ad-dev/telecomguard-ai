"""Application configuration and secure environment/secrets management for TelecomGuard AI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from dotenv import load_dotenv

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent

# Load .env from project root if present without overwriting exported env vars
load_dotenv(PROJECT_ROOT / ".env", override=False)

DEPRECATED_MODEL_MAP: Dict[str, str] = {
    "gemini-2.5-flash": "gemini-4-hydrogen",
    "gemini-2.5-pro": "gemini-4-neon",
    "gemini-2.5-flash-lite": "gemini-3.5-flash-lite",
    "gemini-2.0-flash": "gemini-4-hydrogen",
    "gemini-2.0-flash-lite": "gemini-3.5-flash-lite",
    "gemini-1.5-flash": "gemini-4-hydrogen",
    "gemini-1.5-pro": "gemini-4-neon",
    "gemini-3.5-flash": "gemini-4-hydrogen",
    "gemini-3.7-flash": "gemini-4-hydrogen",
}

SUPPORTED_GEMINI_MODELS: List[str] = [
    "gemini-4-hydrogen",
    "gemini-4-neon",
    "gemini-4-argon",
    "gemini-4-carbon",
    "gemini-3.5-flash-lite",
]

EVALUATION_DIMENSIONS: List[str] = [
    "accuracy",
    "groundedness",
    "relevance",
    "completeness",
    "task_completion",
    "privacy",
    "safety",
    "escalation_quality",
]

REDTEAM_CATEGORIES: List[str] = [
    "Direct Prompt Injection",
    "Indirect Prompt Injection",
    "Jailbreak Attempt",
    "System Prompt Extraction",
    "PII Extraction",
    "Cross-Customer Data Access",
    "Unauthorized Tool Execution",
    "Privilege Escalation",
    "Sensitive Information Disclosure",
    "Unsafe Telecom Account Operations",
]


def get_config_value(key: str, default: str = "") -> str:
    """Read configuration from environment variables first, then Streamlit secrets if available."""
    env_val = os.getenv(key)
    if env_val is not None and env_val.strip() != "":
        return env_val.strip()
    try:
        import streamlit as st

        if key in st.secrets:
            val = str(st.secrets[key]).strip()
            if val:
                return val
    except Exception:
        pass
    return default


def normalize_database_url(raw_url: str) -> str:
    """Normalize Postgres/SQLite URIs for SQLAlchemy 2.x compatibility."""
    url = (raw_url or "").strip()
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://") :]
    return url


def resolve_model_name(raw_model: str | None) -> tuple[str, str | None]:
    """Resolve model string and return (resolved_model, deprecation_notice_if_any)."""
    candidate = (raw_model or "").strip() or "gemini-4-hydrogen"
    if candidate in DEPRECATED_MODEL_MAP:
        replacement = DEPRECATED_MODEL_MAP[candidate]
        return (
            replacement,
            f"Legacy model '{candidate}' is deprecated and automatically mapped to '{replacement}'.",
        )
    return candidate, None


@dataclass(frozen=True)
class Settings:
    """Centralized runtime settings (never exposes secrets to UI layers)."""

    app_name: str = "TelecomGuard AI"
    app_tagline: str = "Enterprise AI Evaluation, Security Testing & Red Teaming Platform"
    environment: str = field(default_factory=lambda: get_config_value("TELECOMGUARD_ENV", "local-sandbox"))
    simulation_disclaimer: str = (
        "CONTROLLED SANDBOX: All tests operate exclusively on synthetic telecom customers, "
        "fictional accounts, and isolated simulated tools. No external telecom systems are connected."
    )
    gemini_model_raw: str = field(default_factory=lambda: get_config_value("GEMINI_MODEL", "gemini-4-hydrogen"))
    gemini_embedding_model: str = field(
        default_factory=lambda: get_config_value("GEMINI_EMBEDDING_MODEL", "gemini-embedding-001")
    )
    gemini_timeout_seconds: int = field(
        default_factory=lambda: int(get_config_value("GEMINI_TIMEOUT_SECONDS", "45"))
    )
    gemini_max_retries: int = field(
        default_factory=lambda: int(get_config_value("GEMINI_MAX_RETRIES", "3"))
    )
    database_url: str = field(
        default_factory=lambda: normalize_database_url(
            get_config_value("DATABASE_URL", f"sqlite:///{(PACKAGE_DIR / 'telecomguard.db').as_posix()}")
        )
    )
    chroma_persist_dir: Path = field(
        default_factory=lambda: Path(
            get_config_value("CHROMA_PERSIST_DIR", str(PACKAGE_DIR / "chroma_db"))
        ).resolve()
    )
    backend_api_url: str = field(
        default_factory=lambda: get_config_value("BACKEND_API_URL", "http://127.0.0.1:8000")
    )
    allowed_origins_raw: str = field(
        default_factory=lambda: get_config_value(
            "ALLOWED_ORIGINS", "http://localhost:8501,http://127.0.0.1:8501"
        )
    )
    data_dir: Path = PACKAGE_DIR / "data"
    reports_dir: Path = PROJECT_ROOT / "reports"
    max_upload_bytes: int = 10 * 1024 * 1024  # 10 MB upload cap
    allowed_doc_extensions: tuple[str, ...] = (".pdf", ".txt", ".docx")
    allowed_dataset_extensions: tuple[str, ...] = (".csv", ".json")
    default_pass_threshold: float = 0.75

    @property
    def allowed_origins(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins_raw.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def gemini_model(self) -> str:
        resolved, _ = resolve_model_name(get_config_value("GEMINI_MODEL", self.gemini_model_raw))
        return resolved

    @property
    def model_deprecation_notice(self) -> str | None:
        _, notice = resolve_model_name(get_config_value("GEMINI_MODEL", self.gemini_model_raw))
        return notice

    def get_gemini_api_key(self) -> str | None:
        """Return the API key solely for backend/service SDK clients; never expose to frontend."""
        key = get_config_value("GEMINI_API_KEY", "")
        if not key or key == "your_api_key_here":
            return None
        return key

    def has_gemini_api_key(self) -> bool:
        """Check if a non-placeholder GEMINI_API_KEY is configured."""
        return self.get_gemini_api_key() is not None

    def get_api_token(self) -> str | None:
        """Optional FastAPI Bearer/X-API-Key token for production API protection."""
        tok = get_config_value("TELECOMGUARD_API_TOKEN", "")
        return tok if tok else None

    def get_admin_password(self) -> str:
        """Configured admin login password (defaults to sandbox demo password in non-prod only)."""
        return get_config_value("TELECOMGUARD_ADMIN_PASSWORD", "")

    def public_demo_login_enabled(self) -> bool:
        """Allow one-click sandbox role sign-in when explicitly enabled or not in locked prod mode."""
        flag = get_config_value("TELECOMGUARD_PUBLIC_DEMO", "true").lower()
        return flag in {"true", "1", "yes"}

    def masked_api_key_status(self) -> str:
        """Return a safe status string without revealing secret characters."""
        key = self.get_gemini_api_key()
        if not key:
            return "Not configured (Local Synthetic Demo Mode active)"
        if len(key) <= 8:
            return "Configured (masked)"
        return f"Configured (***{key[-4:]})"


settings = Settings()
