"""Authentication and Role-Based Access Control (RBAC) service for TelecomGuard AI."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any, Dict, Optional, Set

from telecomguard.backend.database import get_db
from telecomguard.backend.models import AuditLog, User
from telecomguard.config import settings

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "admin": {
        "view_dashboard",
        "run_evaluation",
        "manage_datasets",
        "run_rag",
        "run_redteam",
        "run_simulator",
        "test_tools",
        "run_regression",
        "manage_findings",
        "export_reports",
        "manage_settings",
    },
    "analyst": {
        "view_dashboard",
        "run_evaluation",
        "manage_datasets",
        "run_rag",
        "run_redteam",
        "run_simulator",
        "test_tools",
        "run_regression",
        "manage_findings",
        "export_reports",
    },
    "support_agent": {
        "view_dashboard",
        "run_simulator",
        "export_reports",
    },
    "viewer": {
        "view_dashboard",
        "export_reports",
    },
}


def hash_password(password: str, salt: str | None = None) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256."""
    use_salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), use_salt.encode("utf-8"), 120_000)
    return f"pbkdf2_sha256${use_salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str | None) -> bool:
    """Constant-time verification against stored PBKDF2 hash."""
    if not stored_hash or "$" not in stored_hash:
        return False
    parts = stored_hash.split("$")
    if len(parts) != 3 or parts[0] != "pbkdf2_sha256":
        return False
    _, salt, expected_hex = parts
    candidate = hash_password(password, salt=salt).split("$")[2]
    return hmac.compare_digest(candidate, expected_hex)


class AuthService:
    """Handles UI/API user authentication, RBAC permission checks, and auth audit logging."""

    def has_permission(self, role: str, permission: str) -> bool:
        return permission in ROLE_PERMISSIONS.get(role, set())

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        clean_user = (username or "").strip().lower()
        with get_db() as db:
            user = db.query(User).filter(User.username == clean_user, User.is_active.is_(True)).first()
            if not user:
                db.add(
                    AuditLog(
                        actor=clean_user or "unknown",
                        role="unauthenticated",
                        action="ui_login",
                        resource="session",
                        decision="BLOCKED",
                        reason="Unknown or inactive username.",
                    )
                )
                return None

            # If explicit admin password is set in env/secrets, enforce it for admin
            env_admin_pw = settings.get_admin_password()
            if user.role == "admin" and env_admin_pw:
                valid = hmac.compare_digest(password, env_admin_pw)
            else:
                valid = verify_password(password, user.password_hash)

            if not valid:
                db.add(
                    AuditLog(
                        actor=user.username,
                        role=user.role,
                        action="ui_login",
                        resource="session",
                        decision="BLOCKED",
                        reason="Invalid password.",
                    )
                )
                return None

            db.add(
                AuditLog(
                    actor=user.username,
                    role=user.role,
                    action="ui_login",
                    resource="session",
                    decision="ALLOWED",
                    reason="Authenticated successfully.",
                )
            )
            return {
                "username": user.username,
                "display_name": user.display_name,
                "role": user.role,
                "email": user.email,
            }

    def get_demo_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Return a sandbox user profile ONLY when public demo mode is enabled."""
        if not settings.public_demo_login_enabled():
            return None
        with get_db() as db:
            user = db.query(User).filter(User.username == username, User.is_active.is_(True)).first()
            if not user:
                return None
            db.add(
                AuditLog(
                    actor=user.username,
                    role=user.role,
                    action="sandbox_demo_login",
                    resource="session",
                    decision="ALLOWED",
                    reason="Signed in via controlled public sandbox demo mode.",
                )
            )
            return {
                "username": user.username,
                "display_name": user.display_name,
                "role": user.role,
                "email": user.email,
            }


auth_service = AuthService()
