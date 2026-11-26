"""Tests for authentication, RBAC permissions, FastAPI security headers/token auth, and DB persistence."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi.testclient import TestClient

from telecomguard.backend.api import app
from telecomguard.backend.database import configure_database, init_db
from telecomguard.services.auth_service import auth_service, hash_password, verify_password
from telecomguard.services.evaluation_engine import evaluation_engine


def test_password_hashing_and_rbac_permissions():
    pw_hash = hash_password("StrongTestPass!2026")
    assert verify_password("StrongTestPass!2026", pw_hash) is True
    assert verify_password("WrongPass", pw_hash) is False

    assert auth_service.has_permission("admin", "manage_settings") is True
    assert auth_service.has_permission("analyst", "run_redteam") is True
    assert auth_service.has_permission("analyst", "manage_settings") is False
    assert auth_service.has_permission("viewer", "run_redteam") is False
    assert auth_service.has_permission("viewer", "view_dashboard") is True

    user = auth_service.authenticate_user("eval_engineer", "TelecomGuard!Analyst2026")
    assert user is not None
    assert user["role"] == "analyst"

    bad = auth_service.authenticate_user("eval_engineer", "wrong-password")
    assert bad is None


def test_fastapi_security_headers_and_token_guard(monkeypatch):
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"

    monkeypatch.setenv("TELECOMGUARD_API_TOKEN", "prod-secret-token-xyz")
    r_unauth = client.post("/simulator/chat", json={"customer_id": "CUST-1001", "message": "Hi"})
    assert r_unauth.status_code == 401

    r_auth = client.post(
        "/simulator/chat",
        headers={"X-API-Key": "prod-secret-token-xyz"},
        json={"customer_id": "CUST-1001", "message": "What is my plan?"},
    )
    assert r_auth.status_code == 200


def test_database_persistence_across_reinit(tmp_path: Path):
    db_file = tmp_path / "persist_check.db"
    db_uri = f"sqlite:///{db_file.as_posix()}"
    configure_database(db_uri)
    init_db(seed=True)

    ds_id = evaluation_engine.list_datasets()[0]["id"]
    summary = evaluation_engine.run_evaluation(ds_id, use_gemini_judge=False)
    assert summary["passed_cases"] == summary["total_cases"], (
        f"Expected all built-in cases to pass in local synthetic mode, got {summary['passed_cases']}/{summary['total_cases']}"
    )

    import telecomguard.backend.database as db_mod
    db_mod.engine.dispose()
    # Simulate app restart / reconnect to same SQLite file
    configure_database(db_uri)
    init_db(seed=True)
    runs = evaluation_engine.list_runs()
    assert any(r["run_code"] == summary["run_code"] for r in runs)
    db_mod.engine.dispose()
