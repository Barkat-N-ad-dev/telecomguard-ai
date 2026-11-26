"""Tests for AI Agent Tool Security Gateway (RBAC, tenant isolation, confirmation, PIN, Fraud Hold, audit logs)."""

from __future__ import annotations

from telecomguard.backend.database import get_db
from telecomguard.backend.models import AuditLog
from telecomguard.services.tool_security import ToolContext, tool_gateway


def test_cross_customer_tool_blocked_for_customer_role():
    ctx = ToolContext(actor_id="cust:1001", actor_role="customer", authenticated_customer_id="CUST-1001")
    res = tool_gateway.execute("get_billing_details", {"customer_id": "CUST-1002"}, ctx)
    assert res.allowed is False
    assert res.status == "BLOCKED"
    assert "Cross-customer" in res.message


def test_unauthenticated_role_blocked():
    ctx = ToolContext(actor_id="anon", actor_role="unauthenticated", authenticated_customer_id="CUST-1001")
    res = tool_gateway.execute("check_data_balance", {"customer_id": "CUST-1001"}, ctx)
    assert res.allowed is False
    assert res.status == "BLOCKED"


def test_refund_requires_confirmation_and_enforces_25_cap():
    ctx_no_conf = ToolContext(actor_id="cust:1001", actor_role="customer", authenticated_customer_id="CUST-1001", confirmed=False)
    r1 = tool_gateway.execute("request_refund", {"customer_id": "CUST-1001", "amount_usd": 15.0}, ctx_no_conf)
    assert r1.allowed is False
    assert "confirmation" in r1.message.lower()

    ctx_conf = ToolContext(actor_id="cust:1001", actor_role="customer", authenticated_customer_id="CUST-1001", confirmed=True)
    r_over = tool_gateway.execute("request_refund", {"customer_id": "CUST-1001", "amount_usd": 145.0}, ctx_conf)
    assert r_over.allowed is False
    assert "exceeds" in r_over.message.lower()

    r_ok = tool_gateway.execute("request_refund", {"customer_id": "CUST-1001", "amount_usd": 15.0}, ctx_conf)
    assert r_ok.allowed is True
    assert r_ok.data["amount_usd"] == 15.0


def test_sim_replacement_requires_pin_and_blocks_fraud_hold():
    # Wrong PIN
    ctx_bad_pin = ToolContext(
        actor_id="cust:1001",
        actor_role="customer",
        authenticated_customer_id="CUST-1001",
        confirmed=True,
        verification_pin="0000",
    )
    r_bad = tool_gateway.execute("request_sim_replacement", {"customer_id": "CUST-1001"}, ctx_bad_pin)
    assert r_bad.allowed is False

    # Valid PIN for CUST-1001 (4821)
    ctx_good_pin = ToolContext(
        actor_id="cust:1001",
        actor_role="customer",
        authenticated_customer_id="CUST-1001",
        confirmed=True,
        verification_pin="4821",
    )
    r_ok = tool_gateway.execute("request_sim_replacement", {"customer_id": "CUST-1001"}, ctx_good_pin)
    assert r_ok.allowed is True

    # Fraud Hold account CUST-1003 blocked even with valid PIN (7712)
    ctx_fraud = ToolContext(
        actor_id="cust:1003",
        actor_role="customer",
        authenticated_customer_id="CUST-1003",
        confirmed=True,
        verification_pin="7712",
    )
    r_fraud = tool_gateway.execute("request_sim_replacement", {"customer_id": "CUST-1003"}, ctx_fraud)
    assert r_fraud.allowed is False
    assert "Fraud Hold" in r_fraud.message

    with get_db() as db:
        assert db.query(AuditLog).count() >= 5
