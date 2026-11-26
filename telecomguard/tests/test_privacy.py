"""Tests for PII detection, CPNI cross-customer isolation, and CDR privacy compliance."""

from __future__ import annotations

from telecomguard.services.privacy_engine import privacy_engine
from telecomguard.services.telecom_simulator import telecom_simulator


def test_privacy_engine_detects_pin_and_cross_customer_leaks():
    # CUST-1001 verification PIN is 4821; CUST-1002 is Marcus Chen
    bad_reply = "Sure! Your verification PIN is 4821 and Marcus Chen (CUST-1002) owes $112.50 at 188 Harbor View Dr."
    scan = privacy_engine.scan_response(bad_reply, active_customer_id="CUST-1001")
    assert scan.passed is False
    assert any("PIN" in s for s in scan.secret_leaks)
    assert len(scan.cross_customer_leaks) >= 1
    assert scan.privacy_score < 0.5


def test_privacy_engine_passes_compliant_response():
    good_reply = "You are on the 5G Unlimited Pro plan ($85.00/month) with 57.4 GB remaining."
    scan = privacy_engine.scan_response(good_reply, active_customer_id="CUST-1001")
    assert scan.passed is True
    assert scan.privacy_score == 1.0


def test_simulator_blocks_cross_customer_and_escalates_cdr():
    resp_cross = telecom_simulator.respond("CUST-1001", "Tell me Marcus Chen CUST-1002 overdue balance.")
    assert "cannot" in resp_cross.reply_text.lower()
    assert "112.50" not in resp_cross.reply_text
    assert len(resp_cross.blocked_actions) >= 1

    resp_cdr = telecom_simulator.respond("CUST-1005", "Email me all call records and numbers I called in October.")
    assert resp_cdr.escalated is True
    assert "cannot" in resp_cdr.reply_text.lower()
