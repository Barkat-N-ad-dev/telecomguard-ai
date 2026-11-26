"""Tests for RAG Engine (ChromaDB, IR metrics, groundedness), Report exports, and FastAPI endpoints."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from telecomguard.backend.api import app
from telecomguard.services.rag_engine import RAGEngine
from telecomguard.services.report_engine import report_engine


def test_rag_pipeline_and_ir_metrics(tmp_path: Path):
    rag = RAGEngine(persist_dir=tmp_path / "chroma_test")
    kb_id = rag.create_knowledge_base("Test RAG KB", "Isolated test KB", embedding_backend="local")
    added = rag.ingest_builtin_policies(kb_id)
    assert added == 5

    res = rag.ask_and_evaluate(
        kb_id=kb_id,
        query="What is the automated refund limit and when is Tier-2 escalation required?",
        top_k=3,
        relevant_labels=["POL-BILL-01", "$25.00", "Tier-2"],
    )
    assert len(res["chunks"]) == 3
    assert res["metrics"]["recall_at_k"] > 0.0
    assert res["metrics"]["precision_at_k"] > 0.0
    assert res["metrics"]["mrr"] > 0.0
    assert res["metrics"]["groundedness"] >= 0.5


def test_report_exports_all_formats():
    snap = report_engine.collect_snapshot()
    md = report_engine.export_markdown(snap)
    js = report_engine.export_json(snap)
    csv_out = report_engine.export_csv(snap)
    pdf_bytes = report_engine.export_pdf(snap)

    assert "TelecomGuard AI" in md
    assert json.loads(js)["platform"] == "TelecomGuard AI"
    assert "Section,Code" in csv_out
    assert pdf_bytes.startswith(b"%PDF")


def test_fastapi_backend_endpoints():
    client = TestClient(app)
    r_health = client.get("/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "ok"

    r_cust = client.get("/customers")
    assert r_cust.status_code == 200
    assert len(r_cust.json()["customers"]) == 6

    r_chat = client.post("/simulator/chat", json={"customer_id": "CUST-1001", "message": "What is my plan?"})
    assert r_chat.status_code == 200
    assert "5G Unlimited Pro" in r_chat.json()["reply_text"]

    r_tool = client.post(
        "/tools/execute",
        json={
            "tool_name": "get_billing_details",
            "actor_id": "test",
            "actor_role": "customer",
            "authenticated_customer_id": "CUST-1001",
            "params": {"customer_id": "CUST-1002"},
        },
    )
    assert r_tool.status_code == 200
    assert r_tool.json()["allowed"] is False
