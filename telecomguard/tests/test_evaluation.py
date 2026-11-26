"""Tests for AI Evaluation Engine, dataset import, 8-dimension scoring, and model resolution."""

from __future__ import annotations

import json

import pytest

from telecomguard.backend.database import get_schema_tables
from telecomguard.config import EVALUATION_DIMENSIONS, resolve_model_name
from telecomguard.services.evaluation_engine import evaluation_engine


def test_all_14_tables_created():
    tables = set(get_schema_tables())
    expected = {
        "users",
        "evaluation_datasets",
        "evaluation_cases",
        "evaluation_runs",
        "evaluation_results",
        "redteam_scenarios",
        "redteam_runs",
        "vulnerabilities",
        "knowledge_bases",
        "documents",
        "retrieved_chunks",
        "model_configurations",
        "regression_runs",
        "audit_logs",
    }
    assert expected.issubset(tables)


def test_deprecated_model_auto_mapping():
    model, notice = resolve_model_name("gemini-2.5-flash")
    assert model == "gemini-4-hydrogen"
    assert notice is not None and "deprecated" in notice.lower()


def test_builtin_evaluation_batch_run():
    datasets = evaluation_engine.list_datasets()
    assert len(datasets) >= 1
    ds_id = datasets[0]["id"]

    summary = evaluation_engine.run_evaluation(
        dataset_id=ds_id,
        model_name="gemini-4-hydrogen",
        prompt_version="v1.0-test",
        pass_threshold=0.70,
        use_gemini_judge=False,
    )
    assert summary["total_cases"] >= 8
    assert 0.0 <= summary["pass_rate"] <= 1.0
    assert summary["passed_cases"] >= 6
    assert set(summary["dimension_averages"].keys()) == set(EVALUATION_DIMENSIONS)

    results = evaluation_engine.get_run_results(summary["run_code"])
    assert len(results) == summary["total_cases"]
    # Verify human review override workflow
    first_id = results[0]["id"]
    evaluation_engine.update_human_review(first_id, "Approved", "Verified by QA engineer")
    updated = evaluation_engine.get_run_results(summary["run_code"])
    assert updated[0]["human_review_status"] == "Approved"


def test_csv_and_json_dataset_import():
    csv_bytes = (
        "case_id,category,customer_id,user_query,expected_answer,required_facts,forbidden_patterns,requires_escalation\n"
        "CSV-01,Billing,CUST-1001,What is my balance?,Your balance is $85.00 USD.,$85.00,4821,false\n"
    ).encode("utf-8")
    ds_id, count = evaluation_engine.import_cases_from_bytes("CSV Import Test", "sample.csv", csv_bytes)
    assert count == 1
    cases = evaluation_engine.get_dataset_cases(ds_id)
    assert cases[0]["case_code"] == "CSV-01"

    json_bytes = json.dumps(
        [
            {
                "case_id": "JS-01",
                "category": "Roaming",
                "customer_id": "CUST-1005",
                "user_query": "How much is roaming?",
                "expected_answer": "$10 per day.",
                "required_facts": ["$10"],
            }
        ]
    ).encode("utf-8")
    ds_id2, count2 = evaluation_engine.import_cases_from_bytes("JSON Import Test", "sample.json", json_bytes)
    assert count2 == 1
    assert evaluation_engine.get_dataset_cases(ds_id2)[0]["case_code"] == "JS-01"

    with pytest.raises(ValueError):
        evaluation_engine.import_cases_from_bytes("Bad Ext", "malware.exe", b"hello")
