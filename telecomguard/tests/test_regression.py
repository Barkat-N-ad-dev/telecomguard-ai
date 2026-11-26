"""Tests for automated regression comparison and threshold detection."""

from __future__ import annotations

from telecomguard.services.evaluation_engine import evaluation_engine
from telecomguard.services.regression_engine import regression_engine


def test_regression_comparison_workflow():
    ds_id = evaluation_engine.list_datasets()[0]["id"]
    run_base = evaluation_engine.run_evaluation(ds_id, model_name="gemini-4-hydrogen", prompt_version="v1.0", use_gemini_judge=False)
    run_cand = evaluation_engine.run_evaluation(ds_id, model_name="gemini-4-neon", prompt_version="v1.1", use_gemini_judge=False)

    comp = regression_engine.compare_runs(
        baseline_run_code=run_base["run_code"],
        candidate_run_code=run_cand["run_code"],
        min_acceptance_threshold=0.75,
    )
    assert comp["regression_code"].startswith("REG-")
    assert comp["score_delta"] == 0.0
    assert len(comp["dimension_deltas"]) == 8

    # Strict threshold above candidate avg (0.9995 < 1.0) triggers gate failure
    comp_strict = regression_engine.compare_runs(
        baseline_run_code=run_base["run_code"],
        candidate_run_code=run_cand["run_code"],
        min_acceptance_threshold=1.0,
    )
    assert comp_strict["regression_detected"] is True
    assert len(regression_engine.list_regressions()) >= 2
