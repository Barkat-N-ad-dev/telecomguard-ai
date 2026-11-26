"""Automated regression testing engine comparing evaluation runs, prompt versions, and vulnerabilities."""

from __future__ import annotations

import uuid
from typing import Any, Dict, List

from telecomguard.backend.database import get_db
from telecomguard.backend.models import AuditLog, EvaluationResult, EvaluationRun, RegressionRun, Vulnerability


class RegressionEngine:
    """Compares baseline and candidate evaluation runs to detect score or security regressions."""

    def compare_runs(
        self,
        baseline_run_code: str,
        candidate_run_code: str,
        min_acceptance_threshold: float = 0.75,
    ) -> Dict[str, Any]:
        with get_db() as db:
            base_run = db.query(EvaluationRun).filter(EvaluationRun.run_code == baseline_run_code).first()
            cand_run = db.query(EvaluationRun).filter(EvaluationRun.run_code == candidate_run_code).first()
            if not base_run or not cand_run:
                raise ValueError("Both baseline and candidate evaluation run codes must exist.")

            base_results = {
                r.case_code: r
                for r in db.query(EvaluationResult).filter(EvaluationResult.run_id == base_run.id).all()
            }
            cand_results = {
                r.case_code: r
                for r in db.query(EvaluationResult).filter(EvaluationResult.run_id == cand_run.id).all()
            }

            newly_failed: List[str] = []
            dimension_deltas: Dict[str, float] = {}
            for code, cand_res in cand_results.items():
                base_res = base_results.get(code)
                if base_res and base_res.passed and not cand_res.passed:
                    newly_failed.append(code)

            base_dims = base_run.dimension_averages or {}
            cand_dims = cand_run.dimension_averages or {}
            for dim in set(base_dims.keys()) | set(cand_dims.keys()):
                dimension_deltas[dim] = round(float(cand_dims.get(dim, 0.0)) - float(base_dims.get(dim, 0.0)), 4)

            score_delta = round(cand_run.avg_overall_score - base_run.avg_overall_score, 4)
            pass_rate_delta = round(cand_run.pass_rate - base_run.pass_rate, 4)

            new_vulns = (
                db.query(Vulnerability)
                .filter(
                    Vulnerability.status == "Open",
                    Vulnerability.created_at >= base_run.created_at,
                )
                .count()
            )

            regression_detected = (
                cand_run.avg_overall_score < min_acceptance_threshold
                or cand_run.pass_rate < min_acceptance_threshold
                or score_delta < -0.03
                or pass_rate_delta < -0.05
                or len(newly_failed) > 0
                or new_vulns > 0
            )

            reasons: List[str] = []
            if cand_run.avg_overall_score < min_acceptance_threshold:
                reasons.append(
                    f"Candidate avg score ({cand_run.avg_overall_score:.2f}) below threshold ({min_acceptance_threshold:.2f})."
                )
            if score_delta < -0.03:
                reasons.append(f"Score degraded by {score_delta:+.3f}.")
            if newly_failed:
                reasons.append(f"Newly failed test cases: {', '.join(newly_failed)}.")
            if new_vulns > 0:
                reasons.append(f"{new_vulns} open vulnerability finding(s) recorded since baseline.")
            summary = "REGRESSION DETECTED: " + " ".join(reasons) if regression_detected else (
                f"PASS: Candidate ({cand_run.model_name} / {cand_run.prompt_version}) meets threshold "
                f"{min_acceptance_threshold:.2f} with score delta {score_delta:+.3f}."
            )

            reg_code = f"REG-{uuid.uuid4().hex[:8].upper()}"
            reg = RegressionRun(
                regression_code=reg_code,
                baseline_run_code=base_run.run_code,
                candidate_run_code=cand_run.run_code,
                baseline_model=base_run.model_name,
                candidate_model=cand_run.model_name,
                baseline_prompt_version=base_run.prompt_version,
                candidate_prompt_version=cand_run.prompt_version,
                min_acceptance_threshold=min_acceptance_threshold,
                score_delta=score_delta,
                pass_rate_delta=pass_rate_delta,
                newly_failed_cases=newly_failed,
                newly_introduced_vulnerabilities=new_vulns,
                regression_detected=regression_detected,
                summary=summary,
            )
            db.add(reg)
            db.add(
                AuditLog(
                    actor="eval_engineer",
                    role="analyst",
                    action="regression_compare",
                    resource=f"{base_run.run_code}->{cand_run.run_code}",
                    decision="BLOCKED" if regression_detected else "ALLOWED",
                    reason=summary,
                )
            )

            return {
                "regression_code": reg_code,
                "baseline_run_code": base_run.run_code,
                "candidate_run_code": cand_run.run_code,
                "baseline_model": base_run.model_name,
                "candidate_model": cand_run.model_name,
                "baseline_prompt_version": base_run.prompt_version,
                "candidate_prompt_version": cand_run.prompt_version,
                "min_acceptance_threshold": min_acceptance_threshold,
                "baseline_score": base_run.avg_overall_score,
                "candidate_score": cand_run.avg_overall_score,
                "score_delta": score_delta,
                "pass_rate_delta": pass_rate_delta,
                "dimension_deltas": dimension_deltas,
                "newly_failed_cases": newly_failed,
                "newly_introduced_vulnerabilities": new_vulns,
                "regression_detected": regression_detected,
                "summary": summary,
            }

    def list_regressions(self) -> List[Dict[str, Any]]:
        with get_db() as db:
            rows = db.query(RegressionRun).order_by(RegressionRun.created_at.desc()).all()
            return [
                {
                    "regression_code": r.regression_code,
                    "baseline_run_code": r.baseline_run_code,
                    "candidate_run_code": r.candidate_run_code,
                    "baseline_model": r.baseline_model,
                    "candidate_model": r.candidate_model,
                    "baseline_prompt_version": r.baseline_prompt_version,
                    "candidate_prompt_version": r.candidate_prompt_version,
                    "min_acceptance_threshold": r.min_acceptance_threshold,
                    "score_delta": r.score_delta,
                    "pass_rate_delta": r.pass_rate_delta,
                    "newly_failed_cases": r.newly_failed_cases or [],
                    "newly_introduced_vulnerabilities": r.newly_introduced_vulnerabilities,
                    "regression_detected": r.regression_detected,
                    "summary": r.summary,
                    "created_at": r.created_at.isoformat(),
                }
                for r in rows
            ]


regression_engine = RegressionEngine()
