"""Enterprise report generation in PDF, CSV, JSON, and Markdown formats."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from telecomguard.backend.database import get_db
from telecomguard.backend.models import (
    EvaluationRun,
    RedTeamRun,
    RegressionRun,
    RetrievedChunk,
    Vulnerability,
)
from telecomguard.services.gemini_service import gemini_service


class ReportEngine:
    """Builds consolidated TelecomGuard AI assurance reports from live SQLite records."""

    def generate_ai_executive_narrative(self, snapshot: Dict[str, Any] | None = None) -> str:
        """Generate an executive summary narrative using Gemini when configured."""
        data = snapshot or self.collect_snapshot()
        ex = data["executive_summary"]
        if not gemini_service.is_configured():
            return (
                f"Local Summary: {ex['total_evaluation_runs']} evaluation run(s) completed with "
                f"{ex['overall_pass_rate']:.1%} average pass rate and {ex['total_redteam_tests']} red-team probe(s) "
                f"({ex['redteam_resistance_rate']:.1%} resistance). Open findings: {ex['open_findings']}."
            )
        res = gemini_service.generate_text(
            prompt=(
                "Write a concise 3-4 sentence executive AI assurance summary for a telecom CISO based strictly on these metrics:\n"
                f"{json.dumps(ex, indent=2)}\n"
                f"Top findings count: {len(data['redteam_findings'])}"
            ),
            system_instruction="You are a principal AI security consultant summarizing metrics accurately without inventing data.",
            metadata={"component": "report_narrative"},
        )
        if res.success and res.text:
            return res.text
        return (
            f"Summary: {ex['total_evaluation_runs']} evaluation run(s), pass rate {ex['overall_pass_rate']:.1%}, "
            f"red-team resistance {ex['redteam_resistance_rate']:.1%}, open findings {ex['open_findings']}."
        )

    def collect_snapshot(self) -> Dict[str, Any]:
        with get_db() as db:
            eval_runs = db.query(EvaluationRun).order_by(EvaluationRun.created_at.desc()).all()
            rt_runs = db.query(RedTeamRun).order_by(RedTeamRun.created_at.desc()).all()
            vulns = db.query(Vulnerability).order_by(Vulnerability.created_at.desc()).all()
            regs = db.query(RegressionRun).order_by(RegressionRun.created_at.desc()).all()
            chunks = db.query(RetrievedChunk).order_by(RetrievedChunk.created_at.desc()).limit(50).all()

            total_eval = len(eval_runs)
            avg_pass_rate = round(sum(r.pass_rate for r in eval_runs) / total_eval, 4) if total_eval else 0.0
            avg_score = round(sum(r.avg_overall_score for r in eval_runs) / total_eval, 4) if total_eval else 0.0
            total_rt = len(rt_runs)
            rt_resisted = sum(1 for r in rt_runs if r.resisted)
            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for v in vulns:
                sev_counts[v.severity] = sev_counts.get(v.severity, 0) + 1

            avg_rag_sim = round(sum(c.similarity_score for c in chunks) / len(chunks), 4) if chunks else 0.0

            return {
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "platform": "TelecomGuard AI",
                "environment": "Controlled Synthetic Telecom Sandbox",
                "executive_summary": {
                    "total_evaluation_runs": total_eval,
                    "overall_pass_rate": avg_pass_rate,
                    "ai_reliability_score": avg_score,
                    "total_redteam_tests": total_rt,
                    "redteam_resistance_rate": round(rt_resisted / total_rt, 4) if total_rt else 0.0,
                    "open_findings": sum(1 for v in vulns if v.status == "Open"),
                    "severity_distribution": sev_counts,
                    "rag_avg_similarity": avg_rag_sim,
                },
                "evaluation_runs": [
                    {
                        "run_code": r.run_code,
                        "model_name": r.model_name,
                        "prompt_version": r.prompt_version,
                        "execution_mode": r.execution_mode,
                        "total_cases": r.total_cases,
                        "passed_cases": r.passed_cases,
                        "pass_rate": r.pass_rate,
                        "avg_overall_score": r.avg_overall_score,
                        "created_at": r.created_at.isoformat(),
                    }
                    for r in eval_runs[:20]
                ],
                "redteam_findings": [
                    {
                        "finding_code": v.finding_code,
                        "title": v.title,
                        "category": v.category,
                        "severity": v.severity,
                        "status": v.status,
                        "assigned_owner": v.assigned_owner,
                        "recommended_fix": v.recommended_fix,
                    }
                    for v in vulns[:30]
                ],
                "redteam_runs": [
                    {
                        "run_code": r.run_code,
                        "scenario_code": r.scenario_code,
                        "category": r.category,
                        "target_name": r.target_name,
                        "resisted": r.resisted,
                        "severity": r.severity,
                    }
                    for r in rt_runs[:30]
                ],
                "regressions": [
                    {
                        "regression_code": rg.regression_code,
                        "baseline": rg.baseline_run_code,
                        "candidate": rg.candidate_run_code,
                        "score_delta": rg.score_delta,
                        "regression_detected": rg.regression_detected,
                        "summary": rg.summary,
                    }
                    for rg in regs[:15]
                ],
                "testing_limitations": [
                    "All evaluations use synthetic telecom customer profiles and isolated local policy knowledge bases.",
                    "No production OSS/BSS, billing gateways, or real subscriber CPNI records are connected.",
                    "When GEMINI_API_KEY is unset, local deterministic synthetic evaluation and simulation modes are used.",
                ],
            }

    def export_json(self, snapshot: Dict[str, Any] | None = None) -> str:
        data = snapshot or self.collect_snapshot()
        return json.dumps(data, indent=2)

    def export_csv(self, snapshot: Dict[str, Any] | None = None) -> str:
        data = snapshot or self.collect_snapshot()
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Section", "Code", "Category_or_Model", "Metric_or_Severity", "Status_or_Score", "Details"])
        for er in data["evaluation_runs"]:
            writer.writerow(["EvaluationRun", er["run_code"], er["model_name"], f"pass_rate={er['pass_rate']}", er["avg_overall_score"], er["prompt_version"]])
        for rt in data["redteam_runs"]:
            writer.writerow(["RedTeamRun", rt["run_code"], rt["category"], rt["severity"], "Resisted" if rt["resisted"] else "Breached", rt["target_name"]])
        for vf in data["redteam_findings"]:
            writer.writerow(["Vulnerability", vf["finding_code"], vf["category"], vf["severity"], vf["status"], vf["recommended_fix"]])
        for rg in data["regressions"]:
            writer.writerow(["Regression", rg["regression_code"], f"{rg['baseline']}->{rg['candidate']}", f"delta={rg['score_delta']}", "REGRESSION" if rg["regression_detected"] else "PASS", rg["summary"]])
        return buf.getvalue()

    def export_markdown(self, snapshot: Dict[str, Any] | None = None) -> str:
        d = snapshot or self.collect_snapshot()
        ex = d["executive_summary"]
        lines = [
            "# TelecomGuard AI — Enterprise AI Assurance & Red Teaming Report",
            "",
            f"- **Generated (UTC):** {d['generated_at_utc']}",
            f"- **Environment:** {d['environment']}",
            "",
            "## 1. Executive Summary",
            f"- **Total Evaluation Runs:** {ex['total_evaluation_runs']}",
            f"- **Overall Evaluation Pass Rate:** {ex['overall_pass_rate']:.1%}",
            f"- **AI Reliability Score:** {ex['ai_reliability_score']:.3f}",
            f"- **Total Red Team Tests:** {ex['total_redteam_tests']}",
            f"- **Red Team Resistance Rate:** {ex['redteam_resistance_rate']:.1%}",
            f"- **Open Security Findings:** {ex['open_findings']}",
            f"- **RAG Avg Chunk Similarity:** {ex['rag_avg_similarity']:.3f}",
            "",
            "## 2. Security Risk Distribution",
        ]
        for sev, cnt in ex["severity_distribution"].items():
            lines.append(f"- **{sev}:** {cnt}")

        lines.extend(["", "## 3. Evaluation Runs"])
        if d["evaluation_runs"]:
            lines.append("| Run Code | Model | Prompt | Mode | Pass Rate | Avg Score |")
            lines.append("|---|---|---|---|---|---|")
            for er in d["evaluation_runs"]:
                lines.append(
                    f"| {er['run_code']} | {er['model_name']} | {er['prompt_version']} | {er['execution_mode']} | {er['pass_rate']:.1%} | {er['avg_overall_score']:.3f} |"
                )
        else:
            lines.append("_No evaluation runs executed yet._")

        lines.extend(["", "## 4. Red Team Findings & Remediation Recommendations"])
        if d["redteam_findings"]:
            for vf in d["redteam_findings"]:
                lines.append(
                    f"- **{vf['finding_code']}** [{vf['severity']} | {vf['status']}] {vf['title']} — Fix: {vf['recommended_fix']}"
                )
        else:
            lines.append("_No open or historical security findings logged._")

        lines.extend(["", "## 5. Regression Comparisons"])
        if d["regressions"]:
            for rg in d["regressions"]:
                lines.append(f"- **{rg['regression_code']}** ({rg['baseline']} -> {rg['candidate']}): {rg['summary']}")
        else:
            lines.append("_No regression comparisons recorded._")

        lines.extend(["", "## 6. Testing Limitations"])
        for lim in d["testing_limitations"]:
            lines.append(f"- {lim}")

        return "\n".join(lines)

    def export_pdf(self, snapshot: Dict[str, Any] | None = None) -> bytes:
        d = snapshot or self.collect_snapshot()
        ex = d["executive_summary"]
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter, title="TelecomGuard AI Assurance Report")
        styles = getSampleStyleSheet()
        elements: List[Any] = []

        elements.append(Paragraph("TelecomGuard AI — Enterprise AI Assurance Report", styles["Title"]))
        elements.append(Paragraph(f"Generated (UTC): {d['generated_at_utc']} | {d['environment']}", styles["Normal"]))
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("1. Executive Summary", styles["Heading2"]))
        summary_table = Table(
            [
                ["Metric", "Value"],
                ["Total Evaluation Runs", str(ex["total_evaluation_runs"])],
                ["Overall Pass Rate", f"{ex['overall_pass_rate']:.1%}"],
                ["AI Reliability Score", f"{ex['ai_reliability_score']:.3f}"],
                ["Total Red Team Tests", str(ex["total_redteam_tests"])],
                ["Red Team Resistance Rate", f"{ex['redteam_resistance_rate']:.1%}"],
                ["Open Findings", str(ex["open_findings"])],
                ["RAG Avg Similarity", f"{ex['rag_avg_similarity']:.3f}"],
            ],
            colWidths=[240, 220],
        )
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94A3B8")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(summary_table)
        elements.append(Spacer(1, 14))

        elements.append(Paragraph("2. Red Team Findings & Recommendations", styles["Heading2"]))
        if d["redteam_findings"]:
            for vf in d["redteam_findings"][:12]:
                elements.append(
                    Paragraph(
                        f"<b>{vf['finding_code']}</b> [{vf['severity']} | {vf['status']}] {vf['title']}<br/>"
                        f"Fix: {vf['recommended_fix']}",
                        styles["Normal"],
                    )
                )
                elements.append(Spacer(1, 6))
        else:
            elements.append(Paragraph("No security vulnerabilities recorded in current database.", styles["Normal"]))
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("3. Testing Limitations", styles["Heading2"]))
        for lim in d["testing_limitations"]:
            elements.append(Paragraph(f"• {lim}", styles["Normal"]))

        doc.build(elements)
        return buf.getvalue()


report_engine = ReportEngine()
