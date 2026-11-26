"""FastAPI REST API backend for TelecomGuard AI."""

from __future__ import annotations

import hmac
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from telecomguard.backend.database import get_db, get_schema_tables, init_db
from telecomguard.backend.models import AuditLog, Vulnerability
from telecomguard.backend.schemas import (
    EvaluationRunRequest,
    FindingUpdateRequest,
    HealthResponse,
    RedTeamRunRequest,
    SimulatorTurnRequest,
    ToolExecutionRequest,
)
from telecomguard.config import settings
from telecomguard.services.evaluation_engine import evaluation_engine
from telecomguard.services.gemini_service import gemini_service
from telecomguard.services.rag_engine import rag_engine
from telecomguard.services.redteam_engine import redteam_engine
from telecomguard.services.regression_engine import regression_engine
from telecomguard.services.report_engine import report_engine
from telecomguard.services.telecom_simulator import telecom_simulator
from telecomguard.services.tool_security import ToolContext, tool_gateway


def verify_api_token(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> None:
    """Enforce API token auth on sensitive endpoints whenever TELECOMGUARD_API_TOKEN is configured."""
    expected = settings.get_api_token()
    if not expected:
        return
    token = x_api_key
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API authentication token.")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db(seed=True)
    yield


app = FastAPI(
    title="TelecomGuard AI API",
    description="Enterprise AI Evaluation, Security Testing & Red Teaming Platform API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(Exception)
async def safe_exception_handler(_request: Request, _exc: Exception):
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    init_db(seed=True)
    return HealthResponse(
        status="ok",
        app_name=settings.app_name,
        gemini_configured=gemini_service.is_configured(),
        active_model=settings.gemini_model,
        database_tables=get_schema_tables(),
        timestamp=datetime.now(timezone.utc),
    )


@app.get("/customers")
def list_customers():
    return {"customers": telecom_simulator.list_customers_sanitized()}


@app.post("/simulator/chat", dependencies=[Depends(verify_api_token)])
def simulator_chat(req: SimulatorTurnRequest):
    resp = telecom_simulator.respond(
        customer_id=req.customer_id,
        user_message=req.message,
        actor_role=req.actor_role,
        verified_pin=req.verified_pin,
        model_name=req.model_name,
    )
    return resp.__dict__


@app.get("/evaluations/datasets")
def get_datasets():
    return {"datasets": evaluation_engine.list_datasets()}


@app.post("/evaluations/run", dependencies=[Depends(verify_api_token)])
def run_evaluation(req: EvaluationRunRequest):
    try:
        return evaluation_engine.run_evaluation(
            dataset_id=req.dataset_id,
            model_name=req.model_name,
            prompt_version=req.prompt_version,
            pass_threshold=req.pass_threshold,
            use_gemini_judge=req.use_gemini_judge,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/evaluations/runs")
def list_evaluation_runs():
    return {"runs": evaluation_engine.list_runs()}


@app.get("/redteam/scenarios")
def list_redteam_scenarios():
    return {"scenarios": redteam_engine.list_scenarios()}


@app.post("/redteam/run", dependencies=[Depends(verify_api_token)])
def run_redteam(req: RedTeamRunRequest):
    return {
        "results": redteam_engine.run_scenarios(
            scenario_ids=req.scenario_ids,
            model_name=req.model_name,
            target_mode=req.target_mode,
        )
    }


@app.post("/tools/execute", dependencies=[Depends(verify_api_token)])
def execute_tool(req: ToolExecutionRequest):
    ctx = ToolContext(
        actor_id=req.actor_id,
        actor_role=req.actor_role,
        authenticated_customer_id=req.authenticated_customer_id,
        confirmed=req.confirmed,
        verification_pin=req.verification_pin,
    )
    res = tool_gateway.execute(req.tool_name, req.params, ctx)
    return res.__dict__


@app.get("/rag/knowledge-bases")
def list_kbs():
    return {"knowledge_bases": rag_engine.list_knowledge_bases()}


@app.get("/findings")
def list_findings():
    with get_db() as db:
        rows = db.query(Vulnerability).order_by(Vulnerability.created_at.desc()).all()
        return {
            "findings": [
                {
                    "finding_code": v.finding_code,
                    "title": v.title,
                    "category": v.category,
                    "severity": v.severity,
                    "status": v.status,
                    "assigned_owner": v.assigned_owner,
                    "retest_result": v.retest_result,
                }
                for v in rows
            ]
        }


@app.patch("/findings/{finding_code}", dependencies=[Depends(verify_api_token)])
def update_finding(finding_code: str, req: FindingUpdateRequest):
    allowed = {"Open", "In Progress", "Fixed", "Retested", "Accepted Risk"}
    if req.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid status; must be one of {sorted(allowed)}")
    with get_db() as db:
        row = db.query(Vulnerability).filter(Vulnerability.finding_code == finding_code).first()
        if not row:
            raise HTTPException(status_code=404, detail="Finding not found")
        row.status = req.status
        if req.assigned_owner:
            row.assigned_owner = req.assigned_owner
        if req.retest_result is not None:
            row.retest_result = req.retest_result
        return {"updated": True, "finding_code": finding_code, "status": row.status}


@app.get("/regression/runs")
def list_regressions():
    return {"regressions": regression_engine.list_regressions()}


@app.get("/reports/snapshot")
def report_snapshot():
    return report_engine.collect_snapshot()


@app.get("/audit-logs", dependencies=[Depends(verify_api_token)])
def get_audit_logs(limit: int = 100):
    with get_db() as db:
        rows = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
        return {
            "logs": [
                {
                    "id": a.id,
                    "actor": a.actor,
                    "role": a.role,
                    "action": a.action,
                    "resource": a.resource,
                    "decision": a.decision,
                    "reason": a.reason,
                    "created_at": a.created_at.isoformat(),
                }
                for a in rows
            ]
        }
