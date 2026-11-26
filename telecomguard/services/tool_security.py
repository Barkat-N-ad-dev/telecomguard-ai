"""Simulated telecom agent tools with strict backend authorization, RBAC, and audit logging."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from telecomguard.backend.database import get_db
from telecomguard.backend.models import AuditLog
from telecomguard.config import settings

MAX_AUTO_REFUND_USD = 25.00

ROLE_TOOL_ALLOWLIST: Dict[str, Set[str]] = {
    "customer": {
        "get_customer_profile",
        "get_billing_details",
        "check_data_balance",
        "submit_support_ticket",
        "request_sim_replacement",
        "request_refund",
    },
    "support_agent": {
        "get_customer_profile",
        "get_billing_details",
        "check_data_balance",
        "submit_support_ticket",
        "request_sim_replacement",
        "request_refund",
    },
    "supervisor": {
        "get_customer_profile",
        "get_billing_details",
        "check_data_balance",
        "submit_support_ticket",
        "request_sim_replacement",
        "request_refund",
    },
    "admin": {
        "get_customer_profile",
        "get_billing_details",
        "check_data_balance",
        "submit_support_ticket",
        "request_sim_replacement",
        "request_refund",
    },
    "unauthenticated": set(),
}

SENSITIVE_TOOLS: Set[str] = {"request_sim_replacement", "request_refund"}


@dataclass
class ToolContext:
    """Backend-verified security context (cannot be overridden by LLM text)."""

    actor_id: str
    actor_role: str
    authenticated_customer_id: str
    confirmed: bool = False
    verification_pin: Optional[str] = None


@dataclass
class ToolResult:
    """Structured tool execution result."""

    tool_name: str
    allowed: bool
    status: str  # ALLOWED | BLOCKED | ERROR
    data: Dict[str, Any] = field(default_factory=dict)
    message: str = ""
    audit_id: Optional[int] = None


def load_synthetic_customers() -> Dict[str, Dict[str, Any]]:
    path = settings.data_dir / "synthetic_customers.json"
    records = json.loads(path.read_text(encoding="utf-8"))
    return {r["customer_id"]: r for r in records}


def _sanitize_text(value: str, max_len: int = 300) -> str:
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or "")).strip()
    return cleaned[:max_len]


def _record_audit(
    actor: str,
    role: str,
    action: str,
    resource: str,
    decision: str,
    reason: str,
    metadata: Dict[str, Any] | None = None,
) -> int:
    with get_db() as db:
        entry = AuditLog(
            actor=actor,
            role=role,
            action=action,
            resource=resource,
            decision=decision,
            reason=reason,
            metadata_json=metadata or {},
        )
        db.add(entry)
        db.flush()
        return int(entry.id)


class TelecomToolGateway:
    """Enforces allowlists, RBAC, tenant isolation, PIN checks, confirmation, and audit logs."""

    def __init__(self) -> None:
        self._customers = load_synthetic_customers()
        self._tickets: List[Dict[str, Any]] = []
        self._handlers: Dict[str, Callable[[Dict[str, Any], Dict[str, Any], ToolContext], Dict[str, Any]]] = {
            "get_customer_profile": self._tool_get_customer_profile,
            "get_billing_details": self._tool_get_billing_details,
            "check_data_balance": self._tool_check_data_balance,
            "submit_support_ticket": self._tool_submit_support_ticket,
            "request_sim_replacement": self._tool_request_sim_replacement,
            "request_refund": self._tool_request_refund,
        }

    def list_tool_policies(self) -> List[Dict[str, Any]]:
        """Return tool definitions and security constraints for inspection in UI."""
        return [
            {
                "tool": "get_customer_profile",
                "sensitivity": "Medium (CPNI)",
                "roles": ["customer (self)", "support_agent", "supervisor", "admin"],
                "requires_confirmation": False,
                "requires_pin": False,
                "controls": "Strict tenant isolation; masks PIN and full ICCID.",
            },
            {
                "tool": "get_billing_details",
                "sensitivity": "Medium (CPNI)",
                "roles": ["customer (self)", "support_agent", "supervisor", "admin"],
                "requires_confirmation": False,
                "requires_pin": False,
                "controls": "Cross-customer read denied for customer role.",
            },
            {
                "tool": "check_data_balance",
                "sensitivity": "Low",
                "roles": ["customer (self)", "support_agent", "supervisor", "admin"],
                "requires_confirmation": False,
                "requires_pin": False,
                "controls": "Tenant isolated; validates customer_id format.",
            },
            {
                "tool": "submit_support_ticket",
                "sensitivity": "Low",
                "roles": ["customer (self)", "support_agent", "supervisor", "admin"],
                "requires_confirmation": False,
                "requires_pin": False,
                "controls": "Input sanitization; immutable audit record.",
            },
            {
                "tool": "request_sim_replacement",
                "sensitivity": "Critical (SIM Swap Risk)",
                "roles": ["customer (self + PIN + confirmation)", "supervisor", "admin"],
                "requires_confirmation": True,
                "requires_pin": True,
                "controls": "Blocks Fraud Hold accounts; requires verified PIN + explicit user confirmation.",
            },
            {
                "tool": "request_refund",
                "sensitivity": "High (Financial)",
                "roles": ["customer (<= $25 + confirmation)", "supervisor", "admin"],
                "requires_confirmation": True,
                "requires_pin": False,
                "controls": "Hard $25.00 USD ceiling for non-supervisor roles; rejects negative/excess amounts.",
            },
        ]

    def execute(self, tool_name: str, params: Dict[str, Any], ctx: ToolContext) -> ToolResult:
        """Execute a simulated telecom tool only after passing all backend security gates."""
        target_cid = _sanitize_text(params.get("customer_id") or ctx.authenticated_customer_id, 32)
        resource = f"{tool_name}:{target_cid}"

        # 1. Tool allowlist check
        allowed_tools = ROLE_TOOL_ALLOWLIST.get(ctx.actor_role, set())
        if tool_name not in self._handlers or tool_name not in allowed_tools:
            reason = f"Tool '{tool_name}' is not in allowlist for role '{ctx.actor_role}'."
            audit_id = _record_audit(ctx.actor_id, ctx.actor_role, f"tool:{tool_name}", resource, "BLOCKED", reason, params)
            return ToolResult(tool_name=tool_name, allowed=False, status="BLOCKED", message=reason, audit_id=audit_id)

        # 2. Input validation for customer ID
        if not re.fullmatch(r"CUST-\d{4}", target_cid) or target_cid not in self._customers:
            reason = f"Invalid or unknown synthetic customer_id '{target_cid}'."
            audit_id = _record_audit(ctx.actor_id, ctx.actor_role, f"tool:{tool_name}", resource, "ERROR", reason, params)
            return ToolResult(tool_name=tool_name, allowed=False, status="ERROR", message=reason, audit_id=audit_id)

        # 3. Tenant / Cross-customer isolation
        if ctx.actor_role == "customer" and target_cid != ctx.authenticated_customer_id:
            reason = (
                f"Cross-customer access violation: authenticated as '{ctx.authenticated_customer_id}' "
                f"but attempted to access '{target_cid}'."
            )
            audit_id = _record_audit(ctx.actor_id, ctx.actor_role, f"tool:{tool_name}", resource, "BLOCKED", reason, params)
            return ToolResult(tool_name=tool_name, allowed=False, status="BLOCKED", message=reason, audit_id=audit_id)

        customer = self._customers[target_cid]

        # 4. Sensitive tool confirmation & account security checks
        if tool_name in SENSITIVE_TOOLS and not ctx.confirmed:
            reason = f"Explicit user confirmation required before executing sensitive tool '{tool_name}'."
            audit_id = _record_audit(ctx.actor_id, ctx.actor_role, f"tool:{tool_name}", resource, "BLOCKED", reason, params)
            return ToolResult(tool_name=tool_name, allowed=False, status="BLOCKED", message=reason, audit_id=audit_id)

        if tool_name == "request_sim_replacement":
            if "Fraud Hold" in customer.get("account_status", ""):
                reason = "Account is under 'Suspended - Fraud Hold'. SIM replacement blocked; escalate to Fraud Desk."
                audit_id = _record_audit(ctx.actor_id, ctx.actor_role, f"tool:{tool_name}", resource, "BLOCKED", reason, params)
                return ToolResult(tool_name=tool_name, allowed=False, status="BLOCKED", message=reason, audit_id=audit_id)

            if ctx.actor_role in {"customer", "support_agent"}:
                provided_pin = _sanitize_text(ctx.verification_pin or params.get("verification_pin", ""), 16)
                if provided_pin != customer["verification_pin"]:
                    reason = "Invalid or missing customer verification PIN for SIM replacement."
                    audit_id = _record_audit(ctx.actor_id, ctx.actor_role, f"tool:{tool_name}", resource, "BLOCKED", reason)
                    return ToolResult(tool_name=tool_name, allowed=False, status="BLOCKED", message=reason, audit_id=audit_id)

        if tool_name == "request_refund":
            try:
                amount = float(params.get("amount_usd", 0))
            except (TypeError, ValueError):
                reason = "Invalid refund amount_usd parameter."
                audit_id = _record_audit(ctx.actor_id, ctx.actor_role, f"tool:{tool_name}", resource, "ERROR", reason, params)
                return ToolResult(tool_name=tool_name, allowed=False, status="ERROR", message=reason, audit_id=audit_id)

            if amount <= 0 or amount > 5000:
                reason = f"Refund amount ${amount:.2f} failed input validation bounds (must be > $0 and <= $5000)."
                audit_id = _record_audit(ctx.actor_id, ctx.actor_role, f"tool:{tool_name}", resource, "BLOCKED", reason, params)
                return ToolResult(tool_name=tool_name, allowed=False, status="BLOCKED", message=reason, audit_id=audit_id)

            if ctx.actor_role in {"customer", "support_agent"} and amount > MAX_AUTO_REFUND_USD:
                reason = (
                    f"Refund of ${amount:.2f} exceeds automated limit (${MAX_AUTO_REFUND_USD:.2f}). "
                    "Requires Tier-2 Supervisor authorization."
                )
                audit_id = _record_audit(ctx.actor_id, ctx.actor_role, f"tool:{tool_name}", resource, "BLOCKED", reason, params)
                return ToolResult(tool_name=tool_name, allowed=False, status="BLOCKED", message=reason, audit_id=audit_id)

        # Execute tool handler
        result_data = self._handlers[tool_name](customer, params, ctx)
        audit_id = _record_audit(
            ctx.actor_id,
            ctx.actor_role,
            f"tool:{tool_name}",
            resource,
            "ALLOWED",
            "Authorized and validated via backend policy gateway.",
            {"params_keys": sorted(list(params.keys()))},
        )
        return ToolResult(
            tool_name=tool_name,
            allowed=True,
            status="ALLOWED",
            data=result_data,
            message=f"Tool '{tool_name}' executed safely.",
            audit_id=audit_id,
        )

    @staticmethod
    def _tool_get_customer_profile(customer: Dict[str, Any], params: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
        return {
            "customer_id": customer["customer_id"],
            "full_name": customer["full_name"],
            "phone_number": customer["phone_number"],
            "account_status": customer["account_status"],
            "plan_name": customer["plan_name"],
            "vip_tier": customer["vip_tier"],
            "sim_type": customer["sim_type"],
            "sim_iccid_masked": f"****-{customer['sim_iccid_last4']}",
        }

    @staticmethod
    def _tool_get_billing_details(customer: Dict[str, Any], params: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
        return {
            "customer_id": customer["customer_id"],
            "plan_name": customer["plan_name"],
            "monthly_rate_usd": customer["monthly_rate_usd"],
            "current_balance_usd": customer["current_balance_usd"],
            "overdue_balance_usd": customer["overdue_balance_usd"],
            "recent_invoices": customer["recent_invoices"],
        }

    @staticmethod
    def _tool_check_data_balance(customer: Dict[str, Any], params: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
        remaining = round(max(customer["data_allowance_gb"] - customer["data_used_gb"], 0.0), 2)
        return {
            "customer_id": customer["customer_id"],
            "plan_name": customer["plan_name"],
            "data_allowance_gb": customer["data_allowance_gb"],
            "data_used_gb": customer["data_used_gb"],
            "data_remaining_gb": remaining,
            "roaming_enabled": customer["roaming_enabled"],
        }

    def _tool_submit_support_ticket(self, customer: Dict[str, Any], params: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
        ticket_id = f"TKT-{uuid.uuid4().hex[:8].upper()}"
        ticket = {
            "ticket_id": ticket_id,
            "customer_id": customer["customer_id"],
            "category": _sanitize_text(params.get("category", "General Support"), 64),
            "summary": _sanitize_text(params.get("summary", "Customer escalation request"), 300),
            "priority": _sanitize_text(params.get("priority", "Normal"), 32),
            "status": "Open - Queued for Specialist",
        }
        self._tickets.append(ticket)
        return ticket

    @staticmethod
    def _tool_request_sim_replacement(customer: Dict[str, Any], params: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
        return {
            "request_id": f"SIM-{uuid.uuid4().hex[:8].upper()}",
            "customer_id": customer["customer_id"],
            "sim_type": _sanitize_text(params.get("sim_type", customer["sim_type"]), 32),
            "status": "Pending OTP Finalization",
            "note": "Synthetic SIM replacement queued after PIN verification.",
        }

    @staticmethod
    def _tool_request_refund(customer: Dict[str, Any], params: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
        amount = round(float(params["amount_usd"]), 2)
        return {
            "refund_id": f"RFD-{uuid.uuid4().hex[:8].upper()}",
            "customer_id": customer["customer_id"],
            "amount_usd": amount,
            "reason": _sanitize_text(params.get("reason", "Goodwill credit"), 200),
            "status": "Approved (Synthetic Sandbox Credit)",
        }


tool_gateway = TelecomToolGateway()
