"""Reusable Gemini API adapter & model abstraction layer using official google-genai SDK."""

from __future__ import annotations

import json
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Type, TypeVar

from pydantic import BaseModel

from telecomguard.config import resolve_model_name, settings

logger = logging.getLogger("telecomguard.gemini")
T = TypeVar("T", bound=BaseModel)


def _sanitize_error(msg: Any) -> str:
    """Strip any accidental API key query params or bearer tokens from error logs."""
    text = str(msg or "")
    text = re.sub(r"(key|api_key|token)=([A-Za-z0-9_\-]+)", r"\1=***REDACTED***", text, flags=re.IGNORECASE)
    text = re.sub(r"AIza[0-9A-Za-z\-_]{20,}", "***REDACTED_KEY***", text)
    return text


@dataclass
class ModelCallResult:
    """Standardized response & telemetry envelope from any LLM adapter."""

    text: str
    parsed: Optional[Any] = None
    model_name: str = "gemini-4-hydrogen"
    execution_time_ms: float = 0.0
    prompt_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    request_metadata: Dict[str, Any] = field(default_factory=dict)
    mode: str = "gemini"  # gemini | fallback
    success: bool = True
    error: Optional[str] = None

    def to_log_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload.pop("parsed", None)
        return payload


class BaseModelAdapter(ABC):
    """Abstract adapter interface so future LLM providers can plug in cleanly."""

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if live provider credentials are present."""

    @abstractmethod
    def generate_text(
        self,
        prompt: str,
        system_instruction: str | None = None,
        model_name: str | None = None,
        metadata: Dict[str, Any] | None = None,
    ) -> ModelCallResult:
        """Generate unstructured text response."""

    @abstractmethod
    def generate_structured(
        self,
        prompt: str,
        schema_model: Type[T],
        system_instruction: str | None = None,
        model_name: str | None = None,
        metadata: Dict[str, Any] | None = None,
    ) -> ModelCallResult:
        """Generate structured JSON response validated against a Pydantic schema."""


class GeminiService(BaseModelAdapter):
    """Production Gemini service built on the official google-genai SDK."""

    def __init__(
        self,
        api_key: str | None = None,
        default_model: str | None = None,
        timeout_seconds: int | None = None,
        max_retries: int | None = None,
    ) -> None:
        self._explicit_api_key = api_key
        resolved_model, notice = resolve_model_name(default_model or settings.gemini_model)
        self.default_model = resolved_model
        self.deprecation_notice = notice
        self.timeout_seconds = timeout_seconds or settings.gemini_timeout_seconds
        self.max_retries = max_retries or settings.gemini_max_retries
        self.call_history: List[Dict[str, Any]] = []

    def _get_api_key(self) -> str | None:
        if self._explicit_api_key and self._explicit_api_key != "your_api_key_here":
            return self._explicit_api_key
        return settings.get_gemini_api_key()

    def is_configured(self) -> bool:
        return self._get_api_key() is not None

    def _build_client(self):
        from google import genai

        api_key = self._get_api_key()
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured.")
        return genai.Client(
            api_key=api_key,
            http_options={"timeout": self.timeout_seconds * 1000},
        )

    @staticmethod
    def _extract_usage(interaction: Any) -> tuple[int, int, int]:
        usage = getattr(interaction, "usage", None)
        if usage is None:
            return 0, 0, 0
        prompt_t = int(getattr(usage, "total_input_tokens", 0) or getattr(usage, "input_tokens", 0) or 0)
        output_t = int(getattr(usage, "total_output_tokens", 0) or getattr(usage, "output_tokens", 0) or 0)
        total_t = int(getattr(usage, "total_tokens", 0) or (prompt_t + output_t))
        return prompt_t, output_t, total_t

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        msg = str(exc).lower()
        retry_markers = ("429", "rate limit", "resource_exhausted", "timeout", "503", "502", "temporarily")
        return any(marker in msg for marker in retry_markers)

    def _record_telemetry(self, result: ModelCallResult) -> None:
        entry = result.to_log_dict()
        entry["text_preview"] = (result.text or "")[:140]
        self.call_history.append(entry)
        if len(self.call_history) > 200:
            self.call_history = self.call_history[-200:]
        logger.info(
            "gemini_call model=%s mode=%s success=%s time_ms=%.1f tokens=%d meta=%s",
            result.model_name,
            result.mode,
            result.success,
            result.execution_time_ms,
            result.total_tokens,
            json.dumps(result.request_metadata, default=str),
        )

    def test_connection(self, model_name: str | None = None) -> Dict[str, Any]:
        """Run a minimal live API connectivity check without exposing credentials."""
        if not self.is_configured():
            return {
                "ok": False,
                "model": resolve_model_name(model_name or self.default_model)[0],
                "latency_ms": 0.0,
                "tokens": 0,
                "message": "GEMINI_API_KEY is not configured in environment or Streamlit secrets.",
            }
        res = self.generate_text(
            prompt="Reply with exactly: TELECOMGUARD_GEMINI_OK",
            system_instruction="Connectivity health check. Respond concisely.",
            model_name=model_name,
            metadata={"component": "connectivity_test"},
        )
        return {
            "ok": res.success and bool(res.text),
            "model": res.model_name,
            "latency_ms": res.execution_time_ms,
            "tokens": res.total_tokens,
            "message": res.text if res.success else (res.error or "Unknown Gemini API error"),
        }

    def generate_text(
        self,
        prompt: str,
        system_instruction: str | None = None,
        model_name: str | None = None,
        metadata: Dict[str, Any] | None = None,
    ) -> ModelCallResult:
        resolved_model, _ = resolve_model_name(model_name or self.default_model)
        req_meta = dict(metadata or {})
        start = time.perf_counter()

        if not self.is_configured():
            res = ModelCallResult(
                text="",
                model_name=resolved_model,
                execution_time_ms=round((time.perf_counter() - start) * 1000, 2),
                request_metadata=req_meta,
                mode="fallback",
                success=False,
                error="GEMINI_API_KEY is not configured. Running in local synthetic demo mode.",
            )
            self._record_telemetry(res)
            return res

        last_err: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                client = self._build_client()
                kwargs: Dict[str, Any] = {
                    "model": resolved_model,
                    "input": prompt,
                    "store": False,
                }
                if system_instruction:
                    kwargs["system_instruction"] = system_instruction

                interaction = client.interactions.create(**kwargs)
                text = getattr(interaction, "output_text", None) or ""
                if not text and getattr(interaction, "steps", None):
                    parts = []
                    for step in interaction.steps:
                        for item in getattr(step, "content", []) or []:
                            t = getattr(item, "text", None)
                            if t:
                                parts.append(t)
                    text = "\n".join(parts)

                pt, ot, tt = self._extract_usage(interaction)
                res = ModelCallResult(
                    text=text.strip(),
                    model_name=resolved_model,
                    execution_time_ms=round((time.perf_counter() - start) * 1000, 2),
                    prompt_tokens=pt,
                    output_tokens=ot,
                    total_tokens=tt,
                    request_metadata={**req_meta, "attempt": attempt},
                    mode="gemini",
                    success=True,
                )
                self._record_telemetry(res)
                return res
            except Exception as exc:  # pragma: no cover - network dependent
                last_err = exc
                if attempt < self.max_retries and self._is_retryable(exc):
                    time.sleep(min(2 ** attempt, 8))
                    continue
                break

        res = ModelCallResult(
            text="",
            model_name=resolved_model,
            execution_time_ms=round((time.perf_counter() - start) * 1000, 2),
            request_metadata=req_meta,
            mode="fallback",
            success=False,
            error=f"Gemini API error: {_sanitize_error(last_err)}",
        )
        self._record_telemetry(res)
        return res

    def generate_structured(
        self,
        prompt: str,
        schema_model: Type[T],
        system_instruction: str | None = None,
        model_name: str | None = None,
        metadata: Dict[str, Any] | None = None,
    ) -> ModelCallResult:
        resolved_model, _ = resolve_model_name(model_name or self.default_model)
        req_meta = {**(metadata or {}), "schema": schema_model.__name__}
        start = time.perf_counter()

        if not self.is_configured():
            res = ModelCallResult(
                text="",
                parsed=None,
                model_name=resolved_model,
                execution_time_ms=round((time.perf_counter() - start) * 1000, 2),
                request_metadata=req_meta,
                mode="fallback",
                success=False,
                error="GEMINI_API_KEY is not configured. Structured fallback required.",
            )
            self._record_telemetry(res)
            return res

        last_err: Exception | None = None
        schema_dict = schema_model.model_json_schema()

        for attempt in range(1, self.max_retries + 1):
            try:
                client = self._build_client()
                kwargs: Dict[str, Any] = {
                    "model": resolved_model,
                    "input": prompt,
                    "store": False,
                    "response_format": {
                        "type": "text",
                        "mime_type": "application/json",
                        "schema": schema_dict,
                    },
                }
                if system_instruction:
                    kwargs["system_instruction"] = system_instruction

                interaction = client.interactions.create(**kwargs)
                raw_text = (getattr(interaction, "output_text", None) or "").strip()
                parsed_obj = schema_model.model_validate_json(raw_text)
                pt, ot, tt = self._extract_usage(interaction)

                res = ModelCallResult(
                    text=raw_text,
                    parsed=parsed_obj,
                    model_name=resolved_model,
                    execution_time_ms=round((time.perf_counter() - start) * 1000, 2),
                    prompt_tokens=pt,
                    output_tokens=ot,
                    total_tokens=tt,
                    request_metadata={**req_meta, "attempt": attempt},
                    mode="gemini",
                    success=True,
                )
                self._record_telemetry(res)
                return res
            except Exception as exc:  # pragma: no cover - network dependent
                last_err = exc
                if attempt < self.max_retries and self._is_retryable(exc):
                    time.sleep(min(2 ** attempt, 8))
                    continue
                break

        res = ModelCallResult(
            text="",
            parsed=None,
            model_name=resolved_model,
            execution_time_ms=round((time.perf_counter() - start) * 1000, 2),
            request_metadata=req_meta,
            mode="fallback",
            success=False,
            error=f"Gemini structured call failed: {_sanitize_error(last_err)}",
        )
        self._record_telemetry(res)
        return res

    def embed_texts(self, texts: List[str], model_name: str | None = None) -> List[List[float]] | None:
        """Compute embeddings via Gemini embedding model if API key is configured."""
        if not self.is_configured() or not texts:
            return None
        embed_model = model_name or settings.gemini_embedding_model
        try:
            client = self._build_client()
            resp = client.models.embed_content(model=embed_model, contents=texts)
            return [list(item.values) for item in resp.embeddings]
        except Exception as exc:  # pragma: no cover
            logger.warning("Gemini embed_content failed (%s); falling back to local embeddings.", _sanitize_error(exc))
            return None


gemini_service = GeminiService()
