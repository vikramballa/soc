"""AI investigation job: context -> prompt policy -> Ollama -> schema + grounding validation -> stored result.

No database transaction is held open while the model generates.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from sentinelx.ai.context import AiContext, build_context
from sentinelx.ai.ollama import LlmUnavailable, OllamaClient
from sentinelx.ai.prompt import SYSTEM_PROMPT, correction_prompt, user_prompt
from sentinelx.ai.schema import OLLAMA_FORMAT, AiAnalysis
from sentinelx.ai.validator import to_stored, validate
from sentinelx.config import get_settings
from sentinelx.logging import get_logger
from sentinelx.persistence.db import tenant_session
from sentinelx.persistence.models import AiInvestigation, IncidentActivity, Tenant

log = get_logger(__name__)
MAX_ATTEMPTS = 3


async def model_for_tenant(tenant_id: uuid.UUID) -> str:
    async with tenant_session(tenant_id) as s:
        t = await s.get(Tenant, tenant_id)
        return str(((t.settings or {}) if t else {}).get("ai_model") or get_settings().ollama_model)


def _parse(content: str) -> AiAnalysis:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{") :]
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise ValueError("model did not return a JSON object")
    return AiAnalysis.model_validate(json.loads(text[start : end + 1]))


async def run_investigation(
    tenant_id: uuid.UUID, investigation_id: uuid.UUID, client: OllamaClient | None = None
) -> dict[str, Any]:
    client = client or OllamaClient()
    started = time.perf_counter()
    async with tenant_session(tenant_id) as s:
        inv = await s.get(AiInvestigation, investigation_id)
        if inv is None:
            return {"status": "missing"}
        inv.status = "running"
        ctx: AiContext = await build_context(s, tenant_id, inv.incident_id, get_settings().ai_max_evidence_events)
        inv.context_sha256 = ctx.sha256()
        inv.context_stats = ctx.stats()
        inv.injection_flags = ctx.injection_flags
        model = inv.model
        incident_id = inv.incident_id

    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_prompt(ctx.payload)}]
    status, result, errors, error_msg, attempts = "failed", None, [], None, 0
    try:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            attempts = attempt
            content, meta = await client.chat_json(model, messages, OLLAMA_FORMAT, get_settings().ollama_num_ctx)
            try:
                analysis = _parse(content)
                errors = validate(analysis, ctx)
            except (ValueError, ValidationError) as e:
                analysis = None
                errors = [f"output is not valid structured JSON: {str(e).splitlines()[0][:300]}"]
            if analysis is not None and not errors:
                result = to_stored(analysis, ctx)
                result["generation"] = meta
                status = "completed"
                break
            messages += [
                {"role": "assistant", "content": content[:6000]},
                {"role": "user", "content": correction_prompt(errors)},
            ]
        else:
            status = "rejected"
    except LlmUnavailable as e:
        status, error_msg = "failed", str(e)
    except LookupError as e:
        status, error_msg = "failed", str(e)

    duration = int((time.perf_counter() - started) * 1000)
    async with tenant_session(tenant_id) as s:
        inv = await s.get(AiInvestigation, investigation_id)
        if inv is not None:
            inv.status, inv.result, inv.validation_errors = status, result, errors
            inv.error, inv.attempts, inv.duration_ms = error_msg, attempts, duration
            inv.completed_at = datetime.now(UTC)
            msg = {
                "completed": "AI investigation completed and passed evidence validation",
                "rejected": "AI output was rejected: it failed evidence-grounding validation",
                "failed": f"AI investigation unavailable: {error_msg}",
            }[status]
            s.add(
                IncidentActivity(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    kind="ai",
                    actor=inv.requested_by,
                    message=msg,
                    data={"investigation_id": str(investigation_id), "model": model},
                )
            )
    log.info("ai_investigation_finished", status=status, attempts=attempts, duration_ms=duration, model=model)
    return {"status": status, "attempts": attempts, "errors": errors}
