"""Minimal async Ollama client (local runtime only). https://docs.ollama.com/api"""

from __future__ import annotations

import time
from typing import Any

import httpx

from sentinelx.config import get_settings
from sentinelx.metrics import LLM_ERRORS, LLM_REQUEST_DURATION


class LlmUnavailable(RuntimeError):
    pass


def is_local_model(m: dict[str, Any]) -> bool:
    name = str(m.get("name") or m.get("model") or "")
    return not (name.endswith(":cloud") or "-cloud" in name or m.get("remote_host") or m.get("remote_model"))


class OllamaClient:
    def __init__(
        self,
        base_url: str | None = None,
        timeout: float | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        s = get_settings()
        self.base_url = (base_url or s.ollama_url).rstrip("/")
        self.timeout = timeout or s.ollama_timeout_seconds
        self.transport = transport

    def _client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url, timeout=timeout, transport=self.transport, follow_redirects=False
        )

    async def local_models(self) -> list[dict[str, Any]]:
        try:
            async with self._client(5.0) as c:
                r = await c.get("/api/tags")
                r.raise_for_status()
                models = r.json().get("models", [])
        except (httpx.HTTPError, ValueError) as e:
            raise LlmUnavailable(f"Ollama not reachable at {self.base_url}") from e
        return [
            {
                "name": m.get("name"),
                "size": m.get("size"),
                "parameter_size": (m.get("details") or {}).get("parameter_size"),
                "family": (m.get("details") or {}).get("family"),
            }
            for m in models
            if is_local_model(m)
        ]

    async def status(self, model: str) -> dict[str, Any]:
        try:
            models = await self.local_models()
        except LlmUnavailable as e:
            return {"available": False, "reason": str(e), "model": model}
        names = {m["name"] for m in models}
        if model not in names:
            return {
                "available": False,
                "reason": f"model '{model}' is not installed (run: ollama pull {model})",
                "model": model,
                "installed": sorted(names),
            }
        return {"available": True, "model": model, "installed": sorted(names)}

    async def chat_json(
        self, model: str, messages: list[dict[str, str]], schema: dict[str, Any], num_ctx: int = 8192
    ) -> tuple[str, dict[str, Any]]:
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "format": schema,
            "options": {"temperature": 0.1, "num_ctx": num_ctx, "top_p": 0.9},
            "keep_alive": "10m",
        }
        if model.startswith("qwen3:") and "instruct" not in model:
            body["think"] = False
        started = time.perf_counter()
        try:
            async with self._client(self.timeout) as c:
                r = await c.post("/api/chat", json=body)
                if r.status_code == 404:
                    raise LlmUnavailable(f"model '{model}' not found in Ollama")
                r.raise_for_status()
                data = r.json()
        except httpx.TimeoutException as e:
            LLM_ERRORS.labels(kind="timeout").inc()
            raise LlmUnavailable("Ollama request timed out") from e
        except httpx.HTTPError as e:
            LLM_ERRORS.labels(kind="http").inc()
            raise LlmUnavailable(f"Ollama request failed: {type(e).__name__}") from e
        finally:
            LLM_REQUEST_DURATION.observe(time.perf_counter() - started)
        content = ((data.get("message") or {}).get("content") or "").strip()
        meta = {k: data.get(k) for k in ("model", "total_duration", "prompt_eval_count", "eval_count")}
        return content, meta
