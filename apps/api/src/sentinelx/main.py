"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from sentinelx import __version__
from sentinelx.config import REPO_ROOT, get_settings
from sentinelx.logging import configure_logging, get_logger, request_id_var
from sentinelx.metrics import DATABASE_ERRORS
from sentinelx.persistence.db import dispose_engine, system_session

log = get_logger("sentinelx.api")
WEB_DIST = REPO_ROOT / "apps" / "web" / "dist"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
        "font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    ),
}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    s = get_settings()
    configure_logging(s.log_level, s.log_json)
    problems = s.validate_for_production()
    if problems:
        raise RuntimeError("Refusing to start in production: " + "; ".join(problems))
    worker_task = None
    worker = None
    if s.embedded_worker:
        from sentinelx.jobs.worker import Worker

        worker = Worker(concurrency=s.worker_concurrency)
        worker_task = asyncio.create_task(worker.run())
        log.info("embedded_worker_started")
    log.info("api_started", version=__version__, env=s.app_env)
    yield
    if worker is not None and worker_task is not None:
        worker.stop()
        with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
            await asyncio.wait_for(worker_task, timeout=10)
    await dispose_engine()


def create_app() -> FastAPI:
    s = get_settings()
    configure_logging(s.log_level, s.log_json)
    app = FastAPI(
        title="SentinelX API",
        version=__version__,
        description="Open-source SOC platform: correlated, explainable, evidence-grounded incidents.",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=s.api_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-Requested-With", "X-SentinelX-Tenant", "Authorization"],
    )

    @app.middleware("http")
    async def core_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        rid = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex
        request_id_var.set(rid)
        started = time.perf_counter()
        path = request.url.path
        # CSRF defence for cookie-authenticated requests: browsers cannot send this custom header
        # cross-site without a CORS preflight, which our CORS policy rejects for foreign origins.
        if (
            request.method in UNSAFE
            and path.startswith("/api/")
            and s.session_cookie_name in request.cookies
            and not request.headers.get("authorization")
            and request.headers.get("x-requested-with") != "SentinelX"
        ):
            return JSONResponse({"detail": "Missing X-Requested-With header"}, status_code=403)
        if path.startswith("/api/") and not path.startswith("/api/v1/ingest"):
            from sentinelx.security.ratelimit import limiter

            ip = request.client.host if request.client else "unknown"
            if not limiter.allow(f"api:{ip}", s.rate_limit_api_per_minute):
                return JSONResponse({"detail": "Too many requests"}, status_code=429, headers={"Retry-After": "10"})
        try:
            response = await call_next(request)
        except Exception as exc:  # never leak stack traces to clients
            if type(exc).__module__.startswith(("sqlalchemy", "asyncpg")):
                DATABASE_ERRORS.inc()
            log.exception("unhandled_error", path=path)
            response = JSONResponse({"detail": "Internal error", "request_id": rid}, status_code=500)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if s.is_production:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        response.headers["X-Request-ID"] = rid
        if getattr(request.state, "refresh_session", False):
            token = request.cookies.get(s.session_cookie_name)
            if token:
                response.set_cookie(
                    s.session_cookie_name,
                    token,
                    max_age=s.session_ttl_minutes * 60,
                    httponly=True,
                    secure=s.session_cookie_secure,
                    samesite="lax",
                    path="/",
                )
        duration = (time.perf_counter() - started) * 1000
        if path.startswith("/api/") and not path.endswith(("/live", "/health")):
            log.info(
                "request", method=request.method, path=path, status=response.status_code, duration_ms=round(duration, 1)
            )
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"field": ".".join(str(x) for x in e.get("loc", [])[1:]), "message": e.get("msg")}
            for e in exc.errors()[:20]
        ]
        return JSONResponse({"detail": "Invalid request", "errors": errors}, status_code=422)

    from sentinelx.api.routes import (
        admin,
        ai,
        alerts,
        analytics,
        assets,
        auth,
        detections,
        events,
        incidents,
        ingest,
        mitre,
        threat_intel,
    )

    for r in (auth, incidents, alerts, events, assets, detections, mitre, threat_intel, analytics, ai, admin, ingest):
        app.include_router(r.router, prefix="/api/v1")

    async def _db_ok() -> bool:
        try:
            async with system_session() as db:
                await db.execute(text("SELECT 1"))
            return True
        except Exception:
            DATABASE_ERRORS.inc()
            return False

    @app.get("/live", tags=["health"])
    @app.get("/api/v1/live", include_in_schema=False)
    async def live() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/ready", tags=["health"])
    @app.get("/api/v1/ready", include_in_schema=False)
    async def ready() -> JSONResponse:
        ok = await _db_ok()
        return JSONResponse({"status": "ready" if ok else "not_ready", "database": ok}, status_code=200 if ok else 503)

    @app.get("/health", tags=["health"])
    @app.get("/api/v1/health", include_in_schema=False)
    async def health() -> JSONResponse:
        """Distinguishes: application running / dependencies available / ingestion operational."""
        db_ok = await _db_ok()
        out: dict[str, Any] = {"application": "running", "version": __version__, "database": db_ok}
        if db_ok:
            from sentinelx.api.routes.analytics import ai_status, worker_status

            async with system_session() as db:
                w = await worker_status(db)
                last = (await db.execute(text("SELECT max(last_ingest_at) FROM ingestion_sources"))).scalar_one()
            out["worker"] = w
            out["ingestion"] = {"last_ingest_at": last, "operational": w["running"]}
            ai = await ai_status(get_settings().ollama_model)
            out["ai_analyst"] = "available" if ai.get("available") else "unavailable"
            out["core_detection"] = "operational" if w["running"] else "degraded (worker not running)"
        status = "ok" if db_ok else "error"
        return JSONResponse(jsonable_encoder({"status": status, **out}), status_code=200 if db_ok else 503)

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> PlainTextResponse:
        return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
    async def api_404(path: str) -> JSONResponse:
        raise HTTPException(404, "Not found")

    if WEB_DIST.is_dir():
        index = WEB_DIST / "index.html"

        @app.get("/{path:path}", include_in_schema=False)
        async def spa(path: str) -> FileResponse:
            candidate = (WEB_DIST / path).resolve()
            if path and candidate.is_file() and WEB_DIST.resolve() in candidate.parents:
                headers = {"Cache-Control": "public, max-age=31536000, immutable"} if path.startswith("assets/") else {}
                return FileResponse(candidate, headers=headers)
            return FileResponse(index, headers={"Cache-Control": "no-cache"})

    return app


app = create_app()
