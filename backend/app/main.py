"""
main — FastAPI application factory for Mini-UPI.

Creates the ASGI app with all middleware, error handlers, and routers.
In Phase 0 this only exposes /health and /ready; subsequent phases wire
additional routers for identity, payments, etc.

Crypto concept: defence-in-depth via security headers and CORS policy set at
the application boundary.

Threat mitigated: XSS, clickjacking, MIME-type confusion, cross-origin attacks.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import get_settings
from app.core.database import async_session_factory, check_db_connection
from app.core.errors import AppError, app_error_handler
from app.core.logging import (
    RequestIdMiddleware,
    configure_logging,
    get_logger,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup / shutdown lifecycle hook."""
    configure_logging(json_output=get_settings().app_env != "development")
    log = get_logger("startup")
    log.info(
        "mini_upi_starting",
        env=get_settings().app_env,
        demo_mode=get_settings().demo_mode,
    )

    async def expire_collect_requests_periodically() -> None:
        from app.psp.service import expire_collect_requests

        while True:
            await asyncio.sleep(60)
            async with async_session_factory() as session:
                await expire_collect_requests(session)

    expiry_task = asyncio.create_task(expire_collect_requests_periodically())
    try:
        yield
    finally:
        expiry_task.cancel()
        await asyncio.gather(expiry_task, return_exceptions=True)
    log.info("mini_upi_shutdown")


def create_app() -> FastAPI:
    """Build and return the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="Mini-UPI",
        description="Secure Campus Payment Simulation — virtual points, no real money.",
        version="0.1.0",
        lifespan=lifespan,
    )

    # ── Error handlers ──────────────────────────────────────────────────
    app.add_exception_handler(AppError, app_error_handler)  # type: ignore[arg-type]

    # ── API Routers ─────────────────────────────────────────────────────
    from app.admin.router import router as admin_router
    from app.bank.router import router as bank_router
    from app.crypto.router import router as crypto_router
    from app.identity.router import router as identity_router
    from app.psp.router import router as psp_router

    app.include_router(identity_router, prefix="/api/v1")
    app.include_router(bank_router, prefix="/api/v1")
    app.include_router(crypto_router, prefix="/api/v1")
    app.include_router(admin_router, prefix="/api/v1")
    app.include_router(psp_router, prefix="/api/v1")

    # ── Middleware (order matters: outermost first) ──────────────────────
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.web_origin, "http://localhost", "http://localhost:80", "http://localhost:5173"],
        allow_origin_regex=r"^https?://.*\.app\.github\.dev$",
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
        allow_credentials=True,
    )
    request_limits: dict[tuple[str, str], list[float]] = {}
    limit_rules = {
        # Per-account login failures lock after five attempts; leave enough
        # requests for that control to return its explicit locked response.
        ("/auth/login", "POST"): (10, 60),
        ("/payments/pay", "POST"): (20, 60),
        ("/payments/collect", "POST"): (20, 60),
    }

    @app.middleware("http")
    async def rate_limit_sensitive_routes(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        rule = limit_rules.get((request.url.path.removeprefix("/api/v1"), request.method))
        if rule:
            maximum, window = rule
            key = (request.client.host if request.client else "unknown", request.url.path)
            now = time.monotonic()
            recent = [stamp for stamp in request_limits.get(key, []) if now - stamp < window]
            if len(recent) >= maximum:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": {
                            "code": "RATE_LIMITED",
                            "message": "Too many requests. Try again later.",
                        }
                    },
                )
            recent.append(now)
            request_limits[key] = recent
        return await call_next(request)

    # ── Security headers ────────────────────────────────────────────────
    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'"
        )
        return response

    # ── Health endpoints ────────────────────────────────────────────────
    @app.get("/health", tags=["ops"])
    async def health() -> dict[str, str]:
        """Liveness probe — always returns 200 if the process is running."""
        return {"status": "ok"}

    @app.get("/ready", tags=["ops"])
    async def ready() -> JSONResponse:
        """Readiness probe — 200 only when the database is reachable."""
        db_ok = await check_db_connection()
        if db_ok:
            return JSONResponse({"status": "ready", "db": "ok"})
        return JSONResponse(
            status_code=503,
            content={"status": "not ready", "db": "unreachable"},
        )

    return app


app = create_app()
