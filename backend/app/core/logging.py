"""
core.logging — Structured JSON logging with request_id and secret scrubbing.

Every log line includes a `request_id` for traceability. A processor scrubs
patterns that look like secrets (JWTs, base64 tokens, MPINs) from log output.

Crypto concept: defence-in-depth — even if a developer accidentally logs a
secret, the scrubber replaces it before it reaches the log sink.

Threat mitigated: credential leakage via logs (server compromise, log aggregation
systems, accidental exposure in CI output).
"""

from __future__ import annotations

import re
import uuid
from typing import Any, cast

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

# ── Secret-scrubbing processor ──────────────────────────────────────────────

# Patterns that should be redacted in log output
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # JWT tokens (three base64url segments separated by dots)
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[REDACTED_JWT]"),
    # Generic long base64url strings (≥32 chars, likely tokens/keys)
    (re.compile(r"[A-Za-z0-9_-]{32,}"), "[REDACTED_TOKEN]"),
    # 6-digit MPIN patterns when labelled
    (re.compile(r'(?i)(mpin["\s:=]+)\d{6}'), r"\1[REDACTED_MPIN]"),
    # password/secret values in key=value style
    (re.compile(r'(?i)(password|secret|pepper|key)["\s:=]+\S+'), r"\1=[REDACTED]"),
]


def scrub_secrets(
    logger: Any,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Structlog processor that scrubs secret-looking patterns from log events."""
    for key, value in event_dict.items():
        if isinstance(value, str):
            for pattern, replacement in _SECRET_PATTERNS:
                value = pattern.sub(replacement, value)
            event_dict[key] = value
    return event_dict


# ── Structlog configuration ─────────────────────────────────────────────────

def configure_logging(*, json_output: bool = True) -> None:
    """Configure structlog with JSON output and secret scrubbing."""
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        scrub_secrets,
    ]
    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(0),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


# ── Request-ID middleware ────────────────────────────────────────────────────

class RequestIdMiddleware(BaseHTTPMiddleware):
    """Inject a unique request_id into every request's structlog context."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a named structlog logger."""
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))
