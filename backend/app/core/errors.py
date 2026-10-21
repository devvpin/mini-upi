"""
core.errors — Standardised error responses.

All API errors share the same JSON shape so the client can rely on one parser.
Error messages never reveal which authentication factor failed.

Crypto concept: constant error responses prevent enumeration attacks.
Threat mitigated: username/factor enumeration, information leakage.
"""

from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


class AppError(HTTPException):
    """Structured application error with a machine-readable code."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.code = code
        super().__init__(status_code=status_code, detail=message, headers=headers)


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    """Convert AppError to the standard error JSON shape."""
    import structlog

    request_id = structlog.contextvars.get_contextvars().get("request_id", "unknown")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.code,
                "message": exc.detail,
                "request_id": request_id,
            }
        },
    )


# Predefined error factories for stable error codes (see 06_API_SPEC.md)

def auth_failed(message: str = "Authentication failed.") -> AppError:
    return AppError(401, "AUTH_FAILED", message)

def account_locked(message: str = "Account is locked.") -> AppError:
    return AppError(423, "ACCOUNT_LOCKED", message)

def device_not_bound(message: str = "No device bound to this account.") -> AppError:
    return AppError(403, "DEVICE_NOT_BOUND", message)

def signature_invalid(message: str = "Signature verification failed.") -> AppError:
    return AppError(400, "SIGNATURE_INVALID", message)

def envelope_invalid(message: str = "Envelope decryption failed.") -> AppError:
    return AppError(400, "ENVELOPE_INVALID", message)

def replay_detected(message: str = "Replay detected.") -> AppError:
    return AppError(409, "REPLAY_DETECTED", message)

def timestamp_skew(message: str = "Timestamp outside allowed window.") -> AppError:
    return AppError(400, "TIMESTAMP_SKEW", message)

def insufficient_funds(message: str = "Insufficient funds.") -> AppError:
    return AppError(402, "INSUFFICIENT_FUNDS", message)

def limit_exceeded(message: str = "Transaction limit exceeded.") -> AppError:
    return AppError(400, "LIMIT_EXCEEDED", message)

def payee_not_found(message: str = "Payee not found.") -> AppError:
    return AppError(404, "PAYEE_NOT_FOUND", message)

def account_frozen(message: str = "Account is frozen.") -> AppError:
    return AppError(403, "ACCOUNT_FROZEN", message)

def rate_limited(message: str = "Rate limit exceeded. Try again later.") -> AppError:
    return AppError(429, "RATE_LIMITED", message)

def internal_error(message: str = "Internal error.") -> AppError:
    return AppError(500, "INTERNAL", message)
