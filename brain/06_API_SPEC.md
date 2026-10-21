# 06 — API Specification (v1)

Base path `/api/v1`. JSON only. Errors: `{ "error": { "code": "STRING", "message": "human text", "request_id": "…" } }`.
Money fields are integers in paise (`amount_paise`). Timestamps are ISO-8601 UTC.

## Auth and identity
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | /auth/login | none | `{college_id, password}` → access + refresh (cookie or body) |
| POST | /auth/refresh | refresh | rotate refresh token |
| POST | /auth/logout | access | revoke refresh token |
| POST | /auth/change-password | access | required when `must_change_password` |
| POST | /mpin/set | access | set MPIN (first time, requires password re-entry) |
| POST | /devices/register | access | `{public_key_jwk, label}` |
| GET | /devices | access | list own devices |
| DELETE | /devices/{id} | access | revoke |
| GET | /me | access | profile, department, class, primary VPA |

## Wallet and VPA
| Method | Path | Purpose |
|---|---|---|
| GET | /wallet | balance + last 5 transactions |
| GET | /vpa/resolve?handle= | returns display name (masked) + VPA for confirmation screen |
| GET | /vpa/me | own VPAs and QR payload |

## Payments (all payment bodies are envelope-encrypted)
| Method | Path | Purpose |
|---|---|---|
| GET | /crypto/server-key | CA-signed server ECDH public key + CA fingerprint |
| POST | /payments/pay | envelope with `{payload, device_sig, mpin}` → encrypted receipt |
| POST | /payments/collect | create a collect request (payee asks payer) |
| GET | /payments/collect/incoming | pending requests addressed to me |
| POST | /payments/collect/{id}/approve | envelope pay flow for the request |
| POST | /payments/collect/{id}/decline | decline |
| GET | /transactions?cursor=&limit= | own history, cursor pagination |
| GET | /transactions/{id} | detail + receipt + Security Lens data (hashes, sig status, chain seq) |

## Admin
| Method | Path | Purpose |
|---|---|---|
| POST | /admin/import | CSV upload: departments, classes, users (dry-run flag) |
| POST | /admin/topup | `{college_id | vpa, amount_paise, reason}` from treasury (audited) |
| POST | /admin/users/{id}/freeze | freeze / unfreeze |
| GET | /admin/stats | counts, volume, active devices |
| POST | /audit/verify | verify hash chain |
| GET | /audit/events?seq_from= | read-only audit viewer |

## Security headers and policies
- `Strict-Transport-Security`, `Content-Security-Policy` (no inline scripts), `X-Content-Type-Options`,
  `Referrer-Policy: no-referrer`, tight CORS to the web origin.
- Rate limits: login 5/min/IP + 10/hour/user; `/payments/*` 20/min/user; `/vpa/resolve` 30/min/user
  (prevents directory scraping of ~3,000 users).
- Idempotency: `txn_id` supplied by client inside the signed payload.
- All list endpoints are paginated; never return another user's balance.

## Error codes (stable)
`AUTH_FAILED`, `ACCOUNT_LOCKED`, `DEVICE_NOT_BOUND`, `SIGNATURE_INVALID`, `ENVELOPE_INVALID`,
`REPLAY_DETECTED`, `TIMESTAMP_SKEW`, `INSUFFICIENT_FUNDS`, `LIMIT_EXCEEDED`, `PAYEE_NOT_FOUND`,
`ACCOUNT_FROZEN`, `RATE_LIMITED`, `INTERNAL`.
Login and MPIN failures must both return `AUTH_FAILED` with identical shape.

## Limits (configurable in env)
Per transaction ₹5,000 · Daily ₹20,000 · Min ₹1 · Collect request expiry 24 h.
