"""
core — Application configuration, database, logging, error handling, and shared dependencies.

Crypto concept: centralised config enforces that all crypto secrets are present at startup
(fail-fast), preventing the app from running in an insecure partial-config state.

Threat mitigated: missing secrets could disable signature verification or HMAC checks,
silently weakening the entire security model.
"""
