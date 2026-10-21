"""
audit — Hash-chained audit log and verifier.

Maintains an append-only log where each entry's hash depends on its
predecessor, creating a tamper-evident chain. The HMAC layer adds a
second integrity check using a server-side secret.

Crypto concept: SHA-256 hash chain, HMAC-SHA256 per-entry integrity.
Threat mitigated: silent edits to transaction history (insider threat).

Implemented in Phase 3.
"""
