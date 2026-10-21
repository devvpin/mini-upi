"""
messaging — Signed and MAC'd message objects for inter-module communication.

Defines the canonical message schema and helpers for signing, verifying,
and serializing messages. Modules communicate exclusively through these
message objects, even within the same process, so the simulation accurately
mirrors real UPI's multi-party architecture.

Crypto concept: canonical JSON serialization, ECDSA message signing.
Threat mitigated: internal message forgery between simulated parties.

Implemented in Phase 3.
"""
