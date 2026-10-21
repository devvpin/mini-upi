"""
psp — Payment Service Provider module.

Handles payment ingress: JWT authentication, envelope decryption, device
signature verification, MPIN validation, nonce/replay checks. Acts as the
gateway between the client app and the internal UPI pipeline.

Crypto concept: ECDH+AES-GCM envelope decryption, ECDSA device signature
verification, Argon2id MPIN check.
Threat mitigated: eavesdropping, tampering, replay, device theft.

Implemented in Phase 3-4.
"""
