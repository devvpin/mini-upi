"""
identity — Users, departments, classes, authentication, RBAC, and device management.

This module owns the campus hierarchy (Department → Class → Student/Faculty),
user authentication (Argon2id passwords, MPIN), JWT sessions, and device key
registration.

Crypto concept: Argon2id password hashing with server pepper, device-bound ECDSA.
Threat mitigated: credential theft (rainbow tables, GPU cracking, stolen tokens).

Implemented in Phase 1.
"""
