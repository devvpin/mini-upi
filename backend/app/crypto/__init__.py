"""
crypto — Pure cryptographic functions.

Contains helpers for key derivation, signing, envelope encryption, HMAC,
hash-chain construction, and mini-PKI operations. All functions are pure
(no DB access) and have unit tests with known-answer vectors.

Uses only vetted libraries: `cryptography`, `argon2-cffi`, stdlib `hmac`/`hashlib`.
No hand-rolled primitives.

Crypto concept: library of building blocks used by PSP, Switch, and Bank modules.
Threat mitigated: implementation errors from ad-hoc crypto code.

Implemented in Phase 3.
"""
