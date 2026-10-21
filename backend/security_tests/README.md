# Phase 6 attack demos

Run all executable rejection demonstrations with:

```bash
make attacks
```

The payment attack matrix is implemented in `tests/test_phase4.py`: replay,
ciphertext tampering, stolen JWT/device mismatch, MPIN brute force, limits,
idempotency, and audit verification. PKI forgery and signature tampering are
covered by `tests/test_phase3.py`. Every passing negative test means the attack
was blocked.
