# PHASE 3 — Crypto Core

**Goal:** every cryptographic building block implemented, tested, and interoperable between browser and server.
**Read:** 05 in full.

## Tasks (server, `backend/app/crypto/` — pure functions)
- [x] `canonical.py`: canonical JSON + shared test vectors
- [x] `signing.py`: ECDSA P-256 verify (device sigs, raw r‖s ↔ DER conversion), sign (PSP/Bank)
- [x] `envelope.py`: ECDH + HKDF + AES-256-GCM encrypt/decrypt with AAD; response encryption
- [x] `hmac_.py`: service MAC sign/verify, constant-time compare, `key_id`
- [x] `chain.py`: audit hash chain append + verify
- [x] `pki.py` + `scripts/pki/make_ca.py`: root CA, issue PSP/Switch/Bank certs, verify chain/role/validity
- [x] Devices: `POST /devices/register`, list, revoke; `mpin_credentials` set/verify with lockout
- [x] Nonce store + timestamp window helper
- [x] `GET /crypto/server-key` (CA-signed)
- [x] Audit log table trigger blocking UPDATE/DELETE; `POST /audit/verify`

## Tasks (browser, `web/src/crypto/`)
- [x] `keys.ts`: generate non-extractable ECDSA key, store in IndexedDB, export public JWK
- [x] `sign.ts`: sign canonical JSON, produce raw r‖s
- [x] `envelope.ts`: ECDH + HKDF + AES-GCM matching the server exactly; decrypt responses
- [x] `canonical.ts`: same canonicalization; run the shared vectors in Vitest

## Tests
- Known-answer vectors both directions (WebCrypto → Python and Python → WebCrypto)
- Negative: flipped bit, wrong AAD, wrong key, replayed nonce, skewed ts, revoked device, expired cert, wrong-role cert, edited audit row
- MPIN lockout: 3 failures → locked; unlock after window

## Phase Gate
- [x] Interop test: browser-encrypted envelope decrypts on the server and vice versa
- [x] Every negative test fails with the specific audited reason
- [x] Audit verify detects a manually tampered row and reports the exact `seq`
- [x] Private device key is non-extractable (test attempts `exportKey` and expects failure)
- [x] `mypy --strict` clean on `app/crypto`
- [x] `PROGRESS.md` updated
