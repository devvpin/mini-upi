# PHASE 3 — Crypto Core

**Goal:** every cryptographic building block implemented, tested, and interoperable between browser and server.
**Read:** 05 in full.

## Tasks (server, `backend/app/crypto/` — pure functions)
- [ ] `canonical.py`: canonical JSON + shared test vectors
- [ ] `signing.py`: ECDSA P-256 verify (device sigs, raw r‖s ↔ DER conversion), sign (PSP/Bank)
- [ ] `envelope.py`: ECDH + HKDF + AES-256-GCM encrypt/decrypt with AAD; response encryption
- [ ] `hmac_.py`: service MAC sign/verify, constant-time compare, `key_id`
- [ ] `chain.py`: audit hash chain append + verify
- [ ] `pki.py` + `scripts/pki/make_ca.py`: root CA, issue PSP/Switch/Bank certs, verify chain/role/validity
- [ ] Devices: `POST /devices/register`, list, revoke; `mpin_credentials` set/verify with lockout
- [ ] Nonce store + timestamp window helper
- [ ] `GET /crypto/server-key` (CA-signed)
- [ ] Audit log table trigger blocking UPDATE/DELETE; `POST /audit/verify`

## Tasks (browser, `web/src/crypto/`)
- [ ] `keys.ts`: generate non-extractable ECDSA key, store in IndexedDB, export public JWK
- [ ] `sign.ts`: sign canonical JSON, produce raw r‖s
- [ ] `envelope.ts`: ECDH + HKDF + AES-GCM matching the server exactly; decrypt responses
- [ ] `canonical.ts`: same canonicalization; run the shared vectors in Vitest

## Tests
- Known-answer vectors both directions (WebCrypto → Python and Python → WebCrypto)
- Negative: flipped bit, wrong AAD, wrong key, replayed nonce, skewed ts, revoked device, expired cert, wrong-role cert, edited audit row
- MPIN lockout: 3 failures → locked; unlock after window

## Phase Gate
- ☐ Interop test: browser-encrypted envelope decrypts on the server and vice versa
- ☐ Every negative test fails with the specific audited reason
- ☐ Audit verify detects a manually tampered row and reports the exact `seq`
- ☐ Private device key is non-extractable (test attempts `exportKey` and expects failure)
- ☐ `mypy --strict` clean on `app/crypto`
- ☐ `PROGRESS.md` updated
