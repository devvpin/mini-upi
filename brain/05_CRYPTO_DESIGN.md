# 05 — Cryptographic Design

This file is the heart of the course submission. Every row maps to a lecture topic.

## Mapping table (use directly in the report and seminar)

| Feature | Mechanism | Library | Threat mitigated |
|---|---|---|---|
| Password + MPIN storage | Argon2id, per-user salt, server pepper (HMAC-SHA256 pre-hash) | argon2-cffi | DB leak, rainbow tables, GPU cracking |
| Device binding | ECDSA P-256 keypair generated in browser, non-extractable | WebCrypto | Stolen token used from another device |
| Transaction signature | ECDSA-SHA256 over canonical JSON | WebCrypto / cryptography | Tampering, repudiation |
| App-layer confidentiality | ECDH P-256 → HKDF-SHA256 → AES-256-GCM | WebCrypto / cryptography | Eavesdropping, TLS-stripping, payload tampering |
| Replay protection | Nonce table + ±60 s timestamp window + idempotent `txn_id` | Postgres | Replay of captured request |
| PSP → Switch trust | ECDSA signature + X.509 cert from mini-CA | cryptography | Rogue PSP, message forgery |
| Switch → Bank integrity | HMAC-SHA256 with per-service key | stdlib `hmac` | Internal message tampering |
| Receipts | Bank ECDSA signature, verified in client | cryptography / WebCrypto | Forged "payment successful" |
| Audit trail | SHA-256 hash chain + HMAC per entry | hashlib / hmac | Silent edits to history |
| Transport | TLS 1.3 via Caddy | Caddy | Network sniffing, MITM |
| Sessions | Short-lived JWT + rotating refresh token (hashed at rest) | PyJWT | Token theft window |

## 1. Password and MPIN hashing
- Argon2id parameters (tune on target VM, floor shown): `time_cost=3`, `memory_cost=64 MiB`, `parallelism=2`.
- Pre-hash: `HMAC-SHA256(PEPPER, secret)` then Argon2id. Pepper lives in env/secret file, not DB.
- MPIN is 6 digits (low entropy) → **the lockout is the real defence**: 3 failures → lock 15 min,
  exponential back-off after repeated locks, every failure audited.
- Constant-time comparison; same error and similar timing for unknown user vs wrong secret
  (verify against a dummy hash when the user doesn't exist).

## 2. Device binding
- On first login the browser generates ECDSA P-256 with `extractable: false`, stores the `CryptoKey`
  in IndexedDB, and sends the public key (JWK) to `POST /devices/register` (needs password + MPIN setup).
- Server stores the public key; a payment is valid only if the signature verifies against **an active
  device of that user**. A stolen JWT alone cannot pay.
- Admin or user can revoke a device.

## 3. Canonical JSON (for signing)
- UTF-8, keys sorted lexicographically, no insignificant whitespace, integers only (no floats),
  strings NFC-normalized. Both client and server use the same documented function; include
  cross-language test vectors in `backend/tests/vectors/canonical.json` and `web/src/crypto/__tests__`.

## 4. Envelope encryption (app layer)
```
client: (e_priv, e_pub) = ECDH P-256 ephemeral
        shared = ECDH(e_priv, server_static_pub)
        key    = HKDF-SHA256(shared, salt = random 16B, info = "miniupi/v1/envelope", L = 32)
        ct,tag = AES-256-GCM(key, iv = random 12B, plaintext, AAD = txn_id || ts)
send:   { v:1, eph_pub, salt, iv, ct, tag, txn_id, ts }
server: same derivation with server_static_priv + eph_pub; reject on tag failure
reply:  encrypt with the same key, fresh random 12B IV, AAD = txn_id || "resp"
```
- Never reuse an IV with a key. Random 96-bit IVs are fine for one-request keys (each request has a fresh ephemeral key).
- Server static key is published at `GET /crypto/server-key`, **signed by the mini-CA**; the client pins the CA public key.
- Version field `v` allows future algorithm changes.

## 5. Replay and ordering
- Reject if `|now - ts| > 60 s`.
- Insert `nonce` into `used_nonces` (unique). Conflict → reject.
- `txn_id` is idempotency key: repeat returns the stored result.

## 6. Mini PKI
- A root CA key is created offline by `scripts/pki/make_ca.py` (kept outside the repo).
- Issues certs for PSP, Switch, Bank (role in subject; 1-year validity).
- Switch verifies: signature chain, validity, role == `PSP`. Bank verifies Switch similarly or via HMAC.
- Show certificate inspection and rejection of an expired/wrong-role cert in the demo.

## 7. HMAC service channel (Switch → Bank)
- `mac = HMAC-SHA256(K_switch_bank, canonical(message) || ts || msg_id)`; constant-time verify.
- Keys from env; rotate by adding `key_id` to the message.

## 8. Hash-chained audit log
```
entry_hash = SHA256( prev_hash || canonical(event) || created_at_iso )
entry_hmac = HMAC(K_audit, entry_hash)
```
- Genesis `prev_hash = 32 zero bytes`.
- DB trigger forbids UPDATE/DELETE on `audit_log`.
- `POST /audit/verify` (admin) walks the chain and returns `{ok, head_hash, checked, first_bad_seq}`.
- Demo: manually edit a row as DB superuser → verification pinpoints the broken `seq`.

## 9. Key management (simulation-grade, be honest in the report)
- Keys come from environment/secret files mounted in Docker; no HSM.
- Document in the report what a real system would add: HSMs, key ceremonies, rotation, split knowledge.

## 10. What we deliberately do NOT do
- No custom ciphers, no home-made KDFs, no RSA-PKCS1v1.5 encryption, no MD5/SHA-1, no ECB.
- No storing MPIN/passwords reversibly. No logging of secrets or full tokens.
- No claim of PCI/NPCI compliance.

## Test requirements
- Known-answer tests for HKDF/AES-GCM interop between WebCrypto and Python.
- Negative tests: flipped ciphertext bit, wrong AAD, wrong signature, expired timestamp, reused nonce,
  revoked device, wrong-role cert, tampered audit row. Each must fail with a specific audited reason.
