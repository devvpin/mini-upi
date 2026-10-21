# Mini-UPI threat model

Mini-UPI is a virtual campus-points simulation; no real payment rail is connected.

| Asset | STRIDE threat | Control | Demonstration/test |
|---|---|---|---|
| Password and MPIN | Credential disclosure / elevation | Argon2id peppered hashes, dummy verification, three-strike lockout | `test_phase1.py`, MPIN rejection tests |
| Device private key | Spoofing / information disclosure | Non-extractable WebCrypto ECDSA key in IndexedDB | Browser crypto tests |
| Payment payload | Tampering / repudiation | Canonical JSON, device ECDSA, AES-GCM envelope and AAD | Phase 3/4 rejection tests |
| Nonce and transaction ID | Replay | Timestamp window, unique nonce, idempotent transaction | Replay rejection tests |
| PSP message | Spoofing / tampering | CA-signed PSP certificate and ECDSA signature | PKI tests |
| Switch-bank message | Tampering | HMAC-SHA256 service MAC | Messaging tests |
| Wallet and ledger | Tampering / repudiation | Atomic double-entry transaction and database constraints | Ledger invariant tests |
| Receipt | Forgery | Bank ECDSA signature and client verification | Receipt tests and Security Lens |
| Audit chain | Tampering | Hash chain, HMAC, append-only trigger | Audit verification tests |
| VPA directory | Information disclosure / denial of service | Masked names and 30/min lookup limit | Phase 2 rate-limit test |
| API surface | XSS / clickjacking / CSRF | CSP, HSTS, frame denial, strict CORS | Phase 6 header tests |
| Secrets and logs | Information disclosure | Ignored secret files, structured redacted logs | Repository and logging review |
