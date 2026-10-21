# Mini-UPI project report

## Abstract

Mini-UPI is a secure campus payment **simulation**. It uses virtual points, not
real money, cards, banks, or payment gateways. The project demonstrates how
authentication, device binding, authenticated encryption, signatures, service
trust, and an auditable ledger work together.

## Architecture

The browser client sends an ECDH/AES-GCM envelope to the PSP. The PSP verifies
the JWT, timestamp, nonce, device signature, and MPIN. It signs a message to
the Switch, which verifies the mini-PKI certificate, resolves the VPA, checks
limits, and authenticates the Switch-to-Bank HMAC. The Bank atomically posts
double-entry ledger rows, appends a hash-chain audit record, and returns a
signed receipt.

## Crypto mapping

| Feature | Mechanism | Threat |
|---|---|---|
| Password/MPIN | Argon2id + pepper | Offline cracking |
| Device binding | Non-extractable ECDSA P-256 | Stolen token |
| Payment payload | Canonical JSON + ECDSA | Tampering/repudiation |
| Envelope | ECDH, HKDF, AES-256-GCM | Disclosure/tampering |
| Service trust | X.509 mini-PKI and HMAC | Rogue internal service |
| Receipt | Bank ECDSA signature | Forged success |
| Audit | SHA-256 chain + HMAC | Silent history edits |

## Results and limitations

The PostgreSQL payment deployment benchmark completed 200 payments at p95
231.12 ms, below the 800 ms target. Backend regression tests, browser tests,
attack demonstrations, and the Lighthouse accessibility audit passed.

This is simulation-grade key management: secrets are mounted files, not HSMs;
there is no real UPI/NPCI integration, KYC, refund rail, or regulatory claim.
Production deployment would add HSM-backed keys, rotation ceremonies, managed
observability, backups off-host, and independent penetration testing.
