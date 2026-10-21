# Seminar outline: UPI cryptography and Mini-UPI

1. UPI actors: customer app, PSP, switch, issuer/remitter bank, beneficiary bank.
2. Trust boundaries: device, transport, service-to-service, ledger, receipt.
3. Real-world concepts: public-key signatures, TLS, HMAC, replay windows,
   idempotency, authorization, fraud monitoring, and auditability.
4. Mini-UPI mapping: Client → PSP → Switch → Bank is simulated in one modular
   monolith, with the same message boundaries.
5. Attacks: phishing and token theft are reduced by device binding; replay by
   nonce/timestamp; tampering by AES-GCM and signatures; brute force by
   Argon2id and lockout; directory scraping by masking and rate limits.
6. Limits: this project does not claim NPCI, PCI, banking, or regulatory
   compliance and does not move real funds.
