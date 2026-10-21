# Viva Q&A cheat sheet

1. **Why Argon2id?** Memory-hard password hashing resists GPU cracking.
2. **Why a pepper?** A secret outside the database adds a second protection layer.
3. **Why ECDSA?** Compact signatures provide authenticity and non-repudiation.
4. **Why P-256?** It is widely implemented by WebCrypto and server libraries.
5. **Why ECDH?** It establishes a shared key without sending that key.
6. **Why ephemeral ECDH?** Each request gets a fresh shared secret.
7. **Why HKDF?** It safely derives an encryption key from shared material.
8. **Why AES-GCM?** It provides confidentiality and integrity together.
9. **What is AAD?** Authenticated context such as transaction ID and timestamp.
10. **What is replay?** Reusing a captured valid request.
11. **How is replay blocked?** A unique nonce and timestamp window.
12. **Why canonical JSON?** Both languages sign identical bytes.
13. **Why a device key?** A stolen JWT alone cannot authorize a payment.
14. **Why MPIN lockout?** Six digits have low entropy; attempts must be capped.
15. **Why an X.509 certificate?** It binds a service identity to a trusted key.
16. **Why HMAC internally?** It authenticates the Switch-Bank shared channel.
17. **Why double-entry?** Every debit has an equal credit.
18. **Why lock wallets?** Concurrent payments must not double-spend.
19. **Why idempotency?** A retry after a timeout must not post twice.
20. **Why sign receipts?** A client can verify success was issued by the Bank.
21. **Why hash-chain audit rows?** Edits change the chain head and are detectable.
22. **Why HMAC the audit hash?** It prevents unkeyed chain forgery.
23. **What does CSP do?** Restricts script and resource origins.
24. **What does HSTS do?** Forces HTTPS after the browser learns the policy.
25. **Why mask VPA names?** Reduce directory enumeration and privacy leakage.
26. **What is a rate limit?** A cap on requests in a time window.
27. **Why Postgres?** ACID transactions and row locks protect the ledger.
28. **Why integer paise?** Avoid floating-point money errors.
29. **What is the biggest limitation?** Keys are file-mounted, not HSM-protected.
30. **Is this real UPI?** No; it is a virtual campus-points teaching simulation.
