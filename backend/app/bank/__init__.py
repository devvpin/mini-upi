"""
bank — Remitter/beneficiary bank module (ledger, wallets, receipts).

The only module that writes financial rows (ledger_entries, wallets,
audit_log). Executes atomic double-entry postings with SELECT … FOR UPDATE,
produces bank-signed receipts, and maintains the hash-chained audit log.

Crypto concept: ECDSA receipts, SHA-256 hash chain, HMAC audit integrity.
Threat mitigated: double-spend, balance tampering, silent history edits.

Implemented in Phase 2-4.
"""
