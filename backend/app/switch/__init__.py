"""
switch — NPCI-like routing switch.

Verifies PSP certificates (mini-CA chain), resolves payee VPA to a bank
account, enforces transaction limits, and forwards to the bank module
with an HMAC-SHA256 service MAC.

Crypto concept: X.509 certificate chain verification, HMAC service channel.
Threat mitigated: rogue PSP injection, VPA spoofing, limit bypass.

Implemented in Phase 4.
"""
