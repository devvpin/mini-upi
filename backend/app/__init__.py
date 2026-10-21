"""
Mini-UPI Backend — Secure Campus Payment Simulation.

This package contains the FastAPI application simulating a UPI payment system.
All money is virtual campus points. No real payments are processed.

Crypto concept: modular monolith where each sub-package (psp, switch, bank)
mirrors a real UPI party and communicates through signed/encrypted messages.

Threat mitigated: clear module boundaries prevent privilege leaks between parties.
"""
