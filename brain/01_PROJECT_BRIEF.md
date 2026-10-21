# 01 — Project Brief

## Title
Secure Campus UPI-Based Payment Simulation System (Mini-UPI)

## One-line clarification (put this in the report and on the UI)
This project simulates the UPI payment process using virtual wallet balances to demonstrate
cryptographic security, and does not perform or complete any real money transfer.

## Course
Information Network Security (Cryptography). Seminar topic (separate deliverable):
*Cryptographic Architecture of the Unified Payments Interface (UPI)*.

## Users and scale
- ~1,000–1,100 students in years 1–2 (17 classes), ~1,300–1,400 in years 3–4 (22 classes)
- ~165–200 faculty across 11 departments
- ~2,500–3,000 accounts total. Peak load is tiny: design for 50 concurrent users, test at 200.

## Roles
| Role | Can do |
|---|---|
| student | log in, bind device, pay/request, view own history |
| faculty | same as student + view own class/department reports (read-only, no other users' balances) |
| admin | import users, top-up from treasury, freeze accounts, run audit verification |
| auditor (optional) | read-only audit and chain verification |

## Core features
1. Campus hierarchy: Department → Class → Student; Department → Faculty
2. Account: login, MPIN, device binding, VPA, virtual wallet
3. Payments: pay by VPA, pay by QR, collect request (request money), transaction history
4. Admin: CSV bulk import, treasury top-up, freeze/unfreeze, audit chain verification
5. Security Lens (UI): shows signature, nonce, ciphertext size, hash-chain link for any transaction

## Non-goals
Real money, real bank/NPCI integration, KYC, mobile native app, push notifications, refunds/chargebacks
(optional reversal as stretch), multi-currency.

## Success criteria for the course
- Live demo of a payment with the Security Lens open
- Live demo of at least three attacks failing
- Clear mapping table: *feature → cryptographic concept → threat mitigated* (see `05_CRYPTO_DESIGN.md`)
