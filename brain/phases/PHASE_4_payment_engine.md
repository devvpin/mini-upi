# PHASE 4 — Payment Engine

**Goal:** the full Client → PSP → Switch → Bank pipeline with every control from `03` and `05`.
**Read:** 03 (sequence), 05, 06 (Payments).

## Tasks
- [ ] `messaging/`: message schemas (`PspToSwitch`, `SwitchToBank`, `BankReceipt`), canonicalisation, sign/MAC helpers
- [ ] `psp/`: `POST /payments/pay`
  1. verify JWT → decrypt envelope → check ts window + nonce → verify device signature → verify MPIN
  2. build PSP-signed message and call Switch (in-process through `messaging/`)
- [ ] `switch/`: verify PSP cert + signature + role, resolve VPA → account, enforce limits, call Bank with HMAC
- [ ] `bank/`: verify MAC, `post_transfer`, append audit entry (same DB transaction), sign receipt
- [ ] Return encrypted receipt; client-side verification target documented for Phase 5
- [ ] Collect requests: create, list incoming, approve (runs the same pay flow), decline, expire (background job)
- [ ] QR payload format: `miniupi://pay?vpa=<handle>&am=<paise>&tn=<note>&sig=<optional HMAC for static merchant QR>`
- [ ] Audit events: PAY_OK, PAY_REJECTED(reason), MPIN_FAIL, DEVICE_REJECTED, REPLAY_DETECTED, TOPUP, FREEZE
- [ ] `GET /transactions/{id}` returns Security Lens data (signature status, cert subject, hashes, chain seq)
- [ ] Failure injection hooks (test-only flag) for the demo: corrupt ciphertext, corrupt signature, replay

## Tests
- End-to-end happy path (Python client simulating the browser)
- One test per rejection reason with the exact error code and audit entry
- Idempotent retry after a simulated network failure after Bank commit
- Concurrency: 50 users paying each other simultaneously → ledger and audit chain still verify
- No endpoint returns plaintext MPIN/signature internals to other users

## Phase Gate
- ☐ Happy path completes and ledger + audit verify OK
- ☐ Every rejection scenario fails closed, writes an audit event, leaks no detail to the client
- ☐ Stolen JWT without the device key cannot pay (test)
- ☐ Retry with the same `txn_id` returns the original receipt
- ☐ Load test: 200 simulated users, p95 pay latency < 800 ms on a 2-vCPU VM
- ☐ `PROGRESS.md` updated
