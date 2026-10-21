# 03 — System Architecture

## Style
**Modular monolith.** One FastAPI process, four internal modules that mirror real UPI parties.
Modules may only communicate through `messaging/` (signed + MAC'd message objects), never by
importing each other's internals. This keeps the simulation honest and lets any module be split
into its own container later without redesign.

## The four parties

```
┌────────────┐  TLS + app-layer      ┌────────┐  ECDSA-signed   ┌──────────┐  HMAC-SHA256   ┌────────┐
│ Client App │  ECDH+AES-GCM envelope│  PSP   │  message        │  Switch  │  service MAC   │  Bank  │
│ (browser)  │ ────────────────────▶ │(psp/)  │ ──────────────▶ │(switch/) │ ─────────────▶ │(bank/) │
│ WebCrypto  │  + device ECDSA sig   │ authN  │  PSP cert chain │ routing  │                │ ledger │
└────────────┘ ◀──────────────────── └────────┘ ◀────────────── └──────────┘ ◀───────────── └────────┘
        encrypted + bank-signed receipt flows back along the same path
```

| Party | Real-world analogue | Responsibilities here |
|---|---|---|
| Client App | PhonePe/GPay app | Holds device key, builds + signs payment, encrypts envelope, shows Security Lens |
| PSP (`psp/`) | Payment service provider | Auth (JWT), decrypt envelope, verify device signature, verify MPIN, replay checks |
| Switch (`switch/`) | NPCI UPI switch | Verify PSP signature + cert, resolve VPA → bank account, route, enforce limits |
| Bank (`bank/`) | Remitter/beneficiary bank | Atomic double-entry posting, balance checks, signed receipt, hash-chained ledger |

## Repository layout

```
mini-upi/
├─ AGENTS.md                 # points agents to brain/
├─ brain/                    # this folder (specs, phases, progress)
├─ docker-compose.yml
├─ .env.example
├─ backend/
│  ├─ pyproject.toml
│  ├─ alembic/               # migrations
│  ├─ app/
│  │  ├─ main.py             # app factory, router wiring
│  │  ├─ core/               # config, db session, logging, errors, deps
│  │  ├─ identity/           # users, depts, classes, auth, RBAC, devices
│  │  ├─ psp/                # payment ingress, MPIN, envelope handling
│  │  ├─ switch/             # routing, limits, VPA directory
│  │  ├─ bank/               # accounts, ledger, receipts
│  │  ├─ crypto/             # kdf.py, signing.py, envelope.py, hmac_.py, chain.py, pki.py
│  │  ├─ messaging/          # message schemas, canonical JSON, sign/verify helpers
│  │  ├─ audit/              # hash-chained audit log + verifier
│  │  └─ admin/              # CSV import, top-up, freeze
│  ├─ tests/
│  └─ security_tests/        # attack demo scripts
├─ web/
│  ├─ src/
│  │  ├─ design/             # tokens.css, base.css, motion.css
│  │  ├─ crypto/             # webcrypto wrappers (keygen, sign, envelope)
│  │  ├─ features/           # auth, wallet, pay, collect, history, admin, lens
│  │  ├─ components/         # hand-written UI primitives
│  │  └─ app/                # routes, providers
│  └─ index.html
├─ scripts/                  # seed data, backup, restore, load test
└─ docs/                     # report, seminar deck outline, diagrams
```

## Module rules
1. `identity` may be imported by anyone for the `current_user` dependency only.
2. `psp → switch → bank` is a one-way call chain through `messaging/`.
3. `bank` is the only module allowed to write `ledger_entries`, `wallets`, `audit_log`.
4. `crypto/` is pure functions with no database access, fully unit-tested.
5. No module logs or returns secrets; error messages never reveal which factor failed
   (generic "authentication failed" for login/MPIN).

## Payment sequence (authoritative)

1. **Client** builds payload `{txn_id, payer_vpa, payee_vpa, amount_paise, note, nonce, ts}`.
2. Client canonicalizes JSON, **signs with device ECDSA key** → `device_sig`.
3. Client builds inner message `{payload, device_sig, mpin}` and **encrypts** it in an envelope:
   ephemeral ECDH P-256 key + server static public key → HKDF-SHA256 → AES-256-GCM
   (AAD = `txn_id || ts`). Sends `{eph_pub, iv, ciphertext, tag}` with the JWT.
4. **PSP** verifies JWT, decrypts, checks `ts` window (±60 s) and nonce uniqueness,
   verifies `device_sig` against the registered device public key,
   verifies MPIN (Argon2id + pepper, lockout after 3 failures / 15 min).
5. PSP creates a **PSP-signed message** (ECDSA with PSP key, includes PSP cert) and hands it to the Switch.
6. **Switch** verifies the PSP cert chain (mini-CA) + signature, resolves payee VPA → bank account,
   applies limits (per-txn, daily), and calls the Bank with an **HMAC-SHA256** service MAC.
7. **Bank** verifies MAC, opens one DB transaction: lock both wallets in id order, check balance,
   write two ledger entries (debit/credit), append hash-chain audit entry, commit.
8. Bank returns a **bank-signed receipt**. Receipt travels back; PSP encrypts it to the client
   using the same session key (fresh IV). Client verifies the bank signature and stores the receipt.

## Failure behaviour
- Any verification failure → request rejected, audit event written (without secrets), generic error to client.
- Idempotency: the same `txn_id` returns the original result and never double-posts.
- Bank step is atomic; PSP/Switch hold no money state.

## Observability
- Structured logs with a `request_id` and `txn_id` on every line.
- `/health` (liveness) and `/ready` (DB reachable, keys loaded).
- Metrics endpoint optional in Phase 7.
