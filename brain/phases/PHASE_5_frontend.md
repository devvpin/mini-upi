# PHASE 5 — Frontend (Hive UI)

**Goal:** the complete, polished, hand-written UI from `07_UI_DESIGN_SYSTEM.md`.
**Read:** 07, 06, and `web/src/crypto` from Phase 3.

## Rules
- No UI kit or template. Every component hand-written with CSS modules + tokens.
- Mobile first at 360 px; verify at 768 and 1280 (projector layout).
- Keyboard + screen-reader support on every interactive element.

## Tasks
- [ ] Base styles: tokens, reset, typography, hex background, grain, simulation ribbon
- [ ] Primitives: Button, IconButton, Card, Chip, Input, OtpInput, AmountPad, Sheet, Toast, Skeleton, Avatar, QRCard, Timeline, HashBlock, Banner, EmptyState
- [ ] Auth flow: login → change password → set MPIN → bind device (wizard with one-line explanations)
- [ ] Home: balance hero, quick actions, recent activity
- [ ] Pay: VPA input / QR scan → payee confirm → amount pad → MPIN sheet → animated success/failure; builds, signs, encrypts, sends, decrypts, **verifies the bank receipt signature**
- [ ] Request money + incoming requests inbox
- [ ] History with day grouping, filters, detail drawer
- [ ] **Security Lens** panel (all fields listed in `07`), including demo-mode tamper toggle
- [ ] Profile & devices (revoke), QR card
- [ ] Admin: CSV import with dry-run preview, top-up, freeze, audit verify with chain visual, stats
- [ ] Error and empty states for every screen; offline banner
- [ ] Vitest unit tests for crypto + amount pad; one Playwright happy-path smoke test

## Phase Gate
- ☐ Full flow works in the browser: login → bind device → pay → receipt verified → Security Lens shows all fields
- ☐ Tamper toggle produces a visible, correct rejection
- ☐ Lighthouse accessibility ≥ 95 on Home and Pay
- ☐ Contrast checks pass; works at 360 px with no horizontal scroll
- ☐ `prefers-reduced-motion` respected
- ☐ Bundle contains no UI-kit dependency (check `package.json`)
- ☐ `PROGRESS.md` updated
