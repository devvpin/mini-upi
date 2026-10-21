# 07 — UI Design System ("Hive" look, inspired by Pollinations.ai)

Goal: a bold, dark, playful-technical interface in the spirit of pollinations.ai — near-black canvas,
one electric lime/yellow accent, chunky rounded shapes, big confident type, lots of breathing room.
**Inspired by, not copied:** write all CSS and SVG from scratch; do not reuse their assets, logos or code.
No UI kit, no dashboard template.

## Principles
1. **Dark first.** Light theme optional in Phase 6.
2. **One accent.** Lime is for the single most important action on screen.
3. **Big type, few words.** Amounts are the hero. Labels are quiet.
4. **Chunky and friendly.** Large radii, soft borders, glassy cards, subtle grain.
5. **Show the crypto.** Security is a feature: the Security Lens makes it visible and presentable.
6. **Mobile first** (360 px), scales to a projector-friendly desktop layout.

## Design tokens (`web/src/design/tokens.css`)
```css
:root {
  /* surface */
  --bg-0: #0a0a0c;          /* app background */
  --bg-1: #121216;          /* cards */
  --bg-2: #1a1a20;          /* raised / inputs */
  --line: rgba(255,255,255,0.08);
  --line-strong: rgba(255,255,255,0.16);

  /* text */
  --tx-0: #f5f5f0;
  --tx-1: #b8b8b0;
  --tx-2: #7c7c76;

  /* accent (lime) */
  --accent: #d4ff3a;
  --accent-ink: #0a0a0c;    /* text on accent */
  --accent-glow: rgba(212,255,58,0.25);

  /* semantic */
  --ok: #5af0a0;
  --warn: #ffc857;
  --danger: #ff5c7a;
  --info: #7cc4ff;

  /* shape */
  --r-sm: 10px; --r-md: 18px; --r-lg: 28px; --r-pill: 999px;

  /* space (4px base) */
  --s-1: 4px; --s-2: 8px; --s-3: 12px; --s-4: 16px; --s-5: 24px; --s-6: 32px; --s-7: 48px; --s-8: 72px;

  /* type */
  --font-display: "Bricolage Grotesque", system-ui, sans-serif;
  --font-body: "Inter", system-ui, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, monospace;

  /* motion */
  --ease: cubic-bezier(.2,.8,.2,1);
  --t-fast: 120ms; --t-med: 240ms; --t-slow: 480ms;
}
```
Type scale: display 56/64, h1 36/44, h2 24/32, body 16/24, small 13/18, mono 13/20.
Amounts: `font-display`, weight 700, tabular numerals, size 56 on the pay screen.

## Signature elements
- **Hex-cell motif:** subtle hexagon pattern background on landing/login (pure SVG, low opacity).
- **Glow button:** primary button is a lime pill with a soft `--accent-glow` shadow, scales 1.02 on hover.
- **Glass card:** `background: color-mix(in srgb, var(--bg-1) 80%, transparent); backdrop-filter: blur(14px); border: 1px solid var(--line);`
- **Amount pad:** custom large numeric keypad (hand-built component), haptic-style press animation.
- **Status chips:** pill chips with a dot (ok/warn/danger).
- **Grain overlay:** 3% noise via inline SVG filter on `body::before`.
- **Simulation ribbon:** thin top bar always visible: "SIMULATION — virtual points, no real money".

## Screens
1. **Landing/Login** — big headline, hex background, college ID + password.
2. **First-run wizard** — change password → set MPIN → bind device (explain each step in one line).
3. **Home** — balance hero, quick actions (Pay, Request, Scan, History), recent activity.
4. **Pay** — VPA/QR → confirm payee (masked name) → amount pad → MPIN sheet → animated result.
5. **Request money** — create and track collect requests; incoming requests inbox.
6. **History** — grouped by day, filters, detail drawer.
7. **Transaction detail + Security Lens** — see below.
8. **Profile & Devices** — list devices, revoke, view VPA/QR.
9. **Admin** — import CSV (dry-run preview), top-up, freeze, audit verification, stats.

## Security Lens (the demo feature)
A slide-up panel on any transaction showing, in mono type with copy buttons:
- `txn_id`, `nonce`, timestamp
- Canonical payload (collapsed), **device signature** (hex, truncated) with ✔ verified status
- Envelope: ephemeral public key fingerprint, IV, ciphertext length, GCM tag ✔
- PSP cert subject + serial, Switch route, HMAC status
- Bank receipt signature ✔
- Audit chain: `seq`, `prev_hash` → `entry_hash` (visual linked blocks)
- A "Tamper test" toggle (dev/demo mode only) that flips one bit before sending so the failure path can be shown live.

## Components to hand-build (`web/src/components/`)
Button, IconButton, Card, Chip, Input, OtpInput (MPIN dots), AmountPad, Sheet (bottom drawer),
Toast, Skeleton, Avatar (initials on hex), QRCard, Timeline, HashBlock, Banner, EmptyState.
Each has a CSS module, uses only tokens, supports keyboard + screen reader (ARIA), and a visible focus ring.

## Motion
- Page transitions 240 ms fade+rise. Payment success: ring draw + confetti of hex shapes (CSS only).
- Respect `prefers-reduced-motion`.

## Accessibility
Contrast ≥ 4.5:1 for text (verify lime-on-dark and ink-on-lime). Touch targets ≥ 44 px.
Never rely on color alone for status. Forms announce errors via `aria-live`.

## Copy tone
Short, warm, plain English. Examples: "Sent ₹250 to Aarav." / "Wrong MPIN. 2 tries left."
Errors never expose which credential was wrong beyond the generic message.
