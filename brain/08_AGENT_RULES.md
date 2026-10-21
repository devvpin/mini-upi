# 08 — Agent Rules (for Antigravity, Codex, or any coding agent)

## How to start a session
1. Read `brain/00_MASTER_PROMPT.md`, then every numbered file in `brain/`, then `brain/PROGRESS.md`.
2. Find the phase marked `IN PROGRESS`. Read its file in `brain/phases/`.
3. State the plan in ≤ 10 lines, then implement.

## Hard stops
- Do not begin a phase whose predecessor's gate has not passed.
- Do not add real payment/bank/UPI integrations or any third-party payment SDK.
- Do not add UI kits, admin templates, or component libraries.
- Do not weaken a security control to make a test pass; fix the cause.
- Do not commit secrets, `.env`, private keys, or `one_time_credentials.csv`.

## Code standards
- Python: type hints everywhere, `ruff` + `mypy --strict` on `app/crypto`, `app/bank`, `app/psp`.
- TypeScript: `strict: true`, no `any` in `src/crypto`.
- Small functions, explicit names, docstring header per module (purpose · crypto concept · threat).
- Public functions in `crypto/` are pure and have unit tests with known-answer vectors.
- Database access only through repository functions inside the owning module.
- Every endpoint has request/response models and at least one success and one failure test.

## Commit style
Conventional commits (`feat(psp): verify device signature`). One logical change per commit.

## Definition of done per task
Code + tests + docs line in `PROGRESS.md` + gate item ticked.

## Reporting format at the end of a phase
```
Phase N complete
Built: …
Run it: …
Gate: ✔ item … ✔ item … (✘ item … with reason)
Decisions/deviations: …
Next: Phase N+1
```

## If blocked
Pick the simplest safe option, log it under **Decisions** in `PROGRESS.md`, continue.
Ask the author only for branding, domain, real data, or a policy call.
