# brain/ — how to use this folder

This folder is the single source of truth for building Mini-UPI with an AI coding agent
(Antigravity, Codex, or similar).

## Start
1. Create an empty repo, copy this whole `brain/` folder and the root `AGENTS.md` into it.
2. Open the repo in your agent. Give it this one prompt:

> Read `brain/00_MASTER_PROMPT.md` and follow it exactly. Start with the phase marked IN PROGRESS in `brain/PROGRESS.md`.

3. When the agent reports "Phase N complete", review it, run the gate yourself, then say:

> Phase N approved. Mark it done in PROGRESS.md and start Phase N+1.

## Files
| File | Purpose |
|---|---|
| 00_MASTER_PROMPT | Rules, decisions, phase list, working loop |
| 01_PROJECT_BRIEF | What and for whom, scale, roles, non-goals |
| 02_TECH_STACK | Stack and reasoning |
| 03_ARCHITECTURE | Four-party design, repo layout, payment sequence |
| 04_DATABASE_SCHEMA | Tables and invariants |
| 05_CRYPTO_DESIGN | Every crypto mechanism mapped to a threat |
| 06_API_SPEC | Endpoints, limits, error codes |
| 07_UI_DESIGN_SYSTEM | Pollinations-inspired "Hive" design system |
| 08_AGENT_RULES | Standards and hard stops |
| phases/ | Eight phase checklists with gates |
| reference/ | `schema.sql`, `docker-compose.yml`, `env.example` |

## Tips
- Keep one phase per agent session to avoid context drift.
- If the agent drifts, tell it: "Re-read brain/ and PROGRESS.md, then continue the current phase."
- You must be able to explain every file. After each phase, ask the agent: "Walk me through what you built and which crypto concept each file shows."
