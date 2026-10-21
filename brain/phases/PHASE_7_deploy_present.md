# PHASE 7 — Deploy & Present

**Goal:** a stable deployment on a single small VM and a ready-to-present project and seminar.

## Deployment tasks
- [ ] Production `docker-compose.prod.yml`: restart policies, resource limits, healthchecks, read-only filesystems where possible
- [ ] Caddy with automatic HTTPS (public domain) or internal CA for campus LAN; HSTS enabled
- [ ] Secrets provisioning guide (env files outside the repo, file permissions)
- [ ] Nightly `pg_dump` backup + documented restore; restore tested once
- [ ] Seed production with real CSVs (departments/classes/users); distribute one-time passwords securely
- [ ] Log rotation; simple uptime check; `/ready` monitored
- [ ] Load test at 200 concurrent users (`scripts/loadtest`) with results saved

## Documentation and presentation
- [ ] `docs/REPORT.md`: abstract, simulation disclaimer, architecture, crypto mapping table, threat model, test results, limitations, future work
- [ ] `docs/DEMO_SCRIPT.md`: 10-minute live demo (login → bind device → pay with Security Lens → three attacks failing → audit tamper detection)
- [ ] Architecture and sequence diagrams exported as PNG/SVG for slides
- [ ] Seminar outline `docs/SEMINAR_UPI_CRYPTO.md`: real UPI architecture, mapping to this project, real-world attacks and mitigations
- [ ] Viva Q&A cheat sheet (≈30 questions: why Argon2id, why AES-GCM, why ECDH ephemeral, what is non-repudiation, what is replay, what the pepper adds, etc.)
- [ ] Clear limitations section: simulation-grade key management, no HSM, no real regulation

## Phase Gate
- ☐ Fresh VM → running system following only the README
- ☐ Backup restored on a second machine and ledger + audit verify OK
- ☐ 200-user load test within targets
- ☐ Demo script rehearsed end to end without errors
- ☐ Report and seminar outline complete
- ☐ `PROGRESS.md` updated — project complete
