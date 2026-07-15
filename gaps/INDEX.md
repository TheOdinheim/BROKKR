# Amendment-Gap Index

Amendment-gap reports filed under CLAUDE.md Section 4. When the framework does not
cover a situation, the build STOPS, the gap is reported to the DAP, a recommendation
is stated, and work waits. Each gap is a dated file; this index is appended to,
never rewritten.

| Date | ID | Phase | Summary | Recommendation | Status | Link |
|---|---|---|---|---|---|---|
| 2026-07-14 | GAP-2026-07-14-001 | 0.5 | Eight OQGF-1.0 Organ requirements (G-7, I-1, I-2, I-5, M-5, M-6, R-6, A.6.1) neither specified nor declared n.a. in the architecture | DAP to declare n.a., add a hook, or defer — placed as an architecture revision | OPEN — build stopped | [GAP-2026-07-14-001.md](GAP-2026-07-14-001.md) |
| 2026-07-15 | GAP-2026-07-15-001 | 1 | brokkr-core missing type-level obligations from AMD-008/009: Risk Register surface (RiskRegister/RiskEntry/Disposition/TreatmentPlan + RiskAcceptance into core) and personal-data classification dimension | DAP to approve a Phase 1 revision (R3) scoped to those types; settle RiskAcceptance placement and the personal-data dimension surface | CLOSED — types written (risk.rs, personal_data.rs); RiskAcceptance created in core; builds --locked, tests pass | [GAP-2026-07-15-001.md](GAP-2026-07-15-001.md) |
