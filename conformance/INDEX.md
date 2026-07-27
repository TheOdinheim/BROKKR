# Conformance-Check Index

Conformance checks under CLAUDE.md Section 5.3. Each check enumerates normative
requirements from the governance corpus (the ground truth) and audits the subject
(the architecture, or later a built crate) against them, requirement by requirement.
Ground truth is never the subject's own traceability table. This index is appended
to, never rewritten.

| Date | Round | Phase | Subject | Scope | satisfied | partial | absent | n.a. | Link |
|---|---|---|---|---|---|---|---|---|---|
| 2026-07-14 | R1 | 0.5 | BROKKR-ARCH Rev 1.1 | Full corpus: OQGF-1.0 + AMD-001…007, 85 numbered normative requirements | 52 | 16 | 8 | 9 | [CONF-2026-07-14-P0.5-R1.md](CONF-2026-07-14-P0.5-R1.md) |
| 2026-07-14 | R1 | 1 | Built crate `brokkr-core` | Corpus requirements whose type-shape is in-scope for brokkr-core + invariants I-1…I-12 | 11 (+9 inv) | 17 | 0 | 2 | [CONF-2026-07-14-P1-R1.md](CONF-2026-07-14-P1-R1.md) |
| 2026-07-15 | R2 | 1 | `brokkr-core` proof-rigor revision | Pin error codes on all 10 compile-fail doctests; close I-1 sole-construction-path proof | — | — | 0 | — | [CONF-2026-07-14-P1-R2.md](CONF-2026-07-14-P1-R2.md) |
| 2026-07-15 | DELTA-R1 | 1 | `brokkr-core` vs AMD-008/AMD-009 (OQGF-P-10, P-11) | Type-level delta: A/B/C sort of all 13 new requirements | 0 (A) | — | 5 (bucket B) | 8 (bucket C) | [CONF-2026-07-15-P1-DELTA-R1.md](CONF-2026-07-15-P1-DELTA-R1.md) |
| 2026-07-15 | DELTA-R2 | 1 | `brokkr-core` vs AMD-008/009, POST-BUILD | Re-sort with types real; file:line citations; build/test/clippy output | 6 (A, core-shape) | — | 0 | 7 (bucket C, Phase 2/5/6/7) | [CONF-2026-07-15-P1-DELTA-R2.md](CONF-2026-07-15-P1-DELTA-R2.md) |
| 2026-07-15 | R1 | 2 | Built crate `brokkr-crypto` (wolfCrypt FFI) | G-1, G-5, R-1, R-4, G-7, P-11.5 crypto-shred — real round-trips vs the real .so | 4 | 2 | 0 | — | [CONF-2026-07-15-P2-R1.md](CONF-2026-07-15-P2-R1.md) |
| 2026-07-16 | R1 | 3 | Built crate `brokkr-intent` (SKULD) | AMD-001 §AMD.1 M-8…M-14 (quoted) + P-10/P-11 n.a.; real dual-family chain | 2 | 3 | 0 | 4 | [CONF-2026-07-16-P3-R1.md](CONF-2026-07-16-P3-R1.md) |
| 2026-07-17 | REV-R1 | 2 (rev) | `brokkr-crypto` DualPublicKey — public-key-only verification | M-8 public-roots-of-trust capability, R-1, G-5; closes RISK-2026-0003 blocker | 3 | 0 | 0 | — | [CONF-2026-07-17-P2-REV-R1.md](CONF-2026-07-17-P2-REV-R1.md) |
| 2026-07-20 | REV-R1 | 3 (rev) | `brokkr-intent` `verify_chain_public` — public-key chain verification | M-8 (chain-verifier side), M-9 & M-14 preserved, behavior preservation; further reduces RISK-2026-0003 | 4 | 0 | 0 | — | [CONF-2026-07-20-P3-REV-R1.md](CONF-2026-07-20-P3-REV-R1.md) |
| 2026-07-24 | R1 | 4 | Committed core surface vs OQGF-M-11 (SINDRI pre-build audit) | M-11, M-8, M-9, M-10, M-14, M-1 (quoted) + P-10/P-11 n.a.; buildability of `evaluate` from committed types | 0 (3 buildable-not-built) | 3 | 2 clauses | 2 | [CONF-2026-07-24-P4-R1.md](CONF-2026-07-24-P4-R1.md) |
| 2026-07-24 | R2 | 4 | Built crate `brokkr-gate` (SINDRI) under ARCH Rev 1.3 | M-11, M-1, M-8, M-9, M-14, M-10 (quoted), M-12/M-13/P-10/P-11 n.a.; I-1/I-5/I-6; Signals 1-2 enforced, conjuncts 3-4 structurally unreachable | 3 (M-8 gate-half, M-9, M-14) + I-1/5/6 | 3 (M-11, M-1, M-10) | 0 | 3 (+M-13 traced) | [CONF-2026-07-24-P4-R2.md](CONF-2026-07-24-P4-R2.md) |
