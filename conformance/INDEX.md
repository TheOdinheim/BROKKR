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
