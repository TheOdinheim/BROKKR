# Reports Index

Phase reports, readiness reports, and other standalone records produced during the
BROKKR build. Per CLAUDE.md Section 8, this index is appended to, never rewritten.
Every report is a new dated file; corrections are annotations, not edits.

| Date | Round | Phase | Scope | Verdict | Link |
|---|---|---|---|---|---|
| 2026-07-13 | R1 | 0 | Readiness: import proof, context cost, structure, toolchain | Complete; DAP approved | [READINESS-2026-07-13-R1.md](READINESS-2026-07-13-R1.md) |
| 2026-07-14 | R2 | 0.5 | Re-readiness + conformance check of BROKKR-ARCH Rev 1.1 against the corpus; crypto prerequisite; v1.3 checkpoint-commit rule | Build stopped on 8 ABSENT findings (GAP-2026-07-14-001); awaiting DAP disposition | [READINESS-2026-07-14-R2.md](READINESS-2026-07-14-R2.md) |
| 2026-07-14 | R1 | 1 | Built `brokkr-core`: governance types, invariants I-1…I-12 encoded by construction, negative tests, conformance check | Complete; builds --locked, 11 runtime + 9 compile-fail tests pass; 0 absent findings; awaiting DAP review; not committed | [PHASE-1-2026-07-14-R1.md](PHASE-1-2026-07-14-R1.md) |
| 2026-07-15 | R2 | 1 | `brokkr-core` proof-rigor revision: pinned compile-fail error codes; closed I-1 sole-construction-path proof (+ no-Clone) | Complete; 12 runtime + 10 compile-fail tests pass, all codes pinned; not committed | [PHASE-1-2026-07-14-R2.md](PHASE-1-2026-07-14-R2.md) |
| 2026-07-15 | REV-R1 | 1 | AMD-008/009 core-type revision: attempted | BLOCKED before building — two instruction premises (`RiskAcceptance` present; `Classification` has a `personal` field) contradict the source; reported with evidence, awaiting DAP resolution | [PHASE-1-REV-2026-07-15-R1.md](PHASE-1-REV-2026-07-15-R1.md) |
| 2026-07-15 | REV-R2 | 1 | AMD-008/009 core types WRITTEN: risk.rs (Risk Register + RiskAcceptance created) + personal_data.rs (Purpose, RetentionPeriod) | Complete; builds --locked, 12+6 tests + 11 doctests pass, clippy clean; RiskAcceptance created (was absent), classification.rs untouched; not committed | [PHASE-1-REV-2026-07-15-R2.md](PHASE-1-REV-2026-07-15-R2.md) |
| 2026-07-16 | R1 | 2 | `brokkr-crypto` — hand-written wolfCrypt FFI: ML-DSA, SLH-DSA, ML-KEM, SHA-384, AES-256-GCM, dual-family signing, crypto-shred | Complete; links real .so, 6 real round-trip tests pass, clippy clean, non-FIPS stated; ML-DSA symbol-name + R-4 entropy findings flagged; not committed | [PHASE-2-2026-07-16-R1.md](PHASE-2-2026-07-16-R1.md) |
| 2026-07-16 | R1 | 3 | `brokkr-intent` (SKULD) — canonical serialization, real dual-family signing, SHA-384 hash-linking, freshness, cryptographically-enforced attenuation | Complete; builds --locked, 8 tests pass (real crypto), clippy clean, no unsafe, I-5/I-6 hold; 0 absent; added workspace .cargo/config.toml rpath; not committed | [PHASE-3-2026-07-16-R1.md](PHASE-3-2026-07-16-R1.md) |
| 2026-07-17 | REV-R1 | 2 (rev) | `brokkr-crypto` DualPublicKey — public-key-only dual-family verification (export/import raw public keys); closes Phase 4 blocker RISK-2026-0003 | Complete; additive, builds --locked, 4 new + 6 existing tests pass, clippy clean, unsafe only in ffi.rs; not committed | [PHASE-2-REV-2026-07-17-R1.md](PHASE-2-REV-2026-07-17-R1.md) |
