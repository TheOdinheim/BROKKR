# Test Records Index

Functionality- and verification-test records for the BROKKR build. Per CLAUDE.md
Section 8, every test run is a new dated file; this index is appended to, never
rewritten. Per Section 7, no coverage or completeness claims are made: what was
tested is stated, what was not is stated, and the numbers are left as they are.

| Date | Round | Phase | Scope | Verdict | Link |
|---|---|---|---|---|---|
| 2026-07-16 | R1 | 3 | `brokkr-intent` (SKULD) chain tests — real dual-family signing/hashing, M-9/M-10/M-14 negatives | 8 passed, 0 failed | [FUNC-2026-07-16-R1.md](FUNC-2026-07-16-R1.md) |
| 2026-07-17 | R1 | 2 (rev) | `brokkr-crypto` DualPublicKey — public-key-only verification, R-1 both-families, fail-closed + full-key-bytes tamper, import (+ 6 existing Phase 2) | 11 passed, 0 failed | [FUNC-2026-07-17-R1.md](FUNC-2026-07-17-R1.md) |
| 2026-07-20 | R1 | 3 (rev) | `brokkr-intent` `verify_chain_public` — public-key chain verification, M-8/M-9/M-14 + keypair-vs-public equivalence + fail-closed hop-key-missing (+ 8 existing Phase 3, unchanged) | 14 passed, 0 failed | [FUNC-2026-07-20-R1.md](FUNC-2026-07-20-R1.md) |
| 2026-07-24 | R1 | 4 | `brokkr-gate` (SINDRI) — costimulation: M-11 grant, M-1 resolve+bind (incl. load-bearing identity-doesn't-bind), M-14 expired, M-8 integrity (bad sig / broken link), unresolvable hop, root-only binding, I-1 never-mints | 10 passed, 0 failed | [FUNC-2026-07-24-R1.md](FUNC-2026-07-24-R1.md) |
| 2026-07-27 | R1 | 1 (rev) | `brokkr-core` genome surface (Rev 1.4) — types only; I-10 extended to new `roots`/`policy` registers (new roots-None E0308 doctest); doctests 11→12; downstream crypto/intent/gate unchanged | core: 12 unit + 6 risk_shape + 12 doc pass; workspace all green | [FUNC-2026-07-27-R1.md](FUNC-2026-07-27-R1.md) |
| 2026-07-27 | R2 | 1 (rev) | `brokkr-core` capability vocabulary (Rev 1.5) — one field `PolicyRegister::capabilities`; doctests unchanged 12→12; 3 genome E0308 doctests pass (arity 10); downstream unchanged | core: 12 unit + 6 risk_shape + 12 doc pass; workspace all green | [FUNC-2026-07-27-R2.md](FUNC-2026-07-27-R2.md) |
| 2026-07-28 | R1 | 5 | `brokkr-genome` (REGIN) — promotion gate: G-4 valid-promotes, canonical determinism/unambiguity, domain separation (highest-risk), 6 predicate negatives + Rev 1.5 narrowing-promotes + all-findings + non-circular wrong-key + I-2 no-downgrade doctest | 13 passed + 1 doctest, 0 failed | [FUNC-2026-07-28-R1.md](FUNC-2026-07-28-R1.md) |
| 2026-07-29 | R1 | 1 (rev) | `brokkr-core` barrier surface (Rev 1.6) — types only; `BoundaryFlow`→sum type + BCR/DestinationClass/ContextClass/OriginId; doctests unchanged 12→12; BarrierVerdict E0599 doctest passes; no BoundaryFlow construction anywhere; downstream unchanged | core: 12 + 6 + 12 doc pass; workspace all green | [FUNC-2026-07-29-R1.md](FUNC-2026-07-29-R1.md) |
| 2026-07-30 | R1 | 1 (rev) | `brokkr-core` Personal-Data Tag (Rev 1.7) — types only; `PersonalDataTag` + `personal` field on BoundaryFlow (both variants) + BCR; doctests unchanged 12→12; BarrierVerdict E0599 doctest passes; no BoundaryFlow/BCR construction anywhere; downstream unchanged | core: 12 + 6 + 12 doc pass; workspace all green (0 failures) | [FUNC-2026-07-30-R1.md](FUNC-2026-07-30-R1.md) |
