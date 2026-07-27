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
