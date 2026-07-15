# Conformance Delta R2 — brokkr-core against AMD-008/009, POST-BUILD verification

**Record ID:** CONF-2026-07-15-P1-DELTA-R2
**Phase:** 1 revision (`brokkr-core`) — verification after the types were written
**Date:** 15 July 2026
**Subject:** the built crate `brokkr-core` with `risk.rs` and `personal_data.rs` added.
**Ground truth:** the text of AMD-008 (OQGF-P-10.1…P-10.6) and AMD-009 (OQGF-P-11.1…P-11.7).
**Revises:** CONF-2026-07-15-P1-DELTA-R1 (the analysis; R2 is the post-build re-sort).
**Auditor:** Claude Code. **For:** Jeremy Rose, DAP — who verifies the source, not this file.

---

## 0. Two honesty caveats, stated before the table (§7)

**(1) `RiskAcceptance` was CREATED in this revision — it did not pre-exist.** The
instruction said to reuse an existing `brokkr-core::RiskAcceptance` "confirmed present."
Ground truth (`grep -rn "RiskAcceptance" brokkr-core/src/`) showed only `RiskAcceptanceId`
before this session. `RiskAcceptance` is the AMD-006 §5.1 corpus-specified type; it is now
defined **once** at `risk.rs:40` (not duplicated). This matches what `GAP-2026-07-15-001`
§3 recorded must happen. Verify the source: `brokkr-core/src/risk.rs:40`.

**(2) `classification.rs` was NOT touched and has NO `personal` field.** The instruction's
premise that "the personal tag already exists as `Classification.personal`" does not match
the source: `classification.rs:10` is a tier-only `enum Classification`, and
`grep -c personal classification.rs` = **0**. Per instruction I left it exactly as is. I
therefore did **not** cite a `Classification.personal` field (it does not exist); instead I
record the personal-data classification *dimension* as **bucket C** — carried at the
barrier (Phase 6), composing with the core tier enum — and the core *value types* the tag
carries (`Purpose`, `RetentionPeriod`) as now present in core. See P-11.1 below.

---

## 1. OQGF-P-10 (Risk Register) — re-sorted, types now real

| Req | Bucket now | Core type (file:line) — verifiable |
|---|---|---|
| P-10.1 (Register: assessed, owned, dispositioned) | **A (present)** | `risk::RiskRegister` trait `risk.rs:175`; `risk::RiskEntry` `risk.rs:159` (id/description/context/`Likelihood` `:57`/`Impact` `:67`/`owner: Dap`/`RiskSource` `:79`/`Disposition`) |
| P-10.2 (continuous identification) | **C** (behavioral; audit/sentinel/genome feed) | provenance value `risk::RiskSource` `risk.rs:79` rides on `RiskEntry`; the continuous function is Phase 7/8 |
| P-10.3 (exactly one of four dispositions; plans) | **A (present)** | `risk::Disposition` enum `risk.rs:138` {Avoid, Reduce, Transfer, Accept}; `risk::TreatmentPlan` `risk.rs:114` |
| P-10.4 (Accept carries OQGF-P-9 accountability) | **A (present)** | `Disposition::Accept { acceptance: RiskAcceptance }` `risk.rs:138`; `risk::RiskAcceptance` `risk.rs:40` (**created this revision**, gate `Some`/`None` for gate/non-gate) |
| P-10.5 (track to closure; residual re-assessed) | **A (present, type shape)** | `TreatmentStatus {Open, Executed}` `risk.rs:104`; `residual: Box<RiskEntry>` on Reduce/Transfer `risk.rs:138` — non-empty by type. Tracking/closure *behavior* is Phase 7. |
| P-10.6 (review/report/append-only) | **C** (persistence/review) | `RiskRegister::inventory()` `risk.rs:177` rides the trait; append-only Organ-5 store is Phase 7 |

Supporting types added: `RiskId` `risk.rs:24`, `DeterministicGateId` `risk.rs:29`,
`TransferMechanism` `risk.rs:96`.

## 2. OQGF-P-11 (Personal Data) — core value-type subset

| Req | Bucket now | Where |
|---|---|---|
| P-11.1 (Personal-Data Tag: dimension orthogonal to tier) | **C** (barrier Phase 6) — see caveat (2) | dimension composes with core `Classification` (tier) at the Barrier; `classification.rs` unchanged and carries no `personal` field |
| P-11.2 (minimization into Privileged Contexts) | **C** | genome Phase 5 / barrier Phase 6 |
| P-11.3 (declared, binding Purpose) | **A (core value type present)** | `personal_data::Purpose` `personal_data.rs:21`; the *enforcement* (repurpose = fresh DAP decision) is Phase 5/6/7 |
| P-11.4 (Retention Period) | **A (core value type present)** | `personal_data::RetentionPeriod` `personal_data.rs:29`; the retention *sweep* is Phase 7 |
| P-11.5 (erasure by crypto-shredding) | **C** | crypto-shredding = `brokkr-crypto` Phase 2; erasure tombstone = `brokkr-audit` Phase 7. **No key-handle, no erasure logic in core** — as required. |
| P-11.6 (subject rights) | **C** | audit Phase 7 (regulator interface) |
| P-11.7 (personal data in the accountability record) | **C** | audit Phase 7 |

## 3. The invariant question (the DAP asked; answered)

**No new numbered invariant. I did not add I-13.** Considered and rejected:
- *Four dispositions mutually exclusive* — true by enum construction; that is how enums
  work, not a new encoding.
- *Reduce/Transfer non-empty residual* — true because `residual: Box<RiskEntry>` is a
  required field, not `Option`; that is how required fields work. It is proven at compile
  time by a `compile_fail,E0063` **shape** doctest on `risk::Disposition` (`risk.rs:131`),
  labeled explicitly as a required-field shape property, not a numbered structural
  invariant of the I-1…I-12 caliber (those prevent an actor from *doing* something
  dangerous; a disposition's shape prevents nothing an actor does).

## 4. Verification — actual output (not a description)

Reproduce with `cargo test --locked -p brokkr-core`:

- `cargo build -p brokkr-core` → **Finished, clean.**
- `cargo test -p brokkr-core` →
  - `negative_invariants.rs`: **12 passed, 0 failed** (the original twelve, untouched).
  - `risk_shape.rs`: **6 passed, 0 failed** (new: Accept-holds-RiskAcceptance, non-gate
    accept, Reduce/Transfer residual, Avoid plan, RiskRegister impl, Purpose/Retention).
  - Doc-tests: **11 passed, 0 failed** (the original ten + the new `E0063` residual proof).
- `cargo clippy -p brokkr-core --all-targets` → **clean** (§6 deny lints still hold).

## 5. Verdict

**`brokkr-core` is complete against the ten-amendment corpus for its type-shape
obligations.** Every OQGF-P-10 core type exists and is cited by file:line (§1); the
OQGF-P-11 core value types exist (§2); and every bucket-C item — crypto-shredding
(P-11.5, Phase 2), register persistence and review (P-10.2/.6, P-11.6/.7, Phase 7),
minimization and the personal-tag composition (P-11.1/.2, Phase 5/6) — is explicitly
deferred to its phase, not silently dropped, and will be checked there.

Two caveats bound that "complete" (§0): `RiskAcceptance` was **created**, not reused; and
the personal-data *dimension* (P-11.1) is bucket C at the barrier because
`classification.rs` carries no `personal` field and was not touched — so "complete" means
**core owes nothing further for P-11.1**, not that a `Classification.personal` field
exists. Verify the source.

— End of delta CONF-2026-07-15-P1-DELTA-R2.
