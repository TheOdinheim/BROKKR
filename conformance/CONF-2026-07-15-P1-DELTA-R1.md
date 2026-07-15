# Conformance Delta — brokkr-core against AMD-008 (OQGF-P-10) and AMD-009 (OQGF-P-11)

**Record ID:** CONF-2026-07-15-P1-DELTA-R1
**Phase:** 1 (`brokkr-core`) — delta check against the two-amendment corpus growth
**Date:** 15 July 2026
**Subject:** the built crate `brokkr-core` (as of PHASE-1-2026-07-14-R2).
**Ground truth:** the text of `governance/AMD-008-risk-surveillance.md` (OQGF-P-10.1…P-10.6)
and `governance/AMD-009-personal-data-lifecycle.md` (OQGF-P-11.1…P-11.7), enumerated
directly. The amendments' own §6 traceability tables were **not** used as the source
(§5.3); they are the subject, not the ground truth.
**Auditor:** Claude Code. **For:** Jeremy Rose, DAP.

---

## 0. The one question, asked of every requirement

Does this requirement impose a **type-level obligation on `brokkr-core` specifically** —
a struct, enum, trait, or field that must exist *in* `brokkr-core` for the requirement
to be satisfiable, the same category as `ResponseClass`, `BarrierVerdict`,
`EscalationType`? Each requirement is sorted into exactly one bucket:

- **A** — core type obligation, **present** (a type already in `brokkr-core` satisfies it).
- **B** — core type obligation, **absent** (the bucket that matters; each is a Phase-1 gap).
- **C** — **not** a core obligation (lands in another crate, or is behavioral/operational).

**§4 unblock note, stated up front.** The verdict below is that bucket **B is
non-empty** — Phase 1 needs a revision. That is the *harder* path, not the unblocking
one: the disposition that would have cleared me to close Phase 1 is "everything is C."
I did not take it. Two items I could have routed to C — the personal-data classification
dimension (P-11.1) and the `RiskAcceptance` accountability shape (P-10.4) — I placed in
B because a core type must (or most faithfully should) exist for them, per the
tie-breaker rule that a type which must live in core is B even when that means a
revision I would rather avoid.

---

## 1. OQGF-P-10 (AMD-008 — Risk Register)

| Req | Quoted obligation (text) | Type-level core obligation? | Bucket |
|---|---|---|---|
| **P-10.1** | "SHALL maintain a Risk Register recording, for every identified risk: a description and its context; an assessment of its likelihood and its impact; a named DAP owner; and exactly one disposition." | A `RiskRegister` trait and a `RiskEntry` struct (id, description, context, `Likelihood`, `Impact`, `owner: Dap`, `source`, `disposition`) — governance type shapes, the category of `ToleranceController`/`HostHarmReport`. **Absent** from `brokkr-core`. | **B** |
| **P-10.2** | "Risk identification SHALL be a continuous function … drawing from … confirmed incidents … threat models … Deterministic-Gate findings … supply-chain and dependency changes." | Behavioral/operational: a *continuous* function fed from Organ 5 (audit, Phase 7), the sentinel (Phase 8), and the genome (Phase 5). The `RiskSource` enum is a field-type of `RiskEntry` and rides on the B shape; the continuity itself is not a core type. | **C** (operational; `RiskSource` folds into the P-10.1 B shape) |
| **P-10.3** | "Every registered risk SHALL carry exactly one disposition from the set {Avoid, Reduce, Transfer, Accept}. Avoid, Reduce, and Transfer SHALL each carry a tracked treatment plan." | A `Disposition` enum with exactly those four variants and a `TreatmentPlan` struct — the category of `BarrierVerdict`. **Absent.** | **B** |
| **P-10.4** | "An Accept disposition SHALL carry the accountability properties of an OQGF-P-9 Risk-Acceptance Entry: a named DAP, a scope specific to the risk, an expiry, a PQC signature …, and an Organ-5 record." | `Disposition::Accept` (a core enum variant) must hold the OQGF-P-9 accountability shape — the AMD-006 `RiskAcceptance` struct. `brokkr-core` has only `RiskAcceptanceId` and the `BarrierVerdict::AcceptedRisk` variant, **not** the `RiskAcceptance` struct (it was scoped to the Phase-6 barrier registry). For a *core* `Disposition` to carry OQGF-P-9 accountability, the `RiskAcceptance` shape must be in core. **Absent — and a dependency question (below).** | **B** |
| **P-10.5** | "Avoid, Reduce, and Transfer dispositions SHALL be tracked to completion … remain visible … as an open item until … completed. On completion of a Reduce or Transfer disposition, the Residual Risk SHALL be re-assessed and re-dispositioned." | The core-type slivers — `TreatmentStatus {Open, Executed}` and a `residual: RiskEntry` on Reduce/Transfer — must exist for the `Disposition`/`TreatmentPlan` shape to be complete. **Absent** (part of the P-10.3 B shape). The *tracking-to-closure* enforcement (keeping items open, re-assessing) is behavioral → Phase 7. | **B** (type shape; closure behavior is C/Phase 7) |
| **P-10.6** | "The Register SHALL be reviewed periodically and SHALL be reportable on demand as a standing inventory … A risk that is closed, superseded, or re-dispositioned SHALL be annotated and retained, never deleted." | Behavioral/operational: periodic review and append-only persistence live in `brokkr-audit` (SAGA, Phase 7). The `RiskRegister::inventory()` method rides on the P-10.1 B trait. | **C** (persistence/review, Phase 7) |

---

## 2. OQGF-P-11 (AMD-009 — Personal Data)

| Req | Quoted obligation (text) | Type-level core obligation? | Bucket |
|---|---|---|---|
| **P-11.1** | "SHALL … mark it with a Personal-Data Tag: a Data Classification dimension (AMD-007) that composes with, and is orthogonal to, the sensitivity tier … regardless of the datum's sensitivity tier, including where that tier is Public." | The AMD-007 classification vocabulary in BROKKR is `classification.rs::Classification` — a **core** type, and the core `barrier` module's `BoundaryFlow`/`BarrierFinding` carry it. A personal-data **dimension orthogonal to** that tier is therefore most faithfully a core shape. `classification.rs` carries **only the sensitivity tier** and has **no** personal dimension. (Adding `Personal` as a `Classification` variant would be *wrong* — it conflates orthogonal dimensions the requirement says must compose.) **Absent.** | **B** |
| **P-11.2** | "SHALL collect and retain Personal Data only to the extent necessary for a declared Purpose … admitted to a Privileged Context … SHALL be minimized." | Behavioral: ingress minimization at the Barrier (Phase 6, via OQGF-I-11) and into the AIBOM (Phase 5). Not a core type. | **C** (barrier Phase 6 / genome Phase 5) |
| **P-11.3** | "Personal Data SHALL carry a declared Purpose recorded in its Boundary Custody Record (OQGF-I-9) or its AIBOM entry … used only for its declared Purpose … repurpose … SHALL require a fresh decision by a DAP, recorded in Organ 5." | The `Purpose` type is carried on the BCR (Phase 6, a non-core type) or AIBOM (Phase 5). The repurpose decision is behavioral (Phase 5/6/7). No core type is required for satisfiability; `Purpose`'s placement follows the P-11.1 tag decision. | **C** (barrier Phase 6 / genome Phase 5 / audit Phase 7) |
| **P-11.4** | "Personal Data SHALL carry a declared Retention Period tied to its Purpose, and SHALL be erased … when the Retention Period elapses or the Purpose is fulfilled." | `RetentionPolicy` rides on the tag/BCR (downstream); the retention sweep that fires erasure is a scheduler (Phase 7). Not a core type. | **C** (barrier Phase 6 / audit Phase 7) |
| **P-11.5** | "Erasure … SHALL be performed by destroying the quantum-safe key … SHALL NOT be performed by deleting the record … a signed Erasure Tombstone SHALL be appended … The key … SHALL be quantum-safe (CNSA 2.0)." | Crypto-shredding (key destruction) is **`brokkr-crypto`, Phase 2**. The `ErasureTombstone` is a signed SAGA record (`brokkr-audit`, Phase 7) — the same category as the audit event, which is **not** a core type. The `SubjectKeyRef` key-handle is a Phase-2 crypto concern (there is no key-handle type in the core crypto *seam* today, and shredding operates on Phase-2 key material). No core type strictly required. | **C** (crypto Phase 2 / audit Phase 7) |
| **P-11.6** | "SHALL be able to answer, for an authenticated data subject: what Personal Data … is held, its declared Purpose, and its Retention Period; and SHALL be able to execute erasure … served through the Organ 5 regulator query interface (OQGF-A-7)." | Behavioral: the subject-authenticated path on the Organ 5 regulator interface (`brokkr-audit`, Phase 7). Not a core type. | **C** (audit Phase 7) |
| **P-11.7** | "any Personal Data in the recorded input SHALL be stored either as a privacy-preserving derivative or under the crypto-shredding regime … re-signing … SHALL preserve the crypto-shredding property." | Governs how SAGA stores personal data and how the re-signer (OQGF-A-6) behaves — `brokkr-audit`, Phase 7. Not a core type. | **C** (audit Phase 7) |

---

## 3. Bucket A — core type obligations already present

**None.** No P-10 or P-11 requirement is fully satisfied by a type already in
`brokkr-core`. The accountability *primitives* the new types will reuse do exist and are
unchanged — `Dap`, `DualSignature`, `Timestamp`, `Score`, and the sensitivity-tier
`Classification` — but a primitive is not the requirement's shape. The one candidate the
prompt flagged for A ("does P-10 Accept reuse a `RiskAcceptance` already in core?") is
**not** A: core has only `RiskAcceptanceId`, so it is B (P-10.4).

---

## 4. The dependency question inside P-10.4 (for DAP scoping)

`Disposition::Accept` must carry the OQGF-P-9 accountability shape. AMD-006 §5.1 places
`RiskAcceptance` in `oqgf-core`; the BROKKR architecture (§9) associated the *risk-
acceptance registry* with the Phase-6 barrier crate, and Phase 1 built only
`RiskAcceptanceId` + the `AcceptedRisk` variant, not the `RiskAcceptance` struct. AMD-008
now forces the choice, because a **core** `Disposition::Accept` cannot hold a **barrier
(Phase-6)** type (`brokkr-core` may not depend on `brokkr-barrier`; the direction is
one-way, I-5). Two clean resolutions, both coherent — the DAP picks one in scoping:

- **(a) Add `RiskAcceptance` to `brokkr-core`.** `Disposition::Accept` holds it directly;
  the Phase-6 barrier registry and Phase-7 audit consume the core type. This matches
  AMD-006's own "`oqgf-core`" placement and keeps the dependency direction clean.
- **(b) `Disposition::Accept` holds a `RiskAcceptanceId`** and the full `RiskAcceptance`
  is placed in core anyway (so both the id and the struct are core). Functionally the
  same core surface; (a) is simpler.

Either way, the `RiskAcceptance` **struct** enters `brokkr-core`. That is the B item.

---

## 5. Verdict

**`brokkr-core` is NOT complete against the ten-amendment corpus. Phase 1 needs a
revision.** Bucket B is non-empty. The revision adds these types to `brokkr-core`, and
**only** these (no behavior, no other crate):

1. **Risk Register surface** (P-10.1, P-10.3, P-10.4, P-10.5): a `RiskRegister` trait; a
   `RiskEntry` struct; a `Disposition` enum `{Avoid, Reduce, Transfer, Accept}`; a
   `TreatmentPlan` struct with a `TreatmentStatus {Open, Executed}`; a `residual:
   RiskEntry` on `Reduce`/`Transfer`; supporting types `RiskId`, `Likelihood`, `Impact`,
   `RiskSource`, `TransferMechanism`; and the AMD-006 `RiskAcceptance` accountability
   struct that `Disposition::Accept` holds (§4).
2. **Personal-data classification dimension** (P-11.1): a marker/type in `classification.rs`
   that composes orthogonally with `Classification` (never a new `Classification` variant).

Everything in bucket C (P-10.2, P-10.6, P-11.2–P-11.7) lands in `brokkr-crypto` (Phase 2),
`brokkr-genome` (Phase 5), `brokkr-barrier` (Phase 6), or `brokkr-audit` (Phase 7), or is
behavioral, and is **out of scope for `brokkr-core`** — recorded here so it is not
silently dropped, and to be checked at each of those phases.

The Phase-1 conformance results recorded before today (CONF-2026-07-14-P1-R1/R2, "0
absent") were measured against eight amendments and remain valid *against eight*; this
delta records the two new requirements' verdicts, per the CLAUDE.md v1.5 §0 instruction.

**A gap is filed:** `gaps/GAP-2026-07-15-001.md`. Per §4 I stop at the gap; I do **not**
build the revision. The DAP approves scope first. No code was written, no type was added,
`brokkr-core` was not edited.

— End of delta CONF-2026-07-15-P1-DELTA-R1.
