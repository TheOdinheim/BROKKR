# BROKKR Risk Register

**Document ID:** BROKKR-RISK-REGISTER
**Requirement:** OQGF-P-10 (AMD-008)
**Owner (DAP):** Jeremy Rose, CEO — Odin's LLC
**Started:** 16 July 2026
**Status:** Interim tracking register (see "Nature of this document" below)

---

## Nature of this document

OQGF-P-10.1 requires the Risk Register to be recorded in Organ 5 (`brokkr-audit`), which
is **Phase 7 — not yet built.** The `brokkr-core` risk types (`RiskRegister` trait,
`RiskEntry`, `Disposition`, `TreatmentPlan`) exist as of the Phase 1 revision, but the
persisted, append-only store they live in does not.

This markdown register is the **interim record of identified risks**, in the same pattern
already used for `conformance/` and `gaps/`. It satisfies the *assurance* OQGF-P-10 exists
to provide — every identified risk is **visible, owned, assessed, and dispositioned** — without
falsely claiming the Register is *implemented in code*. It is not a Deterministic Gate; it
does not block; its assurance is completeness and ownership, not prevention (AMD-008 §AMD.0.6).

Each entry below is written as a faithful rendering of the real `brokkr-core` types (exact
field and variant names), so that when `brokkr-audit` is built in Phase 7 the migration into
the persisted `RiskRegister` is a direct field-for-field mapping with no translation. Per
OQGF-P-10.6, entries here are **annotated, never deleted**: when a risk is closed, superseded,
or re-dispositioned, its entry is struck through with a `SUPERSEDED by …` note, and the
migration into the Phase-7 store preserves this history.

**Type provenance (verified against `brokkr-core/src/risk.rs`, 16 July 2026):**
`RiskEntry { id, description, context, likelihood: Likelihood, impact: Impact, owner: Dap,
source: RiskSource, disposition: Disposition }`;
`Likelihood ∈ {Rare, Unlikely, Possible, Likely, AlmostCertain}`;
`Impact ∈ {Negligible, Minor, Moderate, Major, Severe}`;
`Disposition::Reduce { plan: TreatmentPlan, residual: Box<RiskEntry> }`;
`TreatmentPlan { owner: Dap, target: Timestamp, status ∈ {Open, Executed} }`.

Note: `Disposition::Reduce` carries a **non-empty `residual: Box<RiskEntry>` by type** — a
mitigation may not close a risk without stating what remains after it (OQGF-P-10.5). Each
Reduce entry below therefore records its residual explicitly.

---

## RISK-2026-0001 — Single-source entropy for key generation (OQGF-R-4)

| Field | Value |
| --- | --- |
| **id** | RISK-2026-0001 |
| **source** | `RiskSource::ThreatModel` (Phase 2 conformance finding, `CONF-2026-07-15-P2-R1.md`; recorded in `GAP-2026-07-16-001.md` §4) |
| **description** | `brokkr-crypto` key generation draws from wolfCrypt's Hash-DRBG — a **single** entropy source. OQGF-R-4 at Enhanced requires **≥2 independent entropy sources** with **SP 800-90B continuous health tests**. The current single non-FIPS DRBG does not meet the diversification or health-test requirement. |
| **context** | Affects all PQC key generation (ML-DSA, SLH-DSA, ML-KEM). Not an active cryptographic break — the DRBG is sound — but a diversification/assurance gap. Relevant to harvest-now-decrypt-later posture because weak or single-source entropy narrows key unpredictability. The second source and the health tests are properties of the **wolfCrypt build configuration and the host OS entropy setup**, not of BROKKR's Rust code. |
| **likelihood** | `Likelihood::Unlikely` (a single well-seeded Hash-DRBG failing catastrophically is unlikely; the finding is an assurance gap, not an observed weakness) |
| **impact** | `Impact::Major` (entropy failure compromises every key; scored high on impact even though likelihood is low) |
| **owner** | Jeremy Rose (DAP) |
| **disposition** | `Disposition::Reduce` |
| **plan.owner** | Jeremy Rose |
| **plan.target** | Pre-production hardening (before any production key is generated) |
| **plan.status** | `TreatmentStatus::Open` |
| **mitigation** | (1) Build/deploy against a FIPS-capable wolfCrypt configuration providing the SP 800-90B health tests; (2) configure a second independent entropy source at the OS/deployment layer per OQGF-R-4; (3) verify diversification in the deployment conformance check. |
| **residual (required by type)** | After mitigation: entropy diversification and health tests met at deployment. Residual = dependence on the correct **operational** configuration being applied and verified per deployment (a deployment-conformance item, not a code item). Residual `likelihood: Rare`, `impact: Major`, re-dispositioned at deployment. |

**Provenance note:** This risk is a *deployment/build-configuration* gap, not a `brokkr-crypto`
code defect. `brokkr-crypto` correctly uses the DRBG wolfCrypt provides; the diversification and
health-test obligation is discharged by how wolfCrypt is built and how the host supplies entropy.
It is recorded here so the obligation is owned and tracked rather than lost in a conformance note.

---

## RISK-2026-0002 — Crypto-shred durability not guaranteed at the FFI layer (OQGF-P-11 / OQGF-G-7)

| Field | Value |
| --- | --- |
| **id** | RISK-2026-0002 |
| **source** | `RiskSource::ThreatModel` (Phase 2 conformance finding, `CONF-2026-07-15-P2-R1.md`; crypto-shred marked PARTIAL) |
| **description** | The Phase 2 crypto-shred primitive zeroizes per-subject key material **in memory** (via `zeroize`, `ZeroizeOnDrop` — not an elidable loop). It does **not** guarantee **durable** destruction: that the key cannot be recovered after surviving a process boundary, a swap-to-disk, or storage-media remanence. Durable destruction is an OS/storage property the FFI layer cannot assert alone. |
| **context** | OQGF-P-11 crypto-shredding is durable erasure only if the destroyed key is genuinely irrecoverable. In-memory zeroization is necessary but not sufficient. The durability half is architecturally assigned to `brokkr-audit` (Phase 7), which owns the persisted per-subject key lifecycle and the erasure tombstone. |
| **likelihood** | `Likelihood::Unlikely` (recovering a zeroized key from swap/remanence requires specific adversary access to the host storage substrate) |
| **impact** | `Impact::Major` (a recovered "shredded" key defeats the right-to-erasure guarantee for a data subject's personal data) |
| **owner** | Jeremy Rose (DAP) |
| **disposition** | `Disposition::Reduce` |
| **plan.owner** | Jeremy Rose |
| **plan.target** | Phase 7 (`brokkr-audit`) |
| **plan.status** | `TreatmentStatus::Open` |
| **mitigation** | Implement durable key destruction in `brokkr-audit`: per-subject key storage that supports verifiable destruction (e.g. keys held only in memory-locked pages excluded from swap, or an HSM-backed key store whose destruction is attestable), plus the OQGF-P-11 erasure tombstone recording that destruction occurred. |
| **residual (required by type)** | After mitigation: durable destruction implemented and tombstoned. Residual = the destruction is only as durable as the underlying key-storage substrate's guarantees (HSM attestation, OS memory-locking correctness) — a bounded dependency on the storage layer, re-assessed when the Phase 7 mechanism is chosen. Residual `likelihood: Rare`, `impact: Major`. |

**Provenance note:** This is the durability half of the Phase 1 delta's bucket-C deferral, now a
*tracked open item with a target phase* rather than a comment. The in-memory zeroization delivered
in Phase 2 stands; this risk covers only what Phase 2 explicitly could not guarantee.

---

## RISK-2026-0003 — brokkr-crypto has no public-key-only verifier (DualPublicKey) (OQGF-M-8)

| Field | Value |
| --- | --- |
| **id** | RISK-2026-0003 |
| **source** | `RiskSource::ThreatModel` (Phase 3 conformance finding, `CONF-2026-07-16-P3-R1.md`; M-8 corrected from satisfied to partial) |
| **description** | `brokkr-crypto`'s only keypair constructor is `DualKeyPair::generate()`, which mints **private** key material; `verify_dual` is a method on the full keypair. No type holds a verify-only public key. `verify_chain` (`brokkr-intent`) therefore cannot verify a chain using only public roots of trust — it needs the signer's keypair, so verification is demonstrated only as *signer-verifies-own-signature*. |
| **context** | OQGF-M-8's "a verifier SHALL be able to reconstruct the complete chain … using only declared public roots of trust" is only **partially** satisfied at Phase 3: the record-and-reconstruct half is done and tested; the public-roots-of-trust half is not yet reachable. This is a **HARD PREREQUISITE for Phase 4** (SINDRI verifies chains it did **not** sign, using public keys derived from OQGF-M-1 attestations). It is a missing type in `brokkr-crypto`, not a defect in `brokkr-intent`. |
| **likelihood** | `Likelihood::AlmostCertain` (without the type, Phase 4 verification-by-public-key cannot be built — the gap is certain to be hit) |
| **impact** | `Impact::Major` (blocks the costimulation gate's core Signal-2 verification and the OQGF-M-8 public-roots-of-trust obligation) |
| **owner** | Jeremy Rose (DAP) |
| **disposition** | `Disposition::Reduce` |
| **plan.owner** | Jeremy Rose |
| **plan.target** | Phase 4 prerequisite (before SINDRI verifies chains it did not sign) |
| **plan.status** | ~~`TreatmentStatus::Open`~~ → **`TreatmentStatus::Executed`** (17 Jul 2026, Phase 2 revision — type added; 20 Jul 2026, Phase 3 revision — SKULD verify path added; see UPDATEs below). Residual **still Open**, target Phase 4 (SINDRI wiring) |
| **mitigation** | Add a `DualPublicKey` type to `brokkr-crypto` (`from_public_bytes` + a verify path independent of the private keypair), so `verify_chain` and SINDRI can verify with public roots of trust only. Not an amendment-gap — the framework is clear; the type is missing. |
| **residual (required by type)** | After the type is added: verification uses public roots of trust. Residual = the *provenance* of those public keys still depends on OQGF-M-1 attestation (HW root of trust) being valid — a bounded dependency verified at the gate (Phase 4), re-assessed when SINDRI wires attestation→public-key. Residual `likelihood: Unlikely`, `impact: Major`. |

**UPDATE — 17 July 2026 (Phase 2 revision, `reports/PHASE-2-REV-2026-07-17-R1.md`):** the
missing type now **EXISTS**. `brokkr-crypto` gained `DualPublicKey` (verify-only, no private
material) with `from_public_bytes` (length-validated, fail-closed import — 1952 B ML-DSA-65,
48 B SLH-DSA-SHAKE-192s) and `verify_dual` (both families required), plus
`DualKeyPair::public_key_bytes` to export raw public keys. Public-key-only verification is
proven by `test_oqgf_m_8_public_key_only_verification` (`CONF-2026-07-17-P2-REV-R1.md`). **The
Phase 4 prerequisite is MET and the blocker is removed.** Per OQGF-P-10.5 the
`Disposition::Reduce` plan is now **Executed** and the residual is re-dispositioned:

- **Residual (re-dispositioned, OPEN — Phase 4):** `brokkr-intent`'s `verify_chain` still
  takes a `DualKeyPair`; switching it to `DualPublicKey` with attestation-sourced public keys
  is **Phase 4** (SINDRI), and the *provenance* of those keys depends on OQGF-M-1 attestation.
  Residual `likelihood: Unlikely`, `impact: Major`, target **Phase 4**, status **Open**. The
  risk is *reduced* (the type exists) but **not closed** until the wiring lands. OQGF-M-8 in
  `CONF-2026-07-16-P3-R1` stays **partial** until then.

**UPDATE — 20 July 2026 (Phase 3 revision, `reports/PHASE-3-REV-2026-07-20-R1.md`):** the
SKULD-side public-key verify path now **EXISTS**. `brokkr-intent` gained
`Skuld::verify_chain_public` (and `verify_root_public`): chain verification using only declared
public roots of trust (`DualPublicKey`), no private material, identical semantics to
`verify_chain` (both delegate to one shared walk). Proven by
`test_verify_chain_public_accepts_valid_multihop` and the keypair/public-key equivalence test
(`CONF-2026-07-20-P3-REV-R1.md`, `FUNC-2026-07-20-R1.md`). The residual is **further reduced**:

- **Residual (re-dispositioned, still OPEN — Phase 4):** the *type* (Phase 2 rev) and now the
  *SKULD-side verify path* (this revision) both exist and are tested. What remains for Phase 4
  (SINDRI) is the **wiring**: resolve a hop's public key from its OQGF-M-1 attestation and call
  `verify_chain_public`; the *provenance* of those keys still depends on the attestation (HW
  root of trust) being valid. Residual `likelihood: Unlikely`, `impact: Major`, target **Phase
  4**, status **Open**. The risk is *further reduced* (type + verify path exist) but **not
  closed** until SINDRI wires attestation→public-key→verify. OQGF-M-8 in `CONF-2026-07-16-P3-R1`
  stays **partial** until then.

**Provenance note:** Raised by the Phase 3 records correction. The Phase 3 chain cryptography
(canonical serialization, dual-family signing, hash-linking, freshness) stands and is tested;
this risk covered the verifier-side key material `brokkr-crypto` did not yet expose — now
added by this revision, with the wiring residual carried forward to Phase 4.

---

## RISK-2026-0004 — Two of OQGF-M-11's four conjuncts not enforced at Phase 4 (OQGF-M-11 / M-10)

| Field | Value |
| --- | --- |
| **id** | RISK-2026-0004 |
| **source** | `RiskSource::ThreatModel` (Phase 4 conformance surface check, `CONF-2026-07-24-P4-R1.md` / `GAP-2026-07-24-001.md`; disposed by Architecture Rev 1.3, commit `612f4b5`) |
| **description** | SINDRI enforces OQGF-M-11's Signals 1–2 (identity + Intent Provenance Chain). Conjuncts 3 (**action-in-scope**) and 4 (**action-respects-invariants**) are **not evaluated**, because `Action` carries no capability, `ToolId` and `Capability` have no committed conversion, and `Invariant` has no committed `(Action, Invariant) -> bool` evaluation predicate. |
| **context** | Safe **only** because nothing consumes an `AuthorizedAction` until the executor is wired at **Phase 11** (last by design); between Phase 4 and Phase 11 there is no execution path an under-checked authorization can reach. The deferral is controlled by the **normative Deferred-Conjunct Deadline** (ARCH Rev 1.3 §6.4): conjuncts 3 and 4 SHALL be enforced before the executor is wired. The exposure **if the deadline is missed** is an executor wired to a gate that grants actions it has not checked for scope-fit or invariant-respect — a fail-open on two of four M-11 conjuncts. Recorded PARTIAL for M-11 and M-10 in ARCH §14; residual in §13. |
| **likelihood** | `Likelihood::Possible` (a multi-phase scheduling dependency: the risk materializes only if Phase 11 proceeds before the Phase-5 seam lands — bounded by a normative deadline, but a real cross-phase dependency) |
| **impact** | `Impact::Major` (an executor on an under-checking gate would grant out-of-scope or invariant-violating actions — the exact failure the costimulation gate exists to prevent) |
| **owner** | Jeremy Rose (DAP) |
| **disposition** | `Disposition::Reduce` |
| **plan.owner** | Jeremy Rose |
| **plan.target** | **Phase 5 (REGIN)** — an action-to-capability binding (a `required: Capability` field on `Action`, or a REGIN-owned `required_capability(&Action) -> Capability` consumed through a trait SINDRI does not implement) **and** an invariant-evaluator seam (`(&Action, &Invariant) -> bool` reached through an interface). A **hard gate before Phase 11** (the executor SHALL NOT be wired to a gate lacking both). Landing may be Phase 5 or a scoped SINDRI revision immediately after. |
| **plan.status** | `TreatmentStatus::Open` |
| **mitigation** | Land both seams (above); then extend SINDRI's `evaluate` to compute conjunct 3 (`required_capability(action) ∈ current_scope()` else `OutOfScope`) and conjunct 4 (invariant evaluator over `current_invariants()` else `InvariantViolated`). Enforce the Deferred-Conjunct Deadline as a precondition on wiring the executor at Phase 11. |
| **residual (required by type)** | After both land: SINDRI evaluates all four conjuncts. Residual = the **correctness of the capability vocabulary and invariant semantics REGIN defines** — a governance/vocabulary judgment (does the tool→capability mapping and the invariant-evaluation predicate capture the intended authority?), re-assessed when the REGIN seams are specified. Residual `likelihood: Unlikely`, `impact: Major`, re-dispositioned at the Phase-5 seam. |

**Provenance note:** Raised at the Phase 4 surface check when the committed types were found to
lack the action-semantics surface for conjuncts 3–4. Disposed by the DAP via ARCH Rev 1.3 §6.4,
which selected the scope option (the builder's labeled self-interest disclosure was correct and
the labeled option was selected knowingly), stated all four conjuncts in full, reduced none, and
bounded the deferral with the Deferred-Conjunct Deadline. This entry tracks the residual that
deadline governs.

---

## RISK-2026-0005 — Attestation is not verified as attestation (OQGF-M-1 PARTIAL)

| Field | Value |
| --- | --- |
| **id** | RISK-2026-0005 |
| **source** | `RiskSource::ThreatModel` (Phase 4 conformance surface check, `CONF-2026-07-24-P4-R1.md` / `GAP-2026-07-24-002.md`; disposed by Architecture Rev 1.3, commit `612f4b5`) |
| **description** | Signal 1 at Phase 4 proves **key possession** for a declared root of trust and binds it to the chain's cryptographically proven hop (via Signal 2). It does **not** verify `Attestation.measurements` against expected platform state, no attestation issuer exists, and the committed types define **no attestation signed-content encoding** for the `signatures` field. The intrinsic attestation-signature check is dropped as redundant with the Signal-2 possession proof. |
| **context** | Signal 1 is **PKI-grade identity, not hardware-attested platform state**. This is **not a regression** — `measurements` are unverifiable today regardless, because nothing issues attestations. Trust in a hop's key rests on **out-of-band registration** (ARCH Rev 1.3 §6.4.1, the declared-registry model); pre-shared roots of trust are themselves a named residual (ARCH §13). Recorded PARTIAL for M-1 in ARCH §14. |
| **likelihood** | `Likelihood::Unlikely` (exploitation requires an adversary holding a **declared** private key on a **compromised** platform — measurements would be the check that catches platform compromise, and that check is absent; but obtaining a declared private key is itself gated by registration) |
| **impact** | `Impact::Major` (a compromised-but-declared platform would present a valid identity that the gate cannot distinguish from an honest one, because platform state goes unchecked) |
| **owner** | Jeremy Rose (DAP) |
| **disposition** | `Disposition::Reduce` |
| **plan.owner** | Jeremy Rose |
| **plan.target** | **Deferred** — closing M-1 requires an **attestation issuer**, a **committed attestation signed-content encoding** (a `brokkr-core` change), and a **measurement-expectation source**. The **Option A** resolver (attestation-carried, issuer-certified keys) slots in behind the existing `KeyResolver` seam **without changing SINDRI** (ARCH §6.4.1). No phase is yet assigned; it is later work. |
| **plan.status** | `TreatmentStatus::Open` |
| **mitigation** | Introduce an attestation issuer and a committed attestation signed-content encoding; add a measurement-expectation source so `measurements` can be checked against expected platform state; provide an Option-A `KeyResolver` implementation that verifies the attestation against an issuer root and extracts the subject key. SINDRI's verdict logic is unchanged by this migration (the seam exists for exactly this). |
| **residual (required by type)** | After mitigation: platform state is attested and checked. Residual = **pre-shared roots of trust remain a trusted out-of-band input** (the issuer root and the initial registration are themselves trusted anchors) — the same shape as the ARCH §13 "declared roots of trust are pre-shared" residual, re-assessed when the issuer model is chosen. Residual `likelihood: Rare`, `impact: Major`. |

**Provenance note:** Raised at the Phase 4 surface check when the committed `Attestation` was
found to define no signed-content for its `signatures` field. Disposed by the DAP via ARCH Rev
1.3 §6.4/§6.4.1, which adopted the gap's preferred construction (resolve-to-declared-root +
bind-to-proven-hop, intrinsic check dropped), recorded exactly what it costs (`measurements`
carried but unverified), and recorded M-1 PARTIAL rather than satisfied. This entry tracks the
platform-attestation residual.

---

## Register discipline (OQGF-P-10.6)

- **Never delete.** A closed, superseded, or re-dispositioned entry is struck through with a
  `SUPERSEDED by RISK-YYYY-NNNN` (or `CLOSED dd Mon yyyy — <reason>`) annotation and retained.
- **Every entry is owned** by a named DAP. An unowned risk is not recorded here.
- **Reduce/Transfer track to closure.** `plan.status` stays `Open` until the mitigation is
  executed; on execution the residual is re-assessed and re-dispositioned (OQGF-P-10.5).
- **Continuous identification** (OQGF-P-10.2): new risks enter from confirmed incidents,
  `THREAT_MODEL.md` findings, Deterministic-Gate findings, dependency changes, and conformance
  findings — as these two entries did.
- **Migration:** on completion of Phase 7, these entries migrate into the persisted
  `brokkr-audit` Risk Register field-for-field; this document then becomes the historical
  record of the pre-persistence period and is retained, not deleted.
