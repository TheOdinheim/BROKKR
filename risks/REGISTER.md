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
| **plan.target** | ~~Phase 7 (`brokkr-audit`)~~ → **Pre-production (with a `brokkr-crypto` memory-locking revision before Phase 11)** — DAP decision, 6 Aug 2026; see the DAP-DECISION note below |
| **plan.status** | `TreatmentStatus::Open` |
| **mitigation** | Implement durable key destruction in `brokkr-audit`: per-subject key storage that supports verifiable destruction (e.g. keys held only in memory-locked pages excluded from swap, or an HSM-backed key store whose destruction is attestable), plus the OQGF-P-11 erasure tombstone recording that destruction occurred. |
| **residual (required by type)** | After mitigation: durable destruction implemented and tombstoned. Residual = the destruction is only as durable as the underlying key-storage substrate's guarantees (HSM attestation, OS memory-locking correctness) — a bounded dependency on the storage layer, re-assessed when the Phase 7 mechanism is chosen. Residual `likelihood: Rare`, `impact: Major`. |

**Provenance note:** This is the durability half of the Phase 1 delta's bucket-C deferral, now a
*tracked open item with a target phase* rather than a comment. The in-memory zeroization delivered
in Phase 2 stands; this risk covers only what Phase 2 explicitly could not guarantee.

**UPDATE — 6 August 2026 (Phase 7, `reports/PHASE-7-2026-08-06-R2.md`): partial advance + mitigation
re-assignment; plan.status remains `Open`.** Phase 7 (`brokkr-audit`) delivered the **erasure-tombstone
recording** half of the mitigation and no more: a signed, append-only `ErasureTombstone` (erased seq,
classification, time, DAP) that records destruction occurred, with the erased record preserved and the
chain intact (`test_oqgf_p_11_5_erasure_preserves_chain`), and — structurally — a re-signed erased record
that stays irrecoverable (`test_oqgf_p_11_7_resigned_erased_record_stays_irrecoverable`). What Phase 7 did
**not** deliver is the **durable-key-destruction substrate** the mitigation names (memory-locked pages
excluded from swap, or an HSM-backed key store with attestable destruction). And Phase 7 **refined where
that substrate belongs:** the risk's context assigned durable destruction to `brokkr-audit` on the theory
that it "owns the persisted per-subject key lifecycle" — but ARCH §6.9 / Task 4(ii) (OQGF-P-11.7) require
SAGA to hold **no** subject key and to have **no** decrypt path, so it can never resurrect erased data.
Consequently `brokkr-audit` records the tombstone but does **not** own the subject-key store; durable
destruction is a **`brokkr-crypto` + deployment/key-store** concern (`SubjectKey::shred` zeroizes in
memory; durability across swap/remanence remains an OS/storage property, unchanged from Phase 2).

- **Substantive risk: unchanged and Open.** In-memory zeroization is still not durable destruction; no
  memory-locking or HSM-backed store was built this phase.
- **Plan re-targeting flagged to the DAP.** `plan.target` was Phase 7; the durable-destruction half is
  not a `brokkr-audit` deliverable. It needs re-targeting to the key-store/deployment layer (an HSM-backed
  or memory-locked subject-key store with attestable destruction), which no built phase yet owns. This is
  a governance decision for the DAP, recorded here rather than silently re-assigned.
- **Residual (unchanged):** durability is only as strong as the eventual key-storage substrate's
  guarantees; residual `likelihood: Rare`, `impact: Major`, re-assessed when the substrate mechanism is
  chosen and its owning phase is set.

**DAP-DECISION — 6 August 2026 (treatment target set; annotation per §8, the Phase 7 UPDATE above stands
unchanged).** The `plan.target` re-targeting the Phase 7 UPDATE flagged is now decided: **Pre-production,
with a `brokkr-crypto` memory-locking revision landing before Phase 11.** `plan.status` remains `Open`;
`likelihood` (`Unlikely`), `impact` (`Major`), and `disposition` (`Reduce`) are unchanged. The mitigation
splits into two named halves:

- **Architectural half — `brokkr-crypto`.** Allocate subject-key material in memory-locked pages excluded
  from swap, plus a seam for an external key store with attestable destruction. This is a **scoped revision
  to an already-built crate**, landing **before Phase 11** so the hardening gate has a concrete mechanism to
  verify rather than a promise.
- **Deployment half — Odin's operations.** HSM procurement and OS swap configuration. BROKKR can **require
  and verify** these; it cannot implement them. This is the same plan/substrate split as **OQGF-A.6.1**
  (BROKKR emits the triggers; the IR plan is organizational) and **OQGF-A-7** (BROKKR provides the export
  capability; the 72-hour response window is operational).

This target matches **RISK-2026-0001** (single-source entropy, OQGF-R-4), whose target is already
**Pre-production** for the identical reason: the primitive is correct, and the guarantee depends on the
deployment substrate, which no code phase can supply alone.

**No hard build-stop deadline.** Unlike **RISK-2026-0004** — whose deferred OQGF-M-11 conjuncts carry the
Deferred-Conjunct Deadline that *stops the build* at Phase 11 — this risk carries **no** build-halting
deadline. Its visibility rests on Phase 11's declared **hardening gate** (CLAUDE.md §5.1) and the
pre-production review; **naming the target is what keeps it in view**, which is the point of recording the
decision here rather than leaving it TBD.

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
| **plan.status** | ~~`TreatmentStatus::Open`~~ → **`TreatmentStatus::Executed`** (17 Jul 2026, Phase 2 revision — type added; 20 Jul 2026, Phase 3 revision — SKULD verify path added; **24 Jul 2026, Phase 4 — SINDRI wiring landed**; see UPDATEs below). Wiring residual **CLOSED**; the Option-B pre-shared-roots residual is carried by RISK-2026-0005, not here |
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

**UPDATE — 24 July 2026 (Phase 4, `reports/PHASE-4-2026-07-24-R2.md`):** the **wiring is now
DONE**. `brokkr-gate` (SINDRI) resolves the root's and every hop's `DualPublicKey` through the
`KeyResolver` seam and calls `Skuld::verify_chain_public(root, entries, &root_pub, &hop_refs,
now)` in Signal 2. Proven by the Phase-4 suite (`test_oqgf_m_11_valid_costimulation_grants`,
`test_unresolvable_hop_is_anergy`, `test_tampered_entry_signature_is_anergy`,
`test_broken_hash_link_is_anergy`; `CONF-2026-07-24-P4-R2.md`, `FUNC-2026-07-24-R1.md`). The
Phase-4 wiring residual this entry tracked is therefore **executed**. What remains is a
**different, named residual — not this one**:

- **Residual (re-dispositioned — the wiring residual is CLOSED; a provenance residual remains
  under Option B):** SINDRI now verifies chains against **declared roots of trust** supplied by
  a `RegistryResolver` (Option B, ARCH §6.4.1). The remaining exposure is that those roots are
  **pre-shared** — trust rests on out-of-band registration, not on a hardware root of trust
  certifying the key at attestation time. This is **not** the "SINDRI is not yet wired" residual
  (that is closed); it is the platform-attestation / pre-shared-roots residual already tracked
  as **RISK-2026-0005** and named in ARCH §13. To avoid double-tracking, the provenance residual
  lives in RISK-2026-0005; **RISK-2026-0003's own residual is now closed by the Phase-4 wiring.**
  OQGF-M-8's gate-verification half moves from **partial** toward **satisfied** in
  `CONF-2026-07-24-P4-R2` (Option B), with the pre-shared-roots residual explicit; the
  standing `CONF-2026-07-16-P3-R1` verdict is superseded for that half by the Phase-4 record.
- Disposition: `Disposition::Reduce`, **plan.status → Executed** (the wiring landed); the risk is
  **Reduced, wiring residual closed**, with the remaining provenance concern carried by
  RISK-2026-0005 (not re-counted here). `likelihood: Unlikely`, `impact: Major`.

**Provenance note:** Raised by the Phase 3 records correction. The Phase 3 chain cryptography
(canonical serialization, dual-family signing, hash-linking, freshness) stands and is tested;
this risk covered the verifier-side key material `brokkr-crypto` did not yet expose — added by
the Phase 2 revision, the SKULD verify path by the Phase 3 revision, and the SINDRI wiring by
Phase 4. The wiring residual is now closed; the Option-B pre-shared-roots residual is tracked as
RISK-2026-0005.

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
| **plan.status** | `TreatmentStatus::Open` (types placed 27 Jul 2026, Rev 1.4 core revision — **enforcement still pending Phase 5**; see UPDATE below. NOT Executed: the treatment is the enforcement, not the type.) |
| **mitigation** | Land both seams (above); then extend SINDRI's `evaluate` to compute conjunct 3 (`required_capability(action) ∈ current_scope()` else `OutOfScope`) and conjunct 4 (invariant evaluator over `current_invariants()` else `InvariantViolated`). Enforce the Deferred-Conjunct Deadline as a precondition on wiring the executor at Phase 11. |
| **residual (required by type)** | After both land: SINDRI evaluates all four conjuncts. Residual = the **correctness of the capability vocabulary and invariant semantics REGIN defines** — a governance/vocabulary judgment (does the tool→capability mapping and the invariant-evaluation predicate capture the intended authority?), re-assessed when the REGIN seams are specified. Residual `likelihood: Unlikely`, `impact: Major`, re-dispositioned at the Phase-5 seam. |

**UPDATE — 27 July 2026 (Phase 1 core revision, `reports/PHASE-1-REV-2026-07-27-R1.md`, under ARCH
Rev 1.4):** the **types** for both treatment seams are now **placed in `brokkr-core`** — but the
enforcement is not, so this remains **Open**:

- **Action-to-capability binding — type placed.** `ToolEntry::required_capabilities: Vec<Capability>`
  now carries, in the signed tool register, the least-privilege capabilities each tool exercises.
  The §6.2 check ("every `required_capabilities` entry present in `chain.current_scope()`, else
  `OutOfScope`; an undeclared tool is denied") is **SINDRI's and lands in Phase 5** — not built here.
- **Invariant-evaluator surface — type placed.** `InvariantEntry { invariant, forbids_capabilities,
  forbids_privilege }` + `PolicyRegister` place the **declarative** predicate surface, computable
  from the signed registers. The evaluation (and the construction-time check that a Root Intent
  carries no undeclared invariant) is **Phase 5**.
- **The detail-level-invariant half stays OPEN.** Invariants that need to interpret `Action.detail`
  (e.g. "read-only outside ./src") are **not** expressible by `InvariantEntry` and are a named
  residual (ARCH §13). Placing `InvariantEntry` does not close them.

**Disposition unchanged: `Reduce`, `plan.status: Open`.** The type surface is a prerequisite the
revision satisfies; the **treatment is the enforcement**, which is Phase 5. This is **not** marked
Executed. `likelihood: Possible`, `impact: Major` unchanged.

**Provenance note:** Raised at the Phase 4 surface check when the committed types were found to
lack the action-semantics surface for conjuncts 3–4. Disposed by the DAP via ARCH Rev 1.3 §6.4,
which selected the scope option (the builder's labeled self-interest disclosure was correct and
the labeled option was selected knowingly), stated all four conjuncts in full, reduced none, and
bounded the deferral with the Deferred-Conjunct Deadline. ARCH Rev 1.4 then placed the type
surface (this UPDATE); Phase 5 lands the enforcement. This entry tracks the residual that
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

## RISK-2026-0006 — A defeated freshness check survived four phases of review (OQGF-M-14 / I-13)

| Field | Value |
| --- | --- |
| **id** | RISK-2026-0006 |
| **source** | `RiskSource::ThreatModel` (found at the Phase 8.5 buildability check; recommended for DAP placement in `reports/PHASE-1-REV-2026-08-18-R10.md` §Task 7 and `conformance/CONF-2026-08-18-P1-REV-R10.md`; disposed by Architecture Rev 1.15 and CLAUDE.md v1.7 invariant **I-13**) |
| **description** | SINDRI stored `now` at construction (`Sindri::new(resolver, now)`) and checked intent-chain expiry against `self.now`. A gate alive for any length of time compared an **aging expiry against an equally aging present**, so the OQGF-M-14 freshness check passed while enforcing nothing — the arithmetic worked, the check returned "fresh," and no expiry could ever fail it. `brokkr-bifrost` later **adopted the same held-clock pattern**, its Phase 8.5 report citing "the same discipline SINDRI/EIR use" — so the class of defect propagated from the gate to the crossing before either was corrected. |
| **context** | The defect lived in **committed, pushed, DAP-ratified** code from **Phase 4 (commit `a326450`)** through the Phase 8.5 checkpoint — **four phases**. It survived a phase conformance check that recorded **OQGF-M-14 as satisfied**, because the Phase-4 test injected a fixed `now` at construction and **never advanced it**: the test and the code shared the same assumption, so **the test agreed with the defect** and could not have failed. It also survived because the build-prompt wording it satisfied — *"an explicit parameter, never a wall-clock read"* — is satisfied **exactly** by a constructor parameter, so a builder following the instruction to the letter produced the defect and a reviewer reading the code found a freshness check that looked correct. **Exposure — a fact about build order, not about the control working:** *no exposure was realized.* Nothing consumes an `AuthorizedAction` until the executor is wired at **Phase 11** (last by design), so no expired chain ever authorized an action. The gate did not "hold" because it was sound; it held because **nothing downstream of it existed yet.** This is recorded as a property of the build order, not as evidence the freshness control worked. |
| **likelihood** | `Likelihood::Possible` — assessed on two distinct axes, both stated because they point different ways. **Realized harm on this instance:** near-nil, and only because of build order (no executor until Phase 11) — not because the control functioned. **Recurrence of the class:** demonstrated — the held-clock pattern *already recurred once*, in `brokkr-bifrost`, adopted deliberately as "the same discipline." That is direct evidence the pattern reintroduces easily on any future gate that evaluates an expiry. Matching the register's convention for a cross-phase scheduling dependency (cf. RISK-2026-0004), `Possible` scores the live path by which harm materializes: an executor wired to a still-held-clock gate before the fix and the held-clock grep close it. The recurrence evidence is about *the class*, not this instance, and is what keeps this above `Unlikely`. |
| **impact** | `Impact::Major` — an **expired intent chain authorizing an action** is an OQGF-M-14 failure **at the costimulation gate**, the deterministic spine. A stale Signal-2 that passes lets the gate mint an `AuthorizedAction` on authority that should have lapsed — precisely the freshness guarantee the gate exists to enforce. Scored Major (a spine-level authorization defect), consistent with every other gate/attestation risk in this register even where realized likelihood is low. |
| **owner** | Jeremy Rose (DAP) |
| **disposition** | `Disposition::Reduce` |
| **plan.owner** | Jeremy Rose |
| **plan.target** | Corrected in the **`brokkr-gate` revision (SINDRI)** and the **Phase 8.5 rebuild (BIFRÖST)**, both immediately following the `brokkr-core` I-13 revision (commit `7d47d2a`), which made the held clock impossible to keep silently by requiring `now` as a per-call parameter on `CostimulationGate::{evaluate, authorize}` and `ContextClearance::{evaluate_context, clear}`. |
| **plan.status** | `TreatmentStatus::Open` — until **both** land (SINDRI threads the call-site `now` into the intent-chain freshness check in place of `self.now`; BIFRÖST passes the call-site `now` to `Barrier::evaluate`) **and** the workspace grep for a held clock (a `Timestamp` stored as construction state on a gate that evaluates an expiry) returns **empty**. |
| **mitigation** | (1) I-13 — the current time is a parameter of the evaluating call, never construction state — now enforced by the trait signatures (core revision, done). (2) Replace SINDRI's `self.now` with the call-site `now` in the freshness check; replace BIFRÖST's held `now` with the call-site `now` passed to the barrier. (3) A standing **workspace grep for a held clock in every conformance pass**, plus per-crate review, because no signature can prove an implementor forwards `now` rather than reading a stored value. |
| **residual (required by type)** | After mitigation: SINDRI and BIFRÖST evaluate freshness against a per-call time, and the grep is clean. **Mechanical residual:** I-13 makes the *call site* require a time; **no signature can prove an implementor forwards it** rather than ignoring the argument and reading a stored `Timestamp` — detection remains the workspace grep in every conformance pass plus per-crate review. Residual `likelihood: Unlikely` (reintroduction is caught by the grep, but the grep must actually be run), `impact: Major`, re-assessed whenever a new gate that evaluates an expiry is built. **Deeper residual — NOT addressed by this treatment:** the defect survived because **a conformance verdict was recorded on a test that could not have failed** — the test injected a fixed `now` and never advanced it, so test and code shared the same wrong assumption. The class of defect where *the check and the checked share a blind spot* is a process gap (a "does this test have a way to fail?" discipline), not a type-system or grep item, and this Reduce treatment does not close it. It is named here rather than claimed eliminated. |

**Provenance note:** Raised by the builder at the Phase 8.5 buildability check and recommended for
DAP placement in the `brokkr-core` I-13 revision (the builder correctly declined to open a
register entry itself, per the RECORDS-ONLY cadence and the scope lock). The DAP has decided to
open it. This entry tracks the window in which SINDRI's freshness check was defeated, the once-
recurred held-clock class, and the two residuals — the mechanical one (grep + review) and the
deeper one (a verdict recorded on a test that could not fail).

**UPDATE — 18 August 2026 (`brokkr-gate` revision, `reports/PHASE-4-REV-2026-08-18-R1.md`): the
SINDRI half is closed; the risk remains Open.** `brokkr-gate` removed the held clock: the `now`
field is gone from `Sindri` (which now holds only `resolver`), `Sindri::new` no longer takes a
time, and `evaluate` threads the call-site `now` to `verify_chain_public`. The held-clock grep over
`brokkr-gate/src` (broad enough to catch a **method** as well as a field, `self\.now`) returns
**empty**. Critically, the **test that agreed with the defect was rewritten** to have a way to fail:
`test_oqgf_m_14_i13_expiry_is_evaluated_against_call_time_not_a_held_clock` evaluates one chain
twice with one instance (grant before expiry, `ChainExpired` after) — impossible to pass against a
stored clock. OQGF-M-14 is now genuinely satisfied at SINDRI on that proof
(`CONF-2026-08-18-P4-REV-R1`).

- **NOT Executed, NOT closed.** The plan requires **both** corrections to land **and** the
  workspace held-clock grep to return empty. `brokkr-bifrost` still holds `self.now()` (its held
  clock governs BCR expiry, OQGF-I-9) and still fails to build with the expected `E0050`; the
  workspace grep is therefore **not** empty. `plan.status` remains `TreatmentStatus::Open`.
- **Remaining half:** the Phase 8.5 rebuild threads `now` into `brokkr-bifrost`'s
  `evaluate_context` (and to `Barrier::evaluate`), after which the grep is re-run workspace-wide;
  only an empty result closes this risk.
- **Residuals unchanged.** The mechanical residual (no signature proves forwarding; grep + per-crate
  review) and the deeper residual (a conformance verdict was recorded on a test that could not fail)
  both stand; `likelihood: Possible`, `impact: Major`, `disposition: Reduce` unchanged.

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
