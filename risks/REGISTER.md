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
| **plan.status** | `TreatmentStatus::Open` |
| **mitigation** | Add a `DualPublicKey` type to `brokkr-crypto` (or `from_public_bytes` + a verify path independent of the private keypair), so `verify_chain` and SINDRI can verify with public roots of trust only. Not an amendment-gap — the framework is clear; the type is missing. |
| **residual (required by type)** | After the type is added: verification uses public roots of trust. Residual = the *provenance* of those public keys still depends on OQGF-M-1 attestation (HW root of trust) being valid — a bounded dependency verified at the gate (Phase 4), re-assessed when SINDRI wires attestation→public-key. Residual `likelihood: Unlikely`, `impact: Major`. |

**Provenance note:** Raised by the Phase 3 records correction. The Phase 3 chain cryptography
(canonical serialization, dual-family signing, hash-linking, freshness) stands and is tested;
this risk covers only the verifier-side key material that `brokkr-crypto` does not yet expose.

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
