//! REGIN — the Genome (OQGF-G): four signed registers (tools, CBOM, AIBOM,
//! endpoint registry).
//!
//! I-10 (type-level shape): a [`Genome`] cannot exist without a signature and all
//! four registers — the fields are required. The running promotion gate is Phase 5;
//! the type forbidding an unsigned genome lives here.
//!
//! I-11: [`ModelEndpoint::client_cert`] is a required field, not an `Option`.
//! One-sided TLS to a reasoner is unrepresentable (OQGF-M-5).

use crate::capability::ConformanceTier;
use crate::classification::{Classification, NamedGroup};
use crate::crypto::{Digest, DualSignature, HashAlg, KemAlg, SignatureAlg};
use crate::ids::{
    ClientCertRef, Dap, FieldName, GenomeVersion, ModelEndpointId, ModelIdentity, Score, SubjectId,
    Timestamp, ToolId, TrustAnchor,
};
use crate::intent::{Capability, Invariant};
use crate::personal_data::Purpose;
use crate::tolerance::ResponseClass;
use alloc::string::String;
use alloc::vec::Vec;

/// Privilege class of a tool (OQGF-M-13, I-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeClass {
    /// Read-only within the working tree, no side effects.
    Unprivileged,
    /// File writes, shell, network — requires costimulation.
    Privileged,
    /// Modifies BROKKR's own control surface. Costimulated AND DAP-confirmed. No
    /// carve-out.
    SelfModifying,
}

/// A tool's typed schema (opaque here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSchema {
    pub detail: String,
}

/// A declared, signed tool the agent may invoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolEntry {
    pub id: ToolId,
    pub schema: ToolSchema,
    pub privilege: PrivilegeClass,
    /// Gates on this tool are `Deterministic`.
    pub response_class: ResponseClass,
    /// The authority this tool exercises, in the intent vocabulary (Rev 1.4,
    /// OQGF-M-11 conjunct 3 / OQGF-M-13). Every capability listed here SHALL be present
    /// in the chain's current scope for the action to be authorized — but the *check* is
    /// SINDRI's and lands in Phase 5; this field only makes it computable. A
    /// least-privilege declaration: the least authority the tool requires, not the most
    /// it could use.
    pub required_capabilities: Vec<Capability>,
}

/// The signed tool register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolGenome {
    pub entries: Vec<ToolEntry>,
    pub signature: DualSignature,
}

/// A typed algorithm identifier over the signature, hash, and KEM identifiers already
/// committed in [`crate::crypto`] (OQGF-G-5: a typed enum, never a string). Rev 1.4
/// introduces **no new** algorithm identifiers — it only wraps the three existing ones so
/// a deterministic gate (Phase 5) can evaluate the CBOM's inventory and the policy's
/// disallow-list without parsing any string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmId {
    Signature(SignatureAlg),
    Hash(HashAlg),
    Kem(KemAlg),
}

/// How BROKKR's long-lived signing keys are held (OQGF-R-6, AMD-018; ARCH Rev 1.21/1.22).
///
/// Carried on [`Cbom`] as a **required** field and inside the CBOM's signed content, so a
/// custody declaration is deliberate, attributable, and gate-visible. Variants are ordered
/// by the AMD-018 tier each can satisfy: R-6.1, R-6.2, R-6.3.
///
/// **What this proves and what it does not.** It proves the claim was made deliberately
/// (there is no default and no `Unspecified` variant), is signed into the genome, and
/// cannot change without re-promotion. It does **not** prove the claim is true: a genome
/// declaring [`KeyCustody::HardwareBacked`] over keys held in process memory passes every
/// predicate and violates R-6.2 entirely. AMD-018 §AMD.2.1 routes that case to assessment,
/// not to the gate — "a declared custody model that overstates the separation actually
/// achieved is a conformance failure, not a documentation defect."
// `Threshold` is much larger than `SoftwareInProcess` — it embeds the R-6.2 elements plus
// three procedure references, a quorum, and the custodian declaration. Boxing it would add
// indirection to a type that lives in a signed register and is read once per promotion, and
// the embedding is the point: it is what makes threshold-without-hardware unrepresentable
// (AMD-018 defines R-6.3 as "in addition to R-6.2"). A stack-layout hint does not outrank a
// structural guarantee. Same disposition as `brokkr-audit`'s `AuditEvent`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyCustody {
    /// R-6.1 territory. Private key material exists in extractable form in the process
    /// address space. Selecting this variant is the deliberate, signed act R-6.1 requires
    /// of a software-held key; it does **not** satisfy R-6.2 and fails promotion-gate
    /// predicate 7 at Enhanced or above. This is BROKKR's honest posture today.
    SoftwareInProcess {
        /// R-6.1: "the protection mechanism SHALL be declared."
        protection: ExtractionProtection,
    },

    /// R-6.2 candidate. The private key material cannot be extracted from the declared
    /// boundary — that non-extractability **is** the meaning of choosing this variant,
    /// which is why there is no `non_extractable: bool` for an author to set beside a
    /// claim they are already making.
    HardwareBacked {
        boundary: HardwareBoundary,
        /// Separate from `boundary` because AMD-018 §AMD.5 is explicit that "a FIPS
        /// validation is not by itself evidence of dual control — R-6.2 requires both."
        dual_control: DualControl,
    },

    /// R-6.3 candidate. R-6.2 **plus** k-of-n threshold custody. The R-6.2 elements are
    /// embedded rather than adjacent, because AMD-018 defines R-6.3 as "in addition to
    /// R-6.2" — so threshold custody without a hardware boundary and dual control is not
    /// a state this type can express.
    Threshold {
        boundary: HardwareBoundary,
        dual_control: DualControl,
        /// AMD-018: quorum of at least 3-of-5.
        quorum: Quorum,
        /// "Shares SHALL be held by distinct custodians with documented separation of duty."
        custodians: CustodianSeparation,
        ceremony: ProcedureRef,
        recovery: ProcedureRef,
        rotation: ProcedureRef,
        /// "SHALL rehearse recovery at least annually with the rehearsal recorded."
        /// Staleness is arithmetic against `now`, like the OQGF-M-6 trust score.
        last_rehearsal: Timestamp,
    },
}

/// R-6.1's declared protection mechanism for a software-held key.
///
/// **Every variant here produces the same tier verdicts** — R-6.1 satisfied on the
/// declaration clause, R-6.2 and R-6.3 failed — because none of them is a hardware
/// boundary. This enum participates in **no predicate**; its whole job is R-6.1's "the
/// protection mechanism SHALL be declared." It is therefore sized for an honest
/// declaration and no larger (ARCH Rev 1.22).
///
/// Rev 1.21 specified an `EncryptedAtRest { kek: KeyRef }` variant against a `KeyRef` type
/// that does not exist (GAP-2026-09-07-001). Rev 1.22 removed the payload rather than
/// inventing the type: the KEK reference changes no tier verdict, so it is descriptive
/// detail that does not earn a place in the committed vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionProtection {
    /// Nothing beyond OS process isolation. The weakest honest declaration, and BROKKR's
    /// actual posture today.
    ProcessIsolationOnly,
    /// Key material encrypted at rest under a separate key; still extractable from process
    /// memory while in use. Named rather than folded into `Other` so the common case is
    /// machine-comparable and typo-proof — the reasoning that made `PolicyRegister::
    /// capabilities` a closed vocabulary (Rev 1.5).
    EncryptedAtRest,
    /// Anything else, described. Covers memory-locking, swap exclusion,
    /// sealed-blob-then-loaded schemes, and mechanisms not common enough to earn a variant.
    Other { description: String },
}

/// The declared hardware boundary for R-6.2 / R-6.3 custody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareBoundary {
    /// What the module is, in the operator's own words.
    pub module: String,
    pub interface: BoundaryInterface,
    /// AMD-018 §AMD.5: "FIPS 140-3 Level 2 or above satisfies R-6.2's hardware boundary
    /// where the module's key-storage service is used; the level SHALL be declared in the
    /// CBOM."
    pub fips: FipsValidation,
}

/// How the hardware boundary is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryInterface {
    Pkcs11,
    CloudKms,
    Tpm,
    SecureEnclave,
    Other { description: String },
}

/// The declared FIPS validation of the boundary module.
///
/// **A FIPS validation is not by itself evidence of dual control** (AMD-018 §AMD.5); the
/// two are separate declarations and predicate 7 requires both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FipsValidation {
    NotValidated,
    Level { level: u8, certificate: String },
}

/// Whether key issuance and rotation require a second party (R-6.2).
///
/// **`SingleOperator` exists deliberately.** An operator with hardware but no second-party
/// procedure must be able to declare that **honestly** and fail predicate 7 on the
/// dual-control element, rather than choosing between a false `TwoParty` claim and a false
/// [`KeyCustody::SoftwareInProcess`] one. A type that makes the honest declaration
/// inexpressible manufactures lies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DualControl {
    SingleOperator,
    TwoParty { procedure: ProcedureRef },
}

/// k-of-n threshold parameters (R-6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quorum {
    pub k: u8,
    pub n: u8,
}

/// Why a [`Quorum`] is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumError {
    /// `k < 3` — below AMD-018's floor.
    QuorumTooSmall,
    /// `n < 5` — below AMD-018's floor.
    TooFewShares,
    /// `k > n` — a quorum larger than the share count can never be met.
    QuorumExceedsShares,
}

impl Quorum {
    /// AMD-018's floor: at least 3-of-5, and a quorum no larger than the share count.
    pub fn validate(&self) -> Result<(), QuorumError> {
        if self.k > self.n {
            return Err(QuorumError::QuorumExceedsShares);
        }
        if self.k < 3 {
            return Err(QuorumError::QuorumTooSmall);
        }
        if self.n < 5 {
            return Err(QuorumError::TooFewShares);
        }
        Ok(())
    }
}

/// Declared custodial separation (R-6.3).
///
/// AMD-018: "a share-holding arrangement in which fewer than k independent parties can
/// reconstruct the secret SHALL NOT satisfy this requirement." `independent_parties` is
/// the operator's declared count of genuinely separated holders — the number an assessor
/// tests by inquiry, and the number predicate 7 checks against `quorum.k`. It is checked
/// against `k` rather than assumed from `n`, which is why a declared 3-of-5 held by one
/// party **fails on its own stated numbers**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodianSeparation {
    pub independent_parties: u8,
    pub separation_of_duty: ProcedureRef,
}

/// A named document **and** its digest, so the declaration commits to a specific version.
/// Changing the procedure changes the digest, changes the CBOM signature, and requires
/// re-promotion — the discipline the AIBOM applies to prompt and corpus digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureRef {
    pub document: String,
    pub digest: Digest,
}

/// The Cryptographic Bill of Materials (OQGF-G-1). Carries both the CycloneDX interchange
/// document and the typed inventory a deterministic gate evaluates (Rev 1.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cbom {
    /// CycloneDX 1.6, the interchange artifact (OQGF-G-1).
    pub cyclonedx: String,
    /// The same inventory, typed — what the promotion gate actually evaluates
    /// (OQGF-G-5; Rev 1.4). SHALL agree with `cyclonedx`; the FFI honesty rule (§10)
    /// applies to both.
    pub algorithms: Vec<AlgorithmId>,
    /// How the long-lived signing keys are held (OQGF-R-6, AMD-018; Rev 1.21/1.22).
    ///
    /// **Required, never `Option`:** a CBOM that does not state a custody model is
    /// unrepresentable, so *omission* is not a way to avoid the declaration. That is the
    /// whole of what the type provides — it makes the declaration explicit, not true.
    pub custody: KeyCustody,
    pub signature: DualSignature,
}

/// The AI Bill of Materials (OQGF-G-2): models, providers, prompt/corpus digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aibom {
    pub cyclonedx: String,
    pub signature: DualSignature,
}

/// Evidence behind a **measured** factor of a [`VendorTrustScore`] (OQGF-M-6; ARCH Rev 1.31).
///
/// [`Score`] is a `u8` in `0..=100` where higher is better, so it **has no value meaning
/// "unmeasured"** — `Score(0)` is the *worst* score, not a neutral one. This says it instead.
///
/// **The correct instinct is already committed one crate away.** `window_rate`
/// (`brokkr-sentinel`) returns `NaN` rather than `0.0` for an empty window, because *"a rate
/// of `0.0` would claim safety from none."* The host-harm rate can say "no evidence"; a trust
/// score could not. This carries that distinction into a register where the value is **signed**
/// rather than computed on demand.
///
/// **`Option<Score>` was refused.** It makes absence representable while saying nothing about
/// *how much* evidence a present score rests on: `Some(Score(100))` from one observation and
/// from ten thousand are indistinguishable, and the first is the more dangerous.
///
/// **`Score(0)` paired with `observations: 0` is the honest encoding of "unmeasured"** — the
/// pair, not either half, carries the meaning. That is `reconciliation_pass_rate`'s true state
/// today (ARCH §6.2): the input is degenerate, so no counter is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactorEvidence {
    /// Reconciliation outcomes the score was computed over. **Zero means unmeasured**, and
    /// promotion-gate predicate 8 refuses a genome whose measured factor claims evidence it
    /// has none of.
    pub observations: u64,
    /// When the measurement window closed.
    ///
    /// **Deliberately distinct from [`VendorTrustScore::reviewed`]**, which is when a DAP
    /// *reviewed the score*. A review can restate an old measurement, and conflating the two
    /// would let a fresh review launder stale evidence.
    pub measured: Timestamp,
}

/// A per-supplier trustworthiness score (OQGF-M-6). Distinct from OQGF-R-2
/// substitutability: a provider you can switch away from may still be one you
/// should not send source to. A stale score fails the promotion gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorTrustScore {
    pub attestation_capability: Score,
    pub fips_validation: Score,
    pub breach_history: Score,
    pub jurisdictional_exposure: Score,
    pub data_handling: Score,
    /// Statistical reconciliation pass rate — OQGF-M-6's fifth factor (Rev 1.4). It is
    /// **measured, not declared**: the output of HEIMDALL's cross-hop reconciliation
    /// (OQGF-M-12, Phase 8). Until HEIMDALL feeds it, the field carries a declared
    /// placeholder, so **M-6 stays PARTIAL** — the factor is present in shape, not yet
    /// sourced from measurement. The type is necessary, not sufficient.
    pub reconciliation_pass_rate: Score,
    /// Evidence behind the **measured** factor above (OQGF-M-6; Rev 1.31). `observations: 0`
    /// means `reconciliation_pass_rate` is unmeasured rather than measured at zero — a
    /// distinction `Score` alone cannot express, and the one promotion-gate predicate 8
    /// enforces.
    pub evidence: FactorEvidence,
    pub reviewed: Timestamp,
    pub reviewer: Dap,
    // No `signature` (removed Rev 1.32, GAP-2026-09-18-001). The score's tamper-evidence
    // and DAP attribution come from the endpoints register that carries it: this whole
    // struct is inside `endpoints_signed_content`, whose signature promotion-gate
    // predicate 2 verifies against the DAP root. A field here would have been a second
    // attestation with no signed content defined for it and no verification site.
}

/// A model endpoint BROKKR is permitted to speak to.
///
/// **I-11** — `client_cert` is a required field, not an `Option`. OQGF-M-5 is
/// enforced at registration: an endpoint that cannot present a client certificate
/// is not a value this type can represent. "Just use a bearer token" is the absence
/// of a constructor, not a policy.
///
/// This does not compile — a `None` cannot stand in for the required certificate:
///
/// ```compile_fail,E0308
/// use brokkr_core::genome::ModelEndpoint;
/// fn any<T>() -> T { unimplemented!() }
/// let _ = ModelEndpoint::new(any(), any(), None, any(), any(), any(), any());
/// // E0308: mismatched types — expected `ClientCertRef`, found `Option<_>` (3rd arg)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelEndpoint {
    pub id: ModelEndpointId,
    pub model: ModelIdentity,
    /// REQUIRED. No `Option` (OQGF-M-5).
    pub client_cert: ClientCertRef,
    pub server_trust: TrustAnchor,
    pub min_group: NamedGroup,
    /// The ceiling this endpoint may *receive* (before channel-strength collapse).
    pub max_classification: Classification,
    pub trust_score: VendorTrustScore,
}

impl ModelEndpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ModelEndpointId,
        model: ModelIdentity,
        client_cert: ClientCertRef,
        server_trust: TrustAnchor,
        min_group: NamedGroup,
        max_classification: Classification,
        trust_score: VendorTrustScore,
    ) -> Self {
        Self {
            id,
            model,
            client_cert,
            server_trust,
            min_group,
            max_classification,
            trust_score,
        }
    }
}

/// The signed endpoint register (new in Rev 1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRegistry {
    pub endpoints: Vec<ModelEndpoint>,
    pub signature: DualSignature,
}

/// One declared root of trust: a subject and the dual-family public key BROKKR will accept
/// signatures from (OQGF-M-8; the register Rev 1.3 §6.4.1 assigned to REGIN, placed in
/// Rev 1.4).
///
/// **Raw bytes, not `DualPublicKey` — a dependency fact, not a style choice, and it is
/// load-bearing.** `DualPublicKey` lives in `brokkr-crypto`, which depends on
/// `brokkr-core`. A core register holding `DualPublicKey` would invert that direction and
/// break **I-5** (the spine does not depend on what it governs). The register therefore
/// declares raw bytes; SINDRI's resolver mints a `DualPublicKey` per resolution via
/// `from_public_bytes`, which is length-validated and fail-closed — a malformed key fails
/// at resolution, not silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootOfTrustEntry {
    pub subject: SubjectId,
    /// Raw ML-DSA-65 public key. Length-validated on import (by the resolver, Phase 5).
    pub ml_dsa_public: Vec<u8>,
    /// Raw SLH-DSA-SHAKE-192s public key. Length-validated on import (by the resolver).
    pub slh_dsa_public: Vec<u8>,
}

/// The signed roots-of-trust register: whose signatures BROKKR will believe (OQGF-M-8).
/// `SelfModifying` (I-7) — the most consequential register in the genome. The pre-shared
/// residual stands (§13; RISK-2026-0005): trust rests on out-of-band registration, not on
/// a hardware root of trust certifying a key at attestation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootsOfTrust {
    pub entries: Vec<RootOfTrustEntry>,
    pub signature: DualSignature,
}

/// A declarative invariant predicate (OQGF-M-10; Rev 1.4). An action VIOLATES this
/// invariant if the tool it names requires any forbidden capability, or carries a
/// forbidden privilege class — both computable from the signed registers alone, with **no**
/// interpretation of `Action.detail`. Detail-level invariants (e.g. "read-only outside
/// ./src") require interpreting an opaque `String` and are a **named residual** (§13), not
/// expressible here by design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantEntry {
    pub invariant: Invariant,
    pub forbids_capabilities: Vec<Capability>,
    pub forbids_privilege: Vec<PrivilegeClass>,
}

/// The field set a declared [`Purpose`] is permitted to admit (OQGF-P-11.2).
///
/// A closed vocabulary for the same reason `PolicyRegister::capabilities` is one (Rev 1.5):
/// `FieldName` is an open string newtype, so without a declared set nothing distinguishes
/// `dob` from `bod`, and a typo becomes a silently permanent refusal rather than a loud
/// promotion failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurposeFieldPolicy {
    /// Matched against the `Purpose` declared on a crossing.
    pub purpose: Purpose,
    /// The closed set of fields this purpose may admit. **An empty set means this purpose
    /// may admit no fields** — a datum declaring none passes containment vacuously, and any
    /// declared field is refused.
    pub allowed: Vec<FieldName>,
}

/// The signed policy register (OQGF-G-8 policy-as-code; OQGF-G-4 disallow-list; OQGF-M-10
/// invariants; Rev 1.4). Types only in this revision — the promotion gate that evaluates
/// `disallowed` and the construction-time invariant check are Phase 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRegister {
    /// The closed vocabulary of capabilities BROKKR recognizes (Rev 1.5). Every
    /// capability a tool requires (`ToolEntry::required_capabilities`), and every
    /// capability an invariant forbids (`InvariantEntry::forbids_capabilities`),
    /// SHALL appear here. `Capability` is an open `String` newtype, so without this
    /// set there is nothing to check a declaration against: nothing distinguishes
    /// `write` from `wirte`. Promotion-gate predicates 5 and 6 (Phase 5) check
    /// against it; this revision places the field only.
    pub capabilities: Vec<Capability>,
    pub invariants: Vec<InvariantEntry>,
    /// The field set each declared `Purpose` may admit (OQGF-P-11.2, ARCH Rev 1.29 §6.5).
    ///
    /// **Here rather than on `Purpose`, and that is the security argument, not a modelling
    /// preference.** A `Purpose` travels *on the crossing* inside the BCR. If the allowed
    /// set travelled with it, the party assembling the data would declare both the fields
    /// it is admitting **and** the fields it may admit — a producer's claim checked against
    /// the same producer's claim, which is the circular shape §7 names and the defect
    /// Rev 1.22 refused when it declined a caller-supplied tier for `promote`: **the thing
    /// being governed does not supply the terms of its own governance.**
    ///
    /// Minimization is a DAP judgment made in advance, not a computation: whether a field
    /// is *necessary* for a purpose is answerable only from why the data is collected. The
    /// gate does not determine necessity — it holds a declaration to what was signed.
    pub purpose_fields: Vec<PurposeFieldPolicy>,
    /// Algorithms that fail the promotion gate (OQGF-G-4). Typed identifiers, never
    /// strings (OQGF-G-5).
    pub disallowed: Vec<AlgorithmId>,
    pub signature: DualSignature,
}

/// What BROKKR is made of — **six** signed registers plus a genome signature (Rev 1.4).
///
/// **I-10 (type-level shape)** — every register and the `signature` are required fields.
/// An unsigned or incomplete genome is unrepresentable. Rev 1.4 extends this to the two
/// new registers, `roots` and `policy`: a genome missing either does not compile, exactly
/// as an unsigned one already did not. The running promotion gate (OQGF-G-4,
/// Deterministic) is Phase 5; the *type* that forbids an incomplete genome is here.
///
/// The genome signature is not optional (I-10) — this does not compile (`None` as the
/// 11th argument, the signature; Rev 1.22 inserted `tier` as the 8th):
///
/// ```compile_fail,E0308
/// use brokkr_core::genome::Genome;
/// fn any<T>() -> T { unimplemented!() }
/// let _ = Genome::new(
///     any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), None,
/// );
/// // E0308: mismatched types — expected `DualSignature`, found `Option<_>` (11th arg)
/// ```
///
/// Rev 1.4's new `roots` register is required too (the I-10 extension to the new
/// registers) — a `None` for it does not compile (`None` as the 6th argument):
///
/// ```compile_fail,E0308
/// use brokkr_core::genome::Genome;
/// fn any<T>() -> T { unimplemented!() }
/// let _ = Genome::new(
///     any(), any(), any(), any(), any(), None, any(), any(), any(), any(), any(),
/// );
/// // E0308: mismatched types — expected `RootsOfTrust`, found `Option<_>` (6th arg)
/// ```
///
/// Rev 1.22's `tier` is required on the same footing — a `None` for it does not compile
/// (`None` as the 8th argument), so a genome that declares no conformance level is
/// unrepresentable and predicate 7 always has a tier to check against:
///
/// ```compile_fail,E0308
/// use brokkr_core::genome::Genome;
/// fn any<T>() -> T { unimplemented!() }
/// let _ = Genome::new(
///     any(), any(), any(), any(), any(), any(), any(), None, any(), any(), any(),
/// );
/// // E0308: mismatched types — expected `ConformanceTier`, found `Option<_>` (8th arg)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Genome {
    pub version: GenomeVersion,
    pub tools: ToolGenome,
    pub cbom: Cbom,
    pub aibom: Aibom,
    pub endpoints: EndpointRegistry,
    pub roots: RootsOfTrust,
    pub policy: PolicyRegister,
    /// The conformance level this genome is built to (ARCH Rev 1.22).
    ///
    /// **Inside the genome's signed content**, so changing the declared tier changes the
    /// genome signature and requires re-promotion — a downgrade that would relax what
    /// promotion-gate predicate 7 demands of key custody is a visible, signed,
    /// DAP-attributed act rather than a configuration edit.
    ///
    /// It is a genome field rather than a `promote` parameter deliberately: a
    /// caller-supplied tier would let **the party being checked choose the threshold it is
    /// checked against**, the defect I-12 forecloses for `ClearedContext` and I-1 for
    /// `AuthorizedAction`. The thing being governed does not supply the terms of its own
    /// governance.
    pub tier: ConformanceTier,
    pub corpus_digest: Digest,
    pub owner: Dap,
    pub signature: DualSignature,
}

impl Genome {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: GenomeVersion,
        tools: ToolGenome,
        cbom: Cbom,
        aibom: Aibom,
        endpoints: EndpointRegistry,
        roots: RootsOfTrust,
        policy: PolicyRegister,
        tier: ConformanceTier,
        corpus_digest: Digest,
        owner: Dap,
        signature: DualSignature,
    ) -> Self {
        Self {
            version,
            tools,
            cbom,
            aibom,
            endpoints,
            roots,
            policy,
            tier,
            corpus_digest,
            owner,
            signature,
        }
    }
}
