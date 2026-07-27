//! REGIN — the Genome (OQGF-G): four signed registers (tools, CBOM, AIBOM,
//! endpoint registry).
//!
//! I-10 (type-level shape): a [`Genome`] cannot exist without a signature and all
//! four registers — the fields are required. The running promotion gate is Phase 5;
//! the type forbidding an unsigned genome lives here.
//!
//! I-11: [`ModelEndpoint::client_cert`] is a required field, not an `Option`.
//! One-sided TLS to a reasoner is unrepresentable (OQGF-M-5).

use crate::classification::{Classification, NamedGroup};
use crate::crypto::{Digest, DualSignature, HashAlg, KemAlg, SignatureAlg};
use crate::ids::{
    ClientCertRef, Dap, GenomeVersion, ModelEndpointId, ModelIdentity, Score, SubjectId, Timestamp,
    ToolId, TrustAnchor,
};
use crate::intent::{Capability, Invariant};
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
    pub signature: DualSignature,
}

/// The AI Bill of Materials (OQGF-G-2): models, providers, prompt/corpus digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aibom {
    pub cyclonedx: String,
    pub signature: DualSignature,
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
    pub reviewed: Timestamp,
    pub reviewer: Dap,
    pub signature: DualSignature,
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
/// 10th argument, the signature):
///
/// ```compile_fail,E0308
/// use brokkr_core::genome::Genome;
/// fn any<T>() -> T { unimplemented!() }
/// let _ = Genome::new(
///     any(), any(), any(), any(), any(), any(), any(), any(), any(), None,
/// );
/// // E0308: mismatched types — expected `DualSignature`, found `Option<_>` (10th arg)
/// ```
///
/// Rev 1.4's new `roots` register is required too (the I-10 extension to the new
/// registers) — a `None` for it does not compile (`None` as the 6th argument):
///
/// ```compile_fail,E0308
/// use brokkr_core::genome::Genome;
/// fn any<T>() -> T { unimplemented!() }
/// let _ = Genome::new(
///     any(), any(), any(), any(), any(), None, any(), any(), any(), any(),
/// );
/// // E0308: mismatched types — expected `RootsOfTrust`, found `Option<_>` (6th arg)
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
            corpus_digest,
            owner,
            signature,
        }
    }
}
