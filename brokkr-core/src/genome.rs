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
use crate::crypto::{Digest, DualSignature};
use crate::ids::{
    ClientCertRef, Dap, GenomeVersion, ModelEndpointId, ModelIdentity, Score, Timestamp, ToolId,
    TrustAnchor,
};
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
}

/// The signed tool register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolGenome {
    pub entries: Vec<ToolEntry>,
    pub signature: DualSignature,
}

/// The Cryptographic Bill of Materials (OQGF-G-1), CycloneDX 1.6 as an opaque
/// string here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cbom {
    pub cyclonedx: String,
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

/// What BROKKR is made of — four signed registers plus a genome signature.
///
/// **I-10 (type-level shape)** — `cbom`, `aibom`, `endpoints`, and `signature` are
/// all required fields. An unsigned or incomplete genome is unrepresentable. The
/// running promotion gate (OQGF-G-4, Deterministic) is Phase 5; the *type* that
/// forbids an unsigned genome is here.
///
/// This does not compile — the genome signature is not optional:
///
/// ```compile_fail,E0308
/// use brokkr_core::genome::Genome;
/// fn any<T>() -> T { unimplemented!() }
/// let _ = Genome::new(any(), any(), any(), any(), any(), any(), any(), None);
/// // E0308: mismatched types — expected `DualSignature`, found `Option<_>` (8th arg)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Genome {
    pub version: GenomeVersion,
    pub tools: ToolGenome,
    pub cbom: Cbom,
    pub aibom: Aibom,
    pub endpoints: EndpointRegistry,
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
            corpus_digest,
            owner,
            signature,
        }
    }
}
