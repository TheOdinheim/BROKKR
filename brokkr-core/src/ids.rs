//! Common identifiers and small value types.
//!
//! [`Timestamp`] substitutes `std::time::SystemTime` and [`ResourcePath`]
//! substitutes `std::path::PathBuf`, so this crate is genuinely `no_std`. Neither
//! is invariant-bearing.

use alloc::string::String;

string_id! {
    /// Subject of an attestation (a hop, a workload).
    SubjectId,
    /// A registered model endpoint (REGIN).
    ModelEndpointId,
    /// A genome version tag.
    GenomeVersion,
    /// An escalation type identifier.
    EscalationId,
    /// A heuristic detector identifier.
    DetectorId,
    /// A tolerance-grant identifier.
    GrantId,
    /// A risk-acceptance-entry identifier (AMD-006).
    RiskAcceptanceId,
    /// An audit incident identifier (SAGA).
    IncidentId,
    /// A reasoning-hop identifier.
    HopId,
    /// A tool identifier (REGIN tool genome).
    ToolId,
    /// An evaluation-corpus version (KVASIR).
    CorpusVersion,
    /// A Self Set version (OQGF-P-3).
    SelfSetVersion,
    /// A network host.
    Host,
    /// A reference to a client certificate (mTLS, OQGF-M-5). Opaque here.
    ClientCertRef,
    /// A pinned server trust anchor.
    TrustAnchor,
    /// A reference to a datum crossing a boundary (AMD-007).
    DatumRef,
    /// The provenance root recorded on a Boundary Custody Record (AMD-007, OQGF-I-9).
    OriginId,
    /// Identity of a Deterministic-Gate finding an acceptance is scoped to (OQGF-P-9.2).
    FindingId,
    /// A named field of a personal datum (OQGF-P-11.2, ARCH Rev 1.29 §6.5). Declared on
    /// a crossing (`PersonalDataTag::fields`) and permitted by the signed
    /// `PurposeFieldPolicy`; the check is set containment over the two **declarations**,
    /// never an inspection of content.
    FieldName,
}

/// Epoch milliseconds. Substitutes `std::time::SystemTime` for `no_std`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u64);

/// A freshness nonce (OQGF-M-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nonce(pub u64);

/// A 0..=100 trust/score value (OQGF-M-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Score(pub u8);

/// A resource path. Substitutes `std::path::PathBuf` for `no_std`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourcePath(pub String);

impl ResourcePath {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The Designated Accountable Party — a natural person (OQGF-A-5).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dap {
    pub name: String,
    pub id: String,
}

impl Dap {
    pub fn new(name: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            id: id.into(),
        }
    }
}

/// A model's declared identity, recorded in the AIBOM (OQGF-G-2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModelIdentity {
    pub name: String,
    pub version: String,
    pub provider: String,
}

/// The organs that emit and receive coordinated signals (AMD-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrganId {
    Genome,
    Intent,
    Gate,
    Barrier,
    Sentinel,
    Resolution,
    Adapt,
    Audit,
    Bifrost,
    Reasoner,
}
