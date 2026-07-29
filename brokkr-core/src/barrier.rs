//! HÚÐ — the Barrier (AMD-007), and the [`BarrierVerdict`] whose `Deny` has no
//! path to `Allow` (I-2).

use crate::classification::{ChannelStrength, Classification, NamedGroup};
use crate::crypto::DualSignature;
use crate::ids::{
    DatumRef, Host, ModelEndpointId, OriginId, ResourcePath, RiskAcceptanceId, Timestamp,
};
use alloc::string::String;
use alloc::vec::Vec;

/// A still-visible finding attached to a deterministic `Deny` (OQGF-I-10). It is
/// never removed; the only sanctioned way past is an `AcceptedRisk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierFinding {
    pub classification: Classification,
    pub reason: String,
}

/// The barrier's verdict on a proposed crossing.
///
/// **I-2 — a `Deny` cannot become an `Allow`.** There is deliberately no method,
/// `impl From`, or conversion of any kind on `Deny` (or on this enum) that yields
/// `Allow`. `AcceptedRisk` is a *distinct variant* — the only sanctioned way past a
/// deterministic `Deny` (AMD-006 / OQGF-P-9) — and it keeps the finding visible; it
/// is not a flag on `Allow`.
///
/// No such conversion exists, so this does not compile:
///
/// ```compile_fail,E0599
/// use brokkr_core::barrier::{BarrierVerdict, BarrierFinding};
/// use brokkr_core::classification::Classification;
/// let d = BarrierVerdict::Deny {
///     finding: BarrierFinding { classification: Classification::Secret, reason: "x".into() },
/// };
/// let _allow = d.into_allow(); // E0599: no method named `into_allow` found for enum `BarrierVerdict`
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BarrierVerdict {
    /// The crossing is permitted.
    Allow,
    /// Deterministic, non-suppressible (OQGF-I-10 inheriting OQGF-P-2). The
    /// finding stays visible.
    Deny { finding: BarrierFinding },
    /// Unprovenanced ingress into a privileged context (OQGF-I-11).
    Quarantine { datum: DatumRef },
    /// A DAP recorded a scoped, expiring, signed decision to proceed past a
    /// still-visible `Deny` (AMD-006 / OQGF-P-9). Distinct from `Allow` by
    /// construction.
    AcceptedRisk { entry: RiskAcceptanceId },
}

/// A destination is not merely *where* data goes; it is also the *pipe* it goes
/// through. The `Reasoner` variant is why Rev 1.2 exists: its authorization is
/// conditional on the channel actually negotiated (BROKKR-ARCH 6.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    LocalPath(ResourcePath),
    Network {
        host: Host,
        channel: ChannelStrength,
    },
    Reasoner {
        endpoint: ModelEndpointId,
        negotiated: NamedGroup,
    },
}

/// What a [`BoundaryCustodyRecord`] may pre-authorize: **where** data may go, not over
/// **what pipe**.
///
/// It is deliberately coarser than [`Destination`]. `Destination::Network` carries a live
/// [`ChannelStrength`] and `Destination::Reasoner` a negotiated [`NamedGroup`] — facts
/// about *this* crossing, established at connection time. A BCR is signed *before* the
/// crossing and cannot know them. If a BCR could pre-authorize a `ChannelStrength`, a
/// record written when a strong channel was available would authorize a later crossing
/// over a classical one. Two questions stay separate: *is this destination authorized*
/// (the BCR answers) and *is this channel strong enough* (`effective_authorization`
/// answers, from the negotiated group). Collapsing them would let a valid BCR launder a
/// weak channel (§6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationClass {
    LocalPath(ResourcePath),
    Network { host: Host },
    Reasoner { endpoint: ModelEndpointId },
}

/// Whether an ingress destination is a Privileged Context (AMD-007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextClass {
    /// A training corpus, evaluation dataset, fine-tuning corpus, model registry, or any
    /// AIBOM-governed artifact (OQGF-G-2). Unprovenanced data SHALL NOT enter here.
    Privileged,
    /// Any other context. Unprovenanced data **MAY** be used here (OQGF-I-11) — quarantine
    /// is not denial; only promotion into model-building artifacts is gated.
    NonPrivileged,
}

/// A Boundary Custody Record — a bill of materials for data in transit, sibling to the
/// CBOM (OQGF-G-1) and AIBOM (OQGF-G-2), and the secretory-IgA analog: a mark that travels
/// with the material and states something verifiable about it (OQGF-I-9).
///
/// One record serves both directions. At egress the `classification` and `authorized`
/// destinations decide; at ingress the `origin` is what makes provenance established — so a
/// separate ingress-provenance type would only duplicate a field this record already
/// carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryCustodyRecord {
    /// Which datum this record covers. A Phase-6 `evaluate` requires it to equal the flow's
    /// `datum`: this is what "matched at the Barrier" means (OQGF-I-9).
    pub datum: DatumRef,
    pub classification: Classification,
    /// The provenance root. At ingress this **is** the established provenance (OQGF-I-11);
    /// there is no separate provenance type.
    pub origin: OriginId,
    /// The destinations this record pre-authorizes — coarsely (see [`DestinationClass`]).
    pub authorized: Vec<DestinationClass>,
    pub issued: Timestamp,
    pub expiry: Timestamp,
    pub signature: DualSignature,
}

/// A proposed crossing. **The direction is the type, not a flag.**
///
/// Rev 1.5's `BoundaryFlow` carried a classification and a destination — an egress shape.
/// It could not express an ingress crossing at all, which made
/// [`BarrierVerdict::Quarantine`] **unreachable from `evaluate`**: the method held no
/// [`DatumRef`] to construct one with and no provenance to judge. Folding direction into
/// the type makes an ingress flow carrying a [`Destination`], or an egress flow carrying a
/// [`ContextClass`], **unrepresentable** (§6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryFlow {
    /// Data leaving a controlled compartment (OQGF-I-10). Absent `bcr` above Public is a
    /// `Deny` at Phase 6 — the Barrier does not infer custody it was not given.
    Egress {
        datum: DatumRef,
        classification: Classification,
        destination: Destination,
        bcr: Option<BoundaryCustodyRecord>,
    },
    /// Data arriving. Provenance is the BCR's `origin`; its absence is what quarantine
    /// responds to (OQGF-I-11).
    Ingress {
        datum: DatumRef,
        bcr: Option<BoundaryCustodyRecord>,
        context: ContextClass,
    },
}

/// HÚÐ's contract (implemented in Phase 6). Evaluation returns a [`BarrierVerdict`]; there
/// is no method anywhere that turns a `Deny` into an `Allow` (I-2).
///
/// `now` is an explicit parameter, **never a wall-clock read**: a BCR's `expiry` is checked
/// against it, and a gate whose verdict depends on an ambient clock is not
/// deterministically testable.
pub trait Barrier: Send + Sync {
    fn evaluate(&self, flow: &BoundaryFlow, now: Timestamp) -> BarrierVerdict;
}
