//! HÚÐ — the Barrier (AMD-007), and the [`BarrierVerdict`] whose `Deny` has no
//! path to `Allow` (I-2).

use crate::classification::{ChannelStrength, Classification, NamedGroup};
use crate::ids::{DatumRef, Host, ModelEndpointId, ResourcePath, RiskAcceptanceId};
use alloc::string::String;

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

/// A proposed crossing: some classified content bound for some destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryFlow {
    pub classification: Classification,
    pub destination: Destination,
}

/// HÚÐ's contract (implemented in Phase 6). Evaluation returns a [`BarrierVerdict`];
/// there is no method anywhere that turns a `Deny` into an `Allow`.
pub trait Barrier: Send + Sync {
    fn evaluate(&self, flow: &BoundaryFlow) -> BarrierVerdict;
}
