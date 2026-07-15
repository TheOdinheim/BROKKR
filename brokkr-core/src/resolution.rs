//! EIR — the Resolution Engine (AMD-005).
//!
//! I-8 is encoded here in two halves: an [`EscalationType`] cannot be constructed
//! without a resolution path and a baseline (the fields are not optional — no
//! one-way ratchets, OQGF-P-8.1); and a [`ResolutionDecision`] cannot be
//! constructed without a DAP and a signature, so a de-escalation with no
//! accountable party is unrepresentable (OQGF-P-8.2, OQGF-P-8.5).

use crate::crypto::DualSignature;
use crate::ids::{Dap, EscalationId, Timestamp};
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

/// The criteria marking an escalation's trigger "cleared".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearCondition {
    pub detail: String,
}

/// The homeostatic set point an escalation returns to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselinePosture {
    pub detail: String,
}

/// A registered escalation type.
///
/// **I-8 (first half)** — `resolution_criteria` and `baseline` are required
/// fields, not `Option`. An escalation with no way down is not a value this type
/// can hold (OQGF-P-8.1: *there are no one-way ratchets*).
///
/// This does not compile — a `None` cannot stand in for the required baseline:
///
/// ```compile_fail,E0308
/// use brokkr_core::resolution::EscalationType;
/// fn any<T>() -> T { unimplemented!() }
/// let _ = EscalationType::new(any(), any(), None, any(), any(), any());
/// // E0308: mismatched types — expected `BaselinePosture`, found `Option<_>` (3rd arg)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationType {
    pub id: EscalationId,
    pub resolution_criteria: ClearCondition,
    pub baseline: BaselinePosture,
    pub dwell_min: Duration,
    pub hold_window: Duration,
    pub max_duration: Duration,
}

impl EscalationType {
    pub fn new(
        id: EscalationId,
        resolution_criteria: ClearCondition,
        baseline: BaselinePosture,
        dwell_min: Duration,
        hold_window: Duration,
        max_duration: Duration,
    ) -> Self {
        Self {
            id,
            resolution_criteria,
            baseline,
            dwell_min,
            hold_window,
            max_duration,
        }
    }
}

/// Evidence that the clear condition was met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearEvidence {
    pub detail: String,
}

/// An explicit, recorded de-escalation decision.
///
/// **I-8 (second half)** — `dap` and `signature` are required fields. A resolution
/// without a named, accountable DAP is unrepresentable (OQGF-P-8.2, OQGF-P-8.5).
///
/// This does not compile — the DAP is not optional:
///
/// ```compile_fail,E0308
/// use brokkr_core::resolution::ResolutionDecision;
/// fn any<T>() -> T { unimplemented!() }
/// let _ = ResolutionDecision::new(any(), any(), None, any(), any());
/// // E0308: mismatched types — expected `Dap`, found `Option<_>` (3rd arg)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionDecision {
    pub escalation: EscalationId,
    pub cleared_condition: ClearEvidence,
    pub dap: Dap,
    pub at: Timestamp,
    pub signature: DualSignature,
}

impl ResolutionDecision {
    pub fn new(
        escalation: EscalationId,
        cleared_condition: ClearEvidence,
        dap: Dap,
        at: Timestamp,
        signature: DualSignature,
    ) -> Self {
        Self {
            escalation,
            cleared_condition,
            dap,
            at,
            signature,
        }
    }
}

/// Whether an escalation may come down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionVerdict {
    /// Criteria met and hysteresis satisfied. Above baseline, `needs_dap` is true
    /// (OQGF-P-8.5).
    Eligible { needs_dap: bool },
    /// Not yet resolvable.
    NotYet { reason: String },
    /// Past its maximum duration (OQGF-P-8.6).
    Chronic,
}

/// Confirmation that an escalation returned to baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnedToBaseline {
    pub escalation: EscalationId,
}

/// An escalation flagged as chronic (OQGF-P-8.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChronicEscalation {
    pub escalation: EscalationId,
}

error_enum! {
    /// Why a resolution was refused.
    pub enum ResolveError {
        CriteriaNotMet => "resolution criteria not met (OQGF-P-8.1)",
        HysteresisNotSatisfied => "dwell/hold hysteresis not satisfied (OQGF-P-8.3)",
        NeedsDapConfirmation => "de-escalation above baseline requires DAP confirmation (OQGF-P-8.5)",
    }
}

/// The resolution engine (EIR, Phase 8). Autonomous action may raise posture;
/// nothing autonomous lowers it above baseline (OQGF-P-8.5).
pub trait ResolutionEngine: Send + Sync {
    fn may_resolve(&self, escalation: &EscalationId) -> ResolutionVerdict;
    fn resolve(&self, decision: ResolutionDecision) -> Result<ReturnedToBaseline, ResolveError>;
    fn scan_chronic(&self) -> Vec<ChronicEscalation>;
}
