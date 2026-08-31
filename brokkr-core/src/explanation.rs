//! AMD-010 — Explanation Validity (OQGF-A-8 … A-12), extending Organ 5's
//! quantum-appropriate explanation artifact (OQGF-A-4).
//!
//! **Type surface only (Option B).** AMD-010 governs *quantum ML* explanation
//! artifacts — bounded Pauli-string scope, classical-shadow estimation,
//! trainability reconciliation, and canary-probe channel attestation. BROKKR runs
//! a classical LLM: BROKKR-ARCH §1.4 declares OQGF-A-4 (quantum explanation
//! artifacts) `n.a.` ("no variational or kernel quantum model in the decision
//! path"), so there is nothing to exercise this logic against — building it would
//! be dead code. These types are placed so the architecture can reference them and
//! the surface is ready when a quantum workload arrives. No constructors beyond
//! derive, no validation, no recording, no integration with SAGA / HEIMDALL / the
//! orchestrator — just the shapes.
//!
//! One structural property is worth stating even at the type level:
//! [`ExplanationValidity`] has **no variant in which a `Null` explanation is
//! representable as `Valid`** (OQGF-A-9), and its `Null` arm makes the OQGF-A-10
//! DAP acknowledgment an explicit `Option` a consumer must confront before acting
//! on an unexplained decision.

use alloc::string::String;

use crate::crypto::DualSignature;
use crate::risk::RiskId;

/// Reference to the OQGF-A-1 decision record an explanation artifact explains. No
/// `DecisionRef` type existed in the workspace; this is the minimal wrapper AMD-010
/// places alongside the artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRef(pub String);

/// OQGF-A-8 — Bounded Explanation Scope. Every artifact declares what it covers
/// (the estimation method, the weight / Pauli-string bound `k`, the sample count,
/// and a confidence interval) and never implies coverage beyond that bound.
/// Carries an `f64`-bearing [`ConfidenceInterval`], so it is not `Eq`.
#[derive(Debug, Clone)]
pub struct ExplanationScope {
    pub method: EstimationMethod,
    /// `k` — the declared weight / Pauli-string bound (operator-declared, not fixed by the spec).
    pub weight_bound: u8,
    pub samples: u64,
    pub confidence: ConfidenceInterval,
}

/// The bounded-estimation method behind an [`ExplanationScope`] (OQGF-A-8).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EstimationMethod {
    /// Classical-shadow estimation — the RECOMMENDED bounded method (OQGF-A-8).
    ClassicalShadow,
    DirectExpectation,
    Kernel,
    Other(String),
}

/// A confidence interval at a stated level (e.g. `level = 0.95` for 95%). Carries
/// `f64`, so it is not `Eq`.
#[derive(Debug, Clone)]
pub struct ConfidenceInterval {
    pub lower: f64,
    pub upper: f64,
    pub level: f64,
}

/// OQGF-A-9 — Explanation Validity. A `Null` explanation is **never** recorded,
/// reported, or exported as `Valid`, and is never omitted: absence of explanation
/// is recorded as absence. There is no representable path from `Null` to `Valid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplanationValidity {
    Valid,
    Null {
        cause: NullCause,
        /// OQGF-A-10 — the decision SHALL NOT be acted upon until this is present
        /// and signed. `None` => unexplained and unacknowledged => no action.
        acknowledgment: Option<DapAcknowledgment>,
        /// OQGF-A-10 — the corresponding AMD-008 Risk Register entry.
        risk_ref: RiskId,
    },
}

/// Why an explanation is [`ExplanationValidity::Null`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NullCause {
    /// Flat AND consistent with the declared Trainability Profile: real physics.
    ExpectedTrainabilityRegime,
    /// Flat or distorted AND deviating from the profile: an incident (A.6.1).
    ReconciliationAnomaly,
    /// The Canary Probe failed — the channel, not the model, is non-responsive.
    ChannelFailure,
}

/// OQGF-A-10 — a signed DAP acknowledgment for proceeding with an unexplained
/// (Null) regulated decision. Its presence is the precondition for action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DapAcknowledgment {
    pub decision_ref: DecisionRef,
    pub cause: NullCause,
    pub justification: String,
    pub signature: DualSignature,
}

/// OQGF-A-11 — Trainability Declaration and Reconciliation: the OQGF-M-3
/// declare-then-test pattern applied to explainability. A profile is declared, an
/// observed signal statistic is measured, and a statistical test reconciles them
/// into a consistent-or-deviates outcome. Carries `f64`-bearing fields, not `Eq`.
#[derive(Debug, Clone)]
pub struct TrainabilityReconciliation {
    pub declared_profile: TrainabilityProfile,
    pub observed_signal: SignalStatistic,
    pub test: StatisticalTest,
    pub outcome: TrainabilityOutcome,
}

/// The declared expected trainability regime (OQGF-A-11). Carries `f64`, not `Eq`.
#[derive(Debug, Clone)]
pub struct TrainabilityProfile {
    pub expected_gradient_norm: f64,
    pub tolerance: f64,
}

/// The observed trainability signal (OQGF-A-11). Carries `f64`, not `Eq`.
#[derive(Debug, Clone)]
pub struct SignalStatistic {
    pub observed_gradient_norm: f64,
    pub sample_count: u64,
}

/// The statistical test reconciling declared vs observed (mirrors the OQGF-M-3
/// K-S / chi-squared machinery).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatisticalTest {
    KolmogorovSmirnov,
    ChiSquared,
    Other(String),
}

/// The reconciliation outcome (OQGF-A-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrainabilityOutcome {
    Consistent,
    Deviates,
}

/// OQGF-A-12 — Canary Probe / Explanation Channel Attestation. A known-answer,
/// analytically non-degenerate control circuit proving the explanation channel is
/// alive; a failure marks every artifact in its declared scope Null (Channel
/// Failure), so a broken channel cannot yield a single surviving "valid"
/// explanation. Carries `f64`, not `Eq`.
#[derive(Debug, Clone)]
pub struct CanaryAttestation {
    pub probe_circuit_id: String,
    pub expected_result: f64,
    pub observed_result: f64,
    pub passed: bool,
    pub granularity: CanaryGranularity,
}

/// The declared granularity at which the canary probe is run (OQGF-A-12).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanaryGranularity {
    PerSession,
    PerBatch,
    PerJob,
}

/// The complete explanation artifact (OQGF-A-4 extended by AMD-010): the decision
/// it explains, its declared scope, its validity, its trainability reconciliation,
/// an optional canary attestation, and a dual-family signature (OQGF-R-1). Stored
/// in Organ 5 beside the decision record. Carries `f64`-bearing fields, not `Eq`.
#[derive(Debug, Clone)]
pub struct ExplanationArtifact {
    pub decision_ref: DecisionRef,
    pub scope: ExplanationScope,
    pub validity: ExplanationValidity,
    pub trainability: TrainabilityReconciliation,
    pub canary: Option<CanaryAttestation>,
    pub signature: DualSignature,
}
