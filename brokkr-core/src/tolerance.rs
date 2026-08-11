//! HEIMDALL's tolerance controller and host-harm monitor (AMD-002).
//!
//! I-4 is encoded here: [`ToleranceController::grant`] refuses a `Deterministic`
//! target with an error — never a silent no-op. The refusal lives in the provided
//! method, in core, so no implementor can skip it (OQGF-P-2).

use crate::crypto::{Digest, DualSignature};
use crate::gate::Action;
use crate::ids::{Dap, DetectorId, GrantId, SelfSetVersion, Timestamp};
use alloc::string::String;

/// Classifies every defensive response. Tolerance may attach only to `Heuristic`
/// (OQGF-P-2). This enum is the structural boundary between the trained layer and
/// the conserved-pattern (deterministic) layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseClass {
    Deterministic,
    Heuristic,
}

/// The narrow scope of a tolerance grant (a specific detector/signal/pattern).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionScope {
    pub detail: String,
}

/// A signed, scoped, expiring suppression of a confirmed false positive — the
/// peripheral-tolerance (Treg) analog (OQGF-P-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToleranceGrant {
    pub target: DetectorId,
    pub scope: SuppressionScope,
    pub dap: Dap,
    pub issued: Timestamp,
    pub expiry: Timestamp,
    pub signature: DualSignature,
}

error_enum! {
    /// Why a tolerance operation was refused.
    pub enum ToleranceError {
        NonSuppressibleGate => "cannot attach a tolerance grant to a Deterministic gate (OQGF-P-2)",
        FailsCentralTolerance => "detector fails central-tolerance screening against the Self Set (OQGF-P-3)",
        Expired => "the tolerance grant has expired (OQGF-P-4)",
        OutOfScope => "the tolerance grant is out of scope (OQGF-P-4)",
    }
}

/// Host-harm measurement against the declared bound (OQGF-P-1, OQGF-P-5).
///
/// Not `Eq`/`Hash`: it carries `f64`.
#[derive(Debug, Clone, PartialEq)]
pub struct HostHarmReport {
    /// Legitimate actions harmed / legitimate actions.
    pub rate: f64,
    /// The declared ceiling (OQGF-P-1).
    pub bound: f64,
    /// Sustained breach of the bound (OQGF-P-5a).
    pub autoimmunity: bool,
    /// A single response beyond the declared blast radius (OQGF-P-5b).
    pub storm: Option<StormEvent>,
}

/// A response whose magnitude threatens host availability (OQGF-P-5b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StormEvent {
    pub detail: String,
}

/// The **kind** of defensive response that can constitute host harm when applied to
/// legitimate work (OQGF-P-1) — the four §6.7 names. This records **what was done**, not
/// a verdict: it is the after-the-fact classification of a response for host-harm
/// accounting. The deterministic verdict types stay exactly where they are — a
/// costimulation refusal is still an [`crate::gate::AnergyReason`], a barrier decision
/// still a [`crate::barrier::BarrierVerdict`]. `DefensiveResponse` does not replace or
/// convert either; it names the category a confirmed [`HostHarmIncident`] falls into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefensiveResponse {
    /// Architectural anergy — a costimulation denial (AMD-001).
    Anergy,
    /// A barrier egress denial (OQGF-I-10).
    Deny,
    /// A barrier ingress quarantine (OQGF-I-11).
    Quarantine,
    /// A rate-limiting throttle (OQGF-I-6 graded response).
    Throttle,
}

/// A defensive response a DAP has confirmed was applied to **legitimate** work — the
/// numerator of the host-harm rate (OQGF-P-1).
///
/// This is the deliberate mirror of [`crate::adapt::SeedingIncident`], and both exist for
/// the same reason: whether a blocked action was legitimate is **not derivable from the
/// action** — someone who knows the work has to say so. `SeedingIncident` is a
/// DAP-confirmed **true** positive, the only thing that may seed learning (OQGF-P-6.1);
/// `HostHarmIncident` is a DAP-confirmed **false** positive, the only thing that counts
/// toward the host-harm rate (OQGF-P-1). Confirmation is a human act in **both**
/// directions.
///
/// `confirmed_by` is **required, not `Option`**: an unconfirmed report is not a host-harm
/// incident, and this type cannot represent one.
///
/// The **rate** — this numerator over the count of governed actions a gate or the barrier
/// evaluated in the window — is computed in `brokkr-sentinel` (HEIMDALL, Phase 8), **not
/// here**. §13 records that rate as a **lower bound**: it counts only *confirmed* false
/// positives, so an unreported one never appears and the measured rate under-states real
/// host harm, always in the same direction — toward looking safer than it is. A rising
/// confirmed rate is real; a low one is weak evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHarmIncident {
    /// What was done to the legitimate action.
    pub response: DefensiveResponse,
    /// The legitimate action that was harmed. `Action` is `Clone`, so the incident owns
    /// its own copy.
    pub action: Action,
    /// The accountable natural person who confirmed the action was legitimate (OQGF-A-5).
    pub confirmed_by: Dap,
    pub at: Timestamp,
}

/// The declared known-good baseline ("self"), screened against before deployment
/// (central tolerance, OQGF-P-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfSet {
    pub version: SelfSetVersion,
    pub corpus_digest: Digest,
    pub owner: Dap,
}

/// A heuristic detector under screening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorSpec {
    pub id: DetectorId,
}

/// A passed central-tolerance screening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenPass {
    pub version: SelfSetVersion,
}

/// The tolerance controller (HEIMDALL, Phase 8).
///
/// **I-4** — the `Deterministic` refusal is enforced in the provided
/// [`grant`](Self::grant), in core. An implementor supplies only the heuristic
/// path ([`grant_heuristic`](Self::grant_heuristic)), which is never reached for a
/// `Deterministic` target.
pub trait ToleranceController: Send + Sync {
    /// Attach a grant to a heuristic detector. Reached only for `Heuristic` targets.
    fn grant_heuristic(&self, grant: ToleranceGrant) -> Result<GrantId, ToleranceError>;

    /// Screen a heuristic detector against the Self Set before deployment
    /// (OQGF-P-3).
    fn screen(
        &self,
        detector: &DetectorSpec,
        self_set: &SelfSet,
    ) -> Result<ScreenPass, ToleranceError>;

    /// Current host-harm posture (OQGF-P-1, OQGF-P-5).
    fn host_harm(&self) -> HostHarmReport;

    /// Attach a tolerance grant. **Refuses a `Deterministic` target** with
    /// [`ToleranceError::NonSuppressibleGate`] — an error, never a silent no-op
    /// (I-4 / OQGF-P-2).
    fn grant(
        &self,
        grant: ToleranceGrant,
        class: ResponseClass,
    ) -> Result<GrantId, ToleranceError> {
        match class {
            ResponseClass::Deterministic => Err(ToleranceError::NonSuppressibleGate),
            ResponseClass::Heuristic => self.grant_heuristic(grant),
        }
    }
}
