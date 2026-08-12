//! The observation surface and the detector seam (§6.7).
//!
//! HEIMDALL is the *trained*, heuristic layer. It is **fed** [`Observation`]s — it does not
//! reach into other crates to collect them (I-5). Every `Observation` variant is built from
//! types already committed in `brokkr-core`, so the sentinel observes a crossing without
//! depending on `brokkr-barrier` and an authorization without depending on `brokkr-gate`.

use brokkr_core::barrier::{BarrierVerdict, BoundaryFlow};
use brokkr_core::crypto::Digest;
use brokkr_core::gate::{Action, AnergyReason};
use brokkr_core::ids::{DetectorId, SelfSetVersion};
use brokkr_core::signal::{Severity, Signal};

/// What a heuristic detector may be shown (§6.7). Every variant is committed-core data.
///
/// `Crossing` carries a `BoundaryFlow` unboxed, matching the shape §6.7 places. The variants
/// differ in size (a crossing is larger than a hop); boxing to equalize them would diverge
/// from the declared surface for a size-heuristic gain that does not matter for an observation
/// passed by reference, so `large_enum_variant` is allowed here deliberately.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// A proposed crossing and the Barrier's verdict on it (OQGF-I-12).
    Crossing {
        flow: BoundaryFlow,
        verdict: BarrierVerdict,
    },
    /// An action presented to the gate and its outcome.
    Authorization {
        action: Action,
        granted: bool,
        anergy: Option<AnergyReason>,
    },
    /// A coordinated signal received (AMD-004).
    Signalled { signal: Signal },
    /// One hop of a reconciliation: what the intent authorized, what was executed.
    /// `executed` is `None` until the executor exists (Phase 11) — the absence of a
    /// comparison, not a deviation.
    Hop {
        authorized: Action,
        executed: Option<Action>,
    },
}

/// A heuristic detector's verdict.
///
/// **A detector cannot grant anything (structural).** This enum has exactly two variants —
/// `Clear` and `Fired` — and **no variant that permits an action**. The strongest act
/// available to a detector is to *fire*, which raises posture through the graded-response
/// path (OQGF-P-7); it never opens a gate. This is the interface analogue of
/// `RefinedDetector`'s fixed `Heuristic` class (I-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionVerdict {
    Clear,
    Fired { severity: Severity, detail: String },
}

/// A heuristic detector. `observe` may FIRE; it never authorizes (see [`DetectionVerdict`]).
pub trait Detector: Send + Sync {
    fn id(&self) -> &DetectorId;
    fn observe(&self, o: &Observation) -> DetectionVerdict;
}

/// The known-good baseline, supplied to HEIMDALL (§6.7). REGIN owns the declared `SelfSet`
/// record (`corpus_digest`, version, owner); this seam provides the observations that digest
/// is *of*. Screening recomputes the digest over `observations()` and binds it to the
/// declared `SelfSet.corpus_digest` — the digest field is not decoration, it is the binding.
pub trait SelfSetCorpus: Send + Sync {
    fn version(&self) -> SelfSetVersion;
    fn observations(&self) -> &[Observation];
    /// The corpus's self-reported digest. **Screening does not trust this** — it recomputes
    /// over `observations()` and compares to the declared `SelfSet.corpus_digest`.
    fn digest(&self) -> Digest;
}
