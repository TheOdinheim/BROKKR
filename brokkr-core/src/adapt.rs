//! KVASIR — the Maturation Pipeline (AMD-003).
//!
//! I-9 is encoded here: a [`RefinedDetector`] is `Heuristic` by construction. Its
//! `response_class` is private and fixed to `Heuristic`; there is no constructor,
//! conversion, or setter that makes it `Deterministic` (OQGF-P-2). Activation is
//! gated ([`MaturationPipeline::activate`] returns `Err(FailsTolerance)` /
//! `Err(NeedsApproval)`).
//!
//! ## The evaluation-corpus content seam is *not* here (Rev 1.17, §6.12)
//!
//! §6.12 specifies an `EvaluationCorpusContent` trait — `version()`, labeled
//! `samples()`, `digest()` — that Gate 2 (selection, OQGF-P-6.2) measures against.
//! Its `samples()` are `(Observation, Option<AttackClass>)` pairs, and `Observation`
//! is a **`brokkr-sentinel`** type. `brokkr-core` SHALL NOT depend on
//! `brokkr-sentinel` (**I-5**), so the seam **cannot live in core** and is not placed
//! here. It is a Phase-9 crate-local type in `brokkr-adapt`, beside its only consumer
//! ([`MaturationPipeline::select`]). [`AttackClass`] is a core type (below);
//! `Observation` is not, and moving it into core to make the seam fit is exactly the
//! dependency inversion I-5 forbids.

use crate::crypto::DualSignature;
use crate::ids::{CorpusVersion, Dap, DetectorId, IncidentId, Timestamp};
use crate::tolerance::{ResponseClass, ScreenPass};
use alloc::string::String;

/// A class of attack a refinement targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackClass {
    pub detail: String,
}

/// A DAP-confirmed true positive — the only thing that may seed learning
/// (OQGF-P-6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedingIncident {
    pub incident_id: IncidentId,
    pub confirmed_by: Dap,
    pub attack_class: AttackClass,
}

/// The heuristic detector a refinement is based on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorSpecBase {
    pub id: DetectorId,
}

/// The change a refinement makes (tighter pattern / threshold / signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorDelta {
    pub detail: String,
}

/// A candidate refined detector — the hypermutated variant.
///
/// **I-9** — `response_class` is private and set to [`ResponseClass::Heuristic`]
/// at construction. There is no path to make it `Deterministic`: no field to set,
/// no conversion, no configuration. BROKKR can learn to see better; it cannot
/// learn to see less.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinedDetector {
    base: DetectorSpecBase,
    change: DetectorDelta,
    generation: u64,
    response_class: ResponseClass,
}

impl RefinedDetector {
    pub fn new(base: DetectorSpecBase, change: DetectorDelta, generation: u64) -> Self {
        Self {
            base,
            change,
            generation,
            // Fixed at construction. A RefinedDetector is Heuristic. Always.
            response_class: ResponseClass::Heuristic,
        }
    }

    /// Always [`ResponseClass::Heuristic`] (I-9).
    pub fn response_class(&self) -> ResponseClass {
        self.response_class
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn base(&self) -> &DetectorSpecBase {
        &self.base
    }

    pub fn change(&self) -> &DetectorDelta {
        &self.change
    }
}

/// Signed lineage. A detector whose provenance cannot be reconstructed SHALL NOT
/// be active (OQGF-P-6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorProvenance {
    pub seeding: IncidentId,
    pub corpus_version: CorpusVersion,
    pub screen_result: ScreenPass,
    pub approver: Dap,
    pub signature: DualSignature,
}

/// An independent evaluation corpus (OQGF-P-6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationCorpus {
    pub version: CorpusVersion,
}

/// A passed independent-corpus selection (OQGF-P-6.2).
///
/// Carries the `version` it was selected against and the `produced_at` time it was
/// produced. **Version equality, not recency, is the gate** (§6.12): a pass one
/// minute old against a superseded corpus is invalid — it selected against evidence
/// that is no longer the declared corpus — while a pass a week old against the
/// current corpus is valid. `produced_at` is the **audit trail** that lets
/// [`MaturationPipeline::activate`] flag a version-current but implausibly-old pass;
/// it is never the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionPass {
    pub version: CorpusVersion,
    pub produced_at: Timestamp,
}

/// A handle to the generation replaced by an activation, so every activation is
/// reversible (OQGF-P-6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorGeneration {
    pub generation: u64,
}

error_enum! {
    /// Why a maturation step was refused. Each is a poisoning gate.
    pub enum AdaptError {
        UnconfirmedSeed => "refinement may only be seeded by a DAP-confirmed incident (OQGF-P-6.1)",
        Overfit => "candidate improves only on its seeding sample (OQGF-P-6.2)",
        CoverageRegression => "candidate degrades coverage elsewhere in the corpus (OQGF-P-6.2)",
        FailsTolerance => "candidate raises host harm above the bound, regardless of detection gains (OQGF-P-6.3)",
        NeedsApproval => "activation requires DAP approval at Enhanced (OQGF-P-6.6)",
    }
}

/// The maturation pipeline (KVASIR, Phase 9). Four poisoning gates. `brokkr-adapt`
/// SHALL NOT depend on `brokkr-reasoner`: the agent does not teach itself (I-9).
pub trait MaturationPipeline: Send + Sync {
    /// Refuses unconfirmed seeds (OQGF-P-6.1).
    fn generate(&self, seed: &SeedingIncident) -> Result<RefinedDetector, AdaptError>;

    /// Select against an independent corpus; disqualify overfit / coverage
    /// regression (OQGF-P-6.2).
    fn select(
        &self,
        candidate: &RefinedDetector,
        corpus: &EvaluationCorpus,
    ) -> Result<SelectionPass, AdaptError>;

    /// Activate only after selection, tolerance screening, and (at Enhanced) DAP
    /// approval. Returns the prior generation so activation is reversible
    /// (OQGF-P-6.3, P-6.5, P-6.6).
    ///
    /// Takes `now` per call (**I-13**): a clock held from construction silently stops
    /// catching an aging pass. `now` is **not itself the gate** — **version equality
    /// is** (§6.12). A Phase-9 implementor refuses a [`SelectionPass`] or
    /// [`ScreenPass`](crate::tolerance::ScreenPass) whose version is not the current
    /// one (a gate that did not run against the thing it was required to run against);
    /// `now` is the audit trail that makes a version-current but implausibly-old pass
    /// visible. This method carries `now` because it is the one that *evaluates* a
    /// pass against the present; [`generate`](Self::generate) and
    /// [`select`](Self::select) evaluate no time and take none.
    fn activate(
        &self,
        candidate: RefinedDetector,
        provenance: DetectorProvenance,
        now: Timestamp,
    ) -> Result<PriorGeneration, AdaptError>;
}
