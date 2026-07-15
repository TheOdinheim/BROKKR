//! AMD-008 (OQGF-P-10) — the Risk Register, and the AMD-006 (OQGF-P-9)
//! [`RiskAcceptance`] accountability type its `Accept` disposition reuses.
//!
//! **Provenance note (created 15 July 2026, Phase 1 revision).** `RiskAcceptance` did
//! **not** previously exist in `brokkr-core` — only the id newtype `RiskAcceptanceId`
//! did (`ids.rs`). It is the AMD-006 §5.1 corpus-specified accountability record, and
//! `gaps/GAP-2026-07-15-001.md` §3 recorded that it must enter `brokkr-core` so a *core*
//! `Disposition::Accept` can carry it (a core type may not depend on the Phase-6 barrier
//! crate, I-5). It is defined here **once** — not duplicated, not redefined — because
//! there was nothing to reuse. Its `gate` is `Some` for a Deterministic-Gate finding and
//! `None` for a non-gate risk, per OQGF-P-10.4.
//!
//! Persistence (append-only, Organ 5) is `brokkr-audit` (Phase 7). This file is the
//! type surface only.

use crate::crypto::DualSignature;
use crate::ids::{Dap, RiskAcceptanceId, Timestamp};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

string_id! {
    /// Identifier of a risk in the Register (OQGF-P-10.1).
    RiskId,
}

/// The two Deterministic Gates a [`RiskAcceptance`] may attach to (OQGF-G-4, OQGF-M-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeterministicGateId {
    /// The Genetic-Layer promotion gate (OQGF-G-4).
    Genome,
    /// The MHC attestation gate (OQGF-M-1).
    Mhc,
}

/// The AMD-006 (OQGF-P-9) accountable risk-acceptance record. Created in this revision
/// because it was absent from `brokkr-core` (see the module note). For a Deterministic-
/// Gate finding `gate` is `Some(_)`; for a non-gate risk (OQGF-P-10.4) it is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAcceptance {
    /// The still-visible finding this acceptance proceeds past.
    pub finding: RiskAcceptanceId,
    /// The gate the finding was caught at, or `None` for a non-gate risk (OQGF-P-10.4).
    pub gate: Option<DeterministicGateId>,
    /// The accountable party (OQGF-A-5). Reuses the existing `Dap` type.
    pub dap: Dap,
    /// Why the risk is being accepted.
    pub justification: String,
    /// Acceptance is bounded and renewable, never permanent (OQGF-P-9.3).
    pub expiry: Timestamp,
    /// Binds the acceptance to the issuing DAP (dual-family at High-Assurance).
    pub signature: DualSignature,
}

/// A qualitative likelihood assessment (OQGF-P-10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Likelihood {
    Rare,
    Unlikely,
    Possible,
    Likely,
    AlmostCertain,
}

/// A qualitative impact assessment (OQGF-P-10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Impact {
    Negligible,
    Minor,
    Moderate,
    Major,
    Severe,
}

/// Where a risk entered the Register (OQGF-P-10.2 provenance). The *continuous*
/// identification that feeds these is behavioral and lives downstream (audit, sentinel,
/// genome); this enum is the provenance value it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskSource {
    /// A confirmed incident, including autoimmunity/storm (OQGF-P-5).
    Incident,
    /// A per-crate `THREAT_MODEL.md` finding.
    ThreatModel,
    /// A Deterministic-Gate finding (OQGF-G-4 / OQGF-M-1).
    DeterministicGate,
    /// A supply-chain or dependency change.
    SupplyChain,
    /// External threat intelligence.
    ExternalIntel,
    /// A material change to the system or its operating environment.
    EnvironmentChange,
}

/// How a Transfer disposition shifts a risk to a third party (OQGF-P-10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMechanism {
    Contract,
    Insurance,
    ThirdParty,
}

/// Whether a treatment plan has been executed (OQGF-P-10.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreatmentStatus {
    /// Decided but not yet executed — remains a visible open item (OQGF-P-10.5).
    Open,
    /// Executed.
    Executed,
}

/// A tracked treatment plan for an Avoid/Reduce/Transfer disposition (OQGF-P-10.3,
/// OQGF-P-10.5). Reuses the existing `Dap` type for the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreatmentPlan {
    pub owner: Dap,
    pub target: Timestamp,
    pub status: TreatmentStatus,
}

/// Exactly one of the four canonical risk responses (OQGF-P-10.3).
///
/// Mutual exclusivity is by enum construction — a risk carries exactly one variant;
/// that is how enums work, not a new structural invariant. `Reduce`/`Transfer` carry a
/// `residual: Box<RiskEntry>` (not `Option`), so a disposition that mitigates without an
/// assessed residual is unrepresentable (OQGF-P-10.5). `Box` is required because the
/// type is recursive under `no_std`.
///
/// `Reduce` cannot be built without a residual — a required-field shape property, not a
/// numbered invariant:
///
/// ```compile_fail,E0063
/// use brokkr_core::risk::{Disposition, TreatmentPlan, TreatmentStatus};
/// use brokkr_core::ids::{Dap, Timestamp};
/// let plan = TreatmentPlan { owner: Dap::new("d", "1"), target: Timestamp(1), status: TreatmentStatus::Open };
/// let _ = Disposition::Reduce { plan }; // E0063: missing field `residual`
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Avoid {
        plan: TreatmentPlan,
    },
    Reduce {
        plan: TreatmentPlan,
        residual: Box<RiskEntry>,
    },
    Transfer {
        mechanism: TransferMechanism,
        residual: Box<RiskEntry>,
    },
    /// Reuses the AMD-006 [`RiskAcceptance`] accountability record (OQGF-P-10.4).
    Accept {
        acceptance: RiskAcceptance,
    },
}

/// One risk in the Register: assessed, owned, dispositioned (OQGF-P-10.1). Reuses the
/// existing `Dap` type for the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskEntry {
    pub id: RiskId,
    pub description: String,
    pub context: String,
    pub likelihood: Likelihood,
    pub impact: Impact,
    pub owner: Dap,
    pub source: RiskSource,
    pub disposition: Disposition,
}

/// The continuously maintained catalog of identified risks (OQGF-P-10.1, OQGF-P-10.6).
///
/// This is the type surface. Continuous identification (OQGF-P-10.2), append-only
/// persistence and periodic review (OQGF-P-10.6) are behavioral and live in
/// `brokkr-audit` (Organ 5, Phase 7); an implementor there provides these methods.
pub trait RiskRegister: Send + Sync {
    /// Record a newly identified risk, returning its id.
    fn record(&self, risk: RiskEntry) -> RiskId;

    /// The standing inventory of all identified risks and their dispositions
    /// (OQGF-P-10.6).
    fn inventory(&self) -> Vec<RiskEntry>;
}
