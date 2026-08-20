//! The confirmed-incident ledger seam (Task 2 / Step-0 reading (c), OQGF-P-6.1).
//!
//! P-6.1 requires a Refined Detector to be seeded only by a **DAP-confirmed incident recorded in
//! Organ 5**. `brokkr-adapt` SHALL NOT depend on `brokkr-audit` (Organ 5), so [`Kvasir::generate`]
//! cannot read SAGA itself. A [`SeedingIncident`] carries its own `confirmed_by: Dap` — but **a
//! gate that accepts its input's own claim about itself is not a gate.** This seam is how
//! `generate` becomes a real gate: it verifies the incident against an external source of truth
//! rather than the caller's assertion.
//!
//! **Honest limitation (reported in the conformance record).** At Phase 9 the only implementation
//! is [`InMemoryLedger`], a test double. The *production* binding — querying the actual
//! DAP-confirmed incidents recorded in SAGA — is this seam's Phase-11 implementation (recording to
//! Organ 5 is out of scope for Phase 9; querying it is Phase-11 wiring). The gate is structurally
//! real *given a faithful ledger*; whether the ledger faithfully reflects Organ 5 is the Phase-11
//! implementor's responsibility, not something `brokkr-adapt` can verify from committed types.
//!
//! [`Kvasir::generate`]: crate::Kvasir::generate
//! [`SeedingIncident`]: brokkr_core::adapt::SeedingIncident

use brokkr_core::ids::{Dap, IncidentId};

/// Whether an incident is genuinely recorded and DAP-confirmed in Organ 5, and by whom.
///
/// `generate` refuses `UnconfirmedSeed` when this returns `None`, **or** when the confirming
/// `Dap` it returns differs from the seed's `confirmed_by` — so a caller cannot assert a
/// confirmation the ledger does not record, nor attribute it to a different DAP.
pub trait ConfirmedIncidentLedger: Send + Sync {
    fn confirmation(&self, incident: &IncidentId) -> Option<Dap>;
}

/// An in-memory [`ConfirmedIncidentLedger`] — the seam's test double. Production queries SAGA
/// (Phase 11); see the module doc.
pub struct InMemoryLedger {
    confirmed: Vec<(IncidentId, Dap)>,
}

impl InMemoryLedger {
    pub fn new(confirmed: Vec<(IncidentId, Dap)>) -> Self {
        Self { confirmed }
    }
}

impl ConfirmedIncidentLedger for InMemoryLedger {
    fn confirmation(&self, incident: &IncidentId) -> Option<Dap> {
        self.confirmed
            .iter()
            .find(|(id, _)| id == incident)
            .map(|(_, dap)| dap.clone())
    }
}
