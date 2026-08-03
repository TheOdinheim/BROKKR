//! The two injected seams the Barrier depends on — the endpoint-ceiling resolver (Task 5)
//! and the risk-acceptance resolver (Task 6). Both follow SINDRI's `KeyResolver` pattern:
//! a barrier-owned trait, held in the gate's state, injected at construction, so the
//! Barrier does not know where the answer came from.
//!
//! **I-5:** the endpoint ceiling lives on `ModelEndpoint` in REGIN's `EndpointRegistry`,
//! but `brokkr-barrier` SHALL NOT depend on `brokkr-genome` (§6.5). REGIN supplies a
//! [`EndpointCeiling`] implementation; the Barrier consumes the trait.

use brokkr_core::classification::Classification;
use brokkr_core::ids::{FindingId, ModelEndpointId, RiskAcceptanceId};
use brokkr_core::risk::RiskAcceptance;
use std::collections::BTreeMap;

/// Resolves a model endpoint to its declared maximum classification (`max_classification`
/// on REGIN's `ModelEndpoint`). `None` means the endpoint is not declared — the Barrier
/// treats that as a fail-closed channel-strength failure (it cannot prove the channel may
/// carry the data).
pub trait EndpointCeiling: Send + Sync {
    fn resolve(&self, endpoint: &ModelEndpointId) -> Option<Classification>;
}

/// Resolves a finding's identity to a recorded risk acceptance, **and its register id**.
///
/// The pair `(RiskAcceptanceId, RiskAcceptance)` is what makes `AcceptedRisk { entry }`
/// constructible without invention: `RiskAcceptance` carries no id of its own, but
/// OQGF-P-9.2 requires acceptance entries "recorded in Organ 5," and a record in a register
/// has a key. The resolver — the register / Organ-5 seam — supplies both; the Barrier does
/// not synthesize the id.
///
/// **The acceptance is resolver-supplied, never caller-asserted:** a caller that could hand
/// the Barrier an acceptance of its own construction could authorize itself. The Barrier
/// still re-validates every acceptance the resolver returns (finding match, gate, signature,
/// expiry) before honoring it.
pub trait AcceptanceResolver: Send + Sync {
    fn resolve(&self, finding: &FindingId) -> Option<(RiskAcceptanceId, RiskAcceptance)>;
}

/// An in-memory [`EndpointCeiling`], constructed from declared `(endpoint, ceiling)` pairs.
/// The signed, DAP-owned registry that supplies these in production is REGIN's (Phase 5);
/// this is the direct-value form for the Barrier's own tests and callers.
#[derive(Debug, Default, Clone)]
pub struct InMemoryCeiling {
    ceilings: BTreeMap<ModelEndpointId, Classification>,
}

impl InMemoryCeiling {
    pub fn new() -> Self {
        Self {
            ceilings: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with(mut self, endpoint: ModelEndpointId, ceiling: Classification) -> Self {
        self.ceilings.insert(endpoint, ceiling);
        self
    }
}

impl EndpointCeiling for InMemoryCeiling {
    fn resolve(&self, endpoint: &ModelEndpointId) -> Option<Classification> {
        self.ceilings.get(endpoint).copied()
    }
}

/// An in-memory [`AcceptanceResolver`], keyed by the [`FindingId`] an acceptance is scoped
/// to. The persistent, append-only register is Organ 5's (`brokkr-audit`, Phase 7); this is
/// the direct-value form for the Barrier's own tests and callers.
#[derive(Debug, Default, Clone)]
pub struct InMemoryAcceptances {
    by_finding: BTreeMap<FindingId, (RiskAcceptanceId, RiskAcceptance)>,
}

impl InMemoryAcceptances {
    pub fn new() -> Self {
        Self {
            by_finding: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with(
        mut self,
        finding: FindingId,
        id: RiskAcceptanceId,
        acceptance: RiskAcceptance,
    ) -> Self {
        self.by_finding.insert(finding, (id, acceptance));
        self
    }
}

impl AcceptanceResolver for InMemoryAcceptances {
    fn resolve(&self, finding: &FindingId) -> Option<(RiskAcceptanceId, RiskAcceptance)> {
        self.by_finding.get(finding).cloned()
    }
}
