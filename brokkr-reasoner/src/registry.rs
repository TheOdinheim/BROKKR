//! The endpoint-registration seam (§6.1 binding rule 3).
//!
//! A `Reasoner` is meaningless against an unregistered endpoint — §6.1: *"its endpoint must be a
//! registered member of the Model Endpoint Registry,"* and *"a Reasoner CANNOT be constructed
//! against an unregistered endpoint."* So [`Mimir::new`](crate::Mimir::new) checks registration and
//! refuses [`ReasonerError::UnregisteredEndpoint`](brokkr_core::reasoner::ReasonerError::UnregisteredEndpoint)
//! otherwise — the check is at **construction**, not at propose time.
//!
//! The reasoner does not depend on `brokkr-genome` (REGIN, which owns the signed endpoint
//! registry). Registration is therefore a **seam**: this crate-local trait, backed in production
//! (Phase 11) by REGIN's signed `EndpointRegistry`, and by [`InMemoryRegistry`] in tests.

use brokkr_core::ids::ModelEndpointId;

/// Whether an endpoint is a registered member of the Model Endpoint Registry.
pub trait RegisteredEndpoints: Send + Sync {
    fn is_registered(&self, endpoint: &ModelEndpointId) -> bool;
}

/// An in-memory [`RegisteredEndpoints`] — the seam's test double. Production is backed by REGIN's
/// signed `EndpointRegistry` (Phase 11).
pub struct InMemoryRegistry {
    registered: Vec<ModelEndpointId>,
}

impl InMemoryRegistry {
    pub fn new(registered: impl IntoIterator<Item = ModelEndpointId>) -> Self {
        Self {
            registered: registered.into_iter().collect(),
        }
    }
}

impl RegisteredEndpoints for InMemoryRegistry {
    fn is_registered(&self, endpoint: &ModelEndpointId) -> bool {
        self.registered.iter().any(|e| e == endpoint)
    }
}
