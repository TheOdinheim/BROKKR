//! MÍMIR — the [`Reasoner`] implementation (Task 1).
//!
//! MÍMIR proposes; the trust path never consults it. It holds a registered endpoint, the hop it
//! reasons at, and a [`ModelBackend`] seam. `propose` extracts the **cleared payload** (text) and
//! hands it, with the current attenuated scope, to the backend — then wraps the untrusted result
//! as a [`Proposal`].

use brokkr_core::ids::{HopId, ModelEndpointId};
use brokkr_core::intent::IntentScope;
use brokkr_core::reasoner::{ClearedContext, Proposal, Reasoner, ReasonerError};

use crate::backend::ModelBackend;
use crate::registry::RegisteredEndpoints;

/// The advisory reasoner. Untrusted; carries no authority. `propose` accepts only a
/// [`ClearedContext`] (I-12) and returns an untrusted [`Proposal`].
///
/// **The hop.** A [`Proposal`] carries a [`HopId`] that `propose` does not receive (the trait's
/// signature is `propose(&ClearedContext, &IntentScope)`). MÍMIR therefore holds the hop it reasons
/// at, set at construction; the orchestrator (Phase 11) supplies the right hop per reasoning step.
pub struct Mimir {
    endpoint: ModelEndpointId,
    hop: HopId,
    backend: Box<dyn ModelBackend>,
}

impl Mimir {
    /// Construct MÍMIR for a **registered** endpoint (§6.1 binding rule 3). Refuses
    /// [`ReasonerError::UnregisteredEndpoint`] if the endpoint is not a registered member of the
    /// Model Endpoint Registry — the registration check is at construction, so a MÍMIR against an
    /// unregistered endpoint cannot exist.
    pub fn new(
        endpoint: ModelEndpointId,
        registry: &dyn RegisteredEndpoints,
        backend: Box<dyn ModelBackend>,
        hop: HopId,
    ) -> Result<Self, ReasonerError> {
        if !registry.is_registered(&endpoint) {
            return Err(ReasonerError::UnregisteredEndpoint);
        }
        Ok(Self {
            endpoint,
            hop,
            backend,
        })
    }
}

impl Reasoner for Mimir {
    fn endpoint(&self) -> &ModelEndpointId {
        &self.endpoint
    }

    fn propose(
        &self,
        ctx: &ClearedContext,
        scope: &IntentScope,
    ) -> Result<Proposal, ReasonerError> {
        // The backend receives the cleared context's PAYLOAD (text) and the CURRENT attenuated
        // scope — never the ClearedContext token, never the root intent, never a gate (§6.1 rules 1
        // and 2). `ctx.get()` yields the Context; only its `payload` crosses to the model.
        let payload = ctx.get().payload.as_str();
        let proposed = self
            .backend
            .propose(payload, scope)
            .map_err(|_| ReasonerError::Backend)?;

        // Wrap as an UNTRUSTED Proposal. It carries no authority; SINDRI decides whether it may act.
        Ok(Proposal {
            action: proposed.action,
            rationale: proposed.rationale,
            hop: self.hop.clone(),
        })
    }
}
