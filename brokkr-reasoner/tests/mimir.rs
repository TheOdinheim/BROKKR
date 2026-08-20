//! MÍMIR tests. The four required propose tests use a `ContextClearance` double (core) to mint a
//! `ClearedContext`; the end-to-end test uses the REAL `brokkr_bifrost::Bifrost` to clear a context
//! before MÍMIR proposes on it — I-12 proven end-to-end with the real barrier.

use std::sync::{Arc, Mutex};

use brokkr_core::barrier::{BarrierVerdict, Destination};
use brokkr_core::classification::{Classification, NamedGroup};
use brokkr_core::gate::Action;
use brokkr_core::ids::{DatumRef, HopId, ModelEndpointId, Timestamp, ToolId};
use brokkr_core::intent::{Capability, IntentScope};
use brokkr_core::reasoner::{ClearedContext, Context, ContextClearance, Reasoner, ReasonerError};

use brokkr_reasoner::{BackendError, BackendProposal, InMemoryRegistry, Mimir, ModelBackend};

// ---- test doubles --------------------------------------------------------------------

/// A `ContextClearance` that allows everything — used to MINT a `ClearedContext` the sanctioned way
/// (core's provided `clear` is the sole minter, I-12). The reasoner tests need a cleared context;
/// this is the lightest legitimate way to get one.
struct AllowClearance;
impl ContextClearance for AllowClearance {
    fn evaluate_context(&self, _c: &Context, _d: &Destination, _n: Timestamp) -> BarrierVerdict {
        BarrierVerdict::Allow
    }
}

fn cleared(payload: &str) -> ClearedContext {
    let ctx = Context {
        payload: payload.to_string(),
        datum: DatumRef::new("d1"),
        classification: Classification::Public,
        personal: None,
        bcr: None,
    };
    let dest = Destination::Reasoner {
        endpoint: ModelEndpointId::new("mimir-1"),
        negotiated: NamedGroup::X25519MlKem768,
    };
    AllowClearance
        .clear(ctx, &dest, Timestamp(1000))
        .expect("AllowClearance clears")
}

/// A model backend that records the payload it was handed and returns a fixed proposal (or fails).
struct MockBackend {
    action: Action,
    rationale: String,
    seen_payload: Arc<Mutex<Option<String>>>,
    fail: bool,
}
impl ModelBackend for MockBackend {
    fn propose(
        &self,
        payload: &str,
        _scope: &IntentScope,
    ) -> Result<BackendProposal, BackendError> {
        if let Ok(mut slot) = self.seen_payload.lock() {
            *slot = Some(payload.to_string());
        }
        if self.fail {
            return Err(BackendError {
                detail: "model unavailable".to_string(),
            });
        }
        Ok(BackendProposal {
            action: self.action.clone(),
            rationale: self.rationale.clone(),
        })
    }
}

fn backend(fail: bool, seen: Arc<Mutex<Option<String>>>) -> Box<dyn ModelBackend> {
    Box::new(MockBackend {
        action: Action {
            tool: ToolId::new("write"),
            detail: "src/main.rs".to_string(),
        },
        rationale: "the task asks to write the file".to_string(),
        seen_payload: seen,
        fail,
    })
}

fn mimir(
    endpoint: &str,
    hop: &str,
    backend: Box<dyn ModelBackend>,
) -> Result<Mimir, ReasonerError> {
    let registry = InMemoryRegistry::new([ModelEndpointId::new("mimir-1")]);
    Mimir::new(
        ModelEndpointId::new(endpoint),
        &registry,
        backend,
        HopId::new(hop),
    )
}

fn scope() -> IntentScope {
    IntentScope::new([Capability::new("write")])
}

// ---- required tests ------------------------------------------------------------------

#[test]
fn test_propose_with_cleared_context_produces_proposal() {
    let seen = Arc::new(Mutex::new(None));
    let m = mimir("mimir-1", "hop-7", backend(false, seen)).expect("registered endpoint");

    let proposal = m
        .propose(&cleared("read src/main.rs"), &scope())
        .expect("propose succeeds");

    assert_eq!(
        proposal.action,
        Action {
            tool: ToolId::new("write"),
            detail: "src/main.rs".to_string(),
        }
    );
    assert_eq!(proposal.rationale, "the task asks to write the file");
    // The proposal carries the reasoner's hop.
    assert_eq!(proposal.hop, HopId::new("hop-7"));
    assert_eq!(m.endpoint(), &ModelEndpointId::new("mimir-1"));
}

#[test]
fn test_propose_does_not_hand_cleared_context_to_backend() {
    // Structural: `ModelBackend::propose` takes `&str`, not `&ClearedContext` — the governance token
    // cannot be passed to the model. Here we confirm the backend received exactly the cleared
    // PAYLOAD text (and nothing else could have been the token).
    let seen = Arc::new(Mutex::new(None));
    let m = mimir("mimir-1", "hop-1", backend(false, seen.clone())).expect("registered endpoint");

    m.propose(&cleared("the exact payload text"), &scope())
        .expect("propose succeeds");

    assert_eq!(
        seen.lock().expect("lock").as_deref(),
        Some("the exact payload text"),
        "the backend receives the payload, never the ClearedContext"
    );
}

#[test]
fn test_backend_error_maps_to_reasoner_error() {
    let seen = Arc::new(Mutex::new(None));
    let m = mimir("mimir-1", "hop-1", backend(true, seen)).expect("registered endpoint");

    assert_eq!(
        m.propose(&cleared("x"), &scope()),
        Err(ReasonerError::Backend)
    );
}

#[test]
fn test_i12_propose_requires_cleared_context() {
    // I-12: `propose` takes a `&ClearedContext`, which has no public constructor — a raw `Context`
    // cannot reach a model. The COMPILE-TIME proof (passing a raw `Context` to `propose` does not
    // compile, `E0308`) is the `compile_fail` doctest in `brokkr-core::reasoner`, verified there and
    // still passing (14 core doctests, unchanged). This confirms the runtime path: `propose` accepts
    // a genuinely-cleared context and produces a proposal.
    let seen = Arc::new(Mutex::new(None));
    let m = mimir("mimir-1", "hop-1", backend(false, seen)).expect("registered endpoint");
    assert!(m.propose(&cleared("x"), &scope()).is_ok());
}

// ---- construction: the endpoint must be registered (§6.1 rule 3) ---------------------

#[test]
fn test_unregistered_endpoint_refused() {
    let registry = InMemoryRegistry::new([ModelEndpointId::new("some-other-endpoint")]);
    let seen = Arc::new(Mutex::new(None));
    let r = Mimir::new(
        ModelEndpointId::new("mimir-1"),
        &registry,
        backend(false, seen),
        HopId::new("hop-1"),
    );
    assert!(matches!(r, Err(ReasonerError::UnregisteredEndpoint)));
}

// ---- end-to-end: the REAL BIFRÖST clears, then MÍMIR proposes (I-12) ------------------

#[test]
fn test_end_to_end_real_bifrost_clears_then_proposes() {
    use brokkr_barrier::{InMemoryAcceptances, InMemoryCeiling};
    use brokkr_bifrost::Bifrost;

    // A real BIFRÖST over HÚÐ, with the barrier's ready-made resolvers. Public content clears
    // without a BCR (HÚÐ's egress condition 1), so no signatures are needed for this crossing.
    let bifrost = Bifrost::new(
        (Vec::new(), Vec::new()),
        (Vec::new(), Vec::new()),
        InMemoryCeiling::new().with(ModelEndpointId::new("mimir-1"), Classification::Internal),
        InMemoryAcceptances::new(),
    );
    let ctx = Context {
        payload: "read the file and summarize".to_string(),
        datum: DatumRef::new("d1"),
        classification: Classification::Public,
        personal: None,
        bcr: None,
    };
    let dest = Destination::Reasoner {
        endpoint: ModelEndpointId::new("mimir-1"),
        negotiated: NamedGroup::X25519MlKem768,
    };
    let cleared = bifrost
        .clear(ctx, &dest, Timestamp(1000))
        .expect("a Public context clears the real barrier");

    let seen = Arc::new(Mutex::new(None));
    let m = mimir("mimir-1", "hop-1", backend(false, seen.clone())).expect("registered endpoint");
    let proposal = m
        .propose(&cleared, &scope())
        .expect("MÍMIR proposes on the bifrost-cleared context");

    assert_eq!(proposal.action.tool, ToolId::new("write"));
    assert_eq!(
        seen.lock().expect("lock").as_deref(),
        Some("read the file and summarize")
    );
}
