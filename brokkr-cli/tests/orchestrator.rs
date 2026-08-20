//! Integration tests for the governed action cycle (Phase 11).
//!
//! Every subsystem is a **test double** — no production backend. Doubles are spies: they record
//! that they were called (and with what) via `Arc`-shared state the test inspects after the hop.
//! The doubles are `Send + Sync` (atomics + mutexes, never `Cell`/`RefCell`), because the
//! orchestrator holds each behind a `Box<dyn Trait: Send + Sync>`.
//!
//! The ten tests prove the shape of the cycle, not any subsystem's internal logic (each was tested
//! in its own phase): the loop runs the steps in order, a denial at any gate stops it and names the
//! stage, HEIMDALL receives the reconciliation observation with `executed: Some(..)`, SAGA records
//! the decisions, and `now` is supplied per call (I-13).

use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

use brokkr_audit::AuditEvent;
use brokkr_cli::{
    AuditSink, DenialStage, GenomeCheck, GenomeRefusal, HopRequest, HopResult, Orchestrator,
    Sentinel, SignalRouter,
};
use brokkr_core::barrier::{
    Barrier, BarrierCondition, BarrierFinding, BarrierVerdict, BoundaryFlow, Destination,
};
use brokkr_core::classification::{Classification, NamedGroup};
use brokkr_core::crypto::{Attestation, Digest, DualSignature, HashAlg, Signature, SignatureAlg};
use brokkr_core::gate::AuthorizedAction;
use brokkr_core::gate::{Action, AnergyReason, CostimulationGate};
use brokkr_core::ids::HopId;
use brokkr_core::ids::OrganId;
use brokkr_core::ids::{
    Dap, DatumRef, DetectorId, ModelEndpointId, Nonce, SubjectId, Timestamp, ToolId,
};
use brokkr_core::intent::{IntentProvenanceChain, IntentScope, InvariantSet, RootIntent};
use brokkr_core::reasoner::{Context, ContextClearance, Proposal};
use brokkr_core::signal::{PostureEffect, Signal, SignalClass, SignalScope};
use brokkr_sentinel::{Detection, Observation};
use brokkr_tools::{ToolError, ToolExecutor, ToolOutcome};

// ---- value builders ------------------------------------------------------------------

fn dual_sig() -> DualSignature {
    DualSignature {
        lattice: Signature {
            alg: SignatureAlg::MlDsa65,
            bytes: Vec::new(),
        },
        hash_based: Signature {
            alg: SignatureAlg::SlhDsaShake192s,
            bytes: Vec::new(),
        },
    }
}

fn digest() -> Digest {
    Digest {
        alg: HashAlg::Sha384,
        bytes: Vec::new(),
    }
}

fn dap() -> Dap {
    Dap::new("Jeremy Rose", "jr")
}

fn attestation() -> Attestation {
    Attestation {
        subject: SubjectId::new("hop-1"),
        measurements: digest(),
        freshness: Nonce(1),
        signatures: dual_sig(),
    }
}

fn chain() -> IntentProvenanceChain {
    let root = RootIntent {
        principal: SubjectId::new("hop-1"),
        dap: dap(),
        scope: IntentScope::empty(),
        invariants: InvariantSet::new([]),
        nonce: Nonce(1),
        expiry: Timestamp(1_000_000),
        signature: dual_sig(),
    };
    IntentProvenanceChain::new(root)
}

fn action() -> Action {
    Action {
        tool: ToolId::new("write_file"),
        detail: "./src/x.rs".to_string(),
    }
}

fn context() -> Context {
    Context {
        payload: "some source".to_string(),
        datum: DatumRef::new("ctx-1"),
        classification: Classification::Public,
        personal: None,
        bcr: None,
    }
}

fn reasoner_dest() -> Destination {
    Destination::Reasoner {
        endpoint: ModelEndpointId::new("mimir-local"),
        negotiated: NamedGroup::Secp384r1MlKem1024,
    }
}

fn hop_request() -> HopRequest {
    HopRequest {
        identity: attestation(),
        chain: chain(),
        context: context(),
        dest: reasoner_dest(),
    }
}

fn deny_verdict() -> BarrierVerdict {
    BarrierVerdict::Deny {
        finding: BarrierFinding {
            datum: DatumRef::new("ctx-1"),
            condition: BarrierCondition::UnauthorizedDestination,
            classification: Classification::Public,
            reason: "test denial".to_string(),
        },
    }
}

fn signal() -> Signal {
    Signal {
        source: OrganId::Sentinel,
        class: SignalClass::PostureRaiseRequest,
        severity: brokkr_core::signal::Severity::High,
        effect: PostureEffect::Raise {
            detail: "deviation".to_string(),
        },
        scope: SignalScope {
            detail: "hop-1".to_string(),
        },
        nonce: Nonce(7),
        expiry: Timestamp(2_000_000),
        signature: dual_sig(),
    }
}

fn firing_detection() -> Detection {
    Detection {
        detector: DetectorId::new("d1"),
        severity: brokkr_core::signal::Severity::High,
        detail: "fired".to_string(),
        suppressed_by: None,
        signal: Some(signal()),
    }
}

// ---- call counter --------------------------------------------------------------------

#[derive(Default)]
struct Calls(AtomicUsize);
impl Calls {
    fn hit(&self) {
        self.0.fetch_add(1, SeqCst);
    }
    fn count(&self) -> usize {
        self.0.load(SeqCst)
    }
}

// ---- doubles -------------------------------------------------------------------------

/// BIFRÖST double. `deny == true` blocks the crossing; the provided `clear` mints on Allow.
struct SpyClearance {
    deny: bool,
    calls: Arc<Calls>,
}
impl ContextClearance for SpyClearance {
    fn evaluate_context(
        &self,
        _ctx: &Context,
        _dest: &Destination,
        _now: Timestamp,
    ) -> BarrierVerdict {
        self.calls.hit();
        if self.deny {
            deny_verdict()
        } else {
            BarrierVerdict::Allow
        }
    }
}

/// MÍMIR double. Records the call; returns a fixed proposal.
struct SpyReasoner {
    endpoint: ModelEndpointId,
    calls: Arc<Calls>,
}
impl brokkr_core::reasoner::Reasoner for SpyReasoner {
    fn endpoint(&self) -> &ModelEndpointId {
        &self.endpoint
    }
    fn propose(
        &self,
        _ctx: &brokkr_core::reasoner::ClearedContext,
        _scope: &IntentScope,
    ) -> Result<Proposal, brokkr_core::reasoner::ReasonerError> {
        self.calls.hit();
        Ok(Proposal {
            action: action(),
            rationale: "because".to_string(),
            hop: HopId::new("hop-1"),
        })
    }
}

/// REGIN port double. `refuse == true` refuses the tool.
struct SpyGenome {
    refuse: bool,
    calls: Arc<Calls>,
}
impl GenomeCheck for SpyGenome {
    fn check(&self, _action: &Action, _chain: &IntentProvenanceChain) -> Result<(), GenomeRefusal> {
        self.calls.hit();
        if self.refuse {
            Err(GenomeRefusal {
                detail: "tool not in genome".to_string(),
            })
        } else {
            Ok(())
        }
    }
}

/// SINDRI double. `anergy == Some(reason)` denies; `None` grants (the provided `authorize` mints).
struct SpyGate {
    anergy: Option<AnergyReason>,
    calls: Arc<Calls>,
}
impl CostimulationGate for SpyGate {
    fn evaluate(
        &self,
        _identity: &Attestation,
        _chain: &IntentProvenanceChain,
        _action: &Action,
        _now: Timestamp,
    ) -> Result<(), AnergyReason> {
        self.calls.hit();
        match self.anergy {
            Some(r) => Err(r),
            None => Ok(()),
        }
    }
}

/// HÚÐ double. `deny == true` blocks the action crossing.
struct SpyBarrier {
    deny: bool,
    calls: Arc<Calls>,
}
impl Barrier for SpyBarrier {
    fn evaluate(&self, _flow: &BoundaryFlow, _now: Timestamp) -> BarrierVerdict {
        self.calls.hit();
        if self.deny {
            deny_verdict()
        } else {
            BarrierVerdict::Allow
        }
    }
}

/// Tool double. Records that it ran; returns fixed output.
struct SpyTool {
    id: ToolId,
    calls: Arc<Calls>,
}
impl ToolExecutor for SpyTool {
    fn tool_id(&self) -> &ToolId {
        &self.id
    }
    fn execute(&self, _action: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        self.calls.hit();
        Ok(ToolOutcome {
            output: "did the work".to_string(),
        })
    }
}

/// HEIMDALL port double. Records every observation; returns the configured detections.
struct SpySentinel {
    seen: Arc<Mutex<Vec<Observation>>>,
    returns: Vec<Detection>,
}
impl Sentinel for SpySentinel {
    fn observe(&self, observation: &Observation, _now: Timestamp) -> Vec<Detection> {
        self.seen.lock().unwrap().push(observation.clone());
        self.returns.clone()
    }
}

/// SAGA port double. Records every event.
struct SpyAudit {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}
impl AuditSink for SpyAudit {
    fn record(&self, event: AuditEvent, _dap: Dap, _at: Timestamp) {
        self.events.lock().unwrap().push(event);
    }
}

/// EIR/KVASIR port double. Records routed signals.
struct SpySignals {
    routed: Arc<Mutex<Vec<Signal>>>,
}
impl SignalRouter for SpySignals {
    fn route(&self, signal: &Signal) {
        self.routed.lock().unwrap().push(signal.clone());
    }
}

// ---- a fixture that wires an orchestrator from doubles and exposes the spies ----------

struct Rig {
    bifrost: Arc<Calls>,
    reasoner: Arc<Calls>,
    genome: Arc<Calls>,
    gate: Arc<Calls>,
    barrier: Arc<Calls>,
    tool: Arc<Calls>,
    observations: Arc<Mutex<Vec<Observation>>>,
    events: Arc<Mutex<Vec<AuditEvent>>>,
    routed: Arc<Mutex<Vec<Signal>>>,
    orch: Orchestrator,
}

#[derive(Default)]
struct Cfg {
    bifrost_deny: bool,
    genome_refuse: bool,
    gate_anergy: Option<AnergyReason>,
    barrier_deny: bool,
    detections: Vec<Detection>,
}

fn build(cfg: Cfg) -> Rig {
    let bifrost = Arc::new(Calls::default());
    let reasoner = Arc::new(Calls::default());
    let genome = Arc::new(Calls::default());
    let gate = Arc::new(Calls::default());
    let barrier = Arc::new(Calls::default());
    let tool = Arc::new(Calls::default());
    let observations = Arc::new(Mutex::new(Vec::new()));
    let events = Arc::new(Mutex::new(Vec::new()));
    let routed = Arc::new(Mutex::new(Vec::new()));

    let orch = Orchestrator::new(
        Box::new(SpyClearance {
            deny: cfg.bifrost_deny,
            calls: bifrost.clone(),
        }),
        Box::new(SpyReasoner {
            endpoint: ModelEndpointId::new("mimir-local"),
            calls: reasoner.clone(),
        }),
        Box::new(SpyGenome {
            refuse: cfg.genome_refuse,
            calls: genome.clone(),
        }),
        Box::new(SpyGate {
            anergy: cfg.gate_anergy,
            calls: gate.clone(),
        }),
        Box::new(SpyBarrier {
            deny: cfg.barrier_deny,
            calls: barrier.clone(),
        }),
        Box::new(SpyTool {
            id: ToolId::new("write_file"),
            calls: tool.clone(),
        }),
        Box::new(SpySentinel {
            seen: observations.clone(),
            returns: cfg.detections,
        }),
        Box::new(SpyAudit {
            events: events.clone(),
        }),
        Box::new(SpySignals {
            routed: routed.clone(),
        }),
        dap(),
    );

    Rig {
        bifrost,
        reasoner,
        genome,
        gate,
        barrier,
        tool,
        observations,
        events,
        routed,
        orch,
    }
}

fn has_hop_with_executed(obs: &[Observation]) -> bool {
    obs.iter().any(|o| {
        matches!(
            o,
            Observation::Hop {
                executed: Some(_),
                ..
            }
        )
    })
}

fn has_granted_authorization(obs: &[Observation]) -> bool {
    obs.iter()
        .any(|o| matches!(o, Observation::Authorization { granted: true, .. }))
}

// ---- the ten tests -------------------------------------------------------------------

/// 1. All gates clear → the action executes, and SAGA records the decision sequence.
#[test]
fn full_cycle_executes_on_all_gates_clear() {
    let rig = build(Cfg::default());
    let result = rig.orch.execute_hop(hop_request(), Timestamp(100));

    assert_eq!(
        result,
        HopResult::Executed {
            output: "did the work".to_string()
        }
    );
    // Every stage ran, in order, exactly once.
    assert_eq!(rig.bifrost.count(), 1);
    assert_eq!(rig.reasoner.count(), 1);
    assert_eq!(rig.genome.count(), 1);
    assert_eq!(rig.gate.count(), 1);
    assert_eq!(rig.barrier.count(), 1);
    assert_eq!(rig.tool.count(), 1);

    // SAGA holds the proposal (step 3) and the granted authorization (step 5), in that order.
    let events = rig.events.lock().unwrap();
    let proposal_idx = events
        .iter()
        .position(|e| matches!(e, AuditEvent::Proposal(_)))
        .expect("proposal recorded");
    let auth_idx = events
        .iter()
        .position(|e| matches!(e, AuditEvent::Authorization(_)))
        .expect("authorization recorded");
    assert!(
        proposal_idx < auth_idx,
        "proposal is recorded before the gate verdict"
    );
}

/// 2. SINDRI anergy stops the cycle at the gate; the tool never runs.
#[test]
fn gate_denial_stops_execution() {
    let rig = build(Cfg {
        gate_anergy: Some(AnergyReason::ChainInvalid),
        ..Cfg::default()
    });
    let result = rig.orch.execute_hop(hop_request(), Timestamp(100));

    assert!(matches!(
        result,
        HopResult::Denied {
            stage: DenialStage::Gate,
            ..
        }
    ));
    assert_eq!(rig.gate.count(), 1, "the gate was consulted");
    assert_eq!(rig.tool.count(), 0, "the tool never ran");
    assert_eq!(
        rig.barrier.count(),
        0,
        "HÚÐ is after the gate; never reached"
    );
}

/// 3. REGIN refusal stops the cycle before SINDRI is consulted.
#[test]
fn genome_refusal_stops_before_gate() {
    let rig = build(Cfg {
        genome_refuse: true,
        ..Cfg::default()
    });
    let result = rig.orch.execute_hop(hop_request(), Timestamp(100));

    assert!(matches!(
        result,
        HopResult::Denied {
            stage: DenialStage::Genome,
            ..
        }
    ));
    assert_eq!(rig.genome.count(), 1);
    assert_eq!(rig.gate.count(), 0, "SINDRI never called");
    assert_eq!(rig.tool.count(), 0);
    // The refusal is recorded as an anergic authorization decision.
    let events = rig.events.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuditEvent::Authorization(_)))
    );
}

/// 4. HÚÐ denial stops the cycle after the gate granted; the tool never runs.
#[test]
fn barrier_denial_stops_after_gate() {
    let rig = build(Cfg {
        barrier_deny: true,
        ..Cfg::default()
    });
    let result = rig.orch.execute_hop(hop_request(), Timestamp(100));

    assert!(matches!(
        result,
        HopResult::Denied {
            stage: DenialStage::Barrier,
            ..
        }
    ));
    assert_eq!(rig.gate.count(), 1, "the gate granted first");
    assert_eq!(rig.barrier.count(), 1, "HÚÐ denied the crossing");
    assert_eq!(rig.tool.count(), 0, "the tool never ran");
}

/// 5. On a clean hop, HEIMDALL receives `Observation::Hop { executed: Some(..) }`.
#[test]
fn heimdall_receives_hop_observation_with_executed() {
    let rig = build(Cfg::default());
    let _ = rig.orch.execute_hop(hop_request(), Timestamp(100));

    let obs = rig.observations.lock().unwrap();
    assert!(
        has_hop_with_executed(&obs),
        "reconciliation observation carries the executed action"
    );
}

/// 6. On a clean hop, HEIMDALL receives the granted `Observation::Authorization`.
#[test]
fn heimdall_receives_authorization_observation() {
    let rig = build(Cfg::default());
    let _ = rig.orch.execute_hop(hop_request(), Timestamp(100));

    let obs = rig.observations.lock().unwrap();
    assert!(
        has_granted_authorization(&obs),
        "HEIMDALL sees the granted authorization"
    );
}

/// 7. A denial at each stage names that stage.
#[test]
fn denial_at_each_stage_names_the_stage() {
    let bifrost = build(Cfg {
        bifrost_deny: true,
        ..Cfg::default()
    })
    .orch
    .execute_hop(hop_request(), Timestamp(100));
    assert!(matches!(
        bifrost,
        HopResult::Denied {
            stage: DenialStage::Bifrost,
            ..
        }
    ));

    let genome = build(Cfg {
        genome_refuse: true,
        ..Cfg::default()
    })
    .orch
    .execute_hop(hop_request(), Timestamp(100));
    assert!(matches!(
        genome,
        HopResult::Denied {
            stage: DenialStage::Genome,
            ..
        }
    ));

    let gate = build(Cfg {
        gate_anergy: Some(AnergyReason::OutOfScope),
        ..Cfg::default()
    })
    .orch
    .execute_hop(hop_request(), Timestamp(100));
    assert!(matches!(
        gate,
        HopResult::Denied {
            stage: DenialStage::Gate,
            ..
        }
    ));

    let barrier = build(Cfg {
        barrier_deny: true,
        ..Cfg::default()
    })
    .orch
    .execute_hop(hop_request(), Timestamp(100));
    assert!(matches!(
        barrier,
        HopResult::Denied {
            stage: DenialStage::Barrier,
            ..
        }
    ));
}

/// 8. `now` is supplied per call (I-13): two hops with different `now` both work, and the
///    orchestrator holds no clock (the value comes only from the argument).
#[test]
fn now_is_passed_not_held() {
    let rig = build(Cfg::default());
    let first = rig.orch.execute_hop(hop_request(), Timestamp(100));
    let second = rig.orch.execute_hop(hop_request(), Timestamp(999_999));

    assert!(matches!(first, HopResult::Executed { .. }));
    assert!(matches!(second, HopResult::Executed { .. }));
    // Two hops → each subsystem consulted twice; nothing was cached across the `now` change.
    assert_eq!(rig.gate.count(), 2);
    assert_eq!(rig.barrier.count(), 2);
    assert_eq!(rig.tool.count(), 2);
}

/// 9. SAGA records every decision: the proposal (step 3), the gate verdict (step 5), and — when a
///    detection fires at reconciliation (step 8) — the raised signal. (There is no dedicated
///    execution event; the executed action is recorded as the reconciliation observation to
///    HEIMDALL, asserted in test 5.)
#[test]
fn saga_records_every_decision() {
    let rig = build(Cfg {
        detections: vec![firing_detection()],
        ..Cfg::default()
    });
    let result = rig.orch.execute_hop(hop_request(), Timestamp(100));
    assert!(matches!(result, HopResult::Executed { .. }));

    let events = rig.events.lock().unwrap();
    assert!(
        events.iter().any(|e| matches!(e, AuditEvent::Proposal(_))),
        "proposal recorded"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuditEvent::Authorization(_))),
        "gate verdict recorded"
    );
    let signal_events = events
        .iter()
        .filter(|e| matches!(e, AuditEvent::Signal(_)))
        .count();
    assert!(signal_events >= 1, "the raised signal is recorded");
    // Every raised signal is both recorded to SAGA and routed to EIR/KVASIR — the two counts agree.
    assert_eq!(
        rig.routed.lock().unwrap().len(),
        signal_events,
        "each raised signal is routed exactly once and recorded exactly once"
    );
}

/// 10. BIFRÖST denial stops the cycle before MÍMIR is consulted — the ungoverned context never
///     reaches a model (I-12).
#[test]
fn bifrost_denial_stops_before_reasoner() {
    let rig = build(Cfg {
        bifrost_deny: true,
        ..Cfg::default()
    });
    let result = rig.orch.execute_hop(hop_request(), Timestamp(100));

    assert!(matches!(
        result,
        HopResult::Denied {
            stage: DenialStage::Bifrost,
            ..
        }
    ));
    assert_eq!(rig.bifrost.count(), 1);
    assert_eq!(rig.reasoner.count(), 0, "the reasoner is never reached");
    assert_eq!(rig.gate.count(), 0);
    assert_eq!(rig.tool.count(), 0);
}
