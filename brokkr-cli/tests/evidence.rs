//! Organ 5 evidence-capture hardening patch — every SAGA record the orchestrator writes carries
//! evidence-source provenance (sensor, capture path, timestamp, coverage, explicit gap), and an
//! errored hop records a trajectory evidence gap rather than presenting a partial record as
//! complete. Hermetic; real dual-family PQC signed once in `fx()`.

use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};

use brokkr_audit::AuditEvent;
use brokkr_cli::{
    AuditSink, GenomeCheck, GenomeRefusal, Guards, HopRequest, HopResult, Orchestrator, Sentinel,
    SignalRouter,
};
use brokkr_core::barrier::{BarrierVerdict, BoundaryFlow, Destination};
use brokkr_core::capability::{CapabilityEnvelope, EvidenceProvenance};
use brokkr_core::classification::{Classification, NamedGroup};
use brokkr_core::crypto::{Attestation, Hasher};
use brokkr_core::gate::{Action, AuthorizedAction, CostimulationGate};
use brokkr_core::genome::PrivilegeClass;
use brokkr_core::ids::{
    Dap, DatumRef, HopId, ModelEndpointId, Nonce, SubjectId, Timestamp, ToolId,
};
use brokkr_core::intent::{
    Capability, IntentProvenanceChain, IntentScope, Invariant, InvariantSet, RootIntent,
};
use brokkr_core::reasoner::{
    ClearedContext, Context, ContextClearance, Proposal, Reasoner, ReasonerError,
};
use brokkr_core::signal::Signal;
use brokkr_crypto::{DualKeyPair, Sha384Hasher};
use brokkr_gate::Sindri;
use brokkr_gate::resolver::{GenomeResolver, RegistryResolver, ResolvedInvariant, ResolvedTool};
use brokkr_intent::Skuld;
use brokkr_sentinel::{Detection, Observation};
use brokkr_tools::{ToolError, ToolExecutor, ToolOutcome};

const P1: &str = "principal-1";

fn dap() -> Dap {
    Dap::new("Jeremy Rose", "jr")
}
fn cap(s: &str) -> Capability {
    Capability::new(s)
}

struct Fx {
    p1_pub: (Vec<u8>, Vec<u8>),
    legit: IntentProvenanceChain,
}
fn fx() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| {
        let mut kp = DualKeyPair::generate().expect("kp");
        let p1_pub = kp.public_key_bytes().expect("pub");
        let root: RootIntent = Skuld
            .sign_root(
                SubjectId::new(P1),
                dap(),
                IntentScope::new([cap("write")]),
                InvariantSet::new([]),
                Nonce(1),
                Timestamp(9_000_000),
                &mut kp,
            )
            .expect("sign");
        Fx {
            p1_pub,
            legit: IntentProvenanceChain::new(root),
        }
    })
}
fn registry() -> RegistryResolver {
    let (ml, slh) = &fx().p1_pub;
    RegistryResolver::new().with_root(SubjectId::new(P1), ml.clone(), slh.clone())
}
fn attest(subject: &str) -> Attestation {
    Attestation {
        subject: SubjectId::new(subject),
        measurements: Sha384Hasher.hash(b"m"),
        freshness: Nonce(1),
        signatures: fx().legit.root().signature.clone(),
    }
}

// ---- doubles --------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Genome;
impl GenomeResolver for Genome {
    fn resolve_tool(&self, t: &ToolId) -> Option<ResolvedTool> {
        (t.as_str() == "write_file").then(|| ResolvedTool {
            required_capabilities: vec![cap("write")],
            privilege: PrivilegeClass::Unprivileged,
        })
    }
    fn resolve_invariant(&self, _i: &Invariant) -> Option<ResolvedInvariant> {
        None
    }
}
impl GenomeCheck for Genome {
    fn check(&self, a: &Action, _c: &IntentProvenanceChain) -> Result<(), GenomeRefusal> {
        if a.tool.as_str() == "write_file" {
            Ok(())
        } else {
            Err(GenomeRefusal {
                detail: "undeclared".to_string(),
            })
        }
    }
}
struct Puppet {
    endpoint: ModelEndpointId,
}
impl Reasoner for Puppet {
    fn endpoint(&self) -> &ModelEndpointId {
        &self.endpoint
    }
    fn propose(&self, _c: &ClearedContext, _s: &IntentScope) -> Result<Proposal, ReasonerError> {
        Ok(Proposal {
            action: Action {
                tool: ToolId::new("write_file"),
                detail: "/tmp/x".to_string(),
            },
            rationale: "ok".to_string(),
            hop: HopId::new("h"),
        })
    }
}
struct OkTool;
impl ToolExecutor for OkTool {
    fn tool_id(&self) -> &ToolId {
        static ID: OnceLock<ToolId> = OnceLock::new();
        ID.get_or_init(|| ToolId::new("write_file"))
    }
    fn execute(&self, _a: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        Ok(ToolOutcome {
            output: "ok".to_string(),
        })
    }
}
struct ErrTool {
    calls: Arc<AtomicUsize>,
}
impl ToolExecutor for ErrTool {
    fn tool_id(&self) -> &ToolId {
        static ID: OnceLock<ToolId> = OnceLock::new();
        ID.get_or_init(|| ToolId::new("write_file"))
    }
    fn execute(&self, _a: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        self.calls.fetch_add(1, SeqCst);
        Err(ToolError {
            detail: "boom".to_string(),
        })
    }
}
struct ClearAll;
impl ContextClearance for ClearAll {
    fn evaluate_context(&self, _c: &Context, _d: &Destination, _n: Timestamp) -> BarrierVerdict {
        BarrierVerdict::Allow
    }
}
struct AllowBarrier;
impl brokkr_core::barrier::Barrier for AllowBarrier {
    fn evaluate(&self, _f: &BoundaryFlow, _n: Timestamp) -> BarrierVerdict {
        BarrierVerdict::Allow
    }
}
struct DiscardSentinel;
impl Sentinel for DiscardSentinel {
    fn observe(&self, _o: &Observation, _n: Timestamp) -> Vec<Detection> {
        Vec::new()
    }
}
struct NoSignals;
impl SignalRouter for NoSignals {
    fn route(&self, _s: &Signal) {}
}

/// Captures every `(event, provenance)` the orchestrator records. The orchestrator records **only**
/// through `record_with_provenance`; the plain `record` path delegates here with a marker sensor so
/// an unexpected direct call would be caught by the sensor-id assertions.
struct ProvSpy {
    seen: Arc<Mutex<Vec<(AuditEvent, EvidenceProvenance)>>>,
}
impl AuditSink for ProvSpy {
    fn record(&self, event: AuditEvent, dap: Dap, at: Timestamp) {
        self.record_with_provenance(
            event,
            dap,
            at,
            EvidenceProvenance {
                sensor_id: "unexpected-direct-record".to_string(),
                capture_path: "record".to_string(),
                capture_timestamp: at,
                expected_coverage: String::new(),
                observed_coverage: String::new(),
                evidence_gap: None,
            },
        );
    }
    fn record_with_provenance(
        &self,
        event: AuditEvent,
        _dap: Dap,
        _at: Timestamp,
        provenance: EvidenceProvenance,
    ) {
        self.seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((event, provenance));
    }
}

struct Rig {
    orch: Orchestrator,
    events: Arc<Mutex<Vec<(AuditEvent, EvidenceProvenance)>>>,
}

fn rig(tool: Box<dyn ToolExecutor>) -> Rig {
    let events = Arc::new(Mutex::new(Vec::new()));
    let gate: Box<dyn CostimulationGate> = Box::new(Sindri::new(registry(), Genome));
    let orch = Orchestrator::new(
        Box::new(ClearAll),
        Box::new(Puppet {
            endpoint: ModelEndpointId::new("mimir"),
        }),
        Box::new(Genome),
        gate,
        Box::new(AllowBarrier),
        tool,
        Box::new(DiscardSentinel),
        Box::new(ProvSpy {
            seen: events.clone(),
        }),
        Box::new(NoSignals),
        dap(),
    )
    .with_guards(Guards::permissive())
    .with_envelope(CapabilityEnvelope::permissive());
    Rig { orch, events }
}
fn req(identity: Attestation) -> HopRequest {
    HopRequest {
        identity,
        chain: fx().legit.clone(),
        context: Context {
            payload: "c".to_string(),
            datum: DatumRef::new("d"),
            classification: Classification::Public,
            personal: None,
            bcr: None,
        },
        dest: Destination::Reasoner {
            endpoint: ModelEndpointId::new("mimir"),
            negotiated: NamedGroup::Secp384r1,
        },
    }
}
fn events(rig: &Rig) -> Vec<(AuditEvent, EvidenceProvenance)> {
    rig.events.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

// ---- 1..6 ----

/// 1 — after a full hop, every recorded SAGA event carries non-empty provenance.
#[test]
fn saga_record_carries_provenance() {
    let r = rig(Box::new(OkTool));
    assert!(matches!(
        r.orch.execute_hop(req(attest(P1)), Timestamp(1000)),
        HopResult::Executed { .. }
    ));
    let ev = events(&r);
    assert!(!ev.is_empty(), "a full hop records events");
    for (_, prov) in &ev {
        assert!(!prov.sensor_id.is_empty());
        assert!(!prov.capture_path.is_empty());
    }
}

/// 2 — every recorded event's `sensor_id` is `"orchestrator"` (the recorder, stated honestly).
#[test]
fn provenance_sensor_is_orchestrator() {
    let r = rig(Box::new(OkTool));
    let _ = r.orch.execute_hop(req(attest(P1)), Timestamp(1000));
    for (_, prov) in &events(&r) {
        assert_eq!(prov.sensor_id, "orchestrator");
    }
}

/// 3 — capture path varies by event: the Proposal record is captured after the reasoner, the
/// Authorization after the gate.
#[test]
fn provenance_capture_path_varies_by_event() {
    let r = rig(Box::new(OkTool));
    let _ = r.orch.execute_hop(req(attest(P1)), Timestamp(1000));
    let ev = events(&r);
    let proposal = ev
        .iter()
        .find(|(e, _)| matches!(e, AuditEvent::Proposal(_)))
        .expect("a Proposal was recorded");
    assert!(
        proposal.1.capture_path.contains("after_reasoner"),
        "{:?}",
        proposal.1
    );
    let authz = ev
        .iter()
        .find(|(e, _)| matches!(e, AuditEvent::Authorization(_)))
        .expect("an Authorization was recorded");
    assert!(authz.1.capture_path.contains("after_gate"), "{:?}", authz.1);
}

/// 4 — a tool failure records a trajectory evidence gap rather than a clean record.
#[test]
fn evidence_gap_recorded_on_failure() {
    let calls = Arc::new(AtomicUsize::new(0));
    let r = rig(Box::new(ErrTool {
        calls: calls.clone(),
    }));
    let out = r.orch.execute_hop(req(attest(P1)), Timestamp(1000));
    assert!(matches!(out, HopResult::Error { .. }), "{out:?}");
    assert_eq!(calls.load(SeqCst), 1, "the tool ran and failed");
    let traj = r.orch.trajectory();
    assert_eq!(traj.len(), 1);
    assert!(
        traj[0].provenance.evidence_gap.is_some(),
        "an errored hop records an explicit evidence gap: {:?}",
        traj[0].provenance
    );
    assert_eq!(traj[0].provenance.observed_coverage, "partial_hop");
}

/// 5 — every recorded event's `capture_timestamp` matches the `now` passed to `execute_hop`.
#[test]
fn provenance_timestamp_matches_hop_now() {
    let r = rig(Box::new(OkTool));
    let _ = r.orch.execute_hop(req(attest(P1)), Timestamp(4242));
    let ev = events(&r);
    assert!(!ev.is_empty());
    for (_, prov) in &ev {
        assert_eq!(prov.capture_timestamp, Timestamp(4242));
    }
}

/// 6 — across a full cycle, no recorded event carries a missing/default (marker) provenance.
#[test]
fn all_saga_events_have_provenance() {
    let r = rig(Box::new(OkTool));
    let _ = r.orch.execute_hop(req(attest(P1)), Timestamp(1000));
    let ev = events(&r);
    // A granting hop records at least the Proposal and the Authorization.
    assert!(ev.iter().any(|(e, _)| matches!(e, AuditEvent::Proposal(_))));
    assert!(
        ev.iter()
            .any(|(e, _)| matches!(e, AuditEvent::Authorization(_)))
    );
    for (_, prov) in &ev {
        // Never the SAGA self-report default, never the direct-record marker.
        assert_ne!(prov.sensor_id, "saga");
        assert_ne!(prov.sensor_id, "unexpected-direct-record");
        assert_eq!(prov.expected_coverage, "full_hop");
    }
}
