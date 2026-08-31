//! AMD-011 — orchestrator integration for Capability-Triggered Assurance:
//! deterministic default-deny egress (P-12.4), independent termination (P-12.5),
//! and trajectory reconstruction with evidence provenance (P-12.8).
//!
//! Hermetic; real dual-family PQC signed once serially in `fx()`.

use std::sync::OnceLock;
use std::sync::atomic::Ordering;
use std::thread;

use brokkr_audit::AuditEvent;
use brokkr_cli::{
    AuditSink, DenialStage, GenomeCheck, GenomeRefusal, Guards, HopRequest, HopResult,
    Orchestrator, Sentinel, SignalRouter,
};
use brokkr_core::barrier::{BarrierVerdict, BoundaryFlow, Destination};
use brokkr_core::capability::{
    CapabilityEnvelope, CapabilityProperty, ConformanceTier, EgressManifest, EgressProtocol,
    EgressRule, TrajectoryOutcome,
};
use brokkr_core::classification::{ChannelStrength, Classification, NamedGroup};
use brokkr_core::crypto::{Attestation, DualSignature, Hasher, Signature, SignatureAlg};
use brokkr_core::gate::{Action, AuthorizedAction, CostimulationGate};
use brokkr_core::genome::PrivilegeClass;
use brokkr_core::ids::{
    Dap, DatumRef, HopId, Host, ModelEndpointId, Nonce, SubjectId, Timestamp, ToolId,
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
fn sig() -> DualSignature {
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

/// BROKKR's actual envelope: CodeExecution + NetworkAccess(localhost:8443) +
/// ExternalEffect(filesystem); egress manifest allows localhost:8443; governing tier Enhanced.
fn brokkr_envelope() -> CapabilityEnvelope {
    CapabilityEnvelope {
        system_id: "BROKKR".to_string(),
        properties: vec![
            CapabilityProperty::CodeExecution,
            CapabilityProperty::NetworkAccess {
                declared_destinations: vec!["localhost:8443".to_string()],
            },
            CapabilityProperty::ExternalEffect {
                targets: vec!["filesystem:/tmp/brokkr".to_string()],
            },
        ],
        egress_manifest: Some(EgressManifest {
            rules: vec![EgressRule {
                destination: "localhost".to_string(),
                port: 8443,
                protocol: EgressProtocol::Https,
            }],
            signature: sig(),
        }),
        capability_tier: ConformanceTier::Enhanced,
        data_tier: ConformanceTier::Baseline,
        governing_tier: ConformanceTier::Enhanced,
        attested_at: Timestamp(1),
        signature: sig(),
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
struct ClearAll;
impl ContextClearance for ClearAll {
    fn evaluate_context(&self, _c: &Context, _d: &Destination, _n: Timestamp) -> BarrierVerdict {
        BarrierVerdict::Allow
    }
}
struct DenyCrossing;
impl ContextClearance for DenyCrossing {
    fn evaluate_context(&self, _c: &Context, _d: &Destination, _n: Timestamp) -> BarrierVerdict {
        use brokkr_core::barrier::{BarrierCondition, BarrierFinding};
        BarrierVerdict::Deny {
            finding: BarrierFinding {
                datum: DatumRef::new("ctx"),
                condition: BarrierCondition::ChannelStrengthCollapse,
                classification: Classification::Secret,
                reason: "crossing denied".to_string(),
            },
        }
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
struct DiscardAudit;
impl AuditSink for DiscardAudit {
    fn record(&self, _e: AuditEvent, _d: Dap, _a: Timestamp) {}
}
struct NoSignals;
impl SignalRouter for NoSignals {
    fn route(&self, _s: &Signal) {}
}

/// Build a granting orchestrator. `crossing` selects BIFRÖST; `envelope` is installed via
/// `.with_envelope`; guards are permissive so the spine's own gates are what's exercised.
fn build(crossing: Box<dyn ContextClearance>, envelope: CapabilityEnvelope) -> Orchestrator {
    let gate: Box<dyn CostimulationGate> = Box::new(Sindri::new(registry(), Genome));
    Orchestrator::new(
        crossing,
        Box::new(Puppet {
            endpoint: ModelEndpointId::new("mimir"),
        }),
        Box::new(Genome),
        gate,
        Box::new(AllowBarrier),
        Box::new(OkTool),
        Box::new(DiscardSentinel),
        Box::new(DiscardAudit),
        Box::new(NoSignals),
        dap(),
    )
    .with_guards(Guards::permissive())
    .with_envelope(envelope)
}
fn req(dest: Destination, identity: Attestation) -> HopRequest {
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
        dest,
    }
}
fn reasoner_dest() -> Destination {
    Destination::Reasoner {
        endpoint: ModelEndpointId::new("mimir"),
        negotiated: NamedGroup::Secp384r1,
    }
}
fn network_dest(host: &str) -> Destination {
    Destination::Network {
        host: Host::new(host),
        channel: ChannelStrength::PqcHybrid768,
    }
}

// ======================================================================================
// P-12.4 — deterministic default-deny egress
// ======================================================================================

/// 5 — a crossing to a manifested network destination proceeds.
#[test]
fn egress_to_manifested_destination_allowed() {
    let orch = build(Box::new(ClearAll), brokkr_envelope());
    let out = orch.execute_hop(req(network_dest("localhost"), attest(P1)), Timestamp(1000));
    assert!(
        matches!(out, HopResult::Executed { .. }),
        "manifested destination proceeds: {out:?}"
    );
}

/// 6 — a crossing to an UN-manifested network destination is denied at the barrier stage.
#[test]
fn egress_to_unmanifested_destination_denied() {
    let orch = build(Box::new(ClearAll), brokkr_envelope());
    match orch.execute_hop(
        req(network_dest("evil.example.com"), attest(P1)),
        Timestamp(1000),
    ) {
        HopResult::Denied { stage, reason } => {
            assert_eq!(stage, DenialStage::Barrier);
            assert!(reason.contains("egress manifest"), "{reason}");
        }
        other => panic!("unmanifested destination must be denied: {other:?}"),
    }
}

/// 7 — with no egress manifest (permissive envelope), the egress check is a no-op and the hop
/// proceeds. (Also the case for a non-network destination.)
#[test]
fn no_manifest_skips_egress_check() {
    let orch = build(Box::new(ClearAll), CapabilityEnvelope::permissive());
    let out = orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000));
    assert!(
        matches!(out, HopResult::Executed { .. }),
        "no manifest → egress skipped → proceeds: {out:?}"
    );
}

// ======================================================================================
// P-12.5 — independent termination
// ======================================================================================

/// 8 — a kill flag set from another thread stops the next hop.
#[test]
fn kill_flag_stops_execution() {
    let orch = build(Box::new(ClearAll), CapabilityEnvelope::permissive());
    let kill = orch.kill_handle();
    thread::scope(|s| {
        s.spawn(|| kill.store(true, Ordering::Release));
    });
    match orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000)) {
        HopResult::Denied { stage, reason } => {
            assert_eq!(stage, DenialStage::Gate);
            assert!(reason.contains("independent termination"), "{reason}");
        }
        other => panic!("a set kill flag must stop the hop: {other:?}"),
    }
}

/// 9 — with the kill flag unset, execution is normal.
#[test]
fn kill_flag_not_set_executes_normally() {
    let orch = build(Box::new(ClearAll), CapabilityEnvelope::permissive());
    assert!(matches!(
        orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000)),
        HopResult::Executed { .. }
    ));
}

/// 10 — the kill flag is checked before ALL gates: even with a crossing that would otherwise deny
/// at BIFRÖST, a set kill flag produces the termination denial, not the crossing denial.
#[test]
fn kill_flag_checked_before_all_gates() {
    let orch = build(Box::new(DenyCrossing), CapabilityEnvelope::permissive());
    orch.kill_handle().store(true, Ordering::Release);
    match orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000)) {
        HopResult::Denied { stage, reason } => {
            assert_eq!(stage, DenialStage::Gate);
            assert!(
                reason.contains("independent termination"),
                "kill fires before the crossing would deny: {reason}"
            );
        }
        other => panic!("kill must win over the crossing denial: {other:?}"),
    }
}

// ======================================================================================
// P-12.8 — trajectory reconstruction + evidence provenance
// ======================================================================================

/// 11 — a successful hop appends one trajectory entry with an `Executed` outcome.
#[test]
fn trajectory_records_executed_hop() {
    let orch = build(Box::new(ClearAll), CapabilityEnvelope::permissive());
    let _ = orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000));
    let traj = orch.trajectory();
    assert_eq!(traj.len(), 1);
    assert!(matches!(
        traj[0].outcome,
        TrajectoryOutcome::Executed { .. }
    ));
    assert_eq!(traj[0].sequence, 0);
}

/// 12 — a denied hop (unknown identity → SINDRI anergy) appends one entry with a `Denied` outcome.
#[test]
fn trajectory_records_denied_hop() {
    let orch = build(Box::new(ClearAll), CapabilityEnvelope::permissive());
    let r = orch.execute_hop(req(reasoner_dest(), attest("ghost")), Timestamp(1000));
    assert!(matches!(r, HopResult::Denied { .. }));
    let traj = orch.trajectory();
    assert_eq!(traj.len(), 1);
    assert!(matches!(traj[0].outcome, TrajectoryOutcome::Denied { .. }));
}

/// 13 — five hops preserve order: five entries, sequences 0..4.
#[test]
fn trajectory_preserves_order() {
    let orch = build(Box::new(ClearAll), CapabilityEnvelope::permissive());
    for _ in 0..5 {
        let _ = orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000));
    }
    let traj = orch.trajectory();
    assert_eq!(traj.len(), 5);
    for (i, entry) in traj.iter().enumerate() {
        assert_eq!(entry.sequence, i as u64);
    }
}

/// 14 — every trajectory entry carries non-empty evidence provenance (P-12.8 / Organ 5 patch).
#[test]
fn trajectory_entry_carries_provenance() {
    let orch = build(Box::new(ClearAll), CapabilityEnvelope::permissive());
    let _ = orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000));
    let _ = orch.execute_hop(req(reasoner_dest(), attest("ghost")), Timestamp(1001));
    let traj = orch.trajectory();
    assert_eq!(traj.len(), 2);
    for entry in &traj {
        assert_eq!(entry.provenance.sensor_id, "orchestrator");
        assert!(!entry.provenance.capture_path.is_empty());
        assert_eq!(entry.provenance.expected_coverage, "full_hop");
    }
}
