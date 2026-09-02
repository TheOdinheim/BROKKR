//! Phase 16 — post-AMD red team. Adversarial pass on the surfaces AMD-010, AMD-011, and the
//! Organ 5 evidence-capture patch introduced (commits `5d2a6f5`…`70ad4f5`): the Capability
//! Envelope, the egress manifest, the kill flag, the trajectory, and evidence provenance.
//!
//! **Document, don't fix.** Every test here *asserts the behaviour that actually ships*, so the
//! finding is the assertion itself: where a test asserts a fail-open default or an ignored
//! manifest field, that is the finding, recorded in `reports/REDTEAM-16-2026-09-01-R1.md`
//! (findings F-32 … F-38). Attack angles already covered by `tests/capability.rs` (manifested
//! allow/deny, kill-before-all-gates, trajectory order) and `tests/evidence.rs` (per-event
//! provenance capture paths) are not duplicated.
//!
//! Hermetic; real dual-family PQC signed once serially in `fx()`.

use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use brokkr_audit::AuditEvent;
use brokkr_audit::canonical::record_signed_content;
use brokkr_audit::event::{AuditRecord, Timestamping};
use brokkr_cli::{
    AuditSink, GenomeCheck, GenomeRefusal, Guards, HopRequest, HopResult, Orchestrator, Sentinel,
    SignalRouter,
};
use brokkr_core::barrier::{BarrierVerdict, BoundaryFlow, Destination};
use brokkr_core::capability::{
    CapabilityEnvelope, CapabilityProperty, ConformanceTier, EgressManifest, EgressProtocol,
    EgressRule, EnvelopeError, EvidenceProvenance,
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

// ---- doubles (mirroring tests/capability.rs) ------------------------------------------

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
/// A tool that signals it has started (past the pre-hop kill check) and then blocks until
/// released — the instrument for F-37 (mid-hop kill does not abort the current hop).
struct BlockingTool {
    started: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}
impl ToolExecutor for BlockingTool {
    fn tool_id(&self) -> &ToolId {
        static ID: OnceLock<ToolId> = OnceLock::new();
        ID.get_or_init(|| ToolId::new("write_file"))
    }
    fn execute(&self, _a: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        let _ = self.started.send(());
        let _ = self
            .release
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .recv();
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
/// Captures every `AuditEvent` the orchestrator records — for F-38 (the trajectory is *not*
/// among the SAGA events; it lives only in the in-memory `Mutex<Vec<..>>`).
struct EventSpy {
    seen: Arc<Mutex<Vec<AuditEvent>>>,
}
impl AuditSink for EventSpy {
    fn record(&self, e: AuditEvent, _d: Dap, _a: Timestamp) {
        self.seen.lock().unwrap_or_else(|p| p.into_inner()).push(e);
    }
}
struct NoSignals;
impl SignalRouter for NoSignals {
    fn route(&self, _s: &Signal) {}
}

/// Compose a granting orchestrator with a chosen tool and audit sink; guards permissive so the
/// spine's own gates (and the AMD-011 surfaces) are what a test exercises. **Does not** install
/// an envelope — the caller adds `.with_envelope(..)` where the test needs one, so the
/// no-envelope default (F-33) can be exercised too.
fn make(tool: Box<dyn ToolExecutor>, audit: Box<dyn AuditSink>) -> Orchestrator {
    let gate: Box<dyn CostimulationGate> = Box::new(Sindri::new(registry(), Genome));
    Orchestrator::new(
        Box::new(ClearAll),
        Box::new(Puppet {
            endpoint: ModelEndpointId::new("mimir"),
        }),
        Box::new(Genome),
        gate,
        Box::new(AllowBarrier),
        tool,
        Box::new(DiscardSentinel),
        audit,
        Box::new(NoSignals),
        dap(),
    )
    .with_guards(Guards::permissive())
}
fn ok_orch() -> Orchestrator {
    make(Box::new(OkTool), Box::new(DiscardAudit))
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
/// An envelope whose single egress rule is `(destination, port, protocol)`.
fn envelope_with_rule(rule: EgressRule) -> CapabilityEnvelope {
    CapabilityEnvelope {
        system_id: "t".to_string(),
        properties: vec![CapabilityProperty::NetworkAccess {
            declared_destinations: vec![rule.destination.clone()],
        }],
        egress_manifest: Some(EgressManifest {
            rules: vec![rule],
            signature: sig(),
        }),
        capability_tier: ConformanceTier::Enhanced,
        data_tier: ConformanceTier::Baseline,
        governing_tier: ConformanceTier::Enhanced,
        attested_at: Timestamp(1),
        signature: sig(),
    }
}

// ======================================================================================
// F-32 — `with_envelope` does not validate: an invalid envelope governs a live orchestrator
// ======================================================================================

/// F-32 — an envelope with `ExternalEffect` but `capability_tier: Baseline` is invalid
/// (`TierTooLow`), yet `with_envelope` installs it without complaint and the orchestrator runs.
/// The type *can* catch it (`validate()` returns `Err`); the orchestrator boundary does not call
/// `validate()`, so the drafted I-14 ("validated before it governs") is not enforced here.
#[test]
fn f32_with_envelope_accepts_tier_too_low() {
    let bad = CapabilityEnvelope {
        system_id: "bad".to_string(),
        properties: vec![CapabilityProperty::ExternalEffect {
            targets: vec!["filesystem".to_string()],
        }],
        egress_manifest: None,
        capability_tier: ConformanceTier::Baseline, // ExternalEffect requires Enhanced
        data_tier: ConformanceTier::Baseline,
        governing_tier: ConformanceTier::Baseline,
        attested_at: Timestamp(1),
        signature: sig(),
    };
    // The type catches it...
    assert_eq!(bad.validate(), Err(EnvelopeError::TierTooLow));
    // ...but the orchestrator installs it and runs anyway (the finding).
    let orch = ok_orch().with_envelope(bad.clone());
    assert_eq!(orch.envelope().capability_tier, ConformanceTier::Baseline);
    let out = orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000));
    assert!(
        matches!(out, HopResult::Executed { .. }),
        "an invalid (never-validated) envelope still governs a running orchestrator: {out:?}"
    );
}

/// F-32 — a `governing_tier` that is not `max(capability, data)` is `TierMismatch`, and is
/// likewise installed without validation.
#[test]
fn f32_with_envelope_accepts_tier_mismatch() {
    let bad = CapabilityEnvelope {
        system_id: "bad".to_string(),
        properties: vec![],
        egress_manifest: None,
        capability_tier: ConformanceTier::Enhanced,
        data_tier: ConformanceTier::Baseline,
        governing_tier: ConformanceTier::Baseline, // != max(Enhanced, Baseline)
        attested_at: Timestamp(1),
        signature: sig(),
    };
    assert_eq!(bad.validate(), Err(EnvelopeError::TierMismatch));
    let orch = ok_orch().with_envelope(bad);
    // The under-stated governing tier is accepted verbatim.
    assert_eq!(orch.envelope().governing_tier, ConformanceTier::Baseline);
}

// ======================================================================================
// F-33 — capability governance is fail-open by default
// ======================================================================================

/// F-33 — an orchestrator built via `new()` with **no** `.with_envelope()` defaults to a
/// permissive envelope and `egress_rules: None`, so egress enforcement is a no-op: a network
/// crossing to a destination on **no** manifest proceeds. Contrast `guards`, which default to
/// `Guards::production()` (fail-safe). The AMD-011 default is fail-open.
#[test]
fn f33_default_envelope_fails_open_on_egress() {
    let orch = ok_orch(); // no `.with_envelope(..)`
    let out = orch.execute_hop(
        req(network_dest("evil.example.com"), attest(P1)),
        Timestamp(1000),
    );
    assert!(
        matches!(out, HopResult::Executed { .. }),
        "default (no envelope) performs no egress enforcement — fail-open: {out:?}"
    );
    // The default envelope is the permissive one.
    assert_eq!(orch.envelope().system_id, "permissive");
}

// ======================================================================================
// F-34 — the manifest's port and protocol are structurally unenforceable
// ======================================================================================

/// F-34 — `Destination::Network` carries only `{ host, channel }` (no port, no protocol), and
/// `check_egress` matches on host alone. A rule declaring a *wrong* port and protocol still
/// admits the host: the `port`/`protocol` fields of `EgressRule` (mandated by P-12.4) are dead.
#[test]
fn f34_egress_ignores_port_and_protocol() {
    let orch = ok_orch().with_envelope(envelope_with_rule(EgressRule {
        destination: "localhost".to_string(),
        port: 1,                        // deliberately not 8443
        protocol: EgressProtocol::Http, // deliberately not Https
    }));
    let out = orch.execute_hop(req(network_dest("localhost"), attest(P1)), Timestamp(1000));
    assert!(
        matches!(out, HopResult::Executed { .. }),
        "host matches; the rule's wrong port/protocol are ignored — enforcement is host-only: {out:?}"
    );
}

// ======================================================================================
// F-35 — host matching is exact-string: representation-sensitive, no wildcard
// ======================================================================================

/// F-35 — a manifest allowing `localhost` denies `127.0.0.1` (same endpoint, different spelling).
/// Too strict on the host, while F-34 is too loose on the port.
#[test]
fn f35_egress_host_representation_sensitive() {
    let orch = ok_orch().with_envelope(envelope_with_rule(EgressRule {
        destination: "localhost".to_string(),
        port: 8443,
        protocol: EgressProtocol::Https,
    }));
    let out = orch.execute_hop(req(network_dest("127.0.0.1"), attest(P1)), Timestamp(1000));
    assert!(
        matches!(out, HopResult::Denied { .. }),
        "127.0.0.1 != localhost under exact-string match: {out:?}"
    );
}

/// F-35 — `"*"` is a literal destination, not a glob: it matches only the host `"*"`.
#[test]
fn f35_egress_star_is_literal_not_wildcard() {
    let orch = ok_orch().with_envelope(envelope_with_rule(EgressRule {
        destination: "*".to_string(),
        port: 443,
        protocol: EgressProtocol::Https,
    }));
    let out = orch.execute_hop(
        req(network_dest("anything.example"), attest(P1)),
        Timestamp(1000),
    );
    assert!(
        matches!(out, HopResult::Denied { .. }),
        "\"*\" is a literal host, not a wildcard: {out:?}"
    );
}

// ======================================================================================
// F-36 — the kill flag is not a latch
// ======================================================================================

/// F-36 — set then unset resumes operation. `AtomicBool` is freely settable; there is no
/// once-killed-stays-killed latch. Any holder of the handle can re-enable the orchestrator.
#[test]
fn f36_kill_flag_is_not_a_latch() {
    let orch = ok_orch();
    let kill = orch.kill_handle();
    kill.store(true, Ordering::Release);
    // Denied while set...
    assert!(matches!(
        orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000)),
        HopResult::Denied { .. }
    ));
    // ...reset resumes.
    kill.store(false, Ordering::Release);
    assert!(
        matches!(
            orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1001)),
            HopResult::Executed { .. }
        ),
        "unsetting the kill flag resumes operation — it is not a latch"
    );
}

// ======================================================================================
// F-37 — the kill flag is a pre-hop check, not a mid-hop abort
// ======================================================================================

/// F-37 — a kill set *after* a hop has passed the pre-hop check (while the tool is executing)
/// does not abort the current hop; it stops the *next* one. Termination latency is bounded by
/// the longest single tool call, not immediate.
#[test]
fn f37_kill_flag_is_pre_hop_not_mid_hop() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let orch = make(
        Box::new(BlockingTool {
            started: started_tx,
            release: Mutex::new(release_rx),
        }),
        Box::new(DiscardAudit),
    );
    let kill = orch.kill_handle();
    thread::scope(|s| {
        let h = s.spawn(|| orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000)));
        started_rx.recv().expect("tool started"); // past the pre-hop kill check, inside execute
        kill.store(true, Ordering::Release); // set kill mid-hop
        release_tx.send(()).expect("release"); // let the tool finish
        let out = h.join().expect("join");
        assert!(
            matches!(out, HopResult::Executed { .. }),
            "a mid-hop kill does not abort the in-flight hop: {out:?}"
        );
    });
    // The next hop sees the flag and is denied.
    match orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1001)) {
        HopResult::Denied { reason, .. } => assert!(reason.contains("independent termination")),
        other => panic!("the next hop must be denied by the still-set flag: {other:?}"),
    }
}

// ======================================================================================
// F-38 — the trajectory is in-memory, not a SAGA event
// ======================================================================================

/// F-38 — a hop populates the in-memory trajectory, but the SAGA event stream contains no
/// trajectory record (there is no `AuditEvent` trajectory variant). Durable reconstruction rests
/// on the individual SAGA events; the `TrajectoryEntry` snapshot is volatile.
#[test]
fn f38_trajectory_is_not_a_saga_event() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let orch = make(Box::new(OkTool), Box::new(EventSpy { seen: seen.clone() }));
    let _ = orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000));

    // The trajectory is populated in memory...
    assert_eq!(orch.trajectory().len(), 1);

    // ...but every SAGA event is one of the ordinary decision records, never a trajectory.
    let events = seen.lock().unwrap_or_else(|p| p.into_inner());
    assert!(!events.is_empty(), "the hop recorded SAGA events");
    for e in events.iter() {
        assert!(
            matches!(
                e,
                AuditEvent::Proposal(_)
                    | AuditEvent::BarrierCrossing(_)
                    | AuditEvent::Authorization(_)
                    | AuditEvent::Signal(_)
            ),
            "no trajectory record enters the SAGA stream: {e:?}"
        );
    }
}

// ======================================================================================
// Supporting confirmations (PASS) on the same surfaces
// ======================================================================================

/// A.1.3 / B.1.2 — an empty-properties envelope and the `permissive()` default both validate,
/// even though `with_envelope` never calls `validate()`. (Documents that permissive is *valid*,
/// so F-32/F-33's risk is the missing call, not a malformed default.)
#[test]
fn empty_and_permissive_envelopes_are_valid() {
    assert!(CapabilityEnvelope::permissive().validate().is_ok());
    let empty = CapabilityEnvelope {
        system_id: "e".to_string(),
        properties: vec![],
        egress_manifest: None,
        capability_tier: ConformanceTier::Baseline,
        data_tier: ConformanceTier::Baseline,
        governing_tier: ConformanceTier::Baseline,
        attested_at: Timestamp(0),
        signature: sig(),
    };
    assert!(empty.validate().is_ok());
}

/// A.2.3 — a manifest with no rules denies every network destination (default-deny holds even
/// with an empty allow-list; the finding surface is only F-34/F-35 on *how* a rule matches).
#[test]
fn empty_manifest_denies_all_network() {
    let orch = ok_orch().with_envelope(CapabilityEnvelope {
        system_id: "empty-manifest".to_string(),
        properties: vec![CapabilityProperty::NetworkAccess {
            declared_destinations: vec![],
        }],
        egress_manifest: Some(EgressManifest {
            rules: vec![],
            signature: sig(),
        }),
        capability_tier: ConformanceTier::Enhanced,
        data_tier: ConformanceTier::Baseline,
        governing_tier: ConformanceTier::Enhanced,
        attested_at: Timestamp(1),
        signature: sig(),
    });
    assert!(matches!(
        orch.execute_hop(req(network_dest("localhost"), attest(P1)), Timestamp(1000)),
        HopResult::Denied { .. }
    ));
}

/// A.4.3 — under concurrent hops the trajectory sequence numbers are unique and contiguous
/// (assigned under the trajectory `Mutex`), even though temporal order may interleave.
#[test]
fn trajectory_sequences_unique_and_contiguous_under_concurrency() {
    let orch = ok_orch();
    thread::scope(|s| {
        for _ in 0..10 {
            s.spawn(|| {
                let _ = orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000));
            });
        }
    });
    let mut seqs: Vec<u64> = orch.trajectory().iter().map(|e| e.sequence).collect();
    seqs.sort_unstable();
    assert_eq!(seqs, (0..10).collect::<Vec<_>>(), "unique, contiguous 0..9");
}

/// B.4.2 — evidence provenance is part of the signed content: two records differing *only* in
/// `provenance.sensor_id` produce different signed bytes, so a non-key-holder cannot rewrite how
/// a record claims it was captured without breaking the signature/chain.
#[test]
fn provenance_is_covered_by_signed_content() {
    let base = AuditRecord {
        seq: 0,
        prev: Sha384Hasher.hash(b"genesis"),
        at: Timestamp(1),
        dap: dap(),
        event: AuditEvent::Correction {
            corrects: 0,
            detail: "x".to_string(),
        },
        provenance: EvidenceProvenance {
            sensor_id: "orchestrator".to_string(),
            capture_path: "execute_hop".to_string(),
            capture_timestamp: Timestamp(1),
            expected_coverage: "full_hop".to_string(),
            observed_coverage: "full_hop".to_string(),
            evidence_gap: None,
        },
        signatures: Vec::new(),
        timestamping: Timestamping::Unavailable {
            reason: "pending".to_string(),
        },
    };
    let sc1 = record_signed_content(&base);
    let mut altered = base.clone();
    altered.provenance.sensor_id = "attacker-sensor".to_string();
    let sc2 = record_signed_content(&altered);
    assert_ne!(
        sc1, sc2,
        "provenance is inside the signed content — altering it changes the signed bytes"
    );
}

/// C.1.1 — the envelope is self-declared, not attested against the environment (P-12.3 residual):
/// a tool with real filesystem effect runs under an envelope that declares **no** `ExternalEffect`,
/// and the spine does not detect the under-declaration.
#[test]
fn under_declared_envelope_is_not_detected() {
    let orch = ok_orch().with_envelope(CapabilityEnvelope {
        system_id: "under-declared".to_string(),
        properties: vec![CapabilityProperty::CodeExecution], // no ExternalEffect declared
        egress_manifest: None,
        capability_tier: ConformanceTier::Baseline,
        data_tier: ConformanceTier::Baseline,
        governing_tier: ConformanceTier::Baseline,
        attested_at: Timestamp(1),
        signature: sig(),
    });
    // OkTool "writes a file"; nothing reconciles that effect against the declaration.
    assert!(matches!(
        orch.execute_hop(req(reasoner_dest(), attest(P1)), Timestamp(1000)),
        HopResult::Executed { .. }
    ));
}
