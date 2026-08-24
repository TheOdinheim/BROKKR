//! Phase 14C — White-box red team, low noise. The final red-team phase.
//!
//! The deepest attacks: `unsafe` memory safety under specific call sequences, integer/overflow and
//! cast safety, panic safety and `Mutex` poisoning, timing side channels, and cross-subsystem
//! interaction bugs. Most memory-safety / overflow / lock-order attacks are **code-reading**
//! verifications (recorded in `reports/REDTEAM-14C-2026-08-23-R1.md`); this file holds the
//! **runtime** attacks: panic safety (3.1, 3.4), timing side channels (4.1, 4.2), and
//! cross-subsystem interaction (5.1, 5.2, 5.3).
//!
//! Findings continue from **F-18**. Hermetic; real dual-family PQC, signed once serially in `fx()`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use brokkr_audit::AuditEvent;
use brokkr_cli::{
    AuditSink, DenialStage, GenomeCheck, GenomeRefusal, Guards, HopRequest, HopResult,
    Orchestrator, Sentinel, SignalRouter,
};
use brokkr_core::barrier::{
    BarrierCondition, BarrierFinding, BarrierVerdict, BoundaryFlow, Destination,
};
use brokkr_core::classification::{Classification, NamedGroup};
use brokkr_core::crypto::{Attestation, DualSignature, Hasher, Signature, SignatureAlg};
use brokkr_core::gate::{Action, AnergyReason, AuthorizedAction, CostimulationGate};
use brokkr_core::genome::PrivilegeClass;
use brokkr_core::ids::{
    Dap, DatumRef, HopId, ModelEndpointId, Nonce, SubjectId, Timestamp, ToolId,
};
use brokkr_core::intent::{
    Capability, IntentProvenanceChain, IntentScope, Invariant, InvariantSet,
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
    /// p1-signed, scope {write} — a valid granting chain.
    legit: IntentProvenanceChain,
    /// principal = p1 but signed by a DIFFERENT key → root signature fails (slow Signal-2 crypto).
    forged: IntentProvenanceChain,
}
fn fx() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| {
        let mut kp = DualKeyPair::generate().expect("kp");
        let mut attacker = DualKeyPair::generate().expect("attacker");
        let p1_pub = kp.public_key_bytes().expect("pub");
        let far = Timestamp(9_000_000);
        let sign = |kp: &mut DualKeyPair| {
            let root = Skuld
                .sign_root(
                    SubjectId::new(P1),
                    dap(),
                    IntentScope::new([cap("write")]),
                    InvariantSet::new([]),
                    Nonce(1),
                    far,
                    kp,
                )
                .expect("sign");
            IntentProvenanceChain::new(root)
        };
        Fx {
            p1_pub,
            legit: sign(&mut kp),
            forged: sign(&mut attacker), // principal p1, signed by the attacker key
        }
    })
}
fn registry() -> RegistryResolver {
    let (ml, slh) = &fx().p1_pub;
    RegistryResolver::new().with_root(SubjectId::new(P1), ml.clone(), slh.clone())
}
fn hand_sig() -> DualSignature {
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
fn attest(subject: &str) -> Attestation {
    Attestation {
        subject: SubjectId::new(subject),
        measurements: Sha384Hasher.hash(b"m"),
        freshness: Nonce(1),
        signatures: hand_sig(),
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

#[derive(Default)]
struct Counter(AtomicUsize);
impl Counter {
    fn hit(&self) {
        self.0.fetch_add(1, SeqCst);
    }
    fn count(&self) -> usize {
        self.0.load(SeqCst)
    }
}

/// A tool that panics on its FIRST call, succeeds afterwards (proves panic recovery).
struct FlipPanicTool {
    id: ToolId,
    panicked: AtomicBool,
}
impl ToolExecutor for FlipPanicTool {
    fn tool_id(&self) -> &ToolId {
        &self.id
    }
    fn execute(&self, _a: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        if !self.panicked.swap(true, SeqCst) {
            panic!("tool panic (first call)");
        }
        Ok(ToolOutcome {
            output: "recovered".to_string(),
        })
    }
}

/// A tool that returns `Err` (for 5.1 — execution failure).
struct ErrTool {
    id: ToolId,
    calls: Arc<Counter>,
}
impl ToolExecutor for ErrTool {
    fn tool_id(&self) -> &ToolId {
        &self.id
    }
    fn execute(&self, _a: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        self.calls.hit();
        Err(ToolError {
            detail: "boom".to_string(),
        })
    }
}

/// A normal tool.
struct OkTool {
    id: ToolId,
    calls: Arc<Counter>,
}
impl ToolExecutor for OkTool {
    fn tool_id(&self) -> &ToolId {
        &self.id
    }
    fn execute(&self, _a: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        self.calls.hit();
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
/// BIFRÖST double that denies (for 5.3).
struct DenyCrossing;
impl ContextClearance for DenyCrossing {
    fn evaluate_context(&self, _c: &Context, _d: &Destination, _n: Timestamp) -> BarrierVerdict {
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
struct Puppet {
    endpoint: ModelEndpointId,
    calls: Arc<Counter>,
}
impl Reasoner for Puppet {
    fn endpoint(&self) -> &ModelEndpointId {
        &self.endpoint
    }
    fn propose(&self, _c: &ClearedContext, _s: &IntentScope) -> Result<Proposal, ReasonerError> {
        self.calls.hit();
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
struct SpySentinel {
    seen: Arc<Mutex<Vec<Observation>>>,
}
impl Sentinel for SpySentinel {
    fn observe(&self, o: &Observation, _n: Timestamp) -> Vec<Detection> {
        self.seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(o.clone());
        Vec::new()
    }
}
struct SpyAudit {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}
impl AuditSink for SpyAudit {
    fn record(&self, e: AuditEvent, _d: Dap, _a: Timestamp) {
        self.events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(e);
    }
}
struct NoSignals;
impl SignalRouter for NoSignals {
    fn route(&self, _s: &Signal) {}
}

struct Rig {
    orch: Orchestrator,
    reasoner_calls: Arc<Counter>,
    observations: Arc<Mutex<Vec<Observation>>>,
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

/// Build a rig. `tool` selects the executor (the test holds its own call counter); `crossing`
/// selects BIFRÖST; guards default permissive (these tests probe panic/timing/interaction).
fn rig(tool: Box<dyn ToolExecutor>, crossing: Box<dyn ContextClearance>) -> Rig {
    let reasoner_calls = Arc::new(Counter::default());
    let observations = Arc::new(Mutex::new(Vec::new()));
    let events = Arc::new(Mutex::new(Vec::new()));
    let gate: Box<dyn CostimulationGate> = Box::new(Sindri::new(registry(), Genome));
    let orch = Orchestrator::new(
        crossing,
        Box::new(Puppet {
            endpoint: ModelEndpointId::new("mimir"),
            calls: reasoner_calls.clone(),
        }),
        Box::new(Genome),
        gate,
        Box::new(AllowBarrier),
        tool,
        Box::new(SpySentinel {
            seen: observations.clone(),
        }),
        Box::new(SpyAudit {
            events: events.clone(),
        }),
        Box::new(NoSignals),
        dap(),
    )
    .with_guards(Guards::permissive());
    Rig {
        orch,
        reasoner_calls,
        observations,
        events,
    }
}
fn req(chain: IntentProvenanceChain, identity: Attestation) -> HopRequest {
    HopRequest {
        identity,
        chain,
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
fn ok_tool(calls: Arc<Counter>) -> Box<dyn ToolExecutor> {
    Box::new(OkTool {
        id: ToolId::new("write_file"),
        calls,
    })
}

// ======================================================================================
// 3. Panic safety and Mutex poisoning
// ======================================================================================

/// 3.1 — a tool that panics on its first call: the panic unwinds out of `execute_hop` and is
/// caught; the orchestrator's internal state is NOT poisoned, so a second hop executes normally.
/// (No lock is held across `tool.execute` — `check_guards` released `guard_state` and each
/// `audit.record` released SAGA before the tool ran.)
#[test]
fn attack_3_1_tool_panic_does_not_poison_orchestrator() {
    let rig = rig(
        Box::new(FlipPanicTool {
            id: ToolId::new("write_file"),
            panicked: AtomicBool::new(false),
        }),
        Box::new(ClearAll),
    );
    // First hop: the tool panics; catch it.
    let first = catch_unwind(AssertUnwindSafe(|| {
        rig.orch
            .execute_hop(req(fx().legit.clone(), attest(P1)), Timestamp(1000))
    }));
    assert!(
        first.is_err(),
        "the tool panic unwound and was caught (no abort)"
    );
    // Second hop on the SAME orchestrator: the tool now succeeds; the orchestrator is not poisoned.
    let second = rig
        .orch
        .execute_hop(req(fx().legit.clone(), attest(P1)), Timestamp(1001));
    assert!(
        matches!(second, HopResult::Executed { .. }),
        "orchestrator usable after a caught tool panic: {second:?}"
    );
}

/// 3.4 — a panicking hop in one thread does not corrupt a normal hop in another (Rust panics are
/// per-thread). Two independent orchestrators run concurrently; the normal one completes.
#[test]
fn attack_3_4_concurrent_panic_isolated() {
    let normal_calls = Arc::new(Counter::default());
    let normal = rig(ok_tool(normal_calls.clone()), Box::new(ClearAll));
    let panicker = rig(
        Box::new(FlipPanicTool {
            id: ToolId::new("write_file"),
            panicked: AtomicBool::new(false),
        }),
        Box::new(ClearAll),
    );
    let normal_result = thread::scope(|s| {
        let h_panic = s.spawn(|| {
            catch_unwind(AssertUnwindSafe(|| {
                panicker
                    .orch
                    .execute_hop(req(fx().legit.clone(), attest(P1)), Timestamp(1000))
            }))
        });
        let h_normal = s.spawn(|| {
            normal
                .orch
                .execute_hop(req(fx().legit.clone(), attest(P1)), Timestamp(1000))
        });
        let panicked = h_panic.join().expect("thread joined");
        assert!(
            panicked.is_err(),
            "the panicking thread's hop panicked (caught)"
        );
        h_normal.join().expect("normal thread joined")
    });
    assert!(
        matches!(normal_result, HopResult::Executed { .. }),
        "the concurrent normal hop completed: {normal_result:?}"
    );
    assert_eq!(normal_calls.count(), 1);
}

// ======================================================================================
// 4. Timing side channels (informational — inherent in variable-cost work)
// ======================================================================================

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

/// 4.1 — a Signal-1 denial (unknown identity, a registry lookup) is dramatically faster than a
/// Signal-2 denial (a real dual-family signature verification). An observer of denial latency can
/// distinguish "wrong identity" from "wrong signature". Informational — inherent in doing
/// variable-cost work; measured and documented.
#[test]
fn attack_4_1_signal1_vs_signal2_timing() {
    let sindri = Sindri::new(registry(), Genome);
    let action = Action {
        tool: ToolId::new("write_file"),
        detail: "/tmp/x".to_string(),
    };
    let n = 15;
    // Signal-1 denial: identity "ghost" is not in the registry → resolve returns None → fast.
    let id_times: Vec<Duration> = (0..n)
        .map(|_| {
            let t = Instant::now();
            let r = sindri.evaluate(&attest("ghost"), &fx().legit, &action, Timestamp(1000));
            let e = t.elapsed();
            assert_eq!(r, Err(AnergyReason::IdentityUnverified));
            e
        })
        .collect();
    // Signal-2 denial: identity resolves (p1), but the chain's root signature was made by the
    // attacker key → verify_chain_public runs real crypto → slow.
    let sig_times: Vec<Duration> = (0..n)
        .map(|_| {
            let t = Instant::now();
            let r = sindri.evaluate(&attest(P1), &fx().forged, &action, Timestamp(1000));
            let e = t.elapsed();
            assert_eq!(r, Err(AnergyReason::ChainInvalid));
            e
        })
        .collect();
    let (id_med, sig_med) = (median(id_times), median(sig_times));
    println!("4.1 timing: Signal-1 denial median={id_med:?}, Signal-2 denial median={sig_med:?}");
    assert!(
        sig_med > id_med,
        "the crypto (Signal-2) denial is measurably slower than the lookup (Signal-1) denial: {sig_med:?} vs {id_med:?}"
    );
}

/// 4.2 — a guard denial (replay, no crypto) is faster than a SINDRI grant (real crypto). An
/// observer can distinguish "replay detected" from a hop that reached the gate. Informational.
#[test]
fn attack_4_2_guard_vs_sindri_timing() {
    // Replay guard on; first hop primes the nonce, the second is a fast guard denial.
    let calls = Arc::new(Counter::default());
    let orch = {
        let r = rig(ok_tool(calls.clone()), Box::new(ClearAll));
        r.orch
    }
    .with_guards(Guards {
        replay_guard: true,
        rate_limit: None,
        monotonic_time: false,
        uniform_denial_stage: true,
    });
    // Prime + measure a full (crypto) grant.
    let t = Instant::now();
    let first = orch.execute_hop(req(fx().legit.clone(), attest(P1)), Timestamp(1000));
    let grant_time = t.elapsed();
    assert!(matches!(first, HopResult::Executed { .. }));
    // Replay: same nonce → guard denial, no crypto.
    let t = Instant::now();
    let second = orch.execute_hop(req(fx().legit.clone(), attest(P1)), Timestamp(1001));
    let replay_time = t.elapsed();
    assert!(matches!(second, HopResult::Denied { .. }));
    println!("4.2 timing: SINDRI grant median={grant_time:?}, replay-guard denial={replay_time:?}");
    assert!(
        replay_time < grant_time,
        "the guard denial is faster than the crypto grant: {replay_time:?} vs {grant_time:?}"
    );
}

// ======================================================================================
// 5. Cross-subsystem interaction
// ======================================================================================

/// 5.1 — a tool execution FAILURE produces `HopResult::Error` and **no HEIMDALL observation**: the
/// step-8 reconciliation feed is unreachable after a tool error. A failed authorized execution is
/// invisible to HEIMDALL's behavioral loop (F-20).
#[test]
fn attack_5_1_tool_error_is_invisible_to_heimdall() {
    let err_calls = Arc::new(Counter::default());
    let rig = rig(
        Box::new(ErrTool {
            id: ToolId::new("write_file"),
            calls: err_calls.clone(),
        }),
        Box::new(ClearAll),
    );
    let r = rig
        .orch
        .execute_hop(req(fx().legit.clone(), attest(P1)), Timestamp(1000));
    assert!(
        matches!(r, HopResult::Error { .. }),
        "tool error → HopResult::Error: {r:?}"
    );
    assert_eq!(err_calls.count(), 1, "the tool ran and failed");
    // HEIMDALL received NO Hop observation (the reconciliation gap, F-20).
    let obs = rig.observations.lock().unwrap();
    assert!(
        !obs.iter().any(|o| matches!(o, Observation::Hop { .. })),
        "a failed execution emits no reconciliation observation"
    );
}

/// 5.2 — MÍMIR proposes, SAGA records the Proposal, then SINDRI denies. The audit trail shows the
/// proposal AND the anergic authorization — a consistent Proposal→Denied record.
#[test]
fn attack_5_2_proposal_then_denial_both_recorded() {
    // Use an out-of-scope chain so SINDRI denies (read-only scope, tool needs write).
    // Here we deny via an unknown identity for simplicity — SINDRI denies at Signal 1.
    let calls = Arc::new(Counter::default());
    let rig = rig(ok_tool(calls.clone()), Box::new(ClearAll));
    let r = rig
        .orch
        .execute_hop(req(fx().legit.clone(), attest("ghost")), Timestamp(1000));
    assert!(
        matches!(
            r,
            HopResult::Denied {
                stage: DenialStage::Gate,
                ..
            }
        ),
        "{r:?}"
    );
    let events = rig.events.lock().unwrap();
    assert!(
        events.iter().any(|e| matches!(e, AuditEvent::Proposal(_))),
        "the proposal is recorded even though the gate denied"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuditEvent::Authorization(_))),
        "the anergic authorization is recorded"
    );
    assert_eq!(calls.count(), 0, "the tool never ran");
}

/// 5.3 — a BIFRÖST crossing denial records a BarrierCrossing to SAGA and the model is NEVER called
/// (I-12): the classified context stays within the boundary.
#[test]
fn attack_5_3_bifrost_denial_records_and_model_not_called() {
    let calls = Arc::new(Counter::default());
    let rig = rig(ok_tool(calls.clone()), Box::new(DenyCrossing));
    let r = rig
        .orch
        .execute_hop(req(fx().legit.clone(), attest(P1)), Timestamp(1000));
    assert!(
        matches!(
            r,
            HopResult::Denied {
                stage: DenialStage::Bifrost,
                ..
            }
        ),
        "{r:?}"
    );
    assert_eq!(
        rig.reasoner_calls.count(),
        0,
        "the model was never called (I-12)"
    );
    let events = rig.events.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuditEvent::BarrierCrossing(_))),
        "the denied crossing is recorded in SAGA"
    );
}
