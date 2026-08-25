//! Phase 14-FIX — regression tests for the white-box red-team findings at the orchestrator / tool
//! layer: **F-13** (nonce-ledger bound), **F-14** (unterminated-CSI bound in the audit sanitizer),
//! **F-15** (empty-path rejection), **F-20** (HEIMDALL observes tool failures).
//!
//! F-16 / F-17 (parser) have their regression tests co-located in `brokkr-reasoner::ollama`;
//! F-18 / F-19 (crypto) in `brokkr-crypto`. Each test **fails without the fix and passes with it**.
//! Hermetic; real dual-family PQC, signed once serially in `fx()`.

use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};

use brokkr_audit::AuditEvent;
use brokkr_cli::{
    AuditSink, DenialStage, GenomeCheck, GenomeRefusal, Guards, HopRequest, HopResult,
    MAX_NONCE_ENTRIES, Orchestrator, Sentinel, SignalRouter, sanitize_for_audit,
};
use brokkr_core::barrier::{
    BarrierCondition, BarrierFinding, BarrierVerdict, BoundaryFlow, Destination,
};
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

// A single serially-signed chain + its public key (13A F-4: never sign concurrently).
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
fn attest() -> Attestation {
    Attestation {
        subject: SubjectId::new(P1),
        measurements: Sha384Hasher.hash(b"m"),
        freshness: Nonce(1),
        signatures: fx().legit.root().signature.clone(),
    }
}

/// A cheap chain variant: clone the (signed) root and overwrite only `nonce`/`expiry`. The replay
/// guard reads only `principal`/`nonce`/`expiry` and never verifies the signature — and in the
/// F-13 test the crossing denies before SINDRI would — so an invalid signature is irrelevant here.
fn variant(nonce: u64, expiry: u64) -> IntentProvenanceChain {
    let mut root = fx().legit.root().clone();
    root.nonce = Nonce(nonce);
    root.expiry = Timestamp(expiry);
    IntentProvenanceChain::new(root)
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
struct OkTool {
    id: ToolId,
}
impl ToolExecutor for OkTool {
    fn tool_id(&self) -> &ToolId {
        &self.id
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
/// BIFRÖST double that denies every crossing (so a hop stops right after the driver guards run).
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

#[allow(clippy::too_many_arguments)]
fn orchestrator(
    tool: Box<dyn ToolExecutor>,
    crossing: Box<dyn ContextClearance>,
    sentinel: Box<dyn Sentinel>,
    audit: Box<dyn AuditSink>,
    guards: Guards,
) -> Orchestrator {
    let gate: Box<dyn CostimulationGate> = Box::new(Sindri::new(registry(), Genome));
    Orchestrator::new(
        crossing,
        Box::new(Puppet {
            endpoint: ModelEndpointId::new("mimir"),
        }),
        Box::new(Genome),
        gate,
        Box::new(AllowBarrier),
        tool,
        sentinel,
        audit,
        Box::new(NoSignals),
        dap(),
    )
    .with_guards(guards)
}

fn ctx() -> Context {
    Context {
        payload: "c".to_string(),
        datum: DatumRef::new("d"),
        classification: Classification::Public,
        personal: None,
        bcr: None,
    }
}
fn req(chain: IntentProvenanceChain) -> HopRequest {
    HopRequest {
        identity: attest(),
        chain,
        context: ctx(),
        dest: Destination::Reasoner {
            endpoint: ModelEndpointId::new("mimir"),
            negotiated: NamedGroup::Secp384r1,
        },
    }
}

// ---- F-13: the replay-nonce ledger is bounded ----------------------------------------

/// The ledger is bounded — it never grows past `MAX_NONCE_ENTRIES`. **15-FIX F-29 changed the
/// mechanism:** where F-13 evicted the smallest-expiry entry at capacity, F-29 evicts only *expired*
/// entries and, when the ledger is full of still-valid nonces, **rejects** the new chain ("ledger
/// full") rather than dropping a fresh one. This test fills the ledger with `MAX_NONCE_ENTRIES` fresh
/// nonces, confirms the overflow is rejected (bounded), and confirms every recorded nonce is still
/// remembered (never evicted while fresh). Fails without F-13/F-29 (an unbounded ledger admits the
/// overflow; the old eviction would re-admit an evicted nonce). Each hop stops at the denying
/// crossing after the guard records it.
#[test]
fn fix_f13_nonce_ledger_bounded() {
    let orch = orchestrator(
        Box::new(OkTool {
            id: ToolId::new("write_file"),
        }),
        Box::new(DenyCrossing),
        Box::new(DiscardSentinel),
        Box::new(DiscardAudit),
        Guards {
            replay_guard: true,
            rate_limit: None,
            monotonic_time: false,
            uniform_denial_stage: false,
        },
    );
    let now = Timestamp(1000);
    let fresh = u64::MAX; // every nonce is still valid at `now`

    // Fill the ledger to capacity with MAX_NONCE_ENTRIES distinct fresh nonces (0 .. MAX-1). Each is
    // admitted by the guard and then denied by the crossing.
    for i in 0..MAX_NONCE_ENTRIES as u64 {
        match orch.execute_hop(req(variant(i, fresh)), now) {
            HopResult::Denied {
                stage: DenialStage::Bifrost,
                ..
            } => {}
            other => panic!("hop {i} should be admitted then crossing-denied: {other:?}"),
        }
    }

    // The ledger is now full of valid entries. A *new* nonce is REJECTED (F-29), not admitted by
    // evicting a fresh one — this is the memory bound.
    match orch.execute_hop(req(variant(MAX_NONCE_ENTRIES as u64, fresh)), now) {
        HopResult::Denied { stage, reason } => {
            assert_eq!(stage, DenialStage::Gate);
            assert!(
                reason.contains("ledger full"),
                "overflow is rejected: {reason}"
            );
        }
        other => panic!("a full ledger must reject a new nonce (F-29): {other:?}"),
    }

    // Every recorded nonce is still remembered — none was evicted while fresh (F-29). Both the first
    // and a middle nonce replay-deny.
    for target in [0u64, 1u64] {
        match orch.execute_hop(req(variant(target, fresh)), now) {
            HopResult::Denied { stage, reason } => {
                assert_eq!(stage, DenialStage::Gate);
                assert!(
                    reason.contains("replay"),
                    "nonce_{target} still remembered: {reason}"
                );
            }
            other => panic!("nonce_{target} must remain a replay (never evicted): {other:?}"),
        }
    }
}

// ---- F-14: unterminated ANSI CSI drop is bounded -------------------------------------

/// An unterminated CSI (ESC `[` followed only by parameter bytes with no final byte) previously
/// consumed the whole remainder of the string, letting an attacker truncate a recorded value by
/// appending a lone `ESC [`. F-14 caps the skip at 16 chars, so a long tail survives. Fails without
/// the fix (the whole `;`-run is dropped → output == "KEEP").
#[test]
fn fix_f14_unterminated_csi_bounded() {
    let tail = ";".repeat(40); // 40 CSI parameter bytes (0x3b) — never a final byte, so unterminated
    let input = format!("KEEP\u{1b}[{tail}");
    let out = sanitize_for_audit(&input);
    assert!(out.starts_with("KEEP"), "prefix survives: {out:?}");
    // At most 16 chars are consumed by the capped CSI skip, so > 20 of the 40 tail bytes survive.
    assert!(
        out.len() > "KEEP".len() + 20,
        "the unterminated-CSI drop is bounded; the tail survives: len={} ({out:?})",
        out.len()
    );
    // The ESC introducer never appears in the audit copy.
    assert!(!out.contains('\u{1b}'), "ESC dropped: {out:?}");
}

/// A *terminated* CSI is still fully dropped (regression guard: the cap did not break normal
/// stripping). `ESC [ 3 1 m` → the `m` (0x6d) is the final byte; `31m` is removed, `red` survives.
#[test]
fn fix_f14_terminated_csi_still_stripped() {
    let out = sanitize_for_audit("a\u{1b}[31mred");
    assert_eq!(out, "ared", "terminated CSI fully stripped: {out:?}");
}

// ---- F-15: empty path rejected by the sandbox ----------------------------------------

/// `SandboxedTool::resolve("")` is rejected at the sandbox layer (F-15), rather than resolving to
/// the root directory and relying on the filesystem to refuse the write. Fails without the fix
/// (`resolve("")` returns `Ok(root)`).
#[test]
fn fix_f15_empty_detail_rejected() {
    use brokkr_tools::SandboxedTool;
    let root = std::env::temp_dir().join(format!("brokkr-fix-f15-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let tool = SandboxedTool::new(ToolId::new("write_file"), &root).expect("sandbox");
    assert!(
        tool.resolve("").is_err(),
        "empty detail is rejected by the sandbox check itself"
    );
    // A legitimate in-root path is still accepted (no over-denial).
    assert!(tool.resolve("safe.txt").is_ok());
    let _ = std::fs::remove_dir_all(&root);
}

// ---- F-20: HEIMDALL observes an authorized-but-failed execution ----------------------

/// When an *authorized* action fails to execute, the orchestrator now feeds HEIMDALL an
/// `Observation::Hop { executed: None }` (F-20), so a failed authorized execution is visible to the
/// reconciliation loop. Fails without the fix (the tool-error path returned before the observation).
#[test]
fn fix_f20_tool_failure_observed() {
    let obs = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(Counter::default());
    let orch = orchestrator(
        Box::new(ErrTool {
            id: ToolId::new("write_file"),
            calls: calls.clone(),
        }),
        Box::new(ClearAll),
        Box::new(SpySentinel { seen: obs.clone() }),
        Box::new(DiscardAudit),
        Guards::permissive(),
    );
    let r = orch.execute_hop(req(fx().legit.clone()), Timestamp(1000));
    assert!(matches!(r, HopResult::Error { .. }), "tool error: {r:?}");
    assert_eq!(calls.count(), 1, "the tool ran and failed");
    let seen = obs.lock().unwrap_or_else(|p| p.into_inner());
    assert!(
        seen.iter()
            .any(|o| matches!(o, Observation::Hop { executed: None, .. })),
        "HEIMDALL saw the authorized-but-unexecuted action: {seen:?}"
    );
}
