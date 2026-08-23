//! Phase 13-FIX — regression tests for the black-box red-team findings.
//!
//! Each test **fails without the fix and passes with it**. F-4 (crypto `sign_dual(&mut)`) and F-6
//! (strict parser) have their regression tests co-located in `brokkr-crypto`/`brokkr-reasoner`;
//! this file covers the orchestrator-layer fixes: F-1 (replay), F-3 (size), F-5 (uniform denial
//! stage), F-7 (rate limit), F-8 (audit sanitization), F-9 (monotonic time), F-10 (scope
//! validation) — and F-2 (the sandboxed tool) at the `brokkr-tools` boundary.
//!
//! These build a **production-guarded** orchestrator (unlike the red-team rigs, which use
//! `Guards::permissive()` to verify the spine's own gates); F-2 is a direct `SandboxedTool` test.
//! Hermetic; real dual-family PQC, signed once serially.

use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};

use brokkr_audit::{AuditEvent, ProposalRecord};
use brokkr_cli::{
    AuditSink, DenialStage, GenomeCheck, GenomeRefusal, Guards, HopRequest, HopResult,
    Orchestrator, RateLimit, Sentinel, SignalRouter, sanitize_for_audit, validate_scope,
};
use brokkr_core::barrier::{BarrierVerdict, BoundaryFlow, Destination};
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
use brokkr_tools::{SandboxedTool, ToolError, ToolExecutor, ToolOutcome};

const PRINCIPAL: &str = "principal-1";

fn dap() -> Dap {
    Dap::new("Jeremy Rose", "jr")
}
fn cap(s: &str) -> Capability {
    Capability::new(s)
}

// A single serially-signed chain + its public key (13A F-4: never sign concurrently).
struct Fx {
    a_pub: (Vec<u8>, Vec<u8>),
    legit: IntentProvenanceChain,
}
fn fx() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| {
        let mut a = DualKeyPair::generate().expect("kp");
        let a_pub = a.public_key_bytes().expect("pub");
        let root: RootIntent = Skuld
            .sign_root(
                SubjectId::new(PRINCIPAL),
                dap(),
                IntentScope::new([cap("write")]),
                InvariantSet::new([]),
                Nonce(1),
                Timestamp(9_000_000),
                &mut a,
            )
            .expect("sign");
        Fx {
            a_pub,
            legit: IntentProvenanceChain::new(root),
        }
    })
}
fn registry() -> RegistryResolver {
    let (ml, slh) = &fx().a_pub;
    RegistryResolver::new().with_root(SubjectId::new(PRINCIPAL), ml.clone(), slh.clone())
}
fn attestation() -> Attestation {
    Attestation {
        subject: SubjectId::new(PRINCIPAL),
        measurements: Sha384Hasher.hash(b"m"),
        freshness: Nonce(1),
        signatures: fx().legit.root().signature.clone(),
    }
}

#[derive(Clone)]
struct TestGenome;
impl TestGenome {
    fn resolved() -> ResolvedTool {
        ResolvedTool {
            required_capabilities: vec![cap("write")],
            privilege: PrivilegeClass::Privileged,
        }
    }
}
impl GenomeResolver for TestGenome {
    fn resolve_tool(&self, tool: &ToolId) -> Option<ResolvedTool> {
        (tool.as_str() == "write_file").then(TestGenome::resolved)
    }
    fn resolve_invariant(&self, _i: &Invariant) -> Option<ResolvedInvariant> {
        None
    }
}
impl GenomeCheck for TestGenome {
    fn check(&self, action: &Action, _c: &IntentProvenanceChain) -> Result<(), GenomeRefusal> {
        if action.tool.as_str() == "write_file" {
            Ok(())
        } else {
            Err(GenomeRefusal {
                detail: format!("tool {} not declared", action.tool.as_str()),
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

struct SpyTool {
    id: ToolId,
    calls: Arc<Counter>,
}
impl ToolExecutor for SpyTool {
    fn tool_id(&self) -> &ToolId {
        &self.id
    }
    fn execute(&self, _a: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        self.calls.hit();
        Ok(ToolOutcome {
            output: "spy".to_string(),
        })
    }
}

struct Puppet {
    endpoint: ModelEndpointId,
    tool: String,
    detail: String,
    rationale: String,
}
impl Reasoner for Puppet {
    fn endpoint(&self) -> &ModelEndpointId {
        &self.endpoint
    }
    fn propose(&self, _c: &ClearedContext, _s: &IntentScope) -> Result<Proposal, ReasonerError> {
        Ok(Proposal {
            action: Action {
                tool: ToolId::new(&self.tool),
                detail: self.detail.clone(),
            },
            rationale: self.rationale.clone(),
            hop: HopId::new("hop-1"),
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
struct SpyAudit {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}
impl AuditSink for SpyAudit {
    fn record(&self, e: AuditEvent, _d: Dap, _a: Timestamp) {
        self.events.lock().unwrap().push(e);
    }
}
struct NoSentinel;
impl Sentinel for NoSentinel {
    fn observe(&self, _o: &Observation, _n: Timestamp) -> Vec<Detection> {
        Vec::new()
    }
}
struct NoSignals;
impl SignalRouter for NoSignals {
    fn route(&self, _s: &Signal) {}
}

struct Rig {
    orch: Orchestrator,
    tool: Arc<Counter>,
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

/// A **production-guarded** orchestrator (13-FIX defaults) with a puppet proposing `tool`/`detail`.
fn rig(tool: &str, detail: &str, rationale: &str) -> Rig {
    rig_with(tool, detail, rationale, Guards::production())
}
fn rig_with(tool: &str, detail: &str, rationale: &str, guards: Guards) -> Rig {
    let calls = Arc::new(Counter::default());
    let events = Arc::new(Mutex::new(Vec::new()));
    let gate: Box<dyn CostimulationGate> = Box::new(Sindri::new(registry(), TestGenome));
    let orch = Orchestrator::new(
        Box::new(ClearAll),
        Box::new(Puppet {
            endpoint: ModelEndpointId::new("mimir"),
            tool: tool.to_string(),
            detail: detail.to_string(),
            rationale: rationale.to_string(),
        }),
        Box::new(TestGenome),
        gate,
        Box::new(AllowBarrier),
        Box::new(SpyTool {
            id: ToolId::new("write_file"),
            calls: calls.clone(),
        }),
        Box::new(NoSentinel),
        Box::new(SpyAudit {
            events: events.clone(),
        }),
        Box::new(NoSignals),
        dap(),
    )
    .with_guards(guards);
    Rig {
        orch,
        tool: calls,
        events,
    }
}
fn ctx() -> Context {
    Context {
        payload: "ctx".to_string(),
        datum: DatumRef::new("ctx-1"),
        classification: Classification::Public,
        personal: None,
        bcr: None,
    }
}
fn req() -> HopRequest {
    HopRequest {
        identity: attestation(),
        chain: fx().legit.clone(),
        context: ctx(),
        dest: Destination::Reasoner {
            endpoint: ModelEndpointId::new("mimir"),
            negotiated: NamedGroup::Secp384r1,
        },
    }
}
fn proposals(events: &Arc<Mutex<Vec<AuditEvent>>>) -> Vec<ProposalRecord> {
    events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            AuditEvent::Proposal(p) => Some(p.clone()),
            _ => None,
        })
        .collect()
}

// ---- F-1: replay guard ---------------------------------------------------------------

#[test]
fn fix_f1_replay_denied() {
    let r = rig("write_file", "/tmp/x", "ok");
    let first = r.orch.execute_hop(req(), Timestamp(1000));
    let second = r.orch.execute_hop(req(), Timestamp(1000));
    assert!(matches!(first, HopResult::Executed { .. }), "{first:?}");
    match &second {
        HopResult::Denied { stage, reason } => {
            assert_eq!(*stage, DenialStage::Gate);
            assert!(reason.contains("replay"), "{reason}");
        }
        other => panic!("expected replay denial, got {other:?}"),
    }
    assert_eq!(r.tool.count(), 1);
}

// ---- F-2: sandboxed filesystem tool --------------------------------------------------

#[test]
fn fix_f2_path_traversal_denied_by_tool() {
    let root = std::env::temp_dir().join(format!("brokkr-fix-f2-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let tool = SandboxedTool::new(ToolId::new("write_file"), &root).expect("sandbox");
    // A traversal escaping the root is rejected as a ToolError, not a panic.
    let escaped = tool.resolve("../../../etc/passwd");
    assert!(escaped.is_err(), "traversal must be rejected: {escaped:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn fix_f2_legitimate_path_within_root() {
    let root = std::env::temp_dir().join(format!("brokkr-fix-f2-ok-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let tool = SandboxedTool::new(ToolId::new("write_file"), &root).expect("sandbox");
    let ok = tool.resolve("safe.txt");
    assert!(ok.is_ok(), "a path within the root is accepted: {ok:?}");
    assert!(
        ok.unwrap()
            .starts_with(std::fs::canonicalize(&root).unwrap())
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ---- F-3: max detail size ------------------------------------------------------------

#[test]
fn fix_f3_oversized_detail_denied() {
    let huge = "A".repeat(2 * 1024 * 1024); // 2 MiB > 1 MiB cap
    let r = rig("write_file", &huge, "ok");
    let result = r.orch.execute_hop(req(), Timestamp(1000));
    match &result {
        HopResult::Denied { stage, reason } => {
            assert_eq!(*stage, DenialStage::Gate);
            assert!(reason.contains("size limit"), "{reason}");
        }
        other => panic!("expected size denial, got {other:?}"),
    }
    assert_eq!(r.tool.count(), 0);
}

#[test]
fn fix_f3_normal_detail_allowed() {
    let r = rig("write_file", "/tmp/normal.txt", "ok");
    assert!(matches!(
        r.orch.execute_hop(req(), Timestamp(1000)),
        HopResult::Executed { .. }
    ));
}

// ---- F-5: uniform denial stage -------------------------------------------------------

#[test]
fn fix_f5_genome_denial_presents_as_gate() {
    // Before F-5, an undeclared tool was denied at `DenialStage::Genome`, distinguishable from an
    // out-of-scope `DenialStage::Gate` — a genome-enumeration oracle. Under production guards the
    // returned stage is uniform `Gate`, so the two are indistinguishable to the caller. (SAGA still
    // records the true genome reason — the audit is trusted.)
    let r = rig("secret_internal_tool", "/tmp/x", "ok");
    match r.orch.execute_hop(req(), Timestamp(1000)) {
        HopResult::Denied { stage, .. } => {
            assert_eq!(
                stage,
                DenialStage::Gate,
                "undeclared tool presents as Gate, not Genome"
            );
        }
        other => panic!("expected denial, got {other:?}"),
    }
    // The SAGA record still carries the genome-specific reason (trusted audit keeps the truth).
    let has_auth = r
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, AuditEvent::Authorization(_)));
    assert!(has_auth, "the genome refusal was recorded to SAGA");
}

// ---- F-7: rate limit -----------------------------------------------------------------

#[test]
fn fix_f7_rate_limit_enforced() {
    let r = rig_with(
        "write_file",
        "/tmp/x",
        "ok",
        Guards {
            rate_limit: Some(RateLimit {
                max: 5,
                window_ms: 60_000,
            }),
            replay_guard: false, // isolate the rate limiter (reuse one chain by design)
            monotonic_time: false,
            uniform_denial_stage: true,
        },
    );
    let mut denied = 0;
    for _ in 0..6 {
        if let HopResult::Denied { reason, .. } = r.orch.execute_hop(req(), Timestamp(1000)) {
            assert!(reason.contains("rate limit"), "{reason}");
            denied += 1;
        }
    }
    assert_eq!(r.tool.count(), 5);
    assert_eq!(denied, 1, "the 6th hop was rate-limited");
}

// ---- F-8: audit sanitization ---------------------------------------------------------

#[test]
fn fix_f8_control_chars_stripped() {
    let r = rig(
        "write_file",
        "/tmp/x\u{0}\u{1b}[31mred",
        "normal\u{0}hidden\u{1b}[31mred\u{7f}end",
    );
    assert!(matches!(
        r.orch.execute_hop(req(), Timestamp(1000)),
        HopResult::Executed { .. }
    ));
    let p = proposals(&r.events);
    assert_eq!(p.len(), 1);
    for field in [&p[0].output, &p[0].explanation] {
        assert!(!field.contains('\u{0}'), "NUL stripped: {field:?}");
        assert!(!field.contains('\u{1b}'), "ESC stripped: {field:?}");
        assert!(!field.contains('\u{7f}'), "DEL stripped: {field:?}");
        assert!(!field.contains("[31m"), "ANSI CSI dropped: {field:?}");
    }
    assert!(p[0].explanation.contains("normal") && p[0].explanation.contains("end"));
}

#[test]
fn fix_f8_unit_newline_and_tab_preserved() {
    // The sanitizer keeps \n and \t (legible structure) but drops NUL/ESC/DEL.
    let clean = sanitize_for_audit("a\nb\tc\u{0}d\u{1b}[0me\u{7f}f");
    assert_eq!(clean, "a\nb\tcdef");
}

// ---- F-9: monotonic time -------------------------------------------------------------

#[test]
fn fix_f9_backward_clock_rejected() {
    let r = rig_with(
        "write_file",
        "/tmp/x",
        "ok",
        Guards {
            monotonic_time: true,
            replay_guard: false,
            rate_limit: None,
            uniform_denial_stage: true,
        },
    );
    assert!(matches!(
        r.orch.execute_hop(req(), Timestamp(1000)),
        HopResult::Executed { .. }
    ));
    match r.orch.execute_hop(req(), Timestamp(500)) {
        HopResult::Error { detail } => assert!(detail.contains("non-monotonic"), "{detail}"),
        other => panic!("expected non-monotonic error, got {other:?}"),
    }
}

// ---- F-10: scope validation ----------------------------------------------------------

#[test]
fn fix_f10_undeclared_capability_reported() {
    let vocabulary = [cap("read"), cap("write"), cap("network")];
    let scope = IntentScope::new([cap("write"), cap("xyzzy_nonexistent")]);
    let undeclared = validate_scope(&scope, &vocabulary);
    assert_eq!(undeclared, vec![cap("xyzzy_nonexistent")]);

    // A clean scope reports nothing (no over-denial).
    let clean = IntentScope::new([cap("read"), cap("write")]);
    assert!(validate_scope(&clean, &vocabulary).is_empty());
}
