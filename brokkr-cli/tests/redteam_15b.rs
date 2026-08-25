//! Phase 15B — Grey-hat red team, medium noise. Same two threat models as 15A (G1 architecture-
//! informed outsider; G2 insider with tool-layer access), now armed with 15A intelligence (the
//! F-22 reason-string oracle, F-25 all-four-conjuncts, the orchestrator TCB, the lexical sandbox).
//!
//! The attacker mounts targeted, inference-based attacks: quantify the F-22 oracle into a full
//! genome map, infer the invariant set from denial patterns, and run a multi-step
//! enumerate → exploit → audit campaign.
//!
//! Findings continue from **F-26**. Document, don't fix. Hermetic; real dual-family PQC signed once
//! serially in `fx()`. Full analysis: `reports/REDTEAM-15B-2026-08-24-R1.md`.

use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};

use brokkr_audit::{AuditEvent, AuthorizationOutcome};
use brokkr_cli::{
    AuditSink, DenialStage, GenomeCheck, GenomeRefusal, Guards, HopRequest, HopResult,
    Orchestrator, Sentinel, SignalRouter,
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
use brokkr_tools::{ToolError, ToolExecutor, ToolOutcome};

const P1: &str = "principal-1";

fn dap() -> Dap {
    Dap::new("Jeremy Rose", "jr")
}
fn cap(s: &str) -> Capability {
    Capability::new(s)
}
fn inv(s: &str) -> Invariant {
    Invariant::new(s)
}

struct Fx {
    p1_pub: (Vec<u8>, Vec<u8>),
    /// scope {write}, no invariants — grants a declared write-tool.
    write_scope: IntentProvenanceChain,
    /// scope {read}, no invariants — a declared write-tool becomes OutOfScope (the classifier chain).
    read_scope: IntentProvenanceChain,
    /// scope {write, network}, invariant {no-network} — for invariant inference.
    net_scope: IntentProvenanceChain,
    /// scope {write}, expiry 500 — past at now > 500.
    expired: IntentProvenanceChain,
}
fn fx() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| {
        let mut kp = DualKeyPair::generate().expect("kp");
        let p1_pub = kp.public_key_bytes().expect("pub");
        let mut sign = |scope: IntentScope, invs: InvariantSet, expiry: u64| {
            let root: RootIntent = Skuld
                .sign_root(
                    SubjectId::new(P1),
                    dap(),
                    scope,
                    invs,
                    Nonce(1),
                    Timestamp(expiry),
                    &mut kp,
                )
                .expect("sign");
            IntentProvenanceChain::new(root)
        };
        Fx {
            p1_pub: p1_pub.clone(),
            write_scope: sign(
                IntentScope::new([cap("write")]),
                InvariantSet::new([]),
                9_000_000,
            ),
            read_scope: sign(
                IntentScope::new([cap("read")]),
                InvariantSet::new([]),
                9_000_000,
            ),
            net_scope: sign(
                IntentScope::new([cap("write"), cap("network")]),
                InvariantSet::new([inv("no-network")]),
                9_000_000,
            ),
            expired: sign(IntentScope::new([cap("write")]), InvariantSet::new([]), 500),
        }
    })
}
fn registry() -> RegistryResolver {
    let (ml, slh) = &fx().p1_pub;
    RegistryResolver::new().with_root(SubjectId::new(P1), ml.clone(), slh.clone())
}
fn attest_for(subject: &str, chain: &IntentProvenanceChain) -> Attestation {
    Attestation {
        subject: SubjectId::new(subject),
        measurements: Sha384Hasher.hash(b"m"),
        freshness: Nonce(1),
        signatures: chain.root().signature.clone(),
    }
}

// ---- doubles --------------------------------------------------------------------------

/// A genome declaring a set of `(tool, required_capability)` pairs and a set of
/// `(invariant, forbidden_capability)` predicates. Backs both the orchestrator's `GenomeCheck` port
/// and SINDRI's `GenomeResolver` (which enforces conjuncts 3/4 — F-25).
#[derive(Clone)]
struct Genome {
    tools: &'static [(&'static str, &'static str)],
    forbids: &'static [(&'static str, &'static str)],
}
impl GenomeResolver for Genome {
    fn resolve_tool(&self, t: &ToolId) -> Option<ResolvedTool> {
        self.tools
            .iter()
            .find(|(name, _)| *name == t.as_str())
            .map(|(_, reqcap)| ResolvedTool {
                required_capabilities: vec![cap(reqcap)],
                privilege: PrivilegeClass::Unprivileged,
            })
    }
    fn resolve_invariant(&self, i: &Invariant) -> Option<ResolvedInvariant> {
        self.forbids
            .iter()
            .find(|(name, _)| Invariant::new(*name) == *i)
            .map(|(_, forb)| ResolvedInvariant {
                forbids_capabilities: vec![cap(forb)],
                forbids_privilege: Vec::new(),
            })
    }
}
impl GenomeCheck for Genome {
    fn check(&self, a: &Action, _c: &IntentProvenanceChain) -> Result<(), GenomeRefusal> {
        if self.tools.iter().any(|(name, _)| *name == a.tool.as_str()) {
            Ok(())
        } else {
            Err(GenomeRefusal {
                detail: format!("tool {} not declared", a.tool.as_str()),
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

/// A tool that returns a caller-chosen output — used to demonstrate the output covert channel.
struct EchoTool {
    id: ToolId,
    output: String,
    calls: Arc<Counter>,
}
impl ToolExecutor for EchoTool {
    fn tool_id(&self) -> &ToolId {
        &self.id
    }
    fn execute(&self, a: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        self.calls.hit();
        // A malicious tool can encode anything it can see (here: the action detail) into its output.
        Ok(ToolOutcome {
            output: format!("{}{}", self.output, a.action().detail),
        })
    }
}

/// A fixed proposal for the puppet to emit (15B never exercises the backend-failure path — 15A did).
struct Mode {
    tool: String,
    detail: String,
}
struct Puppet {
    endpoint: ModelEndpointId,
    mode: Mode,
}
impl Reasoner for Puppet {
    fn endpoint(&self) -> &ModelEndpointId {
        &self.endpoint
    }
    fn propose(&self, _c: &ClearedContext, _s: &IntentScope) -> Result<Proposal, ReasonerError> {
        Ok(Proposal {
            action: Action {
                tool: ToolId::new(&self.mode.tool),
                detail: self.mode.detail.clone(),
            },
            rationale: "ok".to_string(),
            hop: HopId::new("h"),
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
    tool_calls: Arc<Counter>,
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

#[allow(clippy::too_many_arguments)]
fn build(genome: Genome, tool_output: &str, mode: Mode, guards: Guards) -> Rig {
    let tool_calls = Arc::new(Counter::default());
    let events = Arc::new(Mutex::new(Vec::new()));
    let gate: Box<dyn CostimulationGate> = Box::new(Sindri::new(registry(), genome.clone()));
    let orch = Orchestrator::new(
        Box::new(ClearAll),
        Box::new(Puppet {
            endpoint: ModelEndpointId::new("mimir"),
            mode,
        }),
        Box::new(genome),
        gate,
        Box::new(AllowBarrier),
        Box::new(EchoTool {
            id: ToolId::new("tool"),
            output: tool_output.to_string(),
            calls: tool_calls.clone(),
        }),
        Box::new(DiscardSentinel),
        Box::new(SpyAudit {
            events: events.clone(),
        }),
        Box::new(NoSignals),
        dap(),
    )
    .with_guards(guards);
    Rig {
        orch,
        tool_calls,
        events,
    }
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
fn req(chain: IntentProvenanceChain, identity: Attestation) -> HopRequest {
    HopRequest {
        identity,
        chain,
        context: ctx(),
        dest: Destination::Reasoner {
            endpoint: ModelEndpointId::new("mimir"),
            negotiated: NamedGroup::Secp384r1,
        },
    }
}
fn propose(tool: &str, detail: &str) -> Mode {
    Mode {
        tool: tool.to_string(),
        detail: detail.to_string(),
    }
}
/// Run one hop and return its `HopResult`.
fn run(
    genome: Genome,
    mode: Mode,
    chain: &IntentProvenanceChain,
    id: &str,
    guards: Guards,
) -> HopResult {
    build(genome, "", mode, guards)
        .orch
        .execute_hop(req(chain.clone(), attest_for(id, chain)), Timestamp(1000))
}
/// The denial reason string, or a marker for non-denials.
fn reason_of(r: &HopResult) -> String {
    match r {
        HopResult::Denied { reason, .. } => reason.clone(),
        HopResult::Executed { .. } => "<executed>".to_string(),
        HopResult::Error { detail } => format!("<error:{detail}>"),
    }
}

// The genome the enumeration tests probe against: five declared write-tools.
const DECLARED: &[(&str, &str)] = &[
    ("read_file", "write"),
    ("write_file", "write"),
    ("list_dir", "write"),
    ("stat_file", "write"),
    ("move_file", "write"),
];
const UNDECLARED: &[&str] = &["exec", "admin", "delete_everything", "sudo", "backdoor"];

// ======================================================================================
// 1. G1 — architecture-informed outsider: inference attacks
// ======================================================================================

/// 1.2 — infer the invariant set from denial patterns. A chain with scope {write, network} and an
/// invariant `no-network`: a tool requiring `network` is denied `InvariantViolated`, while a tool
/// requiring `write` grants. The attacker infers *some* invariant forbids `network` — but the
/// denial reason does **not** name the invariant (`no-network` never appears).
#[test]
fn g1_1_2_invariant_inference_precision() {
    let genome = Genome {
        tools: &[("net_tool", "network"), ("write_file", "write")],
        forbids: &[("no-network", "network")],
    };
    let net = run(
        genome.clone(),
        propose("net_tool", "/tmp/x"),
        &fx().net_scope,
        P1,
        Guards::permissive(),
    );
    let reason = reason_of(&net);
    assert!(
        reason.contains("InvariantViolated"),
        "network tool denied by an invariant: {reason}"
    );
    assert!(
        !reason.contains("no-network"),
        "the invariant NAME is not leaked — the attacker infers 'something forbids network', \
         not which invariant: {reason}"
    );
    // A write tool under the same chain grants — so the block is specific to the network capability.
    let w = run(
        genome,
        propose("write_file", "/tmp/x"),
        &fx().net_scope,
        P1,
        Guards::permissive(),
    );
    assert!(
        matches!(w, HopResult::Executed { .. }),
        "write tool grants: {w:?}"
    );
}

/// 1.4 — the replay nonce comes from the DAP-signed Root Intent, not the model. The model (Puppet)
/// cannot influence chain construction: the chain is built before `propose` is called and passed in
/// by the caller. Under production guards, a replay is denied regardless of what the model proposes.
#[test]
fn g1_1_4_nonce_is_dap_controlled_not_model() {
    let genome = Genome {
        tools: &[("write_file", "write")],
        forbids: &[],
    };
    let rig = build(
        genome,
        "",
        propose("write_file", "/tmp/x"),
        Guards::production(),
    );
    let first = rig.orch.execute_hop(
        req(fx().write_scope.clone(), attest_for(P1, &fx().write_scope)),
        Timestamp(1000),
    );
    let second = rig.orch.execute_hop(
        req(fx().write_scope.clone(), attest_for(P1, &fx().write_scope)),
        Timestamp(1001),
    );
    assert!(matches!(first, HopResult::Executed { .. }));
    match second {
        HopResult::Denied { reason, .. } => assert!(reason.contains("replay"), "{reason}"),
        other => panic!("the replay is denied; the model cannot reuse the DAP's nonce: {other:?}"),
    }
}

// ======================================================================================
// 2. G2 — insider: targeted exploitation of the F-22 oracle
// ======================================================================================

/// 2.1 — **F-22, hardened in 15-FIX.** Under PRODUCTION guards the denial reason is now uniform:
/// an undeclared tool (genome refusal) and a declared-but-out-of-scope one (SINDRI) return the
/// **same** `(stage, reason)` pair, so the reason string no longer distinguishes them.
#[test]
fn g2_2_1_reason_string_is_uniform_under_production_guards() {
    let genome = Genome {
        tools: &[("write_file", "write")],
        forbids: &[],
    };
    // Undeclared tool → genome refusal.
    let undeclared = run(
        genome.clone(),
        propose("secret_tool", "/tmp/x"),
        &fx().read_scope,
        P1,
        Guards::production(),
    );
    // Declared but out of scope ({read} chain, write tool) → SINDRI OutOfScope.
    let declared_oos = run(
        genome,
        propose("write_file", "/tmp/x"),
        &fx().read_scope,
        P1,
        Guards::production(),
    );
    // Both are the uniform Gate stage (F-5 held on the stage).
    assert!(matches!(
        undeclared,
        HopResult::Denied {
            stage: DenialStage::Gate,
            ..
        }
    ));
    assert!(matches!(
        declared_oos,
        HopResult::Denied {
            stage: DenialStage::Gate,
            ..
        }
    ));
    // 15-FIX: the reasons are now identical — the oracle is closed on the reason channel too.
    let (ur, dr) = (reason_of(&undeclared), reason_of(&declared_oos));
    assert_eq!(ur, dr, "reasons are uniform under production (F-22 fixed)");
    assert_eq!(ur, "action denied", "the uniform reason: {ur}");
}

/// 2.2 — **F-26, hardened in 15-FIX.** The genome-enumeration oracle is now closed under production
/// guards: every probe — declared or undeclared — yields the identical uniform reason, so the reason
/// string carries **no** classifying information. Enumeration by reason fails.
#[test]
fn g2_2_2_genome_no_longer_enumerable_via_reason_strings() {
    let genome = Genome {
        tools: DECLARED,
        forbids: &[],
    };
    let reason_for = |name: &str| -> String {
        reason_of(&run(
            genome.clone(),
            propose(name, "/tmp/x"),
            &fx().read_scope,
            P1,
            Guards::production(),
        ))
    };
    // Every reason — for a declared tool AND an undeclared one — is the single uniform string, so a
    // reason-string classifier has nothing to separate them on.
    let mut all = Vec::new();
    for (name, _) in DECLARED {
        all.push(reason_for(name));
    }
    for name in UNDECLARED {
        all.push(reason_for(name));
    }
    assert!(
        all.iter().all(|r| r == "action denied"),
        "every probe returns the uniform reason — the genome is no longer enumerable: {all:?}"
    );
}

/// 2.3 — the full denial-reason signature table, **under permissive guards**. Each evaluation path
/// yields a distinct reason there. Note (15-FIX F-22): under *production* guards these gate denials
/// collapse to the single uniform "action denied" — so this fine-grained table is now a
/// permissive-only (misconfiguration) observation, not a production one.
#[test]
fn g2_2_3_denial_reason_signature_table_permissive_only() {
    let genome = Genome {
        tools: &[("net_tool", "network"), ("write_file", "write")],
        forbids: &[("no-network", "network")],
    };
    // Genome refusal.
    let genome_refusal = reason_of(&run(
        genome.clone(),
        propose("undeclared", "/tmp/x"),
        &fx().write_scope,
        P1,
        Guards::permissive(),
    ));
    // Signal 1 — unknown identity.
    let signal1 = reason_of(&run(
        genome.clone(),
        propose("write_file", "/tmp/x"),
        &fx().write_scope,
        "ghost",
        Guards::permissive(),
    ));
    // Conjunct 3 — out of scope ({read} chain, write tool).
    let conj3 = reason_of(&run(
        genome.clone(),
        propose("write_file", "/tmp/x"),
        &fx().read_scope,
        P1,
        Guards::permissive(),
    ));
    // Conjunct 4 — invariant violated (network tool under the no-network chain).
    let conj4 = reason_of(&run(
        genome.clone(),
        propose("net_tool", "/tmp/x"),
        &fx().net_scope,
        P1,
        Guards::permissive(),
    ));
    // Signal 2 — expired chain.
    let expired = reason_of(&run(
        genome,
        propose("write_file", "/tmp/x"),
        &fx().expired,
        P1,
        Guards::permissive(),
    ));

    assert!(genome_refusal.contains("not declared"));
    assert!(signal1.contains("IdentityUnverified"));
    assert!(conj3.contains("OutOfScope"));
    assert!(conj4.contains("InvariantViolated"));
    assert!(expired.contains("ChainExpired"));
    // All five are pairwise distinct — the reason string alone names the failing stage.
    let sigs = [&genome_refusal, &signal1, &conj3, &conj4, &expired];
    for i in 0..sigs.len() {
        for j in (i + 1)..sigs.len() {
            assert_ne!(sigs[i], sigs[j], "reasons {i} and {j} must be distinct");
        }
    }
}

/// 2.6 — **F-27.** `ToolOutcome.output` is unvalidated. A malicious tool encodes data it can see
/// into its output, which flows to the caller via `HopResult::Executed { output }`. The spine does
/// not inspect or constrain tool outputs.
#[test]
fn g2_2_6_tool_output_is_an_unvalidated_covert_channel() {
    let genome = Genome {
        tools: &[("write_file", "write")],
        forbids: &[],
    };
    let secret = "SECRET-EXFIL-";
    let rig = build(
        genome,
        secret,
        propose("write_file", "/etc/hosts"),
        Guards::permissive(),
    );
    let out = rig.orch.execute_hop(
        req(fx().write_scope.clone(), attest_for(P1, &fx().write_scope)),
        Timestamp(1000),
    );
    match out {
        HopResult::Executed { output } => {
            // The tool smuggled its marker AND the action detail out through the unvalidated output.
            assert!(
                output.contains(secret),
                "tool output carries arbitrary data: {output}"
            );
            assert!(
                output.contains("/etc/hosts"),
                "and the action detail: {output}"
            );
        }
        other => panic!("expected execution: {other:?}"),
    }
    assert_eq!(rig.tool_calls.count(), 1);
}

// ======================================================================================
// 3. Combined: multi-step grey-hat campaign
// ======================================================================================

/// 3.1 — enumerate → exploit → audit. (1) Use the F-22 oracle to identify a declared tool.
/// (2) Submit a proposal for it under a matching-scope chain → it executes. (3) The audit trail
/// records the proposal AND the granted authorization — the attacker succeeds but cannot hide, and
/// cannot read or modify SAGA from the `HopResult`.
#[test]
fn combined_3_1_enumerate_exploit_audit_intact() {
    let genome = Genome {
        tools: DECLARED,
        forbids: &[],
    };
    // (1) Enumerate. 15-FIX: under PRODUCTION guards the reason oracle is CLOSED — write_file and
    // backdoor both return the uniform "action denied", so recon by reason fails.
    let reason_prod = |name: &str| {
        reason_of(&run(
            genome.clone(),
            propose(name, "/tmp/x"),
            &fx().read_scope,
            P1,
            Guards::production(),
        ))
    };
    assert_eq!(
        reason_prod("write_file"),
        reason_prod("backdoor"),
        "enumeration by reason is closed under production (F-22/F-26 fixed)"
    );
    // The residual survives only under a PERMISSIVE (misconfigured) deployment, where the reason
    // still distinguishes declared (OutOfScope) from undeclared (not declared).
    let is_declared_permissive = |name: &str| {
        reason_of(&run(
            genome.clone(),
            propose(name, "/tmp/x"),
            &fx().read_scope,
            P1,
            Guards::permissive(),
        ))
        .contains("OutOfScope")
    };
    assert!(is_declared_permissive("write_file"));
    assert!(!is_declared_permissive("backdoor"));

    // (2) Exploit: a matching-scope chain grants the declared tool.
    let rig = build(
        genome,
        "",
        propose("write_file", "/tmp/x"),
        Guards::production(),
    );
    let out = rig.orch.execute_hop(
        req(fx().write_scope.clone(), attest_for(P1, &fx().write_scope)),
        Timestamp(1000),
    );
    assert!(
        matches!(out, HopResult::Executed { .. }),
        "the declared tool executes: {out:?}"
    );

    // (3) Audit intact: SAGA recorded the proposal AND the granted authorization. The attacker has
    // no path from HopResult to read or alter these — success is fully attributable.
    let events = rig.events.lock().unwrap_or_else(|p| p.into_inner());
    assert!(
        events.iter().any(|e| matches!(e, AuditEvent::Proposal(_))),
        "the proposal is recorded"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            AuditEvent::Authorization(a) if matches!(a.outcome, AuthorizationOutcome::Granted)
        )),
        "the granted authorization is recorded — the attacker cannot hide the successful action"
    );
}
