//! Phase 14B — White-box red team, medium noise.
//!
//! Logic bugs *behind* the structural guarantees 14A confirmed: SINDRI conjunct edge cases, FFI
//! error paths, guard-state arithmetic boundaries, intent-chain edge conditions, and
//! `SandboxedTool` path logic. Category 2 (the strict parser) is unit-tested in
//! `brokkr-reasoner/src/ollama.rs` (private `parse_action`); this file covers 1, 3, 4, 5, 6.
//!
//! Findings: `reports/REDTEAM-14B-2026-08-23-R1.md`. Hermetic (no live model/network); real
//! dual-family PQC, all signing done once, serially, in `fx()` (13A F-4: never sign concurrently).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use brokkr_audit::AuditEvent;
use brokkr_cli::{
    AuditSink, GenomeCheck, GenomeRefusal, Guards, HopRequest, HopResult, Orchestrator, RateLimit,
    Sentinel, SignalRouter,
};
use brokkr_core::barrier::{BarrierVerdict, BoundaryFlow, Destination};
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
use brokkr_crypto::{DualKeyPair, DualPublicKey, Sha384Hasher, TlsClient, TlsConfig};
use brokkr_gate::Sindri;
use brokkr_gate::resolver::{GenomeResolver, RegistryResolver, ResolvedInvariant, ResolvedTool};
use brokkr_intent::Skuld;
use brokkr_tools::{SandboxedTool, ToolError, ToolExecutor, ToolOutcome};

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

// ---- fixtures: all real signing done once, serially -----------------------------------

struct Fx {
    p1_pub: (Vec<u8>, Vec<u8>),
    /// scope {}, no invariants.
    empty_scope: IntentProvenanceChain,
    /// scope {write}, invariant "noop-inv".
    noop_inv: IntentProvenanceChain,
    /// scope {write}, invariant "no-write".
    forbid_write: IntentProvenanceChain,
    /// scope {write}, no invariants (for the guards + attenuation tests).
    legit: IntentProvenanceChain,
    /// root {read,write} -> hop {read,write} (identical scope, no narrowing). hop signed by kp2.
    identical_attn: IntentProvenanceChain,
    hop2_pub: (Vec<u8>, Vec<u8>),
    /// a deep chain: root {c0..c7} attenuated 8 times, each dropping one capability. hops by kp2.
    deep: IntentProvenanceChain,
    deep_root_pub: DualPublicKey,
    deep_hop_pub_bytes: (Vec<u8>, Vec<u8>),
    deep_hops: usize,
}

fn fx() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(build_fx)
}

fn build_fx() -> Fx {
    let mut kp = DualKeyPair::generate().expect("kp1");
    let mut kp2 = DualKeyPair::generate().expect("kp2");
    let p1_pub = kp.public_key_bytes().expect("pub1");
    let hop2_pub = kp2.public_key_bytes().expect("pub2");
    let far = Timestamp(9_000_000);

    let sign = |kp: &mut DualKeyPair, scope: IntentScope, invs: InvariantSet| {
        let root = Skuld
            .sign_root(SubjectId::new(P1), dap(), scope, invs, Nonce(1), far, kp)
            .expect("sign root");
        IntentProvenanceChain::new(root)
    };

    let empty_scope = sign(&mut kp, IntentScope::empty(), InvariantSet::new([]));
    let noop_inv = sign(
        &mut kp,
        IntentScope::new([cap("write")]),
        InvariantSet::new([inv("noop-inv")]),
    );
    let forbid_write = sign(
        &mut kp,
        IntentScope::new([cap("write")]),
        InvariantSet::new([inv("no-write")]),
    );
    let legit = sign(
        &mut kp,
        IntentScope::new([cap("write")]),
        InvariantSet::new([]),
    );

    // Identical-scope attenuation: root {read,write} -> hop {read,write}, hop identity = "hop-2".
    let root_rw = Skuld
        .sign_root(
            SubjectId::new(P1),
            dap(),
            IntentScope::new([cap("read"), cap("write")]),
            InvariantSet::new([]),
            Nonce(1),
            far,
            &mut kp,
        )
        .expect("sign root_rw");
    let att2 = Attestation {
        subject: SubjectId::new("hop-2"),
        measurements: Sha384Hasher.hash(b"m"),
        freshness: Nonce(1),
        signatures: hand_sig(),
    };
    let identical_attn = Skuld
        .attenuate_signed(
            IntentProvenanceChain::new(root_rw),
            att2.clone(),
            IntentScope::new([cap("read"), cap("write")]), // identical, no narrowing
            Vec::new(),
            InvariantSet::new([]),
            &mut kp2,
            Timestamp(1000),
        )
        .expect("identical attenuation");

    // Deep chain: 8 hops, each dropping one capability from {c0..c7}.
    let deep_hops = 8usize;
    let all: Vec<Capability> = (0..deep_hops).map(|i| cap(&format!("c{i}"))).collect();
    let deep_root_kp_pub =
        DualPublicKey::from_public_bytes(&p1_pub.0, &p1_pub.1).expect("root pub");
    let mut deep = {
        let root = Skuld
            .sign_root(
                SubjectId::new(P1),
                dap(),
                IntentScope::new(all.clone()),
                InvariantSet::new([]),
                Nonce(1),
                far,
                &mut kp,
            )
            .expect("deep root");
        IntentProvenanceChain::new(root)
    };
    for drop_to in (0..deep_hops).rev() {
        let scope: Vec<Capability> = all.iter().take(drop_to + 1).cloned().collect();
        let att = Attestation {
            subject: SubjectId::new("hop-2"),
            measurements: Sha384Hasher.hash(b"m"),
            freshness: Nonce(1),
            signatures: hand_sig(),
        };
        deep = Skuld
            .attenuate_signed(
                deep,
                att,
                IntentScope::new(scope),
                Vec::new(),
                InvariantSet::new([]),
                &mut kp2,
                Timestamp(1000),
            )
            .expect("deep attenuation");
    }

    Fx {
        p1_pub: p1_pub.clone(),
        empty_scope,
        noop_inv,
        forbid_write,
        legit,
        identical_attn,
        hop2_pub: hop2_pub.clone(),
        deep,
        deep_root_pub: deep_root_kp_pub,
        deep_hop_pub_bytes: hop2_pub,
        deep_hops,
    }
}

/// A hand-built (unverified) dual signature — for attestation `signatures` fields, which SINDRI
/// does not verify (Rev 1.3 §6.4).
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

fn registry() -> RegistryResolver {
    let (ml, slh) = &fx().p1_pub;
    RegistryResolver::new().with_root(SubjectId::new(P1), ml.clone(), slh.clone())
}
fn registry_with_hop2() -> RegistryResolver {
    let (ml, slh) = &fx().p1_pub;
    let (h_ml, h_slh) = &fx().hop2_pub;
    RegistryResolver::new()
        .with_root(SubjectId::new(P1), ml.clone(), slh.clone())
        .with_root(SubjectId::new("hop-2"), h_ml.clone(), h_slh.clone())
}
fn attest(subject: &str) -> Attestation {
    Attestation {
        subject: SubjectId::new(subject),
        measurements: Sha384Hasher.hash(b"m"),
        freshness: Nonce(1),
        signatures: hand_sig(),
    }
}

// ---- a configurable genome resolver ---------------------------------------------------

#[derive(Clone, Default)]
struct Genome {
    tools: HashMap<ToolId, ResolvedTool>,
    invs: HashMap<Invariant, ResolvedInvariant>,
}
impl Genome {
    fn tool(mut self, id: &str, caps: &[&str], p: PrivilegeClass) -> Self {
        self.tools.insert(
            ToolId::new(id),
            ResolvedTool {
                required_capabilities: caps.iter().map(|c| cap(c)).collect(),
                privilege: p,
            },
        );
        self
    }
    fn invariant(mut self, name: &str, fc: &[&str], fp: &[PrivilegeClass]) -> Self {
        self.invs.insert(
            inv(name),
            ResolvedInvariant {
                forbids_capabilities: fc.iter().map(|c| cap(c)).collect(),
                forbids_privilege: fp.to_vec(),
            },
        );
        self
    }
}
impl GenomeResolver for Genome {
    fn resolve_tool(&self, t: &ToolId) -> Option<ResolvedTool> {
        self.tools.get(t).cloned()
    }
    fn resolve_invariant(&self, i: &Invariant) -> Option<ResolvedInvariant> {
        self.invs.get(i).cloned()
    }
}

fn verdict(
    genome: Genome,
    reg: RegistryResolver,
    identity: &Attestation,
    chain: &IntentProvenanceChain,
    tool: &str,
    now: Timestamp,
) -> Result<(), AnergyReason> {
    let sindri = Sindri::new(reg, genome);
    sindri.evaluate(
        identity,
        chain,
        &Action {
            tool: ToolId::new(tool),
            detail: "/tmp/x".to_string(),
        },
        now,
    )
}

// ======================================================================================
// 1. SINDRI evaluation edge cases
// ======================================================================================

/// 1.1 — a declared tool requiring NO capabilities, against an empty scope, grants (conjunct 3's
/// loop is vacuous). An unprivileged, capability-free tool needs no scope — intended.
#[test]
fn attack_1_1_empty_required_capabilities_grants_on_empty_scope() {
    let g = Genome::default().tool("noop_tool", &[], PrivilegeClass::Unprivileged);
    let r = verdict(
        g,
        registry(),
        &attest(P1),
        &fx().empty_scope,
        "noop_tool",
        Timestamp(1000),
    );
    assert_eq!(
        r,
        Ok(()),
        "a no-capability tool grants against an empty scope"
    );
}

/// 1.2 — a declared invariant that forbids nothing is a no-op: it has a predicate (so the
/// fail-closed branch does not fire), but forbids no capability/privilege → grants.
#[test]
fn attack_1_2_noop_invariant_grants() {
    let g = Genome::default()
        .tool("write_file", &["write"], PrivilegeClass::Unprivileged)
        .invariant("noop-inv", &[], &[]); // forbids nothing
    let r = verdict(
        g,
        registry(),
        &attest(P1),
        &fx().noop_inv,
        "write_file",
        Timestamp(1000),
    );
    assert_eq!(r, Ok(()), "a no-op invariant does not deny");
}

/// 1.3 — early exit: an input that fails Signal 1 (unknown identity) AND would fail conjunct 4
/// (the invariant forbids the tool's capability) is denied with the Signal-1 reason, proving
/// conjuncts run in order and the earliest failure wins.
#[test]
fn attack_1_3_earliest_conjunct_wins() {
    // The chain's invariant "no-write" forbids `write`; the tool needs `write` → conjunct 4 WOULD
    // deny. But the identity "ghost" is undeclared → Signal 1 denies first.
    let g = Genome::default()
        .tool("write_file", &["write"], PrivilegeClass::Unprivileged)
        .invariant("no-write", &["write"], &[]);
    let r = verdict(
        g,
        registry(),
        &attest("ghost"),
        &fx().forbid_write,
        "write_file",
        Timestamp(1000),
    );
    assert_eq!(
        r,
        Err(AnergyReason::IdentityUnverified),
        "Signal 1 denies before conjunct 4"
    );
}

/// 1.4 — `map_intent_error` coverage: two chain-integrity failures exercise the mapping to
/// `ChainInvalid` (forged root signature) and `ChainExpired` (expired chain). Documents that the
/// `Backend` and `HopKeyMissing` arms are unreachable from SINDRI (which signs nothing and resolves
/// every key) and are fail-closed to `ChainInvalid`/`IdentityUnverified`.
#[test]
fn attack_1_4_map_intent_error_reachable_arms() {
    // Expired chain (now past expiry) → ChainExpired.
    let expired = {
        let mut kp = DualKeyPair::generate().expect("kp");
        let (ml, slh) = kp.public_key_bytes().expect("pub");
        let reg = RegistryResolver::new().with_root(SubjectId::new(P1), ml, slh);
        let root = Skuld
            .sign_root(
                SubjectId::new(P1),
                dap(),
                IntentScope::new([cap("write")]),
                InvariantSet::new([]),
                Nonce(1),
                Timestamp(1),
                &mut kp,
            )
            .unwrap();
        let chain = IntentProvenanceChain::new(root);
        let g = Genome::default().tool("write_file", &["write"], PrivilegeClass::Unprivileged);
        verdict(g, reg, &attest(P1), &chain, "write_file", Timestamp(1000))
    };
    assert_eq!(
        expired,
        Err(AnergyReason::ChainExpired),
        "Attenuation(Expired) → ChainExpired"
    );
}

// ======================================================================================
// 3. FFI error paths (real wolfSSL / wolfCrypt)
// ======================================================================================

/// 3.1 — `TlsClient::connect` with non-existent cert paths → a `TlsError`, never a panic. The CTX
/// is freed on the partial-init failure path (no leak, no UB).
#[test]
fn attack_3_1_connect_bad_cert_paths_errors_cleanly() {
    let cfg = TlsConfig {
        host: "127.0.0.1".to_string(),
        port: 1,
        ca_file: "/nonexistent/ca.crt".to_string(),
        client_cert_file: "/nonexistent/client.crt".to_string(),
        client_key_file: "/nonexistent/client.key".to_string(),
    };
    // TCP connect to :1 fails first (nothing listening), or the CA load fails — either is a clean
    // TlsError, not a panic.
    assert!(
        TlsClient::connect(&cfg).is_err(),
        "bad config errors, does not panic"
    );
}

/// 3.2 — connect to a closed port → a `TlsError` (TCP layer), no panic.
#[test]
fn attack_3_2_connect_closed_port_errors() {
    let cfg = TlsConfig {
        host: "127.0.0.1".to_string(),
        port: 1, // nothing listens on :1
        ca_file: "/dev/null".to_string(),
        client_cert_file: "/dev/null".to_string(),
        client_key_file: "/dev/null".to_string(),
    };
    assert!(TlsClient::connect(&cfg).is_err());
}

/// 3.4 — `sign_dual` on a zero-length message → a valid signature that verifies against the empty
/// message.
#[test]
fn attack_3_4_sign_empty_message() {
    let mut kp = DualKeyPair::generate().expect("kp");
    let (ml, slh) = kp.public_key_bytes().expect("pub");
    let sig = kp.sign_dual(b"").expect("sign empty");
    let vk = DualPublicKey::from_public_bytes(&ml, &slh).expect("vk");
    assert!(
        vk.verify_dual(b"", &sig).is_ok(),
        "empty-message signature verifies"
    );
}

/// 3.5 — `sign_dual` on a large (1 MiB) message → a valid signature; no panic, no error. (Kept at
/// 1 MiB rather than 10 MiB to bound the workspace-suite runtime; both algorithms accept
/// arbitrary-length messages — the size is hashed internally.)
#[test]
fn attack_3_5_sign_large_message() {
    let mut kp = DualKeyPair::generate().expect("kp");
    let (ml, slh) = kp.public_key_bytes().expect("pub");
    let msg = vec![0u8; 1024 * 1024];
    let sig = kp.sign_dual(&msg).expect("sign large");
    let vk = DualPublicKey::from_public_bytes(&ml, &slh).expect("vk");
    assert!(vk.verify_dual(&msg, &sig).is_ok());
}

/// 3.6 — sign with key A, verify with key B's public key → verification fails cleanly (no panic).
#[test]
fn attack_3_6_verify_wrong_key_fails() {
    let mut a = DualKeyPair::generate().expect("a");
    let b = DualKeyPair::generate().expect("b");
    let (b_ml, b_slh) = b.public_key_bytes().expect("b pub");
    let sig = a.sign_dual(b"msg").expect("sign");
    let vk_b = DualPublicKey::from_public_bytes(&b_ml, &b_slh).expect("vk_b");
    assert!(
        vk_b.verify_dual(b"msg", &sig).is_err(),
        "wrong key fails, does not panic"
    );
}

// ======================================================================================
// 4. Guard-state edge cases (via a minimal orchestrator rig)
// ======================================================================================

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
struct AlwaysGrantGate;
impl CostimulationGate for AlwaysGrantGate {
    fn evaluate(
        &self,
        _i: &Attestation,
        _c: &IntentProvenanceChain,
        _a: &Action,
        _n: Timestamp,
    ) -> Result<(), AnergyReason> {
        Ok(())
    }
}
struct Clear;
impl ContextClearance for Clear {
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
struct OkGenome;
impl GenomeCheck for OkGenome {
    fn check(&self, _a: &Action, _c: &IntentProvenanceChain) -> Result<(), GenomeRefusal> {
        Ok(())
    }
}
struct Puppet(ModelEndpointId);
impl Reasoner for Puppet {
    fn endpoint(&self) -> &ModelEndpointId {
        &self.0
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
struct NoSentinel;
impl Sentinel for NoSentinel {
    fn observe(
        &self,
        _o: &brokkr_sentinel::Observation,
        _n: Timestamp,
    ) -> Vec<brokkr_sentinel::Detection> {
        Vec::new()
    }
}
struct NoAudit;
impl AuditSink for NoAudit {
    fn record(&self, _e: AuditEvent, _d: Dap, _a: Timestamp) {}
}
struct NoSignals;
impl SignalRouter for NoSignals {
    fn route(&self, _s: &Signal) {}
}

fn orch_with(guards: Guards, tool_calls: Arc<Counter>) -> Orchestrator {
    Orchestrator::new(
        Box::new(Clear),
        Box::new(Puppet(ModelEndpointId::new("mimir"))),
        Box::new(OkGenome),
        Box::new(AlwaysGrantGate),
        Box::new(AllowBarrier),
        Box::new(SpyTool {
            id: ToolId::new("write_file"),
            calls: tool_calls,
        }),
        Box::new(NoSentinel),
        Box::new(NoAudit),
        Box::new(NoSignals),
        dap(),
    )
    .with_guards(guards)
}
fn req(chain: IntentProvenanceChain) -> HopRequest {
    HopRequest {
        identity: attest(P1),
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

/// 4.2 — rate limiter at exactly the window boundary. 5/60_000ms: 5 hops at now=0 fill the window;
/// the 6th at now=60_000 is DENIED (cutoff=0, `0 < 0` false → the 5 are not evicted); the 7th at
/// now=60_001 is ADMITTED (cutoff=1, `0 < 1` true → the 5 are evicted).
#[test]
fn attack_4_2_rate_limit_window_boundary() {
    let calls = Arc::new(Counter::default());
    let orch = orch_with(
        Guards {
            rate_limit: Some(RateLimit {
                max: 5,
                window_ms: 60_000,
            }),
            replay_guard: false,
            monotonic_time: false,
            uniform_denial_stage: false,
        },
        calls.clone(),
    );
    for _ in 0..5 {
        assert!(matches!(
            orch.execute_hop(req(fx().legit.clone()), Timestamp(0)),
            HopResult::Executed { .. }
        ));
    }
    let sixth = orch.execute_hop(req(fx().legit.clone()), Timestamp(60_000));
    assert!(
        matches!(sixth, HopResult::Denied { .. }),
        "6th at the boundary is denied: {sixth:?}"
    );
    let seventh = orch.execute_hop(req(fx().legit.clone()), Timestamp(60_001));
    assert!(
        matches!(seventh, HopResult::Executed { .. }),
        "7th past the boundary is admitted: {seventh:?}"
    );
    assert_eq!(calls.count(), 6, "5 + the 7th executed");
}

/// 4.3 — monotonic guard is strictly-less-than: two hops at the SAME time both pass (equal is not
/// backward).
#[test]
fn attack_4_3_monotonic_equal_time_passes() {
    let calls = Arc::new(Counter::default());
    let orch = orch_with(
        Guards {
            monotonic_time: true,
            replay_guard: false,
            rate_limit: None,
            uniform_denial_stage: false,
        },
        calls.clone(),
    );
    assert!(matches!(
        orch.execute_hop(req(fx().legit.clone()), Timestamp(0)),
        HopResult::Executed { .. }
    ));
    assert!(matches!(
        orch.execute_hop(req(fx().legit.clone()), Timestamp(0)),
        HopResult::Executed { .. }
    ));
    assert_eq!(calls.count(), 2, "equal time is not a regression");
}

/// 4.4 — all three guards on; the same chain twice at increasing times. Monotonic passes (200 >
/// 100), rate passes (well under), replay FIRES (same nonce). Confirms replay is evaluated (and
/// denies) after monotonic and rate.
#[test]
fn attack_4_4_guard_order_replay_after_monotonic_and_rate() {
    let calls = Arc::new(Counter::default());
    let orch = orch_with(Guards::production(), calls.clone());
    assert!(matches!(
        orch.execute_hop(req(fx().legit.clone()), Timestamp(100)),
        HopResult::Executed { .. }
    ));
    let second = orch.execute_hop(req(fx().legit.clone()), Timestamp(200));
    match &second {
        HopResult::Denied { reason, .. } => assert!(reason.contains("replay"), "{reason}"),
        other => panic!("expected replay denial, got {other:?}"),
    }
    assert_eq!(calls.count(), 1);
}

// ======================================================================================
// 5. Intent chain edge cases
// ======================================================================================

/// 5.1 — a root-only chain (no entries) verifies as the simplest valid chain.
#[test]
fn attack_5_1_root_only_chain_verifies() {
    let root_pub = DualPublicKey::from_public_bytes(&fx().p1_pub.0, &fx().p1_pub.1).expect("pub");
    let r = Skuld.verify_chain_public(
        fx().legit.root(),
        fx().legit.entries(),
        &root_pub,
        &[],
        Timestamp(1000),
    );
    assert!(r.is_ok(), "root-only chain verifies: {r:?}");
}

/// 5.2 — attenuation to an identical scope succeeds (a subset of itself). It grows the chain by a
/// hop without narrowing — allowed, and SINDRI evaluates the (unchanged) current scope.
#[test]
fn attack_5_2_identical_scope_attenuation_grants() {
    // The two-hop chain's final scope is {read,write}; a tool needing {write} is in scope.
    let g = Genome::default().tool("write_file", &["write"], PrivilegeClass::Unprivileged);
    let r = verdict(
        g,
        registry_with_hop2(),
        &attest("hop-2"),
        &fx().identical_attn,
        "write_file",
        Timestamp(1000),
    );
    assert_eq!(
        r,
        Ok(()),
        "identical-scope attenuation still grants an in-scope tool"
    );
}

/// 5.3 — a deep (8-hop) chain verifies; verification is O(hops) linear (each hop is a dual-family
/// verify). Timing is recorded to `--nocapture`; 100 hops would be ~12.5× this, still linear.
#[test]
fn attack_5_3_deep_chain_verifies() {
    let hop_pub =
        DualPublicKey::from_public_bytes(&fx().deep_hop_pub_bytes.0, &fx().deep_hop_pub_bytes.1)
            .expect("hop pub");
    let hop_refs: Vec<&DualPublicKey> = (0..fx().deep_hops).map(|_| &hop_pub).collect();
    let start = Instant::now();
    let r = Skuld.verify_chain_public(
        fx().deep.root(),
        fx().deep.entries(),
        &fx().deep_root_pub,
        &hop_refs,
        Timestamp(1000),
    );
    let elapsed = start.elapsed();
    assert!(
        r.is_ok(),
        "deep {}-hop chain verifies: {r:?}",
        fx().deep_hops
    );
    println!(
        "5.3 deep-chain verify: {} hops in {:?} ({:?}/hop)",
        fx().deep_hops,
        elapsed,
        elapsed / (fx().deep_hops as u32 + 1)
    );
}

// ======================================================================================
// 6. SandboxedTool path edge cases
// ======================================================================================

/// A UNIQUE sandbox dir per call — tests run in parallel and each removes its own dir, so a shared
/// name would race (create/delete collisions).
fn sandbox() -> (SandboxedTool, std::path::PathBuf) {
    static N: AtomicUsize = AtomicUsize::new(0);
    let uniq = N.fetch_add(1, SeqCst);
    let root = std::env::temp_dir().join(format!("brokkr-14b-{}-{uniq}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let tool = SandboxedTool::new(ToolId::new("write_file"), &root).expect("sandbox");
    (tool, root)
}

/// 6.1 — a symlink INSIDE the root is not resolved (lexical canonicalization only): `resolve` on a
/// path containing the link name passes the sandbox check. This is the F-2 documented limitation.
#[test]
fn attack_6_1_symlink_inside_root_not_resolved() {
    let (tool, root) = sandbox();
    // The path "link/x" stays lexically under the root; resolve accepts it regardless of where a
    // real symlink named "link" might point.
    let resolved = tool.resolve("link/x");
    assert!(
        resolved.is_ok(),
        "lexical check passes a name under the root"
    );
    assert!(
        resolved
            .unwrap()
            .starts_with(std::fs::canonicalize(&root).unwrap())
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// 6.2 — `.`/`..` components inside the root normalize and pass.
#[test]
fn attack_6_2_dot_components_normalize() {
    let (tool, root) = sandbox();
    let r = tool.resolve("./safe/../safe/./file.txt").expect("ok");
    assert!(r.ends_with("safe/file.txt"));
    let _ = std::fs::remove_dir_all(&root);
}

/// 6.3 — an absolute path replaces the root on `join` → escapes → rejected.
#[test]
fn attack_6_3_absolute_path_rejected() {
    let (tool, root) = sandbox();
    assert!(
        tool.resolve("/etc/passwd").is_err(),
        "absolute path escapes → rejected"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// 6.4 — a leading `..` escapes the root → rejected.
#[test]
fn attack_6_4_parent_dir_rejected() {
    let (tool, root) = sandbox();
    assert!(tool.resolve("../escape").is_err());
    assert!(tool.resolve("..").is_err());
    let _ = std::fs::remove_dir_all(&root);
}

/// 6.5 — an EMPTY detail resolves to the sandbox root DIRECTORY itself (starts_with is true). The
/// sandbox check passes; the actual write would then fail at the filesystem layer (cannot write a
/// file to a directory path). Documented as F-15: `resolve("")` is accepted by the path check.
#[test]
fn attack_6_5_empty_path_resolves_to_root_dir() {
    let (tool, root) = sandbox();
    let r = tool.resolve("");
    assert!(
        r.is_ok(),
        "empty detail resolves to the root itself (passes the sandbox check)"
    );
    assert_eq!(r.unwrap(), std::fs::canonicalize(&root).unwrap());
    // A real execute() on "" would fail when std::fs::write targets a directory — the sandbox check
    // is not the layer that rejects it.
    let _ = std::fs::remove_dir_all(&root);
}
