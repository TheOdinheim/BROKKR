//! Phase 15-FIX — regression test for **F-22 / F-26** (uniform denial reason under production
//! guards). Fails without the fix (a genome refusal and a SINDRI denial return different reasons).
//!
//! The **F-29** regression (fresh nonces are never evicted; a full ledger rejects the flood) is the
//! updated `redteam_15c.rs::g2_2_4_nonce_flood_no_longer_opens_a_replay_window`, which fails without
//! the fix because the "nonce ledger full" path does not exist pre-fix. It is not duplicated here
//! (it drives `MAX_NONCE_ENTRIES` hops and is co-located with the attack it neutralizes).
//! Hermetic; real dual-family PQC signed once serially.

use std::sync::OnceLock;

use brokkr_audit::AuditEvent;
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

struct Fx {
    p1_pub: (Vec<u8>, Vec<u8>),
    write_scope: IntentProvenanceChain,
    read_scope: IntentProvenanceChain,
}
fn fx() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| {
        let mut kp = DualKeyPair::generate().expect("kp");
        let p1_pub = kp.public_key_bytes().expect("pub");
        let mut sign = |scope: IntentScope| {
            let root: RootIntent = Skuld
                .sign_root(
                    SubjectId::new(P1),
                    dap(),
                    scope,
                    InvariantSet::new([]),
                    Nonce(1),
                    Timestamp(9_000_000),
                    &mut kp,
                )
                .expect("sign");
            IntentProvenanceChain::new(root)
        };
        Fx {
            p1_pub: p1_pub.clone(),
            write_scope: sign(IntentScope::new([cap("write")])),
            read_scope: sign(IntentScope::new([cap("read")])),
        }
    })
}
fn registry() -> RegistryResolver {
    let (ml, slh) = &fx().p1_pub;
    RegistryResolver::new().with_root(SubjectId::new(P1), ml.clone(), slh.clone())
}
fn attest(chain: &IntentProvenanceChain) -> Attestation {
    Attestation {
        subject: SubjectId::new(P1),
        measurements: Sha384Hasher.hash(b"m"),
        freshness: Nonce(1),
        signatures: chain.root().signature.clone(),
    }
}

#[derive(Clone)]
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
                detail: format!("tool {} not declared", a.tool.as_str()),
            })
        }
    }
}

struct Puppet {
    endpoint: ModelEndpointId,
    tool: String,
}
impl Reasoner for Puppet {
    fn endpoint(&self) -> &ModelEndpointId {
        &self.endpoint
    }
    fn propose(&self, _c: &ClearedContext, _s: &IntentScope) -> Result<Proposal, ReasonerError> {
        Ok(Proposal {
            action: Action {
                tool: ToolId::new(&self.tool),
                detail: "/tmp/x".to_string(),
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
struct NoOpTool;
impl ToolExecutor for NoOpTool {
    fn tool_id(&self) -> &ToolId {
        static ID: OnceLock<ToolId> = OnceLock::new();
        ID.get_or_init(|| ToolId::new("write_file"))
    }
    fn execute(&self, _a: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        Ok(ToolOutcome {
            output: String::new(),
        })
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

fn orchestrator(proposed_tool: &str) -> Orchestrator {
    let gate: Box<dyn CostimulationGate> = Box::new(Sindri::new(registry(), Genome));
    Orchestrator::new(
        Box::new(ClearAll),
        Box::new(Puppet {
            endpoint: ModelEndpointId::new("mimir"),
            tool: proposed_tool.to_string(),
        }),
        Box::new(Genome),
        gate,
        Box::new(AllowBarrier),
        Box::new(NoOpTool),
        Box::new(DiscardSentinel),
        Box::new(DiscardAudit),
        Box::new(NoSignals),
        dap(),
    )
    .with_guards(Guards::production())
}
fn req(chain: &IntentProvenanceChain) -> HopRequest {
    HopRequest {
        identity: attest(chain),
        chain: chain.clone(),
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

/// F-22 / F-26: under production guards a genome refusal (undeclared tool) and a SINDRI denial
/// (declared tool, out of scope) return the **identical** `(stage, reason)` pair, so neither the
/// stage nor the reason distinguishes a declared tool from an undeclared one. Fails without the fix
/// (the reasons were "tool X not declared" vs "architectural anergy: OutOfScope").
#[test]
fn fix_f22_uniform_reason_string_under_production() {
    // Undeclared tool → genome refusal (write_scope chain so only the tool name is at fault).
    let genome_denial =
        orchestrator("secret_tool").execute_hop(req(&fx().write_scope), Timestamp(1000));
    // Declared tool, out of scope → SINDRI OutOfScope ({read} chain, write_file requires {write}).
    let sindri_denial =
        orchestrator("write_file").execute_hop(req(&fx().read_scope), Timestamp(1000));

    let g = match genome_denial {
        HopResult::Denied { stage, reason } => (stage, reason),
        other => panic!("expected a genome denial: {other:?}"),
    };
    let s = match sindri_denial {
        HopResult::Denied { stage, reason } => (stage, reason),
        other => panic!("expected a SINDRI denial: {other:?}"),
    };
    assert_eq!(g.0, DenialStage::Gate);
    assert_eq!(s.0, DenialStage::Gate);
    assert_eq!(
        g, s,
        "genome and SINDRI denials are indistinguishable under production (F-22)"
    );
    assert_eq!(g.1, "action denied", "the uniform reason");
}
