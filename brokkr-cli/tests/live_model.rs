//! Phase 12 — the full governed action cycle with a **real self-hosted model**.
//!
//! `#[ignore]` — **not hermetic**. Requires:
//! - ollama serving `llama3.2:3b` on `localhost:11434`
//! - the nginx mTLS gateway on `localhost:8443` forwarding to ollama
//! - the dev certs under `~/BROKKR/certs/`
//!
//! Run explicitly:
//! ```text
//! cargo test -p brokkr-cli --test live_model -- --ignored --nocapture
//! ```
//!
//! Real for everything now — **BIFRÖST** (wolfSSL mTLS 1.3 to the gateway; reads the negotiated
//! group; the model call passes through its transport, I-6), **MÍMIR** (ollama client), SINDRI,
//! SAGA, HEIMDALL, HÚÐ, and a filesystem tool. The model proposes; the deterministic spine
//! disposes; a real file lands on disk (or, if the model does not comply, a real Proposal is still
//! recorded and the gate denies — the fallback).
//!
//! The channel the current gateway negotiates is **classical** (nginx has no PQC), so the effective
//! authorization collapses to Public and the test sends a Public context — stated honestly.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use brokkr_audit::{AuditEvent, CryptoGeneration, ProposalRecord, Saga};
use brokkr_barrier::{Huth, InMemoryAcceptances, InMemoryCeiling};
use brokkr_bifrost::{Bifrost, GatewayConfig, MtlsTransport};
use brokkr_cli::{
    AuditSink, GenomeCheck, GenomeRefusal, HopRequest, HopResult, Orchestrator, Sentinel,
    SignalRouter,
};
use brokkr_core::barrier::Destination;
use brokkr_core::classification::Classification;
use brokkr_core::crypto::{Attestation, Digest, Hasher};
use brokkr_core::gate::{Action, AuthorizedAction};
use brokkr_core::genome::PrivilegeClass;
use brokkr_core::ids::{
    Dap, DatumRef, HopId, ModelEndpointId, Nonce, SelfSetVersion, SubjectId, Timestamp, ToolId,
};
use brokkr_core::intent::{
    Capability, IntentProvenanceChain, IntentScope, Invariant, InvariantSet, RootIntent,
};
use brokkr_core::reasoner::Context;
use brokkr_core::signal::Signal;
use brokkr_crypto::{DualKeyPair, Sha384Hasher};
use brokkr_gate::Sindri;
use brokkr_gate::resolver::{GenomeResolver, RegistryResolver, ResolvedInvariant, ResolvedTool};
use brokkr_intent::Skuld;
use brokkr_reasoner::{InMemoryRegistry, Mimir, OllamaBackend};
use brokkr_sentinel::{Detection, Heimdall, Observation, SelfSetCorpus};
use brokkr_tools::{ToolError, ToolExecutor, ToolOutcome};

const TOOL: &str = "write_file";
const CAP: &str = "write";
const ENDPOINT: &str = "mimir-gateway";
const TARGET_PATH: &str = "/tmp/brokkr-phase12-test.txt";
const FILE_CONTENT: &str = "hello world";

fn certs_dir() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/jerem".to_string());
    format!("{home}/BROKKR/certs")
}

fn gateway_config() -> GatewayConfig {
    let c = certs_dir();
    GatewayConfig {
        host: "127.0.0.1".to_string(),
        port: 8443,
        ca_file: format!("{c}/ca.crt"),
        client_cert_file: format!("{c}/client.crt"),
        client_key_file: format!("{c}/client.key"),
    }
}

// ---- test infrastructure (as in real_integration.rs) ---------------------------------

struct DeclaredGenome {
    tools: HashMap<ToolId, ResolvedTool>,
}
impl DeclaredGenome {
    fn new() -> Self {
        let mut tools = HashMap::new();
        tools.insert(
            ToolId::new(TOOL),
            ResolvedTool {
                required_capabilities: vec![Capability::new(CAP)],
                privilege: PrivilegeClass::Privileged,
            },
        );
        Self { tools }
    }
}
impl GenomeResolver for DeclaredGenome {
    fn resolve_tool(&self, tool: &ToolId) -> Option<ResolvedTool> {
        self.tools.get(tool).cloned()
    }
    fn resolve_invariant(&self, _invariant: &Invariant) -> Option<ResolvedInvariant> {
        None
    }
}
impl GenomeCheck for DeclaredGenome {
    fn check(&self, action: &Action, _chain: &IntentProvenanceChain) -> Result<(), GenomeRefusal> {
        if self.tools.contains_key(&action.tool) {
            Ok(())
        } else {
            Err(GenomeRefusal {
                detail: format!("tool {} not declared", action.tool.as_str()),
            })
        }
    }
}

struct FsWriteTool {
    id: ToolId,
}
impl ToolExecutor for FsWriteTool {
    fn tool_id(&self) -> &ToolId {
        &self.id
    }
    fn execute(&self, action: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        let path = action.action().detail.clone();
        std::fs::write(&path, FILE_CONTENT).map_err(|e| ToolError {
            detail: format!("write failed: {e}"),
        })?;
        Ok(ToolOutcome {
            output: format!("wrote {} bytes to {}", FILE_CONTENT.len(), path),
        })
    }
}

struct EmptyCorpus {
    obs: Vec<Observation>,
    version: SelfSetVersion,
    digest: Digest,
}
impl SelfSetCorpus for EmptyCorpus {
    fn version(&self) -> SelfSetVersion {
        self.version.clone()
    }
    fn observations(&self) -> &[Observation] {
        &self.obs
    }
    fn digest(&self) -> Digest {
        self.digest.clone()
    }
}

struct SagaSink {
    saga: Arc<Saga>,
}
impl AuditSink for SagaSink {
    fn record(&self, event: AuditEvent, dap: Dap, at: Timestamp) {
        self.saga.append(event, dap, at).expect("saga append");
    }
}

struct RecordingHeimdall {
    inner: Heimdall,
    seen: Arc<Mutex<Vec<Observation>>>,
}
impl Sentinel for RecordingHeimdall {
    fn observe(&self, observation: &Observation, now: Timestamp) -> Vec<Detection> {
        self.seen.lock().unwrap().push(observation.clone());
        self.inner.observe(observation, now)
    }
}

struct RecordingSignals {
    routed: Arc<Mutex<Vec<Signal>>>,
}
impl SignalRouter for RecordingSignals {
    fn route(&self, signal: &Signal) {
        self.routed.lock().unwrap().push(signal.clone());
    }
}

struct Cleanup(Vec<String>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

// ---- the live test -------------------------------------------------------------------

#[test]
#[ignore = "requires ollama + the nginx mTLS gateway + dev certs"]
fn full_cycle_with_a_real_model() {
    let _cleanup = Cleanup(vec![TARGET_PATH.to_string()]);
    let _ = std::fs::remove_file(TARGET_PATH);

    // --- real keys + a real signed Root Intent (scope: write) ---
    let principal_kp = DualKeyPair::generate().expect("principal keypair");
    let saga_kp = DualKeyPair::generate().expect("saga keypair");
    let heimdall_kp = DualKeyPair::generate().expect("heimdall keypair");
    let barrier_kp = DualKeyPair::generate().expect("barrier keypair");
    let (p_ml, p_slh) = principal_kp.public_key_bytes().expect("principal public");

    let principal = SubjectId::new("principal-1");
    let dap = Dap::new("Jeremy Rose", "jr");
    let now = Timestamp(1_000);
    let root: RootIntent = Skuld
        .sign_root(
            principal.clone(),
            dap.clone(),
            IntentScope::new([Capability::new(CAP)]),
            InvariantSet::new([]),
            Nonce(1),
            Timestamp(9_000_000),
            &principal_kp,
        )
        .expect("sign root");
    let chain = IntentProvenanceChain::new(root);
    let identity = Attestation {
        subject: principal.clone(),
        measurements: Sha384Hasher.hash(b"measurements"),
        freshness: Nonce(1),
        signatures: principal_kp.sign_dual(b"attestation").expect("att sig"),
    };

    // --- real SINDRI ---
    let registry = RegistryResolver::new().with_root(principal.clone(), p_ml, p_slh);
    let gate = Sindri::new(registry, DeclaredGenome::new());

    // --- real SAGA ---
    let saga = Arc::new(
        Saga::new(
            saga_kp,
            CryptoGeneration(1),
            Sha384Hasher.hash(b"brokkr-phase12-genesis"),
            None,
        )
        .expect("saga"),
    );

    // --- real HEIMDALL ---
    let (h_ml, h_slh) = heimdall_kp.public_key_bytes().expect("heimdall public");
    let heimdall = Heimdall::new(
        Box::new(EmptyCorpus {
            obs: Vec::new(),
            version: SelfSetVersion::new("v0"),
            digest: Sha384Hasher.hash(b""),
        }),
        (h_ml, h_slh),
        heimdall_kp,
        1.0,
        None,
        100,
    );
    let seen = Arc::new(Mutex::new(Vec::new()));

    // --- real HÚÐ for the ACTION crossing ---
    let (b_ml, b_slh) = barrier_kp.public_key_bytes().expect("barrier public");
    let action_barrier = Huth::new(
        (b_ml.clone(), b_slh.clone()),
        (b_ml.clone(), b_slh.clone()),
        InMemoryCeiling::new(),
        InMemoryAcceptances::new(),
    );

    // --- real BIFRÖST: mTLS transport + the clearance gate ---
    let cfg = gateway_config();
    let endpoint = ModelEndpointId::new(ENDPOINT);

    // Handshake once to learn the ACTUAL negotiated group (a real fact).
    let negotiated = MtlsTransport::new(cfg.clone())
        .negotiate()
        .expect("mTLS handshake to the gateway");
    println!(
        "negotiated group: raw={:?} -> NamedGroup={:?} -> strength={:?}",
        negotiated.raw_name,
        negotiated.group,
        negotiated.strength()
    );

    // BIFRÖST clears the outbound context (its own HÚÐ; endpoint ceiling Internal, collapsed to
    // Public by the classical channel — a Public context clears).
    let bifrost = Bifrost::new(
        (b_ml.clone(), b_slh.clone()),
        (b_ml.clone(), b_slh),
        InMemoryCeiling::new().with(endpoint.clone(), Classification::Internal),
        InMemoryAcceptances::new(),
    );

    // --- real MÍMIR: ollama backend, reached THROUGH BIFRÖST's transport (I-6) ---
    let reg = InMemoryRegistry::new([endpoint.clone()]);
    let backend = OllamaBackend::new(MtlsTransport::new(cfg.clone()), "llama3.2:3b", "localhost");
    let mimir = Mimir::new(
        endpoint.clone(),
        &reg,
        Box::new(backend),
        HopId::new("hop-1"),
    )
    .expect("registered endpoint");

    // --- wire the orchestrator: everything real ---
    let routed = Arc::new(Mutex::new(Vec::new()));
    let orch = Orchestrator::new(
        Box::new(bifrost),
        Box::new(mimir),
        Box::new(DeclaredGenome::new()),
        Box::new(gate),
        Box::new(action_barrier),
        Box::new(FsWriteTool {
            id: ToolId::new(TOOL),
        }),
        Box::new(RecordingHeimdall {
            inner: heimdall,
            seen: seen.clone(),
        }),
        Box::new(SagaSink { saga: saga.clone() }),
        Box::new(RecordingSignals {
            routed: routed.clone(),
        }),
        dap,
    );

    // --- run one governed hop with a coding request ---
    let payload = format!(
        "Write a file at {TARGET_PATH} containing '{FILE_CONTENT}'. \
Respond with only the two required lines."
    );
    let req = HopRequest {
        identity,
        chain,
        context: Context {
            payload,
            datum: DatumRef::new("ctx-1"),
            classification: Classification::Public, // clears the classical channel
            personal: None,
            bcr: None,
        },
        dest: Destination::Reasoner {
            endpoint: endpoint.clone(),
            negotiated: negotiated.group,
        },
    };
    let result = orch.execute_hop(req, now);
    println!("hop result: {result:?}");

    // --- the model's actual proposal must be recorded in SAGA (this always holds) ---
    let records = saga.records();
    let proposal = records.iter().find_map(|r| match &r.event {
        AuditEvent::Proposal(p) => Some(p.clone()),
        _ => None,
    });
    let proposal: ProposalRecord = proposal.expect("MÍMIR's proposal was recorded in SAGA");
    println!(
        "model proposed: output={:?}\nmodel rationale (raw response):\n{}",
        proposal.output, proposal.explanation
    );
    assert!(
        !proposal.explanation.is_empty(),
        "the recorded proposal carries the model's actual response text"
    );

    // --- the governance outcome ---
    match result {
        HopResult::Executed { .. } => {
            // The model complied: SINDRI granted, the tool wrote the file.
            let written = std::fs::read_to_string(TARGET_PATH).expect("file on disk");
            assert_eq!(written, FILE_CONTENT);
            // Real HEIMDALL received the reconciliation observation.
            let obs = seen.lock().unwrap();
            assert!(
                obs.iter().any(|o| matches!(
                    o,
                    Observation::Hop {
                        executed: Some(_),
                        ..
                    }
                )),
                "HEIMDALL received the executed reconciliation observation"
            );
            println!("EXECUTED: file written by the governed cycle from a real model proposal.");
        }
        HopResult::Denied { stage, reason } => {
            // The model did not produce a gate-passable proposal. BIFRÖST + MÍMIR still worked —
            // the proposal is recorded above; the deterministic spine denied it (the fallback).
            println!("DENIED at {stage:?}: {reason} — BIFRÖST+MÍMIR proven; the spine held.");
        }
        HopResult::Error { detail } => panic!("subsystem error: {detail}"),
    }
}
