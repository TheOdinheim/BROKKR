//! Phase 11.5 — real subsystem integration.
//!
//! One tool (a filesystem write) runs through the full governed action cycle with **real**
//! subsystems for everything except BIFRÖST and MÍMIR:
//!
//! - **SINDRI** — the real `Sindri` gate, verifying a real dual-family PQC Root-Intent signature
//!   (ML-DSA-65 + SLH-DSA-SHAKE-192s via wolfSSL) through the `RegistryResolver` and a declared
//!   genome, and enforcing all four OQGF-M-11 conjuncts.
//! - **SAGA** — the real `Saga` audit spine, dual-signing every record it appends.
//! - **HEIMDALL** — the real `Heimdall`, running its observe loop over the reconciliation feed.
//! - **HÚÐ** — the real `Huth` barrier, allowing the Public local-filesystem crossing.
//! - **the tool** — a real filesystem tool that writes an actual file to disk.
//! - **SKULD** — a real Root Intent, signed with real keys.
//!
//! BIFRÖST (`ContextClearance`) and MÍMIR (`Reasoner`) stay as **controlled doubles**: there is no
//! model endpoint, so BIFRÖST clears unconditionally and MÍMIR returns one fixed proposal — "write
//! to this temp file". Everything downstream of the proposal is real.
//!
//! What this proves: the governance spine composes with production-grade components — real PQC
//! signatures flow through SINDRI, real dual-signed audit records land in SAGA, a real file is
//! written — not just with test doubles.
//!
//! The test-file types below (a declared genome, a filesystem tool, an empty Self-Set corpus, and
//! three thin adapters) are **test infrastructure**, not production code: no committed filesystem
//! tool or `SelfSetCorpus` exists yet, and the orchestrator's ports need adapters over the concrete
//! `Saga`/`Heimdall`. No subsystem source is changed and no new crate is added.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use brokkr_audit::{AuditEvent, AuthorizationOutcome, CryptoGeneration, Saga};
use brokkr_barrier::{Huth, InMemoryAcceptances, InMemoryCeiling};
use brokkr_cli::{
    AuditSink, GenomeCheck, GenomeRefusal, HopRequest, HopResult, Orchestrator, Sentinel,
    SignalRouter,
};
use brokkr_core::barrier::{BarrierVerdict, Destination};
use brokkr_core::classification::{Classification, NamedGroup};
use brokkr_core::crypto::{Attestation, Digest, Hasher};
use brokkr_core::gate::Action;
use brokkr_core::gate::AuthorizedAction;
use brokkr_core::genome::PrivilegeClass;
use brokkr_core::ids::SelfSetVersion;
use brokkr_core::ids::{Dap, HopId, ModelEndpointId, Nonce, SubjectId, Timestamp, ToolId};
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
use brokkr_sentinel::{Detection, Heimdall, Observation, SelfSetCorpus};
use brokkr_tools::{ToolError, ToolExecutor, ToolOutcome};

const TOOL: &str = "write_file";
const CAP: &str = "write";
const CONTENT: &str = "hello from BROKKR";

// ---- test infrastructure: a declared genome (backs SINDRI's resolver AND the step-4 port) ----

/// Real declared genome data: a `write_file` tool requiring the `write` capability. Backs both
/// SINDRI's `GenomeResolver` (conjuncts 3/4) and the orchestrator's `GenomeCheck` port (step 4),
/// so the two agree on what is declared. Fail-closed: an undeclared tool resolves to `None` / is
/// refused.
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
        None // no invariants declared in this test's Root Intent
    }
}
impl GenomeCheck for DeclaredGenome {
    fn check(&self, action: &Action, _chain: &IntentProvenanceChain) -> Result<(), GenomeRefusal> {
        if self.tools.contains_key(&action.tool) {
            Ok(())
        } else {
            Err(GenomeRefusal {
                detail: format!("tool {} not declared in the genome", action.tool.as_str()),
            })
        }
    }
}

// ---- test infrastructure: a real filesystem tool ------------------------------------

/// A tool that writes a fixed string to the path named in the authorized action's `detail`. It
/// receives an already-minted `AuthorizedAction` (I-1) and does the work; it re-authorizes nothing.
struct FsWriteTool {
    id: ToolId,
}
impl ToolExecutor for FsWriteTool {
    fn tool_id(&self) -> &ToolId {
        &self.id
    }
    fn execute(&self, action: &AuthorizedAction) -> Result<ToolOutcome, ToolError> {
        let path = action.action().detail.clone();
        std::fs::write(&path, CONTENT).map_err(|e| ToolError {
            detail: format!("write failed: {e}"),
        })?;
        Ok(ToolOutcome {
            output: format!("wrote {} bytes to {}", CONTENT.len(), path),
        })
    }
}

// ---- test infrastructure: trivial Self-Set corpus (not exercised — no detectors, no screen) ----

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

// ---- adapters fitting the real subsystems to the orchestrator's ports ----------------

/// SAGA → `AuditSink`. Wraps the real `Saga`; `record` appends (dual-signing the record). The port
/// is infallible, so a signing failure surfaces as a test panic (SAGA's contract is durability).
struct SagaSink {
    saga: Arc<Saga>,
}
impl AuditSink for SagaSink {
    fn record(&self, event: AuditEvent, dap: Dap, at: Timestamp) {
        self.saga.append(event, dap, at).expect("saga append");
    }
}

/// Real `Heimdall` → `Sentinel`, tapping the observation feed. The committed `HeimdallSentinel`
/// delegates without exposing what was fed; this wrapper records the input **and runs the real
/// `Heimdall::observe`**, so the assertion sees the feed while the real subsystem does the work.
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

/// Signal sink (EIR/KVASIR stand-in). No detectors are registered, so nothing routes here; it
/// exists to complete the wiring and to record anything that would.
struct RecordingSignals {
    routed: Arc<Mutex<Vec<Signal>>>,
}
impl SignalRouter for RecordingSignals {
    fn route(&self, signal: &Signal) {
        self.routed.lock().unwrap().push(signal.clone());
    }
}

// ---- controlled doubles: BIFRÖST clears unconditionally; MÍMIR returns one fixed proposal ----

struct ClearAll;
impl ContextClearance for ClearAll {
    fn evaluate_context(
        &self,
        _ctx: &Context,
        _dest: &Destination,
        _now: Timestamp,
    ) -> BarrierVerdict {
        BarrierVerdict::Allow // the provided `clear` mints the ClearedContext
    }
}

struct FixedProposer {
    endpoint: ModelEndpointId,
    action: Action,
}
impl Reasoner for FixedProposer {
    fn endpoint(&self) -> &ModelEndpointId {
        &self.endpoint
    }
    fn propose(
        &self,
        _ctx: &ClearedContext,
        _scope: &IntentScope,
    ) -> Result<Proposal, ReasonerError> {
        Ok(Proposal {
            action: self.action.clone(),
            rationale: "write the greeting to the temp file".to_string(),
            hop: HopId::new("hop-1"),
        })
    }
}

// ---- temp-file cleanup guard ---------------------------------------------------------

struct TempFile(String);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ---- the test ------------------------------------------------------------------------

#[test]
fn real_governed_hop_writes_a_file_with_real_pqc() {
    // A unique temp path; removed on drop (even if the test panics).
    let path = std::env::temp_dir().join(format!("brokkr-test-{}.txt", std::process::id()));
    let path_str = path.to_string_lossy().to_string();
    let _cleanup = TempFile(path_str.clone());
    let _ = std::fs::remove_file(&path); // start clean

    // --- real PQC keys ---
    let mut principal_kp = DualKeyPair::generate().expect("principal keypair");
    let saga_kp = DualKeyPair::generate().expect("saga keypair");
    let heimdall_kp = DualKeyPair::generate().expect("heimdall keypair");
    let barrier_kp = DualKeyPair::generate().expect("barrier keypair");
    let (p_ml, p_slh) = principal_kp
        .public_key_bytes()
        .expect("principal public bytes");

    // --- a real, signed Root Intent (SKULD) ---
    let principal = SubjectId::new("principal-1");
    let dap = Dap::new("Jeremy Rose", "jr");
    let scope = IntentScope::new([Capability::new(CAP)]); // includes the tool's required capability
    let now = Timestamp(1_000);
    let root: RootIntent = Skuld
        .sign_root(
            principal.clone(),
            dap.clone(),
            scope,
            InvariantSet::new([]), // no invariants → conjunct 4 has nothing to check
            Nonce(1),
            Timestamp(9_000_000), // expiry well after `now`
            &mut principal_kp,
        )
        .expect("sign root intent");
    let chain = IntentProvenanceChain::new(root);

    // The hop identity — subject == principal (root-only chain binds Signal 1 to root.principal).
    // The attestation's own signature field is not verified by SINDRI (Rev 1.3 §6.4), but must be
    // a real DualSignature to construct; sign over a fixed tag.
    let identity = Attestation {
        subject: principal.clone(),
        measurements: Sha384Hasher.hash(b"measurements"),
        freshness: Nonce(1),
        signatures: principal_kp
            .sign_dual(b"attestation")
            .expect("attestation sig"),
    };

    // --- real SINDRI: registry declares the principal's public key; declared genome for conjuncts ---
    let registry = RegistryResolver::new().with_root(principal.clone(), p_ml, p_slh);
    let gate = Sindri::new(registry, DeclaredGenome::new());

    // --- real SAGA (dual-signing) ---
    let genesis = Sha384Hasher.hash(b"brokkr-11.5-genesis");
    let saga =
        Arc::new(Saga::new(saga_kp, CryptoGeneration(1), genesis, None).expect("construct saga"));

    // --- real HEIMDALL (no detectors; observe loop runs) ---
    let (h_ml, h_slh) = heimdall_kp
        .public_key_bytes()
        .expect("heimdall public bytes");
    let corpus = EmptyCorpus {
        obs: Vec::new(),
        version: SelfSetVersion::new("v0"),
        digest: Sha384Hasher.hash(b""),
    };
    let heimdall = Heimdall::new(
        Box::new(corpus),
        (h_ml, h_slh), // dap_public (PublicBytes tuple)
        heimdall_kp,
        1.0,  // host-harm bound
        None, // blast radius
        100,  // sustained threshold
    );
    let seen = Arc::new(Mutex::new(Vec::new()));

    // --- real HÚÐ (allows the Public local-filesystem crossing) ---
    let (b_ml, b_slh) = barrier_kp.public_key_bytes().expect("barrier public bytes");
    let barrier = Huth::new(
        (b_ml.clone(), b_slh.clone()), // bcr key (not exercised on the Public allow path)
        (b_ml, b_slh),                 // dap key
        InMemoryCeiling::new(),
        InMemoryAcceptances::new(),
    );

    // --- the proposal MÍMIR will return: write to the temp file ---
    let proposal_action = Action {
        tool: ToolId::new(TOOL),
        detail: path_str.clone(),
    };

    // --- wire the orchestrator: real everything except BIFRÖST + MÍMIR ---
    let routed = Arc::new(Mutex::new(Vec::new()));
    let orch = Orchestrator::new(
        Box::new(ClearAll),
        Box::new(FixedProposer {
            endpoint: ModelEndpointId::new("mimir-local"),
            action: proposal_action,
        }),
        Box::new(DeclaredGenome::new()),
        Box::new(gate),
        Box::new(barrier),
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

    // --- run one real governed hop ---
    let req = HopRequest {
        identity,
        chain,
        context: Context {
            payload: "the task context".to_string(),
            datum: brokkr_core::ids::DatumRef::new("ctx-1"),
            classification: Classification::Public,
            personal: None,
            bcr: None,
        },
        dest: Destination::Reasoner {
            endpoint: ModelEndpointId::new("mimir-local"),
            negotiated: NamedGroup::Secp384r1MlKem1024,
        },
    };
    let result = orch.execute_hop(req, now);

    // --- assert: the action executed ---
    match &result {
        HopResult::Executed { output } => {
            assert!(output.contains(&path_str), "output names the written path");
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // --- assert: a real file exists on disk with the expected content ---
    let written = std::fs::read_to_string(&path).expect("the tool wrote the file");
    assert_eq!(written, CONTENT, "file content matches");

    // --- assert: SAGA recorded a real Proposal and a Granted Authorization ---
    let records = saga.records();
    assert!(
        records
            .iter()
            .any(|r| matches!(r.event, AuditEvent::Proposal(_))),
        "SAGA recorded the proposal"
    );
    let granted = records.iter().any(|r| {
        matches!(
            &r.event,
            AuditEvent::Authorization(rec) if rec.outcome == AuthorizationOutcome::Granted
        )
    });
    assert!(
        granted,
        "SAGA recorded a Granted authorization from real SINDRI"
    );
    // Each recorded SAGA record carries at least one real dual-family generation signature.
    for r in &records {
        assert!(!r.signatures.is_empty(), "record {} is dual-signed", r.seq);
    }

    // --- assert: real HEIMDALL received the reconciliation observation with the executed action ---
    let observations = seen.lock().unwrap();
    assert!(
        observations.iter().any(|o| matches!(
            o,
            Observation::Hop {
                executed: Some(_),
                ..
            }
        )),
        "HEIMDALL received Observation::Hop with the executed action"
    );
}
