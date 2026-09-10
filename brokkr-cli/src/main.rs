//! `brokkr` — the binary entry point (Phase 11, the executor, wired **last**).
//!
//! A real CLI over the governed action cycle: it parses arguments, constructs the orchestrator
//! from **production subsystems** (BIFRÖST mTLS, MÍMIR/ollama, SINDRI, REGIN, HÚÐ, HEIMDALL, SAGA,
//! a sandboxed filesystem tool), mints a fresh signed Root Intent per task, and drives one governed
//! hop per task through [`brokkr_cli::Orchestrator::execute_hop`]. The composition mirrors the
//! `tests/live_model.rs` template; this file is the production wiring of the same shape.
//!
//! **Independent termination (P-12.5).** The [`brokkr_cli::KillSwitch`] is obtained and honored: a
//! set switch denies the next hop before any gate. It is exposed here via the `kill` REPL command.
//! A true SIGINT (ctrl-c) handler is **not** wired: the `ctrlc` crate is not available offline (an
//! `--locked` build would fail on a new dependency) and raw signal handling requires `unsafe`, which
//! `brokkr-cli` forbids (CLAUDE.md §6). The KillSwitch mechanism itself — checked before every gate,
//! unreachable by the model — is fully wired; only the SIGINT *delivery* is a `kill` command instead.
//!
//! Scope (this build): one governed hop per task; no multi-turn conversation, no config file, no
//! daemon, no sub-agent spawning.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]

use std::io::{BufRead, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use brokkr_audit::{AuditEvent, AuthorizationOutcome, CryptoGeneration, Saga};
use brokkr_barrier::{Huth, InMemoryAcceptances, InMemoryCeiling};
use brokkr_bifrost::{Bifrost, GatewayConfig, MtlsTransport};
use brokkr_cli::{
    AuditSink, GenomeCheck, GenomeRefusal, Guards, HopRequest, HopResult, Orchestrator, Sentinel,
    SignalRouter,
};
use brokkr_core::barrier::Destination;
use brokkr_core::capability::{
    CapabilityEnvelope, CapabilityProperty, ConformanceTier, EgressManifest, EgressProtocol,
    EgressRule, EvidenceProvenance,
};
use brokkr_core::classification::Classification;
use brokkr_core::crypto::{Attestation, Digest, DualSignature, Hasher, Signature, SignatureAlg};
use brokkr_core::gate::Action;
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
use brokkr_tools::SandboxedTool;

const DEFAULT_MODEL: &str = "llama3.1:8b";
const DEFAULT_ENDPOINT: &str = "localhost:8443";
const DEFAULT_CA: &str = "certs/ca.crt";
const DEFAULT_CERT: &str = "certs/client.crt";
const DEFAULT_KEY: &str = "certs/client.key";
const DEFAULT_ROOT_DIR: &str = ".";
const DEFAULT_SCOPE: &str = "read,write";
const TOOL: &str = "write_file";
const CAP_WRITE: &str = "write";
const ENDPOINT_ID: &str = "mimir-gateway";
const EXPIRY_MS: u64 = 5 * 60 * 1000; // 5 minutes

// ======================================================================================
// Configuration (parsed from std::env::args — no external arg-parsing crate)
// ======================================================================================

struct Config {
    model: String,
    endpoint: String,
    ca: String,
    cert: String,
    key: String,
    root_dir: String,
    scope: Vec<String>,
    task: Option<String>,
}

fn usage() -> &'static str {
    "brokkr [OPTIONS] [TASK]\n\
     \n\
     Options:\n\
     \x20 --model <name>       Model name for ollama (default: llama3.1:8b)\n\
     \x20 --endpoint <host>    mTLS endpoint host:port (default: localhost:8443)\n\
     \x20 --ca <path>          CA cert path (default: certs/ca.crt)\n\
     \x20 --cert <path>        Client cert path (default: certs/client.crt)\n\
     \x20 --key <path>         Client key path (default: certs/client.key)\n\
     \x20 --root-dir <path>    Sandbox root for file operations (default: .)\n\
     \x20 --scope <caps>       Comma-separated capabilities (default: read,write)\n\
     \x20 --help               Print usage\n\
     \n\
     If TASK is provided, run it as a single governed hop and exit.\n\
     If no TASK, enter interactive mode (type `exit`, `quit`, or EOF to leave; `kill` to\n\
     activate independent termination).\n"
}

/// Parse arguments. `Err(String)` carries a message to print (usage on `--help`, or an error).
fn parse_args<I: Iterator<Item = String>>(args: I) -> Result<Config, String> {
    let mut cfg = Config {
        model: DEFAULT_MODEL.to_string(),
        endpoint: DEFAULT_ENDPOINT.to_string(),
        ca: DEFAULT_CA.to_string(),
        cert: DEFAULT_CERT.to_string(),
        key: DEFAULT_KEY.to_string(),
        root_dir: DEFAULT_ROOT_DIR.to_string(),
        scope: DEFAULT_SCOPE.split(',').map(str::to_string).collect(),
        task: None,
    };
    let mut task_words: Vec<String> = Vec::new();
    let mut it = args.peekable();
    while let Some(arg) = it.next() {
        let mut take = |name: &str| -> Result<String, String> {
            it.next()
                .ok_or_else(|| format!("option {name} requires a value\n\n{}", usage()))
        };
        match arg.as_str() {
            "--help" | "-h" => return Err(usage().to_string()),
            "--model" => cfg.model = take("--model")?,
            "--endpoint" => cfg.endpoint = take("--endpoint")?,
            "--ca" => cfg.ca = take("--ca")?,
            "--cert" => cfg.cert = take("--cert")?,
            "--key" => cfg.key = take("--key")?,
            "--root-dir" => cfg.root_dir = take("--root-dir")?,
            "--scope" => {
                cfg.scope = take("--scope")?
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown option {other}\n\n{}", usage()));
            }
            _ => task_words.push(arg),
        }
    }
    if !task_words.is_empty() {
        cfg.task = Some(task_words.join(" "));
    }
    Ok(cfg)
}

/// Split `host:port` into `(host, port)`, defaulting the port to 8443.
fn split_endpoint(endpoint: &str) -> (String, u16) {
    match endpoint.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().unwrap_or(8443)),
        None => (endpoint.to_string(), 8443),
    }
}

// ======================================================================================
// Subsystem adapters (the composition point — brokkr-cli is the one crate that wires all)
// ======================================================================================

/// REGIN, minimally: declares the one tool this CLI ships, `write_file`, requiring the `write`
/// capability. Implements both the SINDRI `GenomeResolver` (conjunct 3/4 vocabulary) and the
/// orchestrator's `GenomeCheck` (an undeclared tool is refused).
#[derive(Clone)]
struct CliGenome;
impl GenomeResolver for CliGenome {
    fn resolve_tool(&self, tool: &ToolId) -> Option<ResolvedTool> {
        (tool.as_str() == TOOL).then(|| ResolvedTool {
            required_capabilities: vec![Capability::new(CAP_WRITE)],
            privilege: PrivilegeClass::Privileged,
        })
    }
    fn resolve_invariant(&self, _invariant: &Invariant) -> Option<ResolvedInvariant> {
        None
    }
}
impl GenomeCheck for CliGenome {
    fn check(&self, action: &Action, _chain: &IntentProvenanceChain) -> Result<(), GenomeRefusal> {
        if action.tool.as_str() == TOOL {
            Ok(())
        } else {
            Err(GenomeRefusal {
                detail: format!(
                    "tool `{}` is not declared in the genome",
                    action.tool.as_str()
                ),
            })
        }
    }
}

/// An empty Self Set — screening is inert until a real baseline exists (BROKKR-ARCH §13).
struct EmptyCorpus {
    version: SelfSetVersion,
    digest: Digest,
}
impl SelfSetCorpus for EmptyCorpus {
    fn version(&self) -> SelfSetVersion {
        self.version.clone()
    }
    fn observations(&self) -> &[Observation] {
        &[]
    }
    fn digest(&self) -> Digest {
        self.digest.clone()
    }
}

/// SAGA as an `AuditSink`. Overrides `record_with_provenance` so the orchestrator's evidence-source
/// provenance reaches the signed record (Organ 5 patch); the default would drop it.
struct SagaSink {
    saga: Arc<Saga>,
}
impl AuditSink for SagaSink {
    fn record(&self, event: AuditEvent, dap: Dap, at: Timestamp) {
        if let Err(e) = self.saga.append(event, dap, at) {
            eprintln!("[warn] audit append failed: {e:?}");
        }
    }
    fn record_with_provenance(
        &self,
        event: AuditEvent,
        dap: Dap,
        at: Timestamp,
        provenance: EvidenceProvenance,
    ) {
        if let Err(e) = self.saga.append_with_provenance(event, dap, at, provenance) {
            eprintln!("[warn] audit append failed: {e:?}");
        }
    }
}

/// HEIMDALL behind the orchestrator's `Sentinel` trait (brokkr-sentinel cannot implement a
/// brokkr-cli trait — I-5 — so the adapter lives here).
struct SentinelAdapter {
    inner: Heimdall,
}
impl Sentinel for SentinelAdapter {
    fn observe(&self, observation: &Observation, now: Timestamp) -> Vec<Detection> {
        self.inner.observe(observation, now)
    }
}

/// EIR/KVASIR signal sink. Raise-only posture signals are noted on stderr; routing them into a live
/// resolution/adaptation loop is future work (the REPL is single-hop).
struct StderrSignals;
impl SignalRouter for StderrSignals {
    fn route(&self, signal: &Signal) {
        eprintln!("[signal] {:?} from {:?}", signal.class, signal.source);
    }
}

// ======================================================================================
// Construction
// ======================================================================================

/// A placeholder dual signature (correct algorithm ids, empty bytes). The Capability Envelope
/// carries a signature, but the orchestrator does not verify it at runtime (that is a promotion-gate
/// concern); `validate()` checks only the tier rules. A production deployment supplies a DAP-signed
/// envelope (BROKKR-ARCH §6.13).
fn placeholder_sig() -> DualSignature {
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

/// BROKKR's declared Capability Envelope (BROKKR-ARCH §6.13): `CodeExecution` +
/// `NetworkAccess(host:port)` + `ExternalEffect(filesystem:<root>)`; external-effect floors the
/// capability tier at Enhanced, `data_tier` Baseline, `governing_tier = Enhanced`. Valid, so
/// `with_envelope` (which now hard-validates, F-32) accepts it.
fn brokkr_envelope(host: &str, port: u16, root_dir: &str) -> CapabilityEnvelope {
    let hostport = format!("{host}:{port}");
    CapabilityEnvelope {
        system_id: "BROKKR".to_string(),
        properties: vec![
            CapabilityProperty::CodeExecution,
            CapabilityProperty::NetworkAccess {
                declared_destinations: vec![hostport],
            },
            CapabilityProperty::ExternalEffect {
                targets: vec![format!("filesystem:{root_dir}")],
            },
        ],
        egress_manifest: Some(EgressManifest {
            rules: vec![EgressRule {
                destination: host.to_string(),
                port,
                protocol: EgressProtocol::Https,
            }],
            signature: placeholder_sig(),
        }),
        capability_tier: ConformanceTier::Enhanced,
        data_tier: ConformanceTier::Baseline,
        governing_tier: ConformanceTier::Enhanced,
        attested_at: Timestamp(0),
        signature: placeholder_sig(),
    }
}

/// Everything the REPL needs to mint a fresh Root Intent and run each task.
struct Session {
    orch: Orchestrator,
    saga: Arc<Saga>,
    principal_kp: DualKeyPair,
    principal: SubjectId,
    dap: Dap,
    endpoint: ModelEndpointId,
    gateway: GatewayConfig,
    scope: Vec<Capability>,
    clock: u64,
}

/// Construct the orchestrator with production subsystems. Offline-safe: no network I/O happens here
/// (the mTLS handshake is performed per task, when a hop actually runs).
fn build(cfg: &Config) -> Result<Session, String> {
    let (host, port) = split_endpoint(&cfg.endpoint);

    // --- keys ---
    let principal_kp = DualKeyPair::generate().map_err(|e| format!("principal keypair: {e:?}"))?;
    let saga_kp = DualKeyPair::generate().map_err(|e| format!("saga keypair: {e:?}"))?;
    let heimdall_kp = DualKeyPair::generate().map_err(|e| format!("heimdall keypair: {e:?}"))?;
    let barrier_kp = DualKeyPair::generate().map_err(|e| format!("barrier keypair: {e:?}"))?;
    let (p_ml, p_slh) = principal_kp
        .public_key_bytes()
        .map_err(|e| format!("principal public: {e:?}"))?;
    let (h_ml, h_slh) = heimdall_kp
        .public_key_bytes()
        .map_err(|e| format!("heimdall public: {e:?}"))?;
    let (b_ml, b_slh) = barrier_kp
        .public_key_bytes()
        .map_err(|e| format!("barrier public: {e:?}"))?;

    let principal = SubjectId::new("principal-1");
    let dap = Dap::new("Jeremy Rose", "jr");
    let endpoint = ModelEndpointId::new(ENDPOINT_ID);

    // --- SINDRI (the deterministic spine): resolver knows the principal's key + the genome ---
    let registry = RegistryResolver::new().with_root(principal.clone(), p_ml, p_slh);
    let gate = Sindri::new(registry, CliGenome);

    // --- SAGA ---
    let saga = Arc::new(
        Saga::new(
            saga_kp,
            CryptoGeneration(1),
            Sha384Hasher.hash(b"brokkr-cli-genesis"),
            None,
        )
        .map_err(|e| format!("saga: {e:?}"))?,
    );

    // --- HEIMDALL ---
    let heimdall = Heimdall::new(
        Box::new(EmptyCorpus {
            version: SelfSetVersion::new("v0"),
            digest: Sha384Hasher.hash(b""),
        }),
        (h_ml, h_slh),
        heimdall_kp,
        1.0,
        None,
        100,
    );

    // --- HÚÐ (the ACTION barrier) ---
    let action_barrier = Huth::new(
        (b_ml.clone(), b_slh.clone()),
        (b_ml.clone(), b_slh.clone()),
        InMemoryCeiling::new(),
        InMemoryAcceptances::new(),
        brokkr_barrier::InMemoryPurposeFields::default(),
    );

    // --- BIFRÖST (the reasoner crossing): endpoint ceiling Internal (collapses to Public over a
    //     classical channel — the effective-authorization rule) ---
    let bifrost = Bifrost::new(
        (b_ml.clone(), b_slh.clone()),
        (b_ml.clone(), b_slh),
        InMemoryCeiling::new().with(endpoint.clone(), Classification::Internal),
        InMemoryAcceptances::new(),
        brokkr_barrier::InMemoryPurposeFields::default(),
    );

    // --- MÍMIR (ollama backend, reached THROUGH BIFRÖST's mTLS transport — I-6) ---
    let gateway = GatewayConfig {
        host: host.clone(),
        port,
        ca_file: cfg.ca.clone(),
        client_cert_file: cfg.cert.clone(),
        client_key_file: cfg.key.clone(),
    };
    let reg = InMemoryRegistry::new([endpoint.clone()]);
    let backend = OllamaBackend::new(MtlsTransport::new(gateway.clone()), cfg.model.clone(), host);
    let mimir = Mimir::new(
        endpoint.clone(),
        &reg,
        Box::new(backend),
        HopId::new("hop-1"),
    )
    .map_err(|e| format!("model endpoint not registered: {e:?}"))?;

    // --- the sandboxed filesystem tool (root from --root-dir) ---
    let tool = SandboxedTool::new(ToolId::new(TOOL), &cfg.root_dir)
        .map_err(|e| format!("sandbox root `{}`: {}", cfg.root_dir, e.detail))?;

    // --- wire the orchestrator: production guards, BROKKR's validated envelope ---
    let orch = Orchestrator::new(
        Box::new(bifrost),
        Box::new(mimir),
        Box::new(CliGenome),
        Box::new(gate),
        Box::new(action_barrier),
        Box::new(tool),
        Box::new(SentinelAdapter { inner: heimdall }),
        Box::new(SagaSink { saga: saga.clone() }),
        Box::new(StderrSignals),
        dap.clone(),
    )
    .with_guards(Guards::production())
    .with_envelope(brokkr_envelope(&gateway.host, gateway.port, &cfg.root_dir));

    let scope: Vec<Capability> = cfg
        .scope
        .iter()
        .map(|c| Capability::new(c.clone()))
        .collect();
    let clock = now_ms();

    Ok(Session {
        orch,
        saga,
        principal_kp,
        principal,
        dap,
        endpoint,
        gateway,
        scope,
        clock,
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ======================================================================================
// Running a task
// ======================================================================================

/// Run one governed hop for `task`, printing the outcome. `now` is strictly increasing across tasks
/// (monotonic guard) and each task carries a fresh nonce (replay guard).
fn run_task(s: &mut Session, task: &str) {
    // Strictly-increasing clock: track wall time but never regress (monotonic guard, F-9).
    s.clock = s.clock.max(now_ms()).saturating_add(1);
    let now = Timestamp(s.clock);
    let expiry = Timestamp(s.clock.saturating_add(EXPIRY_MS));
    let nonce = Nonce(s.clock);

    // Learn the ACTUAL negotiated group from a real handshake (a fact, not the offer list).
    let negotiated = match MtlsTransport::new(s.gateway.clone()).negotiate() {
        Ok(n) => n,
        Err(e) => {
            println!(
                "[error] could not reach the mTLS gateway at {}:{} — {e:?}",
                s.gateway.host, s.gateway.port
            );
            return;
        }
    };

    // Fresh, signed Root Intent (scope from --scope; expiry 5 minutes out).
    let root: RootIntent = match Skuld.sign_root(
        s.principal.clone(),
        s.dap.clone(),
        IntentScope::new(s.scope.clone()),
        InvariantSet::new([]),
        nonce,
        expiry,
        &mut s.principal_kp,
    ) {
        Ok(r) => r,
        Err(e) => {
            println!("[error] could not sign the root intent: {e:?}");
            return;
        }
    };
    let chain = IntentProvenanceChain::new(root);

    let att_sig = match s.principal_kp.sign_dual(b"attestation") {
        Ok(sig) => sig,
        Err(e) => {
            println!("[error] could not sign the attestation: {e:?}");
            return;
        }
    };
    let identity = Attestation {
        subject: s.principal.clone(),
        measurements: Sha384Hasher.hash(b"cli-measurements"),
        freshness: nonce,
        signatures: att_sig,
    };

    let req = HopRequest {
        identity,
        chain,
        context: Context {
            payload: task.to_string(),
            datum: DatumRef::new("cli-ctx"),
            classification: Classification::Public, // clears the (classical) dev channel
            personal: None,
            bcr: None,
        },
        dest: Destination::Reasoner {
            endpoint: s.endpoint.clone(),
            negotiated: negotiated.group,
        },
    };

    let before = s.saga.records().len();
    let result = s.orch.execute_hop(req, now);
    report(&result, &s.saga, before);
}

/// Print `[proposal]`/`[gate]`/`[executed]`/`[denied]`/`[killed]`/`[error]` from the new SAGA
/// records and the hop result.
fn report(result: &HopResult, saga: &Saga, from: usize) {
    let records = saga.records();
    for r in records.iter().skip(from) {
        if let AuditEvent::Authorization(a) = &r.event {
            println!(
                "[proposal] tool: {}, path: {}",
                a.action.tool.as_str(),
                a.action.detail
            );
            match &a.outcome {
                AuthorizationOutcome::Granted => println!("[gate] GRANTED"),
                AuthorizationOutcome::Anergy { reason } => {
                    println!("[gate] DENIED ({reason:?})");
                }
            }
        }
    }
    match result {
        HopResult::Executed { output } => println!("[executed] {output}"),
        HopResult::Denied { stage, reason } => {
            if reason.contains("independent termination") {
                println!("[killed] {reason}");
            } else {
                println!("[denied] {stage:?}: {reason}");
            }
        }
        HopResult::Error { detail } => println!("[error] {detail}"),
    }
}

// ======================================================================================
// main / REPL
// ======================================================================================

fn main() -> ExitCode {
    let cfg = match parse_args(std::env::args().skip(1)) {
        Ok(c) => c,
        Err(msg) => {
            // --help prints usage to stdout and succeeds; a parse error prints to stderr and fails.
            if msg.starts_with("brokkr ") {
                print!("{msg}");
                return ExitCode::SUCCESS;
            }
            eprint!("{msg}");
            return ExitCode::FAILURE;
        }
    };

    let mut session = match build(&cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[error] could not construct the orchestrator: {e}");
            return ExitCode::FAILURE;
        }
    };
    let kill = session.orch.kill_switch();

    // Single-task mode.
    if let Some(task) = cfg.task.clone() {
        run_task(&mut session, &task);
        return ExitCode::SUCCESS;
    }

    // Interactive REPL.
    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        print!("BROKKR ({}) > ", cfg.model);
        if std::io::stdout().flush().is_err() {
            return ExitCode::FAILURE;
        }
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => {
                println!();
                break; // EOF (ctrl-d)
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("[error] stdin: {e}");
                break;
            }
        }
        let input = line.trim();
        match input {
            "" => continue,
            "exit" | "quit" => break,
            "kill" => {
                kill.kill();
                println!("[killed] independent termination activated — the next hop is denied");
            }
            task => run_task(&mut session, task),
        }
    }
    ExitCode::SUCCESS
}
