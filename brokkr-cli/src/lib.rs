//! # brokkr-cli — the orchestrator (Phase 11)
//!
//! The governed action cycle (Architecture §5), built **last**. Every prior phase built a
//! subsystem behind a trait or a concrete API; this crate composes them into the loop that makes
//! BROKKR run. The logic lives here (not in `main.rs`) so integration tests compose an
//! [`Orchestrator`] from test doubles.
//!
//! ## How subsystems are reached
//!
//! Five subsystems expose committed **core traits**, held directly as `Box<dyn Trait>`:
//! [`ContextClearance`] (BIFRÖST), [`Reasoner`] (MÍMIR), [`CostimulationGate`] (SINDRI),
//! [`Barrier`] (HÚÐ), and [`ToolExecutor`] (tools). The others are concrete structs
//! (`Heimdall`, `Saga`) or have no per-hop entry point (`REGIN` exposes only the artifact
//! promotion gate), so the orchestrator depends on small crate-local **ports** — [`GenomeCheck`],
//! [`Sentinel`], [`AuditSink`], [`SignalRouter`] — bridged to the real subsystems by adapters (a
//! production concern; [`HeimdallSentinel`] is the one adapter provided here, proving the
//! [`Sentinel`] port matches `Heimdall::observe` at compile time). Test doubles back every port
//! and trait in the integration tests.
//!
//! ## `now` (I-13)
//!
//! [`Orchestrator::execute_hop`] takes `now` as a **call parameter** and threads it to every
//! subsystem that evaluates time (SINDRI, HÚÐ, HEIMDALL) — the same per-call discipline every gate
//! in BROKKR uses; no clock is stored. The single wall-clock read lives in [`Orchestrator::now`],
//! which a production driver calls to obtain `now` before each hop.

#![forbid(unsafe_code)]
// CLAUDE.md §6 — no panics in production paths (tests are a separate crate).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]

use brokkr_audit::{
    AuditEvent, AuthorizationOutcome, AuthorizationRecord, BarrierCrossing, ProposalRecord,
    RecordedInput,
};
use brokkr_core::barrier::{Barrier, BarrierVerdict, BoundaryFlow, Destination};
use brokkr_core::classification::Classification;
use brokkr_core::crypto::{Attestation, Digest, HashAlg, Hasher};
use brokkr_core::gate::{Action, AuthorizationDecision, CostimulationGate};
use brokkr_core::ids::{Dap, DatumRef, ModelIdentity, ResourcePath, Timestamp};
use brokkr_core::intent::IntentProvenanceChain;
use brokkr_core::reasoner::{ClearedContext, Context, ContextClearance, Reasoner};
use brokkr_core::signal::Signal;
use brokkr_crypto::Sha384Hasher;
use brokkr_sentinel::{Detection, Heimdall, Observation};
use brokkr_tools::ToolExecutor;

// ---- ports for the subsystems that are not committed core traits ---------------------

/// REGIN's per-hop check (§5 step 4): is the proposed tool a declared genome member, and does the
/// hop hold its privilege class? `brokkr-genome` exposes only the artifact promotion gate
/// (`promote`), not a per-hop lookup, so the orchestrator depends on this port; production backs
/// it from the signed genome.
pub trait GenomeCheck: Send + Sync {
    fn check(&self, action: &Action, chain: &IntentProvenanceChain) -> Result<(), GenomeRefusal>;
}

/// Why REGIN refused a tool at a hop (tool not declared, or the hop lacks the privilege).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenomeRefusal {
    pub detail: String,
}

/// HEIMDALL's observation surface (§5 step 8). `Heimdall` is a concrete struct; this port lets the
/// orchestrator hold it as a trait object (and lets a test double spy on what it was fed).
pub trait Sentinel: Send + Sync {
    fn observe(&self, observation: &Observation, now: Timestamp) -> Vec<Detection>;
}

/// The audit sink (SAGA). `Saga::append` is inherent; this port holds it as a trait object. The
/// port is infallible — the sink owns durability; a production `Saga` adapter maps a `SagaError`
/// (and would halt the hop / emit a chain-break). Phase 11 uses an in-memory spy.
pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEvent, dap: Dap, at: Timestamp);
}

/// Where HEIMDALL's raise-only [`Signal`]s go (§5 step 9): EIR (resolution) and KVASIR
/// (maturation). Neither is called per-hop; the orchestrator routes signals to this port. Phase 11
/// exercises the routing path with a spy; production signals are follow-on.
pub trait SignalRouter: Send + Sync {
    fn route(&self, signal: &Signal);
}

/// The one adapter provided here: bridges the [`Sentinel`] port to the real `Heimdall`. Its
/// existence proves the port matches `Heimdall::observe` (`&Observation`, `Timestamp` → `Vec<Detection>`)
/// at compile time. Constructing it needs a real `Heimdall` (a production concern); the tests use a
/// spy instead.
pub struct HeimdallSentinel(pub Heimdall);
impl Sentinel for HeimdallSentinel {
    fn observe(&self, observation: &Observation, now: Timestamp) -> Vec<Detection> {
        self.0.observe(observation, now)
    }
}

// ---- the cycle's inputs and outputs --------------------------------------------------

/// One hop's inputs. The Root Intent and the chain are constructed **before** the loop (§5 step 1,
/// not in `execute_hop`); the caller passes the chain in, along with the identity for this hop and
/// the outbound context + reasoner destination the crossing guards.
pub struct HopRequest {
    pub identity: Attestation,
    pub chain: IntentProvenanceChain,
    pub context: Context,
    pub dest: Destination,
}

/// The outcome of one governed hop. A denial **names where** it was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HopResult {
    /// The action executed. Carries the tool's output.
    Executed { output: String },
    /// Denied at a gate — which one, and why.
    Denied { stage: DenialStage, reason: String },
    /// A subsystem failed (not a denial — a failure, e.g. the reasoner backend errored).
    Error { detail: String },
}

/// Which gate denied the hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialStage {
    /// BIFRÖST refused the crossing to the reasoner (§5 step 2).
    Bifrost,
    /// REGIN refused the tool (§5 step 4).
    Genome,
    /// SINDRI returned architectural anergy (§5 step 5).
    Gate,
    /// HÚÐ denied the action's crossing (§5 step 6).
    Barrier,
}

// ---- the orchestrator ----------------------------------------------------------------

/// The governed action cycle. Holds every subsystem behind a trait object; it does not know which
/// implementations back them. The one composition point in the system.
pub struct Orchestrator {
    crossing: Box<dyn ContextClearance>, // §5 step 2 — BIFRÖST
    reasoner: Box<dyn Reasoner>,         // §5 step 3 — MÍMIR
    genome: Box<dyn GenomeCheck>,        // §5 step 4 — REGIN
    gate: Box<dyn CostimulationGate>,    // §5 step 5 — SINDRI
    barrier: Box<dyn Barrier>,           // §5 step 6 — HÚÐ
    tool: Box<dyn ToolExecutor>,         // §5 step 7 — tools
    sentinel: Box<dyn Sentinel>,         // §5 step 8 — HEIMDALL
    audit: Box<dyn AuditSink>,           // SAGA
    signals: Box<dyn SignalRouter>,      // §5 step 9 — EIR / KVASIR
    dap: Dap,                            // the accountable party stamped on audit records
}

impl Orchestrator {
    /// Compose the cycle. Every subsystem is required — there is no default, and no god-mode: an
    /// orchestrator cannot exist without all of them.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        crossing: Box<dyn ContextClearance>,
        reasoner: Box<dyn Reasoner>,
        genome: Box<dyn GenomeCheck>,
        gate: Box<dyn CostimulationGate>,
        barrier: Box<dyn Barrier>,
        tool: Box<dyn ToolExecutor>,
        sentinel: Box<dyn Sentinel>,
        audit: Box<dyn AuditSink>,
        signals: Box<dyn SignalRouter>,
        dap: Dap,
    ) -> Self {
        Self {
            crossing,
            reasoner,
            genome,
            gate,
            barrier,
            tool,
            sentinel,
            audit,
            signals,
            dap,
        }
    }

    /// The single wall-clock read in the whole system (§4). A production driver calls this to
    /// obtain the current time and passes it to [`execute_hop`](Self::execute_hop); the clock is
    /// read fresh per call and is **never stored** on the orchestrator (I-13).
    pub fn now() -> Timestamp {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        Timestamp(ms)
    }

    /// One iteration of the governed action cycle (§5 steps 2–8). `now` is supplied by the caller
    /// (I-13) and threaded to every subsystem that evaluates time. A denial at any step stops the
    /// cycle: the later steps do not run, and the outcome names the stage.
    pub fn execute_hop(&self, req: HopRequest, now: Timestamp) -> HopResult {
        let HopRequest {
            identity,
            chain,
            context,
            dest,
        } = req;

        // The egress flow for the reasoner crossing (for the audit record and the observation) —
        // built before `clear` consumes the context.
        let crossing_flow = BoundaryFlow::Egress {
            datum: context.datum.clone(),
            classification: context.classification,
            personal: context.personal.clone(),
            destination: dest.clone(),
            bcr: context.bcr.clone(),
        };

        // ---- §5 step 2: BIFRÖST guards the crossing to the reasoner -------------------
        let cleared: ClearedContext = match self.crossing.clear(context, &dest, now) {
            Ok(c) => c,
            Err(verdict) => {
                self.audit.record(
                    AuditEvent::BarrierCrossing(BarrierCrossing {
                        verdict: verdict.clone(),
                        flow: crossing_flow.clone(),
                        bcr_digest: None,
                        dap: Some(self.dap.clone()),
                    }),
                    self.dap.clone(),
                    now,
                );
                self.sentinel.observe(
                    &Observation::Crossing {
                        flow: crossing_flow,
                        verdict,
                    },
                    now,
                );
                return HopResult::Denied {
                    stage: DenialStage::Bifrost,
                    reason: "the outbound context did not clear the barrier".to_string(),
                };
            }
        };

        // ---- §5 step 3: MÍMIR proposes (untrusted) -----------------------------------
        let proposal = match self.reasoner.propose(&cleared, chain.current_scope()) {
            Ok(p) => p,
            Err(e) => {
                return HopResult::Error {
                    detail: format!("reasoner failed: {e}"),
                };
            }
        };
        // Record the proposal (OQGF-A-1). The input is a privacy-preserving derivative of the
        // cleared payload, never the payload itself; model identity / AIBOM digest are Phase-11
        // placeholders (production sources them from REGIN's AIBOM).
        let input_derivative = Sha384Hasher.hash(cleared.get().payload.as_bytes());
        self.audit.record(
            AuditEvent::Proposal(ProposalRecord {
                model: ModelIdentity {
                    name: self.reasoner.endpoint().as_str().to_string(),
                    version: String::new(),
                    provider: String::new(),
                },
                aibom_digest: empty_digest(),
                input: RecordedInput::Derivative(input_derivative),
                output: proposal.action.detail.clone(),
                explanation: proposal.rationale.clone(),
            }),
            self.dap.clone(),
            now,
        );
        let action = proposal.action;

        // ---- §5 step 4: REGIN checks the genome --------------------------------------
        if let Err(refusal) = self.genome.check(&action, &chain) {
            self.record_authorization(
                &action,
                AuthorizationOutcome::Anergy {
                    reason: brokkr_core::gate::AnergyReason::OutOfScope,
                },
                now,
            );
            self.sentinel.observe(
                &Observation::Authorization {
                    action: action.clone(),
                    granted: false,
                    anergy: Some(brokkr_core::gate::AnergyReason::OutOfScope),
                },
                now,
            );
            return HopResult::Denied {
                stage: DenialStage::Genome,
                reason: refusal.detail,
            };
        }

        // ---- §5 step 5: SINDRI costimulates ------------------------------------------
        // `authorize` calls `evaluate` and mints the `AuthorizedAction` on success — the only path
        // to one. The orchestrator cannot forge it (I-1).
        let authorized = match self.gate.authorize(&identity, &chain, action.clone(), now) {
            AuthorizationDecision::Granted(a) => {
                self.record_authorization(&action, AuthorizationOutcome::Granted, now);
                a
            }
            AuthorizationDecision::Anergy { reason } => {
                self.record_authorization(&action, AuthorizationOutcome::Anergy { reason }, now);
                self.sentinel.observe(
                    &Observation::Authorization {
                        action: action.clone(),
                        granted: false,
                        anergy: Some(reason),
                    },
                    now,
                );
                return HopResult::Denied {
                    stage: DenialStage::Gate,
                    reason: format!("architectural anergy: {reason:?}"),
                };
            }
        };

        // ---- §5 step 6: HÚÐ governs the action's crossing ----------------------------
        // The authorized action's egress. For a local, non-crossing action a real HÚÐ allows
        // (Public, no BCR); a crossing to an unauthorized destination denies.
        let action_flow = BoundaryFlow::Egress {
            datum: DatumRef::new(action.tool.as_str()),
            classification: Classification::Public,
            personal: None,
            destination: Destination::LocalPath(ResourcePath::new(action.detail.clone())),
            bcr: None,
        };
        match self.barrier.evaluate(&action_flow, now) {
            BarrierVerdict::Allow | BarrierVerdict::AcceptedRisk { .. } => {}
            blocking => {
                self.audit.record(
                    AuditEvent::BarrierCrossing(BarrierCrossing {
                        verdict: blocking.clone(),
                        flow: action_flow.clone(),
                        bcr_digest: None,
                        dap: Some(self.dap.clone()),
                    }),
                    self.dap.clone(),
                    now,
                );
                self.sentinel.observe(
                    &Observation::Crossing {
                        flow: action_flow,
                        verdict: blocking,
                    },
                    now,
                );
                return HopResult::Denied {
                    stage: DenialStage::Barrier,
                    reason: "the action's crossing was denied".to_string(),
                };
            }
        }

        // ---- §5 step 7: execute ------------------------------------------------------
        // Only an `AuthorizedAction` (minted by SINDRI) reaches the executor (I-1). There is no
        // dedicated `Execution` audit event; the reconciliation observation (step 8) is the record
        // that the authorized action ran.
        let outcome = match self.tool.execute(&authorized) {
            Ok(o) => o,
            Err(e) => {
                return HopResult::Error {
                    detail: format!("tool execution failed: {e}"),
                };
            }
        };

        // ---- §5 step 8: HEIMDALL reconciles ------------------------------------------
        // `executed == authorized`: the tool did exactly what was authorized. This is the first
        // point in the system where `Observation::Hop { executed: Some(..) }` is possible.
        let mut detections = self.sentinel.observe(
            &Observation::Hop {
                authorized: action.clone(),
                executed: Some(action.clone()),
            },
            now,
        );
        detections.extend(self.sentinel.observe(
            &Observation::Authorization {
                action: action.clone(),
                granted: true,
                anergy: None,
            },
            now,
        ));
        // Route the raise-only signals of any unsuppressed detection to EIR/KVASIR, and record them.
        for detection in &detections {
            if let Some(signal) = &detection.signal {
                self.signals.route(signal);
                self.audit
                    .record(AuditEvent::Signal(signal.clone()), self.dap.clone(), now);
            }
        }

        HopResult::Executed {
            output: outcome.output,
        }
    }

    /// Record a SINDRI/REGIN authorization decision to SAGA.
    fn record_authorization(&self, action: &Action, outcome: AuthorizationOutcome, now: Timestamp) {
        self.audit.record(
            AuditEvent::Authorization(AuthorizationRecord {
                action: action.clone(),
                outcome,
            }),
            self.dap.clone(),
            now,
        );
    }
}

/// An empty SHA-384 digest — the Phase-11 placeholder for the AIBOM digest a proposal record
/// carries. Production sources the real digest from REGIN's signed AIBOM.
fn empty_digest() -> Digest {
    Digest {
        alg: HashAlg::Sha384,
        bytes: Vec::new(),
    }
}
