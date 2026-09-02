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
use brokkr_core::capability::{
    CapabilityEnvelope, EgressRule, EvidenceProvenance, TrajectoryEntry, TrajectoryOutcome,
};
use brokkr_core::classification::Classification;
use brokkr_core::crypto::{Attestation, Digest, HashAlg, Hasher};
use brokkr_core::gate::{Action, AuthorizationDecision, CostimulationGate};
use brokkr_core::ids::{Dap, DatumRef, ModelIdentity, Nonce, ResourcePath, SubjectId, Timestamp};
use brokkr_core::intent::{Capability, IntentProvenanceChain, IntentScope};
use brokkr_core::reasoner::{ClearedContext, Context, ContextClearance, Reasoner};
use brokkr_core::signal::Signal;
use brokkr_crypto::Sha384Hasher;
use brokkr_sentinel::{Detection, Heimdall, Observation};
use brokkr_tools::ToolExecutor;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// P-12.5 independent termination as a **latch**: once set, it stays set for the life of the
/// session — there is no `unkill`/`unset` (16-FIX, Fix 1). The type also fixes the memory
/// ordering (`Release` on set, `Acquire` on read), so a caller cannot weaken it to `Relaxed`.
/// The model never sees it and cannot reach it; only a thread holding a [`KillSwitch`] handle
/// (a signal handler, a watchdog, a DAP command) can activate it, and activation is irreversible.
#[derive(Clone)]
pub struct KillSwitch(Arc<AtomicBool>);

impl KillSwitch {
    /// A fresh, un-activated switch.
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
    /// Activate independent termination. **Irreversible** — there is no counterpart that clears it.
    pub fn kill(&self) {
        self.0.store(true, Ordering::Release);
    }
    /// Whether termination has been activated.
    pub fn is_killed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    /// A second handle onto the same switch, for another thread. Cloning shares the latch; it does
    /// not reset it.
    pub fn handle(&self) -> Self {
        self.clone()
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

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

    /// Record an event with explicit **evidence-source provenance** (Organ 5 evidence-capture
    /// patch): how it was captured, by what sensor, through what path. The default drops the
    /// provenance and calls [`record`](Self::record), so existing sinks are unaffected; a
    /// provenance-aware sink (a SAGA adapter that calls `append_with_provenance`, or a test spy that
    /// inspects it) overrides this. The orchestrator records **only** through this method.
    fn record_with_provenance(
        &self,
        event: AuditEvent,
        dap: Dap,
        at: Timestamp,
        _provenance: EvidenceProvenance,
    ) {
        self.record(event, dap, at);
    }
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

/// The maximum size of an action's `detail`, in bytes (13-FIX F-3). A proposal whose detail exceeds
/// this is denied before any gate is consulted. Unconditional — a pure resource safety cap.
pub const MAX_DETAIL_BYTES: usize = 1_048_576; // 1 MiB

/// The maximum number of `(principal, nonce)` entries the replay guard retains (14-FIX F-13). A
/// well-formed chain expires and its entry is evicted (its expiry is bounded by the actor's
/// credential lifetime, OQGF-M-14); but a *malformed* chain carrying an implausibly far expiry
/// (e.g. `u64::MAX`) would never be evicted by expiry, so without a cap the ledger could grow
/// without bound. At capacity, the entry closest to expiring (smallest expiry) is evicted before a
/// new one is inserted — it is the one nearest legitimate eviction anyway. Bounds memory
/// regardless of the expiry values a chain declares; it never *forgets* a still-fresh nonce
/// preferentially, so it cannot wrongly admit a replay of a normal chain.
pub const MAX_NONCE_ENTRIES: usize = 10_000;

/// The single denial reason returned for **every** gate denial when `uniform_denial_stage` is on
/// (15-FIX F-22/F-26). Under production guards a genome refusal and a SINDRI anergy return the same
/// `(stage, reason)` pair, so the reason string cannot be used to tell a declared tool from an
/// undeclared one (which 15B F-26 showed enumerates the whole genome). The *specific* reason is
/// still written to SAGA (the audit is trusted; the returned face is not).
pub const UNIFORM_DENIAL_REASON: &str = "action denied";

/// A sliding-window rate limit: at most `max` hops per `window_ms` milliseconds (13-FIX F-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub max: u32,
    pub window_ms: u64,
}

/// The orchestrator's driver-layer guards (13-FIX F-1/F-5/F-7/F-9). These defend the gaps
/// **between** the deterministic gates — replay, rate, clock, denial-oracle — which are the
/// driver's responsibility, not the spine's. **`production()` is the safe default** used by
/// [`Orchestrator::new`]; a test rig verifying the spine's own gates opts into [`permissive`] so it
/// can legitimately reuse a chain, flood, or observe the true denial stage. Note: the F-3 size cap
/// and F-8 audit-sanitization are **not** here — they are unconditional and always applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guards {
    /// F-1: reject a chain whose `(principal, nonce)` has already been used within its expiry.
    pub replay_guard: bool,
    /// F-7: sliding-window per-hop rate limit. `None` = unlimited.
    pub rate_limit: Option<RateLimit>,
    /// F-9: reject a hop whose `now` precedes the last `now` seen.
    pub monotonic_time: bool,
    /// F-5: return a uniform `DenialStage::Gate` for both genome and gate refusals, so the caller
    /// cannot use the stage to tell a declared tool from an undeclared one. (SAGA still records the
    /// true stage — the audit is trusted.)
    pub uniform_denial_stage: bool,
}

impl Guards {
    /// The production default: every guard on; 100 hops / 60 s.
    pub fn production() -> Self {
        Self {
            replay_guard: true,
            rate_limit: Some(RateLimit {
                max: 100,
                window_ms: 60_000,
            }),
            monotonic_time: true,
            uniform_denial_stage: true,
        }
    }

    /// All guards off — for a test rig verifying the deterministic **spine**, which legitimately
    /// reuses a chain, floods, or asserts the true denial stage. The unconditional F-3 size cap and
    /// F-8 sanitization still apply.
    pub fn permissive() -> Self {
        Self {
            replay_guard: false,
            rate_limit: None,
            monotonic_time: false,
            uniform_denial_stage: false,
        }
    }
}

/// The mutable driver-guard state, behind one `Mutex` (interior mutability — `execute_hop` is
/// `&self`, the same pattern SAGA uses).
#[derive(Default)]
struct GuardState {
    /// F-1: `(principal, nonce) -> chain expiry`. An entry means the chain was already used; it is
    /// evicted once `now` passes its expiry (a fresh nonce could then legitimately reappear).
    seen_nonces: HashMap<(SubjectId, Nonce), Timestamp>,
    /// F-7: timestamps of recent hops, within the rate-limit window.
    recent_hops: std::collections::VecDeque<Timestamp>,
    /// F-9: the last `now` accepted.
    last_now: Option<Timestamp>,
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
    guards: Guards,                      // 13-FIX: driver-layer guards (config)
    guard_state: Mutex<GuardState>,      // 13-FIX: their mutable state (interior mutability)
    // ---- AMD-011 Capability-Triggered Assurance ----
    envelope: CapabilityEnvelope, // P-12.2: what the composed system can do (config)
    egress_rules: Option<Vec<EgressRule>>, // P-12.4: extracted from the signed manifest, fast lookup
    kill_switch: KillSwitch, // P-12.5: independent termination — a latch, model cannot reach it
    trajectory: Mutex<Vec<TrajectoryEntry>>, // P-12.8: the ordered session trajectory
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
            guards: Guards::production(),
            guard_state: Mutex::new(GuardState::default()),
            // AMD-011 defaults: a permissive (unenforcing) envelope with no egress manifest, no
            // kill signal, and an empty trajectory. A deployment supplies its attested envelope via
            // `.with_envelope()` (the `.with_guards()` pattern), so existing composition is unchanged.
            envelope: CapabilityEnvelope::permissive(),
            egress_rules: None,
            kill_switch: KillSwitch::new(),
            trajectory: Mutex::new(Vec::new()),
        }
    }

    /// Replace the driver-layer guards (13-FIX). `new` defaults to [`Guards::production`]; a test rig
    /// verifying the spine's own gates uses `.with_guards(Guards::permissive())`.
    #[must_use]
    pub fn with_guards(mut self, guards: Guards) -> Self {
        self.guards = guards;
        self
    }

    /// Install the system's [`CapabilityEnvelope`] (AMD-011). `new` defaults to
    /// [`CapabilityEnvelope::permissive`] (no egress enforcement); a deployment (or a test)
    /// supplies its attested envelope here. The signed egress manifest, if present, is extracted
    /// once for fast per-hop lookup (P-12.4). This does not re-verify the signature.
    ///
    /// F-32 (DAP-directed) — the envelope is **validated before it governs** (I-14): an invalid
    /// envelope (`TierMismatch` or `TierTooLow`) is rejected here rather than allowed to govern a
    /// run. The check is a **hard** `assert!` — fail-closed, the same pattern `permissive()` uses
    /// (F-33), and `assert!` rather than `.expect()` because §6 denies `expect_used` in production.
    #[must_use]
    pub fn with_envelope(mut self, envelope: CapabilityEnvelope) -> Self {
        assert!(
            envelope.validate().is_ok(),
            "capability envelope must be valid before it governs (I-14)"
        );
        self.egress_rules = envelope.egress_manifest.as_ref().map(|m| m.rules.clone());
        self.envelope = envelope;
        self
    }

    /// P-12.5 — independent termination. Returns a [`KillSwitch`] handle any thread (a signal
    /// handler, a watchdog, a DAP command) can `kill()` to stop the orchestrator, without the
    /// model's cooperation. The model never sees it, cannot influence it, cannot delay it, and
    /// cannot route around it — [`execute_hop`](Self::execute_hop) reads it before any gate on
    /// every call. Activation is a **latch**: once killed, the session stays killed (16-FIX).
    pub fn kill_switch(&self) -> KillSwitch {
        self.kill_switch.handle()
    }

    /// P-12.8 — the session trajectory: the ordered, complete sequence of every hop attempt
    /// (executed, denied, or errored), each carrying its evidence provenance. Returned as an owned
    /// snapshot for export / audit.
    pub fn trajectory(&self) -> Vec<TrajectoryEntry> {
        self.trajectory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// The composed system's declared capability envelope (AMD-011 P-12.2).
    pub fn envelope(&self) -> &CapabilityEnvelope {
        &self.envelope
    }

    /// Recover the guard state without panicking on a poisoned lock.
    fn guard_state(&self) -> std::sync::MutexGuard<'_, GuardState> {
        self.guard_state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Apply the driver-layer guards (rate, monotonic time, replay) before any gate runs. Returns
    /// `Some(result)` if a guard denies/errors the hop; `None` to proceed. Records the chain's nonce
    /// as used when the replay guard is active.
    fn check_guards(&self, chain: &IntentProvenanceChain, now: Timestamp) -> Option<HopResult> {
        let mut st = self.guard_state();

        // F-9 — monotonic time. A hop whose `now` precedes the last accepted `now` is rejected
        // (a regressing clock is a driver bug or manipulation; not model-controlled).
        if self.guards.monotonic_time
            && let Some(last) = st.last_now
            && now.0 < last.0
        {
            return Some(HopResult::Error {
                detail: "non-monotonic time rejected".to_string(),
            });
        }

        // F-7 — sliding-window rate limit. Evict timestamps older than the window, then admit only
        // if under `max`.
        if let Some(rl) = self.guards.rate_limit {
            let cutoff = now.0.saturating_sub(rl.window_ms);
            while let Some(front) = st.recent_hops.front().copied() {
                if front.0 < cutoff {
                    st.recent_hops.pop_front();
                } else {
                    break;
                }
            }
            if st.recent_hops.len() as u32 >= rl.max {
                return Some(HopResult::Denied {
                    stage: DenialStage::Gate,
                    reason: "rate limit exceeded".to_string(),
                });
            }
        }

        // F-1 — replay guard. Evict expired entries first (a nonce may legitimately reappear once
        // its chain has expired). Then reject a `(principal, nonce)` already used within expiry.
        if self.guards.replay_guard {
            st.seen_nonces.retain(|_, expiry| now.0 <= expiry.0);
            let key = (chain.root().principal.clone(), chain.root().nonce);
            // Replay check first — a resubmitted nonce is caught here regardless of the cap.
            if st.seen_nonces.contains_key(&key) {
                return Some(HopResult::Denied {
                    stage: DenialStage::Gate,
                    reason: "chain replay detected".to_string(),
                });
            }
            // F-13 — bound the ledger. F-29: only *expired* entries may be evicted. The `retain`
            // above already dropped every expired entry, so a ledger still at capacity here holds
            // only still-valid nonces. Rather than evict a fresh nonce to make room — which would
            // open a replay window under nonce-space exhaustion (15C F-29) — reject the new chain.
            // Replay protection wins over availability under a flood; the flood itself is the
            // operator's signal to investigate.
            if st.seen_nonces.len() >= MAX_NONCE_ENTRIES {
                return Some(HopResult::Denied {
                    stage: DenialStage::Gate,
                    reason: "nonce ledger full — too many active chains".to_string(),
                });
            }
            st.seen_nonces.insert(key, chain.root().expiry);
        }

        // The hop is admitted: record its timestamp (rate window) and advance the clock.
        if self.guards.rate_limit.is_some() {
            st.recent_hops.push_back(now);
        }
        if self.guards.monotonic_time {
            st.last_now = Some(now);
        }
        None
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
        let mut action_taken: Option<Action> = None;
        let result = self.run_hop(req, now, &mut action_taken);
        // P-12.8 — every hop attempt (whatever its outcome) is appended to the trajectory, with its
        // evidence provenance, so the session is reconstructable.
        self.record_trajectory(action_taken, &result, now);
        result
    }

    /// The governed cycle body (§5 steps 2–8). Returns the [`HopResult`] and, via `action_out`, the
    /// proposed action once MÍMIR has proposed one — so [`execute_hop`](Self::execute_hop) can record
    /// the trajectory entry (P-12.8) for every outcome, including a pre-proposal denial.
    fn run_hop(
        &self,
        req: HopRequest,
        now: Timestamp,
        action_out: &mut Option<Action>,
    ) -> HopResult {
        // ---- P-12.5 — independent termination, before EVERY gate ---------------------
        // A lock-free latch ([`KillSwitch`]) any external thread can set; the model never sees it
        // and cannot route around it. This is the very first thing the cycle does — ahead of the
        // guards, the crossing, and every deterministic gate. Once set, it stays set (16-FIX).
        if self.kill_switch.is_killed() {
            return HopResult::Denied {
                stage: DenialStage::Gate,
                reason: "independent termination activated".to_string(),
            };
        }

        let HopRequest {
            identity,
            chain,
            context,
            dest,
        } = req;

        // ---- P-12.4 — deterministic default-deny egress ------------------------------
        // A sibling to HÚÐ: if the crossing targets a declared network destination, it must appear
        // in the signed egress manifest, else deny. A no-op when no manifest is configured, or when
        // the destination is not a network host — the current filesystem tools produce local
        // destinations, and the BIFRÖST reasoner crossing is gated by HÚÐ / effective authorization.
        if let Some(stop) = self.check_egress(&dest) {
            return stop;
        }

        // ---- 13-FIX driver-layer guards (before any gate) ----------------------------
        // Rate limit (F-7), monotonic time (F-9), and chain replay (F-1). A guarded-out hop never
        // reaches the model or a gate. All are no-ops under `Guards::permissive()`.
        if let Some(stop) = self.check_guards(&chain, now) {
            return stop;
        }

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
                self.audit.record_with_provenance(
                    AuditEvent::BarrierCrossing(BarrierCrossing {
                        verdict: verdict.clone(),
                        flow: crossing_flow.clone(),
                        bcr_digest: None,
                        dap: Some(self.dap.clone()),
                    }),
                    self.dap.clone(),
                    now,
                    self.provenance("execute_hop::after_bifrost", now),
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
        // placeholders (production sources them from REGIN's AIBOM). **F-8:** the model-supplied
        // `detail` and `rationale` are sanitized before recording — control characters and ANSI
        // escapes are stripped so a recorded value cannot deceive or corrupt an audit-log viewer.
        // The sanitization is on the *audit copy only*; the real `action.detail` handed to the
        // barrier and tool below is untouched.
        let input_derivative = Sha384Hasher.hash(cleared.get().payload.as_bytes());
        self.audit.record_with_provenance(
            AuditEvent::Proposal(ProposalRecord {
                model: ModelIdentity {
                    name: self.reasoner.endpoint().as_str().to_string(),
                    version: String::new(),
                    provider: String::new(),
                },
                aibom_digest: empty_digest(),
                input: RecordedInput::Derivative(input_derivative),
                output: sanitize_for_audit(&proposal.action.detail),
                explanation: sanitize_for_audit(&proposal.rationale),
            }),
            self.dap.clone(),
            now,
            self.provenance("execute_hop::after_reasoner", now),
        );
        let action = proposal.action;
        // P-12.8 — hand the proposed action back to `execute_hop` for the trajectory record.
        *action_out = Some(action.clone());

        // ---- 13-FIX F-3: reject an oversized detail before any gate runs --------------
        if action.detail.len() > MAX_DETAIL_BYTES {
            self.record_authorization(
                &action,
                AuthorizationOutcome::Anergy {
                    reason: brokkr_core::gate::AnergyReason::OutOfScope,
                },
                now,
            );
            return HopResult::Denied {
                stage: DenialStage::Gate,
                reason: "action detail exceeds size limit".to_string(),
            };
        }

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
            // **F-5 / F-22:** under production guards the SAGA record above keeps the true reason
            // (the Authorization event carries the attempted `action.tool` and the anergy category —
            // the audit is trusted), while both the returned *stage* AND *reason* are uniform, so the
            // caller cannot distinguish an undeclared tool from a SINDRI denial by either channel
            // (15B F-26 showed a distinguishable reason enumerates the genome). A permissive rig
            // reports the real `Genome` stage and the specific `refusal.detail`.
            let stage = if self.guards.uniform_denial_stage {
                DenialStage::Gate
            } else {
                DenialStage::Genome
            };
            let reason = if self.guards.uniform_denial_stage {
                UNIFORM_DENIAL_REASON.to_string()
            } else {
                refusal.detail
            };
            return HopResult::Denied { stage, reason };
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
                // F-22: uniform the reason under production guards so it is indistinguishable from a
                // genome refusal; the specific `AnergyReason` is in the SAGA record above.
                let reason = if self.guards.uniform_denial_stage {
                    UNIFORM_DENIAL_REASON.to_string()
                } else {
                    format!("architectural anergy: {reason:?}")
                };
                return HopResult::Denied {
                    stage: DenialStage::Gate,
                    reason,
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
                self.audit.record_with_provenance(
                    AuditEvent::BarrierCrossing(BarrierCrossing {
                        verdict: blocking.clone(),
                        flow: action_flow.clone(),
                        bcr_digest: None,
                        dap: Some(self.dap.clone()),
                    }),
                    self.dap.clone(),
                    now,
                    self.provenance("execute_hop::after_barrier", now),
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
                // F-20 — an *authorized* action that fails to execute must still be visible to
                // HEIMDALL's reconciliation loop. `executed: None` records that the action was
                // authorized but did not run, so a pattern of authorized-but-failing tools (a
                // possible tamper or resource signal) is detectable rather than invisible.
                self.sentinel.observe(
                    &Observation::Hop {
                        authorized: action.clone(),
                        executed: None,
                    },
                    now,
                );
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
                // The signal originated in HEIMDALL's observation; the orchestrator is the recorder,
                // so the sensor is the orchestrator and the capture path names the HEIMDALL origin.
                self.audit.record_with_provenance(
                    AuditEvent::Signal(signal.clone()),
                    self.dap.clone(),
                    now,
                    self.provenance("execute_hop::after_tool::heimdall_observe", now),
                );
            }
        }

        HopResult::Executed {
            output: outcome.output,
        }
    }

    /// Record a SINDRI/REGIN authorization decision to SAGA.
    fn record_authorization(&self, action: &Action, outcome: AuthorizationOutcome, now: Timestamp) {
        self.audit.record_with_provenance(
            AuditEvent::Authorization(AuthorizationRecord {
                action: action.clone(),
                outcome,
            }),
            self.dap.clone(),
            now,
            self.provenance("execute_hop::after_gate", now),
        );
    }

    /// Organ 5 evidence-capture patch — the evidence-source provenance the orchestrator attaches to
    /// every audit record it writes. `sensor_id` is `"orchestrator"` because the orchestrator is the
    /// recorder: it is in the trusted computing base (F-23), and the patch requires that to be
    /// **stated** in the record, not hidden. `capture_path` names where in `execute_hop` the record
    /// was captured. A production deployment with an independent audit sensor states a different
    /// `sensor_id`.
    fn provenance(&self, capture_path: &str, now: Timestamp) -> EvidenceProvenance {
        EvidenceProvenance {
            sensor_id: "orchestrator".to_string(),
            capture_path: capture_path.to_string(),
            capture_timestamp: now,
            expected_coverage: "full_hop".to_string(),
            observed_coverage: "full_hop".to_string(),
            evidence_gap: None,
        }
    }

    /// P-12.4 — deterministic default-deny egress. Returns `Some(Denied)` when the crossing targets
    /// a **network** destination absent from the signed egress manifest; `None` to proceed.
    ///
    /// A no-op when no manifest is configured (`egress_rules` is `None` — the permissive default),
    /// or when the destination is not a network host. `Destination::Reasoner` (the model crossing,
    /// gated by HÚÐ / effective authorization) and `Destination::LocalPath` (the current filesystem
    /// tools) are not manifest-gated here; a future `Destination::Network` tool **is**. The check is
    /// present and correct so such a tool is gated the moment it exists.
    fn check_egress(&self, dest: &Destination) -> Option<HopResult> {
        let rules = self.egress_rules.as_ref()?;
        let (host, port, protocol) = match dest {
            Destination::Network {
                host,
                port,
                protocol,
                ..
            } => (host.as_str(), *port, protocol),
            _ => return None,
        };
        // Fix 2 (F-35) — normalize the host on both sides, so the same endpoint spelled differently
        // (`localhost` / `127.0.0.1` / `::1`) cannot bypass the manifest nor be falsely denied.
        // Conservative: lowercase + trim + the localhost equivalence only — no DNS resolution (a
        // runtime concern the deterministic gate must not depend on).
        // F-34 (DAP-directed) — a rule matches only when host (normalized), `port`, AND `protocol`
        // all match; a mismatch on any of the three is a denial.
        let norm = normalize_destination(host);
        let allowed = rules.iter().any(|r| {
            normalize_destination(&r.destination) == norm
                && r.port == port
                && &r.protocol == protocol
        });
        if allowed {
            None
        } else {
            Some(HopResult::Denied {
                stage: DenialStage::Barrier,
                reason: "destination not in egress manifest".to_string(),
            })
        }
    }

    /// P-12.8 — append one entry to the session trajectory. Every hop attempt is recorded, whatever
    /// its outcome; a pre-proposal denial (kill flag, egress, guards, crossing) has no proposed
    /// action, so a `(no-action)` marker stands in its place. The evidence provenance states that
    /// **the orchestrator** captured this, through `execute_hop`, with its own clock — the honest
    /// limitation (the orchestrator is the sensor, so the evidence rests on its integrity; F-23) is
    /// stated in the record rather than hidden (the Organ 5 evidence-provenance patch).
    fn record_trajectory(&self, action: Option<Action>, result: &HopResult, now: Timestamp) {
        let mut traj = self.trajectory.lock().unwrap_or_else(|p| p.into_inner());
        let sequence = traj.len() as u64;
        let (action, tool_id) = match action {
            Some(a) => {
                let tool = a.tool.clone();
                (a, tool)
            }
            None => {
                let none = brokkr_core::ids::ToolId::new("(no-action)");
                (
                    Action {
                        tool: none.clone(),
                        detail: String::new(),
                    },
                    none,
                )
            }
        };
        // Organ 5 patch — an errored hop did not complete, so the evidence of what happened is
        // incomplete: record the gap explicitly rather than presenting a partial record as complete.
        let (observed_coverage, evidence_gap) = match result {
            HopResult::Error { detail } => (
                "partial_hop".to_string(),
                Some(format!("hop errored before completion: {detail}")),
            ),
            _ => ("full_hop".to_string(), None),
        };
        let outcome = match result {
            HopResult::Executed { output } => TrajectoryOutcome::Executed {
                output: output.clone(),
            },
            HopResult::Denied { stage, reason } => TrajectoryOutcome::Denied {
                stage: format!("{stage:?}"),
                reason: reason.clone(),
            },
            HopResult::Error { detail } => TrajectoryOutcome::Error {
                detail: detail.clone(),
            },
        };
        traj.push(TrajectoryEntry {
            sequence,
            action,
            tool_id,
            outcome,
            timestamp: now,
            provenance: EvidenceProvenance {
                sensor_id: "orchestrator".to_string(),
                capture_path: "execute_hop".to_string(),
                capture_timestamp: now,
                expected_coverage: "full_hop".to_string(),
                observed_coverage,
                evidence_gap,
            },
        });
    }
}

/// 16-FIX (Fix 2) — canonicalize an egress destination host for manifest comparison. Lowercases
/// and trims, and folds the localhost aliases (`127.0.0.1`, `::1`) to `localhost`, so the same
/// endpoint spelled differently matches the same rule. Deliberately conservative: no DNS
/// resolution, no other host rewriting — the egress gate is deterministic and must not depend on
/// a network lookup.
fn normalize_destination(dest: &str) -> String {
    let t = dest.trim().to_lowercase();
    if t == "127.0.0.1" || t == "::1" {
        String::from("localhost")
    } else {
        t
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

/// Sanitize a model-supplied string before it enters an audit record (13-FIX F-8). Strips control
/// characters — everything below `0x20` **except** `\n` and `\t`, plus `\x7F` (DEL) — and drops ANSI
/// escape sequences (`\x1b[ … <final>`). This is **lossy by design**: an audit record is for human
/// review and export, and a recorded value must not be able to carry a NUL that truncates a viewer,
/// an ESC that recolors a terminal, or a control byte that corrupts a log. The integrity of the
/// *decision* is unaffected — only the human-facing recorded copy of `detail`/`rationale` is
/// sanitized; the real `Action.detail` handed to the barrier and tool is untouched.
pub fn sanitize_for_audit(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // ANSI escape: drop the ESC and the rest of a CSI sequence (`[` … final byte @-~).
            '\u{1b}' => {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    // Consume the CSI body until its final byte (@-~). **F-14:** cap the skip at 16
                    // chars so an *unterminated* CSI (ESC `[` followed only by parameter/intermediate
                    // bytes to EOF) drops at most a bounded prefix, not the entire tail — an attacker
                    // can no longer truncate a recorded value by appending a lone `ESC [`.
                    let mut consumed = 0usize;
                    for e in chars.by_ref() {
                        consumed += 1;
                        if ('\u{40}'..='\u{7e}').contains(&e) || consumed >= 16 {
                            break; // final byte of the CSI sequence, or the F-14 cap
                        }
                    }
                }
                // A bare ESC (or non-CSI escape) is simply dropped.
            }
            '\n' | '\t' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {} // other control char: drop
            c => out.push(c),
        }
    }
    out
}

/// Report the capabilities in `scope` that are **not** in the recognized `vocabulary` (13-FIX
/// F-10). An undeclared capability in a Root Intent's scope is *harmless* — it grants nothing,
/// since no tool requires it — so this is a **warning surface**, not a denial: a hard error would
/// be over-denial (OQGF-P-1). A driver calls this at Root-Intent construction and logs the result;
/// an empty return means the scope is clean.
pub fn validate_scope(scope: &IntentScope, vocabulary: &[Capability]) -> Vec<Capability> {
    scope
        .capabilities()
        .iter()
        .filter(|c| !vocabulary.contains(c))
        .cloned()
        .collect()
}
