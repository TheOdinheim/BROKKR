//! EIR — the Resolution Engine (OQGF-P-8, §6.8).
//!
//! **The load-bearing asymmetry of the phase (OQGF-P-8.5):** autonomous action may *raise*
//! posture; it may never autonomously *lower* it above baseline. EIR enforces this in
//! [`Eir::resolve`]: a [`ResolutionDecision`] whose dual-family signature does not verify under
//! the declared DAP key is **not** DAP-confirmed, and resolution is refused with
//! `NeedsDapConfirmation`. A forged or replayed decision therefore cannot stand BROKKR down.
//!
//! **Resolution is an act, not a timeout (OQGF-P-8.2):** nothing returns to baseline because a
//! timer expired. Only a signed `ResolutionDecision` — naming the cleared condition, the time,
//! and the DAP — de-escalates.
//!
//! **Incident preservation (OQGF-P-8.4):** EIR holds only posture state (which escalations are
//! up, since when, and whether their clear condition is holding). It holds **no** incident
//! records and **no** learned detectors, so standing an escalation down erases nothing — there
//! is nothing to erase. SAGA (Phase 7) and KVASIR (Phase 9) retain their records
//! independently, and EIR depends on neither (I-5). The response stands down; the intelligence
//! does not, because EIR never held it.
//!
//! **The current time is not held (I-13):** `may_resolve`, `resolve`, and `scan_chronic` each
//! take `now` as a parameter of the evaluating call — never a wall-clock read, never stored.
//! `Duration` (nanoseconds) is compared against `Timestamp` (epoch milliseconds) by widening the
//! millisecond elapsed/held spans to `u128`.

use std::sync::Mutex;

use brokkr_core::crypto::DualSignature;
use brokkr_core::ids::{EscalationId, Nonce, Timestamp};
use brokkr_core::resolution::{
    ChronicEscalation, EscalationType, ResolutionDecision, ResolutionVerdict, ResolveError,
    ReturnedToBaseline, resolution_signed_content,
};
use brokkr_crypto::DualPublicKey;

type PublicBytes = (Vec<u8>, Vec<u8>);

/// How ready an escalation is to resolve — the shared basis for [`ResolutionVerdict`]
/// (`may_resolve`) and [`ResolveError`] (`resolve`).
enum Readiness {
    Eligible,
    /// `(reason, is_hysteresis)` — `is_hysteresis` distinguishes a dwell/hold failure
    /// (`HysteresisNotSatisfied`) from a clear-condition failure (`CriteriaNotMet`).
    NotYet(&'static str, bool),
    Chronic,
}

struct EscalationState {
    kind: EscalationType,
    raised_at: Timestamp,
    /// When the clear condition began *continuously* holding, or `None` if not currently met.
    clear_since: Option<Timestamp>,
    active: bool,
}

struct EirState {
    escalations: Vec<EscalationState>,
    /// Nonces already accepted, keyed by `(escalation, nonce)` (OQGF-P-8.5 replay defence).
    ///
    /// **Held at the engine level, not on an `EscalationState`, and it PERSISTS across
    /// resolution and re-raising.** A nonce is recorded here only when a decision *successfully
    /// resolves*, and it is never removed — so a nonce accepted for an escalation id can never
    /// be reused for that id, even after the escalation stands down and is raised again. Were
    /// this tracked per-`EscalationState`, a re-raise would start with an empty set and a
    /// captured stand-down could be replayed against the fresh escalation — exactly the hole
    /// §6.8 warns of. Recording only on success (not on a hysteresis/criteria refusal) leaves a
    /// legitimately-refused decision free to be re-presented once its hold window elapses.
    accepted_nonces: Vec<(EscalationId, Nonce)>,
}

/// EIR.
pub struct Eir {
    /// The DAP public key a [`ResolutionDecision`]'s signature is verified under (OQGF-P-8.5).
    dap_public: PublicBytes,
    state: Mutex<EirState>,
}

impl Eir {
    pub fn new(dap_public: PublicBytes) -> Self {
        Eir {
            dap_public,
            state: Mutex::new(EirState {
                escalations: Vec::new(),
                accepted_nonces: Vec::new(),
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, EirState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Declare an escalation type and mark it active from `raised_at`. Its
    /// `resolution_criteria` and `baseline` are required fields of [`EscalationType`] (I-8),
    /// so an escalation with no way down cannot be registered.
    pub fn raise(&self, kind: EscalationType, raised_at: Timestamp) {
        let mut st = self.state();
        st.escalations.push(EscalationState {
            kind,
            raised_at,
            clear_since: None,
            active: true,
        });
    }

    /// Record that an escalation's clear condition began holding at `since` (or stopped, via
    /// [`Eir::clear_condition_unmet`]). Fed by the orchestrator; hysteresis measures from here.
    pub fn clear_condition_met(&self, id: &EscalationId, since: Timestamp) {
        let mut st = self.state();
        if let Some(e) = st
            .escalations
            .iter_mut()
            .find(|e| e.active && e.kind.id == *id)
        {
            e.clear_since = Some(since);
        }
    }

    pub fn clear_condition_unmet(&self, id: &EscalationId) {
        let mut st = self.state();
        if let Some(e) = st
            .escalations
            .iter_mut()
            .find(|e| e.active && e.kind.id == *id)
        {
            e.clear_since = None;
        }
    }

    /// Classify an escalation's readiness against the injected `now`.
    fn classify(&self, now: Timestamp, e: &EscalationState) -> Readiness {
        let elapsed_ms = u128::from(now.0.saturating_sub(e.raised_at.0));
        let past_max = elapsed_ms > e.kind.max_duration.as_millis();

        let eligible = match e.clear_since {
            None => false,
            Some(since) => {
                let held_ms = u128::from(now.0.saturating_sub(since.0));
                elapsed_ms >= e.kind.dwell_min.as_millis()
                    && held_ms >= e.kind.hold_window.as_millis()
            }
        };

        if eligible {
            Readiness::Eligible
        } else if past_max {
            Readiness::Chronic
        } else {
            match e.clear_since {
                None => Readiness::NotYet("clear condition not met (OQGF-P-8.1)", false),
                Some(since) => {
                    let held_ms = u128::from(now.0.saturating_sub(since.0));
                    if elapsed_ms < e.kind.dwell_min.as_millis() {
                        Readiness::NotYet("minimum dwell not elapsed (OQGF-P-8.3)", true)
                    } else if held_ms < e.kind.hold_window.as_millis() {
                        Readiness::NotYet(
                            "clear condition has not held long enough (OQGF-P-8.3)",
                            true,
                        )
                    } else {
                        // eligible would have been true; unreachable in practice, fail-safe.
                        Readiness::NotYet("not resolvable", false)
                    }
                }
            }
        }
    }
}

fn verify_under(key: &PublicBytes, msg: &[u8], sig: &DualSignature) -> bool {
    match DualPublicKey::from_public_bytes(&key.0, &key.1) {
        Ok(pk) => pk.verify_dual(msg, sig).is_ok(),
        Err(_) => false,
    }
}

/// The time-dependent operations. **These are inherent methods, not a `ResolutionEngine` trait
/// impl, and each takes `now` as a parameter of the evaluating call (I-13).** The committed
/// core `ResolutionEngine` trait carries no `now` and cannot gain one without a core change
/// that also breaks core's own `MockResolutionEngine` test (out of scope); a held `now` field is
/// the only alternative, and that is exactly the defect I-13 forbids (RISK-2026-0006). EIR
/// therefore supersedes the trait with `now`-aware inherent methods. See the revision report.
impl Eir {
    /// May this escalation de-escalate, evaluated against the call-site `now` (I-13)?
    pub fn may_resolve(&self, escalation: &EscalationId, now: Timestamp) -> ResolutionVerdict {
        let st = self.state();
        match st
            .escalations
            .iter()
            .find(|e| e.active && e.kind.id == *escalation)
        {
            None => ResolutionVerdict::NotYet {
                reason: "unknown or inactive escalation".to_string(),
            },
            Some(e) => match self.classify(now, e) {
                // Above baseline, de-escalation always needs DAP confirmation (OQGF-P-8.5).
                Readiness::Eligible => ResolutionVerdict::Eligible { needs_dap: true },
                Readiness::NotYet(reason, _) => ResolutionVerdict::NotYet {
                    reason: reason.to_string(),
                },
                Readiness::Chronic => ResolutionVerdict::Chronic,
            },
        }
    }

    /// De-escalate — but only on a genuinely DAP-confirmed, fresh, non-replayed decision.
    ///
    /// **Check order (first-failing reason returned, §6.8 as reordered in Rev 1.16):**
    /// 1. **Signature** — verified over `brokkr_core::resolution::resolution_signed_content` (the
    ///    *one* encoding the issuer signs and the verifier checks). An unverifiable decision is
    ///    not DAP-confirmed → `NeedsDapConfirmation`. This is first because the other fields of an
    ///    unauthenticated decision — including its `nonce` and `expiry` — are untrustworthy.
    /// 2. **Expiry** — `now > expiry` → `Expired`. **Before** replay (Rev 1.16): a decision
    ///    reaching a replay-first expiry check must carry an unseen nonce, so an
    ///    expired-and-previously-accepted decision was refused as `ReplayedNonce` and the
    ///    `Expired` arm became unreachable for the case it exists to catch. Expiry and replay do
    ///    not overlap in practice (an expiry is a fresh decision arriving late, never a replayed
    ///    one), so a decision that is somehow both reports `Expired` — too old to act on is too
    ///    old regardless of how many times it has been seen. `now` is the call parameter (I-13).
    /// 3. **Replay** — a `(escalation, nonce)` already accepted → `ReplayedNonce` (the attack:
    ///    an authentic, DAP-confirmed stand-down presented again).
    /// 4. **Something to resolve** — no active escalation with this id → `CriteriaNotMet`.
    /// 5. **Readiness** — a premature stand-down is refused (`HysteresisNotSatisfied` /
    ///    `CriteriaNotMet`); where uncertain the system stays escalated (OQGF-P-8.5). A chronic
    ///    escalation may be stood down by a DAP-confirmed decision (OQGF-P-8.6).
    ///
    /// The nonce is recorded as accepted **only on success**, so a decision refused for
    /// hysteresis may be re-presented once its hold window elapses; a decision that actually
    /// lowered a defence can never be replayed. Marking the escalation inactive erases no
    /// incident record or detector — EIR holds none (OQGF-P-8.4).
    pub fn resolve(
        &self,
        d: ResolutionDecision,
        now: Timestamp,
    ) -> Result<ReturnedToBaseline, ResolveError> {
        // 1. Authenticity.
        let body = resolution_signed_content(&d);
        if !verify_under(&self.dap_public, &body, &d.signature) {
            return Err(ResolveError::NeedsDapConfirmation);
        }

        let mut st = self.state();

        // 2. Expiry (latency) before 3. replay (attack) — Rev 1.16.
        if now.0 > d.expiry.0 {
            return Err(ResolveError::Expired);
        }
        if st
            .accepted_nonces
            .iter()
            .any(|(e, n)| *e == d.escalation && *n == d.nonce)
        {
            return Err(ResolveError::ReplayedNonce);
        }

        // 4. Something to resolve.
        let idx = st
            .escalations
            .iter()
            .position(|e| e.active && e.kind.id == d.escalation)
            .ok_or(ResolveError::CriteriaNotMet)?;

        // 5. Readiness.
        let readiness = {
            let e = st
                .escalations
                .get(idx)
                .ok_or(ResolveError::CriteriaNotMet)?;
            self.classify(now, e)
        };

        match readiness {
            Readiness::Eligible | Readiness::Chronic => {
                if let Some(e) = st.escalations.get_mut(idx) {
                    e.active = false;
                }
                // Accept the nonce ONLY now that the decision has lowered a defence.
                st.accepted_nonces.push((d.escalation.clone(), d.nonce));
                Ok(ReturnedToBaseline {
                    escalation: d.escalation,
                })
            }
            Readiness::NotYet(_, true) => Err(ResolveError::HysteresisNotSatisfied),
            Readiness::NotYet(_, false) => Err(ResolveError::CriteriaNotMet),
        }
    }

    /// Escalations past their declared `max_duration` without resolving (OQGF-P-8.6). A chronic
    /// finding IS host harm: it surfaces here as a value, and the orchestrator (Phase 11)
    /// raises it through the graded-response path (a raise-only Signal) and records it — EIR
    /// produces the finding; it does not emit or record (out of scope this phase).
    pub fn scan_chronic(&self, now: Timestamp) -> Vec<ChronicEscalation> {
        let st = self.state();
        st.escalations
            .iter()
            .filter(|e| e.active)
            .filter(|e| {
                u128::from(now.0.saturating_sub(e.raised_at.0)) > e.kind.max_duration.as_millis()
            })
            .map(|e| ChronicEscalation {
                escalation: e.kind.id.clone(),
            })
            .collect()
    }
}
