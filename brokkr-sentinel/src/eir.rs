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
//! `now` is **injected**, never a wall-clock read. `Duration` (nanoseconds) is compared against
//! `Timestamp` (epoch milliseconds) by widening the millisecond elapsed/held spans to `u128`.

use std::sync::Mutex;

use brokkr_core::crypto::DualSignature;
use brokkr_core::ids::{EscalationId, Timestamp};
use brokkr_core::resolution::{
    ChronicEscalation, EscalationType, ResolutionDecision, ResolutionEngine, ResolutionVerdict,
    ResolveError, ReturnedToBaseline,
};
use brokkr_crypto::DualPublicKey;

use crate::canonical;

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
    now: Timestamp,
    escalations: Vec<EscalationState>,
}

/// EIR.
pub struct Eir {
    /// The DAP public key a [`ResolutionDecision`]'s signature is verified under (OQGF-P-8.5).
    dap_public: PublicBytes,
    state: Mutex<EirState>,
}

impl Eir {
    pub fn new(dap_public: PublicBytes, now: Timestamp) -> Self {
        Eir {
            dap_public,
            state: Mutex::new(EirState {
                now,
                escalations: Vec::new(),
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, EirState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn set_now(&self, now: Timestamp) {
        self.state().now = now;
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

impl ResolutionEngine for Eir {
    fn may_resolve(&self, escalation: &EscalationId) -> ResolutionVerdict {
        let st = self.state();
        let now = st.now;
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

    /// De-escalate — but only on a genuinely DAP-confirmed decision. The signature is verified
    /// first: an unverifiable decision is refused with `NeedsDapConfirmation` (the asymmetry).
    /// Resolution additionally requires readiness — a premature stand-down is refused
    /// (`HysteresisNotSatisfied` / `CriteriaNotMet`), because where uncertain the system stays
    /// escalated (OQGF-P-8.5). A chronic escalation may be stood down by a DAP-confirmed
    /// decision (its re-justification/resolution, OQGF-P-8.6). Marking the escalation inactive
    /// erases no incident record or detector — EIR holds none (OQGF-P-8.4).
    fn resolve(&self, d: ResolutionDecision) -> Result<ReturnedToBaseline, ResolveError> {
        let body = canonical::resolution_signed_content(&d);
        if !verify_under(&self.dap_public, &body, &d.signature) {
            return Err(ResolveError::NeedsDapConfirmation);
        }

        let mut st = self.state();
        let now = st.now;
        let idx = st
            .escalations
            .iter()
            .position(|e| e.active && e.kind.id == d.escalation)
            .ok_or(ResolveError::CriteriaNotMet)?;

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
    fn scan_chronic(&self) -> Vec<ChronicEscalation> {
        let st = self.state();
        let now = st.now;
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
