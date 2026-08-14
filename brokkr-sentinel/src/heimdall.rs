//! HEIMDALL — the Sentinel, Tolerance Controller, and Host-Harm Monitor (Organ 2's heuristic
//! layer, OQGF-I-6; cross-hop reconciliation, OQGF-M-12).
//!
//! HEIMDALL is **fed** observations, detectors, a Self Set corpus, confirmed incidents, and a
//! governed-action count; it does not reach into other crates (I-5). It holds a signing key
//! (to sign the raise-only Signals it emits) and the DAP's public key (to verify tolerance
//! grants). Mutable state sits behind a `Mutex`; a poisoned lock is recovered, never
//! panicked on (§6). `now` is **injected**, never read from a wall clock — determinism.

use std::sync::Mutex;

use brokkr_core::crypto::{Digest, Hasher};
use brokkr_core::ids::{GrantId, Nonce, OrganId, Timestamp};
use brokkr_core::signal::{PostureEffect, Severity, Signal, SignalClass, SignalScope};
use brokkr_core::tolerance::{
    DetectorSpec, HostHarmIncident, HostHarmReport, ScreenPass, SelfSet, StormEvent,
    ToleranceController, ToleranceError, ToleranceGrant,
};
use brokkr_crypto::{DualKeyPair, DualPublicKey, Sha384Hasher};

use crate::canonical;
use crate::observation::{DetectionVerdict, Detector, Observation, SelfSetCorpus};

/// Raw dual-family public bytes `(ml_dsa_65, slh_dsa_shake_192s)`.
type PublicBytes = (Vec<u8>, Vec<u8>);

/// The result of assessing a single response's magnitude against the declared blast radius
/// (OQGF-P-5b). `Unenforceable` is the **"say so"** case: with no declared radius the storm
/// bound cannot be exceeded, so the monitor reports the gap rather than a false "no storm".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StormAssessment {
    /// Magnitude within the declared blast radius.
    Within,
    /// Magnitude exceeds the declared blast radius — a storm regardless of target.
    Exceeds(StormEvent),
    /// No blast radius was declared; P-5b is unenforceable and the monitor says so.
    Unenforceable,
}

struct HeimdallState {
    /// Injected evaluation time (never a wall-clock read).
    now: Timestamp,
    /// Detectors HEIMDALL has been given, resolved by id during screening.
    detectors: Vec<Box<dyn Detector>>,
    /// Denominator of the current host-harm window: governed actions evaluated.
    governed: u64,
    /// Numerator of the current window: DAP-confirmed false positives.
    incidents: Vec<HostHarmIncident>,
    /// Consecutive closed windows whose rate breached the bound (sustained-ness, P-5a).
    over_bound_streak: u32,
    /// The most recent storm assessed, surfaced in the report's `storm` field.
    last_storm: Option<StormEvent>,
}

/// HEIMDALL.
pub struct Heimdall {
    corpus: Box<dyn SelfSetCorpus>,
    /// The DAP public key tolerance grants are verified under (OQGF-P-4).
    dap_public: PublicBytes,
    /// HEIMDALL's own signing key, for the raise-only Signals it emits.
    signing: DualKeyPair,
    /// The DAP-declared host-harm ceiling (OQGF-P-1), injected — never inferred.
    bound: f64,
    /// The DAP-declared blast radius (OQGF-P-5b), injected. `None` = undeclared → storm
    /// detection is unenforceable and says so.
    blast_radius: Option<u64>,
    /// How many consecutive over-bound windows constitute a *sustained* breach (P-5a). §6.7
    /// and AMD-002 do not define "sustained" numerically; rather than choose a threshold, it
    /// is a DAP-declared injected parameter, the same posture as `bound`.
    sustained_threshold: u32,
    state: Mutex<HeimdallState>,
}

impl Heimdall {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        corpus: Box<dyn SelfSetCorpus>,
        dap_public: PublicBytes,
        signing: DualKeyPair,
        bound: f64,
        blast_radius: Option<u64>,
        sustained_threshold: u32,
        now: Timestamp,
    ) -> Self {
        Heimdall {
            corpus,
            dap_public,
            signing,
            bound,
            blast_radius,
            sustained_threshold,
            state: Mutex::new(HeimdallState {
                now,
                detectors: Vec::new(),
                governed: 0,
                incidents: Vec::new(),
                over_bound_streak: 0,
                last_storm: None,
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, HeimdallState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Inject the current evaluation time (the orchestrator's clock, Phase 11).
    pub fn set_now(&self, now: Timestamp) {
        self.state().now = now;
    }

    /// Register a detector HEIMDALL may screen and run.
    pub fn register_detector(&self, detector: Box<dyn Detector>) {
        self.state().detectors.push(detector);
    }

    /// Record that a governed action was evaluated (the host-harm denominator). HEIMDALL is
    /// **told** this by the orchestrator (Phase 11); it does not count by reaching into the
    /// gate or the barrier (I-5).
    pub fn record_governed_action(&self) {
        let mut st = self.state();
        st.governed = st.governed.saturating_add(1);
    }

    /// Record a DAP-confirmed host-harm incident (the numerator).
    pub fn record_incident(&self, incident: HostHarmIncident) {
        self.state().incidents.push(incident);
    }

    /// Close the current host-harm window: if the window's rate breached the bound, extend
    /// the over-bound streak (sustained-ness); otherwise reset it. Then clear the window's
    /// counts. The orchestrator calls this at each window boundary (Phase 11).
    pub fn roll_window(&self) {
        let mut st = self.state();
        let breached = match window_rate(st.governed, st.incidents.len() as u64) {
            r if r.is_nan() => false, // no evidence is not a breach
            r => r > self.bound,
        };
        st.over_bound_streak = if breached {
            st.over_bound_streak.saturating_add(1)
        } else {
            0
        };
        st.governed = 0;
        st.incidents.clear();
    }

    /// Assess one response's magnitude against the declared blast radius (OQGF-P-5b).
    pub fn assess_response(&self, magnitude: u64) -> StormAssessment {
        match self.blast_radius {
            None => StormAssessment::Unenforceable,
            Some(radius) if magnitude > radius => {
                let event = StormEvent {
                    detail: format!(
                        "response magnitude {magnitude} exceeds declared blast radius {radius}"
                    ),
                };
                self.state().last_storm = Some(event.clone());
                StormAssessment::Exceeds(event)
            }
            Some(_) => StormAssessment::Within,
        }
    }

    /// Cross-hop reconciliation (OQGF-M-12): a `Hop` whose `executed` differs from its
    /// `authorized` is a deviation and yields a raise-only Signal. `executed: None` is **not**
    /// a deviation — it is the absence of a comparison (every hop before the executor exists,
    /// Phase 11). Any non-`Hop` observation yields `None`.
    pub fn reconcile(&self, observation: &Observation) -> Option<Signal> {
        match observation {
            Observation::Hop {
                authorized,
                executed: Some(executed),
            } if executed != authorized => Some(self.raise_signal(
                SignalClass::ThreatDetected,
                Severity::High,
                "cross-hop reconciliation deviation (OQGF-M-12)",
            )),
            _ => None,
        }
    }

    /// Build and sign a raise-only Signal from `OrganId::Sentinel`. `PostureEffect` has only
    /// `Raise`, so no Signal HEIMDALL emits can lower posture (OQGF-P-7.4).
    fn raise_signal(&self, class: SignalClass, severity: Severity, detail: &str) -> Signal {
        let mut signal = Signal {
            source: OrganId::Sentinel,
            class,
            severity,
            effect: PostureEffect::Raise {
                detail: detail.to_string(),
            },
            scope: SignalScope {
                detail: "sentinel".to_string(),
            },
            nonce: Nonce(0),
            expiry: Timestamp(0),
            signature: empty_dual_signature(),
        };
        let body = canonical::signal_signed_content(&signal);
        if let Ok(sig) = self.signing.sign_dual(&body) {
            signal.signature = sig;
        }
        signal
    }
}

/// The host-harm rate for one window. **Zero denominator yields `NaN`, never `0.0`** — a
/// window that evaluated no governed actions has no evidence, and a rate of `0.0` would claim
/// safety from none (Task 5). No panic: f64 division and `NAN` are total.
fn window_rate(governed: u64, incidents: u64) -> f64 {
    if governed == 0 {
        f64::NAN
    } else {
        incidents as f64 / governed as f64
    }
}

/// A well-formed but empty (invalid) dual-family signature — the fail-closed placeholder for
/// an emitted Signal if signing is unavailable (mirrors `brokkr-audit` / `Sha384Hasher`).
/// Obviously invalid, never a fabricated valid signature. The alarm still raises.
fn empty_dual_signature() -> brokkr_core::crypto::DualSignature {
    use brokkr_core::crypto::{DualSignature, Signature, SignatureAlg};
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

fn verify_under(key: &PublicBytes, msg: &[u8], sig: &brokkr_core::crypto::DualSignature) -> bool {
    match DualPublicKey::from_public_bytes(&key.0, &key.1) {
        Ok(pk) => pk.verify_dual(msg, sig).is_ok(),
        Err(_) => false,
    }
}

impl ToleranceController for Heimdall {
    /// Attach a grant to a heuristic detector (OQGF-P-4). Reached **only** for a `Heuristic`
    /// target: the sole route here is core's provided [`ToleranceController::grant`], which is
    /// NOT overridden and refuses a `Deterministic` target with `NonSuppressibleGate` before
    /// this method is called (OQGF-P-2). A grant SHALL be signed, scoped, and expiring:
    ///
    /// - **signed** — the dual-family signature over the grant's signed content is verified
    ///   under the declared DAP key. `ToleranceError` has no signature-failure variant, so an
    ///   unauthentic grant — one not validly signed by the DAP — carries no authorized scope
    ///   and is refused as `OutOfScope` (fail-closed; see the phase report for the flagged
    ///   naming imprecision).
    /// - **expiring** — `now > expiry` → `Expired`.
    /// - **scoped** — an empty (blanket) scope is not narrow (OQGF-P-4 "never blanket") →
    ///   `OutOfScope`.
    fn grant_heuristic(&self, grant: ToleranceGrant) -> Result<GrantId, ToleranceError> {
        // Ordered checks, first-failing reason returned (§6.7). Signature first: a grant that
        // is not authentically the DAP's is refused **as forged** (`SignatureInvalid`, Rev 1.12)
        // — not as `OutOfScope`, which would report a scope verdict that was never evaluated.
        let body = canonical::grant_signed_content(&grant);
        if !verify_under(&self.dap_public, &body, &grant.signature) {
            return Err(ToleranceError::SignatureInvalid);
        }
        if grant.scope.detail.is_empty() {
            return Err(ToleranceError::OutOfScope);
        }
        if self.state().now.0 > grant.expiry.0 {
            return Err(ToleranceError::Expired);
        }
        Ok(GrantId::new(grant.target.as_str()))
    }

    /// Screen a detector against the Self Set before deployment (OQGF-P-3). The digest check
    /// is load-bearing (Task 3):
    ///
    /// 1. The corpus version SHALL match the declared `SelfSet`.
    /// 2. The digest **recomputed** over `corpus.observations()` SHALL equal
    ///    `SelfSet.corpus_digest`. A mismatch is `FailsCentralTolerance` and **nothing is
    ///    run** — this closes the substituted-corpus attack (a corpus quietly chosen to
    ///    contain nothing the detector fires on).
    /// 3. The detector runs over every observation. A **single** firing fails: the Self Set
    ///    is by declaration legitimate activity, so one hit is a demonstrated false positive.
    fn screen(
        &self,
        detector: &DetectorSpec,
        self_set: &SelfSet,
    ) -> Result<ScreenPass, ToleranceError> {
        if self.corpus.version() != self_set.version {
            return Err(ToleranceError::FailsCentralTolerance);
        }
        let recomputed = self.corpus_digest();
        if recomputed != self_set.corpus_digest {
            return Err(ToleranceError::FailsCentralTolerance);
        }
        let st = self.state();
        let Some(d) = st.detectors.iter().find(|d| *d.id() == detector.id) else {
            // No certification without an actual run over a verified corpus (fail-closed).
            return Err(ToleranceError::FailsCentralTolerance);
        };
        for observation in self.corpus.observations() {
            if let DetectionVerdict::Fired { .. } = d.observe(observation) {
                return Err(ToleranceError::FailsCentralTolerance);
            }
        }
        Ok(ScreenPass {
            version: self_set.version.clone(),
        })
    }

    /// The current host-harm posture (OQGF-P-1, OQGF-P-5). `rate` is a **lower bound** — it
    /// counts only confirmed false positives (§13). `autoimmunity` is a **sustained** breach:
    /// the over-bound streak has reached the DAP-declared threshold (not a single sample,
    /// P-5a). `storm` carries the most recent assessed storm.
    fn host_harm(&self) -> HostHarmReport {
        let st = self.state();
        HostHarmReport {
            rate: window_rate(st.governed, st.incidents.len() as u64),
            bound: self.bound,
            autoimmunity: st.over_bound_streak >= self.sustained_threshold,
            storm: st.last_storm.clone(),
        }
    }
}

impl Heimdall {
    /// The digest recomputed over the corpus's observations (not the corpus's self-reported
    /// digest). This is the binding screening checks against the declared `SelfSet`.
    fn corpus_digest(&self) -> Digest {
        Sha384Hasher.hash(&canonical::corpus_signed_content(
            self.corpus.observations(),
        ))
    }
}
