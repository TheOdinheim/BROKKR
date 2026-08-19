//! HEIMDALL + EIR functionality and structural tests — real wolfSSL v5.9.2 (non-FIPS) through
//! `brokkr-crypto` where signatures are involved, no mocks.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use brokkr_sentinel::canonical::{corpus_signed_content, grant_signed_content};
use brokkr_sentinel::{
    Detection, DetectionVerdict, Detector, Eir, Heimdall, Observation, SelfSetCorpus,
    StormAssessment,
};

use brokkr_core::crypto::{Digest, Hasher};
use brokkr_core::gate::{Action, AnergyReason};
use brokkr_core::ids::{Dap, DetectorId, EscalationId, Nonce, SelfSetVersion, Timestamp, ToolId};
use brokkr_core::resolution::{
    BaselinePosture, ClearCondition, ClearEvidence, EscalationType, ResolutionDecision,
    ResolutionVerdict, ResolveError, resolution_signed_content,
};
use brokkr_core::signal::PostureEffect;
use brokkr_core::tolerance::{
    DetectorSpec, ResponseClass, SelfSet, SuppressionScope, ToleranceError, ToleranceGrant,
};
use brokkr_crypto::{DualKeyPair, Sha384Hasher};

// ---- helpers -------------------------------------------------------------------------

fn dap() -> Dap {
    Dap::new("Jeremy Rose", "dap-1")
}

fn authz(tool: &str, granted: bool) -> Observation {
    Observation::Authorization {
        action: Action {
            tool: ToolId::new(tool),
            detail: "d".to_string(),
        },
        granted,
        anergy: if granted {
            None
        } else {
            Some(AnergyReason::OutOfScope)
        },
    }
}

fn corpus_obs() -> Vec<Observation> {
    vec![
        authz("read", true),
        authz("write", true),
        authz("list", true),
    ]
}

/// A test-double Self Set corpus (§6.7 "a test double serves the tests").
struct TestCorpus {
    version: SelfSetVersion,
    obs: Vec<Observation>,
}
impl SelfSetCorpus for TestCorpus {
    fn version(&self) -> SelfSetVersion {
        self.version.clone()
    }
    fn observations(&self) -> &[Observation] {
        &self.obs
    }
    fn digest(&self) -> Digest {
        Sha384Hasher.hash(&corpus_signed_content(&self.obs))
    }
}

/// A detector that never fires.
struct AlwaysClear(DetectorId);
impl Detector for AlwaysClear {
    fn id(&self) -> &DetectorId {
        &self.0
    }
    fn observe(&self, _o: &Observation) -> DetectionVerdict {
        DetectionVerdict::Clear
    }
}

/// A detector that fires on any observation.
struct FiresAlways(DetectorId);
impl Detector for FiresAlways {
    fn id(&self) -> &DetectorId {
        &self.0
    }
    fn observe(&self, _o: &Observation) -> DetectionVerdict {
        DetectionVerdict::Fired {
            severity: brokkr_core::signal::Severity::High,
            detail: "fired".to_string(),
        }
    }
}

/// A detector that records whether it was ever shown an observation.
struct Spy {
    id: DetectorId,
    observed: Arc<AtomicBool>,
}
impl Detector for Spy {
    fn id(&self) -> &DetectorId {
        &self.id
    }
    fn observe(&self, _o: &Observation) -> DetectionVerdict {
        self.observed.store(true, Ordering::SeqCst);
        DetectionVerdict::Clear
    }
}

fn public_of(kp: &DualKeyPair) -> (Vec<u8>, Vec<u8>) {
    kp.public_key_bytes().unwrap()
}

/// A Heimdall over a matching corpus, with a DAP key and a bound. **No `now`** — HEIMDALL holds
/// no clock (I-13); the evaluation time arrives per call to `observe`.
fn heimdall_with(
    obs: Vec<Observation>,
    dap_kp: &DualKeyPair,
    bound: f64,
    blast_radius: Option<u64>,
    sustained: u32,
) -> Heimdall {
    let corpus = Box::new(TestCorpus {
        version: SelfSetVersion::new("v1"),
        obs,
    });
    Heimdall::new(
        corpus,
        public_of(dap_kp),
        DualKeyPair::generate().unwrap(),
        bound,
        blast_radius,
        sustained,
    )
}

/// The declared SelfSet whose digest matches `obs`.
fn matching_selfset(obs: &[Observation]) -> SelfSet {
    SelfSet {
        version: SelfSetVersion::new("v1"),
        corpus_digest: Sha384Hasher.hash(&corpus_signed_content(obs)),
        owner: dap(),
    }
}

fn signed_grant(target: &str, scope: &str, expiry: u64, dap_kp: &DualKeyPair) -> ToleranceGrant {
    let mut g = ToleranceGrant {
        target: DetectorId::new(target),
        scope: SuppressionScope {
            detail: scope.to_string(),
        },
        dap: dap(),
        issued: Timestamp(0),
        expiry: Timestamp(expiry),
        signature: dummy_dual(),
    };
    g.signature = dap_kp.sign_dual(&grant_signed_content(&g)).unwrap();
    g
}

fn dummy_dual() -> brokkr_core::crypto::DualSignature {
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

fn escalation(id: &str, dwell: u64, hold: u64, max: u64) -> EscalationType {
    EscalationType::new(
        EscalationId::new(id),
        ClearCondition {
            detail: "clear".to_string(),
        },
        BaselinePosture {
            detail: "baseline".to_string(),
        },
        Duration::from_millis(dwell),
        Duration::from_millis(hold),
        Duration::from_millis(max),
    )
}

fn signed_decision(
    id: &str,
    at: u64,
    nonce: u64,
    expiry: u64,
    signer: &DualKeyPair,
) -> ResolutionDecision {
    let mut d = ResolutionDecision::new(
        EscalationId::new(id),
        ClearEvidence {
            detail: "cleared".to_string(),
        },
        dap(),
        Timestamp(at),
        Nonce(nonce),
        Timestamp(expiry),
        dummy_dual(),
    );
    // Sign over CORE's canonical encoding — the same bytes EIR verifies over (Rev 1.12).
    d.signature = signer.sign_dual(&resolution_signed_content(&d)).unwrap();
    d
}

/// The single firing in a one-detector loop result (helper for the loop tests).
fn only(detections: &[Detection]) -> &Detection {
    assert_eq!(detections.len(), 1, "expected exactly one detection");
    &detections[0]
}

// ---- OQGF-P-2 — the central property -------------------------------------------------

#[test]
fn test_oqgf_p_2_tolerance_refuses_deterministic_target() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);
    let grant = signed_grant("det-1", "signal:x", 1000, &dap_kp);
    // core's provided `grant` (NOT overridden) refuses a Deterministic target before
    // grant_heuristic is ever reached.
    let r = h.grant(grant, ResponseClass::Deterministic);
    assert_eq!(r, Err(ToleranceError::NonSuppressibleGate));
}

// ---- OQGF-I-6 / OQGF-P-4 — the evaluation loop (new in Rev 1.16) ----------------------

#[test]
fn test_oqgf_i_6_registered_detector_fires_on_observation() {
    // THE TEST THAT COULD NOT HAVE BEEN WRITTEN BEFORE — Phase 8 never ran detectors outside
    // screening, so a registered detector firing on a live observation had no path. Now it does:
    // a registered detector that fires produces a Detection with a raise-only Signal.
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);
    h.register_detector(Box::new(FiresAlways(DetectorId::new("det-1"))));

    let detections = h.observe(&authz("read", true), Timestamp(500));
    let d = only(&detections);
    assert_eq!(d.detector, DetectorId::new("det-1"));
    assert!(d.suppressed_by.is_none(), "no grant, so not suppressed");
    let signal = d
        .signal
        .as_ref()
        .expect("an unsuppressed firing raises a Signal");
    assert!(matches!(signal.effect, PostureEffect::Raise { .. }));
}

#[test]
fn test_oqgf_p_4_live_grant_suppresses_and_records() {
    // A live grant scoped to the firing detector suppresses it — and the Detection is STILL
    // returned, carrying `suppressed_by` and no Signal. Discarding it would make a grant
    // indistinguishable from a detector that was never registered.
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);
    h.register_detector(Box::new(FiresAlways(DetectorId::new("det-1"))));
    assert!(
        h.grant(
            signed_grant("det-1", "signal:x", 5000, &dap_kp),
            ResponseClass::Heuristic
        )
        .is_ok()
    );

    let detections = h.observe(&authz("read", true), Timestamp(1000)); // now < expiry 5000
    let d = only(&detections);
    assert!(
        d.suppressed_by.is_some(),
        "a live grant suppresses the firing"
    );
    assert!(d.signal.is_none(), "a suppressed firing raises nothing");
}

#[test]
fn test_oqgf_p_4_i13_expired_grant_stops_suppressing() {
    // THE LOAD-BEARING TEST — this is the one that fails toward BLINDNESS if the expiry is
    // checked against a held clock: a grant that never expires silences a detector forever. ONE
    // HEIMDALL, the SAME grant, the SAME firing observation, `observe` at two times: suppressed
    // before the grant's expiry, RAISING after. A held clock is a single stored value and cannot
    // produce two outcomes from one instance.
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);
    h.register_detector(Box::new(FiresAlways(DetectorId::new("det-1"))));
    assert!(
        h.grant(
            signed_grant("det-1", "signal:x", 5000, &dap_kp),
            ResponseClass::Heuristic
        )
        .is_ok()
    );
    let obs = authz("read", true);

    // now (1000) <= expiry (5000): suppressed, no Signal.
    let before = only(&h.observe(&obs, Timestamp(1000))).clone();
    assert!(before.suppressed_by.is_some(), "live grant suppresses");
    assert!(before.signal.is_none());

    // SAME instance, SAME grant, now (10000) > expiry (5000): the grant is spent; the firing
    // RAISES. If this raised nothing, the detector would be silenced forever.
    let after = only(&h.observe(&obs, Timestamp(10_000))).clone();
    assert!(
        after.suppressed_by.is_none(),
        "an expired grant no longer suppresses"
    );
    assert!(
        after.signal.is_some(),
        "the firing raises once the grant is spent — not silenced forever"
    );
}

#[test]
fn test_oqgf_p_4_out_of_scope_grant_does_not_suppress() {
    // A live grant scoped to a DIFFERENT detector does not silence this one.
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);
    h.register_detector(Box::new(FiresAlways(DetectorId::new("det-1"))));
    assert!(
        h.grant(
            signed_grant("det-2", "signal:x", 5000, &dap_kp),
            ResponseClass::Heuristic
        )
        .is_ok()
    );

    let d = only(&h.observe(&authz("read", true), Timestamp(1000))).clone();
    assert!(
        d.suppressed_by.is_none(),
        "a grant for det-2 does not suppress det-1"
    );
    assert!(d.signal.is_some());
}

// ---- OQGF-P-4 — grant validation and retention ---------------------------------------

#[test]
fn test_oqgf_p_4_valid_grant_attaches_on_heuristic() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);
    let grant = signed_grant("det-1", "signal:x", 1000, &dap_kp);
    assert!(h.grant(grant, ResponseClass::Heuristic).is_ok());
}

#[test]
fn test_oqgf_p_4_expired_grant_is_retained_not_refused_at_issuance() {
    // CHANGED (Rev 1.16): grant_heuristic no longer checks expiry at issuance — `now` is not
    // available there and checking an expiry against a held clock is the defect being removed.
    // An already-expired grant is RETAINED (and recorded, OQGF-P-9.5); the `now <= expiry`
    // liveness check moved to the loop (`observe`), where it never suppresses. So issuance
    // succeeds; the loop is what refuses to suppress on an expired grant
    // (test_oqgf_p_4_i13_expired_grant_stops_suppressing).
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);
    let grant = signed_grant("det-1", "signal:x", 1000, &dap_kp); // expiry 1000, past for now=2000
    assert!(
        h.grant(grant, ResponseClass::Heuristic).is_ok(),
        "an expired grant is retained at issuance, not refused"
    );
    // And it suppresses nothing: register the detector and observe well after the expiry.
    h.register_detector(Box::new(FiresAlways(DetectorId::new("det-1"))));
    let d = only(&h.observe(&authz("read", true), Timestamp(2000))).clone();
    assert!(
        d.suppressed_by.is_none(),
        "a retained expired grant does not suppress"
    );
}

#[test]
fn test_oqgf_p_4_forged_grant_reports_signature_invalid() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let attacker = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);
    // Signed by the attacker, not the DAP → not authentic → SignatureInvalid (Rev 1.12).
    let grant = signed_grant("det-1", "signal:x", 1000, &attacker);
    assert_eq!(
        h.grant(grant, ResponseClass::Heuristic),
        Err(ToleranceError::SignatureInvalid)
    );
}

#[test]
fn test_oqgf_p_4_blanket_scope_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);
    let grant = signed_grant("det-1", "", 1000, &dap_kp); // empty scope = blanket
    assert_eq!(
        h.grant(grant, ResponseClass::Heuristic),
        Err(ToleranceError::OutOfScope)
    );
}

// ---- OQGF-P-3 — screening ------------------------------------------------------------

#[test]
fn test_oqgf_p_3_single_firing_fails_screening() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let obs = corpus_obs();
    let h = heimdall_with(obs.clone(), &dap_kp, 0.1, Some(10), 2);
    h.register_detector(Box::new(FiresAlways(DetectorId::new("d"))));
    let r = h.screen(
        &DetectorSpec {
            id: DetectorId::new("d"),
        },
        &matching_selfset(&obs),
        Timestamp(1_000),
    );
    assert_eq!(r, Err(ToleranceError::FailsCentralTolerance));
}

#[test]
fn test_screening_passes_when_detector_clears() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let obs = corpus_obs();
    let h = heimdall_with(obs.clone(), &dap_kp, 0.1, Some(10), 2);
    h.register_detector(Box::new(AlwaysClear(DetectorId::new("d"))));
    let r = h.screen(
        &DetectorSpec {
            id: DetectorId::new("d"),
        },
        &matching_selfset(&obs),
        Timestamp(1_000),
    );
    assert!(r.is_ok());
}

#[test]
fn test_oqgf_p_6_3_i13_screen_pass_carries_screened_version_and_call_site_now() {
    // Phase-9 Gate 3 (OQGF-P-6.3) will check a ScreenPass by the Self Set version it screened
    // against; I-13 requires the produced-at time to be the per-call `now`, never a held clock.
    // A pass recording the wrong version, or a default/held time, would let a stale screening
    // activate a detector — which is the failure this small property exists to foreclose.
    let dap_kp = DualKeyPair::generate().unwrap();
    let obs = corpus_obs();
    let h = heimdall_with(obs.clone(), &dap_kp, 0.1, Some(10), 2);
    h.register_detector(Box::new(AlwaysClear(DetectorId::new("d"))));
    let selfset = matching_selfset(&obs);

    let pass = h
        .screen(
            &DetectorSpec {
                id: DetectorId::new("d"),
            },
            &selfset,
            Timestamp(4242),
        )
        .expect("a clearing detector passes screening");

    // The version is the Self Set actually screened against — not a default or a copy.
    assert_eq!(pass.version, selfset.version);
    assert_eq!(pass.version, SelfSetVersion::new("v1"));
    // produced_at is exactly the `now` handed to this evaluating call (I-13) — never held.
    assert_eq!(pass.produced_at, Timestamp(4242));
}

#[test]
fn test_oqgf_p_3_substituted_corpus_is_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    // Heimdall holds a SUBSTITUTED (benign) corpus.
    let substituted = vec![authz("nothing", true)];
    let h = heimdall_with(substituted, &dap_kp, 0.1, Some(10), 2);

    let flag = Arc::new(AtomicBool::new(false));
    h.register_detector(Box::new(Spy {
        id: DetectorId::new("d"),
        observed: flag.clone(),
    }));

    // The declared SelfSet digest is over the REAL corpus (different bytes), same version.
    let declared = matching_selfset(&corpus_obs());
    let r = h.screen(
        &DetectorSpec {
            id: DetectorId::new("d"),
        },
        &declared,
        Timestamp(1_000),
    );
    assert_eq!(r, Err(ToleranceError::FailsCentralTolerance));
    // NOTHING was run — the digest check fails before any observation reaches the detector.
    assert!(
        !flag.load(Ordering::SeqCst),
        "no detector may run against a substituted corpus"
    );
}

// ---- OQGF-P-1, P-5 — host harm -------------------------------------------------------

#[test]
fn test_host_harm_zero_denominator() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);
    let report = h.host_harm();
    // No governed actions evaluated → rate is undefined (NaN), never 0.0 (false safety).
    assert!(
        report.rate.is_nan(),
        "zero-denominator rate must be NaN, not 0.0"
    );
    assert!(!report.autoimmunity);
}

#[test]
fn test_oqgf_p_5_storm_needs_declared_radius() {
    let dap_kp = DualKeyPair::generate().unwrap();
    // Unconfigured radius.
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, None, 2);
    assert_eq!(h.assess_response(1_000_000), StormAssessment::Unenforceable);

    // Configured radius: exceed and within.
    let h2 = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);
    assert!(matches!(
        h2.assess_response(100),
        StormAssessment::Exceeds(_)
    ));
    assert_eq!(h2.assess_response(5), StormAssessment::Within);
}

#[test]
fn test_host_harm_autoimmunity_is_sustained_not_single() {
    let dap_kp = DualKeyPair::generate().unwrap();
    // sustained_threshold = 3 consecutive over-bound windows.
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 3);
    // One over-bound window: 1 incident / 1 governed = 1.0 > 0.1.
    h.record_governed_action();
    h.record_incident(brokkr_core::tolerance::HostHarmIncident {
        response: brokkr_core::tolerance::DefensiveResponse::Deny,
        action: Action {
            tool: ToolId::new("write"),
            detail: "legit".to_string(),
        },
        confirmed_by: dap(),
        at: Timestamp(1),
    });
    h.roll_window();
    assert!(
        !h.host_harm().autoimmunity,
        "one over-bound window is not sustained"
    );
    // Two more → streak reaches the threshold of 3.
    for _ in 0..2 {
        h.record_governed_action();
        h.record_incident(brokkr_core::tolerance::HostHarmIncident {
            response: brokkr_core::tolerance::DefensiveResponse::Anergy,
            action: Action {
                tool: ToolId::new("x"),
                detail: "legit".to_string(),
            },
            confirmed_by: dap(),
            at: Timestamp(1),
        });
        h.roll_window();
    }
    assert!(
        h.host_harm().autoimmunity,
        "three consecutive over-bound windows is sustained"
    );
}

// ---- OQGF-M-12 — reconciliation, now inside the loop ---------------------------------

#[test]
fn test_oqgf_m_12_mismatch_deviates_and_none_does_not() {
    // Reconciliation JOINS the loop (Rev 1.16): a deviation is a firing among the loop's output,
    // subject to the same suppression rule. The former public `reconcile` method is gone; the
    // deviation surfaces through `observe`.
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);

    let authorized = Action {
        tool: ToolId::new("write"),
        detail: "a".to_string(),
    };
    let executed_other = Action {
        tool: ToolId::new("delete"),
        detail: "b".to_string(),
    };

    // A mismatch deviates → one detection with a raise Signal.
    let mismatch = Observation::Hop {
        authorized: authorized.clone(),
        executed: Some(executed_other),
    };
    let d = only(&h.observe(&mismatch, Timestamp(0))).clone();
    let sig = d.signal.as_ref().expect("mismatch must deviate and raise");
    assert!(matches!(sig.effect, PostureEffect::Raise { .. }));

    // `executed: None` is NOT a deviation — the absence of a comparison. No detection.
    let pending = Observation::Hop {
        authorized: authorized.clone(),
        executed: None,
    };
    assert!(h.observe(&pending, Timestamp(0)).is_empty());

    // A matching hop is not a deviation either.
    let matching = Observation::Hop {
        authorized: authorized.clone(),
        executed: Some(authorized),
    };
    assert!(h.observe(&matching, Timestamp(0)).is_empty());
}

// ---- OQGF-P-8 — EIR ------------------------------------------------------------------

#[test]
fn test_oqgf_p_8_5_cannot_lower_above_baseline_without_dap() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let attacker = DualKeyPair::generate().unwrap();
    let eir = Eir::new(public_of(&dap_kp));
    eir.raise(escalation("e1", 10, 10, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(0));

    // A decision signed by the ATTACKER (not the DAP) is not DAP-confirmed.
    let forged = signed_decision("e1", 1000, 1, 1_000_000, &attacker);
    assert_eq!(
        eir.resolve(forged, Timestamp(1000)),
        Err(ResolveError::NeedsDapConfirmation)
    );
}

#[test]
fn test_resolve_succeeds_with_dap_and_eligibility() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let eir = Eir::new(public_of(&dap_kp));
    eir.raise(escalation("e1", 10, 10, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(0));

    assert!(matches!(
        eir.may_resolve(&EscalationId::new("e1"), Timestamp(1000)),
        ResolutionVerdict::Eligible { needs_dap: true }
    ));
    let decision = signed_decision("e1", 1000, 1, 1_000_000, &dap_kp);
    assert!(eir.resolve(decision, Timestamp(1000)).is_ok());
}

#[test]
fn test_oqgf_p_8_5_expired_decision_reports_expired() {
    // Valid in every respect except freshness: correctly signed, escalation eligible, but the
    // decision's expiry is in the past relative to the call-site `now` → Expired (latency, not an
    // attack). `now` is a parameter of `resolve` (I-13), not a held clock.
    let dap_kp = DualKeyPair::generate().unwrap();
    let eir = Eir::new(public_of(&dap_kp));
    eir.raise(escalation("e1", 10, 10, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(0));

    let decision = signed_decision("e1", 500, 7, 1000, &dap_kp); // expiry 1000
    assert_eq!(
        eir.resolve(decision, Timestamp(2000)), // now 2000 > expiry 1000
        Err(ResolveError::Expired)
    );
}

#[test]
fn test_oqgf_p_8_5_replayed_nonce_still_refused() {
    // Replay protection survives the Rev 1.16 reorder. A decision resolves once; presented again
    // (unexpired, same nonce) it is refused as ReplayedNonce — even after the escalation stood
    // down and was RAISED AGAIN (the accepted nonce persists across resolution and re-raising).
    let dap_kp = DualKeyPair::generate().unwrap();
    let eir = Eir::new(public_of(&dap_kp));
    eir.raise(escalation("e1", 10, 10, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(0));

    let decision = signed_decision("e1", 1000, 42, 1_000_000, &dap_kp);
    assert!(
        eir.resolve(decision.clone(), Timestamp(1000)).is_ok(),
        "first presentation resolves"
    );

    eir.raise(escalation("e1", 10, 10, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(0));
    assert_eq!(
        eir.resolve(decision, Timestamp(1000)), // unexpired, same nonce
        Err(ResolveError::ReplayedNonce)
    );
}

#[test]
fn test_oqgf_p_8_5_expired_before_replay_reports_expired() {
    // THE REORDER PROOF (Rev 1.16). A decision resolves once (its nonce is now accepted). It is
    // re-presented later, now EXPIRED. Under the old replay-first order it would report
    // ReplayedNonce and the Expired arm would be unreachable for exactly this case; under the
    // corrected order it reports Expired — too old to act on is too old regardless of how many
    // times it has been seen. This test FAILS against the pre-Rev-1.16 order.
    let dap_kp = DualKeyPair::generate().unwrap();
    let eir = Eir::new(public_of(&dap_kp));
    eir.raise(escalation("e1", 10, 10, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(0));

    // expiry 1000; accepted at now=500 (fresh).
    let decision = signed_decision("e1", 200, 99, 1000, &dap_kp);
    assert!(
        eir.resolve(decision.clone(), Timestamp(500)).is_ok(),
        "first presentation (fresh) resolves and accepts the nonce"
    );

    // Re-present the SAME decision at now=2000 > expiry 1000: expired AND replayed.
    eir.raise(escalation("e1", 10, 10, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(0));
    assert_eq!(
        eir.resolve(decision, Timestamp(2000)),
        Err(ResolveError::Expired),
        "expired-and-replayed reports Expired (expiry checked before replay)"
    );
}

#[test]
fn test_sentinel_and_core_encodings_agree() {
    // Guards against the sentinel's verification path and core's encoding ever diverging again.
    let dap_kp = DualKeyPair::generate().unwrap();
    let eir = Eir::new(public_of(&dap_kp));
    eir.raise(escalation("e1", 10, 10, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(0));

    let good = signed_decision("e1", 1000, 7, 1_000_000, &dap_kp);
    assert_eq!(
        resolution_signed_content(&good),
        resolution_signed_content(&good.clone())
    );
    assert!(
        eir.resolve(good, Timestamp(1000)).is_ok(),
        "EIR verifies over core's encoding"
    );

    // Signed over unrelated bytes → does NOT verify → not DAP-confirmed.
    let mut bad = ResolutionDecision::new(
        EscalationId::new("e1"),
        ClearEvidence {
            detail: "cleared".to_string(),
        },
        dap(),
        Timestamp(1000),
        Nonce(8),
        Timestamp(1_000_000),
        dummy_dual(),
    );
    bad.signature = dap_kp.sign_dual(b"not the resolution encoding").unwrap();
    eir.raise(escalation("e1", 10, 10, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(0));
    assert_eq!(
        eir.resolve(bad, Timestamp(1000)),
        Err(ResolveError::NeedsDapConfirmation)
    );
}

#[test]
fn test_forged_signal_cannot_stand_down() {
    // Structural: PostureEffect has ONLY Raise — no signal can express lowering (OQGF-P-7.4).
    fn is_raise_only(e: &PostureEffect) -> bool {
        match e {
            PostureEffect::Raise { .. } => true,
            // No other arm exists; adding a Lower variant would fail to compile here.
        }
    }
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2);
    let deviation = Observation::Hop {
        authorized: Action {
            tool: ToolId::new("a"),
            detail: "x".to_string(),
        },
        executed: Some(Action {
            tool: ToolId::new("b"),
            detail: "y".to_string(),
        }),
    };
    let d = only(&h.observe(&deviation, Timestamp(0))).clone();
    let sig = d.signal.as_ref().expect("deviation raises");
    assert!(
        is_raise_only(&sig.effect),
        "an emitted signal only raises posture"
    );
}

#[test]
fn test_oqgf_p_8_3_i13_hysteresis_ages() {
    // EIR hysteresis two-verdict (I-13): ONE instance, the SAME escalation, `may_resolve` at two
    // times — NotYet before the hold window is satisfied, Eligible after. A held clock cannot
    // produce two verdicts from one instance; this proves the aging clock actually ages.
    let dap_kp = DualKeyPair::generate().unwrap();
    let eir = Eir::new(public_of(&dap_kp));
    // dwell 10, hold 1000, raised at 0, clear condition began at 0.
    eir.raise(escalation("e1", 10, 1000, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(0));

    // now = 500: elapsed 500 >= dwell 10, but held 500 < hold 1000 → NotYet.
    assert!(matches!(
        eir.may_resolve(&EscalationId::new("e1"), Timestamp(500)),
        ResolutionVerdict::NotYet { .. }
    ));
    // SAME instance, now = 2000: held 2000 >= hold 1000 → Eligible.
    assert!(matches!(
        eir.may_resolve(&EscalationId::new("e1"), Timestamp(2000)),
        ResolutionVerdict::Eligible { needs_dap: true }
    ));
}

#[test]
fn test_oqgf_p_8_3_hysteresis_not_satisfied() {
    let dap_kp = DualKeyPair::generate().unwrap();
    // dwell 10 (satisfied by elapsed 1000), hold 5000 (NOT satisfied: clear held only 1ms).
    let eir = Eir::new(public_of(&dap_kp));
    eir.raise(escalation("e1", 10, 5000, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(999)); // held only 1ms
    assert!(matches!(
        eir.may_resolve(&EscalationId::new("e1"), Timestamp(1000)),
        ResolutionVerdict::NotYet { .. }
    ));
}

#[test]
fn test_oqgf_p_8_6_chronic_is_flagged() {
    let dap_kp = DualKeyPair::generate().unwrap();
    // max_duration 500ms; now 1000 → elapsed 1000 > 500 → chronic; clear never met.
    let eir = Eir::new(public_of(&dap_kp));
    eir.raise(escalation("e1", 10, 10, 500), Timestamp(0));
    assert!(matches!(
        eir.may_resolve(&EscalationId::new("e1"), Timestamp(1000)),
        ResolutionVerdict::Chronic
    ));
    let chronic = eir.scan_chronic(Timestamp(1000));
    assert_eq!(chronic.len(), 1);
    assert_eq!(chronic[0].escalation, EscalationId::new("e1"));
}

// ---- four-crate domain separation ----------------------------------------------------

fn tagged(tag: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(tag.len() as u64).to_be_bytes());
    v.extend_from_slice(tag);
    v.extend_from_slice(payload);
    v
}

#[test]
fn test_sentinel_domain_separated_from_genome_barrier_audit() {
    let obs = corpus_obs();
    let sentinel_bytes = corpus_signed_content(&obs);

    // Begins with the sentinel corpus tag, and with none of the other crates' tags.
    assert!(sentinel_bytes.starts_with(&tagged(b"brokkr-sentinel:corpus:v1", b"")));
    for foreign in [
        &b"brokkr-genome:tools:v1"[..],
        b"brokkr-genome:genome:v1",
        b"brokkr-barrier:bcr:v1",
        b"brokkr-barrier:risk-acceptance:v1",
        b"brokkr-audit:record:v1",
        b"brokkr-audit:export:v1",
        b"brokkr-audit:chain-break-signal:v1",
    ] {
        assert!(
            !sentinel_bytes.starts_with(&tagged(foreign, b"")),
            "sentinel bytes must not share a foreign domain tag"
        );
    }

    // Crypto: a signature over sentinel bytes does not verify over foreign-tagged bytes.
    let kp = DualKeyPair::generate().unwrap();
    let pubk = kp.public_key_bytes().unwrap();
    let foreign_bytes = tagged(b"brokkr-audit:record:v1", b"some-audit-record");
    let sig_sentinel = kp.sign_dual(&sentinel_bytes).unwrap();
    let sig_foreign = kp.sign_dual(&foreign_bytes).unwrap();
    let vk = brokkr_crypto::DualPublicKey::from_public_bytes(&pubk.0, &pubk.1).unwrap();
    assert!(vk.verify_dual(&sentinel_bytes, &sig_sentinel).is_ok());
    assert!(vk.verify_dual(&foreign_bytes, &sig_sentinel).is_err());
    assert!(vk.verify_dual(&sentinel_bytes, &sig_foreign).is_err());
}
