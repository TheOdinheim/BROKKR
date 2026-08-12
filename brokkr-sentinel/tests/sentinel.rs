//! HEIMDALL + EIR functionality and structural tests — real wolfSSL v5.9.2 (non-FIPS) through
//! `brokkr-crypto` where signatures are involved, no mocks.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use brokkr_sentinel::canonical::{
    corpus_signed_content, grant_signed_content, resolution_signed_content,
};
use brokkr_sentinel::{
    DetectionVerdict, Detector, Eir, Heimdall, Observation, SelfSetCorpus, StormAssessment,
};

use brokkr_core::crypto::{Digest, Hasher};
use brokkr_core::gate::{Action, AnergyReason};
use brokkr_core::ids::{Dap, DetectorId, EscalationId, SelfSetVersion, Timestamp, ToolId};
use brokkr_core::resolution::{
    BaselinePosture, ClearCondition, ClearEvidence, EscalationType, ResolutionDecision,
    ResolutionEngine, ResolutionVerdict, ResolveError,
};
use brokkr_core::signal::PostureEffect;
use brokkr_core::tolerance::{
    DetectorSpec, ResponseClass, SelfSet, SuppressionScope, ToleranceController, ToleranceError,
    ToleranceGrant,
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

/// A Heimdall over a matching corpus, with a DAP key and a bound.
fn heimdall_with(
    obs: Vec<Observation>,
    dap_kp: &DualKeyPair,
    bound: f64,
    blast_radius: Option<u64>,
    sustained: u32,
    now: Timestamp,
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
        now,
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

fn signed_decision(id: &str, at: u64, signer: &DualKeyPair) -> ResolutionDecision {
    let mut d = ResolutionDecision::new(
        EscalationId::new(id),
        ClearEvidence {
            detail: "cleared".to_string(),
        },
        dap(),
        Timestamp(at),
        dummy_dual(),
    );
    d.signature = signer.sign_dual(&resolution_signed_content(&d)).unwrap();
    d
}

// ---- Task 4 / OQGF-P-2 — the central property ----------------------------------------

#[test]
fn test_oqgf_p_2_tolerance_refuses_deterministic_target() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2, Timestamp(0));
    let grant = signed_grant("det-1", "signal:x", 1000, &dap_kp);
    // core's provided `grant` (NOT overridden) refuses a Deterministic target before
    // grant_heuristic is ever reached.
    let r = h.grant(grant, ResponseClass::Deterministic);
    assert_eq!(r, Err(ToleranceError::NonSuppressibleGate));
}

#[test]
fn test_oqgf_p_4_valid_grant_attaches_on_heuristic() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2, Timestamp(100));
    let grant = signed_grant("det-1", "signal:x", 1000, &dap_kp);
    assert!(h.grant(grant, ResponseClass::Heuristic).is_ok());
}

#[test]
fn test_oqgf_p_4_expired_grant_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2, Timestamp(2000));
    let grant = signed_grant("det-1", "signal:x", 1000, &dap_kp); // expiry 1000 < now 2000
    assert_eq!(
        h.grant(grant, ResponseClass::Heuristic),
        Err(ToleranceError::Expired)
    );
}

#[test]
fn test_oqgf_p_4_forged_grant_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let attacker = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2, Timestamp(0));
    // Signed by the attacker, not the DAP → not authentic → OutOfScope (no committed
    // signature-failure variant; fail-closed).
    let grant = signed_grant("det-1", "signal:x", 1000, &attacker);
    assert_eq!(
        h.grant(grant, ResponseClass::Heuristic),
        Err(ToleranceError::OutOfScope)
    );
}

#[test]
fn test_oqgf_p_4_blanket_scope_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2, Timestamp(0));
    let grant = signed_grant("det-1", "", 1000, &dap_kp); // empty scope = blanket
    assert_eq!(
        h.grant(grant, ResponseClass::Heuristic),
        Err(ToleranceError::OutOfScope)
    );
}

// ---- Task 3 / OQGF-P-3 — screening ---------------------------------------------------

#[test]
fn test_oqgf_p_3_single_firing_fails_screening() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let obs = corpus_obs();
    let h = heimdall_with(obs.clone(), &dap_kp, 0.1, Some(10), 2, Timestamp(0));
    h.register_detector(Box::new(FiresAlways(DetectorId::new("d"))));
    let r = h.screen(
        &DetectorSpec {
            id: DetectorId::new("d"),
        },
        &matching_selfset(&obs),
    );
    assert_eq!(r, Err(ToleranceError::FailsCentralTolerance));
}

#[test]
fn test_screening_passes_when_detector_clears() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let obs = corpus_obs();
    let h = heimdall_with(obs.clone(), &dap_kp, 0.1, Some(10), 2, Timestamp(0));
    h.register_detector(Box::new(AlwaysClear(DetectorId::new("d"))));
    let r = h.screen(
        &DetectorSpec {
            id: DetectorId::new("d"),
        },
        &matching_selfset(&obs),
    );
    assert!(r.is_ok());
}

#[test]
fn test_oqgf_p_3_substituted_corpus_is_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    // Heimdall holds a SUBSTITUTED (benign) corpus.
    let substituted = vec![authz("nothing", true)];
    let h = heimdall_with(substituted, &dap_kp, 0.1, Some(10), 2, Timestamp(0));

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
    );
    assert_eq!(r, Err(ToleranceError::FailsCentralTolerance));
    // NOTHING was run — the digest check fails before any observation reaches the detector.
    assert!(
        !flag.load(Ordering::SeqCst),
        "no detector may run against a substituted corpus"
    );
}

// ---- Task 5 / OQGF-P-1, P-5 — host harm ----------------------------------------------

#[test]
fn test_host_harm_zero_denominator() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2, Timestamp(0));
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
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, None, 2, Timestamp(0));
    assert_eq!(h.assess_response(1_000_000), StormAssessment::Unenforceable);

    // Configured radius: exceed and within.
    let h2 = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2, Timestamp(0));
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
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 3, Timestamp(0));
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

// ---- Task 6 / OQGF-M-12 — reconciliation ---------------------------------------------

#[test]
fn test_oqgf_m_12_mismatch_deviates_and_none_does_not() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2, Timestamp(0));

    let authorized = Action {
        tool: ToolId::new("write"),
        detail: "a".to_string(),
    };
    let executed_other = Action {
        tool: ToolId::new("delete"),
        detail: "b".to_string(),
    };

    // A mismatch deviates → a raise Signal.
    let mismatch = Observation::Hop {
        authorized: authorized.clone(),
        executed: Some(executed_other),
    };
    let sig = h.reconcile(&mismatch).expect("mismatch must deviate");
    assert!(matches!(sig.effect, PostureEffect::Raise { .. }));

    // `executed: None` is NOT a deviation — the absence of a comparison.
    let pending = Observation::Hop {
        authorized: authorized.clone(),
        executed: None,
    };
    assert!(h.reconcile(&pending).is_none());

    // A matching hop is not a deviation either.
    let matching = Observation::Hop {
        authorized: authorized.clone(),
        executed: Some(authorized),
    };
    assert!(h.reconcile(&matching).is_none());
}

// ---- Task 7 / OQGF-P-8 — EIR ---------------------------------------------------------

#[test]
fn test_oqgf_p_8_5_cannot_lower_above_baseline_without_dap() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let attacker = DualKeyPair::generate().unwrap();
    let eir = Eir::new(public_of(&dap_kp), Timestamp(1000));
    eir.raise(escalation("e1", 10, 10, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(0));

    // A decision signed by the ATTACKER (not the DAP) is not DAP-confirmed.
    let forged = signed_decision("e1", 1000, &attacker);
    assert_eq!(eir.resolve(forged), Err(ResolveError::NeedsDapConfirmation));
}

#[test]
fn test_resolve_succeeds_with_dap_and_eligibility() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let eir = Eir::new(public_of(&dap_kp), Timestamp(1000));
    eir.raise(escalation("e1", 10, 10, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(0));

    assert!(matches!(
        eir.may_resolve(&EscalationId::new("e1")),
        ResolutionVerdict::Eligible { needs_dap: true }
    ));
    let decision = signed_decision("e1", 1000, &dap_kp);
    assert!(eir.resolve(decision).is_ok());
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
    let h = heimdall_with(corpus_obs(), &dap_kp, 0.1, Some(10), 2, Timestamp(0));
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
    let sig = h.reconcile(&deviation).expect("deviation raises");
    assert!(
        is_raise_only(&sig.effect),
        "an emitted signal only raises posture"
    );
}

#[test]
fn test_oqgf_p_8_3_hysteresis_not_satisfied() {
    let dap_kp = DualKeyPair::generate().unwrap();
    // dwell 10 (satisfied by elapsed 1000), hold 5000 (NOT satisfied: clear held only 1ms).
    let eir = Eir::new(public_of(&dap_kp), Timestamp(1000));
    eir.raise(escalation("e1", 10, 5000, 100_000), Timestamp(0));
    eir.clear_condition_met(&EscalationId::new("e1"), Timestamp(999)); // held only 1ms
    assert!(matches!(
        eir.may_resolve(&EscalationId::new("e1")),
        ResolutionVerdict::NotYet { .. }
    ));
}

#[test]
fn test_oqgf_p_8_6_chronic_is_flagged() {
    let dap_kp = DualKeyPair::generate().unwrap();
    // max_duration 500ms; now 1000 → elapsed 1000 > 500 → chronic; clear never met.
    let eir = Eir::new(public_of(&dap_kp), Timestamp(1000));
    eir.raise(escalation("e1", 10, 10, 500), Timestamp(0));
    assert!(matches!(
        eir.may_resolve(&EscalationId::new("e1")),
        ResolutionVerdict::Chronic
    ));
    let chronic = eir.scan_chronic();
    assert_eq!(chronic.len(), 1);
    assert_eq!(chronic[0].escalation, EscalationId::new("e1"));
}

// ---- Task 2 — four-crate domain separation -------------------------------------------

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
