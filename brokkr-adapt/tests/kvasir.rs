//! KVASIR functionality and structural tests — real wolfSSL v5.9.2 (non-FIPS) through
//! `brokkr-crypto` for every signature and digest, no mocks. Each poisoning gate has a negative
//! test asserting the specific `AdaptError`; the positive test drives the whole pipeline.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use brokkr_adapt::canonical::{DOMAIN_EVAL_CORPUS, DOMAIN_PROVENANCE, provenance_signed_content};
use brokkr_adapt::{InMemoryCorpus, InMemoryLedger, Kvasir};

use brokkr_core::adapt::{
    AdaptError, AttackClass, DetectorDelta, DetectorProvenance, DetectorSpecBase, EvaluationCorpus,
    MaturationPipeline, RefinedDetector, SeedingIncident,
};
use brokkr_core::crypto::{Digest, Hasher};
use brokkr_core::gate::Action;
use brokkr_core::ids::{
    CorpusVersion, Dap, DetectorId, IncidentId, SelfSetVersion, Timestamp, ToolId,
};
use brokkr_core::signal::Severity;
use brokkr_core::tolerance::{ResponseClass, ScreenPass, SelfSet};
use brokkr_crypto::{DualKeyPair, DualPublicKey, Sha384Hasher};
use brokkr_sentinel::canonical::corpus_signed_content;
use brokkr_sentinel::{DetectionVerdict, Detector, Heimdall, Observation, SelfSetCorpus};

// ---- helpers -------------------------------------------------------------------------

fn dap() -> Dap {
    Dap::new("Jeremy Rose", "dap-1")
}

fn authz(tool: &str) -> Observation {
    Observation::Authorization {
        action: Action {
            tool: ToolId::new(tool),
            detail: "d".to_string(),
        },
        granted: true,
        anergy: None,
    }
}

fn attack() -> AttackClass {
    AttackClass {
        detail: "sql-injection".to_string(),
    }
}

/// A detector that fires on any `Authorization` observation whose tool is in its set.
struct FiresOnTools {
    id: DetectorId,
    tools: Vec<&'static str>,
}
impl Detector for FiresOnTools {
    fn id(&self) -> &DetectorId {
        &self.id
    }
    fn observe(&self, o: &Observation) -> DetectionVerdict {
        if let Observation::Authorization { action, .. } = o
            && self.tools.iter().any(|t| action.tool.as_str() == *t)
        {
            return DetectionVerdict::Fired {
                severity: Severity::High,
                detail: "hit".to_string(),
            };
        }
        DetectionVerdict::Clear
    }
}

fn fires(id: &str, tools: Vec<&'static str>) -> Box<dyn Detector> {
    Box::new(FiresOnTools {
        id: DetectorId::new(id),
        tools,
    })
}

struct NeverFires(DetectorId);
impl Detector for NeverFires {
    fn id(&self) -> &DetectorId {
        &self.0
    }
    fn observe(&self, _o: &Observation) -> DetectionVerdict {
        DetectionVerdict::Clear
    }
}

/// A detector that records whether it was ever asked to observe (to prove "nothing measured").
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

/// A `SelfSetCorpus` test double over an in-memory observation list.
struct MemSelfSet {
    version: SelfSetVersion,
    obs: Vec<Observation>,
}
impl SelfSetCorpus for MemSelfSet {
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

/// Build a HEIMDALL over a Self Set corpus with `registered` as its screenable detector, and the
/// matching core `SelfSet` (version + recomputed digest) to hand to `screen`.
fn heimdall_with_selfset(
    version: &str,
    obs: Vec<Observation>,
    dap_kp: &DualKeyPair,
    registered: Box<dyn Detector>,
) -> (Heimdall, SelfSet) {
    let corpus = MemSelfSet {
        version: SelfSetVersion::new(version),
        obs: obs.clone(),
    };
    let self_set = SelfSet {
        version: SelfSetVersion::new(version),
        corpus_digest: Sha384Hasher.hash(&corpus_signed_content(&obs)),
        owner: dap(),
    };
    let dap_pub = dap_kp.public_key_bytes().unwrap();
    let h = Heimdall::new(
        Box::new(corpus),
        dap_pub,
        DualKeyPair::generate().unwrap(),
        0.1,
        Some(10),
        2,
    );
    h.register_detector(registered);
    (h, self_set)
}

/// A dual-family-signed `DetectorProvenance`. `signer` signs; a wrong signer models "no approval".
fn provenance(
    seeding: &str,
    corpus_version: &str,
    screen_version: &str,
    produced_at: u64,
    signer: &mut DualKeyPair,
) -> DetectorProvenance {
    let mut p = DetectorProvenance {
        seeding: IncidentId::new(seeding),
        corpus_version: CorpusVersion::new(corpus_version),
        screen_result: ScreenPass {
            version: SelfSetVersion::new(screen_version),
            produced_at: Timestamp(produced_at),
        },
        approver: dap(),
        // Placeholder; replaced below. The signature is excluded from the signed content, so the
        // placeholder does not affect the bytes we then sign.
        signature: signer.sign_dual(b"placeholder").unwrap(),
    };
    let body = provenance_signed_content(&p);
    p.signature = signer.sign_dual(&body).unwrap();
    p
}

/// Everything one refinement needs. `kvasir()` borrows it and rebuilds the by-value verify key
/// (`DualPublicKey` does not derive `Clone`).
struct Setup {
    ledger: InMemoryLedger,
    base: DetectorSpecBase,
    delta: DetectorDelta,
    generation: u64,
    corpus: InMemoryCorpus,
    declared_digest: Digest,
    current_corpus_version: CorpusVersion,
    seed_attack_class: AttackClass,
    seeding_sample: Observation,
    candidate: Box<dyn Detector>,
    incumbent: Box<dyn Detector>,
    produced_at: Timestamp,
    heimdall: Heimdall,
    current_self_set: SelfSet,
    dap_public_bytes: (Vec<u8>, Vec<u8>),
    prior_generation: u64,
}

impl Setup {
    fn kvasir(&self) -> Kvasir<'_> {
        Kvasir {
            ledger: &self.ledger,
            base: self.base.clone(),
            delta: self.delta.clone(),
            generation: self.generation,
            corpus: &self.corpus,
            declared_corpus_digest: self.declared_digest.clone(),
            current_corpus_version: self.current_corpus_version.clone(),
            seed_attack_class: self.seed_attack_class.clone(),
            seeding_sample: self.seeding_sample.clone(),
            candidate: self.candidate.as_ref(),
            incumbent: self.incumbent.as_ref(),
            produced_at: self.produced_at,
            screen: &self.heimdall,
            current_self_set: self.current_self_set.clone(),
            dap_public: DualPublicKey::from_public_bytes(
                &self.dap_public_bytes.0,
                &self.dap_public_bytes.1,
            )
            .unwrap(),
            prior_generation: self.prior_generation,
        }
    }
}

/// A fully-valid setup: every gate passes. Tests break exactly one gate by overriding a field.
fn valid_setup(dap_kp: &DualKeyPair) -> Setup {
    // Evaluation corpus: one seeded-class attack the candidate catches, one benign it leaves alone.
    let samples = vec![
        (authz("attack-1"), Some(attack())),
        (authz("benign-1"), None),
    ];
    let declared_digest = Sha384Hasher.hash(&brokkr_adapt::canonical::eval_corpus_digest_content(
        &samples,
    ));
    let corpus = InMemoryCorpus::new(CorpusVersion::new("corpus-v1"), samples);

    // Self Set: one legitimate action the candidate does NOT fire on (so screening passes).
    let (heimdall, current_self_set) = heimdall_with_selfset(
        "selfset-v1",
        vec![authz("legit-1")],
        dap_kp,
        fires("cand", vec!["attack-1"]),
    );

    Setup {
        ledger: InMemoryLedger::new(vec![(IncidentId::new("inc-1"), dap())]),
        base: DetectorSpecBase {
            id: DetectorId::new("cand"),
        },
        delta: DetectorDelta {
            detail: "tighter pattern".to_string(),
        },
        generation: 2,
        corpus,
        declared_digest,
        current_corpus_version: CorpusVersion::new("corpus-v1"),
        seed_attack_class: attack(),
        seeding_sample: authz("the-seed"), // NOT present in the corpus
        candidate: fires("cand", vec!["attack-1"]),
        incumbent: Box::new(NeverFires(DetectorId::new("incumbent"))),
        produced_at: Timestamp(500),
        heimdall,
        current_self_set,
        dap_public_bytes: dap_kp.public_key_bytes().unwrap(),
        prior_generation: 1,
    }
}

fn confirmed_seed() -> SeedingIncident {
    SeedingIncident {
        incident_id: IncidentId::new("inc-1"),
        confirmed_by: dap(),
        attack_class: attack(),
    }
}

fn corpus_arg(v: &str) -> EvaluationCorpus {
    EvaluationCorpus {
        version: CorpusVersion::new(v),
    }
}

// ---- the positive path: generate -> select -> activate -------------------------------

#[test]
fn test_full_pipeline_activates_and_returns_prior_generation() {
    let mut dap_kp = DualKeyPair::generate().unwrap();
    let s = valid_setup(&dap_kp);
    let k = s.kvasir();

    let detector = k
        .generate(&confirmed_seed())
        .expect("confirmed seed generates");
    assert_eq!(detector.response_class(), ResponseClass::Heuristic);

    let pass = k
        .select(&detector, &corpus_arg("corpus-v1"))
        .expect("an improving, non-regressing candidate is selected");
    assert_eq!(pass.version, CorpusVersion::new("corpus-v1"));
    assert_eq!(pass.produced_at, Timestamp(500));

    let prov = provenance("inc-1", "corpus-v1", "selfset-v1", 500, &mut dap_kp);
    let prior = k
        .activate(detector, prov, Timestamp(9_000))
        .expect("a screened, DAP-approved, current candidate activates");
    assert_eq!(prior.generation, 1);
}

// ---- Gate 1 (OQGF-P-6.1) -------------------------------------------------------------

#[test]
fn test_oqgf_p_6_1_unconfirmed_seed_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let mut s = valid_setup(&dap_kp);
    // The ledger records no confirmation for the seed's incident.
    s.ledger = InMemoryLedger::new(vec![]);
    assert_eq!(
        s.kvasir().generate(&confirmed_seed()),
        Err(AdaptError::UnconfirmedSeed)
    );
}

#[test]
fn test_oqgf_p_6_1_seed_confirmed_by_a_different_dap_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let mut s = valid_setup(&dap_kp);
    // The incident IS recorded, but attributed to a different DAP than the seed claims — a caller
    // cannot pin a confirmation on a DAP who did not make it.
    s.ledger = InMemoryLedger::new(vec![(
        IncidentId::new("inc-1"),
        Dap::new("Someone Else", "dap-2"),
    )]);
    assert_eq!(
        s.kvasir().generate(&confirmed_seed()),
        Err(AdaptError::UnconfirmedSeed)
    );
}

// ---- Gate 2 (OQGF-P-6.2) -------------------------------------------------------------

#[test]
fn test_oqgf_p_6_2_substituted_corpus_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let mut s = valid_setup(&dap_kp);
    // Spy detectors prove NOTHING is measured when the corpus is substituted.
    let cand_seen = Arc::new(AtomicBool::new(false));
    let inc_seen = Arc::new(AtomicBool::new(false));
    s.candidate = Box::new(Spy {
        id: DetectorId::new("cand"),
        observed: cand_seen.clone(),
    });
    s.incumbent = Box::new(Spy {
        id: DetectorId::new("incumbent"),
        observed: inc_seen.clone(),
    });
    // The declared digest does not match the corpus content: tampering.
    s.declared_digest = Sha384Hasher.hash(b"a different corpus");

    let detector = RefinedDetector::new(s.base.clone(), s.delta.clone(), s.generation);
    assert_eq!(
        s.kvasir().select(&detector, &corpus_arg("corpus-v1")),
        Err(AdaptError::SubstitutedCorpus)
    );
    assert!(
        !cand_seen.load(Ordering::SeqCst) && !inc_seen.load(Ordering::SeqCst),
        "a substituted corpus is refused before any measurement"
    );
}

#[test]
fn test_oqgf_p_6_2_stale_corpus_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let s = valid_setup(&dap_kp);
    let detector = RefinedDetector::new(s.base.clone(), s.delta.clone(), s.generation);
    // Selecting against a superseded corpus version — drift, not tampering.
    assert_eq!(
        s.kvasir().select(&detector, &corpus_arg("corpus-v0-old")),
        Err(AdaptError::StaleCorpus)
    );
}

#[test]
fn test_oqgf_p_6_2_corpus_containing_seed_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let mut s = valid_setup(&dap_kp);
    // The seeding sample IS present in the corpus (non-containment fails): Overfit, the true claim.
    s.seeding_sample = authz("attack-1");
    let detector = RefinedDetector::new(s.base.clone(), s.delta.clone(), s.generation);
    assert_eq!(
        s.kvasir().select(&detector, &corpus_arg("corpus-v1")),
        Err(AdaptError::Overfit)
    );
}

#[test]
fn test_oqgf_p_6_2_overfit_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let mut s = valid_setup(&dap_kp);
    // The candidate catches nothing the incumbent missed: no improvement beyond its seed.
    s.candidate = Box::new(NeverFires(DetectorId::new("cand")));
    let detector = RefinedDetector::new(s.base.clone(), s.delta.clone(), s.generation);
    assert_eq!(
        s.kvasir().select(&detector, &corpus_arg("corpus-v1")),
        Err(AdaptError::Overfit)
    );
}

#[test]
fn test_oqgf_p_6_2_coverage_regression_refused() {
    let dap_kp = DualKeyPair::generate().unwrap();
    let mut s = valid_setup(&dap_kp);
    // The candidate improves on the attack class BUT now fires on a benign sample the incumbent
    // cleared — a coverage regression, which disqualifies regardless of the gain.
    s.candidate = fires("cand", vec!["attack-1", "benign-1"]);
    let detector = RefinedDetector::new(s.base.clone(), s.delta.clone(), s.generation);
    assert_eq!(
        s.kvasir().select(&detector, &corpus_arg("corpus-v1")),
        Err(AdaptError::CoverageRegression)
    );
}

// ---- Gate 3 (OQGF-P-6.3) — the load-bearing test ------------------------------------

#[test]
fn test_oqgf_p_6_3_raises_host_harm_refused() {
    // A candidate with REAL detection gains (it passes selection) is STILL discarded because it
    // raises host harm — it fires on a legitimate Self Set action. There is no trade: the gain
    // does not buy tolerance for the harm.
    let mut dap_kp = DualKeyPair::generate().unwrap();
    let mut s = valid_setup(&dap_kp);
    // The candidate catches the attack (gain) AND fires on the legitimate Self Set action (harm).
    s.candidate = fires("cand", vec!["attack-1", "legit-1"]);
    let (heimdall, self_set) = heimdall_with_selfset(
        "selfset-v1",
        vec![authz("legit-1")],
        &dap_kp,
        fires("cand", vec!["attack-1", "legit-1"]),
    );
    s.heimdall = heimdall;
    s.current_self_set = self_set;

    let detector = RefinedDetector::new(s.base.clone(), s.delta.clone(), s.generation);
    let k = s.kvasir();

    // Selection succeeds: the detection gain is real.
    assert!(
        k.select(&detector, &corpus_arg("corpus-v1")).is_ok(),
        "the candidate has real, selectable detection gains"
    );
    // Activation discards it anyway: host harm, regardless of the gain.
    let prov = provenance("inc-1", "corpus-v1", "selfset-v1", 500, &mut dap_kp);
    assert_eq!(
        k.activate(detector, prov, Timestamp(9_000)),
        Err(AdaptError::FailsTolerance)
    );
}

#[test]
fn test_oqgf_p_6_3_stale_screen_pass_refused() {
    // A screen pass against a SUPERSEDED Self Set version is refused however recent it is —
    // version equality, not recency (§6.12). The provenance is validly signed; only its screen
    // version is stale.
    let mut dap_kp = DualKeyPair::generate().unwrap();
    let s = valid_setup(&dap_kp);
    let detector = RefinedDetector::new(s.base.clone(), s.delta.clone(), s.generation);
    // produced_at is recent, but the version is a superseded Self Set.
    let prov = provenance("inc-1", "corpus-v1", "selfset-v0-OLD", 8_999, &mut dap_kp);
    assert_eq!(
        s.kvasir().activate(detector, prov, Timestamp(9_000)),
        Err(AdaptError::FailsTolerance)
    );
}

// ---- Gate 4 (OQGF-P-6.6) -------------------------------------------------------------

#[test]
fn test_oqgf_p_6_6_activation_without_dap_approval_refused() {
    // A provenance signed by a key that is NOT the declared DAP's has no valid approval.
    let dap_kp = DualKeyPair::generate().unwrap();
    let mut impostor = DualKeyPair::generate().unwrap();
    let s = valid_setup(&dap_kp);
    let detector = RefinedDetector::new(s.base.clone(), s.delta.clone(), s.generation);
    let prov = provenance("inc-1", "corpus-v1", "selfset-v1", 500, &mut impostor);
    assert_eq!(
        s.kvasir().activate(detector, prov, Timestamp(9_000)),
        Err(AdaptError::NeedsApproval)
    );
}

// ---- I-9 (structural) ---------------------------------------------------------------

#[test]
fn test_i9_refined_detector_cannot_be_deterministic() {
    // Operationally: every detector KVASIR emits is Heuristic. The COMPILE-TIME impossibility of a
    // Deterministic RefinedDetector (private `response_class`, no Deterministic constructor) is the
    // `compile_fail` doctest in `lib.rs` — the agent can learn to see better, not to see less.
    let dap_kp = DualKeyPair::generate().unwrap();
    let s = valid_setup(&dap_kp);
    let detector = s.kvasir().generate(&confirmed_seed()).unwrap();
    assert_eq!(detector.response_class(), ResponseClass::Heuristic);
}

// ---- Task 6: five-crate domain separation -------------------------------------------

#[test]
fn test_adapt_domain_separated_from_all_siblings() {
    // Every domain tag committed in the five sibling crates. If any adapt tag ever equals one of
    // these, this test fails.
    const SIBLINGS: &[&[u8]] = &[
        b"brokkr-intent:root:v1",
        b"brokkr-intent:entry:v1",
        b"brokkr-genome:tools:v1",
        b"brokkr-genome:cbom:v1",
        b"brokkr-genome:aibom:v1",
        b"brokkr-genome:endpoints:v1",
        b"brokkr-genome:roots:v1",
        b"brokkr-genome:policy:v1",
        b"brokkr-genome:genome:v1",
        b"brokkr-barrier:bcr:v1",
        b"brokkr-barrier:risk-acceptance:v1",
        b"brokkr-audit:record:v1",
        b"brokkr-audit:chain-break-signal:v1",
        b"brokkr-audit:export:v1",
        b"brokkr-sentinel:corpus:v1",
        b"brokkr-sentinel:tolerance-grant:v1",
        b"brokkr-sentinel:signal:v1",
    ];
    for tag in SIBLINGS {
        assert_ne!(DOMAIN_PROVENANCE, *tag);
        assert_ne!(DOMAIN_EVAL_CORPUS, *tag);
    }
    assert_ne!(DOMAIN_PROVENANCE, DOMAIN_EVAL_CORPUS);

    // And a real provenance encoding actually begins with the adapt provenance tag
    // (length-prefixed), so the domain separation is in the bytes, not just the constants.
    let mut dap_kp = DualKeyPair::generate().unwrap();
    let prov = provenance("inc-1", "corpus-v1", "selfset-v1", 500, &mut dap_kp);
    let encoded = provenance_signed_content(&prov);
    let mut expected = (DOMAIN_PROVENANCE.len() as u64).to_be_bytes().to_vec();
    expected.extend_from_slice(DOMAIN_PROVENANCE);
    assert!(encoded.starts_with(&expected));
}
