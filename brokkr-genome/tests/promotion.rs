//! REGIN promotion-gate tests (Phase 5). Real dual-family signing over the real canonical
//! encoding; verification with exported public bytes. No crypto mocks. One negative per
//! predicate, each asserting the specific finding; plus the load-bearing domain-separation
//! test and the Rev 1.5 narrowing case.

use brokkr_core::capability::ConformanceTier;
use brokkr_core::classification::{Classification, NamedGroup};
use brokkr_core::crypto::{Digest, DualSignature, HashAlg, Signature, SignatureAlg};
use brokkr_core::genome::{Aibom, AlgorithmId, BoundaryInterface, Cbom, CustodianSeparation, DualControl, EndpointRegistry, ExtractionProtection, FactorEvidence, FipsValidation, Genome, HardwareBoundary, InvariantEntry, KeyCustody, ModelEndpoint, PolicyRegister, PrivilegeClass, ProcedureRef, Quorum, RootOfTrustEntry, RootsOfTrust, ToolEntry, ToolGenome, ToolSchema, VendorTrustScore};
use brokkr_core::ids::{
    ClientCertRef, Dap, GenomeVersion, ModelEndpointId, ModelIdentity, Score, SubjectId, Timestamp,
    ToolId, TrustAnchor,
};
use brokkr_core::intent::{Capability, Invariant};
use brokkr_core::tolerance::ResponseClass;
use brokkr_crypto::{DualKeyPair, DualPublicKey};
use brokkr_genome::canonical;
use brokkr_genome::{CustodyShortfall, Finding, PromotionVerdict, Register, promote};

const NINETY_DAYS_MS: u64 = 7_776_000_000;
const NOW: u64 = 20_000_000_000;

// ---- helpers -------------------------------------------------------------------------

fn dap() -> Dap {
    Dap::new("Jeremy Rose", "dap-1")
}

/// A never-verified placeholder signature, used only as a pre-signing placeholder: a
/// register is built carrying this, then re-assigned a real signature over its own
/// canonical content. (Before Rev 1.32 it also filled `VendorTrustScore::signature`, a
/// field nothing signed and nothing verified; that field is removed.)
fn dummy_sig() -> DualSignature {
    DualSignature {
        lattice: Signature {
            alg: SignatureAlg::MlDsa65,
            bytes: vec![0u8; 4],
        },
        hash_based: Signature {
            alg: SignatureAlg::SlhDsaShake192s,
            bytes: vec![0u8; 4],
        },
    }
}

fn public_of(kp: &DualKeyPair) -> DualPublicKey {
    let (ml, slh) = kp.public_key_bytes().unwrap();
    DualPublicKey::from_public_bytes(&ml, &slh).unwrap()
}

fn cap(s: &str) -> Capability {
    Capability::new(s)
}

/// The mutable, pre-signing parts of a genome. `default_valid` yields a genome that passes
/// all six predicates; negatives perturb one field, then `sign`.
struct Parts {
    tool_entries: Vec<ToolEntry>,
    cbom_algorithms: Vec<AlgorithmId>,
    endpoints: Vec<ModelEndpoint>,
    roots: Vec<RootOfTrustEntry>,
    policy_capabilities: Vec<Capability>,
    policy_invariants: Vec<InvariantEntry>,
    policy_disallowed: Vec<AlgorithmId>,
    /// Rev 1.22: the declared key custody (OQGF-R-6) and the tier predicate 7 checks it
    /// against. The default pair is CONFORMANT — `Baseline` + software custody with a
    /// declared protection mechanism satisfies R-6.1 — so predicates 1-6 can be exercised
    /// without predicate 7 confounding them.
    custody: KeyCustody,
    tier: ConformanceTier,
}

fn endpoint(id: &str, reviewed: u64) -> ModelEndpoint {
    ModelEndpoint {
        id: ModelEndpointId::new(id),
        model: ModelIdentity {
            name: "mimir".into(),
            version: "1".into(),
            provider: "local".into(),
        },
        client_cert: ClientCertRef::new("cert-1"),
        server_trust: TrustAnchor::new("anchor-1"),
        min_group: NamedGroup::X25519MlKem768,
        max_classification: Classification::Internal,
        trust_score: VendorTrustScore {
            attestation_capability: Score(80),
            fips_validation: Score(0),
            breach_history: Score(90),
            jurisdictional_exposure: Score(50),
            data_handling: Score(60),
            reconciliation_pass_rate: Score(0),
            // Rev 1.31 — the honest encoding of "unmeasured": Score(0) with zero
            // observations. Predicate 8 passes this and refuses the inverse (a non-zero
            // score with zero observations), so the fixture exercises the state BROKKR's
            // own genome is actually in.
            evidence: FactorEvidence {
                observations: 0,
                measured: Timestamp(0),
            },
            reviewed: Timestamp(reviewed),
            reviewer: dap(),
        },
    }
}

impl Parts {
    fn default_valid() -> Self {
        Parts {
            tool_entries: vec![ToolEntry {
                id: ToolId::new("write_file"),
                schema: ToolSchema {
                    detail: "{}".into(),
                },
                privilege: PrivilegeClass::Privileged,
                response_class: ResponseClass::Deterministic,
                required_capabilities: vec![cap("write")],
            }],
            cbom_algorithms: vec![
                AlgorithmId::Signature(SignatureAlg::MlDsa65),
                AlgorithmId::Kem(brokkr_core::crypto::KemAlg::MlKem768),
            ],
            endpoints: vec![endpoint("mimir-1", NOW - 1000)],
            roots: vec![RootOfTrustEntry {
                subject: SubjectId::new("hop-1"),
                ml_dsa_public: vec![1, 2, 3],
                slh_dsa_public: vec![4, 5, 6],
            }],
            policy_capabilities: vec![cap("read"), cap("write"), cap("network")],
            policy_invariants: vec![InvariantEntry {
                invariant: Invariant::new("no-network-egress"),
                forbids_capabilities: vec![cap("network")],
                forbids_privilege: vec![],
            }],
            policy_disallowed: vec![AlgorithmId::Signature(SignatureAlg::EcdsaP256)],
            // Software custody with a declared mechanism — BROKKR's honest posture — at
            // the tier where it is conformant (R-6.1). A fixture that must promote gets a
            // fixture-appropriate tier; the predicate is not weakened to let it pass.
            custody: KeyCustody::SoftwareInProcess {
                protection: ExtractionProtection::ProcessIsolationOnly,
            },
            tier: ConformanceTier::Baseline,
        }
    }

    /// Build every register, sign each register's content, then assemble the genome and
    /// sign it (the genome signature covers the registers' real signatures — so registers
    /// are signed first).
    fn sign(self, kp: &mut DualKeyPair) -> Genome {
        let mut tools = ToolGenome {
            entries: self.tool_entries,
            signature: dummy_sig(),
        };
        tools.signature = kp
            .sign_dual(&canonical::tools_signed_content(&tools))
            .unwrap();

        let mut cbom = Cbom {
            cyclonedx: "<cbom/>".into(),
            algorithms: self.cbom_algorithms,
            custody: self.custody,
            signature: dummy_sig(),
        };
        cbom.signature = kp
            .sign_dual(&canonical::cbom_signed_content(&cbom))
            .unwrap();

        let mut aibom = Aibom {
            cyclonedx: "<aibom/>".into(),
            signature: dummy_sig(),
        };
        aibom.signature = kp
            .sign_dual(&canonical::aibom_signed_content(&aibom))
            .unwrap();

        let mut endpoints = EndpointRegistry {
            endpoints: self.endpoints,
            signature: dummy_sig(),
        };
        endpoints.signature = kp
            .sign_dual(&canonical::endpoints_signed_content(&endpoints))
            .unwrap();

        let mut roots = RootsOfTrust {
            entries: self.roots,
            signature: dummy_sig(),
        };
        roots.signature = kp
            .sign_dual(&canonical::roots_signed_content(&roots))
            .unwrap();

        let mut policy = PolicyRegister {
            capabilities: self.policy_capabilities,
            invariants: self.policy_invariants,
            disallowed: self.policy_disallowed,
            signature: dummy_sig(),
            purpose_fields: Vec::new(),
        };
        policy.signature = kp
            .sign_dual(&canonical::policy_signed_content(&policy))
            .unwrap();

        let mut genome = Genome {
            version: GenomeVersion::new("v1"),
            tools,
            cbom,
            aibom,
            endpoints,
            roots,
            policy,
            tier: self.tier,
            corpus_digest: Digest {
                alg: HashAlg::Sha384,
                bytes: vec![0u8; 48],
            },
            owner: dap(),
            signature: dummy_sig(),
        };
        genome.signature = kp
            .sign_dual(&canonical::genome_signed_content(&genome))
            .unwrap();
        genome
    }
}

fn blocked_findings(v: PromotionVerdict) -> Vec<Finding> {
    match v {
        PromotionVerdict::Blocked { findings } => findings,
        PromotionVerdict::Promoted => panic!("expected Blocked, got Promoted"),
    }
}

// ---- positive ------------------------------------------------------------------------

#[test]
fn test_oqgf_g_4_valid_genome_promotes() {
    let mut kp = DualKeyPair::generate().unwrap();
    let genome = Parts::default_valid().sign(&mut kp);
    assert_eq!(
        promote(&genome, &public_of(&kp), Timestamp(NOW)),
        PromotionVerdict::Promoted,
    );
}

#[test]
fn test_canonical_deterministic_and_unambiguous() {
    let mut kp = DualKeyPair::generate().unwrap();
    let genome = Parts::default_valid().sign(&mut kp);

    // Deterministic: the same value encodes to identical bytes.
    assert_eq!(
        canonical::policy_signed_content(&genome.policy),
        canonical::policy_signed_content(&genome.policy),
    );

    // Unambiguous under a length-prefix collision: {"ab","c"} vs {"a","bc"} would collide
    // without length prefixes. They must not.
    let mut p1 = genome.policy.clone();
    p1.capabilities = vec![cap("ab"), cap("c")];
    let mut p2 = genome.policy.clone();
    p2.capabilities = vec![cap("a"), cap("bc")];
    assert_ne!(
        canonical::policy_signed_content(&p1),
        canonical::policy_signed_content(&p2),
        "length-prefixing must keep concatenation-collision inputs distinct"
    );
}

#[test]
fn test_domain_separation_across_registers() {
    // Structurally analogous "vector-plus-signature" registers with the same entry count
    // (zero) must encode to DIFFERENT signed bytes — the domain tag separates them — and a
    // signature over one must NOT verify against another.
    let empty_tools = ToolGenome {
        entries: vec![],
        signature: dummy_sig(),
    };
    let empty_roots = RootsOfTrust {
        entries: vec![],
        signature: dummy_sig(),
    };
    let tools_bytes = canonical::tools_signed_content(&empty_tools);
    let roots_bytes = canonical::roots_signed_content(&empty_roots);
    assert_ne!(
        tools_bytes, roots_bytes,
        "domain separation: a tool genome and a roots register must not encode identically"
    );

    // The strong form: sign the tools bytes, then confirm that signature does not verify
    // against the roots bytes.
    let mut kp = DualKeyPair::generate().unwrap();
    let sig = kp.sign_dual(&tools_bytes).unwrap();
    let pk = public_of(&kp);
    assert!(pk.verify_dual(&tools_bytes, &sig).is_ok());
    assert!(
        pk.verify_dual(&roots_bytes, &sig).is_err(),
        "a signature over a tool genome must not verify against a roots register"
    );
}

// ---- negative: one per predicate -----------------------------------------------------

#[test]
fn test_oqgf_g_4_tampered_register_fails_signature() {
    let mut kp = DualKeyPair::generate().unwrap();
    let mut genome = Parts::default_valid().sign(&mut kp);
    // Mutate the tools register AFTER signing — its signature no longer covers the content.
    genome.tools.entries.push(ToolEntry {
        id: ToolId::new("sneaky"),
        schema: ToolSchema {
            detail: "{}".into(),
        },
        privilege: PrivilegeClass::SelfModifying,
        response_class: ResponseClass::Deterministic,
        required_capabilities: vec![],
    });
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(
        findings.contains(&Finding::RegisterSignatureInvalid {
            register: Register::Tools
        }),
        "tampering the tools register must produce a tools signature finding; got {findings:?}"
    );
}

#[test]
fn test_oqgf_g_4_disallowed_algorithm_blocks() {
    let mut kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    // Put a disallowed algorithm into the CBOM inventory.
    let ecdsa = AlgorithmId::Signature(SignatureAlg::EcdsaP256);
    parts.cbom_algorithms.push(ecdsa);
    let genome = parts.sign(&mut kp);
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(findings.contains(&Finding::DisallowedAlgorithm { algorithm: ecdsa }));
}

#[test]
fn test_oqgf_m_6_stale_trust_score_blocks() {
    let mut kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    // reviewed more than 90 days before now.
    parts.endpoints = vec![endpoint("mimir-1", NOW - NINETY_DAYS_MS - 1)];
    let genome = parts.sign(&mut kp);
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(findings.contains(&Finding::StaleTrustScore {
        endpoint: ModelEndpointId::new("mimir-1")
    }));
}

/// Predicate 8 — a factor claiming a measurement it has no evidence for is refused.
///
/// `Score` is a `u8` that cannot say "unmeasured", so a non-zero score with zero
/// observations is a **claim without evidence**: signed into the genome, dated,
/// DAP-attributed, read by the OQGF-G-4 gate, and indistinguishable at assessment from a
/// real measurement. ARCH §6.2 records why that is worse than an inert placeholder.
#[test]
fn test_oqgf_m_6_measured_factor_without_evidence_blocks() {
    let mut kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    let mut ep = endpoint("mimir-1", NOW - 1000);
    // A claimed measurement...
    ep.trust_score.reconciliation_pass_rate = Score(100);
    // ...with nothing behind it.
    ep.trust_score.evidence.observations = 0;
    parts.endpoints = vec![ep];
    let genome = parts.sign(&mut kp);
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(
        findings.contains(&Finding::MeasuredFactorWithoutEvidence {
            endpoint: ModelEndpointId::new("mimir-1"),
            claimed: Score(100),
        }),
        "a non-zero score with zero observations must be refused: {findings:?}"
    );
}

/// Predicate 8 — an **honestly unmeasured** factor promotes, and this is the direction that
/// matters most.
///
/// `Score(0)` with zero observations is the honest encoding of "no evidence", and **BROKKR's
/// own genome is in exactly that state**. A predicate that refused it would make BROKKR
/// unpromotable by its own gate — the failure mode predicate 8 is one line away from, and
/// the reason this test exists beside the refusal above rather than being left implied.
#[test]
fn test_oqgf_m_6_unmeasured_factor_still_promotes() {
    let mut kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    let mut ep = endpoint("mimir-1", NOW - 1000);
    ep.trust_score.reconciliation_pass_rate = Score(0);
    ep.trust_score.evidence.observations = 0;
    parts.endpoints = vec![ep];
    let genome = parts.sign(&mut kp);
    let verdict = promote(&genome, &public_of(&kp), Timestamp(NOW));
    assert!(
        matches!(verdict, PromotionVerdict::Promoted),
        "the honest unmeasured state must stay promotable — a gate refusing it would make \
         BROKKR's own genome unpromotable: {verdict:?}"
    );
}

/// Predicate 8 — a measured factor **with** evidence promotes.
///
/// The control. Without it the refusal test would pass equally against a predicate that
/// refused every non-zero score, which is a different and wrong rule.
#[test]
fn test_oqgf_m_6_measured_factor_with_evidence_promotes() {
    let mut kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    let mut ep = endpoint("mimir-1", NOW - 1000);
    ep.trust_score.reconciliation_pass_rate = Score(97);
    ep.trust_score.evidence.observations = 4_000;
    parts.endpoints = vec![ep];
    let genome = parts.sign(&mut kp);
    let verdict = promote(&genome, &public_of(&kp), Timestamp(NOW));
    assert!(
        matches!(verdict, PromotionVerdict::Promoted),
        "a score backed by observations must promote: {verdict:?}"
    );
}

#[test]
fn test_oqgf_m_6_future_trust_score_blocks() {
    let mut kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    // reviewed AFTER now — malformed.
    parts.endpoints = vec![endpoint("mimir-1", NOW + 1000)];
    let genome = parts.sign(&mut kp);
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(findings.contains(&Finding::FutureTrustScore {
        endpoint: ModelEndpointId::new("mimir-1")
    }));
}

#[test]
fn test_tool_capability_not_in_vocabulary_blocks() {
    let mut kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    // A typo: the tool requires "wirte", which is not in the vocabulary.
    parts.tool_entries[0].required_capabilities = vec![cap("wirte")];
    let genome = parts.sign(&mut kp);
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(findings.contains(&Finding::ToolCapabilityNotInVocabulary {
        tool: ToolId::new("write_file"),
        capability: cap("wirte"),
    }));
}

#[test]
fn test_invariant_forbids_unknown_capability_blocks() {
    let mut kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    // An invariant forbidding a capability absent from the vocabulary (a typo).
    parts.policy_invariants[0].forbids_capabilities = vec![cap("netwrok")];
    let genome = parts.sign(&mut kp);
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(
        findings.contains(&Finding::InvariantForbidsUnknownCapability {
            invariant: Invariant::new("no-network-egress"),
            capability: cap("netwrok"),
        })
    );
}

#[test]
fn test_invariant_forbidding_nothing_blocks() {
    let mut kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    // An invariant that forbids neither a capability nor a privilege — can never fire.
    parts.policy_invariants[0].forbids_capabilities = vec![];
    parts.policy_invariants[0].forbids_privilege = vec![];
    let genome = parts.sign(&mut kp);
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(findings.contains(&Finding::InvariantForbidsNothing {
        invariant: Invariant::new("no-network-egress"),
    }));
}

#[test]
fn test_invariant_forbidding_undeclared_but_known_capability_promotes() {
    // The Rev 1.5 narrowing: an invariant forbidding a RECOGNIZED capability that no tool
    // currently requires is valid forward-looking policy and SHALL NOT block. "read" is in
    // the vocabulary; no tool requires it; forbidding it is legitimate.
    let mut kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    parts.policy_invariants.push(InvariantEntry {
        invariant: Invariant::new("no-read"),
        forbids_capabilities: vec![cap("read")],
        forbids_privilege: vec![],
    });
    let genome = parts.sign(&mut kp);
    assert_eq!(
        promote(&genome, &public_of(&kp), Timestamp(NOW)),
        PromotionVerdict::Promoted,
        "forbidding a recognized-but-unrequired capability is forward-looking policy, not a fault"
    );
}

#[test]
fn test_all_findings_returned() {
    // A genome failing MULTIPLE predicates returns ALL of them, not just the first.
    let mut kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    parts
        .cbom_algorithms
        .push(AlgorithmId::Signature(SignatureAlg::EcdsaP256)); // predicate 3
    parts.endpoints = vec![endpoint("mimir-1", NOW + 1000)]; // predicate 4 (future)
    parts.tool_entries[0].required_capabilities = vec![cap("wirte")]; // predicate 5
    parts.policy_invariants.push(InvariantEntry {
        invariant: Invariant::new("dead"),
        forbids_capabilities: vec![],
        forbids_privilege: vec![],
    }); // predicate 6
    let genome = parts.sign(&mut kp);
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(findings.contains(&Finding::DisallowedAlgorithm {
        algorithm: AlgorithmId::Signature(SignatureAlg::EcdsaP256)
    }));
    assert!(findings.contains(&Finding::FutureTrustScore {
        endpoint: ModelEndpointId::new("mimir-1")
    }));
    assert!(findings.contains(&Finding::ToolCapabilityNotInVocabulary {
        tool: ToolId::new("write_file"),
        capability: cap("wirte"),
    }));
    assert!(findings.contains(&Finding::InvariantForbidsNothing {
        invariant: Invariant::new("dead"),
    }));
    assert!(
        findings.len() >= 4,
        "all four content findings present; got {findings:?}"
    );
}

#[test]
fn test_wrong_dap_key_blocks_all_signatures() {
    // Non-circularity: a valid genome verified with a DIFFERENT DAP key fails every
    // signature predicate — the verifying key is the caller's, not read from the genome.
    let mut kp = DualKeyPair::generate().unwrap();
    let genome = Parts::default_valid().sign(&mut kp);
    let wrong = public_of(&DualKeyPair::generate().unwrap());
    let findings = blocked_findings(promote(&genome, &wrong, Timestamp(NOW)));
    assert!(findings.contains(&Finding::GenomeSignatureInvalid));
    assert!(findings.contains(&Finding::RegisterSignatureInvalid {
        register: Register::Tools
    }));
}

// ---------------------------------------------------------------------------------------
// Rev 1.22 — the custody declaration and the declared tier are inside signed content.
// ---------------------------------------------------------------------------------------

/// Changing the declared key custody changes the CBOM's signed content, so it changes the
/// CBOM digest and invalidates the CBOM signature. A custody posture cannot drift quietly:
/// downgrading it is a visible, signed, gate-crossing act (ARCH Rev 1.21 §6.2).
#[test]
fn test_r6_custody_is_inside_cbom_signed_content() {
    let software = Cbom {
        cyclonedx: "<cbom/>".into(),
        algorithms: vec![],
        custody: KeyCustody::SoftwareInProcess {
            protection: ExtractionProtection::ProcessIsolationOnly,
        },
        signature: dummy_sig(),
    };
    let mut hardware = software.clone();
    hardware.custody = KeyCustody::HardwareBacked {
        boundary: HardwareBoundary {
            module: "test-hsm".into(),
            interface: BoundaryInterface::Pkcs11,
            fips: FipsValidation::NotValidated,
        },
        dual_control: DualControl::SingleOperator,
    };
    assert_ne!(
        canonical::cbom_signed_content(&software),
        canonical::cbom_signed_content(&hardware),
        "a change of declared custody MUST change the CBOM signed content"
    );

    // And the two software variants differ too — the declaration is encoded, not elided.
    let mut encrypted = software.clone();
    encrypted.custody = KeyCustody::SoftwareInProcess {
        protection: ExtractionProtection::EncryptedAtRest,
    };
    assert_ne!(
        canonical::cbom_signed_content(&software),
        canonical::cbom_signed_content(&encrypted),
        "a change of declared protection mechanism MUST change the CBOM signed content"
    );
}

/// Changing the declared conformance tier changes the genome's signed content, so a
/// downgrade that would relax what predicate 7 demands of custody requires re-signing and
/// re-promotion (ARCH Rev 1.22 §6.2).
#[test]
fn test_r6_tier_is_inside_genome_signed_content() {
    let mut kp = DualKeyPair::generate().unwrap();
    let baseline = Parts::default_valid().sign(&mut kp);
    let mut enhanced = baseline.clone();
    enhanced.tier = ConformanceTier::Enhanced;
    assert_ne!(
        canonical::genome_signed_content(&baseline),
        canonical::genome_signed_content(&enhanced),
        "a change of declared tier MUST change the genome signed content"
    );
}

// ---------------------------------------------------------------------------------------
// Predicate 7 (Rev 1.21/1.22) — declared key custody against the declared conformance tier.
// ---------------------------------------------------------------------------------------

fn proc_ref(name: &str) -> ProcedureRef {
    ProcedureRef {
        document: name.into(),
        digest: Digest {
            alg: HashAlg::Sha384,
            bytes: vec![7u8; 48],
        },
    }
}

fn boundary() -> HardwareBoundary {
    HardwareBoundary {
        module: "test-hsm".into(),
        interface: BoundaryInterface::Pkcs11,
        fips: FipsValidation::Level {
            level: 3,
            certificate: "CMVP-0000".into(),
        },
    }
}

fn software_custody() -> KeyCustody {
    KeyCustody::SoftwareInProcess {
        protection: ExtractionProtection::ProcessIsolationOnly,
    }
}

/// A conformant R-6.3 declaration: 3-of-5, three independent parties, rehearsed recently.
fn threshold_custody(k: u8, n: u8, independent_parties: u8, last_rehearsal: u64) -> KeyCustody {
    KeyCustody::Threshold {
        boundary: boundary(),
        dual_control: DualControl::TwoParty {
            procedure: proc_ref("dual-control"),
        },
        quorum: Quorum { k, n },
        custodians: CustodianSeparation {
            independent_parties,
            separation_of_duty: proc_ref("separation"),
        },
        ceremony: proc_ref("ceremony"),
        recovery: proc_ref("recovery"),
        rotation: proc_ref("rotation"),
        last_rehearsal: Timestamp(last_rehearsal),
    }
}

/// Evaluate a genome at `now` and return only the predicate-7 shortfall, if any. Other
/// findings (e.g. a trust score that went stale because `now` was advanced) are filtered
/// out deliberately — this helper isolates predicate 7.
fn custody_shortfall_at(
    custody: KeyCustody,
    tier: ConformanceTier,
    now: u64,
) -> Option<CustodyShortfall> {
    let mut kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    parts.custody = custody;
    parts.tier = tier;
    let genome = parts.sign(&mut kp);
    let findings = match promote(&genome, &public_of(&kp), Timestamp(now)) {
        PromotionVerdict::Promoted => Vec::new(),
        PromotionVerdict::Blocked { findings } => findings,
    };
    findings.into_iter().find_map(|f| match f {
        Finding::KeyCustodyBelowTier { element, .. } => Some(element),
        _ => None,
    })
}

fn custody_shortfall_of(custody: KeyCustody, tier: ConformanceTier) -> Option<CustodyShortfall> {
    custody_shortfall_at(custody, tier, NOW)
}

// ---- R-6.1 (Baseline) ----

#[test]
fn test_r6_1_baseline_accepts_software_custody() {
    assert!(
        custody_shortfall_of(software_custody(), ConformanceTier::Baseline).is_none(),
        "R-6.1 permits software-held keys when the CBOM declares them as such"
    );
}

#[test]
fn test_r6_1_baseline_accepts_hardware_custody() {
    let custody = KeyCustody::HardwareBacked {
        boundary: boundary(),
        dual_control: DualControl::SingleOperator,
    };
    assert!(
        custody_shortfall_of(custody, ConformanceTier::Baseline).is_none(),
        "a stronger declaration than the tier requires is not a failure"
    );
}

// ---- R-6.2 (Enhanced) ----

/// **BROKKR's own genome fails predicate 7 today** — it declares Enhanced (BROKKR-ARCH
/// §1.4) and its long-lived keys are software-in-process (§6.11), so the honest
/// declaration is refused promotion. This is the expected and correct consequence recorded
/// in §6.2; the predicate is not weakened to let it pass.
#[test]
fn test_r6_2_enhanced_refuses_software_custody() {
    assert_eq!(
        custody_shortfall_of(software_custody(), ConformanceTier::Enhanced),
        Some(CustodyShortfall::NoHardwareBoundary),
        "Enhanced requires a hardware boundary; software custody must be refused"
    );
}

/// AMD-018 §AMD.5 — "a FIPS validation is not by itself evidence of dual control."
/// `SingleOperator` exists so this can be declared honestly, and it must then fail.
#[test]
fn test_r6_2_enhanced_refuses_hardware_without_dual_control() {
    let custody = KeyCustody::HardwareBacked {
        boundary: boundary(),
        dual_control: DualControl::SingleOperator,
    };
    assert_eq!(
        custody_shortfall_of(custody, ConformanceTier::Enhanced),
        Some(CustodyShortfall::NoDualControl),
        "a hardware boundary without two-party issuance does not satisfy R-6.2"
    );
}

#[test]
fn test_r6_2_enhanced_accepts_hardware_with_dual_control() {
    let custody = KeyCustody::HardwareBacked {
        boundary: boundary(),
        dual_control: DualControl::TwoParty {
            procedure: proc_ref("dual-control"),
        },
    };
    assert!(
        custody_shortfall_of(custody, ConformanceTier::Enhanced).is_none(),
        "hardware boundary + two-party issuance satisfies R-6.2"
    );
}

// ---- R-6.3 (High-Assurance) ----

#[test]
fn test_r6_3_high_assurance_refuses_hardware_without_threshold() {
    let custody = KeyCustody::HardwareBacked {
        boundary: boundary(),
        dual_control: DualControl::TwoParty {
            procedure: proc_ref("dual-control"),
        },
    };
    assert_eq!(
        custody_shortfall_of(custody, ConformanceTier::HighAssurance),
        Some(CustodyShortfall::NoThresholdCustody),
        "R-6.3 requires k-of-n custody in addition to R-6.2"
    );
}

/// **The one shortfall caught on substance rather than form.** AMD-018 §AMD.3: the original
/// OQGF-R-6 could be satisfied by a Shamir implementation with every share in one hand;
/// R-6.3 cannot. A declared 3-of-5 with one independent party is well-formed and
/// self-evidently non-conformant — it fails on its own stated numbers.
#[test]
fn test_r6_3_declared_3_of_5_with_one_independent_party_fails_on_its_own_numbers() {
    assert_eq!(
        custody_shortfall_of(
            threshold_custody(3, 5, 1, NOW - 1000),
            ConformanceTier::HighAssurance
        ),
        Some(CustodyShortfall::InsufficientCustodialSeparation),
        "3-of-5 whose shares one party holds does not satisfy R-6.3"
    );
}

#[test]
fn test_r6_3_quorum_below_floor_fails() {
    assert_eq!(
        custody_shortfall_of(
            threshold_custody(2, 5, 5, NOW - 1000),
            ConformanceTier::HighAssurance
        ),
        Some(CustodyShortfall::QuorumBelowFloor),
        "k < 3 is below AMD-018's floor"
    );
    assert_eq!(
        custody_shortfall_of(
            threshold_custody(3, 4, 4, NOW - 1000),
            ConformanceTier::HighAssurance
        ),
        Some(CustodyShortfall::QuorumBelowFloor),
        "n < 5 is below AMD-018's floor"
    );
}

#[test]
fn test_r6_3_stale_or_future_rehearsal_fails() {
    // NOW is ~231 days from the epoch, so no rehearsal can be a year stale at that clock.
    // Advance `now` instead of retreating the rehearsal below zero.
    let two_years_on = NOW + 2 * 31_536_000_000u64;
    assert_eq!(
        custody_shortfall_at(
            threshold_custody(3, 5, 3, NOW),
            ConformanceTier::HighAssurance,
            two_years_on
        ),
        Some(CustodyShortfall::RehearsalStale),
        "a rehearsal older than a year does not satisfy R-6.3's annual bound"
    );
    assert_eq!(
        custody_shortfall_of(
            threshold_custody(3, 5, 3, NOW + 1_000_000),
            ConformanceTier::HighAssurance
        ),
        Some(CustodyShortfall::RehearsalStale),
        "a rehearsal dated in the future is malformed and fails, as predicate 4 treats a \
         future trust-score review"
    );
}

#[test]
fn test_r6_3_high_assurance_accepts_conformant_threshold() {
    assert!(
        custody_shortfall_of(
            threshold_custody(3, 5, 3, NOW - 1000),
            ConformanceTier::HighAssurance
        )
        .is_none(),
        "3-of-5 with three independent parties and a recent rehearsal satisfies R-6.3"
    );
}

/// R-6.3 is defined as "in addition to R-6.2", so a threshold declaration that lacks dual
/// control fails on the R-6.2 element — the embedded elements are checked first.
#[test]
fn test_r6_3_threshold_without_dual_control_fails_on_the_r62_element() {
    let custody = KeyCustody::Threshold {
        boundary: boundary(),
        dual_control: DualControl::SingleOperator,
        quorum: Quorum { k: 3, n: 5 },
        custodians: CustodianSeparation {
            independent_parties: 3,
            separation_of_duty: proc_ref("separation"),
        },
        ceremony: proc_ref("ceremony"),
        recovery: proc_ref("recovery"),
        rotation: proc_ref("rotation"),
        last_rehearsal: Timestamp(NOW - 1000),
    };
    assert_eq!(
        custody_shortfall_of(custody, ConformanceTier::HighAssurance),
        Some(CustodyShortfall::NoDualControl),
        "R-6.3 embeds R-6.2; the R-6.2 shortfall is what is reported"
    );
}
