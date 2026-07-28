//! REGIN promotion-gate tests (Phase 5). Real dual-family signing over the real canonical
//! encoding; verification with exported public bytes. No crypto mocks. One negative per
//! predicate, each asserting the specific finding; plus the load-bearing domain-separation
//! test and the Rev 1.5 narrowing case.

use brokkr_core::classification::{Classification, NamedGroup};
use brokkr_core::crypto::{Digest, DualSignature, HashAlg, Signature, SignatureAlg};
use brokkr_core::genome::{
    Aibom, AlgorithmId, Cbom, EndpointRegistry, Genome, InvariantEntry, ModelEndpoint,
    PolicyRegister, PrivilegeClass, RootOfTrustEntry, RootsOfTrust, ToolEntry, ToolGenome,
    ToolSchema, VendorTrustScore,
};
use brokkr_core::ids::{
    ClientCertRef, Dap, GenomeVersion, ModelEndpointId, ModelIdentity, Score, SubjectId, Timestamp,
    ToolId, TrustAnchor,
};
use brokkr_core::intent::{Capability, Invariant};
use brokkr_core::tolerance::ResponseClass;
use brokkr_crypto::{DualKeyPair, DualPublicKey};
use brokkr_genome::canonical;
use brokkr_genome::{Finding, PromotionVerdict, Register, promote};

const NINETY_DAYS_MS: u64 = 7_776_000_000;
const NOW: u64 = 20_000_000_000;

// ---- helpers -------------------------------------------------------------------------

fn dap() -> Dap {
    Dap::new("Jeremy Rose", "dap-1")
}

/// A never-verified placeholder signature (used where a signature is data the gate does
/// not check — the vendor trust score's own signature — and as a pre-signing placeholder).
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
            reviewed: Timestamp(reviewed),
            reviewer: dap(),
            signature: dummy_sig(),
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
        }
    }

    /// Build every register, sign each register's content, then assemble the genome and
    /// sign it (the genome signature covers the registers' real signatures — so registers
    /// are signed first).
    fn sign(self, kp: &DualKeyPair) -> Genome {
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
    let kp = DualKeyPair::generate().unwrap();
    let genome = Parts::default_valid().sign(&kp);
    assert_eq!(
        promote(&genome, &public_of(&kp), Timestamp(NOW)),
        PromotionVerdict::Promoted,
    );
}

#[test]
fn test_canonical_deterministic_and_unambiguous() {
    let kp = DualKeyPair::generate().unwrap();
    let genome = Parts::default_valid().sign(&kp);

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
    let kp = DualKeyPair::generate().unwrap();
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
    let kp = DualKeyPair::generate().unwrap();
    let mut genome = Parts::default_valid().sign(&kp);
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
    let kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    // Put a disallowed algorithm into the CBOM inventory.
    let ecdsa = AlgorithmId::Signature(SignatureAlg::EcdsaP256);
    parts.cbom_algorithms.push(ecdsa);
    let genome = parts.sign(&kp);
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(findings.contains(&Finding::DisallowedAlgorithm { algorithm: ecdsa }));
}

#[test]
fn test_oqgf_m_6_stale_trust_score_blocks() {
    let kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    // reviewed more than 90 days before now.
    parts.endpoints = vec![endpoint("mimir-1", NOW - NINETY_DAYS_MS - 1)];
    let genome = parts.sign(&kp);
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(findings.contains(&Finding::StaleTrustScore {
        endpoint: ModelEndpointId::new("mimir-1")
    }));
}

#[test]
fn test_oqgf_m_6_future_trust_score_blocks() {
    let kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    // reviewed AFTER now — malformed.
    parts.endpoints = vec![endpoint("mimir-1", NOW + 1000)];
    let genome = parts.sign(&kp);
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(findings.contains(&Finding::FutureTrustScore {
        endpoint: ModelEndpointId::new("mimir-1")
    }));
}

#[test]
fn test_tool_capability_not_in_vocabulary_blocks() {
    let kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    // A typo: the tool requires "wirte", which is not in the vocabulary.
    parts.tool_entries[0].required_capabilities = vec![cap("wirte")];
    let genome = parts.sign(&kp);
    let findings = blocked_findings(promote(&genome, &public_of(&kp), Timestamp(NOW)));
    assert!(findings.contains(&Finding::ToolCapabilityNotInVocabulary {
        tool: ToolId::new("write_file"),
        capability: cap("wirte"),
    }));
}

#[test]
fn test_invariant_forbids_unknown_capability_blocks() {
    let kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    // An invariant forbidding a capability absent from the vocabulary (a typo).
    parts.policy_invariants[0].forbids_capabilities = vec![cap("netwrok")];
    let genome = parts.sign(&kp);
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
    let kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    // An invariant that forbids neither a capability nor a privilege — can never fire.
    parts.policy_invariants[0].forbids_capabilities = vec![];
    parts.policy_invariants[0].forbids_privilege = vec![];
    let genome = parts.sign(&kp);
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
    let kp = DualKeyPair::generate().unwrap();
    let mut parts = Parts::default_valid();
    parts.policy_invariants.push(InvariantEntry {
        invariant: Invariant::new("no-read"),
        forbids_capabilities: vec![cap("read")],
        forbids_privilege: vec![],
    });
    let genome = parts.sign(&kp);
    assert_eq!(
        promote(&genome, &public_of(&kp), Timestamp(NOW)),
        PromotionVerdict::Promoted,
        "forbidding a recognized-but-unrequired capability is forward-looking policy, not a fault"
    );
}

#[test]
fn test_all_findings_returned() {
    // A genome failing MULTIPLE predicates returns ALL of them, not just the first.
    let kp = DualKeyPair::generate().unwrap();
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
    let genome = parts.sign(&kp);
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
    let kp = DualKeyPair::generate().unwrap();
    let genome = Parts::default_valid().sign(&kp);
    let wrong = public_of(&DualKeyPair::generate().unwrap());
    let findings = blocked_findings(promote(&genome, &wrong, Timestamp(NOW)));
    assert!(findings.contains(&Finding::GenomeSignatureInvalid));
    assert!(findings.contains(&Finding::RegisterSignatureInvalid {
        register: Register::Tools
    }));
}
