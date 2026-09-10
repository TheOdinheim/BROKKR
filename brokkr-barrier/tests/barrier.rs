//! HÚÐ (the Barrier) tests — real dual-family signing over the real canonical encodings,
//! verification with exported public bytes, no crypto mocks. One negative per egress
//! condition (each asserting the specific `BarrierCondition`), the Rev 1.7 defect test,
//! the ingress outcomes incl. the NonPrivileged-allows case, acceptance honoring, and
//! cross-artifact domain separation.

use brokkr_barrier::canonical;
use brokkr_barrier::{Huth, InMemoryAcceptances, InMemoryCeiling};
use brokkr_core::barrier::{
    Barrier, BarrierCondition, BarrierFinding, BarrierVerdict, BoundaryCustodyRecord, BoundaryFlow,
    ContextClass, Destination, DestinationClass, PersonalDataTag,
};
use brokkr_core::capability::EgressProtocol;
use brokkr_core::classification::{ChannelStrength, Classification};
use brokkr_core::crypto::DualSignature;
use brokkr_core::ids::{
    Dap, DatumRef, FindingId, Host, ModelEndpointId, OriginId, ResourcePath, RiskAcceptanceId,
    Timestamp,
};
use brokkr_core::personal_data::{Purpose, RetentionPeriod};
use brokkr_core::risk::{DeterministicGateId, RiskAcceptance};
use brokkr_crypto::{DualKeyPair, DualPublicKey};
use std::time::Duration;

const NOW: u64 = 10_000;

// ---- helpers -------------------------------------------------------------------------

fn dap() -> Dap {
    Dap::new("Jeremy Rose", "dap-1")
}

fn public_bytes(kp: &DualKeyPair) -> (Vec<u8>, Vec<u8>) {
    kp.public_key_bytes().unwrap()
}

fn dummy_sig() -> DualSignature {
    // A structurally valid but wrong signature (for the bad-signature test and as a
    // pre-signing placeholder).
    use brokkr_core::crypto::{Signature, SignatureAlg};
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

fn tag() -> PersonalDataTag {
    PersonalDataTag {
        purpose: Purpose {
            description: "support ticket triage".into(),
        },
        retention: RetentionPeriod {
            duration: Duration::from_secs(86_400),
        },
        fields: Vec::new(),
    }
}

/// A signed BCR. `authorized`/`classification`/`personal`/`expiry`/`datum` are the mutable
/// axes the negatives perturb; the signature is real (over the canonical signed content).
fn signed_bcr(
    bcr_kp: &mut DualKeyPair,
    datum: &str,
    classification: Classification,
    authorized: Vec<DestinationClass>,
    personal: Option<PersonalDataTag>,
    expiry: u64,
) -> BoundaryCustodyRecord {
    let mut bcr = BoundaryCustodyRecord {
        datum: DatumRef::new(datum),
        classification,
        origin: OriginId::new("origin-1"),
        authorized,
        personal,
        issued: Timestamp(1),
        expiry: Timestamp(expiry),
        signature: dummy_sig(),
    };
    bcr.signature = bcr_kp
        .sign_dual(&canonical::bcr_signed_content(&bcr))
        .unwrap();
    bcr
}

fn signed_acceptance(
    dap_kp: &mut DualKeyPair,
    finding: FindingId,
    gate: Option<DeterministicGateId>,
    expiry: u64,
) -> RiskAcceptance {
    let mut a = RiskAcceptance {
        finding,
        gate,
        dap: dap(),
        justification: "removal scheduled; accepted for one quarter".into(),
        expiry: Timestamp(expiry),
        signature: dummy_sig(),
    };
    a.signature = dap_kp
        .sign_dual(&canonical::acceptance_signed_content(&a))
        .unwrap();
    a
}

/// A Barrier with real keys, an endpoint ceiling of `Secret` for "mimir-1", and no
/// acceptances (negatives that need acceptances build their own).
fn barrier(
    bcr_kp: &DualKeyPair,
    dap_kp: &DualKeyPair,
    acceptances: InMemoryAcceptances,
) -> Huth<InMemoryCeiling, InMemoryAcceptances> {
    let ceiling =
        InMemoryCeiling::new().with(ModelEndpointId::new("mimir-1"), Classification::Secret);
    Huth::new(
        public_bytes(bcr_kp),
        public_bytes(dap_kp),
        ceiling,
        acceptances,
    )
}

fn local_dest() -> Destination {
    Destination::LocalPath(ResourcePath::new("./out.txt"))
}

fn egress(
    datum: &str,
    classification: Classification,
    personal: Option<PersonalDataTag>,
    destination: Destination,
    bcr: Option<BoundaryCustodyRecord>,
) -> BoundaryFlow {
    BoundaryFlow::Egress {
        datum: DatumRef::new(datum),
        classification,
        personal,
        destination,
        bcr,
    }
}

fn assert_deny(v: BarrierVerdict, condition: BarrierCondition) {
    match v {
        BarrierVerdict::Deny { finding } => {
            assert_eq!(finding.condition, condition, "wrong condition")
        }
        other => panic!("expected Deny {{ {condition:?} }}, got {other:?}"),
    }
}

// ---- positive ------------------------------------------------------------------------

#[test]
fn test_valid_above_public_egress_allows() {
    let (mut bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    let bcr = signed_bcr(
        &mut bcr_kp,
        "dep-1",
        Classification::Secret,
        vec![DestinationClass::LocalPath(ResourcePath::new("./out.txt"))],
        None,
        NOW + 1000,
    );
    let flow = egress(
        "dep-1",
        Classification::Secret,
        None,
        local_dest(),
        Some(bcr),
    );
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_eq!(b.evaluate(&flow, Timestamp(NOW)), BarrierVerdict::Allow);
}

#[test]
fn test_public_non_personal_allows_via_condition_1() {
    let (bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    // No BCR at all — a Public, non-personal egress short-circuits to Allow.
    let flow = egress("pub-1", Classification::Public, None, local_dest(), None);
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_eq!(b.evaluate(&flow, Timestamp(NOW)), BarrierVerdict::Allow);
}

// ---- THE Rev 1.7 defect test (most important negative) -------------------------------

#[test]
fn test_oqgf_p_11_1_public_personal_data_does_not_short_circuit() {
    // A Public datum WITH a personal tag and no BCR must NOT Allow: OQGF-P-11.1 governs
    // personal data at every tier, Public included. Condition 1 does not fire (personal is
    // Some), so it falls to condition 2 (missing BCR).
    let (bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    let flow = egress(
        "pub-pii",
        Classification::Public,
        Some(tag()),
        local_dest(),
        None,
    );
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_deny(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierCondition::MissingCustodyRecord,
    );
}

// ---- one negative per egress condition -----------------------------------------------

#[test]
fn test_condition_2_missing_bcr_above_public() {
    let (bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    let flow = egress("dep-1", Classification::Secret, None, local_dest(), None);
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_deny(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierCondition::MissingCustodyRecord,
    );
}

#[test]
fn test_condition_3_datum_mismatch() {
    let (mut bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    // BCR covers "other", flow is "dep-1".
    let bcr = signed_bcr(
        &mut bcr_kp,
        "other",
        Classification::Secret,
        vec![DestinationClass::LocalPath(ResourcePath::new("./out.txt"))],
        None,
        NOW + 1000,
    );
    let flow = egress(
        "dep-1",
        Classification::Secret,
        None,
        local_dest(),
        Some(bcr),
    );
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_deny(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierCondition::DatumMismatch,
    );
}

#[test]
fn test_condition_4_bad_signature() {
    let (mut bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    let mut bcr = signed_bcr(
        &mut bcr_kp,
        "dep-1",
        Classification::Secret,
        vec![DestinationClass::LocalPath(ResourcePath::new("./out.txt"))],
        None,
        NOW + 1000,
    );
    bcr.signature = dummy_sig(); // corrupt the signature after signing
    let flow = egress(
        "dep-1",
        Classification::Secret,
        None,
        local_dest(),
        Some(bcr),
    );
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_deny(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierCondition::SignatureInvalid,
    );
}

#[test]
fn test_condition_5_expired() {
    let (mut bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    // expiry before now.
    let bcr = signed_bcr(
        &mut bcr_kp,
        "dep-1",
        Classification::Secret,
        vec![DestinationClass::LocalPath(ResourcePath::new("./out.txt"))],
        None,
        NOW - 1,
    );
    let flow = egress(
        "dep-1",
        Classification::Secret,
        None,
        local_dest(),
        Some(bcr),
    );
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_deny(b.evaluate(&flow, Timestamp(NOW)), BarrierCondition::Expired);
}

#[test]
fn test_condition_6_classification_mismatch() {
    let (mut bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    // BCR is for Internal, flow is Secret.
    let bcr = signed_bcr(
        &mut bcr_kp,
        "dep-1",
        Classification::Internal,
        vec![DestinationClass::LocalPath(ResourcePath::new("./out.txt"))],
        None,
        NOW + 1000,
    );
    let flow = egress(
        "dep-1",
        Classification::Secret,
        None,
        local_dest(),
        Some(bcr),
    );
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_deny(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierCondition::ClassificationMismatch,
    );
}

#[test]
fn test_condition_7_unauthorized_destination() {
    let (mut bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    // BCR authorizes a Network host, flow goes to a LocalPath.
    let bcr = signed_bcr(
        &mut bcr_kp,
        "dep-1",
        Classification::Secret,
        vec![DestinationClass::Network {
            host: Host::new("h"),
        }],
        None,
        NOW + 1000,
    );
    let flow = egress(
        "dep-1",
        Classification::Secret,
        None,
        local_dest(),
        Some(bcr),
    );
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_deny(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierCondition::UnauthorizedDestination,
    );
}

#[test]
fn test_condition_8_channel_strength_collapse() {
    let (mut bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    // A Secret datum over a Classical channel (which permits only Public).
    let dest = Destination::Network {
        host: Host::new("h"),
        port: 443,
        protocol: EgressProtocol::Https,
        channel: ChannelStrength::Classical,
    };
    let bcr = signed_bcr(
        &mut bcr_kp,
        "dep-1",
        Classification::Secret,
        vec![DestinationClass::Network {
            host: Host::new("h"),
        }],
        None,
        NOW + 1000,
    );
    let flow = egress("dep-1", Classification::Secret, None, dest, Some(bcr));
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_deny(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierCondition::ChannelStrengthCollapse,
    );
}

#[test]
fn test_condition_9_personal_tag_absent_from_bcr() {
    let (mut bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    // Flow is personal; BCR carries no personal tag.
    let bcr = signed_bcr(
        &mut bcr_kp,
        "dep-1",
        Classification::Secret,
        vec![DestinationClass::LocalPath(ResourcePath::new("./out.txt"))],
        None,
        NOW + 1000,
    );
    let flow = egress(
        "dep-1",
        Classification::Secret,
        Some(tag()),
        local_dest(),
        Some(bcr),
    );
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_deny(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierCondition::PersonalDataUndeclared,
    );
}

// ---- ingress -------------------------------------------------------------------------

fn ingress(
    datum: &str,
    personal: Option<PersonalDataTag>,
    bcr: Option<BoundaryCustodyRecord>,
    context: ContextClass,
) -> BoundaryFlow {
    BoundaryFlow::Ingress {
        datum: DatumRef::new(datum),
        personal,
        bcr,
        context,
    }
}

#[test]
fn test_provenanced_ingress_allows_in_both_contexts() {
    let (mut bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    // Sign the BCR once (13-FIX F-4: signing is &mut, so the mutable borrow must end before the
    // immutable borrow in `barrier(&bcr_kp, ...)`); reuse the value for both contexts.
    let bcr = signed_bcr(
        &mut bcr_kp,
        "in-1",
        Classification::Secret,
        vec![],
        None,
        NOW + 1000,
    );
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_eq!(
        b.evaluate(
            &ingress("in-1", None, Some(bcr.clone()), ContextClass::Privileged),
            Timestamp(NOW)
        ),
        BarrierVerdict::Allow
    );
    assert_eq!(
        b.evaluate(
            &ingress("in-1", None, Some(bcr), ContextClass::NonPrivileged),
            Timestamp(NOW)
        ),
        BarrierVerdict::Allow
    );
}

#[test]
fn test_oqgf_i_11_unprovenanced_into_nonprivileged_allows() {
    // Quarantine is not denial: unprovenanced public data is useful and MAY be used in a
    // non-privileged context. An implementation denying it would be non-conformant.
    let (bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_eq!(
        b.evaluate(
            &ingress("in-1", None, None, ContextClass::NonPrivileged),
            Timestamp(NOW)
        ),
        BarrierVerdict::Allow,
    );
}

#[test]
fn test_oqgf_i_11_unprovenanced_into_privileged_quarantines() {
    let (bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_eq!(
        b.evaluate(
            &ingress("in-1", None, None, ContextClass::Privileged),
            Timestamp(NOW)
        ),
        BarrierVerdict::Quarantine {
            datum: DatumRef::new("in-1")
        },
    );
}

#[test]
fn test_personal_data_into_privileged_without_purpose_quarantines() {
    // Personal data into a Privileged Context needs a BCR carrying a matching personal tag.
    // Here provenance is established (valid BCR) but the BCR has no personal tag.
    let (mut bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    let bcr = signed_bcr(
        &mut bcr_kp,
        "in-1",
        Classification::Secret,
        vec![],
        None,
        NOW + 1000,
    );
    let b = barrier(&bcr_kp, &dap_kp, InMemoryAcceptances::new());
    assert_eq!(
        b.evaluate(
            &ingress("in-1", Some(tag()), Some(bcr), ContextClass::Privileged),
            Timestamp(NOW)
        ),
        BarrierVerdict::Quarantine {
            datum: DatumRef::new("in-1")
        },
    );
}

// ---- acceptance (AMD-006) ------------------------------------------------------------

/// Build the finding a missing-BCR Secret egress of `datum` raises, and its finding_id.
fn missing_bcr_finding_id(datum: &str) -> FindingId {
    BarrierFinding {
        datum: DatumRef::new(datum),
        condition: BarrierCondition::MissingCustodyRecord,
        classification: Classification::Secret,
        reason: String::new(),
    }
    .finding_id()
}

#[test]
fn test_oqgf_p_9_2_matching_acceptance_yields_accepted_risk() {
    let (bcr_kp, mut dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    let fid = missing_bcr_finding_id("dep-1");
    let acceptance = signed_acceptance(
        &mut dap_kp,
        fid.clone(),
        Some(DeterministicGateId::Barrier),
        NOW + 1000,
    );
    let acc = InMemoryAcceptances::new().with(fid, RiskAcceptanceId::new("ra-7"), acceptance);
    let b = barrier(&bcr_kp, &dap_kp, acc);
    // A Secret egress with no BCR would Deny (condition 2); the acceptance turns it into
    // AcceptedRisk carrying the register entry id.
    let flow = egress("dep-1", Classification::Secret, None, local_dest(), None);
    assert_eq!(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierVerdict::AcceptedRisk {
            entry: RiskAcceptanceId::new("ra-7")
        },
    );
}

#[test]
fn test_oqgf_p_9_2_acceptance_for_different_finding_does_not_apply() {
    // The acceptance names a DIFFERENT (datum, condition); the Deny stands. This is what
    // makes the acceptance scoped rather than blanket.
    let (bcr_kp, mut dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    let other = missing_bcr_finding_id("some-other-datum");
    let acceptance = signed_acceptance(
        &mut dap_kp,
        other.clone(),
        Some(DeterministicGateId::Barrier),
        NOW + 1000,
    );
    let acc = InMemoryAcceptances::new().with(other, RiskAcceptanceId::new("ra-7"), acceptance);
    let b = barrier(&bcr_kp, &dap_kp, acc);
    let flow = egress("dep-1", Classification::Secret, None, local_dest(), None);
    assert_deny(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierCondition::MissingCustodyRecord,
    );
}

#[test]
fn test_oqgf_p_9_3_expired_acceptance_reverts_to_deny() {
    // On expiry the finding reverts to blocking exactly as if no entry existed.
    let (bcr_kp, mut dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    let fid = missing_bcr_finding_id("dep-1");
    let acceptance = signed_acceptance(
        &mut dap_kp,
        fid.clone(),
        Some(DeterministicGateId::Barrier),
        NOW - 1,
    );
    let acc = InMemoryAcceptances::new().with(fid, RiskAcceptanceId::new("ra-7"), acceptance);
    let b = barrier(&bcr_kp, &dap_kp, acc);
    let flow = egress("dep-1", Classification::Secret, None, local_dest(), None);
    assert_deny(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierCondition::MissingCustodyRecord,
    );
}

#[test]
fn test_acceptance_with_wrong_gate_does_not_apply() {
    // gate == Some(Genome), not Some(Barrier).
    let (bcr_kp, mut dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    let fid = missing_bcr_finding_id("dep-1");
    let acceptance = signed_acceptance(
        &mut dap_kp,
        fid.clone(),
        Some(DeterministicGateId::Genome),
        NOW + 1000,
    );
    let acc = InMemoryAcceptances::new().with(fid, RiskAcceptanceId::new("ra-7"), acceptance);
    let b = barrier(&bcr_kp, &dap_kp, acc);
    let flow = egress("dep-1", Classification::Secret, None, local_dest(), None);
    assert_deny(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierCondition::MissingCustodyRecord,
    );
}

#[test]
fn test_acceptance_with_bad_signature_does_not_apply() {
    // A DAP key mismatch: the acceptance is signed by a different key than the barrier holds.
    let (bcr_kp, dap_kp) = (
        DualKeyPair::generate().unwrap(),
        DualKeyPair::generate().unwrap(),
    );
    let mut wrong_dap = DualKeyPair::generate().unwrap();
    let fid = missing_bcr_finding_id("dep-1");
    let acceptance = signed_acceptance(
        &mut wrong_dap,
        fid.clone(),
        Some(DeterministicGateId::Barrier),
        NOW + 1000,
    );
    let acc = InMemoryAcceptances::new().with(fid, RiskAcceptanceId::new("ra-7"), acceptance);
    let b = barrier(&bcr_kp, &dap_kp, acc); // barrier holds dap_kp, acceptance signed by wrong_dap
    let flow = egress("dep-1", Classification::Secret, None, local_dest(), None);
    assert_deny(
        b.evaluate(&flow, Timestamp(NOW)),
        BarrierCondition::MissingCustodyRecord,
    );
}

// ---- domain separation (load-bearing) ------------------------------------------------

#[test]
fn test_bcr_and_acceptance_domain_separated() {
    let mut kp = DualKeyPair::generate().unwrap();
    let pk = DualPublicKey::from_public_bytes(&public_bytes(&kp).0, &public_bytes(&kp).1).unwrap();

    let bcr = signed_bcr(
        &mut kp,
        "d",
        Classification::Secret,
        vec![],
        None,
        NOW + 1000,
    );
    let acc = signed_acceptance(
        &mut kp,
        FindingId::new("f"),
        Some(DeterministicGateId::Barrier),
        NOW + 1000,
    );

    let bcr_bytes = canonical::bcr_signed_content(&bcr);
    let acc_bytes = canonical::acceptance_signed_content(&acc);

    // The two encodings differ, and a signature over one does not verify as the other.
    assert_ne!(bcr_bytes, acc_bytes);
    assert!(pk.verify_dual(&bcr_bytes, &bcr.signature).is_ok());
    assert!(
        pk.verify_dual(&acc_bytes, &bcr.signature).is_err(),
        "BCR sig must not verify as an acceptance"
    );
    assert!(
        pk.verify_dual(&bcr_bytes, &acc.signature).is_err(),
        "acceptance sig must not verify as a BCR"
    );

    // And neither collides with a brokkr-genome register domain (different tag prefix).
    assert!(!bcr_bytes.starts_with(b"\x00\x00\x00\x00\x00\x00\x00\x15brokkr-genome"));
}
