//! BIFRÖST crossing tests — real wolfSSL v5.9.2 (non-FIPS) through `brokkr-crypto` for the BCR
//! signatures HÚÐ verifies, and the real HÚÐ gate (no mock barrier — "one gate, one logic").

use brokkr_barrier::canonical::bcr_signed_content;
use brokkr_barrier::{InMemoryPurposeFields, InMemoryAcceptances, InMemoryCeiling};
use brokkr_bifrost::{Bifrost, CrossingRecord};

use brokkr_core::barrier::{
    BarrierCondition, BarrierVerdict, BoundaryCustodyRecord, Destination, DestinationClass,
    PersonalDataTag,
};
use brokkr_core::classification::{ChannelStrength, Classification, NamedGroup};
use brokkr_core::ids::{DatumRef, ModelEndpointId, OriginId, Timestamp};
use brokkr_core::personal_data::{Purpose, RetentionPeriod};
use brokkr_core::reasoner::{Context, ContextClearance};
use brokkr_crypto::DualKeyPair;

use std::time::Duration;

const ENDPOINT: &str = "mimir-1";
const NOW: u64 = 1_000;

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

fn public_of(kp: &DualKeyPair) -> (Vec<u8>, Vec<u8>) {
    kp.public_key_bytes().unwrap()
}

/// A BIFRÖST whose endpoint (`mimir-1`) has the given declared ceiling, over a HÚÐ that verifies
/// BCRs signed by `bcr_issuer`.
fn bifrost_with(
    endpoint_ceiling: Classification,
    bcr_issuer: &DualKeyPair,
) -> Bifrost<InMemoryCeiling, InMemoryAcceptances, InMemoryPurposeFields> {
    let dap = DualKeyPair::generate().unwrap(); // acceptance-verifying key; unused in these tests
    Bifrost::new(
        public_of(bcr_issuer),
        public_of(&dap),
        InMemoryCeiling::new().with(ModelEndpointId::new(ENDPOINT), endpoint_ceiling),
        InMemoryAcceptances::new(),
        brokkr_barrier::InMemoryPurposeFields::default(),
    )
}

/// A BCR authorizing the reasoner `ENDPOINT` for `classification`, signed by `issuer`, with a
/// far-future expiry (so expiry never trips the non-freshness tests).
fn signed_bcr(
    datum: &str,
    classification: Classification,
    personal: Option<PersonalDataTag>,
    issuer: &mut DualKeyPair,
) -> BoundaryCustodyRecord {
    signed_bcr_expiring(
        datum,
        classification,
        personal,
        Timestamp(1_000_000),
        issuer,
    )
}

/// As [`signed_bcr`], with an explicit `expiry` so a test can evaluate on both sides of it
/// (the two-verdict freshness test, I-13 / OQGF-I-9).
fn signed_bcr_expiring(
    datum: &str,
    classification: Classification,
    personal: Option<PersonalDataTag>,
    expiry: Timestamp,
    issuer: &mut DualKeyPair,
) -> BoundaryCustodyRecord {
    let mut bcr = BoundaryCustodyRecord {
        datum: DatumRef::new(datum),
        classification,
        origin: OriginId::new("origin-1"),
        authorized: vec![DestinationClass::Reasoner {
            endpoint: ModelEndpointId::new(ENDPOINT),
        }],
        personal,
        issued: Timestamp(0),
        expiry,
        signature: dummy_dual(),
    };
    bcr.signature = issuer.sign_dual(&bcr_signed_content(&bcr)).unwrap();
    bcr
}

fn context(
    datum: &str,
    classification: Classification,
    personal: Option<PersonalDataTag>,
    bcr: Option<BoundaryCustodyRecord>,
) -> Context {
    Context {
        payload: "fn main() { /* source */ }".to_string(),
        datum: DatumRef::new(datum),
        classification,
        personal,
        bcr,
    }
}

fn reasoner(negotiated: NamedGroup) -> Destination {
    Destination::Reasoner {
        endpoint: ModelEndpointId::new(ENDPOINT),
        negotiated,
    }
}

fn personal_tag() -> PersonalDataTag {
    PersonalDataTag {
        purpose: Purpose {
            description: "review".to_string(),
        },
        retention: RetentionPeriod {
            duration: Duration::from_secs(3600),
        },
        fields: Vec::new(),
    }
}

fn deny_condition(v: &BarrierVerdict) -> Option<BarrierCondition> {
    match v {
        BarrierVerdict::Deny { finding } => Some(finding.condition),
        _ => None,
    }
}

// ---- THE PHASE'S CENTRAL TEST -------------------------------------------------------

#[test]
fn test_oqgf_m_5_classical_group_collapses_to_public() {
    // Endpoint declared Secret; handshake landed on a CLASSICAL group. The effective level
    // collapses to Public regardless of the endpoint's ceiling, so an Internal crossing — with an
    // otherwise-valid BCR — is DENIED on channel-strength collapse. The record states the claim;
    // the channel decides whether the claim is reachable.
    let mut issuer = DualKeyPair::generate().unwrap();
    let bifrost = bifrost_with(Classification::Secret, &issuer);
    let bcr = signed_bcr("d1", Classification::Internal, None, &mut issuer);
    let ctx = context("d1", Classification::Internal, None, Some(bcr));

    let verdict = bifrost.evaluate_context(&ctx, &reasoner(NamedGroup::X25519), Timestamp(NOW));
    assert_eq!(
        deny_condition(&verdict),
        Some(BarrierCondition::ChannelStrengthCollapse)
    );
}

#[test]
fn test_pqc_group_permits_declared_ceiling() {
    // Endpoint Secret, a PQC-hybrid handshake: a Secret context with a valid BCR clears.
    let mut issuer = DualKeyPair::generate().unwrap();
    let bifrost = bifrost_with(Classification::Secret, &issuer);
    let bcr = signed_bcr("d1", Classification::Secret, None, &mut issuer);
    let ctx = context("d1", Classification::Secret, None, Some(bcr));

    let dest = reasoner(NamedGroup::X25519MlKem768);
    assert_eq!(
        bifrost.evaluate_context(&ctx, &dest, Timestamp(NOW)),
        BarrierVerdict::Allow
    );
    // And the sole minter of a ClearedContext — core's provided `clear` — yields one on Allow.
    assert!(bifrost.clear(ctx, &dest, Timestamp(NOW)).is_ok());
}

#[test]
fn test_effective_is_min_not_endpoint() {
    // Endpoint ceiling PUBLIC, a strong PQC channel: the channel does NOT raise the endpoint.
    // effective = min(Public, Secret) = Public, so an Internal crossing is denied even over PQC.
    let mut issuer = DualKeyPair::generate().unwrap();
    let bifrost = bifrost_with(Classification::Public, &issuer);
    let bcr = signed_bcr("d1", Classification::Internal, None, &mut issuer);
    let ctx = context("d1", Classification::Internal, None, Some(bcr));

    let verdict = bifrost.evaluate_context(
        &ctx,
        &reasoner(NamedGroup::Secp384r1MlKem1024),
        Timestamp(NOW),
    );
    assert_eq!(
        deny_condition(&verdict),
        Some(BarrierCondition::ChannelStrengthCollapse)
    );
}

#[test]
fn test_above_public_without_bcr_is_denied() {
    // Condition 2 reaches the reasoner crossing: Internal with no BCR → MissingCustodyRecord.
    let issuer = DualKeyPair::generate().unwrap();
    let bifrost = bifrost_with(Classification::Secret, &issuer);
    let ctx = context("d1", Classification::Internal, None, None);

    let verdict =
        bifrost.evaluate_context(&ctx, &reasoner(NamedGroup::X25519MlKem768), Timestamp(NOW));
    assert_eq!(
        deny_condition(&verdict),
        Some(BarrierCondition::MissingCustodyRecord)
    );
}

#[test]
fn test_public_personal_context_does_not_short_circuit() {
    // The Rev 1.7 correction, at this boundary: a PUBLIC context that is ALSO personal, with no
    // BCR, does NOT short-circuit to Allow — it is denied (MissingCustodyRecord). A sensitivity-
    // only model would have cleared it.
    let issuer = DualKeyPair::generate().unwrap();
    let bifrost = bifrost_with(Classification::Secret, &issuer);
    let ctx = context("d1", Classification::Public, Some(personal_tag()), None);

    let verdict =
        bifrost.evaluate_context(&ctx, &reasoner(NamedGroup::X25519MlKem768), Timestamp(NOW));
    assert_eq!(
        deny_condition(&verdict),
        Some(BarrierCondition::MissingCustodyRecord)
    );
}

#[test]
fn test_crossing_record_carries_negotiated_group() {
    // The record names what was AGREED: the group, the derived strength, the effective ceiling,
    // the classification, and the verdict.
    let issuer = DualKeyPair::generate().unwrap();
    let bifrost = bifrost_with(Classification::Secret, &issuer);
    let ctx = context("d1", Classification::Internal, None, None);
    let dest = reasoner(NamedGroup::X25519);

    let verdict = bifrost.evaluate_context(&ctx, &dest, Timestamp(NOW));
    let record = bifrost
        .crossing_record(&dest, ctx.classification, &verdict)
        .expect("a reasoner crossing has a record");

    assert_eq!(
        record,
        CrossingRecord {
            endpoint: ModelEndpointId::new(ENDPOINT),
            negotiated: NamedGroup::X25519,
            strength: ChannelStrength::Classical,
            // min(Secret endpoint, Classical→Public) = Public
            effective: Classification::Public,
            classification: Classification::Internal,
            verdict,
        }
    );
    // A non-reasoner destination has no negotiated group, so no crossing record.
    assert!(
        bifrost
            .crossing_record(
                &Destination::LocalPath(brokkr_core::ids::ResourcePath::new("x")),
                Classification::Public,
                &BarrierVerdict::Allow,
            )
            .is_none()
    );
}

#[test]
fn test_no_payload_inspection() {
    // Behavioural confirmation that the decision is independent of `payload`: two contexts
    // identical except for their payloads produce the same verdict. (The structural proof — no
    // code path reads `Context::payload` — is a grep in the phase report.)
    let issuer = DualKeyPair::generate().unwrap();
    let bifrost = bifrost_with(Classification::Secret, &issuer);
    let dest = reasoner(NamedGroup::X25519MlKem768);

    let mut a = context("d1", Classification::Internal, None, None);
    a.payload = "AAAA".to_string();
    let mut b = context("d1", Classification::Internal, None, None);
    b.payload = "totally different bytes, much longer, still no BCR".to_string();

    assert_eq!(
        bifrost.evaluate_context(&a, &dest, Timestamp(NOW)),
        bifrost.evaluate_context(&b, &dest, Timestamp(NOW)),
        "the verdict does not depend on the payload"
    );
}

// ---- I-13: freshness against the call time, not a held clock ------------------------

#[test]
fn test_oqgf_m_14_i13_i9_bcr_expiry_evaluated_against_call_time_not_a_held_clock() {
    // OQGF-M-14 / I-13, and OQGF-I-9's expiry clause — BIFRÖST's analogue of SINDRI's two-verdict
    // freshness test. ONE BIFRÖST instance, the SAME context and destination, `clear` called
    // twice with different `now`: before the BCR's expiry the crossing clears (mints a
    // ClearedContext); after expiry it Denies with the `Expired` condition.
    //
    // Why this catches the defect the original tests could not: a held clock is a single stored
    // value, so from one instance it can produce only ONE verdict for a given crossing. Two
    // different verdicts from one instance is therefore impossible under the pre-I-13 design — this
    // test cannot pass against a stored clock. The original bifrost tests all injected `now` at
    // construction (`Bifrost::new(..., Timestamp(NOW))`) and evaluated once, sharing the defect's
    // assumption; none of them could have caught the held clock.
    let mut issuer = DualKeyPair::generate().unwrap();
    let bifrost = bifrost_with(Classification::Secret, &issuer);
    // A BCR authorizing Secret to the endpoint, expiring at 5_000.
    let bcr = signed_bcr_expiring(
        "dv",
        Classification::Secret,
        None,
        Timestamp(5_000),
        &mut issuer,
    );
    let ctx = context("dv", Classification::Secret, None, Some(bcr));
    let dest = reasoner(NamedGroup::X25519MlKem768); // PQC — no channel-strength collapse

    // now (1_000) < expiry (5_000): fresh -> the crossing clears (a ClearedContext is minted).
    assert!(
        bifrost.clear(ctx.clone(), &dest, Timestamp(1_000)).is_ok(),
        "before BCR expiry the crossing clears"
    );

    // SAME instance, SAME context, now (10_000) > expiry (5_000): stale -> Deny(Expired).
    match bifrost.clear(ctx, &dest, Timestamp(10_000)) {
        Err(v) => assert_eq!(
            deny_condition(&v),
            Some(BarrierCondition::Expired),
            "after BCR expiry the crossing is denied with the Expired condition"
        ),
        Ok(_) => panic!("expected Deny(Expired) after BCR expiry, got a cleared context"),
    }
}
