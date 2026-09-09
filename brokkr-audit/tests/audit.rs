//! SAGA functionality and structural tests — real wolfSSL v5.9.2 (non-FIPS) through
//! `brokkr-crypto`, no mocks. Every record is signed with a real `DualKeyPair` over the real
//! canonical encoding; every verification uses exported public bytes.

use std::time::Duration;

use brokkr_audit::{
    AuditEvent, AuthorizationOutcome, AuthorizationRecord, BarrierCrossing, ChainStatus,
    CryptoGeneration, ErasureTombstone, ProposalRecord, RecordedInput, Saga, TimestampAuthority,
    TimestampToken, Timestamping,
};
use brokkr_core::barrier::{BarrierVerdict, BoundaryFlow, Destination, PersonalDataTag};
use brokkr_core::classification::Classification;
use brokkr_core::crypto::{Digest, Hasher};
use brokkr_core::gate::Action;
use brokkr_core::ids::{
    Dap, DatumRef, FindingId, ModelIdentity, ResourcePath, SubjectId, Timestamp, ToolId,
};
use brokkr_core::personal_data::{Purpose, RetentionPeriod};
use brokkr_core::risk::{DeterministicGateId, RiskAcceptance};
use brokkr_crypto::{DualKeyPair, Sha384Hasher, SubjectKey};

// ---- helpers -------------------------------------------------------------------------

fn dap() -> Dap {
    Dap::new("Jeremy Rose", "dap-1")
}

fn genesis() -> Digest {
    Sha384Hasher.hash(b"brokkr-audit:genesis:test")
}

fn new_saga(tsa: Option<Box<dyn TimestampAuthority>>) -> (Saga, DualKeyPair) {
    // A second keypair with the SAME public bytes is impossible, so the Saga owns the signer
    // and the test asks it for its public bytes when it needs to verify.
    let signer = DualKeyPair::generate().unwrap();
    let saga = Saga::new(signer, CryptoGeneration(1), genesis(), tsa).unwrap();
    // Return a throwaway extra keypair used where a *different* key is needed (re-signing).
    let other = DualKeyPair::generate().unwrap();
    (saga, other)
}

fn correction(n: u64, detail: &str) -> AuditEvent {
    AuditEvent::Correction {
        corrects: n,
        detail: detail.to_string(),
    }
}

fn authorization() -> AuditEvent {
    AuditEvent::Authorization(AuthorizationRecord {
        action: Action {
            tool: ToolId::new("write_file"),
            detail: "src/main.rs".to_string(),
        },
        outcome: AuthorizationOutcome::Granted,
    })
}

fn personal_tag() -> PersonalDataTag {
    PersonalDataTag {
        purpose: Purpose {
            description: "support ticket triage".to_string(),
        },
        retention: RetentionPeriod {
            duration: Duration::from_secs(30 * 24 * 3600),
        },
    }
}

fn shredded_proposal(subject: &SubjectId, ciphertext: Vec<u8>) -> AuditEvent {
    AuditEvent::Proposal(ProposalRecord {
        model: ModelIdentity {
            name: "claude-opus".to_string(),
            version: "4.8".to_string(),
            provider: "anthropic".to_string(),
        },
        aibom_digest: Sha384Hasher.hash(b"aibom"),
        input: RecordedInput::Shredded {
            subject: subject.clone(),
            personal: personal_tag(),
            ciphertext,
        },
        output: "proposed edit".to_string(),
        explanation: "rationale".to_string(),
    })
}

fn intact(s: &ChainStatus) -> bool {
    matches!(s, ChainStatus::Intact)
}

// A test-double timestamp authority (§ Task 8: test double only). It echoes the canonical
// bytes as an opaque "token" — enough to prove the seam wires a Token when an authority is
// present. NOT a production RFC-3161 authority.
struct EchoTsa;
impl TimestampAuthority for EchoTsa {
    fn stamp(&self, canonical: &[u8]) -> Result<TimestampToken, brokkr_audit::TimestampError> {
        Ok(TimestampToken {
            token: canonical.to_vec(),
            authority: "echo-test-double".to_string(),
            algorithm: brokkr_audit::TimestampSigAlg::Unrecognized {
                key_oid: 0,
                hash_oid: 0,
            },
            key_oid: 0,
            hash_oid: 0,
            gen_time: "19700101000000Z".to_string(),
        })
    }
}

// ---- positive ------------------------------------------------------------------------

#[test]
fn test_append_and_verify_multi_record_chain() {
    let (saga, _) = new_saga(None);
    saga.append(correction(0, "a"), dap(), Timestamp(1))
        .unwrap();
    saga.append(authorization(), dap(), Timestamp(2)).unwrap();
    saga.append(correction(1, "b"), dap(), Timestamp(3))
        .unwrap();
    assert_eq!(saga.records().len(), 3);
    assert!(intact(&saga.verify_chain()));
    // Sequence numbers increment; the first record links to genesis.
    let recs = saga.records();
    assert_eq!(recs[0].seq, 0);
    assert_eq!(recs[0].prev, genesis());
    assert_eq!(recs[2].seq, 2);
}

#[test]
fn test_public_nonpersonal_record_round_trips() {
    let (saga, _) = new_saga(None);
    let flow = BoundaryFlow::Egress {
        datum: DatumRef::new("d1"),
        classification: Classification::Public,
        personal: None,
        destination: Destination::LocalPath(ResourcePath::new("out.txt")),
        bcr: None,
    };
    let event = AuditEvent::BarrierCrossing(BarrierCrossing {
        verdict: BarrierVerdict::Allow,
        flow,
        bcr_digest: None,
        dap: None,
    });
    saga.append(event, dap(), Timestamp(1)).unwrap();
    assert!(intact(&saga.verify_chain()));
}

#[test]
fn test_export_verifies_under_exporter_key() {
    let (saga, other) = new_saga(None);
    saga.append(correction(0, "a"), dap(), Timestamp(1))
        .unwrap();
    saga.append(authorization(), dap(), Timestamp(2)).unwrap();

    let export = saga.export().unwrap();
    let public = saga.signer_public().unwrap();
    assert!(
        export.verify(&public),
        "export verifies under the exporter's key"
    );

    // A different key must not verify the bundle.
    let other_public = other.public_key_bytes().unwrap();
    assert!(
        !export.verify(&other_public),
        "a foreign key must not verify the export"
    );
}

// ---- OQGF-A-6 re-signing -------------------------------------------------------------

#[test]
fn test_oqgf_a_6_resigning_does_not_break_the_chain() {
    // The Rev 1.10 correction, executable: because the chain links over signed content only,
    // re-signing an early record leaves every downstream link byte-identical.
    let (saga, mut new_gen_signer) = new_saga(None);
    saga.append(correction(0, "a"), dap(), Timestamp(1))
        .unwrap();
    saga.append(authorization(), dap(), Timestamp(2)).unwrap();
    saga.append(correction(1, "b"), dap(), Timestamp(3))
        .unwrap();

    let prev_of_1_before = saga.records()[1].prev.clone();
    let prev_of_2_before = saga.records()[2].prev.clone();

    saga.resign(0, CryptoGeneration(2), &mut new_gen_signer, Timestamp(100))
        .unwrap();

    assert!(
        intact(&saga.verify_chain()),
        "chain still verifies after re-signing"
    );
    assert_eq!(
        saga.records()[1].prev,
        prev_of_1_before,
        "the record following the re-signed one has a byte-identical prev"
    );
    assert_eq!(saga.records()[2].prev, prev_of_2_before);
}

#[test]
fn test_oqgf_a_6_resigning_preserves_original_signature() {
    let (saga, mut new_gen_signer) = new_saga(None);
    saga.append(correction(0, "a"), dap(), Timestamp(1))
        .unwrap();

    let original = saga.records()[0].signatures[0].clone();
    assert_eq!(original.generation, CryptoGeneration(1));

    saga.resign(0, CryptoGeneration(2), &mut new_gen_signer, Timestamp(100))
        .unwrap();

    let after = saga.records();
    assert_eq!(
        after[0].signatures.len(),
        2,
        "re-signing appends, not replaces"
    );
    assert_eq!(
        after[0].signatures[0], original,
        "the original signature is unchanged and still present"
    );
    assert_eq!(after[0].signatures[1].generation, CryptoGeneration(2));
    // Both signatures verify (verify_chain checks the whole set under each generation's key).
    assert!(intact(&saga.verify_chain()));
}

// ---- OQGF-P-11.5 / 11.7 erasure ------------------------------------------------------

#[test]
fn test_oqgf_p_11_5_erasure_preserves_chain() {
    let (saga, _) = new_saga(None);
    let subject = SubjectId::new("subject-42");

    // A subject key protects the personal data; the ciphertext is what the record holds.
    let mut subject_key = SubjectKey::generate().unwrap();
    let (_wrapped, _dk) = subject_key.wrap_new_data_key().unwrap();

    saga.append(correction(0, "before"), dap(), Timestamp(1))
        .unwrap();
    let personal_seq = saga
        .append(
            shredded_proposal(&subject, b"ciphertext-blob".to_vec()),
            dap(),
            Timestamp(2),
        )
        .unwrap();

    // The record holding personal data, captured before erasure.
    let personal_record_before = saga.records()[personal_seq as usize].clone();

    // Erase: destroy the key (crypto layer), then record the tombstone (SAGA).
    subject_key.shred();
    saga.record_erasure(
        ErasureTombstone {
            erased: personal_seq,
            classification: Classification::Cui,
            at: Timestamp(3),
            dap: dap(),
        },
        dap(),
        Timestamp(3),
    )
    .unwrap();

    // The chain still verifies, and the erased record itself is byte-for-byte unchanged.
    assert!(intact(&saga.verify_chain()));
    let personal_record_after = saga.records()[personal_seq as usize].clone();
    assert_eq!(
        personal_record_before, personal_record_after,
        "erasure does not modify the erased record; it appends a tombstone"
    );
    // A tombstone naming the erased seq is present.
    assert!(saga.records().iter().any(|r| matches!(
        &r.event,
        AuditEvent::Erasure(t) if t.erased == personal_seq
    )));
}

#[test]
fn test_oqgf_p_11_7_resigned_erased_record_stays_irrecoverable() {
    // THE MOST IMPORTANT TEST. Erase, then re-sign the erased record, then confirm the
    // plaintext is STILL unrecoverable: re-signing operates over ciphertext and canonical
    // bytes only and holds no subject key, so it cannot undo an erasure.
    let (saga, mut new_gen_signer) = new_saga(None);
    let subject = SubjectId::new("subject-7");

    let mut subject_key = SubjectKey::generate().unwrap();
    let (wrapped, dk) = subject_key.wrap_new_data_key().unwrap();

    // Positive control: before erasure, the data key is recoverable.
    let recovered = subject_key.unwrap_data_key(&wrapped).unwrap();
    assert_eq!(recovered, dk, "before erasure the data key unwraps");

    let personal_seq = saga
        .append(
            shredded_proposal(&subject, b"aes-gcm-under-dk".to_vec()),
            dap(),
            Timestamp(1),
        )
        .unwrap();

    // Erase: destroy the subject key. The data key — and therefore any ciphertext under it,
    // including what the record holds — is now cryptographically irrecoverable.
    subject_key.shred();
    saga.record_erasure(
        ErasureTombstone {
            erased: personal_seq,
            classification: Classification::Secret,
            at: Timestamp(2),
            dap: dap(),
        },
        dap(),
        Timestamp(2),
    )
    .unwrap();
    assert!(
        subject_key.unwrap_data_key(&wrapped).is_err(),
        "after erasure the data key is unrecoverable"
    );

    // Re-sign the ERASED record under a new generation.
    saga.resign(
        personal_seq,
        CryptoGeneration(2),
        &mut new_gen_signer,
        Timestamp(3),
    )
    .unwrap();

    // The chain still verifies AND the plaintext is STILL unrecoverable — re-signing added a
    // signature over the canonical bytes; it did not, and structurally cannot, restore the key.
    assert!(intact(&saga.verify_chain()));
    assert!(
        subject_key.unwrap_data_key(&wrapped).is_err(),
        "re-signing does not resurrect erased data (OQGF-P-11.7)"
    );
}

// ---- OQGF-A.6.1 chain-break trigger --------------------------------------------------

#[test]
fn test_chain_break_emits_a_6_1_signal() {
    use brokkr_core::ids::OrganId;
    use brokkr_core::signal::{Severity, SignalClass};

    let (saga, _) = new_saga(None);
    saga.append(correction(0, "a"), dap(), Timestamp(1))
        .unwrap();
    saga.append(correction(1, "b"), dap(), Timestamp(2))
        .unwrap();
    saga.append(correction(2, "c"), dap(), Timestamp(3))
        .unwrap();

    // Tamper record 1 after the fact by rewriting its event; its signature (over the original
    // signed content) will no longer verify.
    let signer = DualKeyPair::generate().unwrap(); // stand-in signer for the reconstructed store
    let public = saga.signer_public().unwrap();
    let mut records = saga.records();
    if let AuditEvent::Correction { corrects, .. } = records[1].event.clone() {
        records[1].event = AuditEvent::Correction {
            corrects,
            detail: "TAMPERED".to_string(),
        };
    }
    // Reconstruct a store over the tampered records, keeping the real verifier key so the
    // signature check runs against the genuine public key.
    let verifiers = vec![(CryptoGeneration(1), public)];
    let tampered = Saga::from_records(
        signer,
        CryptoGeneration(1),
        genesis(),
        None,
        records,
        verifiers,
    );

    match tampered.verify_chain() {
        ChainStatus::Intact => panic!("tampered chain must not verify"),
        ChainStatus::Broken(signal) => {
            assert_eq!(signal.source, OrganId::Audit);
            assert_eq!(signal.class, SignalClass::ThreatDetected);
            assert_eq!(signal.severity, Severity::Critical);
        }
    }
}

#[test]
fn test_correction_does_not_alter_corrected_record() {
    let (saga, _) = new_saga(None);
    saga.append(authorization(), dap(), Timestamp(1)).unwrap();
    let corrected_before = saga.records()[0].clone();
    let digest_before = Sha384Hasher.hash(&brokkr_audit::canonical::record_signed_content(
        &corrected_before,
    ));

    // A correction is an appended event, not an edit.
    saga.append(
        correction(0, "the earlier entry was mis-scoped"),
        dap(),
        Timestamp(2),
    )
    .unwrap();

    let corrected_after = saga.records()[0].clone();
    assert_eq!(
        corrected_before, corrected_after,
        "the corrected entry is untouched by the correction"
    );
    let digest_after = Sha384Hasher.hash(&brokkr_audit::canonical::record_signed_content(
        &corrected_after,
    ));
    assert_eq!(
        digest_before, digest_after,
        "the corrected entry's digest is unchanged"
    );
    assert!(intact(&saga.verify_chain()));
}

// ---- OQGF-A-3 timestamp seam ---------------------------------------------------------

#[test]
fn test_oqgf_a_3_absent_authority_records_unavailable() {
    let (saga, _) = new_saga(None); // no TSA configured
    saga.append(correction(0, "a"), dap(), Timestamp(1))
        .unwrap();
    let rec = saga.records();
    match &rec[0].timestamping {
        Timestamping::Unavailable { reason } => assert!(!reason.is_empty()),
        Timestamping::Token(_) => panic!("no authority was configured; expected Unavailable"),
    }
    // The record still appended and the chain verifies — recording is not refused.
    assert_eq!(rec.len(), 1);
    assert!(intact(&saga.verify_chain()));
}

#[test]
fn test_oqgf_a_3_present_authority_records_token() {
    let (saga, _) = new_saga(Some(Box::new(EchoTsa)));
    saga.append(correction(0, "a"), dap(), Timestamp(1))
        .unwrap();
    assert!(matches!(
        &saga.records()[0].timestamping,
        Timestamping::Token(_)
    ));
    assert!(intact(&saga.verify_chain()));
}

// ---- Task 1 domain separation across three crates ------------------------------------

fn tagged(tag: &[u8], payload: &[u8]) -> Vec<u8> {
    // Mirrors the Canon domain-tag prefix (8-byte BE length, then the tag), so this is what a
    // brokkr-genome / brokkr-barrier signed content begins with.
    let mut v = Vec::new();
    v.extend_from_slice(&(tag.len() as u64).to_be_bytes());
    v.extend_from_slice(tag);
    v.extend_from_slice(payload);
    v
}

#[test]
fn test_audit_domain_separated_from_genome_and_barrier() {
    let (saga, _) = new_saga(None);
    saga.append(authorization(), dap(), Timestamp(1)).unwrap();
    let record = saga.records()[0].clone();
    let audit_bytes = brokkr_audit::canonical::record_signed_content(&record);

    // The audit signed content begins with the audit domain tag, and with none of the others.
    assert!(audit_bytes.starts_with(&tagged(b"brokkr-audit:record:v1", b"")));
    for foreign in [
        &b"brokkr-barrier:bcr:v1"[..],
        b"brokkr-barrier:risk-acceptance:v1",
        b"brokkr-genome:tools:v1",
        b"brokkr-genome:genome:v1",
    ] {
        assert!(
            !audit_bytes.starts_with(&tagged(foreign, b"")),
            "audit bytes must not share a foreign domain tag"
        );
    }

    // Crypto direction: a signature over foreign-tagged bytes does not verify as the audit
    // record's signed content, and vice versa.
    let public = saga.signer_public().unwrap();
    let export = saga.export().unwrap();
    // (export gives us nothing to sign with directly; use a fresh keypair for the crypto test)
    let mut kp = DualKeyPair::generate().unwrap();
    let kp_public = kp.public_key_bytes().unwrap();

    let barrier_like = tagged(b"brokkr-barrier:bcr:v1", b"some-bcr-content");
    let sig_over_audit = kp.sign_dual(&audit_bytes).unwrap();
    let sig_over_barrier = kp.sign_dual(&barrier_like).unwrap();

    let vk = brokkr_crypto::DualPublicKey::from_public_bytes(&kp_public.0, &kp_public.1).unwrap();
    assert!(vk.verify_dual(&audit_bytes, &sig_over_audit).is_ok());
    assert!(
        vk.verify_dual(&barrier_like, &sig_over_audit).is_err(),
        "an audit-record signature must not verify over barrier-tagged bytes"
    );
    assert!(
        vk.verify_dual(&audit_bytes, &sig_over_barrier).is_err(),
        "a barrier-tagged signature must not verify over the audit record"
    );

    // The exporter's own key is distinct from the throwaway kp used above.
    assert_ne!(public, kp_public);
    let _ = export; // silence unused in case of future edits
}

// ---- Task 7 the acceptance register --------------------------------------------------

#[test]
fn test_acceptance_register_assigns_id() {
    let (saga, _) = new_saga(None);
    let mut kp = DualKeyPair::generate().unwrap();
    let acceptance = RiskAcceptance {
        finding: FindingId::new("42:d1:unauthorized-destination"),
        gate: Some(DeterministicGateId::Barrier),
        dap: dap(),
        justification: "vendor dependency, remediation tracked".to_string(),
        expiry: Timestamp(9_999),
        signature: kp.sign_dual(b"acceptance").unwrap(),
    };

    let id = saga.record_acceptance(acceptance.clone());
    // The SAGA-assigned id resolves back to the same record — this is where HÚÐ's resolver
    // gets its (id, record) pair.
    assert_eq!(saga.resolve_acceptance(&id), Some(acceptance.clone()));

    // A second acceptance gets a distinct id; the inventory reports both.
    let id2 = saga.record_acceptance(acceptance);
    assert_ne!(id, id2);
    assert_eq!(saga.acceptance_inventory().len(), 2);
}
