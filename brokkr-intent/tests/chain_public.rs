//! Public-key chain-verification tests (brokkr-intent revision). Real backend, no
//! mocks. Mirrors the Phase 3 chain tests but through `verify_chain_public` with real
//! `DualPublicKey`s — proving a verifier holding ONLY public roots of trust (no private
//! material) can verify a chain, with identical semantics to the keypair path.

use brokkr_core::crypto::{Attestation, Digest, DualSignature, HashAlg, Signature, SignatureAlg};
use brokkr_core::ids::{Dap, Nonce, SubjectId, Timestamp};
use brokkr_core::intent::{
    AttenuationError, Capability, IntentProvenanceChain, IntentScope, Invariant, InvariantSet,
};
use brokkr_crypto::{DualKeyPair, DualPublicKey};
use brokkr_intent::{IntentError, Skuld};

fn scope(caps: &[&str]) -> IntentScope {
    IntentScope::new(caps.iter().map(|c| Capability::new(*c)))
}

fn invs(items: &[&str]) -> InvariantSet {
    InvariantSet::new(items.iter().map(|i| Invariant::new(*i)))
}

fn dummy_sig() -> DualSignature {
    DualSignature {
        lattice: Signature {
            alg: SignatureAlg::MlDsa65,
            bytes: vec![1, 2, 3],
        },
        hash_based: Signature {
            alg: SignatureAlg::SlhDsaShake192s,
            bytes: vec![4, 5, 6],
        },
    }
}

fn attestation(subject: &str) -> Attestation {
    Attestation {
        subject: SubjectId::new(subject),
        measurements: Digest {
            alg: HashAlg::Sha384,
            bytes: vec![0u8; 48],
        },
        freshness: Nonce(1),
        signatures: dummy_sig(),
    }
}

/// The verify-only public key derived from a keypair's exported public bytes.
fn public_of(kp: &DualKeyPair) -> DualPublicKey {
    let (mldsa_pub, slhdsa_pub) = kp.public_key_bytes().unwrap();
    DualPublicKey::from_public_bytes(&mldsa_pub, &slhdsa_pub).unwrap()
}

/// A signed 2-hop chain over scope {read,write,exec} -> {read,write} -> {read}, expiry
/// 10_000. Returns the chain plus the three keypairs (root, hop-1, hop-2).
fn build_chain() -> (
    Skuld,
    IntentProvenanceChain,
    DualKeyPair,
    DualKeyPair,
    DualKeyPair,
) {
    let skuld = Skuld;
    let mut root_kp = DualKeyPair::generate().unwrap();
    let root = skuld
        .sign_root(
            SubjectId::new("principal"),
            Dap::new("Jeremy Rose", "dap-1"),
            scope(&["read", "write", "exec"]),
            invs(&["no-network-egress"]),
            Nonce(42),
            Timestamp(10_000),
            &mut root_kp,
        )
        .unwrap();
    let chain = IntentProvenanceChain::new(root);

    let mut hop1_kp = DualKeyPair::generate().unwrap();
    let chain = skuld
        .attenuate_signed(
            chain,
            attestation("hop-1"),
            scope(&["read", "write"]),
            vec![],
            invs(&["read-only-outside-src"]),
            &mut hop1_kp,
            Timestamp(100),
        )
        .unwrap();

    let mut hop2_kp = DualKeyPair::generate().unwrap();
    let chain = skuld
        .attenuate_signed(
            chain,
            attestation("hop-2"),
            scope(&["read"]),
            vec![],
            InvariantSet::default(),
            &mut hop2_kp,
            Timestamp(200),
        )
        .unwrap();

    (skuld, chain, root_kp, hop1_kp, hop2_kp)
}

#[test]
fn test_verify_chain_public_accepts_valid_multihop() {
    let (skuld, chain, root_kp, hop1_kp, hop2_kp) = build_chain();
    // Only PUBLIC keys — no DualKeyPair reaches verification.
    let root_pub = public_of(&root_kp);
    let hop1_pub = public_of(&hop1_kp);
    let hop2_pub = public_of(&hop2_kp);
    let entries = chain.entries().to_vec();
    assert!(
        skuld
            .verify_chain_public(
                chain.root(),
                &entries,
                &root_pub,
                &[&hop1_pub, &hop2_pub],
                Timestamp(500)
            )
            .is_ok(),
        "a valid multi-hop chain must verify through public roots of trust alone"
    );
}

#[test]
fn test_verify_chain_public_and_keypair_paths_agree() {
    // For one valid chain, the keypair path and the public-key path (SAME keys' public
    // halves) must both return Ok — the two paths agree.
    let (skuld, chain, root_kp, hop1_kp, hop2_kp) = build_chain();
    let entries = chain.entries().to_vec();

    let keypair_ok = skuld
        .verify_chain(
            chain.root(),
            &entries,
            &root_kp,
            &[&hop1_kp, &hop2_kp],
            Timestamp(500),
        )
        .is_ok();

    let root_pub = public_of(&root_kp);
    let hop1_pub = public_of(&hop1_kp);
    let hop2_pub = public_of(&hop2_kp);
    let public_ok = skuld
        .verify_chain_public(
            chain.root(),
            &entries,
            &root_pub,
            &[&hop1_pub, &hop2_pub],
            Timestamp(500),
        )
        .is_ok();

    assert!(
        keypair_ok && public_ok,
        "keypair and public-key paths must agree (both Ok)"
    );
}

#[test]
fn test_verify_chain_public_rejects_tampered_entry() {
    let (skuld, chain, root_kp, hop1_kp, hop2_kp) = build_chain();
    let root_pub = public_of(&root_kp);
    let hop1_pub = public_of(&hop1_kp);
    let hop2_pub = public_of(&hop2_kp);

    let mut entries = chain.entries().to_vec();
    // Broaden hop-1's scope (bypassing extend) — must fail, same as verify_chain.
    entries[0].emitted_scope = scope(&["read", "write", "admin"]);

    let res = skuld.verify_chain_public(
        chain.root(),
        &entries,
        &root_pub,
        &[&hop1_pub, &hop2_pub],
        Timestamp(500),
    );
    assert!(
        matches!(
            res,
            Err(IntentError::Attenuation(AttenuationError::WouldBroaden))
                | Err(IntentError::EntrySignatureInvalid { .. })
        ),
        "a broadened entry must be rejected (WouldBroaden or EntrySignatureInvalid)"
    );
}

#[test]
fn test_verify_chain_public_rejects_wrong_key() {
    let (skuld, chain, root_kp, _hop1_kp, hop2_kp) = build_chain();
    let root_pub = public_of(&root_kp);
    // A DIFFERENT key's public half for hop 0.
    let wrong_pub = public_of(&DualKeyPair::generate().unwrap());
    let hop2_pub = public_of(&hop2_kp);

    let entries = chain.entries().to_vec();
    let res = skuld.verify_chain_public(
        chain.root(),
        &entries,
        &root_pub,
        &[&wrong_pub, &hop2_pub],
        Timestamp(500),
    );
    assert_eq!(
        res.unwrap_err(),
        IntentError::EntrySignatureInvalid { hop: 0 }
    );
}

#[test]
fn test_verify_chain_public_expired() {
    let (skuld, chain, root_kp, hop1_kp, hop2_kp) = build_chain();
    let root_pub = public_of(&root_kp);
    let hop1_pub = public_of(&hop1_kp);
    let hop2_pub = public_of(&hop2_kp);
    let entries = chain.entries().to_vec();

    // now (20_000) > expiry (10_000): refused before the walk.
    assert_eq!(
        skuld
            .verify_chain_public(
                chain.root(),
                &entries,
                &root_pub,
                &[&hop1_pub, &hop2_pub],
                Timestamp(20_000)
            )
            .unwrap_err(),
        IntentError::Attenuation(AttenuationError::Expired)
    );
}

#[test]
fn test_verify_chain_public_hop_key_missing() {
    let (skuld, chain, root_kp, hop1_kp, _hop2_kp) = build_chain();
    let root_pub = public_of(&root_kp);
    let hop1_pub = public_of(&hop1_kp);
    let entries = chain.entries().to_vec(); // 2 entries

    // Only ONE hop public supplied -> hop 1 has no key.
    let res = skuld.verify_chain_public(
        chain.root(),
        &entries,
        &root_pub,
        &[&hop1_pub],
        Timestamp(500),
    );
    assert_eq!(res.unwrap_err(), IntentError::HopKeyMissing { hop: 1 });
}
