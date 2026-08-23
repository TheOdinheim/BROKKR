//! Public-key-only verification tests (Phase 2 revision). Real backend, no mocks.
//! Proves a verifier holding ONLY public keys (no private material) verifies exactly
//! what a keypair signed — the public-roots-of-trust half of OQGF-M-8 — and that the
//! dual-family requirement (OQGF-R-1) and fail-closed import both hold.

use brokkr_core::crypto::CryptoError;
use brokkr_crypto::{DualKeyPair, DualPublicKey};

const MSG: &[u8] = b"BROKKR M-8 public-roots-of-trust verification";

#[test]
fn test_oqgf_m_8_public_key_only_verification() {
    let mut kp = DualKeyPair::generate().unwrap();
    let sig = kp.sign_dual(MSG).unwrap();

    // A signer publishes only its public keys.
    let (mldsa_pub, slhdsa_pub) = kp.public_key_bytes().unwrap();
    assert_eq!(mldsa_pub.len(), 1952, "ML-DSA-65 public key is 1952 bytes");
    assert_eq!(
        slhdsa_pub.len(),
        48,
        "SLH-DSA-SHAKE-192s public key is 48 bytes"
    );

    // A verifier holding ONLY those public bytes (no private material) verifies exactly
    // what the keypair signed.
    let pubkey = DualPublicKey::from_public_bytes(&mldsa_pub, &slhdsa_pub).unwrap();
    assert!(pubkey.verify_dual(MSG, &sig).is_ok());

    // A different message does not verify.
    assert!(pubkey.verify_dual(b"a different message", &sig).is_err());
}

#[test]
fn test_wrong_public_key_fails() {
    let mut kp = DualKeyPair::generate().unwrap();
    let sig = kp.sign_dual(MSG).unwrap();

    // A DIFFERENT keypair's public bytes must not verify kp's signature.
    let other = DualKeyPair::generate().unwrap();
    let (m, s) = other.public_key_bytes().unwrap();
    let wrong = DualPublicKey::from_public_bytes(&m, &s).unwrap();
    assert_eq!(
        wrong.verify_dual(MSG, &sig).unwrap_err(),
        CryptoError::VerificationFailed
    );
}

#[test]
fn test_oqgf_r_1_both_families_required() {
    let mut kp = DualKeyPair::generate().unwrap();
    let (m, s) = kp.public_key_bytes().unwrap();
    let pubkey = DualPublicKey::from_public_bytes(&m, &s).unwrap();

    // Intact: both families verify.
    let good = kp.sign_dual(MSG).unwrap();
    assert!(pubkey.verify_dual(MSG, &good).is_ok());

    // Tamper ONLY the lattice (ML-DSA) signature -> the dual fails (SLH-DSA intact).
    let mut only_lattice_bad = kp.sign_dual(MSG).unwrap();
    only_lattice_bad.lattice.bytes[0] ^= 0xff;
    assert!(pubkey.verify_dual(MSG, &only_lattice_bad).is_err());

    // Tamper ONLY the hash-based (SLH-DSA) signature -> the dual fails (ML-DSA intact).
    let mut only_hash_bad = kp.sign_dual(MSG).unwrap();
    only_hash_bad.hash_based.bytes[0] ^= 0xff;
    assert!(pubkey.verify_dual(MSG, &only_hash_bad).is_err());
}

#[test]
fn test_malformed_public_bytes_rejected() {
    let kp = DualKeyPair::generate().unwrap();
    let (m, s) = kp.public_key_bytes().unwrap();

    // Wrong-length ML-DSA public bytes -> fail-closed import.
    assert!(DualPublicKey::from_public_bytes(&m[..100], &s).is_err());
    // Wrong-length SLH-DSA public bytes -> fail-closed import.
    assert!(DualPublicKey::from_public_bytes(&m, &s[..10]).is_err());
    // Empty ML-DSA public bytes -> MalformedKey (matches!, since DualPublicKey holds
    // raw FFI handles and is intentionally not Debug).
    assert!(matches!(
        DualPublicKey::from_public_bytes(&[], &s),
        Err(CryptoError::MalformedKey)
    ));
}

#[test]
fn test_tampered_public_key_fails_verification() {
    // Verification is keyed on the FULL public-key bytes, not a prefix. A one-byte flip
    // in the *middle* of a public key (keeping its length valid) must never produce an
    // import that then verifies the intact signature — the key analog of the Phase 3
    // narrowing-scope M-9 tamper proof, which a fresh-different-keypair test cannot catch.
    let mut kp = DualKeyPair::generate().unwrap();
    let sig = kp.sign_dual(MSG).unwrap();
    let (mldsa_pub, slhdsa_pub) = kp.public_key_bytes().unwrap();

    // Case A — flip one middle byte of the ML-DSA public key; SLH-DSA intact.
    let mut mldsa_tampered = mldsa_pub.clone();
    let mid = mldsa_tampered.len() / 2;
    mldsa_tampered[mid] ^= 0xff;
    match DualPublicKey::from_public_bytes(&mldsa_tampered, &slhdsa_pub) {
        // Import rejected the tampered key — acceptable (fail-closed).
        Err(_) => {}
        // Import succeeded (length still 1952) -> verification MUST fail.
        Ok(pubkey) => assert!(
            pubkey.verify_dual(MSG, &sig).is_err(),
            "a tampered ML-DSA public key must not verify the intact signature"
        ),
    }

    // Case B — flip one middle byte of the SLH-DSA public key; ML-DSA intact.
    let mut slhdsa_tampered = slhdsa_pub.clone();
    let mid = slhdsa_tampered.len() / 2;
    slhdsa_tampered[mid] ^= 0xff;
    match DualPublicKey::from_public_bytes(&mldsa_pub, &slhdsa_tampered) {
        Err(_) => {}
        Ok(pubkey) => assert!(
            pubkey.verify_dual(MSG, &sig).is_err(),
            "a tampered SLH-DSA public key must not verify the intact signature"
        ),
    }
}
