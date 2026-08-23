//! Real round-trip tests against the real wolfCrypt shared library. No mocks — this
//! is the crate where the mock ends and the actual cryptography begins.
//!
//! Ground truth (CLAUDE.md §7) is external to wolfCrypt where a claim needs it:
//! - SHA-384 uses the NIST FIPS 180-4 known-answer vector for "abc".
//! - ML-KEM correctness is the algorithm's defining property (encap/decap agree).
//! - AES-GCM's auth-tag rejection on a wrong key is the AEAD integrity guarantee.
//! - The ML-DSA-65 signature is exactly 3309 bytes (FIPS-204 params) — the anchor
//!   that the bound symbol is ML-DSA, and a `nm` symbol check (see the phase report)
//!   confirms no `dilithium` symbol is referenced.

use brokkr_core::crypto::{HashAlg, Hasher, SignatureAlg, Signer, Verifier};
use brokkr_crypto::{DualKeyPair, MlDsaSigner, Sha384Hasher, SlhDsaSigner, SubjectKey, ffi};

const MSG: &[u8] = b"BROKKR governed audit record: proposal -> gate -> action";

#[test]
fn test_sha384_known_answer_vector_fips_180_4() {
    // FIPS 180-4 SHA-384("abc") — published ground truth, not wolfCrypt's own output.
    let expected: [u8; 48] = [
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50,
        0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff,
        0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34,
        0xc8, 0x25, 0xa7,
    ];
    let digest = Sha384Hasher.hash(b"abc");
    assert_eq!(digest.alg, HashAlg::Sha384);
    assert_eq!(
        digest.bytes, expected,
        "SHA-384(\"abc\") must match the NIST vector"
    );
}

#[test]
fn test_mldsa65_roundtrip_tamper_and_not_dilithium() {
    let signer = MlDsaSigner::generate().unwrap();
    let sig = signer.sign(MSG).unwrap();

    // Not-dilithium / correct-params anchor: ML-DSA-65 signature is exactly 3309 B.
    assert_eq!(
        sig.bytes.len(),
        3309,
        "ML-DSA-65 signature must be 3309 bytes"
    );
    assert_eq!(sig.alg, SignatureAlg::MlDsa65);

    // Valid signature verifies.
    assert!(signer.verify(MSG, &sig).is_ok());

    // Tampered message fails.
    assert!(
        signer
            .verify(b"a different message entirely", &sig)
            .is_err()
    );

    // Tampered signature fails.
    let mut bad = sig.clone();
    bad.bytes[10] ^= 0xff;
    assert!(signer.verify(MSG, &bad).is_err());
}

#[test]
fn test_slhdsa192s_roundtrip_and_tamper() {
    let signer = SlhDsaSigner::generate().unwrap();
    let sig = signer.sign(MSG).unwrap();

    // SLH-DSA-SHAKE-192s signature size (FIPS-205 params).
    assert_eq!(
        sig.bytes.len(),
        16224,
        "SLH-DSA-SHAKE-192s signature must be 16224 bytes"
    );
    assert_eq!(sig.alg, SignatureAlg::SlhDsaShake192s);

    assert!(signer.verify(MSG, &sig).is_ok());
    assert!(signer.verify(b"tampered", &sig).is_err());

    let mut bad = sig.clone();
    bad.bytes[100] ^= 0xff;
    assert!(signer.verify(MSG, &bad).is_err());
}

#[test]
fn test_dual_signature_requires_both_families() {
    let mut kp = DualKeyPair::generate().unwrap();
    let dual = kp.sign_dual(MSG).unwrap();

    assert_eq!(dual.lattice.alg, SignatureAlg::MlDsa65);
    assert_eq!(dual.hash_based.alg, SignatureAlg::SlhDsaShake192s);

    // Both families valid -> the dual verifies.
    assert!(kp.verify_dual(MSG, &dual).is_ok());

    // Corrupt ONLY the lattice (ML-DSA) signature -> the whole dual FAILS, even
    // though the SLH-DSA half is intact. This proves both are required.
    let mut d_lattice = dual.clone();
    d_lattice.lattice.bytes[0] ^= 0xff;
    assert!(
        kp.verify_dual(MSG, &d_lattice).is_err(),
        "a corrupt ML-DSA signature must fail the dual"
    );

    // Corrupt ONLY the hash-based (SLH-DSA) signature -> the whole dual FAILS.
    let mut d_hash = dual.clone();
    d_hash.hash_based.bytes[0] ^= 0xff;
    assert!(
        kp.verify_dual(MSG, &d_hash).is_err(),
        "a corrupt SLH-DSA signature must fail the dual"
    );
}

#[test]
fn test_mlkem768_encapsulate_decapsulate_agree() {
    let kem = ffi::MlKem768::generate().unwrap();
    let (ct, ss_enc) = kem.encapsulate().unwrap();
    let ss_dec = kem.decapsulate(&ct).unwrap();

    // ML-KEM-768 shared secret is 32 bytes; encap and decap must agree.
    assert_eq!(ss_enc.len(), 32);
    assert_eq!(
        ss_enc, ss_dec,
        "ML-KEM encapsulate/decapsulate must produce the same secret"
    );
}

#[test]
fn test_crypto_shred_roundtrip_then_irrecoverable() {
    let mut subject = SubjectKey::generate().unwrap();
    let (wrapped, dk) = subject.wrap_new_data_key().unwrap();

    // Encrypt real "personal data" under the data key, to demonstrate the data
    // becomes irrecoverable once the key is shredded.
    let iv = [7u8; 12];
    let (ct, tag) =
        ffi::aes256_gcm_encrypt(&dk, &iv, b"subject personal data", b"record-42").unwrap();

    // Round-trip: unwrapping recovers the SAME data key, which decrypts the data.
    let dk_again = subject.unwrap_data_key(&wrapped).unwrap();
    assert_eq!(dk, dk_again, "unwrap must recover the same data key");
    let recovered = ffi::aes256_gcm_decrypt(&dk_again, &iv, &ct, &tag, b"record-42").unwrap();
    assert_eq!(recovered, b"subject personal data");

    // A DIFFERENT subject key cannot unwrap: the wrong ML-KEM key yields a wrong KEK,
    // and the AES-GCM auth tag rejects it (AEAD integrity — external ground truth).
    let other = SubjectKey::generate().unwrap();
    assert!(
        other.unwrap_data_key(&wrapped).is_err(),
        "a different subject key must not unwrap the data key"
    );

    // SHRED: destroy the ML-KEM private key.
    subject.shred();

    // After shredding, the original subject can no longer unwrap -> the data key is
    // cryptographically irrecoverable, so the ciphertext above can never be decrypted.
    assert!(
        subject.unwrap_data_key(&wrapped).is_err(),
        "after crypto-shred, the data key must be irrecoverable"
    );
}
