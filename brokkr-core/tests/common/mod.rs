//! Shared test fixtures. No real crypto — mock/opaque bytes only, per the Phase 1
//! prompt (the negative tests run against a mock signer with no FFI).

use brokkr_core::crypto::{
    Attestation, CryptoError, Digest, DualSignature, HashAlg, Hasher, Signature, SignatureAlg,
    Signer, Verifier,
};
use brokkr_core::ids::{Dap, Nonce, SubjectId};

/// A mock signer that returns fixed bytes. Proves the crypto seam is usable
/// without wolfCrypt (Phase 2 supplies the real backend).
pub struct MockSigner {
    pub alg: SignatureAlg,
}

impl Signer for MockSigner {
    fn algorithm(&self) -> SignatureAlg {
        self.alg
    }
    fn sign(&self, msg: &[u8]) -> Result<Signature, CryptoError> {
        // Not cryptography: a deterministic stand-in so tests need no FFI.
        Ok(Signature {
            alg: self.alg,
            bytes: msg.to_vec(),
        })
    }
}

/// A mock verifier that accepts a signature iff its bytes equal the message.
pub struct MockVerifier {
    pub alg: SignatureAlg,
}

impl Verifier for MockVerifier {
    fn algorithm(&self) -> SignatureAlg {
        self.alg
    }
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        if sig.alg == self.alg && sig.bytes == msg {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

/// A mock hasher.
pub struct MockHasher;

impl Hasher for MockHasher {
    fn algorithm(&self) -> HashAlg {
        HashAlg::Sha384
    }
    fn hash(&self, msg: &[u8]) -> Digest {
        Digest {
            alg: HashAlg::Sha384,
            bytes: msg.to_vec(),
        }
    }
}

pub fn dual_sig() -> DualSignature {
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

pub fn digest() -> Digest {
    Digest {
        alg: HashAlg::Sha384,
        bytes: vec![0; 48],
    }
}

pub fn dap() -> Dap {
    Dap::new("Jeremy Rose", "dap-1")
}

pub fn attestation() -> Attestation {
    Attestation {
        subject: SubjectId::new("hop-0"),
        measurements: digest(),
        freshness: Nonce(1),
        signatures: dual_sig(),
    }
}
