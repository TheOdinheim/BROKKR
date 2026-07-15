//! The cryptographic seam: traits and typed algorithm identifiers only.
//!
//! No implementation lives here and nothing calls wolfCrypt. Phase 2
//! (`brokkr-crypto`) implements [`Signer`] / [`Verifier`] / [`Hasher`] against
//! wolfCrypt. Algorithm identifiers are typed enums, never strings (OQGF-G-5).

use crate::ids::{Nonce, SubjectId};
use alloc::vec::Vec;

/// Signature algorithm identifier. Typed, never a string (OQGF-G-5). Classical
/// variants are the hybrid fallback deprecated after 2030 (OQGF-R-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureAlg {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaSha2_128s,
    SlhDsaSha2_192s,
    SlhDsaSha2_256s,
    SlhDsaShake128s,
    SlhDsaShake192s,
    SlhDsaShake256s,
    EcdsaP256,
    EcdsaP384,
}

/// Hash algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
    Shake128,
    Shake256,
}

/// Key-encapsulation algorithm identifier (used for at-rest AES-256 keys per
/// BROKKR-ARCH 6.11 — established under ML-KEM, never classically).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KemAlg {
    MlKem512,
    MlKem768,
    MlKem1024,
}

/// Opaque signature bytes bound to a typed algorithm identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    pub alg: SignatureAlg,
    pub bytes: Vec<u8>,
}

/// Opaque digest bytes bound to a typed algorithm identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    pub alg: HashAlg,
    pub bytes: Vec<u8>,
}

/// A dual-family signature: one lattice (ML-DSA) plus one hash-based (SLH-DSA),
/// per OQGF-R-1 at Enhanced. The pairing is a shape, not a policy: what is signed
/// with a `DualSignature` carries both families.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DualSignature {
    pub lattice: Signature,
    pub hash_based: Signature,
}

/// An identity attestation (Signal 1, OQGF-M-1). Opaque payload; verification is
/// a Phase 2/4 concern. No crypto is performed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub subject: SubjectId,
    pub measurements: Digest,
    pub freshness: Nonce,
    pub signatures: DualSignature,
}

error_enum! {
    /// Errors surfaced by a cryptographic backend (implemented in Phase 2).
    pub enum CryptoError {
        AlgorithmMismatch => "signer/verifier algorithm mismatch",
        VerificationFailed => "signature verification failed",
        MalformedKey => "malformed key material",
        MalformedSignature => "malformed signature",
        Backend => "cryptographic backend error",
    }
}

/// Produces signatures. Implemented in Phase 2 against wolfCrypt.
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> SignatureAlg;
    fn sign(&self, msg: &[u8]) -> Result<Signature, CryptoError>;
}

/// Verifies signatures. Implemented in Phase 2 against wolfCrypt.
pub trait Verifier: Send + Sync {
    fn algorithm(&self) -> SignatureAlg;
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), CryptoError>;
}

/// Computes digests. Implemented in Phase 2 against wolfCrypt.
pub trait Hasher: Send + Sync {
    fn algorithm(&self) -> HashAlg;
    fn hash(&self, msg: &[u8]) -> Digest;
}
