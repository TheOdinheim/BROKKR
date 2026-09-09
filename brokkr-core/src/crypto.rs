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
    /// RSASSA-PKCS#1 v1.5 with SHA-256. **The only classical, non-elliptic signature
    /// algorithm BROKKR names**, and it exists for one reason: an RFC 3161 timestamp
    /// authority signs its tokens RSA or ECDSA, and OQGF-G-1 requires the CBOM to list
    /// every cryptographic primitive the system **uses** — verifying a token is a use
    /// (ARCH Rev 1.25 §6.9, "the CBOM consequence").
    ///
    /// Its presence in a CBOM is what lets promotion-gate predicate 3 (§6.2) **refuse**
    /// this path: a genome whose `policy.disallowed` contains this variant cannot be
    /// promoted while its CBOM declares an RSA-verifying timestamp path. That is a
    /// control a High-Assurance deployment can use to decline a classical signature in
    /// its audit chain, not a side effect of naming the algorithm.
    ///
    /// **Naming it is not endorsing it.** It is never used to *produce* a BROKKR
    /// signature — `DualKeyPair` signs ML-DSA + SLH-DSA and nothing else — and it is
    /// quantum-vulnerable.
    RsaPkcs1Sha256,
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
