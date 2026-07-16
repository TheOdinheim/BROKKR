//! ML-DSA and SLH-DSA implementations of the brokkr-core `Signer`/`Verifier`
//! traits, and dual-family signing (OQGF-R-1 at Enhanced).
//!
//! A [`brokkr_core::DualSignature`] carries one ML-DSA signature **and** one
//! SLH-DSA signature. [`DualKeyPair::verify_dual`] returns `Ok` only if **both**
//! families verify — a single-family signature is not sufficient, and the core
//! `DualSignature` type structurally requires both (it has two `Signature` fields).

#![forbid(unsafe_code)]

use crate::ffi;
use brokkr_core::crypto::{CryptoError, DualSignature, Signature, SignatureAlg, Signer, Verifier};

/// ML-DSA-65 keypair (lattice family). Signs and verifies with a NULL FIPS-204
/// context.
pub struct MlDsaSigner {
    key: ffi::MlDsa65,
}

impl MlDsaSigner {
    pub fn generate() -> Result<Self, CryptoError> {
        ffi::MlDsa65::generate()
            .map(|key| MlDsaSigner { key })
            .map_err(|_| CryptoError::Backend)
    }
}

impl Signer for MlDsaSigner {
    fn algorithm(&self) -> SignatureAlg {
        SignatureAlg::MlDsa65
    }
    fn sign(&self, msg: &[u8]) -> Result<Signature, CryptoError> {
        let bytes = self.key.sign(msg).map_err(|_| CryptoError::Backend)?;
        Ok(Signature {
            alg: SignatureAlg::MlDsa65,
            bytes,
        })
    }
}

impl Verifier for MlDsaSigner {
    fn algorithm(&self) -> SignatureAlg {
        SignatureAlg::MlDsa65
    }
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        if sig.alg != SignatureAlg::MlDsa65 {
            return Err(CryptoError::AlgorithmMismatch);
        }
        if self.key.verify(msg, &sig.bytes) {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

/// SLH-DSA-SHAKE-192s keypair (hash-based family).
pub struct SlhDsaSigner {
    key: ffi::SlhDsaShake192s,
}

impl SlhDsaSigner {
    pub fn generate() -> Result<Self, CryptoError> {
        ffi::SlhDsaShake192s::generate()
            .map(|key| SlhDsaSigner { key })
            .map_err(|_| CryptoError::Backend)
    }
}

impl Signer for SlhDsaSigner {
    fn algorithm(&self) -> SignatureAlg {
        SignatureAlg::SlhDsaShake192s
    }
    fn sign(&self, msg: &[u8]) -> Result<Signature, CryptoError> {
        let bytes = self.key.sign(msg).map_err(|_| CryptoError::Backend)?;
        Ok(Signature {
            alg: SignatureAlg::SlhDsaShake192s,
            bytes,
        })
    }
}

impl Verifier for SlhDsaSigner {
    fn algorithm(&self) -> SignatureAlg {
        SignatureAlg::SlhDsaShake192s
    }
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        if sig.alg != SignatureAlg::SlhDsaShake192s {
            return Err(CryptoError::AlgorithmMismatch);
        }
        if self.key.verify(msg, &sig.bytes) {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

/// A dual-family keypair: ML-DSA-65 (lattice) **and** SLH-DSA-SHAKE-192s
/// (hash-based). This is OQGF-R-1's dual PQC families for any signature relied on
/// as legal evidence (SAGA's audit signatures at Enhanced).
pub struct DualKeyPair {
    mldsa: ffi::MlDsa65,
    slhdsa: ffi::SlhDsaShake192s,
}

impl DualKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let mldsa = ffi::MlDsa65::generate().map_err(|_| CryptoError::Backend)?;
        let slhdsa = ffi::SlhDsaShake192s::generate().map_err(|_| CryptoError::Backend)?;
        Ok(DualKeyPair { mldsa, slhdsa })
    }

    /// Sign under both families, producing a `DualSignature` that carries both.
    pub fn sign_dual(&self, msg: &[u8]) -> Result<DualSignature, CryptoError> {
        let lattice = Signature {
            alg: SignatureAlg::MlDsa65,
            bytes: self.mldsa.sign(msg).map_err(|_| CryptoError::Backend)?,
        };
        let hash_based = Signature {
            alg: SignatureAlg::SlhDsaShake192s,
            bytes: self.slhdsa.sign(msg).map_err(|_| CryptoError::Backend)?,
        };
        Ok(DualSignature {
            lattice,
            hash_based,
        })
    }

    /// Verify a `DualSignature`. Returns `Ok(())` **only if BOTH families verify**.
    /// If either family's signature is wrong, corrupted, or from the wrong
    /// algorithm, this fails — proving dual-family is real, not two independent
    /// checks either of which could pass alone.
    pub fn verify_dual(&self, msg: &[u8], dual: &DualSignature) -> Result<(), CryptoError> {
        if dual.lattice.alg != SignatureAlg::MlDsa65
            || dual.hash_based.alg != SignatureAlg::SlhDsaShake192s
        {
            return Err(CryptoError::AlgorithmMismatch);
        }
        let lattice_ok = self.mldsa.verify(msg, &dual.lattice.bytes);
        let hash_ok = self.slhdsa.verify(msg, &dual.hash_based.bytes);
        if lattice_ok && hash_ok {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}
