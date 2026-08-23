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
///
/// **13-FIX F-4 — signing is `&mut self`, and the keypair is not `Sync`.** Concurrent signing on
/// one keypair through a shared `&` raced on the wolfCrypt key/RNG state and silently corrupted
/// signatures (red-team 13A F-4). Two structural fixes make that uncompilable rather than merely
/// discouraged: [`sign_dual`](Self::sign_dual) now takes `&mut self` (a shared `&DualKeyPair`
/// cannot sign at all), and the `PhantomData<Cell<()>>` marker removes the auto `Sync` impl (a
/// `&DualKeyPair` cannot even cross a thread boundary). A holder that must sign from a `&self`
/// method (SAGA, HEIMDALL) keeps the keypair behind a `Mutex`. Verification is unaffected — it uses
/// a separate verify-only [`DualPublicKey`], which stays `Sync`.
pub struct DualKeyPair {
    mldsa: ffi::MlDsa65,
    slhdsa: ffi::SlhDsaShake192s,
    /// Removes the auto `Sync` impl (keeps `Send`): a signing keypair must not be shared across
    /// threads. `Cell<()>` is `Send` but not `Sync`.
    _no_sync: core::marker::PhantomData<core::cell::Cell<()>>,
}

impl DualKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let mldsa = ffi::MlDsa65::generate().map_err(|_| CryptoError::Backend)?;
        let slhdsa = ffi::SlhDsaShake192s::generate().map_err(|_| CryptoError::Backend)?;
        Ok(DualKeyPair {
            mldsa,
            slhdsa,
            _no_sync: core::marker::PhantomData,
        })
    }

    /// Sign under both families, producing a `DualSignature` that carries both. **`&mut self`
    /// (13-FIX F-4):** signing mutates the underlying key/RNG state, so it requires exclusive
    /// access — this makes concurrent signing through a shared reference a compile error.
    ///
    /// Signing through a shared `&DualKeyPair` does not compile (E0596) — the regression test for
    /// 13A finding F-4 (concurrent signing on one keypair corrupted signatures):
    ///
    /// ```compile_fail,E0596
    /// let kp = brokkr_crypto::DualKeyPair::generate().unwrap();
    /// let shared: &brokkr_crypto::DualKeyPair = &kp;
    /// let _ = shared.sign_dual(b"msg"); // cannot borrow `*shared` as mutable, behind a `&`
    /// ```
    ///
    /// And a `&DualKeyPair` cannot cross a thread boundary — `DualKeyPair` is not `Sync` (E0277):
    ///
    /// ```compile_fail,E0277
    /// let kp = brokkr_crypto::DualKeyPair::generate().unwrap();
    /// let r = &kp;
    /// std::thread::scope(|s| {
    ///     s.spawn(move || {
    ///         let _ = r.public_key_bytes(); // &DualKeyPair is not Send (DualKeyPair is !Sync)
    ///     });
    /// });
    /// ```
    pub fn sign_dual(&mut self, msg: &[u8]) -> Result<DualSignature, CryptoError> {
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

    /// Export this keypair's raw public keys `(ml_dsa_65, slh_dsa_shake_192s)`, for a
    /// signer to publish so a verifier can later check its signatures with a
    /// [`DualPublicKey`] holding no private material.
    pub fn public_key_bytes(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mldsa = self
            .mldsa
            .export_public()
            .map_err(|_| CryptoError::Backend)?;
        let slhdsa = self
            .slhdsa
            .export_public()
            .map_err(|_| CryptoError::Backend)?;
        Ok((mldsa, slhdsa))
    }
}

/// A **verify-only** dual-family public key: ML-DSA-65 + SLH-DSA-SHAKE-192s, holding
/// **no** private material. This is what a verifier — SINDRI (Phase 4), or a
/// public-roots-of-trust chain verifier — uses to check a `DualSignature` it did not
/// produce, given public keys sourced from an OQGF-M-1 attestation. It closes the
/// public-roots-of-trust half of OQGF-M-8.
pub struct DualPublicKey {
    mldsa: ffi::MlDsa65Public,
    slhdsa: ffi::SlhDsaShake192sPublic,
}

impl DualPublicKey {
    /// Import raw ML-DSA-65 and SLH-DSA-SHAKE-192s public keys. Length-validated per
    /// family in the FFI layer; a wrong-length key fails closed with
    /// `CryptoError::MalformedKey`.
    pub fn from_public_bytes(mldsa_pub: &[u8], slhdsa_pub: &[u8]) -> Result<Self, CryptoError> {
        let mldsa = ffi::MlDsa65Public::from_public_bytes(mldsa_pub)
            .map_err(|_| CryptoError::MalformedKey)?;
        let slhdsa = ffi::SlhDsaShake192sPublic::from_public_bytes(slhdsa_pub)
            .map_err(|_| CryptoError::MalformedKey)?;
        Ok(DualPublicKey { mldsa, slhdsa })
    }

    /// Verify a `DualSignature` with public keys only. Returns `Ok(())` **only if BOTH
    /// families verify** — mirrors [`DualKeyPair::verify_dual`] exactly (algorithm-
    /// mismatch check first, then both families).
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
