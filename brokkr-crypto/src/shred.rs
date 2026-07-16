//! The crypto-shredding primitive (OQGF-P-11.5 / OQGF-G-7).
//!
//! **This builds the crypto, not the policy.** The lifecycle — retention sweeps,
//! the erasure tombstone, subject-rights plumbing — is Phase 7. Here is the
//! primitive: a per-subject AES-256 data key **wrapped under ML-KEM** (never a
//! classical KEM — the Mosca inequality is already violated for a classical wrap,
//! BROKKR-ARCH §6.11), and a durable key-destruction operation.
//!
//! ## Construction
//!
//! A subject owns an ML-KEM-768 keypair. To protect data:
//! 1. A fresh random AES-256 data key `DK` is generated.
//! 2. Encapsulation to the subject's ML-KEM public key yields `(ct, ss)`; `ss`
//!    (the 32-byte ML-KEM shared secret) is the key-encryption key `KEK`.
//! 3. `DK` is wrapped as `AES-256-GCM(KEK, DK)`.
//!
//! Erasure = **destroying the ML-KEM private key**. After that, `ct` can no longer
//! be decapsulated, so `KEK` is unrecoverable, so `DK` (and any data under it) is
//! cryptographically irrecoverable — while nothing was deleted from any store.
//! Because the KEM is ML-KEM, this survives a future CRQC (OQGF-G-7).

#![forbid(unsafe_code)]

use crate::ffi;
use brokkr_core::crypto::CryptoError;

const SHRED_AAD: &[u8] = b"brokkr-crypto-shred-v1";

/// The wrapped-key blob. Holds the ML-KEM ciphertext and the AES-GCM-wrapped data
/// key. Storable; useless once the subject key is shredded.
pub struct WrappedKey {
    /// ML-KEM ciphertext binding the KEK to the subject's private key.
    pub kem_ciphertext: Vec<u8>,
    /// AES-256-GCM-wrapped data key.
    pub wrapped_dk: Vec<u8>,
    pub iv: [u8; 12],
    pub tag: [u8; 16],
}

/// A per-subject key. Destroying it crypto-shreds everything wrapped to it.
pub struct SubjectKey {
    kem: ffi::MlKem768,
}

fn kek_from_ss(ss: &[u8]) -> Result<[u8; 32], CryptoError> {
    // ML-KEM-768 shared secret is 32 bytes = an AES-256 key. copy_from_slice (not
    // indexing) after an explicit length check.
    if ss.len() != 32 {
        return Err(CryptoError::MalformedKey);
    }
    let mut kek = [0u8; 32];
    kek.copy_from_slice(ss);
    Ok(kek)
}

impl SubjectKey {
    pub fn generate() -> Result<Self, CryptoError> {
        ffi::MlKem768::generate()
            .map(|kem| SubjectKey { kem })
            .map_err(|_| CryptoError::Backend)
    }

    /// Generate and wrap a fresh AES-256 data key under this subject's ML-KEM key.
    /// Returns the storable [`WrappedKey`] and the plaintext data key for immediate
    /// use (encrypt data under it now; it need never be stored in the clear).
    pub fn wrap_new_data_key(&self) -> Result<(WrappedKey, [u8; 32]), CryptoError> {
        let rng = ffi::Rng::new().map_err(|_| CryptoError::Backend)?;

        let mut dk = [0u8; 32];
        rng.fill(&mut dk).map_err(|_| CryptoError::Backend)?;

        let (kem_ciphertext, ss) = self.kem.encapsulate().map_err(|_| CryptoError::Backend)?;
        let kek = kek_from_ss(&ss)?;

        let mut iv = [0u8; 12];
        rng.fill(&mut iv).map_err(|_| CryptoError::Backend)?;

        let (wrapped_dk, tag) =
            ffi::aes256_gcm_encrypt(&kek, &iv, &dk, SHRED_AAD).map_err(|_| CryptoError::Backend)?;

        Ok((
            WrappedKey {
                kem_ciphertext,
                wrapped_dk,
                iv,
                tag,
            },
            dk,
        ))
    }

    /// Unwrap the data key. Requires the ML-KEM private key, so this **fails after
    /// [`shred`](Self::shred)**, and fails for any *other* subject key (the wrong
    /// key yields a wrong KEK, so the AES-GCM auth tag rejects it).
    pub fn unwrap_data_key(&self, w: &WrappedKey) -> Result<[u8; 32], CryptoError> {
        let ss = self
            .kem
            .decapsulate(&w.kem_ciphertext)
            .map_err(|_| CryptoError::MalformedKey)?;
        let kek = kek_from_ss(&ss)?;
        let dk = ffi::aes256_gcm_decrypt(&kek, &w.iv, &w.wrapped_dk, &w.tag, SHRED_AAD)
            .map_err(|_| CryptoError::VerificationFailed)?;
        kek_from_ss(&dk) // reuse the 32-byte checked conversion
    }

    /// Crypto-shred: durably destroy the ML-KEM private key. Irreversible. After
    /// this, [`unwrap_data_key`](Self::unwrap_data_key) can never succeed, so every
    /// data key wrapped to this subject is irrecoverable.
    pub fn shred(&mut self) {
        self.kem.destroy();
    }
}
