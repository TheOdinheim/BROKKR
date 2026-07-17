//! # brokkr-crypto
//!
//! The wolfCrypt FFI backend. Implements the `brokkr-core` crypto traits
//! (`Signer`, `Verifier`, `Hasher`) against the verified wolfSSL v5.9.2 shared
//! library, plus dual-family signing (OQGF-R-1) and the crypto-shredding primitive
//! (OQGF-P-11.5 / OQGF-G-7).
//!
//! ## Unsafe confinement
//!
//! `unsafe` lives in exactly one file: [`ffi`]. Every other module begins with
//! `#![forbid(unsafe_code)]`. The crate root does **not** forbid `unsafe` crate-wide,
//! because that would also forbid `ffi.rs` (a crate-level `forbid` cannot be relaxed
//! by a submodule). The discipline is therefore per-module; `lib.rs` itself contains
//! no `unsafe`.
//!
//! ## Cryptographic posture — the FFI honesty rule (CLAUDE.md §7)
//!
//! This build is **non-FIPS** (zero FIPS symbols, verified via `nm -D`). No FIPS
//! validation is claimed anywhere. See [`CRYPTO_POSTURE`].

// Production discipline (CLAUDE.md §6). Not crate-wide `forbid(unsafe_code)` — see above.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]

pub mod ffi; // the sole `unsafe` module
pub mod hash;
pub mod shred;
pub mod sign;

pub use hash::Sha384Hasher;
pub use shred::{SubjectKey, WrappedKey};
pub use sign::{DualKeyPair, DualPublicKey, MlDsaSigner, SlhDsaSigner};

/// The only correct statement of cryptographic posture for this build (CLAUDE.md §7,
/// BROKKR-ARCH §9). Never write, log, or document anything stronger.
pub const CRYPTO_POSTURE: &str =
    "CNSA-2.0-aligned; FIPS module validation pending; current build non-FIPS";

/// CBOM facts for the wolfCrypt backend (OQGF-G-1). The FFI honesty rule applies:
/// the version and non-FIPS status are recorded exactly; no algorithm identity is
/// asserted beyond the symbols actually bound. The signed CycloneDX assembly is a
/// Phase-5 (REGIN) concern; this is the raw, truthful source material.
pub const WOLFCRYPT_CBOM: &str = concat!(
    "wolfssl 5.9.2-stable; build=cmake, non-FIPS (zero FIPS symbols); ",
    "algorithms bound: ",
    "ML-DSA-65 (FIPS 204, wc_MlDsaKey_*, sig 3309B), ",
    "SLH-DSA-SHAKE-192s (FIPS 205, wc_SlhDsaKey_*), ",
    "ML-KEM-768 (FIPS 203, wc_MlKemKey_*), ",
    "SHA-384 (FIPS 180-4, wc_Sha384_*), ",
    "AES-256-GCM (FIPS 197/SP 800-38D, wc_AesGcm*); ",
    "FIPS validation: none (this build is non-FIPS)"
);
