//! SHA-384 implementation of the brokkr-core `Hasher` trait.

#![forbid(unsafe_code)]

use crate::ffi;
use brokkr_core::crypto::{Digest, HashAlg, Hasher};

/// SHA-384 hasher backed by wolfCrypt.
pub struct Sha384Hasher;

impl Hasher for Sha384Hasher {
    fn algorithm(&self) -> HashAlg {
        HashAlg::Sha384
    }

    fn hash(&self, msg: &[u8]) -> Digest {
        // wolfCrypt SHA-384 over an in-memory slice cannot fail (no allocation, no
        // I/O). The `Hasher` trait is infallible, so on the unreachable error path we
        // return an EMPTY-bytes digest — never a fabricated 48-byte value. An empty
        // digest is obviously not a valid SHA-384 output and fails any downstream
        // comparison (fail-closed), rather than silently substituting a wrong hash.
        match ffi::sha384(msg) {
            Ok(bytes) => Digest {
                alg: HashAlg::Sha384,
                bytes: bytes.to_vec(),
            },
            Err(_) => Digest {
                alg: HashAlg::Sha384,
                bytes: Vec::new(),
            },
        }
    }
}
