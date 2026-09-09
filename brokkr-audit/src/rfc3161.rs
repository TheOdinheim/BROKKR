//! The RFC 3161 timestamp client (OQGF-A-3; ARCH Rev 1.24/1.25 §6.9).
//!
//! ## What this establishes, and the two things it does not
//!
//! Verification establishes that the token is well-formed CMS, that its signature chains to
//! a **pre-configured** trust anchor (never one taken from the token itself), and that its
//! `messageImprint` binds the bytes BROKKR actually sent.
//!
//! **It does not establish that the asserted time is correct.** A misconfigured or
//! compromised authority produces a perfectly verifiable token bearing a wrong time, and no
//! cryptography in the token detects that. **It does not make the authority trustworthy**
//! either — trust in the timestamp is trust in the authority's operator, its clock
//! discipline, and its key custody. BROKKR verifies the *form* and the *binding*; the
//! *truth* is somebody else's governance.
//!
//! ## Independence
//!
//! A **self-hosted** responder is BROKKR's operator attesting BROKKR's own time. It
//! satisfies the mechanism and fails the Organ 5 principle that *the governed system shall
//! not be the authority over its own evidence*. A record bearing such a token, presented as
//! third-party attestation, is **worse than one marked `Unavailable`** — the first misleads
//! a reader, the second tells the truth. [`TimestampToken::authority`] records which was
//! used so a reader need not inspect a config file.
//!
//! ## Failure
//!
//! A token that fails **any** check is never stored as `Timestamping::Token`. It becomes
//! `Unavailable` with the failure named, and **the token bytes are discarded** — an
//! investigator learns that verification failed and cannot examine what arrived. Retaining
//! them would need a third `Timestamping` variant; ARCH Rev 1.24 §6.9 records that as a DAP
//! call rather than something this client decides.

use crate::event::{
    SignerTrust, TimestampAuthority, TimestampError, TimestampSigAlg, TimestampToken,
};
use brokkr_core::crypto::Hasher;
use brokkr_crypto::ffi::{CmsError, PathError};
use brokkr_crypto::{Sha384Hasher, build_request, extract_token, parse_tstinfo};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// wolfSSL v5.9.2 OID constants, from `wolfssl/wolfcrypt/asn.h` and confirmed against a C
/// probe compiled with the library's own flags: these are large hash-derived values, not
/// the small "OID sum" constants older wolfSSL used. Checked rather than assumed, because
/// the first reading of them looked like garbage and was not.
const RSAK: u32 = 2_025_223_203;
const ECDSAK: u32 = 826_901_527;
const SHA256H: u32 = 2_092_137_211;
const SHA384H: u32 = 2_092_137_208;
const SHA512H: u32 = 2_092_137_209;

/// Derive the signature algorithm from the signer's key type and the digest algorithm.
///
/// **This is a derivation, not an observation**, and the caller records both raw OIDs
/// beside the result so a reader can check it. `SignerInfo.signatureAlgorithm` — the field
/// that names the algorithm outright — is consumed by wolfSSL during parsing and retained
/// nowhere (ARCH Rev 1.25 §6.9, an unplaced rule in the §5.4 table).
///
/// **No curve is derived for ECDSA:** `publicKeyOID` carries the key *family*, so naming
/// P-256 or P-384 would assert what the observation does not support.
fn derive_alg(key_oid: u32, hash_oid: u32) -> TimestampSigAlg {
    match (key_oid, hash_oid) {
        (RSAK, SHA256H) => TimestampSigAlg::RsaSha256,
        (RSAK, SHA384H) => TimestampSigAlg::RsaSha384,
        (RSAK, SHA512H) => TimestampSigAlg::RsaSha512,
        (ECDSAK, SHA256H) => TimestampSigAlg::EcdsaSha256,
        (ECDSAK, SHA384H) => TimestampSigAlg::EcdsaSha384,
        (ECDSAK, SHA512H) => TimestampSigAlg::EcdsaSha512,
        _ => TimestampSigAlg::Unrecognized { key_oid, hash_oid },
    }
}

/// An RFC 3161 client speaking to one authority over plain HTTP.
///
/// HTTP rather than HTTPS: an RFC 3161 token is self-authenticating — its signature is
/// what BROKKR checks — so transport confidentiality adds nothing a reader relies on. The
/// request carries only a SHA-384 digest, which reveals nothing about the record.
pub struct Rfc3161Client {
    /// `host:port` of the authority.
    endpoint: String,
    /// The authority's name as recorded on the token — the field that lets a reader tell a
    /// third-party attestation from a self-hosted one.
    authority: String,
    /// How the signer is trusted — **supplied at construction**, never taken from a token.
    trust: SignerTrust,
    timeout: Duration,
}

/// Map a path-validation failure onto the record-level error. Every variant is preserved
/// rather than collapsed: an operator investigating "the issuer is unknown" looks at an
/// anchor set, one investigating "the signature is wrong" looks for tampering, and one
/// investigating "not yet valid" looks at a clock.
fn path_to_timestamp_error(e: PathError) -> TimestampError {
    match e {
        PathError::UntrustedSigner => TimestampError::UntrustedSigner,
        PathError::SignatureInvalid => TimestampError::SignatureInvalid,
        PathError::Expired => TimestampError::CertificateExpired,
        PathError::NotYetValid => TimestampError::CertificateNotYetValid,
        PathError::NotTimestamping => TimestampError::NotTimestampingCertificate,
        PathError::Malformed => TimestampError::Malformed,
    }
}

impl Rfc3161Client {
    /// Construct a client. `trust` selects the signer-trust mode; **`SignerTrust::
    /// AnchorEquality` is what a deployment gets unless it asks for path validation**,
    /// because path validation is the more permissive of the two.
    pub fn new(
        endpoint: impl Into<String>,
        authority: impl Into<String>,
        trust: SignerTrust,
        timeout: Duration,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            authority: authority.into(),
            trust,
            timeout,
        }
    }

    /// Verify the token's CMS signature and make the trust decision over the certificate
    /// that **actually** verified it.
    fn verify(&self, token: &[u8]) -> Result<brokkr_crypto::ffi::VerifiedCms, TimestampError> {
        let map_cms = |e: CmsError| match e {
            CmsError::Malformed => TimestampError::Malformed,
            CmsError::SignatureInvalid => TimestampError::SignatureInvalid,
        };
        match &self.trust {
            // Equality: unchanged from Rev 1.25 — `cms_verify` pins internally.
            SignerTrust::AnchorEquality { anchor_der } => {
                brokkr_crypto::ffi::cms_verify(token, anchor_der).map_err(map_cms)
            }
            // Path validation: verify the signature, then subject the certificate wolfSSL
            // actually used to RFC 5280 path building against the configured root, plus the
            // RFC 3161 timestamping-EKU requirement the Certificate Manager does not check.
            SignerTrust::PathValidation {
                root_der,
                intermediates_der,
            } => {
                let v =
                    brokkr_crypto::ffi::cms_verify_unpinned(token, root_der).map_err(map_cms)?;
                brokkr_crypto::ffi::verify_cert_path(&v.used_cert, root_der, intermediates_der)
                    .map_err(path_to_timestamp_error)?;
                Ok(v)
            }
        }
    }

    /// POST a `TimeStampReq` and return the response body. Hand-rolled, following the
    /// `brokkr-reasoner/src/ollama.rs` precedent (a single request, a single response, no
    /// HTTP crate).
    fn post(&self, body: &[u8]) -> Result<Vec<u8>, TimestampError> {
        let addr: std::net::SocketAddr = self
            .endpoint
            .parse()
            .map_err(|_| TimestampError::Unreachable)?;
        let mut sock = TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|_| TimestampError::Unreachable)?;
        sock.set_read_timeout(Some(self.timeout))
            .map_err(|_| TimestampError::Unreachable)?;

        let head = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/timestamp-query\r\n\
Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.endpoint,
            body.len()
        );
        sock.write_all(head.as_bytes())
            .map_err(|_| TimestampError::Unreachable)?;
        sock.write_all(body)
            .map_err(|_| TimestampError::Unreachable)?;

        // Bounded read (the F-19 discipline): a timestamp response is small, and an
        // unbounded read from a remote party is a denial-of-service surface.
        const MAX: usize = 1 << 20;
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let slice = buf.get(..n).ok_or(TimestampError::Unreachable)?;
                    raw.extend_from_slice(slice);
                    if raw.len() > MAX {
                        return Err(TimestampError::Malformed);
                    }
                }
                Err(_) => return Err(TimestampError::Unreachable),
            }
        }

        // Split headers from body at the blank line.
        let sep = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or(TimestampError::Malformed)?;
        let start = sep.checked_add(4).ok_or(TimestampError::Malformed)?;
        let body = raw.get(start..).ok_or(TimestampError::Malformed)?;
        Ok(body.to_vec())
    }
}

impl TimestampAuthority for Rfc3161Client {
    fn stamp(&self, canonical: &[u8]) -> Result<TimestampToken, TimestampError> {
        // The imprint is SHA-384 of the record's signed content — the same bytes the dual
        // signature covers, so the timestamp attests exactly what the signature attests.
        let digest = Sha384Hasher.hash(canonical);
        let request = build_request(&digest.bytes);
        let response = self.post(&request)?;

        // The one walk over unauthenticated bytes, inherent to the protocol: the token must
        // come out of the response envelope before wolfSSL can verify it.
        let token = extract_token(&response).map_err(|_| TimestampError::Malformed)?;

        // Verify the CMS signature and make the configured trust decision. Every failure
        // mode is kept apart here because they are different investigations.
        let verified = self.verify(&token)?;

        // Read the TSTInfo from the now-authenticated eContent.
        let tst = parse_tstinfo(&verified.content).map_err(|_| TimestampError::Malformed)?;

        // **The imprint must bind what we sent.** A token attesting other bytes is a
        // substituted response or an authority stamping something else — an attack
        // signature, and never `Malformed`. The digest algorithm must also be the one we
        // requested: a token over a different algorithm attests a different imprint.
        if !tst.imprint_is_sha384() || tst.imprint != digest.bytes {
            return Err(TimestampError::ImprintMismatch);
        }

        Ok(TimestampToken {
            token,
            authority: self.authority.clone(),
            algorithm: derive_alg(verified.key_oid, verified.hash_oid),
            key_oid: verified.key_oid,
            hash_oid: verified.hash_oid,
            gen_time: tst.gen_time,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a3_is_post_quantum_is_false_for_every_variant() {
        for a in [
            TimestampSigAlg::RsaSha256,
            TimestampSigAlg::RsaSha384,
            TimestampSigAlg::RsaSha512,
            TimestampSigAlg::EcdsaSha256,
            TimestampSigAlg::EcdsaSha384,
            TimestampSigAlg::EcdsaSha512,
            TimestampSigAlg::Unrecognized {
                key_oid: 1,
                hash_oid: 2,
            },
        ] {
            assert!(
                !a.is_post_quantum(),
                "no RFC 3161 authority signs post-quantum; {a:?} must not claim otherwise"
            );
        }
    }

    #[test]
    fn test_a3_derivation_maps_the_probed_constants() {
        assert_eq!(derive_alg(RSAK, SHA256H), TimestampSigAlg::RsaSha256);
        assert_eq!(derive_alg(ECDSAK, SHA384H), TimestampSigAlg::EcdsaSha384);
    }

    /// An unknown pair is carried verbatim and never guessed (§7's FFI honesty rule).
    #[test]
    fn test_a3_unknown_oid_pair_is_unrecognized_not_guessed() {
        assert_eq!(
            derive_alg(1, 2),
            TimestampSigAlg::Unrecognized {
                key_oid: 1,
                hash_oid: 2
            }
        );
    }
}
