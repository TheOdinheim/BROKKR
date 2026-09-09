//! RFC 3161 `TSTInfo` reader and `TimeStampReq` writer (OQGF-A-3; ARCH Rev 1.25 §6.9).
//!
//! ## What this is, and the objection it partially reintroduces
//!
//! Rev 1.24 rejected hand-written DER for a security boundary. **That rejection is
//! narrowed here rather than withdrawn**, and the narrowing is the whole argument:
//!
//! - The **refused** route walked the **raw token** to *locate* the eContent, before
//!   anything was verified — a hand-written parser over bytes anyone answering an HTTP
//!   request could choose.
//! - This reader walks the **eContent**, *after* [`crate::ffi::cms_verify`] succeeded —
//!   bytes chosen by someone holding a key that chains to the configured trust anchor, and
//!   it *reads named fields* rather than *locating* a structure.
//!
//! **What did not change, and is not glossed:** a compromised or malicious authority can
//! sign arbitrary `TSTInfo`. The input is **authenticated, not trustworthy**, so this
//! reader must be correct against adversarial input — it is merely no longer exposed to
//! *unauthenticated* adversarial input. **A reduction in exposure, not an elimination.**
//!
//! ## The four constraints §6.9 places, and how each is met here
//!
//! 1. **Safe Rust only** — this module contains no `unsafe`. A defect is a wrong value or
//!    an `Err`, never memory corruption.
//! 2. **Total** — every malformed input returns `Err(DerError)`. §6 denies
//!    `indexing_slicing`, `panic`, `unwrap_used`, and `expect_used`, so the reader cannot
//!    slice-index or panic its way out of a bad structure: every read goes through
//!    [`Cursor`], which returns `Err` rather than indexing.
//! 3. **A fixed, small grammar** — named fields in a known order. **Not a general ASN.1
//!    decoder, and it must not become one.**
//! 4. **Bounded input** — the cursor never advances past the slice it was given, which is
//!    `contentSz` bytes from the shim.
//!
//! ## One unauthenticated walk remains, and it is inherent to the protocol
//!
//! Extracting the `timeStampToken` from a `TimeStampResp` happens **before** verification —
//! the token has to come out of the response envelope before wolfSSL can check it. That
//! walk is here too ([`extract_token`]), it is shallow (a `SEQUENCE`, a `PKIStatusInfo` to
//! skip, and the remainder), and it is bounded and total like the rest. It cannot be
//! designed away: no ordering of operations verifies a token before extracting it.

/// Why a DER read failed. One error for the whole module: the caller maps it to
/// `TimestampError::Malformed`, and "which byte was wrong" is not a distinction any
/// governance decision turns on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerError;

/// A bounded, total cursor. **Every read goes through this** — there is no slice-indexing
/// anywhere in the module, which is how constraint 2 is met rather than hoped for.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn byte(&mut self) -> Result<u8, DerError> {
        let b = *self.buf.get(self.pos).ok_or(DerError)?;
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DerError> {
        let end = self.pos.checked_add(n).ok_or(DerError)?;
        let s = self.buf.get(self.pos..end).ok_or(DerError)?;
        self.pos = end;
        Ok(s)
    }

    /// A DER length. Rejects indefinite form (BER, not DER) and any length that does not
    /// fit a `usize` or exceeds what remains.
    fn length(&mut self) -> Result<usize, DerError> {
        let first = self.byte()?;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let count = (first & 0x7f) as usize;
        if count == 0 || count > core::mem::size_of::<usize>() {
            // 0 => indefinite length (not DER); > size_of::<usize>() cannot be represented.
            return Err(DerError);
        }
        let mut len: usize = 0;
        for b in self.take(count)? {
            len = len.checked_mul(256).ok_or(DerError)?;
            len = len.checked_add(*b as usize).ok_or(DerError)?;
        }
        if len > self.remaining() {
            return Err(DerError);
        }
        Ok(len)
    }

    /// Read one TLV, returning `(tag, value)`.
    fn tlv(&mut self) -> Result<(u8, &'a [u8]), DerError> {
        let tag = self.byte()?;
        let len = self.length()?;
        Ok((tag, self.take(len)?))
    }

    /// Read one TLV and require the tag.
    fn tagged(&mut self, want: u8) -> Result<&'a [u8], DerError> {
        let (tag, v) = self.tlv()?;
        if tag != want { Err(DerError) } else { Ok(v) }
    }

    /// Skip one TLV.
    fn skip(&mut self) -> Result<(), DerError> {
        self.tlv()?;
        Ok(())
    }
}

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_BOOLEAN: u8 = 0x01;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;

/// SHA-384, `2.16.840.1.101.3.4.2.2` — the digest BROKKR requests, matching the hash it
/// uses everywhere else (`Sha384Hasher`) and CNSA 2.0.
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

/// The fields this reader extracts from a `TSTInfo`. Named fields in a known order —
/// nothing else is decoded, per constraint 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TstInfo {
    /// `messageImprint.hashAlgorithm` — the digest OID, raw.
    pub imprint_alg_oid: Vec<u8>,
    /// `messageImprint.hashedMessage` — the digest the authority attests over.
    pub imprint: Vec<u8>,
    /// `genTime`, as the authority wrote it (a `GeneralizedTime` string).
    pub gen_time: String,
}

impl TstInfo {
    /// Whether the imprint algorithm is the SHA-384 BROKKR requests.
    pub fn imprint_is_sha384(&self) -> bool {
        self.imprint_alg_oid == OID_SHA384
    }
}

/// Read a `TSTInfo` from **authenticated** eContent.
///
/// ```text
/// TSTInfo ::= SEQUENCE {
///   version        INTEGER { v1(1) },
///   policy         TSAPolicyId,
///   messageImprint MessageImprint,
///   serialNumber   INTEGER,
///   genTime        GeneralizedTime,
///   ... optional fields this reader does not decode
/// }
/// ```
pub fn parse_tstinfo(der: &[u8]) -> Result<TstInfo, DerError> {
    let mut outer = Cursor::new(der);
    let body = outer.tagged(TAG_SEQUENCE)?;
    let mut c = Cursor::new(body);

    c.tagged(TAG_INTEGER)?; // version
    c.tagged(TAG_OID)?; // policy

    // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
    //                               hashedMessage OCTET STRING }
    let imprint_seq = c.tagged(TAG_SEQUENCE)?;
    let mut mi = Cursor::new(imprint_seq);
    let alg_seq = mi.tagged(TAG_SEQUENCE)?;
    let mut alg = Cursor::new(alg_seq);
    let imprint_alg_oid = alg.tagged(TAG_OID)?.to_vec();
    let imprint = mi.tagged(TAG_OCTET_STRING)?.to_vec();

    c.skip()?; // serialNumber
    let gen_time = c.tagged(TAG_GENERALIZED_TIME)?;
    let gen_time = core::str::from_utf8(gen_time).map_err(|_| DerError)?.into();

    Ok(TstInfo {
        imprint_alg_oid,
        imprint,
        gen_time,
    })
}

/// Extract the `timeStampToken` (a CMS `ContentInfo`) from a `TimeStampResp`.
///
/// **This is the one walk over unauthenticated bytes, and it is inherent to the protocol:**
/// the token must come out of the response envelope before wolfSSL can verify it. It is
/// shallow, bounded, and total.
///
/// ```text
/// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
/// PKIStatusInfo ::= SEQUENCE { status INTEGER, ... }
/// ```
///
/// Returns `Err` when the response is malformed **or** when the authority reported a
/// non-granted status — a rejection is not a token.
pub fn extract_token(resp: &[u8]) -> Result<Vec<u8>, DerError> {
    let mut outer = Cursor::new(resp);
    let body = outer.tagged(TAG_SEQUENCE)?;
    let mut c = Cursor::new(body);

    // PKIStatusInfo: status 0 (granted) or 1 (grantedWithMods) carry a token.
    let status_info = c.tagged(TAG_SEQUENCE)?;
    let mut si = Cursor::new(status_info);
    let status = si.tagged(TAG_INTEGER)?;
    let granted = matches!(status, [0] | [1]);
    if !granted {
        return Err(DerError);
    }

    // The remainder is the ContentInfo, re-encoded whole (tag + length + value) because
    // that is what wc_PKCS7_VerifySignedData expects.
    let (tag, value) = c.tlv()?;
    if tag != TAG_SEQUENCE {
        return Err(DerError);
    }
    Ok(reencode(tag, value))
}

/// Re-encode a TLV. Used only to hand a located `ContentInfo` back to wolfSSL whole.
fn reencode(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(tag);
    write_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

fn write_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let mut bytes = Vec::new();
    let mut n = len;
    while n > 0 {
        bytes.push((n & 0xff) as u8);
        n >>= 8;
    }
    bytes.reverse();
    out.push(0x80 | (bytes.len() as u8));
    out.extend_from_slice(&bytes);
}

/// Build a `TimeStampReq` over `digest` (a SHA-384 hash of the record's signed content).
///
/// This is **encoding**, not parsing — it constructs bytes rather than interpreting
/// someone else's, which is why it carries none of the caution the reader above does.
///
/// ```text
/// TimeStampReq ::= SEQUENCE {
///   version        INTEGER { v1(1) },
///   messageImprint MessageImprint,
///   certReq        BOOLEAN DEFAULT FALSE }
/// ```
/// `certReq` is TRUE so the response carries the signer certificate.
pub fn build_request(digest: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }
    let mut alg = Vec::new();
    alg.push(TAG_OID);
    write_len(&mut alg, OID_SHA384.len());
    alg.extend_from_slice(OID_SHA384);
    alg.push(TAG_NULL);
    alg.push(0);
    let alg = reencode(TAG_SEQUENCE, &alg);

    let mut imprint = alg;
    imprint.push(TAG_OCTET_STRING);
    write_len(&mut imprint, digest.len());
    imprint.extend_from_slice(digest);
    let imprint = reencode(TAG_SEQUENCE, &imprint);

    let mut body = Vec::new();
    body.extend_from_slice(&[TAG_INTEGER, 0x01, 0x01]); // version v1
    body.extend_from_slice(&imprint);
    body.extend_from_slice(&[TAG_BOOLEAN, 0x01, 0xff]); // certReq TRUE

    reencode(TAG_SEQUENCE, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constraint 2 — total. No input panics; malformed input yields `Err`.
    #[test]
    fn test_a3_reader_is_total_on_malformed_input() {
        for bad in [
            &b""[..],
            &[0x30][..],                   // tag, no length
            &[0x30, 0x80][..],             // indefinite length (BER, not DER)
            &[0x30, 0x7f][..],             // length exceeding the buffer
            &[0x30, 0x03, 0x02, 0x01][..], // truncated inner TLV
            &[0xff; 64][..],
        ] {
            assert!(parse_tstinfo(bad).is_err(), "must reject {bad:?}");
            assert!(extract_token(bad).is_err(), "must reject {bad:?}");
        }
    }

    /// A request round-trips through the reader's own primitives: the imprint we encode is
    /// the imprint a reader finds.
    ///
    /// Walks via `?` rather than `unwrap` — §6 denies `unwrap_used` crate-wide, and the
    /// in-source test modules in this repository avoid it rather than suppress it.
    fn walk_request(req: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DerError> {
        let mut c = Cursor::new(req);
        let body = c.tagged(TAG_SEQUENCE)?;
        let mut b = Cursor::new(body);
        b.tagged(TAG_INTEGER)?; // version
        let mi = b.tagged(TAG_SEQUENCE)?;
        let mut m = Cursor::new(mi);
        let alg_seq = m.tagged(TAG_SEQUENCE)?;
        let mut a = Cursor::new(alg_seq);
        let oid = a.tagged(TAG_OID)?.to_vec();
        let imprint = m.tagged(TAG_OCTET_STRING)?.to_vec();
        Ok((oid, imprint))
    }

    #[test]
    fn test_a3_request_carries_the_digest_and_sha384_oid() {
        let digest = vec![7u8; 48];
        let req = build_request(&digest);
        assert_eq!(
            walk_request(&req),
            Ok((OID_SHA384.to_vec(), digest)),
            "the request must carry the SHA-384 OID and exactly the digest given"
        );
    }

    /// A non-granted status is not a token.
    #[test]
    fn test_a3_rejected_status_is_not_a_token() {
        // SEQUENCE { SEQUENCE { INTEGER 2 } }  — status 2 = rejection
        let resp = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
        assert!(extract_token(&resp).is_err());
    }
}
