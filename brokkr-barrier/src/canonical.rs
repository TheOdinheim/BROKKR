//! Canonical serialization of the two signed artifacts the Barrier verifies: the
//! [`BoundaryCustodyRecord`] and the [`RiskAcceptance`].
//!
//! Follows `brokkr-genome/src/canonical.rs`'s discipline exactly: deterministic fixed
//! field order; every variable-length field length-prefixed with a fixed 8-byte big-endian
//! count; a domain tag per artifact; exhaustive enum tags (matched with **no catch-all**,
//! so a new variant breaks the build). Signed content **excludes** the artifact's own
//! `signature`.
//!
//! **Domain separation is load-bearing, across crates and within this one.** The BCR tag
//! and the acceptance tag differ from each other and from every `brokkr-genome:*` register
//! tag, so no signature over one artifact verifies as another (tested in `tests/barrier.rs`).

use brokkr_core::barrier::{BoundaryCustodyRecord, DestinationClass, PersonalDataTag};
use brokkr_core::classification::Classification;
use brokkr_core::ids::Dap;
use brokkr_core::personal_data::{Purpose, RetentionPeriod};
use brokkr_core::risk::{DeterministicGateId, RiskAcceptance};

const DOMAIN_BCR: &[u8] = b"brokkr-barrier:bcr:v1";
const DOMAIN_ACCEPTANCE: &[u8] = b"brokkr-barrier:risk-acceptance:v1";

/// A canonical byte accumulator. All variable-length data is length-prefixed.
struct Canon {
    buf: Vec<u8>,
}

impl Canon {
    fn new() -> Self {
        Canon { buf: Vec::new() }
    }

    /// A fixed 8-byte big-endian integer.
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// A single tag byte.
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// A length-prefixed byte string: 8-byte BE length, then the bytes.
    fn bytes(&mut self, b: &[u8]) {
        self.u64(b.len() as u64);
        self.buf.extend_from_slice(b);
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

// ---- exhaustive enum tags (a new variant must break the build, not collide) ----------

fn classification_tag(c: Classification) -> u8 {
    match c {
        Classification::Public => 1,
        Classification::Internal => 2,
        Classification::Cui => 3,
        Classification::Secret => 4,
    }
}

fn gate_tag(g: DeterministicGateId) -> u8 {
    match g {
        DeterministicGateId::Genome => 1,
        DeterministicGateId::Mhc => 2,
        DeterministicGateId::Barrier => 3,
    }
}

// ---- leaf writers --------------------------------------------------------------------

fn write_dap(c: &mut Canon, dap: &Dap) {
    c.bytes(dap.name.as_bytes());
    c.bytes(dap.id.as_bytes());
}

fn write_purpose(c: &mut Canon, p: &Purpose) {
    c.bytes(p.description.as_bytes());
}

fn write_retention(c: &mut Canon, r: &RetentionPeriod) {
    // A Duration is (seconds, subsec-nanos); both fixed-width and canonical.
    c.u64(r.duration.as_secs());
    c.u64(r.duration.subsec_nanos() as u64);
}

fn write_personal(c: &mut Canon, personal: &Option<PersonalDataTag>) {
    match personal {
        None => c.u8(0),
        Some(tag) => {
            c.u8(1);
            write_purpose(c, &tag.purpose);
            write_retention(c, &tag.retention);
            // OQGF-P-11.2 (Rev 1.29). Length-prefixed then each name, so a field list is
            // unambiguous and cannot be confused with a differently-split one.
            c.u64(tag.fields.len() as u64);
            for f in &tag.fields {
                c.bytes(f.as_str().as_bytes());
            }
        }
    }
}

fn write_destination_class(c: &mut Canon, d: &DestinationClass) {
    match d {
        DestinationClass::LocalPath(path) => {
            c.u8(1);
            c.bytes(path.as_str().as_bytes());
        }
        DestinationClass::Network { host } => {
            c.u8(2);
            c.bytes(host.as_str().as_bytes());
        }
        DestinationClass::Reasoner { endpoint } => {
            c.u8(3);
            c.bytes(endpoint.as_str().as_bytes());
        }
    }
}

// ---- public: the two signed-content encodings ----------------------------------------

/// The bytes a [`BoundaryCustodyRecord::signature`] covers — every field except the
/// signature.
pub fn bcr_signed_content(bcr: &BoundaryCustodyRecord) -> Vec<u8> {
    let mut c = Canon::new();
    c.bytes(DOMAIN_BCR);
    c.bytes(bcr.datum.as_str().as_bytes());
    c.u8(classification_tag(bcr.classification));
    c.bytes(bcr.origin.as_str().as_bytes());
    c.u64(bcr.authorized.len() as u64);
    for dest in &bcr.authorized {
        write_destination_class(&mut c, dest);
    }
    write_personal(&mut c, &bcr.personal);
    c.u64(bcr.issued.0);
    c.u64(bcr.expiry.0);
    c.finish()
}

/// The bytes a [`RiskAcceptance::signature`] covers — every field except the signature.
pub fn acceptance_signed_content(a: &RiskAcceptance) -> Vec<u8> {
    let mut c = Canon::new();
    c.bytes(DOMAIN_ACCEPTANCE);
    c.bytes(a.finding.as_str().as_bytes());
    match a.gate {
        None => c.u8(0),
        Some(g) => {
            c.u8(1);
            c.u8(gate_tag(g));
        }
    }
    write_dap(&mut c, &a.dap);
    c.bytes(a.justification.as_bytes());
    c.u64(a.expiry.0);
    c.finish()
}
