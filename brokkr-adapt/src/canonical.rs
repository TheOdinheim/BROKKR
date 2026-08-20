//! Canonical serialization for KVASIR (Task 6).
//!
//! Follows the discipline of the five sibling `canonical.rs` files exactly (`brokkr-intent`,
//! `brokkr-genome`, `brokkr-barrier`, `brokkr-audit`, `brokkr-sentinel`): deterministic fixed
//! field order; every variable-length field length-prefixed with a fixed 8-byte big-endian
//! count; a domain tag per artifact; **no catch-all** in any match (a new enum variant breaks
//! the build rather than colliding).
//!
//! Two domain tags, both `brokkr-adapt:*` — distinct from every `brokkr-intent:*`,
//! `brokkr-genome:*`, `brokkr-barrier:*`, `brokkr-audit:*`, and `brokkr-sentinel:*` tag
//! (five-crate domain separation, tested in `tests/kvasir.rs`):
//!
//! - `brokkr-adapt:provenance:v1` — a [`DetectorProvenance`]'s signed content (OQGF-P-6.4). This
//!   is signed by whoever authored and screened the refinement and verified by KVASIR at
//!   activation, so its bytes are defined **once, here**, and both parties compute them the same.
//! - `brokkr-adapt:eval-corpus:v1` — the evaluation-corpus integrity digest (OQGF-P-6.2). Not a
//!   signature: KVASIR recomputes it over the seam's `samples()` and binds it to the DAP-declared
//!   digest, catching a substituted corpus before any measurement.

use brokkr_core::adapt::{AttackClass, DetectorProvenance};
use brokkr_core::ids::Dap;
use brokkr_sentinel::Observation;

/// Signed content of a [`DetectorProvenance`] (OQGF-P-6.4). Distinct from every sibling tag.
pub const DOMAIN_PROVENANCE: &[u8] = b"brokkr-adapt:provenance:v1";
/// The evaluation-corpus integrity digest (OQGF-P-6.2). Distinct from every sibling tag.
pub const DOMAIN_EVAL_CORPUS: &[u8] = b"brokkr-adapt:eval-corpus:v1";

/// A canonical byte accumulator. All variable-length data is length-prefixed.
struct Canon {
    buf: Vec<u8>,
}

impl Canon {
    fn new() -> Self {
        Canon { buf: Vec::new() }
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u64(b.len() as u64);
        self.buf.extend_from_slice(b);
    }
    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

fn write_dap(c: &mut Canon, dap: &Dap) {
    c.bytes(dap.name.as_bytes());
    c.bytes(dap.id.as_bytes());
}

/// The bytes a [`DetectorProvenance::signature`] covers — every field **except** the signature
/// (OQGF-P-6.4). The `screen_result` contributes both the Self Set version it screened against
/// and its `produced_at`, so a re-pointed or re-timed screen result changes the signed bytes.
pub fn provenance_signed_content(p: &DetectorProvenance) -> Vec<u8> {
    let mut c = Canon::new();
    c.bytes(DOMAIN_PROVENANCE);
    c.bytes(p.seeding.as_str().as_bytes());
    c.bytes(p.corpus_version.as_str().as_bytes());
    c.bytes(p.screen_result.version.as_str().as_bytes());
    c.u64(p.screen_result.produced_at.0);
    write_dap(&mut c, &p.approver);
    c.finish()
}

/// The bytes the evaluation-corpus integrity digest is computed over (OQGF-P-6.2).
///
/// The observation bytes reuse `brokkr-sentinel`'s committed `Observation` encoding
/// ([`brokkr_sentinel::canonical::corpus_signed_content`]) rather than re-deriving it here — one
/// definition of what an `Observation` hashes to, no divergence. The labels are then appended, so
/// a substituted corpus that only relabels attack samples as benign (to make a candidate look
/// clean) still changes the digest.
pub fn eval_corpus_digest_content(samples: &[(Observation, Option<AttackClass>)]) -> Vec<u8> {
    let mut c = Canon::new();
    c.bytes(DOMAIN_EVAL_CORPUS);
    let observations: Vec<Observation> = samples.iter().map(|(o, _)| o.clone()).collect();
    c.bytes(&brokkr_sentinel::canonical::corpus_signed_content(
        &observations,
    ));
    c.u64(samples.len() as u64);
    for (_, label) in samples {
        match label {
            None => c.u8(0),
            Some(ac) => {
                c.u8(1);
                c.bytes(ac.detail.as_bytes());
            }
        }
    }
    c.finish()
}
