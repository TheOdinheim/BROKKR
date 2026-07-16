//! Canonical serialization — the load-bearing deliverable.
//!
//! A deterministic, unambiguous byte encoding of the *signed content* of a
//! [`RootIntent`] and an [`IntentChainEntry`]. The signature commits to these bytes,
//! so if the encoding omitted or under-specified `emitted_scope`, an attacker could
//! swap the scope and the signature would still verify (OQGF-M-9). The encoding
//! therefore covers the scope in full.
//!
//! ## Determinism and unambiguity
//!
//! - **Deterministic:** fixed field order; `IntentScope`/`InvariantSet` iterate their
//!   `BTreeSet`s in sorted order, so the same value always yields identical bytes.
//! - **Unambiguous:** every variable-length field is length-prefixed with a fixed
//!   8-byte big-endian count, so no two distinct structures can collide (there are no
//!   delimiters to spoof). Each top-level structure carries a domain-separation tag.
//!
//! No serialization crate is used: serde/bincode/postcard output is not guaranteed
//! canonical across versions or config, and canonicality is the whole point here.

use brokkr_core::crypto::{Attestation, Digest, DualSignature, HashAlg, Signature, SignatureAlg};
use brokkr_core::intent::{Caveat, IntentChainEntry, IntentScope, InvariantSet, RootIntent};

const DOMAIN_ROOT: &[u8] = b"brokkr-intent:root:v1";
const DOMAIN_ENTRY: &[u8] = b"brokkr-intent:entry:v1";

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

fn hashalg_tag(h: HashAlg) -> u8 {
    // Exhaustive on purpose: a new HashAlg variant must extend this, not silently
    // encode to a colliding tag.
    match h {
        HashAlg::Sha256 => 1,
        HashAlg::Sha384 => 2,
        HashAlg::Sha512 => 3,
        HashAlg::Shake128 => 4,
        HashAlg::Shake256 => 5,
    }
}

fn sigalg_tag(s: SignatureAlg) -> u8 {
    match s {
        SignatureAlg::MlDsa44 => 1,
        SignatureAlg::MlDsa65 => 2,
        SignatureAlg::MlDsa87 => 3,
        SignatureAlg::SlhDsaSha2_128s => 4,
        SignatureAlg::SlhDsaSha2_192s => 5,
        SignatureAlg::SlhDsaSha2_256s => 6,
        SignatureAlg::SlhDsaShake128s => 7,
        SignatureAlg::SlhDsaShake192s => 8,
        SignatureAlg::SlhDsaShake256s => 9,
        SignatureAlg::EcdsaP256 => 10,
        SignatureAlg::EcdsaP384 => 11,
    }
}

fn write_scope(c: &mut Canon, scope: &IntentScope) {
    let caps = scope.capabilities(); // &BTreeSet<Capability> — sorted iteration
    c.u64(caps.len() as u64);
    for cap in caps {
        c.bytes(cap.0.as_bytes());
    }
}

fn write_invariants(c: &mut Canon, inv: &InvariantSet) {
    c.u64(inv.len() as u64);
    for i in inv.iter() {
        // BTreeSet iteration order — sorted, deterministic.
        c.bytes(i.0.as_bytes());
    }
}

fn write_caveats(c: &mut Canon, caveats: &[Caveat]) {
    c.u64(caveats.len() as u64);
    for cav in caveats {
        c.bytes(cav.0.as_bytes());
    }
}

fn write_digest(c: &mut Canon, d: &Digest) {
    c.u8(hashalg_tag(d.alg));
    c.bytes(&d.bytes);
}

fn write_signature(c: &mut Canon, s: &Signature) {
    c.u8(sigalg_tag(s.alg));
    c.bytes(&s.bytes);
}

fn write_dual_signature(c: &mut Canon, ds: &DualSignature) {
    write_signature(c, &ds.lattice);
    write_signature(c, &ds.hash_based);
}

fn write_attestation(c: &mut Canon, a: &Attestation) {
    c.bytes(a.subject.as_str().as_bytes());
    write_digest(c, &a.measurements);
    c.u64(a.freshness.0);
    write_dual_signature(c, &a.signatures);
}

fn write_root_signed(c: &mut Canon, root: &RootIntent) {
    c.bytes(DOMAIN_ROOT);
    c.bytes(root.principal.as_str().as_bytes());
    c.bytes(root.dap.name.as_bytes());
    c.bytes(root.dap.id.as_bytes());
    write_scope(c, &root.scope);
    write_invariants(c, &root.invariants);
    c.u64(root.nonce.0);
    c.u64(root.expiry.0);
}

fn write_entry_signed(c: &mut Canon, e: &IntentChainEntry) {
    c.bytes(DOMAIN_ENTRY);
    write_attestation(c, &e.hop_identity);
    write_digest(c, &e.received_digest);
    write_scope(c, &e.emitted_scope);
    write_caveats(c, &e.added_caveats);
    write_invariants(c, &e.added_invariants);
}

/// The bytes a RootIntent's signature commits to — every field except `signature`.
pub fn root_signed_content(root: &RootIntent) -> Vec<u8> {
    let mut c = Canon::new();
    write_root_signed(&mut c, root);
    c.finish()
}

/// The full canonical bytes of a RootIntent, including its signature — hashed to
/// produce the `received_digest` that hop 1 links back to.
pub fn root_full(root: &RootIntent) -> Vec<u8> {
    let mut c = Canon::new();
    write_root_signed(&mut c, root);
    write_dual_signature(&mut c, &root.signature);
    c.finish()
}

/// The bytes an IntentChainEntry's signature commits to — every field except
/// `signature`. This includes `emitted_scope` in full (the OQGF-M-9 commitment).
pub fn entry_signed_content(e: &IntentChainEntry) -> Vec<u8> {
    let mut c = Canon::new();
    write_entry_signed(&mut c, e);
    c.finish()
}

/// The full canonical bytes of an entry, including its signature — hashed to produce
/// the `received_digest` the next hop links back to.
pub fn entry_full(e: &IntentChainEntry) -> Vec<u8> {
    let mut c = Canon::new();
    write_entry_signed(&mut c, e);
    write_dual_signature(&mut c, &e.signature);
    c.finish()
}
