//! Canonical serialization for HEIMDALL and EIR.
//!
//! Follows the discipline of the three sibling `canonical.rs` files exactly (`brokkr-genome`,
//! `brokkr-barrier`, `brokkr-audit`): deterministic fixed field order; every variable-length
//! field length-prefixed with a fixed 8-byte big-endian count; a domain tag; exhaustive enum
//! tags matched with **no catch-all** (a new variant breaks the build rather than colliding).
//!
//! Three encodings, three domain tags, all `brokkr-sentinel:*` — distinct from every
//! `brokkr-genome:*`, `brokkr-barrier:*`, and `brokkr-audit:*` tag (four-crate domain
//! separation, tested in `tests/sentinel.rs`):
//!
//! - `brokkr-sentinel:corpus:v1` — the Self Set corpus digest (OQGF-P-3 screening).
//! - `brokkr-sentinel:tolerance-grant:v1` — a `ToleranceGrant`'s signed content (OQGF-P-4).
//! - `brokkr-sentinel:signal:v1` — a `Signal`'s signed content (posture-raise emission).
//!
//! **The resolution-decision encoding is NOT here.** A `ResolutionDecision` is signed by a DAP
//! tool and verified by EIR — two parties — so its bytes are defined **once, in `brokkr-core`**
//! ([`brokkr_core::resolution::resolution_signed_content`], tag `brokkr-core:resolution:v1`,
//! Rev 1.12), and EIR calls that. A crate-local copy lived here through Phase 8 and disagreed
//! with core's (a different tag, and missing `nonce`/`expiry`); it was deleted in the Rev 1.12
//! adoption so the issuer and the verifier compute identical bytes from one definition.

use brokkr_core::barrier::{
    BarrierCondition, BarrierFinding, BarrierVerdict, BoundaryCustodyRecord, BoundaryFlow,
    ContextClass, Destination, DestinationClass, PersonalDataTag,
};
use brokkr_core::capability::EgressProtocol;
use brokkr_core::classification::{ChannelStrength, Classification, NamedGroup};
use brokkr_core::crypto::{DualSignature, Signature, SignatureAlg};
use brokkr_core::gate::{Action, AnergyReason};
use brokkr_core::ids::{Dap, OrganId};
use brokkr_core::personal_data::{Purpose, RetentionPeriod};
use brokkr_core::signal::{PostureEffect, Severity, Signal, SignalClass};
use brokkr_core::tolerance::ToleranceGrant;

use crate::observation::Observation;

const DOMAIN_CORPUS: &[u8] = b"brokkr-sentinel:corpus:v1";
const DOMAIN_GRANT: &[u8] = b"brokkr-sentinel:tolerance-grant:v1";
const DOMAIN_SIGNAL: &[u8] = b"brokkr-sentinel:signal:v1";

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

// ---- exhaustive enum tags (a new variant must break the build, not collide) ----------

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

fn classification_tag(c: Classification) -> u8 {
    match c {
        Classification::Public => 1,
        Classification::Internal => 2,
        Classification::Cui => 3,
        Classification::Secret => 4,
    }
}

fn barrier_condition_tag(c: BarrierCondition) -> u8 {
    match c {
        BarrierCondition::MissingCustodyRecord => 1,
        BarrierCondition::DatumMismatch => 2,
        BarrierCondition::SignatureInvalid => 3,
        BarrierCondition::Expired => 4,
        BarrierCondition::ClassificationMismatch => 5,
        BarrierCondition::UnauthorizedDestination => 6,
        BarrierCondition::ChannelStrengthCollapse => 7,
        BarrierCondition::PersonalDataUndeclared => 8,
    }
}

fn channel_strength_tag(c: ChannelStrength) -> u8 {
    match c {
        ChannelStrength::Classical => 1,
        ChannelStrength::PqcHybrid768 => 2,
        ChannelStrength::PqcHybrid1024 => 3,
    }
}

/// Encode an [`EgressProtocol`] into the canonical `Destination::Network` bytes (F-34). Known
/// variants are injective; `EgressProtocol` is `#[non_exhaustive]`, so a catch-all is *forced* by
/// the compiler for a future variant — it maps to tag 0, which is the one place this crate cannot
/// keep the "a new variant breaks the build" discipline. Network destinations are not recorded
/// today, so no persisted record depends on this yet; when they are, a new variant SHALL be given
/// its own tag here.
fn write_egress_protocol(c: &mut Canon, p: &EgressProtocol) {
    match p {
        EgressProtocol::Https => c.u8(1),
        EgressProtocol::Http => c.u8(2),
        EgressProtocol::Other(s) => {
            c.u8(3);
            c.bytes(s.as_bytes());
        }
        _ => c.u8(0),
    }
}

fn named_group_tag(g: NamedGroup) -> u8 {
    match g {
        NamedGroup::X25519 => 1,
        NamedGroup::Secp384r1 => 2,
        NamedGroup::X25519MlKem768 => 3,
        NamedGroup::Secp384r1MlKem1024 => 4,
    }
}

fn context_class_tag(c: ContextClass) -> u8 {
    match c {
        ContextClass::Privileged => 1,
        ContextClass::NonPrivileged => 2,
    }
}

fn organ_tag(o: OrganId) -> u8 {
    match o {
        OrganId::Genome => 1,
        OrganId::Intent => 2,
        OrganId::Gate => 3,
        OrganId::Barrier => 4,
        OrganId::Sentinel => 5,
        OrganId::Resolution => 6,
        OrganId::Adapt => 7,
        OrganId::Audit => 8,
        OrganId::Bifrost => 9,
        OrganId::Reasoner => 10,
    }
}

fn signal_class_tag(c: SignalClass) -> u8 {
    match c {
        SignalClass::ThreatDetected => 1,
        SignalClass::PostureRaiseRequest => 2,
        SignalClass::StateChangeNotice => 3,
    }
}

fn severity_tag(s: Severity) -> u8 {
    match s {
        Severity::Info => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

fn anergy_reason_tag(r: AnergyReason) -> u8 {
    match r {
        AnergyReason::IdentityUnverified => 1,
        AnergyReason::ChainInvalid => 2,
        AnergyReason::OutOfScope => 3,
        AnergyReason::InvariantViolated => 4,
        AnergyReason::ChainExpired => 5,
    }
}

// ---- leaf writers --------------------------------------------------------------------

fn write_signature(c: &mut Canon, s: &Signature) {
    c.u8(sigalg_tag(s.alg));
    c.bytes(&s.bytes);
}

fn write_dual_signature(c: &mut Canon, ds: &DualSignature) {
    write_signature(c, &ds.lattice);
    write_signature(c, &ds.hash_based);
}

fn write_dap(c: &mut Canon, dap: &Dap) {
    c.bytes(dap.name.as_bytes());
    c.bytes(dap.id.as_bytes());
}

fn write_purpose(c: &mut Canon, p: &Purpose) {
    c.bytes(p.description.as_bytes());
}

fn write_retention(c: &mut Canon, r: &RetentionPeriod) {
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

fn write_destination(c: &mut Canon, d: &Destination) {
    match d {
        Destination::LocalPath(path) => {
            c.u8(1);
            c.bytes(path.as_str().as_bytes());
        }
        Destination::Network {
            host,
            port,
            protocol,
            channel,
        } => {
            c.u8(2);
            c.bytes(host.as_str().as_bytes());
            c.u64(u64::from(*port));
            write_egress_protocol(c, protocol);
            c.u8(channel_strength_tag(*channel));
        }
        Destination::Reasoner {
            endpoint,
            negotiated,
        } => {
            c.u8(3);
            c.bytes(endpoint.as_str().as_bytes());
            c.u8(named_group_tag(*negotiated));
        }
    }
}

fn write_bcr(c: &mut Canon, bcr: &BoundaryCustodyRecord) {
    c.bytes(bcr.datum.as_str().as_bytes());
    c.u8(classification_tag(bcr.classification));
    c.bytes(bcr.origin.as_str().as_bytes());
    c.u64(bcr.authorized.len() as u64);
    for dest in &bcr.authorized {
        write_destination_class(c, dest);
    }
    write_personal(c, &bcr.personal);
    c.u64(bcr.issued.0);
    c.u64(bcr.expiry.0);
    write_dual_signature(c, &bcr.signature);
}

fn write_opt_bcr(c: &mut Canon, bcr: &Option<BoundaryCustodyRecord>) {
    match bcr {
        None => c.u8(0),
        Some(b) => {
            c.u8(1);
            write_bcr(c, b);
        }
    }
}

fn write_barrier_finding(c: &mut Canon, f: &BarrierFinding) {
    c.bytes(f.datum.as_str().as_bytes());
    c.u8(barrier_condition_tag(f.condition));
    c.u8(classification_tag(f.classification));
    c.bytes(f.reason.as_bytes());
}

fn write_verdict(c: &mut Canon, v: &BarrierVerdict) {
    match v {
        BarrierVerdict::Allow => c.u8(1),
        BarrierVerdict::Deny { finding } => {
            c.u8(2);
            write_barrier_finding(c, finding);
        }
        BarrierVerdict::Quarantine { datum } => {
            c.u8(3);
            c.bytes(datum.as_str().as_bytes());
        }
        BarrierVerdict::AcceptedRisk { entry } => {
            c.u8(4);
            c.bytes(entry.as_str().as_bytes());
        }
    }
}

fn write_flow(c: &mut Canon, flow: &BoundaryFlow) {
    match flow {
        BoundaryFlow::Egress {
            datum,
            classification,
            personal,
            destination,
            bcr,
        } => {
            c.u8(1);
            c.bytes(datum.as_str().as_bytes());
            c.u8(classification_tag(*classification));
            write_personal(c, personal);
            write_destination(c, destination);
            write_opt_bcr(c, bcr);
        }
        BoundaryFlow::Ingress {
            datum,
            personal,
            bcr,
            context,
        } => {
            c.u8(2);
            c.bytes(datum.as_str().as_bytes());
            write_personal(c, personal);
            write_opt_bcr(c, bcr);
            c.u8(context_class_tag(*context));
        }
    }
}

fn write_action(c: &mut Canon, a: &Action) {
    c.bytes(a.tool.as_str().as_bytes());
    c.bytes(a.detail.as_bytes());
}

fn write_opt_action(c: &mut Canon, a: &Option<Action>) {
    match a {
        None => c.u8(0),
        Some(act) => {
            c.u8(1);
            write_action(c, act);
        }
    }
}

fn write_opt_anergy(c: &mut Canon, a: &Option<AnergyReason>) {
    match a {
        None => c.u8(0),
        Some(r) => {
            c.u8(1);
            c.u8(anergy_reason_tag(*r));
        }
    }
}

fn write_posture_effect(c: &mut Canon, e: &PostureEffect) {
    match e {
        PostureEffect::Raise { detail } => {
            c.u8(1);
            c.bytes(detail.as_bytes());
        }
    }
}

/// A signal's body — every field except its own signature.
fn write_signal_body(c: &mut Canon, s: &Signal) {
    c.u8(organ_tag(s.source));
    c.u8(signal_class_tag(s.class));
    c.u8(severity_tag(s.severity));
    write_posture_effect(c, &s.effect);
    c.bytes(s.scope.detail.as_bytes());
    c.u64(s.nonce.0);
    c.u64(s.expiry.0);
}

/// A full signal, including its signature (for embedding in an observation).
fn write_signal(c: &mut Canon, s: &Signal) {
    write_signal_body(c, s);
    write_dual_signature(c, &s.signature);
}

fn write_observation(c: &mut Canon, o: &Observation) {
    match o {
        Observation::Crossing { flow, verdict } => {
            c.u8(1);
            write_flow(c, flow);
            write_verdict(c, verdict);
        }
        Observation::Authorization {
            action,
            granted,
            anergy,
        } => {
            c.u8(2);
            write_action(c, action);
            c.u8(u8::from(*granted));
            write_opt_anergy(c, anergy);
        }
        Observation::Signalled { signal } => {
            c.u8(3);
            write_signal(c, signal);
        }
        Observation::Hop {
            authorized,
            executed,
        } => {
            c.u8(4);
            write_action(c, authorized);
            write_opt_action(c, executed);
        }
    }
}

// ---- public: the four signed-content / digest encodings ------------------------------

/// The bytes the Self Set corpus digest is computed over (OQGF-P-3). Screening recomputes
/// this over `SelfSetCorpus::observations()` and binds the digest to the declared
/// `SelfSet.corpus_digest`.
pub fn corpus_signed_content(observations: &[Observation]) -> Vec<u8> {
    let mut c = Canon::new();
    c.bytes(DOMAIN_CORPUS);
    c.u64(observations.len() as u64);
    for o in observations {
        write_observation(&mut c, o);
    }
    c.finish()
}

/// The bytes a [`ToleranceGrant::signature`] covers — every field except the signature
/// (OQGF-P-4).
pub fn grant_signed_content(g: &ToleranceGrant) -> Vec<u8> {
    let mut c = Canon::new();
    c.bytes(DOMAIN_GRANT);
    c.bytes(g.target.as_str().as_bytes());
    c.bytes(g.scope.detail.as_bytes());
    write_dap(&mut c, &g.dap);
    c.u64(g.issued.0);
    c.u64(g.expiry.0);
    c.finish()
}

/// The bytes a [`Signal::signature`] covers — the signal body, excluding its own signature.
/// HEIMDALL signs the raise-Signals it emits (reconciliation deviations, chronic findings).
pub fn signal_signed_content(s: &Signal) -> Vec<u8> {
    let mut c = Canon::new();
    c.bytes(DOMAIN_SIGNAL);
    write_signal_body(&mut c, s);
    c.finish()
}
