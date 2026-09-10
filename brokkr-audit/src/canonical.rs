//! Canonical serialization for SAGA.
//!
//! Follows `brokkr-genome/src/canonical.rs` and `brokkr-barrier/src/canonical.rs` **exactly**:
//! deterministic fixed field order; every variable-length field length-prefixed with a fixed
//! 8-byte big-endian count; a domain tag; exhaustive enum tags (matched with **no catch-all**,
//! so a new variant breaks the build rather than colliding).
//!
//! ## The one rule Rev 1.10 settles
//!
//! [`record_signed_content`] encodes a record's **signed content** — `seq`, `prev`, `at`,
//! `dap`, `event` — and **nothing else**. That is what a [`GenerationSignature`] signs, what
//! the next record's `prev` digests, and what a TSA token stamps. `signatures` and
//! `timestamping` are **not** in it: they attest to those bytes from outside them (§6.9, "The
//! three attestations"). There is deliberately **no** "full bytes including signatures"
//! encoding used for chain linkage — appending a signature or a timestamp therefore cannot
//! disturb any link. [`export_signed_content`] *does* commit to the signatures and
//! timestamps, but that is a **bundle** signature over a snapshot, never a `prev`.
//!
//! ## Domain separation across THREE crates
//!
//! `brokkr-audit`'s tags differ from every `brokkr-genome:*` and `brokkr-barrier:*` tag, so no
//! signature over a genome register or a BCR verifies as an audit record, and vice versa
//! (tested directly in `tests/audit.rs`).

use brokkr_core::adapt::{DetectorProvenance, RefinedDetector};
use brokkr_core::barrier::{
    BarrierCondition, BarrierFinding, BarrierVerdict, BoundaryCustodyRecord, BoundaryFlow,
    ContextClass, Destination, DestinationClass, PersonalDataTag,
};
use brokkr_core::capability::{
    AttestationOutcome, CapabilityProbe, CapabilityProperty, EgressProtocol,
    EnvironmentAttestation, EvidenceProvenance, ProbeOutcome,
};
use brokkr_core::classification::{ChannelStrength, Classification, NamedGroup};
use brokkr_core::crypto::{Digest, DualSignature, HashAlg, Signature, SignatureAlg};
use brokkr_core::gate::{Action, AnergyReason};
use brokkr_core::ids::{Dap, ModelIdentity, OrganId};
use brokkr_core::personal_data::{Purpose, RetentionPeriod};
use brokkr_core::resolution::ResolutionDecision;
use brokkr_core::risk::{DeterministicGateId, RiskAcceptance};
use brokkr_core::signal::{PostureEffect, Severity, Signal, SignalClass};
use brokkr_core::tolerance::ToleranceGrant;

use crate::event::{
    AuditEvent, AuditRecord, AuthorizationOutcome, AuthorizationRecord, BarrierCrossing,
    ErasureTombstone, GenerationSignature, GenomePromotion, ProposalRecord, RecordedInput,
    TimestampSigAlg, Timestamping,
};

const DOMAIN_RECORD: &[u8] = b"brokkr-audit:record:v1";
const DOMAIN_SIGNAL: &[u8] = b"brokkr-audit:chain-break-signal:v1";
const DOMAIN_EXPORT: &[u8] = b"brokkr-audit:export:v1";

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

fn hashalg_tag(h: HashAlg) -> u8 {
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
        SignatureAlg::RsaPkcs1Sha256 => 12,
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

        BarrierCondition::PersonalDataFieldOutOfScope => 9,
    }
}

fn gate_tag(g: DeterministicGateId) -> u8 {
    match g {
        DeterministicGateId::Genome => 1,
        DeterministicGateId::Mhc => 2,
        DeterministicGateId::Barrier => 3,
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
/// variants are injective; `EgressProtocol` is `#[non_exhaustive]`, so the catch-all (tag 0) is
/// forced by the compiler for a future variant. Network destinations are not recorded today; when
/// they are, a new variant SHALL be given its own tag here.
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

fn write_dap(c: &mut Canon, dap: &Dap) {
    c.bytes(dap.name.as_bytes());
    c.bytes(dap.id.as_bytes());
}

fn write_model_identity(c: &mut Canon, m: &ModelIdentity) {
    c.bytes(m.name.as_bytes());
    c.bytes(m.version.as_bytes());
    c.bytes(m.provider.as_bytes());
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
            write_personal_tag(c, tag);
        }
    }
}

fn write_personal_tag(c: &mut Canon, tag: &PersonalDataTag) {
    write_purpose(c, &tag.purpose);
    write_retention(c, &tag.retention);
    // OQGF-P-11.2 (Rev 1.29). NOTE: this encoder feeds `record_signed_content` via
    // AuditEvent::BarrierCrossing -> write_flow -> write_personal, and via
    // RecordedInput::Shredded — so this field is inside the audit chain's linkage digest,
    // not only the BCR signature. GAP-2026-09-10-001 corrects Rev 1.29 §6.5, which stated
    // the opposite. Zero cost today (SAGA is in-memory, no persisted chain); not zero once
    // SAGA persists.
    c.u64(tag.fields.len() as u64);
    for f in &tag.fields {
        c.bytes(f.as_str().as_bytes());
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

fn write_opt_digest(c: &mut Canon, d: &Option<Digest>) {
    match d {
        None => c.u8(0),
        Some(dig) => {
            c.u8(1);
            write_digest(c, dig);
        }
    }
}

fn write_opt_dap(c: &mut Canon, d: &Option<Dap>) {
    match d {
        None => c.u8(0),
        Some(dap) => {
            c.u8(1);
            write_dap(c, dap);
        }
    }
}

fn write_action(c: &mut Canon, a: &Action) {
    c.bytes(a.tool.as_str().as_bytes());
    c.bytes(a.detail.as_bytes());
}

fn write_resolution(c: &mut Canon, d: &ResolutionDecision) {
    c.bytes(d.escalation.as_str().as_bytes());
    c.bytes(d.cleared_condition.detail.as_bytes());
    write_dap(c, &d.dap);
    c.u64(d.at.0);
    // Freshness fields (Rev 1.12), in struct field order — without them two decisions differing
    // only in `nonce`/`expiry` would encode identically in the audit chain, and the spine would
    // hold an incomplete account of the one act that lowers a defence.
    c.u64(d.nonce.0);
    c.u64(d.expiry.0);
    write_dual_signature(c, &d.signature);
}

fn write_risk_acceptance(c: &mut Canon, a: &RiskAcceptance) {
    c.bytes(a.finding.as_str().as_bytes());
    match a.gate {
        None => c.u8(0),
        Some(g) => {
            c.u8(1);
            c.u8(gate_tag(g));
        }
    }
    write_dap(c, &a.dap);
    c.bytes(a.justification.as_bytes());
    c.u64(a.expiry.0);
    write_dual_signature(c, &a.signature);
}

fn write_tolerance_grant(c: &mut Canon, g: &ToleranceGrant) {
    c.bytes(g.target.as_str().as_bytes());
    c.bytes(g.scope.detail.as_bytes());
    write_dap(c, &g.dap);
    c.u64(g.issued.0);
    c.u64(g.expiry.0);
    write_dual_signature(c, &g.signature);
}

fn write_posture_effect(c: &mut Canon, e: &PostureEffect) {
    match e {
        PostureEffect::Raise { detail } => {
            c.u8(1);
            c.bytes(detail.as_bytes());
        }
    }
}

fn write_signal_body(c: &mut Canon, s: &Signal) {
    c.u8(organ_tag(s.source));
    c.u8(signal_class_tag(s.class));
    c.u8(severity_tag(s.severity));
    write_posture_effect(c, &s.effect);
    c.bytes(s.scope.detail.as_bytes());
    c.u64(s.nonce.0);
    c.u64(s.expiry.0);
}

fn write_signal(c: &mut Canon, s: &Signal) {
    write_signal_body(c, s);
    write_dual_signature(c, &s.signature);
}

fn write_refined_detector(c: &mut Canon, d: &RefinedDetector) {
    c.bytes(d.base().id.as_str().as_bytes());
    c.bytes(d.change().detail.as_bytes());
    c.u64(d.generation());
    // response_class is Heuristic by construction (I-9); recorded for completeness.
    c.u8(match d.response_class() {
        brokkr_core::tolerance::ResponseClass::Deterministic => 1,
        brokkr_core::tolerance::ResponseClass::Heuristic => 2,
    });
}

fn write_detector_provenance(c: &mut Canon, p: &DetectorProvenance) {
    c.bytes(p.seeding.as_str().as_bytes());
    c.bytes(p.corpus_version.as_str().as_bytes());
    c.bytes(p.screen_result.version.as_str().as_bytes());
    write_dap(c, &p.approver);
    write_dual_signature(c, &p.signature);
}

fn write_recorded_input(c: &mut Canon, i: &RecordedInput) {
    match i {
        RecordedInput::Derivative(d) => {
            c.u8(1);
            write_digest(c, d);
        }
        RecordedInput::Shredded {
            subject,
            personal,
            ciphertext,
        } => {
            c.u8(2);
            c.bytes(subject.as_str().as_bytes());
            write_personal_tag(c, personal);
            c.bytes(ciphertext);
        }
    }
}

fn write_proposal(c: &mut Canon, p: &ProposalRecord) {
    write_model_identity(c, &p.model);
    write_digest(c, &p.aibom_digest);
    write_recorded_input(c, &p.input);
    c.bytes(p.output.as_bytes());
    c.bytes(p.explanation.as_bytes());
}

fn write_barrier_crossing(c: &mut Canon, x: &BarrierCrossing) {
    write_verdict(c, &x.verdict);
    write_flow(c, &x.flow);
    write_opt_digest(c, &x.bcr_digest);
    write_opt_dap(c, &x.dap);
}

fn write_authorization(c: &mut Canon, a: &AuthorizationRecord) {
    write_action(c, &a.action);
    match &a.outcome {
        AuthorizationOutcome::Granted => c.u8(1),
        AuthorizationOutcome::Anergy { reason } => {
            c.u8(2);
            c.u8(anergy_reason_tag(*reason));
        }
    }
}

fn write_genome_promotion(c: &mut Canon, g: &GenomePromotion) {
    c.bytes(g.version.as_str().as_bytes());
    write_digest(c, &g.corpus_digest);
}

fn write_erasure(c: &mut Canon, t: &ErasureTombstone) {
    c.u64(t.erased);
    c.u8(classification_tag(t.classification));
    c.u64(t.at.0);
    write_dap(c, &t.dap);
}

/// A `CapabilityProperty`, via the exhaustive discriminant and payload the defining
/// crate supplies (`CapabilityProperty::canonical_tag` / `canonical_payload`). The
/// enum is `#[non_exhaustive]`, so an encoder-side `match` would need a wildcard —
/// which would let a future variant encode under a borrowed tag instead of breaking
/// the build. The exhaustive match therefore lives in `brokkr-core`.
fn write_capability_property(c: &mut Canon, p: &CapabilityProperty) {
    c.u8(p.canonical_tag());
    let payload = p.canonical_payload();
    c.u64(payload.len() as u64);
    for part in payload {
        c.bytes(part.as_bytes());
    }
}

fn write_probe_outcome(c: &mut Canon, o: &ProbeOutcome) {
    match o {
        ProbeOutcome::Refused { detail } => {
            c.u8(1);
            c.bytes(detail.as_bytes());
        }
        ProbeOutcome::Reachable { detail } => {
            c.u8(2);
            c.bytes(detail.as_bytes());
        }
        ProbeOutcome::NotProbeable { reason } => {
            c.u8(3);
            c.bytes(reason.as_bytes());
        }
        ProbeOutcome::ProbeError { detail } => {
            c.u8(4);
            c.bytes(detail.as_bytes());
        }
    }
}

fn write_capability_probe(c: &mut Canon, p: &CapabilityProbe) {
    write_capability_property(c, &p.capability);
    c.u8(u8::from(p.declared));
    c.bytes(p.attempted.as_bytes());
    write_probe_outcome(c, &p.outcome);
}

/// OQGF-P-12.3 (ARCH Rev 1.23). Inside the record's signed content like every other
/// event, so an attestation cannot be altered without breaking the chain.
fn write_environment_attestation(c: &mut Canon, a: &EnvironmentAttestation) {
    c.bytes(a.system_id.as_bytes());
    c.u64(a.probes.len() as u64);
    for p in &a.probes {
        write_capability_probe(c, p);
    }
    match &a.outcome {
        AttestationOutcome::Attested => c.u8(1),
        AttestationOutcome::Discrepant { reachable } => {
            c.u8(2);
            c.u64(reachable.len() as u64);
            for r in reachable {
                write_capability_property(c, r);
            }
        }
        AttestationOutcome::Incomplete { unprobed } => {
            c.u8(3);
            c.u64(unprobed.len() as u64);
            for u in unprobed {
                write_capability_property(c, u);
            }
        }
    }
    c.u64(a.probed_at.0);
}

/// The whole of the typed event, with an exhaustive variant discriminant (no catch-all).
fn write_event(c: &mut Canon, e: &AuditEvent) {
    match e {
        AuditEvent::BarrierCrossing(x) => {
            c.u8(1);
            write_barrier_crossing(c, x);
        }
        AuditEvent::Authorization(a) => {
            c.u8(2);
            write_authorization(c, a);
        }
        AuditEvent::GenomePromotion(g) => {
            c.u8(3);
            write_genome_promotion(c, g);
        }
        AuditEvent::Resolution(r) => {
            c.u8(4);
            write_resolution(c, r);
        }
        AuditEvent::RiskAcceptance(a) => {
            c.u8(5);
            write_risk_acceptance(c, a);
        }
        AuditEvent::ToleranceGrant(g) => {
            c.u8(6);
            write_tolerance_grant(c, g);
        }
        AuditEvent::Signal(s) => {
            c.u8(7);
            write_signal(c, s);
        }
        AuditEvent::DetectorActivation {
            detector,
            provenance,
        } => {
            c.u8(8);
            write_refined_detector(c, detector);
            write_detector_provenance(c, provenance);
        }
        AuditEvent::Proposal(p) => {
            c.u8(9);
            write_proposal(c, p);
        }
        AuditEvent::Correction { corrects, detail } => {
            c.u8(10);
            c.u64(*corrects);
            c.bytes(detail.as_bytes());
        }
        AuditEvent::Erasure(t) => {
            c.u8(11);
            write_erasure(c, t);
        }
        AuditEvent::EnvironmentAttestation(a) => {
            c.u8(12);
            write_environment_attestation(c, a);
        }
    }
}

// ---- public: the signed content, the signal body, and the export bundle --------------

/// The bytes a record's [`GenerationSignature`]s sign, the next record's `prev` digests, and
/// a TSA token stamps: `seq`, `prev`, `at`, `dap`, `event`, and `provenance` (Rev 1.10 plus the
/// Organ 5 evidence-capture patch — provenance is signed because it is set once at capture, not
/// accumulated like the signatures Rev 1.10 excludes). The `signatures` and `timestamping` fields
/// remain outside.
pub fn record_signed_content(r: &AuditRecord) -> Vec<u8> {
    let mut c = Canon::new();
    c.bytes(DOMAIN_RECORD);
    c.u64(r.seq);
    write_digest(&mut c, &r.prev);
    c.u64(r.at.0);
    write_dap(&mut c, &r.dap);
    write_event(&mut c, &r.event);
    write_provenance(&mut c, &r.provenance);
    c.finish()
}

/// Canonically encode the evidence-source provenance (Organ 5 patch). Every variable-length field
/// is length-prefixed; the optional gap is a presence byte then the bytes.
fn write_provenance(c: &mut Canon, p: &EvidenceProvenance) {
    c.bytes(p.sensor_id.as_bytes());
    c.bytes(p.capture_path.as_bytes());
    c.u64(p.capture_timestamp.0);
    c.bytes(p.expected_coverage.as_bytes());
    c.bytes(p.observed_coverage.as_bytes());
    match &p.evidence_gap {
        None => c.u8(0),
        Some(g) => {
            c.u8(1);
            c.bytes(g.as_bytes());
        }
    }
}

/// The bytes a chain-break [`Signal`]'s signature covers — the signal body, excluding its own
/// signature. Domain-separated from records and exports.
pub fn signal_signed_content(s: &Signal) -> Vec<u8> {
    let mut c = Canon::new();
    c.bytes(DOMAIN_SIGNAL);
    write_signal_body(&mut c, s);
    c.finish()
}

/// One record's **full** bytes for an export bundle: signed content **plus** the accumulated
/// signature set **plus** the timestamping. Used ONLY by [`export_signed_content`] so a
/// recipient can verify the whole snapshot — signatures included — was not altered. This is a
/// bundle projection, **never** a `prev` digest input (that would reintroduce the Rev 1.9
/// contradiction).
fn record_full_for_export(c: &mut Canon, r: &AuditRecord) {
    c.bytes(&record_signed_content(r));
    c.u64(r.signatures.len() as u64);
    for gs in &r.signatures {
        write_generation_signature(c, gs);
    }
    write_timestamping(c, &r.timestamping);
}

fn write_generation_signature(c: &mut Canon, gs: &GenerationSignature) {
    c.u64(gs.generation.0 as u64);
    c.u64(gs.signed_at.0);
    write_dual_signature(c, &gs.signature);
}

/// Exhaustive, no catch-all — a new variant breaks the build rather than colliding.
fn timestamp_sigalg_tag(a: &TimestampSigAlg) -> u8 {
    match a {
        TimestampSigAlg::RsaSha256 => 1,
        TimestampSigAlg::RsaSha384 => 2,
        TimestampSigAlg::RsaSha512 => 3,
        TimestampSigAlg::EcdsaSha256 => 4,
        TimestampSigAlg::EcdsaSha384 => 5,
        TimestampSigAlg::EcdsaSha512 => 6,
        TimestampSigAlg::Unrecognized { .. } => 7,
    }
}

fn write_timestamping(c: &mut Canon, t: &Timestamping) {
    match t {
        Timestamping::Token(tok) => {
            c.u8(1);
            c.bytes(&tok.token);
            c.bytes(tok.authority.as_bytes());
            // The derived algorithm AND the two raw OIDs it was derived from, so an export
            // recipient can re-derive rather than trust (ARCH Rev 1.25 §6.9).
            c.u8(timestamp_sigalg_tag(&tok.algorithm));
            c.u64(u64::from(tok.key_oid));
            c.u64(u64::from(tok.hash_oid));
            c.bytes(tok.gen_time.as_bytes());
        }
        Timestamping::Unavailable { reason } => {
            c.u8(2);
            c.bytes(reason.as_bytes());
        }
    }
}

/// The bytes an export bundle's signature covers: a domain tag and each record's full bytes
/// (signed content + signatures + timestamping). A recipient verifies this under the
/// exporter's public key to confirm the snapshot — signatures and all — is intact.
pub fn export_signed_content(records: &[AuditRecord]) -> Vec<u8> {
    let mut c = Canon::new();
    c.bytes(DOMAIN_EXPORT);
    c.u64(records.len() as u64);
    for r in records {
        record_full_for_export(&mut c, r);
    }
    c.finish()
}
