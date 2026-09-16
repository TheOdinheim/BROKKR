//! Canonical serialization of the six genome registers and the genome itself.
//!
//! A deterministic, unambiguous byte encoding of the *signed content* of each register,
//! following `brokkr-intent/src/canonical.rs`'s discipline exactly:
//!
//! - **Deterministic:** fixed field order; `Vec` iteration order relied on (the registers
//!   are ordered lists, not sets).
//! - **Unambiguous:** every variable-length field is length-prefixed with a fixed 8-byte
//!   big-endian count, so no two distinct structures collide. No delimiters.
//! - **Domain-separated:** each register begins with its own domain tag. `ToolGenome`,
//!   `RootsOfTrust`, and `PolicyRegister` are all "a vector of entries plus a signature";
//!   without distinct tags a signature over one could verify against another. Six register
//!   tags plus one for the genome (§6.2). This is the highest-risk property here and is
//!   tested explicitly (`tests/promotion.rs::test_domain_separation_across_registers`).
//! - **Signed content excludes the register's own `signature`.** The genome's signed
//!   content covers `version`, `corpus_digest`, `owner`, and each register's **full**
//!   canonical bytes *including* that register's signature — so the genome signature
//!   commits to which signed registers it was assembled from.
//! - **Exhaustive enum tags:** every tag function matches the enum with no catch-all arm,
//!   so a new variant forces a compile error rather than a silent colliding tag.
//!
//! Hand-written: no serialization crate. serde/bincode/postcard are not guaranteed
//! canonical across versions or configuration, and canonicality is the whole point.

use brokkr_core::capability::ConformanceTier;
use brokkr_core::classification::{Classification, NamedGroup};
use brokkr_core::crypto::{Digest, DualSignature, HashAlg, KemAlg, Signature, SignatureAlg};
use brokkr_core::genome::{
    Aibom, AlgorithmId, BoundaryInterface, Cbom, CustodianSeparation, DualControl,
    EndpointRegistry, ExtractionProtection, FipsValidation, Genome, HardwareBoundary,
    InvariantEntry, KeyCustody, ModelEndpoint, PolicyRegister, PrivilegeClass, ProcedureRef,
    RootOfTrustEntry, RootsOfTrust, ToolEntry, ToolGenome, VendorTrustScore,
};
use brokkr_core::ids::{Dap, ModelIdentity, Score};
use brokkr_core::intent::Capability;
use brokkr_core::tolerance::ResponseClass;

const DOMAIN_TOOLS: &[u8] = b"brokkr-genome:tools:v1";
const DOMAIN_CBOM: &[u8] = b"brokkr-genome:cbom:v1";
const DOMAIN_AIBOM: &[u8] = b"brokkr-genome:aibom:v1";
const DOMAIN_ENDPOINTS: &[u8] = b"brokkr-genome:endpoints:v1";
const DOMAIN_ROOTS: &[u8] = b"brokkr-genome:roots:v1";
const DOMAIN_POLICY: &[u8] = b"brokkr-genome:policy:v1";
const DOMAIN_GENOME: &[u8] = b"brokkr-genome:genome:v1";

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

fn conformance_tier_tag(t: ConformanceTier) -> u8 {
    match t {
        ConformanceTier::Baseline => 1,
        ConformanceTier::Enhanced => 2,
        ConformanceTier::HighAssurance => 3,
    }
}

fn key_custody_tag(c: &KeyCustody) -> u8 {
    match c {
        KeyCustody::SoftwareInProcess { .. } => 1,
        KeyCustody::HardwareBacked { .. } => 2,
        KeyCustody::Threshold { .. } => 3,
    }
}

fn extraction_protection_tag(p: &ExtractionProtection) -> u8 {
    match p {
        ExtractionProtection::ProcessIsolationOnly => 1,
        ExtractionProtection::EncryptedAtRest => 2,
        ExtractionProtection::Other { .. } => 3,
    }
}

fn boundary_interface_tag(i: &BoundaryInterface) -> u8 {
    match i {
        BoundaryInterface::Pkcs11 => 1,
        BoundaryInterface::CloudKms => 2,
        BoundaryInterface::Tpm => 3,
        BoundaryInterface::SecureEnclave => 4,
        BoundaryInterface::Other { .. } => 5,
    }
}

fn fips_validation_tag(f: &FipsValidation) -> u8 {
    match f {
        FipsValidation::NotValidated => 1,
        FipsValidation::Level { .. } => 2,
    }
}

fn dual_control_tag(d: &DualControl) -> u8 {
    match d {
        DualControl::SingleOperator => 1,
        DualControl::TwoParty { .. } => 2,
    }
}

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

fn kemalg_tag(k: KemAlg) -> u8 {
    match k {
        KemAlg::MlKem512 => 1,
        KemAlg::MlKem768 => 2,
        KemAlg::MlKem1024 => 3,
    }
}

fn privilege_tag(p: PrivilegeClass) -> u8 {
    match p {
        PrivilegeClass::Unprivileged => 1,
        PrivilegeClass::Privileged => 2,
        PrivilegeClass::SelfModifying => 3,
    }
}

fn response_class_tag(r: ResponseClass) -> u8 {
    match r {
        ResponseClass::Deterministic => 1,
        ResponseClass::Heuristic => 2,
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

fn named_group_tag(g: NamedGroup) -> u8 {
    match g {
        NamedGroup::X25519 => 1,
        NamedGroup::Secp384r1 => 2,
        NamedGroup::X25519MlKem768 => 3,
        NamedGroup::Secp384r1MlKem1024 => 4,
    }
}

// ---- leaf writers --------------------------------------------------------------------

fn write_score(c: &mut Canon, s: Score) {
    // A Score is a bounded scalar (u8), not a length — one fixed byte, unambiguous.
    c.u8(s.0);
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

fn write_dap(c: &mut Canon, dap: &Dap) {
    c.bytes(dap.name.as_bytes());
    c.bytes(dap.id.as_bytes());
}

fn write_model_identity(c: &mut Canon, m: &ModelIdentity) {
    c.bytes(m.name.as_bytes());
    c.bytes(m.version.as_bytes());
    c.bytes(m.provider.as_bytes());
}

fn write_algorithm_id(c: &mut Canon, a: &AlgorithmId) {
    // A one-byte family discriminant, then the family's own exhaustive tag.
    match a {
        AlgorithmId::Signature(s) => {
            c.u8(1);
            c.u8(sigalg_tag(*s));
        }
        AlgorithmId::Hash(h) => {
            c.u8(2);
            c.u8(hashalg_tag(*h));
        }
        AlgorithmId::Kem(k) => {
            c.u8(3);
            c.u8(kemalg_tag(*k));
        }
    }
}

fn write_capabilities(c: &mut Canon, caps: &[Capability]) {
    c.u64(caps.len() as u64);
    for cap in caps {
        c.bytes(cap.0.as_bytes());
    }
}

fn write_privileges(c: &mut Canon, ps: &[PrivilegeClass]) {
    c.u64(ps.len() as u64);
    for p in ps {
        c.u8(privilege_tag(*p));
    }
}

// ---- per-register signed content (EXCLUDES the register's own signature) -------------

fn write_tool_entry(c: &mut Canon, e: &ToolEntry) {
    c.bytes(e.id.as_str().as_bytes());
    c.bytes(e.schema.detail.as_bytes());
    c.u8(privilege_tag(e.privilege));
    c.u8(response_class_tag(e.response_class));
    write_capabilities(c, &e.required_capabilities);
}

fn write_tools_signed(c: &mut Canon, t: &ToolGenome) {
    c.bytes(DOMAIN_TOOLS);
    c.u64(t.entries.len() as u64);
    for e in &t.entries {
        write_tool_entry(c, e);
    }
}

fn write_procedure_ref(c: &mut Canon, p: &ProcedureRef) {
    c.bytes(p.document.as_bytes());
    write_digest(c, &p.digest);
}

fn write_extraction_protection(c: &mut Canon, p: &ExtractionProtection) {
    c.u8(extraction_protection_tag(p));
    match p {
        ExtractionProtection::ProcessIsolationOnly | ExtractionProtection::EncryptedAtRest => {}
        ExtractionProtection::Other { description } => c.bytes(description.as_bytes()),
    }
}

fn write_fips_validation(c: &mut Canon, f: &FipsValidation) {
    c.u8(fips_validation_tag(f));
    match f {
        FipsValidation::NotValidated => {}
        FipsValidation::Level { level, certificate } => {
            c.u8(*level);
            c.bytes(certificate.as_bytes());
        }
    }
}

fn write_boundary_interface(c: &mut Canon, i: &BoundaryInterface) {
    c.u8(boundary_interface_tag(i));
    match i {
        BoundaryInterface::Pkcs11
        | BoundaryInterface::CloudKms
        | BoundaryInterface::Tpm
        | BoundaryInterface::SecureEnclave => {}
        BoundaryInterface::Other { description } => c.bytes(description.as_bytes()),
    }
}

fn write_hardware_boundary(c: &mut Canon, b: &HardwareBoundary) {
    c.bytes(b.module.as_bytes());
    write_boundary_interface(c, &b.interface);
    write_fips_validation(c, &b.fips);
}

fn write_dual_control(c: &mut Canon, d: &DualControl) {
    c.u8(dual_control_tag(d));
    match d {
        DualControl::SingleOperator => {}
        DualControl::TwoParty { procedure } => write_procedure_ref(c, procedure),
    }
}

fn write_custodian_separation(c: &mut Canon, s: &CustodianSeparation) {
    c.u8(s.independent_parties);
    write_procedure_ref(c, &s.separation_of_duty);
}

/// The custody declaration (OQGF-R-6, AMD-018). Inside the CBOM's signed content, so a
/// change to the declared custody model changes the CBOM digest, the genome signature, and
/// requires re-promotion.
fn write_key_custody(c: &mut Canon, k: &KeyCustody) {
    c.u8(key_custody_tag(k));
    match k {
        KeyCustody::SoftwareInProcess { protection } => write_extraction_protection(c, protection),
        KeyCustody::HardwareBacked {
            boundary,
            dual_control,
        } => {
            write_hardware_boundary(c, boundary);
            write_dual_control(c, dual_control);
        }
        KeyCustody::Threshold {
            boundary,
            dual_control,
            quorum,
            custodians,
            ceremony,
            recovery,
            rotation,
            last_rehearsal,
        } => {
            write_hardware_boundary(c, boundary);
            write_dual_control(c, dual_control);
            c.u8(quorum.k);
            c.u8(quorum.n);
            write_custodian_separation(c, custodians);
            write_procedure_ref(c, ceremony);
            write_procedure_ref(c, recovery);
            write_procedure_ref(c, rotation);
            c.u64(last_rehearsal.0);
        }
    }
}

fn write_cbom_signed(c: &mut Canon, b: &Cbom) {
    c.bytes(DOMAIN_CBOM);
    c.bytes(b.cyclonedx.as_bytes());
    c.u64(b.algorithms.len() as u64);
    for a in &b.algorithms {
        write_algorithm_id(c, a);
    }
    write_key_custody(c, &b.custody);
}

fn write_aibom_signed(c: &mut Canon, b: &Aibom) {
    c.bytes(DOMAIN_AIBOM);
    c.bytes(b.cyclonedx.as_bytes());
}

fn write_vendor_trust_score(c: &mut Canon, v: &VendorTrustScore) {
    write_score(c, v.attestation_capability);
    write_score(c, v.fips_validation);
    write_score(c, v.breach_history);
    write_score(c, v.jurisdictional_exposure);
    write_score(c, v.data_handling);
    write_score(c, v.reconciliation_pass_rate);
    // OQGF-M-6 evidence (Rev 1.31). This moves `endpoints_signed_content` and therefore
    // `genome_signed_content`: both the endpoints-register signature and the genome
    // signature are recomputed. It does NOT move the audit chain — `GenomePromotion`
    // carries only `version` and the *declared* `corpus_digest`, neither derived from a
    // register encoding (traced per the Rev 1.29 lesson, GAP-2026-09-10-001).
    c.u64(v.evidence.observations);
    c.u64(v.evidence.measured.0);
    c.u64(v.reviewed.0);
    write_dap(c, &v.reviewer);
    // The trust score carries its own signature; the endpoint register commits to it as
    // data (it is not one of the six register signatures the gate verifies separately).
    write_dual_signature(c, &v.signature);
}

fn write_model_endpoint(c: &mut Canon, e: &ModelEndpoint) {
    c.bytes(e.id.as_str().as_bytes());
    write_model_identity(c, &e.model);
    c.bytes(e.client_cert.as_str().as_bytes());
    c.bytes(e.server_trust.as_str().as_bytes());
    c.u8(named_group_tag(e.min_group));
    c.u8(classification_tag(e.max_classification));
    write_vendor_trust_score(c, &e.trust_score);
}

fn write_endpoints_signed(c: &mut Canon, r: &EndpointRegistry) {
    c.bytes(DOMAIN_ENDPOINTS);
    c.u64(r.endpoints.len() as u64);
    for e in &r.endpoints {
        write_model_endpoint(c, e);
    }
}

fn write_root_entry(c: &mut Canon, e: &RootOfTrustEntry) {
    c.bytes(e.subject.as_str().as_bytes());
    c.bytes(&e.ml_dsa_public);
    c.bytes(&e.slh_dsa_public);
}

fn write_roots_signed(c: &mut Canon, r: &RootsOfTrust) {
    c.bytes(DOMAIN_ROOTS);
    c.u64(r.entries.len() as u64);
    for e in &r.entries {
        write_root_entry(c, e);
    }
}

fn write_invariant_entry(c: &mut Canon, e: &InvariantEntry) {
    c.bytes(e.invariant.0.as_bytes());
    write_capabilities(c, &e.forbids_capabilities);
    write_privileges(c, &e.forbids_privilege);
}

fn write_policy_signed(c: &mut Canon, p: &PolicyRegister) {
    c.bytes(DOMAIN_POLICY);
    write_capabilities(c, &p.capabilities);
    c.u64(p.invariants.len() as u64);
    for i in &p.invariants {
        write_invariant_entry(c, i);
    }
    c.u64(p.disallowed.len() as u64);
    for a in &p.disallowed {
        write_algorithm_id(c, a);
    }
}

// ---- public: per-register signed content (what each register signature covers) -------

/// The bytes `ToolGenome::signature` covers — every field except the signature.
pub fn tools_signed_content(t: &ToolGenome) -> Vec<u8> {
    let mut c = Canon::new();
    write_tools_signed(&mut c, t);
    c.finish()
}

/// The bytes `Cbom::signature` covers.
pub fn cbom_signed_content(b: &Cbom) -> Vec<u8> {
    let mut c = Canon::new();
    write_cbom_signed(&mut c, b);
    c.finish()
}

/// The bytes `Aibom::signature` covers.
pub fn aibom_signed_content(b: &Aibom) -> Vec<u8> {
    let mut c = Canon::new();
    write_aibom_signed(&mut c, b);
    c.finish()
}

/// The bytes `EndpointRegistry::signature` covers.
pub fn endpoints_signed_content(r: &EndpointRegistry) -> Vec<u8> {
    let mut c = Canon::new();
    write_endpoints_signed(&mut c, r);
    c.finish()
}

/// The bytes `RootsOfTrust::signature` covers.
pub fn roots_signed_content(r: &RootsOfTrust) -> Vec<u8> {
    let mut c = Canon::new();
    write_roots_signed(&mut c, r);
    c.finish()
}

/// The bytes `PolicyRegister::signature` covers.
pub fn policy_signed_content(p: &PolicyRegister) -> Vec<u8> {
    let mut c = Canon::new();
    write_policy_signed(&mut c, p);
    c.finish()
}

// ---- genome signed content: register FULL bytes (incl. each register's signature) ----

fn write_register_full<F>(c: &mut Canon, write_signed: F, sig: &DualSignature)
where
    F: FnOnce(&mut Canon),
{
    write_signed(c);
    write_dual_signature(c, sig);
}

/// The bytes `Genome::signature` covers: `version`, `corpus_digest`, `owner`, and each
/// register's **full** canonical bytes (signed content **plus** that register's own
/// signature). The genome signature therefore commits to which *signed* registers it was
/// assembled from — swapping in a differently-signed register breaks it.
pub fn genome_signed_content(g: &Genome) -> Vec<u8> {
    let mut c = Canon::new();
    c.bytes(DOMAIN_GENOME);
    c.bytes(g.version.as_str().as_bytes());
    // The declared conformance tier (ARCH Rev 1.22) is inside the genome's signed content:
    // changing it changes the genome signature and requires re-promotion, so a downgrade
    // that would relax predicate 7's custody obligation is a signed, attributable act.
    c.u8(conformance_tier_tag(g.tier));
    write_digest(&mut c, &g.corpus_digest);
    write_dap(&mut c, &g.owner);
    write_register_full(
        &mut c,
        |c| write_tools_signed(c, &g.tools),
        &g.tools.signature,
    );
    write_register_full(&mut c, |c| write_cbom_signed(c, &g.cbom), &g.cbom.signature);
    write_register_full(
        &mut c,
        |c| write_aibom_signed(c, &g.aibom),
        &g.aibom.signature,
    );
    write_register_full(
        &mut c,
        |c| write_endpoints_signed(c, &g.endpoints),
        &g.endpoints.signature,
    );
    write_register_full(
        &mut c,
        |c| write_roots_signed(c, &g.roots),
        &g.roots.signature,
    );
    write_register_full(
        &mut c,
        |c| write_policy_signed(c, &g.policy),
        &g.policy.signature,
    );
    c.finish()
}
