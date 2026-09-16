//! The load-bearing negative tests for brokkr-core. One or more per invariant, the
//! invariant ID in each test name. Runtime tests live here; compile-time invariants
//! (I-1, I-2, I-10, I-11, I-12) are additionally proven by `compile_fail` doctests
//! on the types themselves (run by `cargo test --doc`) and are exercised here from
//! the positive side (the sanctioned minting path works and is the only one).
//!
//! These are integration tests: separate crates, so they may use `unwrap`/`panic`.

mod common;

use brokkr_core::adapt::{
    AdaptError, DetectorDelta, DetectorProvenance, DetectorSpecBase, EvaluationCorpus,
    MaturationPipeline, PriorGeneration, RefinedDetector, SeedingIncident, SelectionPass,
};
use brokkr_core::barrier::{BarrierCondition, BarrierFinding, BarrierVerdict, Destination};
use brokkr_core::classification::{
    ChannelStrength, Classification, NamedGroup, effective_authorization,
};
use brokkr_core::gate::{Action, AnergyReason, AuthorizationDecision, CostimulationGate};
use brokkr_core::genome::{FactorEvidence, ModelEndpoint, VendorTrustScore};
use brokkr_core::ids::{
    ClientCertRef, CorpusVersion, DatumRef, DetectorId, EscalationId, GrantId, IncidentId,
    ModelEndpointId, ModelIdentity, Score, SelfSetVersion, Timestamp, ToolId, TrustAnchor,
};
use brokkr_core::intent::{
    AttenuationError, Capability, IntentProvenanceChain, IntentScope, Invariant, InvariantSet,
    RootIntent,
};
use brokkr_core::reasoner::{Context, ContextClearance};
use brokkr_core::resolution::{
    ClearCondition, ClearEvidence, ResolutionDecision, ResolutionEngine, ResolutionVerdict,
    ResolveError, ReturnedToBaseline,
};
use brokkr_core::tolerance::{
    DetectorSpec, HostHarmReport, ResponseClass, ScreenPass, SelfSet, SuppressionScope,
    ToleranceController, ToleranceError, ToleranceGrant,
};

use common::{MockHasher, MockSigner, MockVerifier, attestation, dap, digest, dual_sig};

use brokkr_core::crypto::{Hasher, SignatureAlg, Signer, Verifier};

// ---------------------------------------------------------------------------
// The crypto seam is usable with a mock — no wolfCrypt, no FFI (Phase 1). Phase 2
// supplies the real backend behind these same traits.
// ---------------------------------------------------------------------------

#[test]
fn test_crypto_seam_usable_with_mock_no_ffi() {
    let signer = MockSigner {
        alg: SignatureAlg::MlDsa87,
    };
    let verifier = MockVerifier {
        alg: SignatureAlg::MlDsa87,
    };
    let hasher = MockHasher;

    let msg = b"governed action";
    let sig = signer.sign(msg).unwrap();
    assert_eq!(signer.algorithm(), SignatureAlg::MlDsa87);
    assert!(verifier.verify(msg, &sig).is_ok());
    assert!(verifier.verify(b"tampered", &sig).is_err());

    let d = hasher.hash(msg);
    assert_eq!(d.alg, brokkr_core::crypto::HashAlg::Sha384);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn root_intent(scope: IntentScope) -> RootIntent {
    RootIntent {
        principal: brokkr_core::ids::SubjectId::new("principal"),
        dap: dap(),
        scope,
        invariants: InvariantSet::new([Invariant::new("no-network-egress")]),
        nonce: brokkr_core::ids::Nonce(1),
        expiry: Timestamp(10_000),
        signature: dual_sig(),
    }
}

fn chain_with_scope(caps: &[&str]) -> IntentProvenanceChain {
    let scope = IntentScope::new(caps.iter().map(|c| Capability::new(*c)));
    IntentProvenanceChain::new(root_intent(scope))
}

fn action() -> Action {
    Action {
        tool: ToolId::new("write_file"),
        detail: "./src/main.rs".into(),
    }
}

/// A concrete evaluation time. I-13: the gate and the clearance take `now` as a
/// per-call argument, so every call site supplies one — this is that argument. It is
/// well before the fixtures' `expiry` (10_000), so freshness never trips these tests.
const NOW: Timestamp = Timestamp(1_000);

// ---------------------------------------------------------------------------
// I-1 — AuthorizedAction is minted only by the gate.
// ---------------------------------------------------------------------------

struct GrantingGate;
impl CostimulationGate for GrantingGate {
    fn evaluate(
        &self,
        _identity: &brokkr_core::crypto::Attestation,
        _chain: &IntentProvenanceChain,
        _action: &Action,
        _now: Timestamp,
    ) -> Result<(), AnergyReason> {
        Ok(())
    }
}

struct DenyingGate;
impl CostimulationGate for DenyingGate {
    fn evaluate(
        &self,
        _identity: &brokkr_core::crypto::Attestation,
        _chain: &IntentProvenanceChain,
        _action: &Action,
        _now: Timestamp,
    ) -> Result<(), AnergyReason> {
        Err(AnergyReason::OutOfScope)
    }
}

#[test]
fn test_i1_authorized_action_minted_only_by_gate() {
    // The sanctioned path yields a grant carrying the action.
    match GrantingGate.authorize(&attestation(), &chain_with_scope(&["write"]), action(), NOW) {
        AuthorizationDecision::Granted(authorized) => {
            assert_eq!(authorized.action(), &action());
        }
        AuthorizationDecision::Anergy { .. } => panic!("expected a grant from the granting gate"),
    }
    // A refusing gate yields anergy — never a forged grant.
    match DenyingGate.authorize(&attestation(), &chain_with_scope(&["write"]), action(), NOW) {
        AuthorizationDecision::Anergy { reason } => assert_eq!(reason, AnergyReason::OutOfScope),
        AuthorizationDecision::Granted(_) => panic!("a denying gate must not grant"),
    }
    // The compile-time half (no public constructor for AuthorizedAction) is proven
    // by the `compile_fail` doctests on `brokkr_core::gate::AuthorizedAction`.
}

#[test]
fn test_i1_authorize_is_sole_construction_path() {
    // The ONLY way to obtain an `AuthorizedAction` is `CostimulationGate::authorize`.
    // Every other path is closed and proven by compile_fail doctests on the type:
    //   - no public constructor          (E0451, private field `action` in a struct literal)
    //   - no access to the minter        (E0624, private fn `mint`)
    //   - no duplication of a grant       (E0599, no `clone` — the type is not Clone)
    // Here we confirm the sanctioned path yields one, and that it is move-only.
    let decision =
        GrantingGate.authorize(&attestation(), &chain_with_scope(&["write"]), action(), NOW);
    let authorized = match decision {
        AuthorizationDecision::Granted(a) => a,
        AuthorizationDecision::Anergy { .. } => panic!("granting gate must yield a grant"),
    };
    // The executor reads the authorized action; the AuthorizedAction itself is a
    // move-only capability (no Clone/Copy), so it cannot be fanned out into several.
    assert_eq!(authorized.action(), &action());

    // A denying gate produces no AuthorizedAction whatsoever — anergy, not a grant.
    assert!(matches!(
        DenyingGate.authorize(&attestation(), &chain_with_scope(&["write"]), action(), NOW),
        AuthorizationDecision::Anergy { .. }
    ));
}

// ---------------------------------------------------------------------------
// I-2 — a Deny has no path to Allow; AcceptedRisk is a distinct variant.
// ---------------------------------------------------------------------------

#[test]
fn test_i2_deny_is_distinct_and_has_no_path_to_allow() {
    let deny = BarrierVerdict::Deny {
        finding: BarrierFinding {
            datum: DatumRef::new("d-1"),
            condition: BarrierCondition::UnauthorizedDestination,
            classification: Classification::Secret,
            reason: "secret to unauthorized destination".into(),
        },
    };
    let allow = BarrierVerdict::Allow;
    let accepted = BarrierVerdict::AcceptedRisk {
        entry: brokkr_core::ids::RiskAcceptanceId::new("ra-1"),
    };

    // AcceptedRisk is not Allow — it is its own variant, keeping the finding visible.
    assert_ne!(accepted, allow);
    assert_ne!(deny, allow);

    // A Deny carries only a finding; it exposes nothing that yields an Allow.
    match &deny {
        BarrierVerdict::Deny { finding } => {
            assert_eq!(finding.classification, Classification::Secret);
        }
        _ => panic!("expected Deny"),
    }
    // The absence of any Deny -> Allow conversion is proven at compile time by the
    // `compile_fail` doctest on `brokkr_core::barrier::BarrierVerdict`.
}

// ---------------------------------------------------------------------------
// I-3 — attenuation rejects broadening; narrowing and invariant-growth are allowed.
// ---------------------------------------------------------------------------

#[test]
fn test_i3_attenuate_rejects_broadening() {
    let chain = chain_with_scope(&["read", "write"]);

    // Narrowing {read, write} -> {read} is a subset: allowed.
    let narrowed = chain.clone().extend(
        attestation(),
        digest(),
        IntentScope::new([Capability::new("read")]),
        vec![],
        InvariantSet::default(),
        dual_sig(),
    );
    assert!(narrowed.is_ok(), "narrowing must be allowed");

    // Broadening {read, write} -> {read, write, exec} is NOT a subset: refused.
    let broadened = chain.extend(
        attestation(),
        digest(),
        IntentScope::new([
            Capability::new("read"),
            Capability::new("write"),
            Capability::new("exec"),
        ]),
        vec![],
        InvariantSet::default(),
        dual_sig(),
    );
    assert_eq!(broadened, Err(AttenuationError::WouldBroaden));
}

#[test]
fn test_i3_invariants_only_accumulate() {
    let chain = chain_with_scope(&["read"]);
    assert!(
        chain
            .current_invariants()
            .contains(&Invariant::new("no-network-egress"))
    );

    let extended = chain
        .extend(
            attestation(),
            digest(),
            IntentScope::new([Capability::new("read")]),
            vec![],
            InvariantSet::new([Invariant::new("read-only-outside-src")]),
            dual_sig(),
        )
        .unwrap();

    let inv = extended.current_invariants();
    // The root invariant survived AND the added one is present: invariants grow.
    assert!(inv.contains(&Invariant::new("no-network-egress")));
    assert!(inv.contains(&Invariant::new("read-only-outside-src")));
    assert_eq!(inv.len(), 2);
}

// ---------------------------------------------------------------------------
// I-4 — a tolerance grant on a Deterministic gate is refused (not a silent no-op).
// ---------------------------------------------------------------------------

struct MockController;
impl ToleranceController for MockController {
    fn grant_heuristic(&self, _grant: ToleranceGrant) -> Result<GrantId, ToleranceError> {
        Ok(GrantId::new("grant-1"))
    }
    fn screen(
        &self,
        _detector: &DetectorSpec,
        _self_set: &SelfSet,
    ) -> Result<ScreenPass, ToleranceError> {
        Ok(ScreenPass {
            version: SelfSetVersion::new("selfset-1"),
            produced_at: Timestamp(10),
        })
    }
    fn host_harm(&self) -> HostHarmReport {
        HostHarmReport {
            rate: 0.0,
            bound: 0.05,
            autoimmunity: false,
            storm: None,
        }
    }
}

fn tolerance_grant() -> ToleranceGrant {
    ToleranceGrant {
        target: DetectorId::new("detector-1"),
        scope: SuppressionScope {
            detail: "one pattern".into(),
        },
        dap: dap(),
        issued: Timestamp(1),
        expiry: Timestamp(2),
        signature: dual_sig(),
    }
}

#[test]
fn test_i4_tolerance_grant_on_deterministic_gate_is_refused() {
    // Deterministic target: refused with an error, never a silent no-op.
    assert_eq!(
        MockController.grant(tolerance_grant(), ResponseClass::Deterministic),
        Err(ToleranceError::NonSuppressibleGate)
    );
    // Heuristic target: the sanctioned path succeeds.
    assert!(
        MockController
            .grant(tolerance_grant(), ResponseClass::Heuristic)
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// I-8 — escalation requires a way down; resolution requires a DAP.
// ---------------------------------------------------------------------------

struct MockResolutionEngine;
impl ResolutionEngine for MockResolutionEngine {
    fn may_resolve(&self, _e: &EscalationId) -> ResolutionVerdict {
        // Above baseline: needs a DAP.
        ResolutionVerdict::Eligible { needs_dap: true }
    }
    fn resolve(&self, _d: ResolutionDecision) -> Result<ReturnedToBaseline, ResolveError> {
        Ok(ReturnedToBaseline {
            escalation: EscalationId::new("esc-1"),
        })
    }
    fn scan_chronic(&self) -> Vec<brokkr_core::resolution::ChronicEscalation> {
        vec![]
    }
}

#[test]
fn test_i8_escalation_needs_resolution_path_and_dap_confirmed_resolution() {
    use brokkr_core::resolution::{BaselinePosture, EscalationType};
    use core::time::Duration;

    // An EscalationType cannot be built without a resolution path and a baseline.
    // (The `None`-for-baseline case is proven by the `compile_fail` doctest.)
    let esc = EscalationType::new(
        EscalationId::new("esc-1"),
        ClearCondition {
            detail: "threat cleared".into(),
        },
        BaselinePosture {
            detail: "nominal".into(),
        },
        Duration::from_secs(60),
        Duration::from_secs(30),
        Duration::from_secs(3600),
    );
    assert_eq!(esc.id, EscalationId::new("esc-1"));

    // Above baseline, may_resolve demands a DAP.
    match MockResolutionEngine.may_resolve(&EscalationId::new("esc-1")) {
        ResolutionVerdict::Eligible { needs_dap } => assert!(needs_dap),
        _ => panic!("expected eligibility needing a DAP"),
    }

    // A ResolutionDecision names an accountable DAP (its type requires one; the
    // `None`-for-dap case is a compile_fail doctest).
    let decision = ResolutionDecision::new(
        EscalationId::new("esc-1"),
        ClearEvidence {
            detail: "sensors nominal for hold window".into(),
        },
        dap(),
        Timestamp(5),
        brokkr_core::ids::Nonce(1),
        Timestamp(1000),
        dual_sig(),
    );
    assert_eq!(decision.dap, dap());
    assert!(MockResolutionEngine.resolve(decision).is_ok());
}

// ---------------------------------------------------------------------------
// I-9 — a RefinedDetector is Heuristic by construction; activation is gated.
// ---------------------------------------------------------------------------

struct MockPipeline {
    fails_tolerance: bool,
}
impl MaturationPipeline for MockPipeline {
    fn generate(&self, _seed: &SeedingIncident) -> Result<RefinedDetector, AdaptError> {
        Ok(RefinedDetector::new(
            DetectorSpecBase {
                id: DetectorId::new("detector-1"),
            },
            DetectorDelta {
                detail: "tighter pattern".into(),
            },
            1,
        ))
    }
    fn select(
        &self,
        _candidate: &RefinedDetector,
        _corpus: &EvaluationCorpus,
    ) -> Result<SelectionPass, AdaptError> {
        Ok(SelectionPass {
            version: CorpusVersion::new("corpus-1"),
            produced_at: Timestamp(20),
        })
    }
    fn activate(
        &self,
        _candidate: RefinedDetector,
        _provenance: DetectorProvenance,
        _now: Timestamp,
    ) -> Result<PriorGeneration, AdaptError> {
        if self.fails_tolerance {
            Err(AdaptError::FailsTolerance)
        } else {
            Err(AdaptError::NeedsApproval)
        }
    }
}

fn provenance() -> DetectorProvenance {
    DetectorProvenance {
        seeding: IncidentId::new("incident-1"),
        corpus_version: CorpusVersion::new("corpus-1"),
        screen_result: ScreenPass {
            version: SelfSetVersion::new("selfset-1"),
            produced_at: Timestamp(10),
        },
        approver: dap(),
        signature: dual_sig(),
    }
}

#[test]
fn test_i9_refined_detector_is_heuristic_and_activation_is_gated() {
    let detector = RefinedDetector::new(
        DetectorSpecBase {
            id: DetectorId::new("detector-1"),
        },
        DetectorDelta {
            detail: "tighter".into(),
        },
        1,
    );
    // A refined detector is Heuristic — always. There is no Deterministic path.
    assert_eq!(detector.response_class(), ResponseClass::Heuristic);

    // Activation that raises host harm is discarded regardless of detection gains.
    assert_eq!(
        MockPipeline {
            fails_tolerance: true
        }
        .activate(detector.clone(), provenance(), Timestamp(30)),
        Err(AdaptError::FailsTolerance)
    );
    // Without DAP approval, activation is refused at Enhanced.
    assert_eq!(
        MockPipeline {
            fails_tolerance: false
        }
        .activate(detector, provenance(), Timestamp(30)),
        Err(AdaptError::NeedsApproval)
    );
}

// ---------------------------------------------------------------------------
// OQGF-P-6.2 — the corpus-validity variants name the EVIDENCE, not the candidate
// (GAP-2026-08-19-001). This is the executable form of the gap's principle: an
// error variant is a claim about what happened, and reporting a candidate defect
// for a corpus-validity failure would be a false claim in the audit record.
// ---------------------------------------------------------------------------

#[test]
fn test_oqgf_p_6_2_corpus_validity_errors_name_the_evidence_not_the_candidate() {
    let substituted = AdaptError::SubstitutedCorpus.to_string();
    let stale = AdaptError::StaleCorpus.to_string();

    // Each names what happened to the CORPUS (the evidence) ...
    assert!(substituted.contains("corpus") && substituted.contains("digest"));
    assert!(stale.contains("corpus") && stale.contains("current version"));
    // ... and says NOTHING about the candidate. A message reworded to imply a
    // candidate defect would fail here — which is the whole point of the gap.
    assert!(!substituted.contains("candidate"));
    assert!(!stale.contains("candidate"));

    // They are distinct from each other (tampering vs drift) and from the
    // candidate-quality variants they must never be conflated with.
    assert_ne!(AdaptError::SubstitutedCorpus, AdaptError::StaleCorpus);
    assert_ne!(substituted, AdaptError::Overfit.to_string());
    assert_ne!(stale, AdaptError::CoverageRegression.to_string());
}

// ---------------------------------------------------------------------------
// I-10 / I-11 — genome and endpoint require their fields (positive side; the
// missing-field cases are compile_fail doctests).
// ---------------------------------------------------------------------------

fn trust_score() -> VendorTrustScore {
    VendorTrustScore {
        attestation_capability: Score(80),
        fips_validation: Score(0),
        breach_history: Score(90),
        jurisdictional_exposure: Score(50),
        data_handling: Score(60),
        // Rev 1.4 M-6 fifth factor. Declared placeholder — measured by HEIMDALL (Phase 8),
        // so it carries a placeholder here, matching the type's PARTIAL status.
        reconciliation_pass_rate: Score(0),
        // Rev 1.31 — the honest encoding of "unmeasured": Score(0) paired with zero
        // observations. `Score(0)` alone would assert a measured 0% pass rate, the worst
        // value obtainable, from no evidence at all.
        evidence: FactorEvidence {
            observations: 0,
            measured: Timestamp(0),
        },
        reviewed: Timestamp(1),
        reviewer: dap(),
        signature: dual_sig(),
    }
}

#[test]
fn test_i11_endpoint_carries_a_required_client_cert() {
    let endpoint = ModelEndpoint::new(
        ModelEndpointId::new("mimir-1"),
        ModelIdentity {
            name: "claude".into(),
            version: "opus-4-8".into(),
            provider: "anthropic".into(),
        },
        ClientCertRef::new("client-cert-fingerprint"),
        TrustAnchor::new("pinned-anchor"),
        NamedGroup::X25519MlKem768,
        Classification::Internal,
        trust_score(),
    );
    // The certificate is present and non-optional. The unconstructable
    // one-sided-TLS case is the compile_fail doctest on ModelEndpoint.
    assert_eq!(endpoint.client_cert.as_str(), "client-cert-fingerprint");
}

// ---------------------------------------------------------------------------
// I-12 — a ClearedContext is minted only by a ContextClearance on a proceed verdict.
// ---------------------------------------------------------------------------

struct AllowClearance;
impl ContextClearance for AllowClearance {
    fn evaluate_context(
        &self,
        _ctx: &Context,
        _dest: &Destination,
        _now: Timestamp,
    ) -> BarrierVerdict {
        BarrierVerdict::Allow
    }
}

struct DenyClearance;
impl ContextClearance for DenyClearance {
    fn evaluate_context(
        &self,
        _ctx: &Context,
        _dest: &Destination,
        _now: Timestamp,
    ) -> BarrierVerdict {
        BarrierVerdict::Deny {
            finding: BarrierFinding {
                datum: DatumRef::new("d-2"),
                condition: BarrierCondition::ChannelStrengthCollapse,
                classification: Classification::Secret,
                reason: "secret to reasoner over insufficient channel".into(),
            },
        }
    }
}

#[test]
fn test_i12_cleared_context_minted_only_via_clearance() {
    let dest = Destination::Reasoner {
        endpoint: ModelEndpointId::new("mimir-1"),
        negotiated: NamedGroup::X25519MlKem768,
    };

    // Allow -> a ClearedContext is minted.
    let cleared = AllowClearance.clear(
        Context {
            payload: "fn main() {}".into(),
            datum: DatumRef::new("ctx-1"),
            classification: Classification::Public,
            personal: None,
            bcr: None,
        },
        &dest,
        NOW,
    );
    assert!(cleared.is_ok());
    assert_eq!(cleared.unwrap().get().payload, "fn main() {}");

    // Deny -> no ClearedContext; the blocking verdict is returned.
    let blocked = DenyClearance.clear(
        Context {
            payload: "SECRET".into(),
            datum: DatumRef::new("ctx-2"),
            classification: Classification::Secret,
            personal: None,
            bcr: None,
        },
        &dest,
        NOW,
    );
    assert!(matches!(blocked, Err(BarrierVerdict::Deny { .. })));
    // That a raw Context cannot reach `Reasoner::propose`, and that ClearedContext
    // has no public constructor, are compile_fail doctests on the reasoner module.
}

// ---------------------------------------------------------------------------
// I-13 — the current time is a call-site parameter, never construction state.
// ---------------------------------------------------------------------------

#[test]
fn test_i13_now_is_a_call_site_parameter() {
    // What core CAN prove: all four freshness-bearing methods — `evaluate`,
    // `authorize`, `evaluate_context`, `clear` — REQUIRE a `Timestamp` argument, so no
    // implementor can be invoked without one supplied at the call site. Here that is
    // exercised from the positive side (the calls compile only because `now` is
    // passed); the compile-time half — that omitting `now` does NOT compile (E0061) —
    // is proven by the `compile_fail,E0061` doctests on `CostimulationGate` and
    // `ContextClearance`.
    let dest = Destination::Reasoner {
        endpoint: ModelEndpointId::new("mimir-1"),
        negotiated: NamedGroup::X25519MlKem768,
    };
    let ctx = Context {
        payload: "fn main() {}".into(),
        datum: DatumRef::new("ctx-i13"),
        classification: Classification::Public,
        personal: None,
        bcr: None,
    };

    // Gate: both methods take `now` last.
    assert!(
        GrantingGate
            .evaluate(
                &attestation(),
                &chain_with_scope(&["write"]),
                &action(),
                NOW
            )
            .is_ok()
    );
    assert!(matches!(
        GrantingGate.authorize(&attestation(), &chain_with_scope(&["write"]), action(), NOW),
        AuthorizationDecision::Granted(_)
    ));
    // Clearance: both methods take `now` last.
    assert_eq!(
        AllowClearance.evaluate_context(&ctx, &dest, NOW),
        BarrierVerdict::Allow
    );
    assert!(AllowClearance.clear(ctx, &dest, NOW).is_ok());

    // What core CANNOT prove, stated plainly: this shows the CALL SITE supplies the
    // time. It does NOT prove an implementor *forwards* `now` to its freshness check
    // rather than ignoring the argument and reading a clock stored in its own struct.
    // No type in core can forbid an implementor from holding a `Timestamp` field. That
    // residual is discharged by per-crate review (SINDRI, BIFRÖST) and the workspace
    // grep for a held clock, not by core's type system — see the revision report.
}

// ---------------------------------------------------------------------------
// §6.10 effective-authorization: a supporting positive test for the BIFRÖST logic
// whose type shapes (Classification, NamedGroup, ChannelStrength) land in core.
// ---------------------------------------------------------------------------

#[test]
fn test_effective_authorization_collapses_over_classical_channel() {
    // Registry "Internal" over a classical handshake collapses to Public (6.10).
    assert_eq!(
        effective_authorization(Classification::Internal, ChannelStrength::Classical),
        Classification::Public
    );
    // Over a PQC-hybrid channel, the registry ceiling stands.
    assert_eq!(
        effective_authorization(Classification::Internal, ChannelStrength::PqcHybrid768),
        Classification::Internal
    );
    assert_eq!(
        effective_authorization(Classification::Secret, ChannelStrength::PqcHybrid1024),
        Classification::Secret
    );
    // Channel strength derives from the negotiated group, and only PQC hybrids carry above Public.
    assert_eq!(
        ChannelStrength::from_group(NamedGroup::X25519),
        ChannelStrength::Classical
    );
    assert!(NamedGroup::X25519MlKem768.is_pqc_hybrid());
    assert_eq!(NamedGroup::X25519MlKem768.code_point(), 4588);
    assert_eq!(NamedGroup::Secp384r1MlKem1024.code_point(), 4589);
}

// ---------------------------------------------------------------------------
// OQGF-P-9.2 — a barrier finding's identity is deterministic, injective over
// (datum, condition), and independent of classification and reason (Rev 1.8).
// ---------------------------------------------------------------------------

fn finding(
    datum: &str,
    condition: BarrierCondition,
    classification: Classification,
    reason: &str,
) -> BarrierFinding {
    BarrierFinding {
        datum: DatumRef::new(datum),
        condition,
        classification,
        reason: reason.into(),
    }
}

#[test]
fn test_oqgf_p_9_2_finding_id_is_deterministic() {
    // A DAP issues an acceptance BEFORE the crossing; the same finding must yield the same
    // id every time, or advance acceptance is impossible.
    let f = finding(
        "dep-42",
        BarrierCondition::SignatureInvalid,
        Classification::Secret,
        "bad sig",
    );
    assert_eq!(f.finding_id(), f.finding_id());
}

#[test]
fn test_oqgf_p_9_2_finding_id_injective_over_datum_and_condition() {
    let f = |d, c| finding(d, c, Classification::Secret, "r");
    // Different datum, same condition -> different ids.
    assert_ne!(
        f("a", BarrierCondition::Expired).finding_id(),
        f("b", BarrierCondition::Expired).finding_id(),
    );
    // Same datum, different condition -> different ids.
    assert_ne!(
        f("a", BarrierCondition::Expired).finding_id(),
        f("a", BarrierCondition::DatumMismatch).finding_id(),
    );
    // Separator-collision robustness: a DatumRef that contains the ':' separator (and even
    // a condition tag's text) must not collide with a shorter datum. The length prefix
    // bounds the datum, so a bare "datum:tag" ambiguity cannot arise.
    assert_ne!(
        f("a", BarrierCondition::Expired).finding_id(),
        f("a:expired", BarrierCondition::Expired).finding_id(),
    );
}

#[test]
fn test_oqgf_p_9_2_finding_id_ignores_classification_and_reason() {
    // `reason` is explanatory and OUTSIDE the match key; `classification` is not part of
    // the id. Two findings differing ONLY in those fields share an id — the property a
    // future refactor is most likely to break silently.
    let a = finding(
        "d",
        BarrierCondition::UnauthorizedDestination,
        Classification::Public,
        "one wording",
    );
    let b = finding(
        "d",
        BarrierCondition::UnauthorizedDestination,
        Classification::Secret,
        "a completely different wording",
    );
    assert_eq!(a.finding_id(), b.finding_id());
}
