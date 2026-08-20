//! SINDRI costimulation-gate tests (Phase 4). Real dual-family signing, real exported
//! public bytes, a real `RegistryResolver`. No crypto mocks. The negatives are
//! load-bearing: each maps to exactly one `AnergyReason`, and the Signal-1 binding test
//! proves identity is not satisfiable by presenting any declared identity alongside
//! someone else's chain.
//!
//! ## On the broadened-chain case (OQGF-M-9)
//!
//! A *broadened* `IntentProvenanceChain` is **unconstructable** through the committed API:
//! `IntentProvenanceChain::extend` refuses a non-subset `emitted_scope` (I-3 / OQGF-M-9)
//! and there is no deserialization path, so SINDRI's `evaluate` cannot be handed a
//! broadened chain — the bad state is unrepresentable, a stronger guarantee than a runtime
//! test. SINDRI's `WouldBroaden -> ChainInvalid` mapping is nonetheless present (for a
//! future reconstructed/deserialized chain) and is exercised where a raw entries slice can
//! be tampered: `brokkr-intent/tests/chain_public.rs::test_verify_chain_public_rejects_tampered_entry`.
//! Here we exercise the *reachable* `ChainInvalid` arms — a bad entry signature and a
//! broken hash link — both of which `extend` (subset-guarded, but not signature- or
//! digest-guarded) lets us build. See the phase report.

use brokkr_core::crypto::{
    Attestation, Digest, DualSignature, HashAlg, Hasher, Signature, SignatureAlg,
};
use brokkr_core::gate::{Action, AnergyReason, AuthorizationDecision, CostimulationGate};
use brokkr_core::genome::PrivilegeClass;
use brokkr_core::ids::{Dap, Nonce, SubjectId, Timestamp, ToolId};
use brokkr_core::intent::{
    Capability, IntentProvenanceChain, IntentScope, Invariant, InvariantSet,
};
use brokkr_crypto::{DualKeyPair, Sha384Hasher};
use brokkr_gate::{GenomeResolver, RegistryResolver, ResolvedInvariant, ResolvedTool, Sindri};
use brokkr_intent::{Skuld, canonical};
use std::collections::HashMap;

// ---- helpers -------------------------------------------------------------------------

fn scope(caps: &[&str]) -> IntentScope {
    IntentScope::new(caps.iter().map(|c| Capability::new(*c)))
}

fn invs(items: &[&str]) -> InvariantSet {
    InvariantSet::new(items.iter().map(|i| Invariant::new(*i)))
}

fn dummy_sig() -> DualSignature {
    // Correct algorithm identifiers (so verify_dual reaches the signature check rather than
    // an AlgorithmMismatch), wrong bytes (so it fails).
    DualSignature {
        lattice: Signature {
            alg: SignatureAlg::MlDsa65,
            bytes: vec![1, 2, 3],
        },
        hash_based: Signature {
            alg: SignatureAlg::SlhDsaShake192s,
            bytes: vec![4, 5, 6],
        },
    }
}

/// An attestation presenting a subject. Its `signatures`/`measurements` are dummies:
/// Signal 1 does not verify the attestation's own signature (Rev 1.3 §6.4), and only the
/// `subject` drives resolution and binding.
fn attn(subject: &SubjectId) -> Attestation {
    Attestation {
        subject: subject.clone(),
        measurements: Digest {
            alg: HashAlg::Sha384,
            bytes: vec![0u8; 48],
        },
        freshness: Nonce(1),
        signatures: dummy_sig(),
    }
}

fn action() -> Action {
    Action {
        tool: ToolId::new("write"),
        detail: "./src/lib.rs".into(),
    }
}

/// A declared identity: a subject and the keypair whose public half is registered for it.
struct Party {
    subject: SubjectId,
    kp: DualKeyPair,
}

fn party(name: &str) -> Party {
    Party {
        subject: SubjectId::new(name),
        kp: DualKeyPair::generate().unwrap(),
    }
}

/// Register a party's public key under its subject in the resolver.
fn declare(reg: RegistryResolver, p: &Party) -> RegistryResolver {
    let (ml, slh) = p.kp.public_key_bytes().unwrap();
    reg.with_root(p.subject.clone(), ml, slh)
}

/// A signed 2-hop chain: root(principal) {read,write,exec} -> hop1 {read,write} ->
/// hop2 {read}, expiry 10_000. Each hop's `hop_identity.subject` matches the keypair that
/// signs its entry, so a resolver declaring all three verifies it.
fn signed_2hop(principal: &Party, hop1: &Party, hop2: &Party) -> IntentProvenanceChain {
    let root = Skuld
        .sign_root(
            principal.subject.clone(),
            Dap::new("Jeremy Rose", "dap-1"),
            scope(&["read", "write", "exec"]),
            invs(&["no-network-egress"]),
            Nonce(42),
            Timestamp(10_000),
            &principal.kp,
        )
        .unwrap();
    let chain = IntentProvenanceChain::new(root);
    let chain = Skuld
        .attenuate_signed(
            chain,
            attn(&hop1.subject),
            scope(&["read", "write"]),
            vec![],
            invs(&["read-only-outside-src"]),
            &hop1.kp,
            Timestamp(100),
        )
        .unwrap();
    Skuld
        .attenuate_signed(
            chain,
            attn(&hop2.subject),
            scope(&["read"]),
            vec![],
            InvariantSet::default(),
            &hop2.kp,
            Timestamp(200),
        )
        .unwrap()
}

/// A registry declaring all three parties of a 2-hop chain.
fn registry_for(principal: &Party, hop1: &Party, hop2: &Party) -> RegistryResolver {
    declare(
        declare(declare(RegistryResolver::new(), principal), hop1),
        hop2,
    )
}

fn assert_anergy(decision: AuthorizationDecision, expected: AnergyReason) {
    match decision {
        AuthorizationDecision::Anergy { reason } => assert_eq!(reason, expected),
        AuthorizationDecision::Granted(_) => {
            panic!("expected Anergy {{ {expected:?} }}, got Granted")
        }
    }
}

// ---- genome-resolver test doubles (conjuncts 3 and 4) --------------------------------

/// Resolves everything permissively: every tool needs no capability and carries no privilege,
/// every invariant forbids nothing. Used to update the Signal-1/Signal-2 tests for the new
/// constructor without letting conjuncts 3/4 change their verdicts — those tests still assert
/// exactly what they asserted before.
struct PermissiveGenome;
impl GenomeResolver for PermissiveGenome {
    fn resolve_tool(&self, _tool: &ToolId) -> Option<ResolvedTool> {
        Some(ResolvedTool {
            required_capabilities: vec![],
            privilege: PrivilegeClass::Unprivileged,
        })
    }
    fn resolve_invariant(&self, _invariant: &Invariant) -> Option<ResolvedInvariant> {
        Some(ResolvedInvariant {
            forbids_capabilities: vec![],
            forbids_privilege: vec![],
        })
    }
}

/// A controlled genome: returns exactly the tools and invariants declared, `None` for anything
/// unknown (an undeclared tool or an invariant with no predicate). This is the test double; it
/// is not the production resolver.
#[derive(Default)]
struct MockGenome {
    tools: HashMap<ToolId, ResolvedTool>,
    invariants: HashMap<Invariant, ResolvedInvariant>,
}
impl MockGenome {
    fn with_tool(mut self, tool: &str, caps: &[&str], privilege: PrivilegeClass) -> Self {
        self.tools.insert(
            ToolId::new(tool),
            ResolvedTool {
                required_capabilities: caps.iter().map(|c| Capability::new(*c)).collect(),
                privilege,
            },
        );
        self
    }
    fn with_invariant(
        mut self,
        invariant: &str,
        forbids_caps: &[&str],
        forbids_priv: &[PrivilegeClass],
    ) -> Self {
        self.invariants.insert(
            Invariant::new(invariant),
            ResolvedInvariant {
                forbids_capabilities: forbids_caps.iter().map(|c| Capability::new(*c)).collect(),
                forbids_privilege: forbids_priv.to_vec(),
            },
        );
        self
    }
}
impl GenomeResolver for MockGenome {
    fn resolve_tool(&self, tool: &ToolId) -> Option<ResolvedTool> {
        self.tools.get(tool).cloned()
    }
    fn resolve_invariant(&self, invariant: &Invariant) -> Option<ResolvedInvariant> {
        self.invariants.get(invariant).cloned()
    }
}

/// A signed root-only chain with an exact current scope and invariant set — the smallest chain
/// that passes Signals 1 and 2 (the identity binds to `principal`) while letting each conjunct-3/4
/// test control precisely what the gate checks.
fn root_chain(principal: &Party, caps: &[&str], invariants: &[&str]) -> IntentProvenanceChain {
    let root = Skuld
        .sign_root(
            principal.subject.clone(),
            Dap::new("Jeremy Rose", "dap-1"),
            scope(caps),
            invs(invariants),
            Nonce(1),
            Timestamp(10_000),
            &principal.kp,
        )
        .unwrap();
    IntentProvenanceChain::new(root)
}

// ---- positive ------------------------------------------------------------------------

#[test]
fn test_oqgf_m_11_valid_costimulation_grants() {
    let (principal, hop1, hop2) = (party("principal"), party("hop-1"), party("hop-2"));
    let chain = signed_2hop(&principal, &hop1, &hop2);
    let sindri = Sindri::new(registry_for(&principal, &hop1, &hop2), PermissiveGenome);

    // Signal 1 identity is the final hop (hop-2), which binds to the chain's last entry.
    let identity = attn(&hop2.subject);
    let act = action();
    match sindri.authorize(&identity, &chain, act.clone(), Timestamp(500)) {
        AuthorizationDecision::Granted(authorized) => {
            assert_eq!(
                authorized.action(),
                &act,
                "the granted action is the one presented"
            );
        }
        AuthorizationDecision::Anergy { reason } => {
            panic!("expected Granted, got Anergy {{ {reason:?} }}");
        }
    }
}

#[test]
fn test_root_only_chain_binds_to_principal() {
    let principal = party("principal");
    let root = Skuld
        .sign_root(
            principal.subject.clone(),
            Dap::new("Jeremy Rose", "dap-1"),
            scope(&["read", "write"]),
            invs(&["no-network-egress"]),
            Nonce(7),
            Timestamp(10_000),
            &principal.kp,
        )
        .unwrap();
    let chain = IntentProvenanceChain::new(root); // no entries
    let sindri = Sindri::new(
        declare(RegistryResolver::new(), &principal),
        PermissiveGenome,
    );

    // Root-only chain: identity binds to root.principal.
    match sindri.authorize(&attn(&principal.subject), &chain, action(), Timestamp(500)) {
        AuthorizationDecision::Granted(_) => {}
        AuthorizationDecision::Anergy { reason } => {
            panic!("expected Granted for a valid root-only chain, got Anergy {{ {reason:?} }}");
        }
    }
}

// ---- negative: each maps to exactly one AnergyReason ---------------------------------

#[test]
fn test_oqgf_m_11_undeclared_identity_is_anergy() {
    let (principal, hop1, hop2) = (party("principal"), party("hop-1"), party("hop-2"));
    let chain = signed_2hop(&principal, &hop1, &hop2);
    let sindri = Sindri::new(registry_for(&principal, &hop1, &hop2), PermissiveGenome);

    // A subject the registry does not declare: resolution returns None.
    assert_anergy(
        sindri.authorize(
            &attn(&SubjectId::new("stranger")),
            &chain,
            action(),
            Timestamp(500),
        ),
        AnergyReason::IdentityUnverified,
    );
}

#[test]
fn test_oqgf_m_11_identity_does_not_bind_is_anergy() {
    // LOAD-BEARING: identity A (hop-1) is declared and resolves, and the chain is valid and
    // ends in B (hop-2, also declared). Signal 1 must still refuse, because A is not the
    // hop the chain proves. Presenting any declared identity alongside someone else's chain
    // does not satisfy Signal 1.
    let (principal, hop1, hop2) = (party("principal"), party("hop-1"), party("hop-2"));
    let chain = signed_2hop(&principal, &hop1, &hop2);
    let sindri = Sindri::new(registry_for(&principal, &hop1, &hop2), PermissiveGenome);

    // hop-1: declared, resolves, but not the final hop the chain proves.
    assert_anergy(
        sindri.authorize(&attn(&hop1.subject), &chain, action(), Timestamp(500)),
        AnergyReason::IdentityUnverified,
    );
}

#[test]
fn test_root_only_chain_wrong_principal_is_anergy() {
    let principal = party("principal");
    let other = party("other"); // declared, but not the root principal
    let root = Skuld
        .sign_root(
            principal.subject.clone(),
            Dap::new("Jeremy Rose", "dap-1"),
            scope(&["read"]),
            InvariantSet::default(),
            Nonce(7),
            Timestamp(10_000),
            &principal.kp,
        )
        .unwrap();
    let chain = IntentProvenanceChain::new(root);
    let reg = declare(declare(RegistryResolver::new(), &principal), &other);
    let sindri = Sindri::new(reg, PermissiveGenome);

    // `other` is declared (resolves) but != root.principal → binding fails.
    assert_anergy(
        sindri.authorize(&attn(&other.subject), &chain, action(), Timestamp(500)),
        AnergyReason::IdentityUnverified,
    );
}

#[test]
fn test_oqgf_m_14_i13_expiry_is_evaluated_against_call_time_not_a_held_clock() {
    // OQGF-M-14 + I-13, and the load-bearing freshness test. The SAME gate instance
    // evaluates the SAME chain twice, with the current time supplied at the CALL: a `now`
    // before expiry grants; a `now` after expiry yields ChainExpired.
    //
    // Why this catches the defect the old test could not: a held clock is fixed at
    // construction, so from one instance it can only ever produce ONE verdict for a given
    // chain. Two different verdicts from one instance is therefore impossible under the
    // pre-I-13 design — this test cannot pass against a stored clock. The old Phase-4 expiry
    // test constructed `Sindri` with `now = 20_000` and evaluated once; because it injected
    // the time at construction and never advanced it, it shared the defect's assumption and
    // could not distinguish a stale held clock from a per-call one. It passed on the held
    // clock precisely because it agreed with it.
    let (principal, hop1, hop2) = (party("principal"), party("hop-1"), party("hop-2"));
    let chain = signed_2hop(&principal, &hop1, &hop2); // expiry 10_000
    let sindri = Sindri::new(registry_for(&principal, &hop1, &hop2), PermissiveGenome);
    let identity = attn(&hop2.subject);

    // now (500) < expiry (10_000): fresh -> Granted.
    match sindri.authorize(&identity, &chain, action(), Timestamp(500)) {
        AuthorizationDecision::Granted(_) => {}
        AuthorizationDecision::Anergy { reason } => {
            panic!("expected Granted before expiry, got Anergy {{ {reason:?} }}");
        }
    }

    // SAME instance, SAME chain, now (20_000) > expiry (10_000): stale -> ChainExpired.
    assert_anergy(
        sindri.authorize(&identity, &chain, action(), Timestamp(20_000)),
        AnergyReason::ChainExpired,
    );
}

#[test]
fn test_tampered_entry_signature_is_anergy() {
    // A ChainInvalid case reachable through the committed API: build hop-1 validly, then
    // push a hop-2 entry via `extend` (subset-guarded, NOT signature-guarded) with the
    // CORRECT hash link but a WRONG signature. Signal 2 -> EntrySignatureInvalid ->
    // ChainInvalid.
    let (principal, hop1, hop2) = (party("principal"), party("hop-1"), party("hop-2"));
    let root = Skuld
        .sign_root(
            principal.subject.clone(),
            Dap::new("Jeremy Rose", "dap-1"),
            scope(&["read", "write"]),
            InvariantSet::default(),
            Nonce(1),
            Timestamp(10_000),
            &principal.kp,
        )
        .unwrap();
    let chain = IntentProvenanceChain::new(root);
    let chain = Skuld
        .attenuate_signed(
            chain,
            attn(&hop1.subject),
            scope(&["read", "write"]),
            vec![],
            InvariantSet::default(),
            &hop1.kp,
            Timestamp(100),
        )
        .unwrap();
    // Correct received_digest for hop-2 = SHA-384 of hop-1's full canonical bytes, so the
    // hash link passes and the SIGNATURE is what fails.
    let last = chain.entries().last().unwrap();
    let received = Sha384Hasher.hash(&canonical::entry_full(last));
    let tampered = chain
        .extend(
            attn(&hop2.subject),
            received,
            scope(&["read"]),
            vec![],
            InvariantSet::default(),
            dummy_sig(), // wrong signature
        )
        .unwrap();

    let sindri = Sindri::new(registry_for(&principal, &hop1, &hop2), PermissiveGenome);
    assert_anergy(
        sindri.authorize(&attn(&hop2.subject), &tampered, action(), Timestamp(500)),
        AnergyReason::ChainInvalid,
    );
}

#[test]
fn test_broken_hash_link_is_anergy() {
    // Another ChainInvalid case: push hop-2 via `extend` with a WRONG received_digest.
    // Signal 2 -> BrokenLink -> ChainInvalid (the hash link is checked before the
    // signature). This also confirms WouldBroaden is not the only route to ChainInvalid.
    let (principal, hop1, hop2) = (party("principal"), party("hop-1"), party("hop-2"));
    let root = Skuld
        .sign_root(
            principal.subject.clone(),
            Dap::new("Jeremy Rose", "dap-1"),
            scope(&["read", "write"]),
            InvariantSet::default(),
            Nonce(1),
            Timestamp(10_000),
            &principal.kp,
        )
        .unwrap();
    let chain = IntentProvenanceChain::new(root);
    let chain = Skuld
        .attenuate_signed(
            chain,
            attn(&hop1.subject),
            scope(&["read", "write"]),
            vec![],
            InvariantSet::default(),
            &hop1.kp,
            Timestamp(100),
        )
        .unwrap();
    let wrong_digest = Digest {
        alg: HashAlg::Sha384,
        bytes: vec![0u8; 48], // not the real prior-state digest
    };
    let broken = chain
        .extend(
            attn(&hop2.subject),
            wrong_digest,
            scope(&["read"]),
            vec![],
            InvariantSet::default(),
            dummy_sig(),
        )
        .unwrap();

    let sindri = Sindri::new(registry_for(&principal, &hop1, &hop2), PermissiveGenome);
    assert_anergy(
        sindri.authorize(&attn(&hop2.subject), &broken, action(), Timestamp(500)),
        AnergyReason::ChainInvalid,
    );
}

#[test]
fn test_unresolvable_hop_is_anergy() {
    // A mid-chain hop (hop-1) is absent from the registry, while the presented identity
    // (hop-2) and the root are declared. Signal 1 passes; Signal 2 fails resolving hop-1.
    let (principal, hop1, hop2) = (party("principal"), party("hop-1"), party("hop-2"));
    let chain = signed_2hop(&principal, &hop1, &hop2);
    // Declare principal and hop-2, but NOT hop-1.
    let reg = declare(declare(RegistryResolver::new(), &principal), &hop2);
    let sindri = Sindri::new(reg, PermissiveGenome);

    assert_anergy(
        sindri.authorize(&attn(&hop2.subject), &chain, action(), Timestamp(500)),
        AnergyReason::IdentityUnverified,
    );
}

#[test]
fn test_i1_sindri_never_mints() {
    // I-1: SINDRI supplies only the verdict; the provided `authorize` is the sole minter.
    // A failure routes to Anergy and yields NO AuthorizedAction. (That `AuthorizedAction`
    // is unforgeable is proven by brokkr-core's compile-fail doctests; that SINDRI contains
    // no construction of it — and no OutOfScope/InvariantViolated path — is proven
    // structurally in the phase report.) Here we prove SINDRI routes a failure to Anergy
    // rather than a grant.
    let (principal, hop1, hop2) = (party("principal"), party("hop-1"), party("hop-2"));
    let chain = signed_2hop(&principal, &hop1, &hop2);
    let sindri = Sindri::new(registry_for(&principal, &hop1, &hop2), PermissiveGenome);

    let decision = sindri.authorize(
        &attn(&SubjectId::new("nobody")),
        &chain,
        action(),
        Timestamp(500),
    );
    assert!(
        matches!(decision, AuthorizationDecision::Anergy { .. }),
        "a failing evaluate must yield Anergy, never a minted grant"
    );
}

// ---- conjunct 3: action in scope -----------------------------------------------------

#[test]
fn tool_not_in_genome_yields_out_of_scope() {
    let principal = party("principal");
    let chain = root_chain(&principal, &["read"], &[]);
    // Empty genome: resolve_tool("write") returns None — an undeclared tool is denied.
    let sindri = Sindri::new(
        declare(RegistryResolver::new(), &principal),
        MockGenome::default(),
    );
    assert_anergy(
        sindri.authorize(&attn(&principal.subject), &chain, action(), Timestamp(500)),
        AnergyReason::OutOfScope,
    );
}

#[test]
fn tool_capability_missing_from_scope() {
    let principal = party("principal");
    let chain = root_chain(&principal, &["read"], &[]);
    // Tool "write" requires the "write" capability; the chain's scope is {read}.
    let genome = MockGenome::default().with_tool("write", &["write"], PrivilegeClass::Unprivileged);
    let sindri = Sindri::new(declare(RegistryResolver::new(), &principal), genome);
    assert_anergy(
        sindri.authorize(&attn(&principal.subject), &chain, action(), Timestamp(500)),
        AnergyReason::OutOfScope,
    );
}

#[test]
fn tool_all_capabilities_in_scope_no_invariants() {
    let principal = party("principal");
    let chain = root_chain(&principal, &["read", "write"], &[]);
    // Tool requires "read" ⊆ {read, write}; no invariants → full grant.
    let genome = MockGenome::default().with_tool("write", &["read"], PrivilegeClass::Unprivileged);
    let sindri = Sindri::new(declare(RegistryResolver::new(), &principal), genome);
    match sindri.authorize(&attn(&principal.subject), &chain, action(), Timestamp(500)) {
        AuthorizationDecision::Granted(_) => {}
        AuthorizationDecision::Anergy { reason } => {
            panic!("expected Granted, got Anergy {{ {reason:?} }}")
        }
    }
}

// ---- conjunct 4: action respects invariants ------------------------------------------

#[test]
fn invariant_with_no_predicate_yields_violated() {
    let principal = party("principal");
    let chain = root_chain(&principal, &["read"], &["x"]);
    // The tool passes conjunct 3, but invariant "x" has no declared predicate → denied.
    let genome = MockGenome::default().with_tool("write", &[], PrivilegeClass::Unprivileged);
    let sindri = Sindri::new(declare(RegistryResolver::new(), &principal), genome);
    assert_anergy(
        sindri.authorize(&attn(&principal.subject), &chain, action(), Timestamp(500)),
        AnergyReason::InvariantViolated,
    );
}

#[test]
fn tool_requires_forbidden_capability() {
    let principal = party("principal");
    // "network" is in scope so conjunct 3 passes and we reach conjunct 4.
    let chain = root_chain(&principal, &["network"], &["no-network"]);
    let genome = MockGenome::default()
        .with_tool("write", &["network"], PrivilegeClass::Unprivileged)
        .with_invariant("no-network", &["network"], &[]);
    let sindri = Sindri::new(declare(RegistryResolver::new(), &principal), genome);
    assert_anergy(
        sindri.authorize(&attn(&principal.subject), &chain, action(), Timestamp(500)),
        AnergyReason::InvariantViolated,
    );
}

#[test]
fn tool_has_forbidden_privilege() {
    let principal = party("principal");
    let chain = root_chain(&principal, &["read"], &["no-privileged"]);
    let genome = MockGenome::default()
        .with_tool("write", &[], PrivilegeClass::Privileged)
        .with_invariant("no-privileged", &[], &[PrivilegeClass::Privileged]);
    let sindri = Sindri::new(declare(RegistryResolver::new(), &principal), genome);
    assert_anergy(
        sindri.authorize(&attn(&principal.subject), &chain, action(), Timestamp(500)),
        AnergyReason::InvariantViolated,
    );
}

#[test]
fn tool_passes_all_invariants() {
    let principal = party("principal");
    let chain = root_chain(&principal, &["read"], &["no-network"]);
    let genome = MockGenome::default()
        .with_tool("write", &["read"], PrivilegeClass::Unprivileged)
        .with_invariant("no-network", &["network"], &[]);
    let sindri = Sindri::new(declare(RegistryResolver::new(), &principal), genome);
    match sindri.authorize(&attn(&principal.subject), &chain, action(), Timestamp(500)) {
        AuthorizationDecision::Granted(_) => {}
        AuthorizationDecision::Anergy { reason } => {
            panic!("expected Granted, got Anergy {{ {reason:?} }}")
        }
    }
}

#[test]
fn multiple_invariants_all_pass() {
    let principal = party("principal");
    let chain = root_chain(&principal, &["read"], &["no-network", "no-exec-outside"]);
    let genome = MockGenome::default()
        .with_tool("write", &["read"], PrivilegeClass::Unprivileged)
        .with_invariant("no-network", &["network"], &[])
        .with_invariant("no-exec-outside", &["exec-root"], &[]);
    let sindri = Sindri::new(declare(RegistryResolver::new(), &principal), genome);
    match sindri.authorize(&attn(&principal.subject), &chain, action(), Timestamp(500)) {
        AuthorizationDecision::Granted(_) => {}
        AuthorizationDecision::Anergy { reason } => {
            panic!("expected Granted, got Anergy {{ {reason:?} }}")
        }
    }
}

#[test]
fn multiple_invariants_second_fails() {
    let principal = party("principal");
    let chain = root_chain(&principal, &["read"], &["no-network", "no-read"]);
    let genome = MockGenome::default()
        .with_tool("write", &["read"], PrivilegeClass::Unprivileged)
        // Passes: the tool needs "read", not "network".
        .with_invariant("no-network", &["network"], &[])
        // Fails: the tool needs "read".
        .with_invariant("no-read", &["read"], &[]);
    let sindri = Sindri::new(declare(RegistryResolver::new(), &principal), genome);
    assert_anergy(
        sindri.authorize(&attn(&principal.subject), &chain, action(), Timestamp(500)),
        AnergyReason::InvariantViolated,
    );
}
