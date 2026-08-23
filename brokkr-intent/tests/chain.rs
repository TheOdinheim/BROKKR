//! SKULD chain tests. Real dual-family signing/hashing via brokkr-crypto (no mocks).
//! Negative tests are load-bearing: they prove OQGF-M-9 broadening is computationally
//! infeasible (not merely detectable), OQGF-M-10 invariants only accumulate, and
//! OQGF-M-14 an expired chain authorizes nothing.

use brokkr_core::crypto::{Attestation, Digest, DualSignature, HashAlg, Signature, SignatureAlg};
use brokkr_core::ids::{Dap, Nonce, SubjectId, Timestamp};
use brokkr_core::intent::{
    AttenuationError, Capability, Caveat, IntentChainEntry, IntentProvenanceChain, IntentScope,
    Invariant, InvariantSet, RootIntent,
};
use brokkr_crypto::DualKeyPair;
use brokkr_intent::{IntentError, Skuld, canonical};

fn scope(caps: &[&str]) -> IntentScope {
    IntentScope::new(caps.iter().map(|c| Capability::new(*c)))
}

fn invs(items: &[&str]) -> InvariantSet {
    InvariantSet::new(items.iter().map(|i| Invariant::new(*i)))
}

fn dummy_sig() -> DualSignature {
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

fn attestation(subject: &str) -> Attestation {
    Attestation {
        subject: SubjectId::new(subject),
        measurements: Digest {
            alg: HashAlg::Sha384,
            bytes: vec![0u8; 48],
        },
        freshness: Nonce(1),
        signatures: dummy_sig(),
    }
}

/// A signed root over scope {read, write, exec}, invariants {no-network-egress},
/// expiry 10_000. Returns (skuld, root, root_keypair).
fn signed_root() -> (Skuld, RootIntent, DualKeyPair) {
    let skuld = Skuld;
    let mut kp = DualKeyPair::generate().unwrap();
    let root = skuld
        .sign_root(
            SubjectId::new("principal"),
            Dap::new("Jeremy Rose", "dap-1"),
            scope(&["read", "write", "exec"]),
            invs(&["no-network-egress"]),
            Nonce(42),
            Timestamp(10_000),
            &mut kp,
        )
        .unwrap();
    (skuld, root, kp)
}

// ---------------------------------------------------------------------------
// Positive
// ---------------------------------------------------------------------------

#[test]
fn test_root_intent_signs_and_verifies() {
    let (skuld, root, kp) = signed_root();
    // The real DualKeyPair round-trips: both families verify.
    assert!(skuld.verify_root(&root, &kp).is_ok());
    // A different keypair does not verify it.
    let other = DualKeyPair::generate().unwrap();
    assert!(skuld.verify_root(&root, &other).is_err());
}

#[test]
fn test_canonical_serialization_deterministic_and_unambiguous() {
    let (_skuld, root, _kp) = signed_root();
    // Deterministic: same struct -> identical bytes, every call.
    assert_eq!(
        canonical::root_signed_content(&root),
        canonical::root_signed_content(&root)
    );

    // Unambiguous: length-prefixing prevents delimiter collisions. Two scopes whose
    // concatenations would collide without length prefixes ({"a","bc"} vs {"ab","c"})
    // must encode to DISTINCT bytes.
    let mk = |caps: &[&str]| RootIntent {
        principal: SubjectId::new("p"),
        dap: Dap::new("n", "i"),
        scope: scope(caps),
        invariants: InvariantSet::default(),
        nonce: Nonce(1),
        expiry: Timestamp(1),
        signature: dummy_sig(),
    };
    let a = mk(&["a", "bc"]);
    let b = mk(&["ab", "c"]);
    assert_ne!(
        canonical::root_signed_content(&a),
        canonical::root_signed_content(&b),
        "length-prefixing must make distinct scopes encode distinctly"
    );
}

#[test]
fn test_multi_hop_chain_attenuates_and_verifies() {
    let (skuld, root, root_kp) = signed_root();

    let chain = IntentProvenanceChain::new(root.clone());
    let mut hop1_kp = DualKeyPair::generate().unwrap();
    let chain = skuld
        .attenuate_signed(
            chain,
            attestation("hop-1"),
            scope(&["read", "write"]),
            vec![],
            invs(&["read-only-outside-src"]),
            &mut hop1_kp,
            Timestamp(100),
        )
        .unwrap();

    let mut hop2_kp = DualKeyPair::generate().unwrap();
    let chain = skuld
        .attenuate_signed(
            chain,
            attestation("hop-2"),
            scope(&["read"]),
            vec![Caveat("no-delete".into())],
            invs(&["no-secret-egress"]),
            &mut hop2_kp,
            Timestamp(200),
        )
        .unwrap();

    // Scope narrowed {read,write,exec} -> {read,write} -> {read}.
    assert_eq!(chain.current_scope().capabilities().len(), 1);

    // Invariants accumulated: root + hop1 + hop2 = 3.
    let inv = chain.current_invariants();
    assert_eq!(inv.len(), 3);
    assert!(inv.contains(&Invariant::new("no-network-egress")));
    assert!(inv.contains(&Invariant::new("read-only-outside-src")));
    assert!(inv.contains(&Invariant::new("no-secret-egress")));

    // Full chain verification: digests link, both signatures verify at every hop.
    let entries = chain.entries().to_vec();
    assert!(
        skuld
            .verify_chain(
                chain.root(),
                &entries,
                &root_kp,
                &[&hop1_kp, &hop2_kp],
                Timestamp(500)
            )
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// Negative (load-bearing)
// ---------------------------------------------------------------------------

#[test]
fn test_i3_attenuate_rejects_broadening() {
    let (skuld, root, _kp) = signed_root();
    let chain = IntentProvenanceChain::new(root);
    let mut hop_kp = DualKeyPair::generate().unwrap();
    // Emit {read,write,exec,admin} — not a subset of {read,write,exec}.
    let res = skuld.attenuate_signed(
        chain,
        attestation("hop-1"),
        scope(&["read", "write", "exec", "admin"]),
        vec![],
        InvariantSet::default(),
        &mut hop_kp,
        Timestamp(100),
    );
    assert_eq!(
        res.unwrap_err(),
        IntentError::Attenuation(AttenuationError::WouldBroaden)
    );
}

#[test]
fn test_oqgf_m_9_broadened_entry_fails_verification() {
    // A validly-signed 2-hop chain, then an attacker edits the reconstructed form to
    // BROADEN hop-1's scope (bypassing extend). Verification must fail.
    let (skuld, root, root_kp) = signed_root();
    let chain = IntentProvenanceChain::new(root);
    let mut hop1_kp = DualKeyPair::generate().unwrap();
    let chain = skuld
        .attenuate_signed(
            chain,
            attestation("hop-1"),
            scope(&["read", "write"]),
            vec![],
            InvariantSet::default(),
            &mut hop1_kp,
            Timestamp(100),
        )
        .unwrap();
    let mut hop2_kp = DualKeyPair::generate().unwrap();
    let chain = skuld
        .attenuate_signed(
            chain,
            attestation("hop-2"),
            scope(&["read"]),
            vec![],
            InvariantSet::default(),
            &mut hop2_kp,
            Timestamp(200),
        )
        .unwrap();

    let mut entries = chain.entries().to_vec();
    // Tamper: broaden hop-1 to include "admin" (not in the root scope).
    entries[0].emitted_scope = scope(&["read", "write", "admin"]);

    let res = skuld.verify_chain(
        chain.root(),
        &entries,
        &root_kp,
        &[&hop1_kp, &hop2_kp],
        Timestamp(500),
    );
    assert!(
        res.is_err(),
        "a broadened chain must not verify — forging one would require forging a DualSignature"
    );
}

#[test]
fn test_oqgf_m_9_scope_tamper_within_subset_fails_signature() {
    // The stronger proof: even a tampered scope that STILL satisfies the subset check
    // (and does not break the hash link) fails, because the signature commits to the
    // exact scope. The subset check is redundant defense; the signature is what makes
    // broadening infeasible.
    let (skuld, root, root_kp) = signed_root();
    let chain = IntentProvenanceChain::new(root);
    let mut hop_kp = DualKeyPair::generate().unwrap();
    let chain = skuld
        .attenuate_signed(
            chain,
            attestation("h"),
            scope(&["read", "write"]),
            vec![],
            InvariantSet::default(),
            &mut hop_kp,
            Timestamp(100),
        )
        .unwrap();

    let mut entries = chain.entries().to_vec();
    // Swap {read,write} -> {read}: still a subset of the root {read,write,exec}, and the
    // hash link (over the root) is unchanged — so the failure is purely the signature.
    entries[0].emitted_scope = scope(&["read"]);

    let res = skuld.verify_chain(chain.root(), &entries, &root_kp, &[&hop_kp], Timestamp(500));
    assert_eq!(
        res.unwrap_err(),
        IntentError::EntrySignatureInvalid { hop: 0 }
    );
}

#[test]
fn test_oqgf_m_10_invariants_accumulate() {
    // Invariants only grow: a hop that adds nothing still keeps every prior invariant,
    // and there is no API that removes or weakens one.
    let (skuld, root, _kp) = signed_root(); // root invariants {no-network-egress}
    let chain = IntentProvenanceChain::new(root);
    let mut kp1 = DualKeyPair::generate().unwrap();
    let chain = skuld
        .attenuate_signed(
            chain,
            attestation("h1"),
            scope(&["read", "write"]),
            vec![],
            invs(&["inv-a"]),
            &mut kp1,
            Timestamp(1),
        )
        .unwrap();
    let mut kp2 = DualKeyPair::generate().unwrap();
    let chain = skuld
        .attenuate_signed(
            chain,
            attestation("h2"),
            scope(&["read"]),
            vec![],
            InvariantSet::default(), // adds nothing
            &mut kp2,
            Timestamp(2),
        )
        .unwrap();

    let inv = chain.current_invariants();
    assert!(inv.contains(&Invariant::new("no-network-egress"))); // root's survives
    assert!(inv.contains(&Invariant::new("inv-a"))); // hop-1's survives
    assert_eq!(inv.len(), 2); // hop-2 removed nothing
}

#[test]
fn test_oqgf_m_14_expired_chain_is_refused() {
    let (skuld, root, root_kp) = signed_root(); // expiry 10_000

    // (a) An expired chain authorizes no new hop.
    let chain = IntentProvenanceChain::new(root.clone());
    let mut kp = DualKeyPair::generate().unwrap();
    let res = skuld.attenuate_signed(
        chain,
        attestation("h"),
        scope(&["read"]),
        vec![],
        InvariantSet::default(),
        &mut kp,
        Timestamp(20_000), // now > expiry
    );
    assert_eq!(
        res.unwrap_err(),
        IntentError::Attenuation(AttenuationError::Expired)
    );

    // (b) An expired chain does not pass verification (checked before the walk).
    let chain2 = IntentProvenanceChain::new(root);
    let entries: Vec<IntentChainEntry> = vec![];
    assert_eq!(
        skuld
            .verify_chain(chain2.root(), &entries, &root_kp, &[], Timestamp(20_000))
            .unwrap_err(),
        IntentError::Attenuation(AttenuationError::Expired)
    );
    // (c) Fresh (now <= expiry) verifies.
    assert!(
        skuld
            .verify_chain(chain2.root(), &entries, &root_kp, &[], Timestamp(5_000))
            .is_ok()
    );
}
