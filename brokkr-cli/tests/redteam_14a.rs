//! Phase 14A — White-box red team, high noise.
//!
//! The attacker has full source access and targets the **structural** guarantees the architecture
//! claims the type system and module privacy enforce. Most of these attacks are `compile_fail`
//! doctests co-located on the types they target (grep `Red-team 14A` in `brokkr-core::gate`,
//! `brokkr-core::reasoner`, `brokkr-tools`, and the F-4 doctests in `brokkr-crypto::sign`). This
//! file holds the **runtime** white-box attacks — the ones whose defense is behavioral or an API
//! boundary rather than a compile error:
//!
//! - **2.3** an always-granting gate is a valid (dangerous) *configuration* — the type system
//!   prevents *forging* a token, not *misconfiguring* the gate. Documented, asserted.
//! - **3.1–3.3** SAGA integrity: `records()` returns a clone (mutating it can't touch the store),
//!   `append` auto-assigns the sequence (the caller cannot choose), and a tampered or truncated
//!   chain fed back through `from_records` is caught by `verify_chain`.
//! - **5.1** dependency direction (I-5/I-6) — captured in the report from `cargo tree`; a couple of
//!   compile-time facts are asserted here.
//!
//! Findings: `reports/REDTEAM-14A-2026-08-23-R1.md`. Hermetic; real dual-family PQC signing.

use brokkr_audit::{AuditEvent, ChainStatus, CryptoGeneration, Saga};
use brokkr_core::crypto::{Attestation, Digest, Hasher};
use brokkr_core::gate::{Action, AnergyReason, AuthorizationDecision, CostimulationGate};
use brokkr_core::ids::{Dap, Nonce, SubjectId, Timestamp, ToolId};
use brokkr_core::intent::{IntentProvenanceChain, IntentScope, InvariantSet, RootIntent};
use brokkr_crypto::{DualKeyPair, Sha384Hasher};

fn dap() -> Dap {
    Dap::new("Jeremy Rose", "jr")
}

// ======================================================================================
// 2.3 — an always-granting gate is a valid (dangerous) CONFIGURATION, not a forgery.
// ======================================================================================

/// A gate whose `evaluate` always says yes. This is *allowed* — the type system prevents an
/// implementor from **forging** an `AuthorizedAction` (see the `compile_fail` doctests on
/// `AuthorizedAction`), but it cannot prevent an operator from **choosing** a permissive gate. The
/// token it mints via the provided `authorize` is genuine. The protection against a bad gate is
/// operational (the gate is a signed, DAP-owned configuration decision), not type-level.
struct AlwaysGrant;
impl CostimulationGate for AlwaysGrant {
    fn evaluate(
        &self,
        _identity: &Attestation,
        _chain: &IntentProvenanceChain,
        _action: &Action,
        _now: Timestamp,
    ) -> Result<(), AnergyReason> {
        Ok(())
    }
    // NOTE: `authorize` is NOT overridden — it cannot usefully be (a doctest proves an override
    // cannot mint). This impl only controls the *verdict*, never the *minting*.
}

fn dummy_sig() -> brokkr_core::crypto::DualSignature {
    use brokkr_core::crypto::{DualSignature, Signature, SignatureAlg};
    DualSignature {
        lattice: Signature {
            alg: SignatureAlg::MlDsa65,
            bytes: Vec::new(),
        },
        hash_based: Signature {
            alg: SignatureAlg::SlhDsaShake192s,
            bytes: Vec::new(),
        },
    }
}

fn dummy_chain() -> IntentProvenanceChain {
    IntentProvenanceChain::new(RootIntent {
        principal: SubjectId::new("p"),
        dap: dap(),
        scope: IntentScope::empty(),
        invariants: InvariantSet::new([]),
        nonce: Nonce(1),
        expiry: Timestamp(9_000_000),
        signature: dummy_sig(),
    })
}

fn dummy_attestation() -> Attestation {
    Attestation {
        subject: SubjectId::new("p"),
        measurements: Sha384Hasher.hash(b"m"),
        freshness: Nonce(1),
        signatures: dummy_sig(),
    }
}

/// 2.3 — an always-granting gate mints a genuine `AuthorizedAction`. This confirms the boundary:
/// **the type system prevents forging, not misconfiguration.** (The `evaluate` here does no
/// verification, so the dummy chain/attestation are never checked — that is the point of a
/// misconfigured gate.)
#[test]
fn attack_2_3_always_granting_gate_is_a_valid_configuration() {
    let gate = AlwaysGrant;
    let action = Action {
        tool: ToolId::new("write_file"),
        detail: "/tmp/x".to_string(),
    };
    match gate.authorize(
        &dummy_attestation(),
        &dummy_chain(),
        action,
        Timestamp(1000),
    ) {
        AuthorizationDecision::Granted(a) => {
            assert_eq!(a.action().tool.as_str(), "write_file");
        }
        AuthorizationDecision::Anergy { .. } => {
            panic!("an always-granting gate should grant")
        }
    }
    // The mint happened through the provided `authorize`, the ONLY path to a token. The defense
    // against this dangerous config is that the gate is a DAP-owned decision, not a type guarantee.
}

// ======================================================================================
// 3. SAGA integrity — API-boundary and hash-chain defenses.
// ======================================================================================

fn genesis() -> Digest {
    Sha384Hasher.hash(b"redteam-14a-genesis")
}

/// Build a Saga and append `n` correction events (the simplest event variant). Returns the Saga.
fn saga_with(n: u64) -> Saga {
    let signer = DualKeyPair::generate().expect("signer");
    let saga = Saga::new(signer, CryptoGeneration(1), genesis(), None).expect("saga");
    for i in 0..n {
        saga.append(
            AuditEvent::Correction {
                corrects: i,
                detail: format!("note {i}"),
            },
            dap(),
            Timestamp(1000 + i),
        )
        .expect("append");
    }
    saga
}

/// 3.1 — `records()` returns an owned clone. Mutating that clone cannot touch SAGA's internal
/// store, so the chain remains intact. (There is no `&mut` accessor to an individual record.)
#[test]
fn attack_3_1_records_returns_a_clone_store_is_immutable() {
    let saga = saga_with(3);
    let mut copy = saga.records();
    assert_eq!(copy.len(), 3);
    // Tamper with the returned copy.
    if let Some(r) = copy.get_mut(1) {
        r.event = AuditEvent::Correction {
            corrects: 999,
            detail: "TAMPERED".to_string(),
        };
    }
    // The internal store is unaffected — the chain still verifies intact.
    assert!(
        matches!(saga.verify_chain(), ChainStatus::Intact),
        "mutating the returned Vec must not affect the store"
    );
}

/// 3.1b — a chain that HAS been tampered (rebuilt via `from_records` with a mutated event) is
/// caught by `verify_chain`, which returns `Broken` with the OQGF-A.6.1 chain-break signal.
#[test]
fn attack_3_1b_tampered_chain_is_detected() {
    let saga = saga_with(3);
    let signer_pub = saga.signer_public().expect("pub");
    let mut records = saga.records();
    // Tamper with record 1's event (changes its signed content → breaks the next link + signature).
    if let Some(r) = records.get_mut(1) {
        r.event = AuditEvent::Correction {
            corrects: 999,
            detail: "TAMPERED".to_string(),
        };
    }
    // Rebuild a store from the tampered records and verify.
    let signer = DualKeyPair::generate().expect("stand-in");
    let tampered = Saga::from_records(
        signer,
        CryptoGeneration(1),
        genesis(),
        None,
        records,
        vec![(CryptoGeneration(1), signer_pub)],
    );
    assert!(
        matches!(tampered.verify_chain(), ChainStatus::Broken(_)),
        "a tampered record must break the chain"
    );
}

/// 3.2 — `append` auto-assigns the sequence number; the caller cannot choose it. Consecutive
/// appends return 0, 1, 2, …
#[test]
fn attack_3_2_append_assigns_sequence_caller_cannot_choose() {
    let signer = DualKeyPair::generate().expect("signer");
    let saga = Saga::new(signer, CryptoGeneration(1), genesis(), None).expect("saga");
    let s0 = saga
        .append(
            AuditEvent::Correction {
                corrects: 0,
                detail: "a".into(),
            },
            dap(),
            Timestamp(1),
        )
        .unwrap();
    let s1 = saga
        .append(
            AuditEvent::Correction {
                corrects: 0,
                detail: "b".into(),
            },
            dap(),
            Timestamp(2),
        )
        .unwrap();
    assert_eq!((s0, s1), (0, 1), "sequence is auto-assigned, monotonic");
    // The `append` signature `(event, dap, at)` carries no seq parameter — the caller has no way to
    // insert out of order or overwrite an existing sequence.
}

/// 3.3 — deleting a record from the chain is detected: a truncated record set (missing the middle
/// record) fed through `from_records` fails `verify_chain`, because record 2's `prev` no longer
/// matches its (now-removed) predecessor.
#[test]
fn attack_3_3_deleted_record_is_detected() {
    let saga = saga_with(3);
    let signer_pub = saga.signer_public().expect("pub");
    let mut records = saga.records();
    records.remove(1); // delete the middle record
    let signer = DualKeyPair::generate().expect("stand-in");
    let gapped = Saga::from_records(
        signer,
        CryptoGeneration(1),
        genesis(),
        None,
        records,
        vec![(CryptoGeneration(1), signer_pub)],
    );
    assert!(
        matches!(gapped.verify_chain(), ChainStatus::Broken(_)),
        "a deleted record must break the chain"
    );
}

// ======================================================================================
// 5.1 — dependency direction, the compile-time slice.
// ======================================================================================

/// 5.1 — a compile-time witness that `brokkr-cli` (this crate, the composition root) *can* name
/// types from both the untrusted side (`brokkr_reasoner`, `brokkr_tools`) and the governance side.
/// The governance-side crates cannot name the untrusted ones — that is enforced by Cargo's
/// dependency graph (captured in the report via `cargo tree`), not by anything expressible here.
/// This test merely confirms the composition root links them all without a cycle.
#[test]
fn attack_5_1_composition_root_links_all_sides() {
    // brokkr-cli (this crate, the composition root) can name a type from the untrusted side
    // (`brokkr_reasoner`) AND the governance side (`brokkr_gate`) in the same file. The reverse —
    // a governance crate naming `brokkr_reasoner` — is forbidden by the Cargo dependency graph,
    // captured in the report from `cargo tree`. This test is only the witness that the root links
    // both without a cycle.
    fn _untrusted(_r: &dyn brokkr_reasoner::RegisteredEndpoints) {}
    fn _governance(_g: &brokkr_gate::resolver::RegistryResolver) {}
    let _ = (_untrusted as fn(_), _governance as fn(_));
}
