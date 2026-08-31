//! AMD-011 — Capability Envelope + Sub-agent validation (OQGF-P-12.1/.2/.6).
//! Core-crate logic tests: tier determination and the child-subset rule.

use brokkr_core::capability::{
    CapabilityEnvelope, CapabilityProperty, ConformanceTier, EnvelopeError, SubAgentError,
    SubAgentRecord,
};
use brokkr_core::crypto::{DualSignature, Signature, SignatureAlg};
use brokkr_core::ids::{Dap, Nonce, SubjectId, Timestamp};
use brokkr_core::intent::{IntentProvenanceChain, IntentScope, InvariantSet, RootIntent};

fn sig() -> DualSignature {
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

/// Build an envelope with the given properties and tiers.
fn envelope(
    properties: Vec<CapabilityProperty>,
    capability_tier: ConformanceTier,
    data_tier: ConformanceTier,
    governing_tier: ConformanceTier,
) -> CapabilityEnvelope {
    CapabilityEnvelope {
        system_id: "sys".to_string(),
        properties,
        egress_manifest: None,
        capability_tier,
        data_tier,
        governing_tier,
        attested_at: Timestamp(1),
        signature: sig(),
    }
}

// ---- 1..4: Capability Envelope validation ----

/// 1 — a well-formed envelope (governing == max(cap, data)) validates.
#[test]
fn envelope_with_correct_tier_validates() {
    let e = envelope(
        vec![CapabilityProperty::CodeExecution],
        ConformanceTier::Enhanced,
        ConformanceTier::Baseline,
        ConformanceTier::Enhanced, // max(Enhanced, Baseline)
    );
    assert_eq!(e.validate(), Ok(()));
}

/// 2 — governing_tier that is not max(cap, data) fails (P-12.1).
#[test]
fn envelope_tier_mismatch_fails() {
    let e = envelope(
        vec![CapabilityProperty::CodeExecution],
        ConformanceTier::Enhanced,
        ConformanceTier::Baseline,
        ConformanceTier::Baseline, // WRONG: should be Enhanced
    );
    assert_eq!(e.validate(), Err(EnvelopeError::TierMismatch));
}

/// 3 — ExternalEffect floors capability_tier at Enhanced (P-12.2).
#[test]
fn external_effect_requires_enhanced() {
    let e = envelope(
        vec![CapabilityProperty::ExternalEffect {
            targets: vec!["filesystem".to_string()],
        }],
        ConformanceTier::Baseline, // too low for ExternalEffect
        ConformanceTier::Baseline,
        ConformanceTier::Baseline, // max is Baseline, so no TierMismatch — the floor is what fails
    );
    assert_eq!(e.validate(), Err(EnvelopeError::TierTooLow));
}

/// 4 — CredentialAccess floors capability_tier at Enhanced (P-12.2).
#[test]
fn credential_access_requires_enhanced() {
    let e = envelope(
        vec![CapabilityProperty::CredentialAccess {
            scope: "vault".to_string(),
        }],
        ConformanceTier::Baseline,
        ConformanceTier::Baseline,
        ConformanceTier::Baseline,
    );
    assert_eq!(e.validate(), Err(EnvelopeError::TierTooLow));
}

// ---- 15..16: Sub-agent validation ----

fn placeholder_chain() -> IntentProvenanceChain {
    // A chain is required to construct a SubAgentRecord; validate() never reads it, so a
    // placeholder-signed root suffices (no crypto needed for the subset check).
    let root = RootIntent {
        principal: SubjectId::new("parent"),
        dap: Dap::new("Jeremy Rose", "jr"),
        scope: IntentScope::new([]),
        invariants: InvariantSet::new([]),
        nonce: Nonce(1),
        expiry: Timestamp(9_000_000),
        signature: sig(),
    };
    IntentProvenanceChain::new(root)
}

fn subagent(child_props: Vec<CapabilityProperty>) -> SubAgentRecord {
    SubAgentRecord {
        parent_id: "parent".to_string(),
        child_id: "child".to_string(),
        child_envelope: envelope(
            child_props,
            ConformanceTier::Enhanced,
            ConformanceTier::Baseline,
            ConformanceTier::Enhanced,
        ),
        intent_chain: placeholder_chain(),
        created_at: Timestamp(1),
    }
}

/// 15 — a child whose capabilities are a subset of the parent's validates (P-12.6).
#[test]
fn child_subset_of_parent_validates() {
    let parent = envelope(
        vec![
            CapabilityProperty::CodeExecution,
            CapabilityProperty::ExternalEffect {
                targets: vec!["filesystem".to_string()],
            },
        ],
        ConformanceTier::Enhanced,
        ConformanceTier::Baseline,
        ConformanceTier::Enhanced,
    );
    // Child holds only CodeExecution — a strict subset.
    let child = subagent(vec![CapabilityProperty::CodeExecution]);
    assert_eq!(child.validate(&parent), Ok(()));
}

/// 16 — a child that declares a capability the parent lacks fails (P-12.6).
#[test]
fn child_exceeds_parent_fails() {
    let parent = envelope(
        vec![CapabilityProperty::CodeExecution],
        ConformanceTier::Enhanced,
        ConformanceTier::Baseline,
        ConformanceTier::Enhanced,
    );
    // Child claims CredentialAccess, which the parent does not hold.
    let child = subagent(vec![
        CapabilityProperty::CodeExecution,
        CapabilityProperty::CredentialAccess {
            scope: "vault".to_string(),
        },
    ]);
    assert_eq!(
        child.validate(&parent),
        Err(SubAgentError::CapabilityExceedsParent)
    );
}
