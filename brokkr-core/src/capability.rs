//! AMD-011 — Capability-Triggered Assurance (OQGF-P-12.1 … P-12.8).
//!
//! The **Capability Envelope**: an inventory of what the composed system can do,
//! reach, change, create, or autonomously pursue — sibling to the AIBOM (which
//! inventories what the model *is*). The governing conformance tier is driven by
//! the **maximum** of the capability-triggered tier and the data-triggered tier
//! (P-12.1), and specific properties (external effect, credential access,
//! sub-agent creation) floor the system at Enhanced (P-12.2).
//!
//! This module places the **type surface and its intrinsic validation** (Option C
//! core half). The orchestrator wiring — deterministic default-deny egress
//! (P-12.4), independent termination (P-12.5), and trajectory reconstruction with
//! evidence provenance (P-12.8) — lives in `brokkr-cli`, which consumes these types.

use alloc::string::String;
use alloc::vec::Vec;

use crate::crypto::{DualSignature, Signature, SignatureAlg};
use crate::gate::Action;
use crate::ids::{Timestamp, ToolId};
use crate::intent::IntentProvenanceChain;

/// A conformance tier (OQGF §A.0.6 / P-12.1). Ordered so the **governing tier**
/// can be computed as the maximum of the capability- and data-triggered tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConformanceTier {
    Baseline,
    Enhanced,
    HighAssurance,
}

/// A discrete capability of the composed system (OQGF-P-12.2) — the
/// "virulence-factor inventory". Each property present raises the
/// capability-triggered tier floor; `ExternalEffect`, `CredentialAccess`, and
/// `SubAgentCreation` each individually floor the system at Enhanced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapabilityProperty {
    CodeExecution,
    NetworkAccess { declared_destinations: Vec<String> },
    CredentialAccess { scope: String },
    ExternalEffect { targets: Vec<String> },
    SubAgentCreation,
    Persistence,
    IdentityCreation,
    CrossRunMemory,
    InterAgentCommunication,
    SharedCoordinationState,
    CrossRunCoordination,
    CollectiveCapabilityAmplification,
    Other { description: String },
}

/// A single allowed egress destination (OQGF-P-12.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRule {
    /// Hostname or IP.
    pub destination: String,
    pub port: u16,
    pub protocol: EgressProtocol,
}

/// The protocol of an [`EgressRule`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EgressProtocol {
    Https,
    Http,
    Other(String),
}

/// Deterministic default-deny egress (OQGF-P-12.4). Signed (not model-generated)
/// and unmodifiable by the agent; its enforcement in the orchestrator is a
/// Deterministic Gate under OQGF-P-2 — a destination absent from `rules` is denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressManifest {
    pub rules: Vec<EgressRule>,
    pub signature: DualSignature,
}

/// OQGF-P-12.2 — the Capability Envelope. Signed and attested against the deployed
/// environment (P-12.3). `governing_tier` SHALL equal `max(capability_tier,
/// data_tier)` (P-12.1); [`validate`](Self::validate) enforces that plus the
/// Enhanced floor for effect/credential/sub-agent properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityEnvelope {
    pub system_id: String,
    pub properties: Vec<CapabilityProperty>,
    /// Present iff the system declares network access (P-12.4).
    pub egress_manifest: Option<EgressManifest>,
    pub capability_tier: ConformanceTier,
    pub data_tier: ConformanceTier,
    /// SHALL be `max(capability_tier, data_tier)` (P-12.1).
    pub governing_tier: ConformanceTier,
    pub attested_at: Timestamp,
    pub signature: DualSignature,
}

/// Why a [`CapabilityEnvelope`] failed [`validate`](CapabilityEnvelope::validate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// `governing_tier` is not `max(capability_tier, data_tier)` (P-12.1).
    TierMismatch,
    /// A property flooring at Enhanced is present but `capability_tier` is below it (P-12.2).
    TierTooLow,
}

impl CapabilityEnvelope {
    /// P-12.1 / P-12.2. `governing_tier` MUST be `max(capability_tier, data_tier)`,
    /// and any of external effect, credential access, or sub-agent creation floors
    /// `capability_tier` at Enhanced.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.governing_tier != core::cmp::max(self.capability_tier, self.data_tier) {
            return Err(EnvelopeError::TierMismatch);
        }
        let requires_enhanced = self.properties.iter().any(|p| {
            matches!(
                p,
                CapabilityProperty::ExternalEffect { .. }
                    | CapabilityProperty::CredentialAccess { .. }
                    | CapabilityProperty::SubAgentCreation
            )
        });
        if requires_enhanced && self.capability_tier < ConformanceTier::Enhanced {
            return Err(EnvelopeError::TierTooLow);
        }
        Ok(())
    }

    /// An all-permissive, unenforcing envelope for a default/composition where no
    /// capability governance is configured (the `Guards::permissive()` analog). No
    /// declared properties and **no egress manifest**, so egress enforcement is a
    /// no-op. The signature is a placeholder — this envelope is a local default, not
    /// an attested, DAP-signed one (which a real deployment supplies).
    pub fn permissive() -> Self {
        let envelope = Self {
            system_id: String::from("permissive"),
            properties: Vec::new(),
            egress_manifest: None,
            capability_tier: ConformanceTier::Enhanced,
            data_tier: ConformanceTier::Baseline,
            governing_tier: ConformanceTier::Enhanced,
            attested_at: Timestamp(0),
            signature: placeholder_signature(),
        };
        // 16-FIX (Fix 3) — belt-and-suspenders: the library-provided default SHALL be a valid
        // envelope. `debug_assert!` (not a hard error) because `permissive()` is a test/composition
        // default and a hard error would panic setup; the assert catches a future regression that
        // makes the tiers inconsistent, during any debug/test run.
        debug_assert!(
            envelope.validate().is_ok(),
            "permissive envelope must be valid"
        );
        envelope
    }
}

/// OQGF-P-12.6 — a record of a sub-agent's creation. The child's envelope MUST be a
/// subset of the parent's, and its intent chain is attenuated from the parent's
/// (AMD-001 OQGF-M-9). BROKKR does not spawn sub-agents; the type and its
/// [`validate`](Self::validate) are placed so the enforcement hook is ready.
#[derive(Debug, Clone)]
pub struct SubAgentRecord {
    pub parent_id: String,
    pub child_id: String,
    pub child_envelope: CapabilityEnvelope,
    pub intent_chain: IntentProvenanceChain,
    pub created_at: Timestamp,
}

/// Why a [`SubAgentRecord`] failed [`validate`](SubAgentRecord::validate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubAgentError {
    /// The child declares a capability the parent does not hold (P-12.6).
    CapabilityExceedsParent,
}

impl SubAgentRecord {
    /// P-12.6 — every capability the child declares MUST be present in the parent's
    /// envelope. A child cannot exceed its parent.
    pub fn validate(&self, parent: &CapabilityEnvelope) -> Result<(), SubAgentError> {
        for prop in &self.child_envelope.properties {
            if !parent.properties.contains(prop) {
                return Err(SubAgentError::CapabilityExceedsParent);
            }
        }
        Ok(())
    }
}

/// OQGF-P-12.8 (+ the Organ 5 evidence-provenance patch) — **how** a material audit
/// record was captured, not just **what** it says. Every trajectory entry carries
/// this so a reviewer can reason about the sensor, its path, its clock, and any
/// coverage gap — rather than trusting the record blindly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceProvenance {
    /// What captured this record.
    pub sensor_id: String,
    /// Through what path it was captured.
    pub capture_path: String,
    /// The capture time — from the sensor, stated so a reader can weigh its independence
    /// from the governed system's own clock.
    pub capture_timestamp: Timestamp,
    /// What the sensor was expected to cover.
    pub expected_coverage: String,
    /// What it actually covered.
    pub observed_coverage: String,
    /// An explicit gap where coverage was incomplete; `None` when complete.
    pub evidence_gap: Option<String>,
}

/// OQGF-P-12.8 — one entry in the session **trajectory**: the ordered, complete
/// sequence of every hop attempt, so a session can be reconstructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrajectoryEntry {
    pub sequence: u64,
    pub action: Action,
    pub tool_id: ToolId,
    pub outcome: TrajectoryOutcome,
    pub timestamp: Timestamp,
    pub provenance: EvidenceProvenance,
}

/// The outcome of a hop, as recorded in the [`TrajectoryEntry`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrajectoryOutcome {
    Executed { output: String },
    Denied { stage: String, reason: String },
    Error { detail: String },
}

/// A placeholder dual signature (empty bytes, correct algorithm identifiers). Used
/// only by [`CapabilityEnvelope::permissive`]; a real envelope carries a genuine
/// DAP signature. Not verified anywhere in this module.
fn placeholder_signature() -> DualSignature {
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
