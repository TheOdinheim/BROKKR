//! The promotion verdict — mirroring `brokkr_core::barrier::BarrierVerdict`'s shape.
//!
//! Two-state at Phase 5: `Promoted`, or `Blocked` with typed findings. There is
//! deliberately **no method, `impl`, `From`, or conversion of any kind** that turns a
//! `Blocked` verdict into a `Promoted` one — the same I-2 / OQGF-P-2 discipline
//! `BarrierVerdict` encodes for `Deny → Allow`. Phase 6 adds the Accountable Risk
//! Acceptance path (`brokkr-barrier`); this phase adds no override and no placeholder
//! variant.

use brokkr_core::genome::AlgorithmId;
use brokkr_core::ids::{ModelEndpointId, ToolId};
use brokkr_core::intent::{Capability, Invariant};

/// Which of the six signed registers a signature-verification finding refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Tools,
    Cbom,
    Aibom,
    Endpoints,
    Roots,
    Policy,
}

/// A typed promotion-gate finding — one variant per failed predicate, carrying **which**
/// register / endpoint / tool / invariant failed. Never a `String`: a blocked verdict says
/// exactly what failed, so the human reading the report can act on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Predicate 2: a register's signature did not verify against the DAP root.
    RegisterSignatureInvalid { register: Register },
    /// Predicate 2: the genome's own signature did not verify against the DAP root.
    GenomeSignatureInvalid,
    /// Predicate 3: `cbom.algorithms` contains an algorithm in `policy.disallowed`.
    DisallowedAlgorithm { algorithm: AlgorithmId },
    /// Predicate 4: an endpoint's trust score is older than 90 days.
    StaleTrustScore { endpoint: ModelEndpointId },
    /// Predicate 4: an endpoint's trust score is reviewed in the future (malformed).
    FutureTrustScore { endpoint: ModelEndpointId },
    /// Predicate 5: a tool requires a capability absent from `policy.capabilities`.
    ToolCapabilityNotInVocabulary {
        tool: ToolId,
        capability: Capability,
    },
    /// Predicate 6: an invariant forbids a capability absent from `policy.capabilities`.
    InvariantForbidsUnknownCapability {
        invariant: Invariant,
        capability: Capability,
    },
    /// Predicate 6: an invariant forbids nothing at all (a predicate that can never fire).
    InvariantForbidsNothing { invariant: Invariant },
}

/// The promotion gate's verdict (OQGF-G-4). `Promoted` or `Blocked` with every finding.
///
/// **I-2 / OQGF-P-2 — a `Blocked` verdict cannot become `Promoted`.** There is no method,
/// `impl From`, or conversion of any kind on `Blocked` (or on this enum) that yields
/// `Promoted`. At Phase 5 a gate finding is a hard fail; the Accountable Risk Acceptance
/// path (AMD-006 / OQGF-P-9) is a *distinct* future variant (`brokkr-barrier`, Phase 6),
/// not a flag on `Promoted` and not present here.
///
/// No such conversion exists, so this does not compile:
///
/// ```compile_fail,E0599
/// use brokkr_genome::verdict::PromotionVerdict;
/// let v = PromotionVerdict::Blocked { findings: Vec::new() };
/// let _p = v.into_promoted(); // E0599: no method named `into_promoted` found
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionVerdict {
    /// The genome passed all six predicates; it may be promoted.
    Promoted,
    /// One or more predicates failed. Carries **all** findings, not just the first.
    Blocked { findings: Vec<Finding> },
}
