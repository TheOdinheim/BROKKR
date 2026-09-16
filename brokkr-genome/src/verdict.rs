//! The promotion verdict — mirroring `brokkr_core::barrier::BarrierVerdict`'s shape.
//!
//! Two-state at Phase 5: `Promoted`, or `Blocked` with typed findings. There is
//! deliberately **no method, `impl`, `From`, or conversion of any kind** that turns a
//! `Blocked` verdict into a `Promoted` one — the same I-2 / OQGF-P-2 discipline
//! `BarrierVerdict` encodes for `Deny → Allow`. Phase 6 adds the Accountable Risk
//! Acceptance path (`brokkr-barrier`); this phase adds no override and no placeholder
//! variant.

use brokkr_core::capability::ConformanceTier;
use brokkr_core::genome::AlgorithmId;
use brokkr_core::ids::{ModelEndpointId, Score, ToolId};
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
    /// Predicate 8 (Rev 1.31): a **measured** factor claims a value it has no evidence
    /// for — `reconciliation_pass_rate` is non-zero while `evidence.observations` is 0.
    ///
    /// **Not the inverse.** An honestly *unmeasured* factor — `Score(0)` with zero
    /// observations — is promotable, and must be: BROKKR's own genome is in exactly that
    /// state. A gate refusing the honest state and admitting the dishonest one would be
    /// precisely backwards, and this predicate is one line away from being that gate.
    MeasuredFactorWithoutEvidence {
        endpoint: ModelEndpointId,
        /// The score claimed, carried so a blocked report says *what* was claimed rather
        /// than only that something was.
        claimed: Score,
    },
    /// Predicate 7 (Rev 1.21/1.22): the declared key custody does not meet the AMD-018
    /// obligation for the genome's declared conformance tier. Carries the tier and the
    /// specific element that failed, so a blocked report says *which* of R-6.2's or
    /// R-6.3's requirements the declaration missed — not merely that it missed one.
    KeyCustodyBelowTier {
        tier: ConformanceTier,
        element: CustodyShortfall,
    },
}

/// Which element of the AMD-018 tier obligation a custody declaration failed.
///
/// Typed rather than a `String` for the same reason every other finding is: an assessor
/// reading a blocked verdict acts on the element, and a hardware boundary that is missing
/// is a different remediation from a dual-control procedure that is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyShortfall {
    /// R-6.2: the declaration is `SoftwareInProcess` — there is no hardware boundary.
    NoHardwareBoundary,
    /// R-6.2: a boundary is declared but issuance is `DualControl::SingleOperator`.
    /// AMD-018 §AMD.5 — "a FIPS validation is not by itself evidence of dual control."
    NoDualControl,
    /// R-6.3: the declaration is not `Threshold` — no k-of-n custody at all.
    NoThresholdCustody,
    /// R-6.3: the quorum is below AMD-018's 3-of-5 floor, or malformed (`k > n`).
    QuorumBelowFloor,
    /// R-6.3: fewer independent parties than the quorum requires — a declared 3-of-5 whose
    /// shares fewer than `k` parties hold. AMD-018 §AMD.3: "a share-holding arrangement in
    /// which fewer than k independent parties can reconstruct the secret SHALL NOT satisfy
    /// this requirement." **This is the one shortfall the gate catches on substance rather
    /// than form**, and only because the operator was made to write the number down.
    InsufficientCustodialSeparation,
    /// R-6.3: the recovery rehearsal is older than a year, or dated in the future.
    RehearsalStale,
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
