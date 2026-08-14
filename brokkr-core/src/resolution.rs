//! EIR — the Resolution Engine (AMD-005).
//!
//! I-8 is encoded here in two halves: an [`EscalationType`] cannot be constructed
//! without a resolution path and a baseline (the fields are not optional — no
//! one-way ratchets, OQGF-P-8.1); and a [`ResolutionDecision`] cannot be
//! constructed without a DAP and a signature, so a de-escalation with no
//! accountable party is unrepresentable (OQGF-P-8.2, OQGF-P-8.5).

use crate::crypto::DualSignature;
use crate::ids::{Dap, EscalationId, Nonce, Timestamp};
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

/// The criteria marking an escalation's trigger "cleared".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearCondition {
    pub detail: String,
}

/// The homeostatic set point an escalation returns to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselinePosture {
    pub detail: String,
}

/// A registered escalation type.
///
/// **I-8 (first half)** — `resolution_criteria` and `baseline` are required
/// fields, not `Option`. An escalation with no way down is not a value this type
/// can hold (OQGF-P-8.1: *there are no one-way ratchets*).
///
/// This does not compile — a `None` cannot stand in for the required baseline:
///
/// ```compile_fail,E0308
/// use brokkr_core::resolution::EscalationType;
/// fn any<T>() -> T { unimplemented!() }
/// let _ = EscalationType::new(any(), any(), None, any(), any(), any());
/// // E0308: mismatched types — expected `BaselinePosture`, found `Option<_>` (3rd arg)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationType {
    pub id: EscalationId,
    pub resolution_criteria: ClearCondition,
    pub baseline: BaselinePosture,
    pub dwell_min: Duration,
    pub hold_window: Duration,
    pub max_duration: Duration,
}

impl EscalationType {
    pub fn new(
        id: EscalationId,
        resolution_criteria: ClearCondition,
        baseline: BaselinePosture,
        dwell_min: Duration,
        hold_window: Duration,
        max_duration: Duration,
    ) -> Self {
        Self {
            id,
            resolution_criteria,
            baseline,
            dwell_min,
            hold_window,
            max_duration,
        }
    }
}

/// Evidence that the clear condition was met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearEvidence {
    pub detail: String,
}

/// An explicit, recorded de-escalation decision.
///
/// **I-8 (second half)** — `dap` and `signature` are required fields. A resolution
/// without a named, accountable DAP is unrepresentable (OQGF-P-8.2, OQGF-P-8.5).
///
/// **Freshness (new in Rev 1.12).** A `nonce` and an `expiry` were added because a
/// signature that verifies today verifies forever: a decision captured once could be
/// **replayed** later, when the escalation it clears is real and current. Resolution is
/// the one act in BROKKR that *lowers* a defense, and it was the only signed artifact in
/// the system without freshness — a [`crate::tolerance::ToleranceGrant`] expires, a
/// [`crate::signal::Signal`] carries both, a [`crate::risk::RiskAcceptance`] expires, a
/// `BoundaryCustodyRecord` expires. EIR SHALL refuse a decision whose `now > expiry` and
/// a `nonce` it has already accepted for that escalation (the *enforcement* is the
/// sentinel's; these fields are what it enforces over).
///
/// This does not compile — the DAP is not optional (7-argument `new`, `None` in the 3rd,
/// `dap`, position):
///
/// ```compile_fail,E0308
/// use brokkr_core::resolution::ResolutionDecision;
/// fn any<T>() -> T { unimplemented!() }
/// let _ = ResolutionDecision::new(any(), any(), None, any(), any(), any(), any());
/// // E0308: mismatched types — expected `Dap`, found `Option<_>` (3rd arg)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionDecision {
    pub escalation: EscalationId,
    pub cleared_condition: ClearEvidence,
    pub dap: Dap,
    pub at: Timestamp,
    /// Freshness, so a decision cannot be replayed (new in Rev 1.12).
    pub nonce: Nonce,
    /// After this instant the decision is stale and SHALL NOT resolve (new in Rev 1.12).
    pub expiry: Timestamp,
    pub signature: DualSignature,
}

impl ResolutionDecision {
    pub fn new(
        escalation: EscalationId,
        cleared_condition: ClearEvidence,
        dap: Dap,
        at: Timestamp,
        nonce: Nonce,
        expiry: Timestamp,
        signature: DualSignature,
    ) -> Self {
        Self {
            escalation,
            cleared_condition,
            dap,
            at,
            nonce,
            expiry,
            signature,
        }
    }
}

// ---------------------------------------------------------------------------
// The canonical signed content of a resolution decision (new in Rev 1.12).
//
// A resolution decision is **signed by a DAP tool and verified by EIR — two parties, two
// crates.** The bytes the signature covers are therefore defined **once, in core, where
// both can see them**: an encoding defined only in the verifier forces the issuer to
// reproduce it from source, and a single disagreement about field order or length-prefixing
// rejects every legitimate decision while looking exactly like an attack. This is the same
// reasoning that put `BarrierFinding::finding_id()` in core (§6.8).
//
// This is **byte composition returning a `Vec<u8>`, not a digest** — `brokkr-core` is
// `#![no_std] + alloc` and implements no `Hasher`. A signer hashes-and-signs these bytes
// downstream; EIR recomputes them and verifies. The discipline matches the sibling
// `canonical` modules exactly: deterministic fixed field order, every variable-length field
// length-prefixed with a fixed 8-byte big-endian count, a leading domain tag.
// ---------------------------------------------------------------------------

/// Domain tag for the resolution-decision signed content. **Distinct from every other
/// signed-artifact tag in the system** — checked against all seven `brokkr-genome:*`, both
/// `brokkr-barrier:*`, all three `brokkr-audit:*`, and all four `brokkr-sentinel:*` tags. The
/// `brokkr-core:` prefix alone separates it from every one of them.
const DOMAIN_RESOLUTION: &[u8] = b"brokkr-core:resolution:v1";

/// A canonical byte accumulator. All variable-length data is length-prefixed with a fixed
/// 8-byte big-endian count. Byte composition, not a digest.
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
    /// A length-prefixed byte string: 8-byte BE length, then the bytes.
    fn bytes(&mut self, b: &[u8]) {
        self.u64(b.len() as u64);
        self.buf.extend_from_slice(b);
    }
    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// The bytes a [`ResolutionDecision::signature`] covers: `escalation`, `cleared_condition`,
/// `dap`, `at`, `nonce`, `expiry` — **everything except the signature** — under a domain tag
/// distinct from every other signed artifact (§6.8, Rev 1.12). Deterministic and unambiguous:
/// identical decisions produce identical bytes; the length prefixes make distinct field
/// contents produce distinct bytes; and because `signature` is excluded, two decisions that
/// differ only in their signature produce identical signed content.
pub fn resolution_signed_content(d: &ResolutionDecision) -> Vec<u8> {
    let mut c = Canon::new();
    c.bytes(DOMAIN_RESOLUTION);
    c.bytes(d.escalation.as_str().as_bytes());
    c.bytes(d.cleared_condition.detail.as_bytes());
    c.bytes(d.dap.name.as_bytes());
    c.bytes(d.dap.id.as_bytes());
    c.u64(d.at.0);
    c.u64(d.nonce.0);
    c.u64(d.expiry.0);
    c.finish()
}

/// Whether an escalation may come down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionVerdict {
    /// Criteria met and hysteresis satisfied. Above baseline, `needs_dap` is true
    /// (OQGF-P-8.5).
    Eligible { needs_dap: bool },
    /// Not yet resolvable.
    NotYet { reason: String },
    /// Past its maximum duration (OQGF-P-8.6).
    Chronic,
}

/// Confirmation that an escalation returned to baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnedToBaseline {
    pub escalation: EscalationId,
}

/// An escalation flagged as chronic (OQGF-P-8.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChronicEscalation {
    pub escalation: EscalationId,
}

error_enum! {
    /// Why a resolution was refused.
    ///
    /// **A refusal names the reason it actually is (Rev 1.13).** [`Expired`](Self::Expired) and
    /// [`ReplayedNonce`](Self::ReplayedNonce) are **two variants, not one**, because they are
    /// two different events. An expiry is almost always operational latency — a slow DAP, a
    /// queued approval, clock skew. **A replay is an attack**, and its whole character is that
    /// the decision is *authentic*: correctly signed, by the right DAP, over criteria that
    /// really were met — **once**. Collapsing them into a single `Stale` would file "someone
    /// took too long" and "someone is replaying a stand-down against you" under one word, and
    /// an operator would learn which only by reading the code.
    ///
    /// **Neither reuses [`NeedsDapConfirmation`](Self::NeedsDapConfirmation).** A replayed
    /// decision *is* DAP-confirmed — the signature verifies, the DAP is named, the record is
    /// authentic — so reporting missing confirmation during a replay points the investigation
    /// at the one thing that is *not* wrong. An error variant is a claim about what happened,
    /// and a false claim in a refusal is a false claim in the audit record. This is the same
    /// correction Rev 1.12 made for [`crate::tolerance::ToleranceError::SignatureInvalid`],
    /// applied to the other half of the same revision (§6.8).
    pub enum ResolveError {
        CriteriaNotMet => "resolution criteria not met (OQGF-P-8.1)",
        HysteresisNotSatisfied => "dwell/hold hysteresis not satisfied (OQGF-P-8.3)",
        NeedsDapConfirmation => "de-escalation above baseline requires DAP confirmation (OQGF-P-8.5)",
        /// `now > decision.expiry`. The decision was validly made and validly signed; it
        /// simply arrived too late — operational latency, not an attack (OQGF-P-8.5, Rev 1.13).
        Expired => "the resolution decision has expired (OQGF-P-8.5)",
        /// The `nonce` was already accepted for this escalation. The decision is **authentic**,
        /// and that is the point: correctly signed, by the right DAP, over criteria that really
        /// were met once — now being presented again (OQGF-P-8.5, Rev 1.13).
        ReplayedNonce => "the resolution decision's nonce was already accepted (OQGF-P-8.5)",
    }
}

/// The resolution engine (EIR, Phase 8). Autonomous action may raise posture;
/// nothing autonomous lowers it above baseline (OQGF-P-8.5).
pub trait ResolutionEngine: Send + Sync {
    fn may_resolve(&self, escalation: &EscalationId) -> ResolutionVerdict;
    fn resolve(&self, decision: ResolutionDecision) -> Result<ReturnedToBaseline, ResolveError>;
    fn scan_chronic(&self) -> Vec<ChronicEscalation>;
}
