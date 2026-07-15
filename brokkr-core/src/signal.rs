//! Coordinated signaling (AMD-004): the signed [`Signal`] envelope.
//!
//! The raise-only-autonomy rule (OQGF-P-7.4) is reflected in [`PostureEffect`]
//! carrying only a `Raise` variant: an autonomous signal cannot express a lowering
//! of posture. De-escalation is resolution-gated (EIR, `resolution` module), not a
//! signal effect. Full envelope verification and propagation are Phase 8.

use crate::crypto::DualSignature;
use crate::ids::{Nonce, OrganId, Timestamp};
use alloc::string::String;

/// Canonical signal classes (extensible per implementation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalClass {
    ThreatDetected,
    PostureRaiseRequest,
    StateChangeNotice,
}

/// Signal severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// The effect a signal requests. **Raise-only** when autonomous (OQGF-P-7.4):
/// there is no `Lower` variant, so an autonomous signal cannot stand the system
/// down. Lowering posture is governed by resolution (OQGF-P-8), not by a signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostureEffect {
    Raise { detail: String },
}

/// The scope a signal applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalScope {
    pub detail: String,
}

/// The signed cytokine envelope (OQGF-P-7.1). A signal that is unsigned,
/// malformed, or expired is ignored (enforced in Phase 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    pub source: OrganId,
    pub class: SignalClass,
    pub severity: Severity,
    pub effect: PostureEffect,
    pub scope: SignalScope,
    pub nonce: Nonce,
    pub expiry: Timestamp,
    pub signature: DualSignature,
}
