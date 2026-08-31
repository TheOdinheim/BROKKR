//! # brokkr-core
//!
//! The governance types of BROKKR — the deterministic spine — with the structural
//! invariants I-1 … I-12 encoded so that a violation **does not compile**. This is
//! the crate every other crate inherits.
//!
//! ## The crypto seam
//!
//! brokkr-core defines cryptography as **traits** ([`Signer`], [`Verifier`],
//! [`Hasher`]) and carries **no implementation**. [`Signature`], [`DualSignature`],
//! [`Digest`], and [`Attestation`] hold opaque bytes plus a typed algorithm
//! identifier ([`SignatureAlg`], [`HashAlg`], [`KemAlg`]) — never a string
//! (OQGF-G-5). Nothing here calls wolfCrypt. Phase 2 (`brokkr-crypto`) implements
//! these traits against wolfCrypt; the negative tests here run against a mock
//! signer with no FFI. brokkr-core SHALL NOT depend on `brokkr-crypto` or any C
//! library (I-5).
//!
//! ## no_std and zero dependencies
//!
//! This crate is `#![no_std] + alloc` and has **no dependencies**. Error types are
//! hand-rolled (`core::fmt::Display` + `core::error::Error`) rather than derived via
//! `thiserror`, to keep the foundational crate `no_std` and dependency-free. Two
//! non-invariant-bearing shape substitutions make genuine `no_std` reachable:
//! [`Timestamp`]`(u64)` for `std::time::SystemTime`, and [`ResourcePath`]`(String)`
//! for `std::path::PathBuf`.
//!
//! ## The invariants
//!
//! See `src/../..`/the phase report for which invariant is proven at compile time
//! (a `compile_fail` doctest) versus at run time (an integration test in `tests/`).
//! I-5, I-6, I-7 are cross-crate / CI properties and are intentionally *not* forced
//! into single-type encodings here.

#![no_std]
#![forbid(unsafe_code)]
// CLAUDE.md 6 — no panics in production paths. Applies to this lib target only;
// integration tests and doctests are separate crates and may use unwrap/panic.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]

extern crate alloc;

// ---------------------------------------------------------------------------
// Zero-dependency helper macros. Defined before the module declarations so they
// are in textual scope for every submodule.
// ---------------------------------------------------------------------------

/// Declare a unit-variant error enum with `Display` + `core::error::Error`,
/// hand-rolled so brokkr-core needs no `thiserror` dependency.
macro_rules! error_enum {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$vm:meta])* $variant:ident => $msg:literal ),+ $(,)?
        }
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $vis enum $name {
            $( $(#[$vm])* $variant ),+
        }
        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self { $( Self::$variant => f.write_str($msg) ),+ }
            }
        }
        impl core::error::Error for $name {}
    };
}

/// Declare newtype string identifiers with the common derives and constructors.
macro_rules! string_id {
    ( $( $(#[$m:meta])* $name:ident ),+ $(,)? ) => {
        $(
            $(#[$m])*
            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name(pub alloc::string::String);
            impl $name {
                pub fn new(s: impl Into<alloc::string::String>) -> Self { Self(s.into()) }
                pub fn as_str(&self) -> &str { &self.0 }
            }
        )+
    };
}

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------

pub mod adapt;
pub mod barrier;
pub mod capability;
pub mod classification;
pub mod crypto;
pub mod explanation;
pub mod gate;
pub mod genome;
pub mod ids;
pub mod intent;
pub mod personal_data;
pub mod reasoner;
pub mod resolution;
pub mod risk;
pub mod signal;
pub mod tolerance;

// ---------------------------------------------------------------------------
// Headline re-exports (the invariant-bearing surface). Modules remain public.
// ---------------------------------------------------------------------------

pub use adapt::{
    AdaptError, DetectorProvenance, MaturationPipeline, RefinedDetector, SeedingIncident,
};
pub use barrier::{
    Barrier, BarrierCondition, BarrierFinding, BarrierVerdict, BoundaryCustodyRecord, BoundaryFlow,
    ContextClass, Destination, DestinationClass, PersonalDataTag,
};
pub use classification::{ChannelStrength, Classification, NamedGroup, effective_authorization};
pub use crypto::{
    Attestation, CryptoError, Digest, DualSignature, HashAlg, Hasher, KemAlg, Signature,
    SignatureAlg, Signer, Verifier,
};
pub use gate::{Action, AnergyReason, AuthorizationDecision, AuthorizedAction, CostimulationGate};
pub use genome::{
    Aibom, Cbom, EndpointRegistry, Genome, ModelEndpoint, PrivilegeClass, ToolEntry, ToolGenome,
    VendorTrustScore,
};
pub use ids::{Dap, ModelIdentity, Nonce, OrganId, ResourcePath, Score, Timestamp};
pub use intent::{
    AttenuationError, Capability, Caveat, IntentChain, IntentChainEntry, IntentProvenanceChain,
    IntentScope, Invariant, InvariantSet, RootIntent,
};
pub use personal_data::{Purpose, RetentionPeriod};
pub use reasoner::{ClearedContext, Context, ContextClearance, Proposal, Reasoner, ReasonerError};
pub use resolution::{
    EscalationType, ResolutionDecision, ResolutionEngine, ResolutionVerdict, ResolveError,
    resolution_signed_content,
};
pub use risk::{
    DeterministicGateId, Disposition, Impact, Likelihood, RiskAcceptance, RiskEntry, RiskId,
    RiskRegister, RiskSource, TransferMechanism, TreatmentPlan, TreatmentStatus,
};
pub use signal::{PostureEffect, Severity, Signal, SignalClass, SignalScope};
pub use tolerance::{
    DefensiveResponse, HostHarmIncident, HostHarmReport, ResponseClass, ScreenPass, SelfSet,
    StormEvent, ToleranceController, ToleranceError, ToleranceGrant,
};
