//! # brokkr-gate (SINDRI)
//!
//! The Costimulation Gate (OQGF-M-11), at the Phase-4 scope placed by Architecture
//! Rev 1.3 (§6.4, §6.4.1). SINDRI is the deterministic spine's decision point: it
//! supplies **only** the verdict logic ([`CostimulationGate::evaluate`]) and can never
//! mint an [`AuthorizedAction`] — the provided `authorize` in `brokkr-core` is the sole
//! minter, and `mint` is private to that module. The worst a buggy or compromised SINDRI
//! can do is **wrongly deny** (I-1, fail-safe by construction).
//!
//! ## What SINDRI enforces
//!
//! A grant requires four conjuncts, all evaluated by [`Sindri`]'s `evaluate`:
//!
//! 1. **Signal 1 — identity**: the presented identity resolves to a declared root of trust
//!    **and** binds to the hop the chain's signature actually proves.
//! 2. **Signal 2 — chain**: a valid Intent Provenance Chain, verified against
//!    resolver-supplied public roots of trust via
//!    [`brokkr_intent::Skuld::verify_chain_public`].
//! 3. **Action in scope**: the action's tool resolves in the genome (through the
//!    [`GenomeResolver`] seam) and every capability it requires is present in the chain's
//!    current attenuated scope. An undeclared tool, or a required capability missing from
//!    scope, is [`AnergyReason::OutOfScope`].
//! 4. **Action respects invariants**: for each accumulated invariant, the tool requires no
//!    capability the invariant forbids and carries no privilege class it forbids. An
//!    invariant with no declared predicate is denied, not passed. Either is
//!    [`AnergyReason::InvariantViolated`].
//!
//! Conjuncts 3 and 4 use the same resolver-seam pattern as Signal 2's key resolver: the gate
//! asks the [`GenomeResolver`], the resolver answers, and the gate does not know where the data
//! lives (the genome, in production).
//!
//! ## Scope and posture
//!
//! Pure logic — **no FFI, no `unsafe`**. Depends only on `brokkr-core` (types),
//! `brokkr-intent` (the chain verifier), and `brokkr-crypto` (the public-key type). It
//! makes **no** model calls (I-6) and does not depend on
//! `brokkr-reasoner`/`brokkr-tools`/`brokkr-cli` (I-5). It contains no model and exposes
//! no channel to one.
//!
//! [`CostimulationGate::evaluate`]: brokkr_core::gate::CostimulationGate::evaluate
//! [`AuthorizedAction`]: brokkr_core::gate::AuthorizedAction
//! [`AnergyReason::OutOfScope`]: brokkr_core::gate::AnergyReason::OutOfScope
//! [`AnergyReason::InvariantViolated`]: brokkr_core::gate::AnergyReason::InvariantViolated

#![forbid(unsafe_code)]
// CLAUDE.md §6 — no panics in production paths (tests are a separate crate).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]

pub mod resolver;
pub mod sindri;

pub use resolver::{
    GenomeResolver, KeyResolver, RegistryResolver, ResolvedInvariant, ResolvedTool,
};
pub use sindri::Sindri;
