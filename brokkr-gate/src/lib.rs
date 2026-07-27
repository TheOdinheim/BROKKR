//! # brokkr-gate (SINDRI)
//!
//! The Costimulation Gate (OQGF-M-11), at the Phase-4 scope placed by Architecture
//! Rev 1.3 (§6.4, §6.4.1). SINDRI is the deterministic spine's decision point: it
//! supplies **only** the verdict logic ([`CostimulationGate::evaluate`]) and can never
//! mint an [`AuthorizedAction`] — the provided `authorize` in `brokkr-core` is the sole
//! minter, and `mint` is private to that module. The worst a buggy or compromised SINDRI
//! can do is **wrongly deny** (I-1, fail-safe by construction).
//!
//! ## What Phase 4 enforces
//!
//! OQGF-M-11 requires four conjuncts for a grant. Per Rev 1.3, Phase 4 enforces the two
//! cryptographic ones and defers the two action-semantics ones:
//!
//! 1. **Signal 1 — identity** (OQGF-M-1): the presented identity resolves to a declared
//!    root of trust **and** binds to the hop the chain's signature actually proves.
//! 2. **Signal 2 — chain** (OQGF-M-8/M-9/M-14): a valid Intent Provenance Chain, verified
//!    against resolver-supplied public roots of trust via
//!    [`brokkr_intent::Skuld::verify_chain_public`].
//! 3. **Action-in-scope** and 4. **action-respects-invariants** are **DEFERRED** under the
//!    Deferred-Conjunct Deadline (Rev 1.3 §6.4): they SHALL be enforced before the executor
//!    is wired at Phase 11. SINDRI builds nothing for them, and by construction
//!    [`AnergyReason::OutOfScope`] and [`AnergyReason::InvariantViolated`] are unreachable
//!    from [`Sindri`]'s `evaluate` at Phase 4.
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

pub use resolver::{KeyResolver, RegistryResolver};
pub use sindri::Sindri;
