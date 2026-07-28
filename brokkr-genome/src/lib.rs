//! # brokkr-genome (REGIN)
//!
//! The Genome and the OQGF-G-4 promotion gate (BROKKR-ARCH §6.2, Rev 1.5). REGIN is what
//! BROKKR is *made of*: six signed registers (tools, CBOM, AIBOM, endpoints, roots of
//! trust, policy). This crate provides two things and no I/O:
//!
//! 1. **Canonical serialization** ([`canonical`]) of each register's signed content and of
//!    the genome — deterministic, unambiguous (length-prefixed), and domain-separated so a
//!    signature over one register cannot verify against another.
//! 2. **The promotion gate** ([`promote`]) — a fail-closed, non-suppressible Deterministic
//!    Gate (OQGF-P-2) that evaluates the six §6.2 predicates and returns a
//!    [`PromotionVerdict`]: `Promoted`, or `Blocked` with every typed [`Finding`].
//!
//! ## Non-circularity, non-suppressibility
//!
//! Signature verification takes the DAP's verifying key as an **explicit parameter**,
//! supplied out of band — never read from the genome's own `RootsOfTrust` register (which
//! is itself signed; verifying it with a key it contains would prove nothing). The gate is
//! unaddressable by a `ToleranceGrant`, which targets a `DetectorId` the gate does not
//! have. A `Blocked` verdict has no conversion to `Promoted` (I-2 / OQGF-P-2).
//!
//! ## Scope and posture
//!
//! Pure logic — **no FFI, no `unsafe`, no I/O**. Registers are values passed in; there is
//! no disk loading and no CycloneDX parsing (the CBOM's typed `algorithms` inventory is
//! what the gate evaluates). Depends only on `brokkr-core` (the types) and `brokkr-crypto`
//! (dual-family verification). It makes **no** model calls (I-6) and does not depend on
//! `brokkr-reasoner`/`brokkr-tools`/`brokkr-cli` (I-5).
//!
//! [`promote`]: gate::promote
//! [`PromotionVerdict`]: verdict::PromotionVerdict
//! [`Finding`]: verdict::Finding

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

pub mod canonical;
pub mod gate;
pub mod verdict;

pub use gate::promote;
pub use verdict::{Finding, PromotionVerdict, Register};
