//! # brokkr-intent (SKULD)
//!
//! The working Intent Provenance Chain (AMD-001) on top of `brokkr-core`'s
//! append-only chain type: real dual-family signing, SHA-384 hash-linking, freshness,
//! and cryptographically-enforced monotonic attenuation.
//!
//! Pure logic — **no FFI, no `unsafe`**. Depends only on `brokkr-core` (the types) and
//! `brokkr-crypto` (the ML-DSA + SLH-DSA signing and SHA-384 hashing). It is the first
//! consumer of `brokkr-crypto`. It makes **no** model calls (I-6) and does not depend
//! on `brokkr-reasoner`/`brokkr-tools`/`brokkr-cli` (I-5).

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
pub mod skuld;

pub use skuld::{IntentError, Skuld};
