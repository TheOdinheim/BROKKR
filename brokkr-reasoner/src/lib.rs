//! # brokkr-reasoner (MÍMIR) — the advisory reasoner (Phase 10)
//!
//! MÍMIR is BROKKR's untrusted proposer. It implements the `brokkr-core` [`Reasoner`] trait:
//! [`propose`](brokkr_core::reasoner::Reasoner::propose) takes a
//! [`ClearedContext`](brokkr_core::reasoner::ClearedContext) — the barrier-cleared input, mintable
//! only by BIFRÖST (I-12) — and the current attenuated scope, calls a [`ModelBackend`] seam with
//! the cleared **payload**, and wraps the result as an untrusted
//! [`Proposal`](brokkr_core::reasoner::Proposal) that carries **no authority**. SINDRI decides
//! whether a proposal may act; the trust path never consults MÍMIR.
//!
//! ## The three binding rules (§6.1), all structural
//!
//! 1. **The model receives only the current attenuated scope.** `propose` passes the `&IntentScope`
//!    argument to the backend; MÍMIR never holds or forwards the root intent.
//! 2. **The model has no channel to any gate's decision.** The [`ModelBackend`] trait takes
//!    `&str` + `&IntentScope` and returns a [`BackendProposal`] (an [`Action`] + rationale) — there
//!    is no `AuthorizedAction`, no `BarrierVerdict`, no boolean it can flip. The gate is not in the
//!    interface, so a model cannot reach it.
//! 3. **The endpoint is registered.** Checked at construction ([`Mimir::new`]) against the
//!    [`RegisteredEndpoints`] seam; an unregistered endpoint yields
//!    [`ReasonerError::UnregisteredEndpoint`](brokkr_core::reasoner::ReasonerError::UnregisteredEndpoint).
//!
//! ## I-6, I-12, and the dependency line
//!
//! `brokkr-reasoner` is the **sole** crate that (in production) makes a model API call, and it makes
//! it **only through BIFRÖST** — no governance crate depends on `brokkr-reasoner`. Phase 10 builds
//! no model call: it defines the backend **seam** and test doubles; the production backend is a
//! deployment concern. The `brokkr-bifrost` dependency establishes that architectural edge; the
//! Phase-10 trait impl itself needs only `brokkr-core` (`ClearedContext` is a core type that
//! `propose` *receives*), and the crate's end-to-end test exercises the real BIFRÖST clearing a
//! context before MÍMIR proposes on it (I-12 end-to-end). [`Action`]: brokkr_core::gate::Action

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

pub mod backend;
pub mod mimir;
pub mod registry;

pub use backend::{BackendError, BackendProposal, ModelBackend};
pub use mimir::Mimir;
pub use registry::{InMemoryRegistry, RegisteredEndpoints};
