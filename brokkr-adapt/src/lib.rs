//! # brokkr-adapt (KVASIR) — the Maturation Pipeline (AMD-003, §6.12)
//!
//! KVASIR refines a heuristic detector from a **confirmed incident**, through four poisoning
//! gates, and hands back the generation it replaced so the change is reversible:
//!
//! 1. **Seeding** (OQGF-P-6.1) — only a DAP-confirmed incident *recorded in Organ 5* may seed a
//!    refinement, verified through the [`ConfirmedIncidentLedger`] seam, **not** the caller's own
//!    claim. KVASIR gates; it does not invent — the `DetectorDelta` is authored, not derived.
//! 2. **Selection** (OQGF-P-6.2) — verify the evaluation-corpus digest against the DAP-declared
//!    record *before measuring* (substituted-corpus defence), verify the corpus does not *contain*
//!    the seeding sample (non-containment, not independence — §13), then require improved
//!    detection of the seeded attack class **without** coverage regression.
//! 3. **Tolerance** (OQGF-P-6.3) — HEIMDALL's central-tolerance `screen` against the **current**
//!    Self Set, *called, not reimplemented*; discarded if it raises host harm above the bound
//!    **regardless of detection gains** — there is no trade curve.
//! 4. **Activation** (OQGF-P-6.4/6.5/6.6) — verify the dual-family provenance signature (the DAP's
//!    approval), require version-equality on the screen pass and the corpus (not recency), and
//!    return the [`PriorGeneration`](brokkr_core::adapt::PriorGeneration) — reversibility by
//!    construction.
//!
//! **I-9 — the agent does not teach itself.** `brokkr-adapt` does **not** depend on
//! `brokkr-reasoner`; there is no path from the reasoner to KVASIR. And a
//! [`RefinedDetector`](brokkr_core::adapt::RefinedDetector) is `Heuristic` by construction (its
//! `response_class` is private and fixed in core) — KVASIR can learn to see better; it cannot
//! learn to see less. The structural impossibility of a `Deterministic` refined detector is a
//! `compile_fail` here:
//!
//! ```compile_fail
//! use brokkr_core::adapt::{RefinedDetector, DetectorSpecBase, DetectorDelta};
//! use brokkr_core::ids::DetectorId;
//! use brokkr_core::tolerance::ResponseClass;
//! // I-9: there is no constructor, field, or conversion that makes a RefinedDetector
//! // Deterministic. `response_class` is a PRIVATE field in brokkr-core, so this literal — the
//! // only way to try to set it — does not compile.
//! let _d = RefinedDetector {
//!     base: DetectorSpecBase { id: DetectorId::new("d") },
//!     change: DetectorDelta { detail: "x".to_string() },
//!     generation: 1,
//!     response_class: ResponseClass::Deterministic,
//! };
//! ```
//!
//! ## Scope (§6.12 "What Phase 9 does not build")
//!
//! Pure logic over `brokkr-core`, `brokkr-crypto`, and `brokkr-sentinel` — no FFI of its own, no
//! `unsafe`, no I/O. Detector **generation** (the `DetectorDelta` is authored elsewhere, and
//! elsewhere is not the reasoner), a **production evaluation corpus** (the seam plus a double),
//! **recording** activation/rollback events to Organ 5 (the orchestrator, Phase 11), and the
//! **rollback trigger** (a DAP act) are all out of scope.

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
pub mod corpus;
pub mod kvasir;
pub mod ledger;

pub use corpus::{EvaluationCorpusContent, InMemoryCorpus};
pub use kvasir::Kvasir;
pub use ledger::{ConfirmedIncidentLedger, InMemoryLedger};
