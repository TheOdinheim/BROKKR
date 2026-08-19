//! # brokkr-sentinel (HEIMDALL + EIR)
//!
//! Organ 2's **heuristic, tolerable layer** and Organ 5's **resolution** counterpart (§6.7,
//! §6.8):
//!
//! - **HEIMDALL** ([`Heimdall`]) — the Sentinel, Tolerance Controller, and Host-Harm Monitor.
//!   It is *fed* [`Observation`]s and detectors; it does not reach into other crates to
//!   collect them (I-5). It screens detectors against a verified Self Set (OQGF-P-3), attaches
//!   signed/scoped/expiring tolerance grants (OQGF-P-4) — **never to a Deterministic gate**
//!   (OQGF-P-2, enforced by core's sealed `grant`) — measures the host-harm rate (OQGF-P-1),
//!   assesses storms against a declared blast radius (OQGF-P-5b), and reconciles hops
//!   (OQGF-M-12), emitting **raise-only** Signals (OQGF-P-7.4).
//! - **EIR** ([`Eir`]) — the Resolution Engine. Every escalation has a declared way down;
//!   above baseline, only a DAP-confirmed (signature-verified) [`ResolutionDecision`]
//!   de-escalates (OQGF-P-8.5). Resolution is an act, not a timeout (OQGF-P-8.2); chronic
//!   escalations are flagged as host harm (OQGF-P-8.6); incident records and learned detectors
//!   are preserved because EIR holds neither (OQGF-P-8.4).
//!
//! ## Scope (§6.7 "What Phase 8 does not build")
//!
//! Pure logic over `brokkr-core` and `brokkr-crypto` — no FFI of its own, no `unsafe`, no I/O.
//! It builds the **trait and machinery**; concrete detectors and a production `SelfSetCorpus`
//! are content (a test double serves the tests). It does not emit Signals to other organs or
//! record to SAGA — it produces Signals as **values**; the orchestrator (Phase 11) delivers
//! them. KVASIR (Phase 9), BIFRÖST (Phase 8.5), the executor (Phase 11), and the OQGF-M-6
//! reconciliation statistic (Phase 11 per Rev 1.11) are out of scope.

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
pub mod eir;
pub mod heimdall;
pub mod observation;

pub use eir::Eir;
pub use heimdall::{Detection, Heimdall, StormAssessment};
pub use observation::{DetectionVerdict, Detector, Observation, SelfSetCorpus};
