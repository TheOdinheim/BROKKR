//! # brokkr-tools — the tools BROKKR may invoke (Phase 10)
//!
//! The **untrusted side** of the dependency line, alongside `brokkr-reasoner`. A [`ToolExecutor`]
//! executes an already-[`AuthorizedAction`](brokkr_core::gate::AuthorizedAction): by the time a
//! tool runs, SINDRI has authorized the action (the `AuthorizedAction` is that proof, I-1), so the
//! tool does not re-check — it **executes**.
//!
//! **A tool cannot self-authorize (structural).** `AuthorizedAction`'s constructor is sealed in
//! `brokkr-core::gate`; nothing in this crate constructs one or calls `authorize`. A tool that
//! tried to forge an `AuthorizedAction` does not compile:
//!
//! ```compile_fail
//! use brokkr_core::gate::{Action, AuthorizedAction};
//! use brokkr_core::ids::ToolId;
//! // A tool cannot mint its own authorization: the `action` field is private (E0451).
//! let _forged = AuthorizedAction { action: Action { tool: ToolId::new("x"), detail: "y".into() } };
//! ```
//!
//! ## Scope (Phase 10)
//!
//! Pure logic over `brokkr-core` — no `unsafe`, no I/O. This crate builds the execution **trait**
//! and stub tools; the executor that maps a `ToolId` to a tool and runs it is the orchestrator
//! (Phase 11), and real file/shell execution is a deployment concern. `ToolSchema` is opaque
//! prose, so dispatch is by `ToolId`, not by a structured schema. **No governance crate depends on
//! `brokkr-tools`** (I-5).

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

pub mod tool;

pub use tool::{FixedResultTool, NoOpTool, ToolError, ToolExecutor, ToolOutcome};
