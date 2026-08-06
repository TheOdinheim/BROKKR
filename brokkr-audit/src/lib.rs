//! # brokkr-audit (SAGA)
//!
//! Organ 5 (OQGF-A) — the **Audit Spine** (§6.9). A dual-family-signed (ML-DSA + SLH-DSA,
//! OQGF-R-1 at Enhanced), **append-only**, hash-linked record of every decision BROKKR makes,
//! with continuous chain self-verification that emits an audit-chain-break trigger
//! (OQGF-A.6.1) on tampering.
//!
//! ## What Rev 1.10 settled, and this crate encodes
//!
//! A record has **one canonical encoding — its signed content** ([`canonical::record_signed_content`]):
//! `seq`, `prev`, `at`, `dap`, `event`, and nothing else. Three things attest to those bytes
//! from **outside** them — the chain link (the next record's `prev`), the accumulating
//! [`event::GenerationSignature`] set (OQGF-A-6), and the RFC 3161 [`event::Timestamping`]
//! token (OQGF-A-3). Because the chain links over signed content only, **re-signing appends a
//! signature without disturbing any link** (proven in `tests/audit.rs`), and a TSA token — a
//! signature *over* the canonical bytes — is not trapped inside the bytes it stamps.
//!
//! ## Erasure without deletion, durable against a CRQC
//!
//! Personal data lives as **ciphertext under a per-subject key**; erasure destroys the key
//! (the crypto layer's `SubjectKey::shred`, quantum-safe per OQGF-G-7) and SAGA **appends a
//! signed [`event::ErasureTombstone`]** — the record is never deleted, the chain stays intact,
//! and the content is irrecoverable (OQGF-P-11.5). Re-signing an erased record **cannot**
//! resurrect it: SAGA holds no subject key and has no decrypt path (OQGF-P-11.7) — see
//! [`saga`] for the structural argument.
//!
//! ## Scope (§6.9 "What Phase 7 does not build")
//!
//! Pure logic over `brokkr-core` and `brokkr-crypto` — no FFI of its own, no `unsafe`, no
//! network or disk I/O (the store is in-memory). It offers a **recording surface**; it does
//! not reach into other crates to collect events (I-5), make model calls (I-6), or wire the
//! orchestrator (that is `brokkr-cli`, Phase 11). The [`event::TimestampAuthority`] seam is
//! defined with **no** production implementation; the later-emitting subsystems' event
//! variants are placed, their subsystems not built.

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
pub mod event;
pub mod saga;

pub use event::{
    AuditEvent, AuditRecord, AuthorizationOutcome, AuthorizationRecord, BarrierCrossing,
    CryptoGeneration, ErasureTombstone, GenerationSignature, GenomePromotion, ProposalRecord,
    RecordedInput, TimestampAuthority, TimestampError, TimestampToken, Timestamping,
};
pub use saga::{ChainStatus, Saga, SagaError, SignedExport, SubjectDatum};
