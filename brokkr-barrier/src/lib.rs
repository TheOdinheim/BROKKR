//! # brokkr-barrier (HÚÐ)
//!
//! The Barrier (AMD-007, §6.5): HÚÐ governs **the substance that crosses**, in both
//! directions. Identity governs the mover (SINDRI); intent governs the action (SKULD);
//! HÚÐ governs the data.
//!
//! - **Egress** ([`Huth`] via [`Barrier::evaluate`]) is a **Deterministic Gate** (OQGF-I-10
//!   inheriting OQGF-P-2): fail-closed, non-suppressible. It denies unless all nine §6.5
//!   conditions hold, each `Deny` carrying a [`BarrierFinding`] naming the `datum` and the
//!   [`BarrierCondition`] that failed. The only sanctioned way past a `Deny` is an AMD-006
//!   [`BarrierVerdict::AcceptedRisk`] — a **distinct verdict**, resolver-supplied and
//!   re-validated (finding match, gate, dual-family signature, expiry), with the finding
//!   preserved. There is no path from `Deny` to `Allow` (I-2).
//! - **Ingress** establishes provenance from a valid BCR; unprovenanced data into a
//!   Privileged Context is **quarantined, not denied** (OQGF-I-11); into a non-privileged
//!   context it is allowed. Personal data into a Privileged Context additionally needs a
//!   matching declared Purpose/Retention (OQGF-P-11.2).
//!
//! ## Seams and scope
//!
//! The endpoint ceiling (condition 8) and risk acceptances arrive through **injected
//! traits** ([`EndpointCeiling`], [`AcceptanceResolver`]), so **`brokkr-barrier` does not
//! depend on `brokkr-genome`** (I-5) and does not know where either answer came from. Pure
//! logic — no FFI, no `unsafe`, no I/O: registers, records, and acceptances are values
//! passed in. No model calls (I-6).
//!
//! What Phase 6 does **not** build (§6.5): `ContextClearance`/BIFRÖST (Phase 8.5), the
//! heuristic data-content sentinel and barrier-bypass detection (Phase 8), the persistent
//! append-only register and crossing records in Organ 5 (Phase 7). Phase 6 **decides**;
//! Phase 7 **records**.
//!
//! [`Barrier::evaluate`]: brokkr_core::barrier::Barrier::evaluate
//! [`BarrierFinding`]: brokkr_core::barrier::BarrierFinding
//! [`BarrierCondition`]: brokkr_core::barrier::BarrierCondition
//! [`BarrierVerdict::AcceptedRisk`]: brokkr_core::barrier::BarrierVerdict
//!
//! ## I-2 — a `Deny` has no path to `Allow`
//!
//! The Barrier returns `brokkr_core::barrier::BarrierVerdict`, whose `Deny` has no
//! conversion to `Allow` (proven on the type in `brokkr-core`). `brokkr-barrier` adds no
//! such path; this does not compile:
//!
//! ```compile_fail,E0599
//! use brokkr_core::barrier::{BarrierVerdict, BarrierFinding, BarrierCondition};
//! use brokkr_core::classification::Classification;
//! use brokkr_core::ids::DatumRef;
//! let d = BarrierVerdict::Deny {
//!     finding: BarrierFinding {
//!         datum: DatumRef::new("x"),
//!         condition: BarrierCondition::UnauthorizedDestination,
//!         classification: Classification::Secret,
//!         reason: "x".into(),
//!     },
//! };
//! let _allow = d.into_allow(); // E0599: no method named `into_allow`
//! ```

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
pub mod huth;
pub mod resolver;
pub mod uncontrolled;

pub use huth::Huth;
pub use resolver::{AcceptanceResolver, EndpointCeiling, InMemoryAcceptances, InMemoryCeiling};
pub use uncontrolled::{ReductionPosture, UncontrolledChannel, UncontrolledChannelRegister};
