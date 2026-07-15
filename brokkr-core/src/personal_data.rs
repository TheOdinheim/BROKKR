//! AMD-009 (OQGF-P-11) — the core VALUE types of the personal-data lifecycle: the
//! declared [`Purpose`] and [`RetentionPeriod`].
//!
//! **Value types only.** The erasure *mechanism* — crypto-shredding, per-subject
//! quantum-safe key destruction, the erasure tombstone — is **bucket C**: it lives in
//! `brokkr-crypto` (Phase 2) and `brokkr-audit` (Phase 7). None of it is here. There is
//! no key-handle type and no erasure logic in this file.
//!
//! `classification.rs` is **not** touched. The personal-data classification dimension
//! composes with the existing `Classification` at the barrier (Phase 6); these two value
//! types are what a Personal-Data Tag carries (OQGF-P-11.3, OQGF-P-11.4).

use alloc::string::String;
use core::time::Duration;

/// The declared reason personal data was collected (OQGF-P-11.3). Recorded on the
/// Boundary Custody Record (Phase 6) or the AIBOM (Phase 5); this is the value type it
/// carries. Personal data may be used only for its declared `Purpose`; a material change
/// is a fresh DAP decision (the enforcement is downstream, not here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Purpose {
    pub description: String,
}

/// The declared span, tied to a [`Purpose`], for which personal data may be held before
/// erasure (OQGF-P-11.4). A value type; the retention sweep that *fires* erasure, and the
/// erasure itself, are Phase 7 / Phase 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPeriod {
    pub duration: Duration,
}
