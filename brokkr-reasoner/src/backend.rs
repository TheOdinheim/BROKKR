//! The model-backend seam (Task 1a).
//!
//! BROKKR has no model of its own (I-6). The model API call is therefore a **seam** — a trait
//! injected into [`Mimir`](crate::Mimir) at construction. Phase 10 defines the seam and supplies
//! test doubles; a production backend (which makes the real network call, through BIFRÖST) is a
//! deployment concern, out of scope.
//!
//! **What the backend receives, and what it does not.** It receives the cleared context's
//! **payload** (text) and the **current attenuated scope** — and *nothing else*:
//!
//! - **not the [`ClearedContext`](brokkr_core::reasoner::ClearedContext)** — that is a governance
//!   token; handing it to a model backend would let the backend assert clearance to something
//!   downstream. The model gets text, not authority.
//! - **no channel to any gate's decision** — the trait returns only a proposed [`Action`] and a
//!   rationale. There is no `AuthorizedAction`, no `BarrierVerdict`, no boolean a rationale could
//!   flip. A model cannot reach a gate through this interface, because the interface has no gate
//!   in it.

use brokkr_core::gate::Action;
use brokkr_core::intent::IntentScope;

/// What the backend proposes: a concrete [`Action`] and an advisory rationale. **Untrusted** — the
/// reasoner wraps it as a [`Proposal`](brokkr_core::reasoner::Proposal), which carries no authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendProposal {
    pub action: Action,
    pub rationale: String,
}

/// A backend failure. The reasoner maps **any** backend error to
/// [`ReasonerError::Backend`](brokkr_core::reasoner::ReasonerError::Backend); the detail is for
/// logs, not for the trust path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendError {
    pub detail: String,
}

impl core::fmt::Display for BackendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "reasoner backend error: {}", self.detail)
    }
}

impl std::error::Error for BackendError {}

/// The model call, as a seam. Given the cleared **payload** (text) and the current attenuated
/// **scope**, return a proposed action and rationale, or a backend error.
///
/// The signature is the structural guarantee of two of §6.1's binding rules: the backend sees only
/// `&str` and `&IntentScope` (never the `ClearedContext`, never a gate), and returns only a
/// `BackendProposal` (never an `AuthorizedAction`, never a verdict).
pub trait ModelBackend: Send + Sync {
    fn propose(&self, payload: &str, scope: &IntentScope) -> Result<BackendProposal, BackendError>;
}
