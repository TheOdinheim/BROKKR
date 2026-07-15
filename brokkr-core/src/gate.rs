//! SINDRI — the Costimulation Gate (OQGF-M-11), and the [`AuthorizedAction`] type
//! that is the structural heart of BROKKR (I-1).

use crate::crypto::Attestation;
use crate::ids::ToolId;
use crate::intent::IntentProvenanceChain;
use alloc::string::String;

/// A concrete proposed action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub tool: ToolId,
    pub detail: String,
}

/// Why a costimulation was refused (architectural anergy, AMD-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnergyReason {
    /// Signal 1 (identity) did not verify (OQGF-M-1).
    IdentityUnverified,
    /// Signal 2 (intent provenance chain) did not verify (OQGF-M-8).
    ChainInvalid,
    /// The action lies outside the current attenuated scope.
    OutOfScope,
    /// The action violates an accumulated invariant (OQGF-M-10).
    InvariantViolated,
    /// The chain has expired (OQGF-M-14).
    ChainExpired,
}

/// Proof that an action passed the costimulation gate.
///
/// **I-1 — Ungoverned action is impossible.** This type has **no public
/// constructor**. It is minted only inside [`CostimulationGate::authorize`], the
/// provided method below, via a module-private `mint`. The executor accepts
/// nothing else, so there is no code path by which a tool executes without one.
///
/// The following does not compile — `action` is private and there is no
/// constructor:
///
/// ```compile_fail,E0616
/// use brokkr_core::gate::{Action, AuthorizedAction};
/// use brokkr_core::ids::ToolId;
/// let a = Action { tool: ToolId::new("write"), detail: "f".into() };
/// let _ = AuthorizedAction { action: a }; // E0616: field `action` of struct `AuthorizedAction` is private
/// ```
///
/// Nor can the minter be called from outside the crate:
///
/// ```compile_fail,E0624
/// use brokkr_core::gate::{Action, AuthorizedAction};
/// use brokkr_core::ids::ToolId;
/// let a = Action { tool: ToolId::new("write"), detail: "f".into() };
/// let _ = AuthorizedAction::mint(a); // E0624: associated function `mint` is private
/// ```
///
/// And a granted authorization cannot be duplicated outside the gate —
/// `AuthorizedAction` derives neither `Clone` nor `Copy`, so even after obtaining one
/// by the sanctioned path there is no `.clone()`:
///
/// ```compile_fail,E0599
/// use brokkr_core::gate::{Action, AnergyReason, AuthorizationDecision, CostimulationGate};
/// use brokkr_core::crypto::Attestation;
/// use brokkr_core::intent::IntentProvenanceChain;
/// struct G;
/// impl CostimulationGate for G {
///     fn evaluate(&self, _i: &Attestation, _c: &IntentProvenanceChain, _a: &Action)
///         -> Result<(), AnergyReason> { Ok(()) }
/// }
/// fn dup(g: &G, id: &Attestation, ch: &IntentProvenanceChain, a: Action) {
///     if let AuthorizationDecision::Granted(authorized) = g.authorize(id, ch, a) {
///         let _copy = authorized.clone(); // E0599: no method named `clone` found
///     }
/// }
/// ```
pub struct AuthorizedAction {
    action: Action,
}

impl AuthorizedAction {
    /// Module-private. The only caller is [`CostimulationGate::authorize`].
    fn mint(action: Action) -> Self {
        Self { action }
    }

    /// The authorized action, for the executor.
    pub fn action(&self) -> &Action {
        &self.action
    }
}

/// The gate's decision. `Granted` wraps an [`AuthorizedAction`], which external
/// code cannot construct — so `Granted` cannot be forged outside the gate.
pub enum AuthorizationDecision {
    Granted(AuthorizedAction),
    Anergy { reason: AnergyReason },
}

/// Every privileged tool call passes here. It contains no model and exposes no
/// channel to one.
///
/// An implementor (SINDRI, Phase 4) supplies only [`evaluate`](Self::evaluate) —
/// the verdict logic — which **cannot mint an [`AuthorizedAction`]**. The provided
/// [`authorize`](Self::authorize) is the sole minter in the entire workspace.
/// Overriding `authorize` gains an implementor nothing: `mint` is private to this
/// module, so an override can only ever return `Anergy` (fail-safe).
pub trait CostimulationGate: Send + Sync {
    /// Verdict logic. `Ok(())` grants; `Err(reason)` yields anergy. Both Signal 1
    /// (identity) and Signal 2 (chain) must be checked here (OQGF-M-11).
    fn evaluate(
        &self,
        identity: &Attestation,
        chain: &IntentProvenanceChain,
        action: &Action,
    ) -> Result<(), AnergyReason>;

    /// The only path to an [`AuthorizedAction`].
    fn authorize(
        &self,
        identity: &Attestation,
        chain: &IntentProvenanceChain,
        action: Action,
    ) -> AuthorizationDecision {
        match self.evaluate(identity, chain, &action) {
            Ok(()) => AuthorizationDecision::Granted(AuthorizedAction::mint(action)),
            Err(reason) => AuthorizationDecision::Anergy { reason },
        }
    }
}
