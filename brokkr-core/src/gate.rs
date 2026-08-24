//! SINDRI — the Costimulation Gate (OQGF-M-11), and the [`AuthorizedAction`] type
//! that is the structural heart of BROKKR (I-1).

use crate::crypto::Attestation;
use crate::ids::{Timestamp, ToolId};
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
/// constructor. Constructing a struct literal with a private field is **E0451** — not
/// E0616, which is private-field *access* (`value.action`); the annotation said E0616
/// and rustdoc never enforced it (it only checks that compilation fails, not why),
/// corrected here to the code the compiler actually emits, verified by standalone
/// compile:
///
/// ```compile_fail,E0451
/// use brokkr_core::gate::{Action, AuthorizedAction};
/// use brokkr_core::ids::ToolId;
/// let a = Action { tool: ToolId::new("write"), detail: "f".into() };
/// let _ = AuthorizedAction { action: a };
/// // E0451: field `action` of struct `AuthorizedAction` is private
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
/// use brokkr_core::ids::Timestamp;
/// use brokkr_core::intent::IntentProvenanceChain;
/// struct G;
/// impl CostimulationGate for G {
///     fn evaluate(&self, _i: &Attestation, _c: &IntentProvenanceChain, _a: &Action, _n: Timestamp)
///         -> Result<(), AnergyReason> { Ok(()) }
/// }
/// fn dup(g: &G, id: &Attestation, ch: &IntentProvenanceChain, a: Action, now: Timestamp) {
///     if let AuthorizationDecision::Granted(authorized) = g.authorize(id, ch, a, now) {
///         let _copy = authorized.clone(); // E0599: no method named `clone` found
///     }
/// }
/// ```
///
/// **Red-team 14A, attack 1.2 — no `Default`.** `AuthorizedAction` derives nothing, so it has no
/// `Default::default()` that would mint an empty, ungoverned token:
///
/// ```compile_fail,E0599
/// let _ = brokkr_core::gate::AuthorizedAction::default(); // E0599: no `default` — not derived
/// ```
///
/// **Red-team 14A, attack 2.1 — an overriding `authorize` still cannot mint a `Granted`.** The
/// trait is *not* sealed; an implementor may override `authorize`. But `mint` is module-private, so
/// an override written outside `brokkr_core::gate` cannot construct an `AuthorizedAction` and so
/// cannot build `AuthorizationDecision::Granted(_)` — it can only ever return `Anergy`. Trying to
/// hand `Granted` an action does not compile (the tuple field wants an `AuthorizedAction`, which is
/// unconstructable here):
///
/// ```compile_fail,E0624
/// use brokkr_core::gate::{Action, AnergyReason, AuthorizationDecision, AuthorizedAction, CostimulationGate};
/// use brokkr_core::crypto::Attestation;
/// use brokkr_core::ids::Timestamp;
/// use brokkr_core::intent::IntentProvenanceChain;
/// struct EvilGate;
/// impl CostimulationGate for EvilGate {
///     fn evaluate(&self, _i: &Attestation, _c: &IntentProvenanceChain, _a: &Action, _n: Timestamp)
///         -> Result<(), AnergyReason> { Ok(()) }
///     // Override authorize to "always grant" — but there is no way to make the AuthorizedAction.
///     fn authorize(&self, _i: &Attestation, _c: &IntentProvenanceChain, action: Action, _n: Timestamp)
///         -> AuthorizationDecision {
///         AuthorizationDecision::Granted(AuthorizedAction::mint(action)) // E0624: `mint` is private
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
///
/// **I-13 — the current time is a call parameter, not construction state.** A caller
/// cannot invoke the gate without supplying `now`; omitting it does not compile
/// (wrong argument count). This proves the *call site* supplies the time; it does not
/// prove an implementor *forwards* it rather than ignoring it and reading a stored
/// value — that residual is per-crate review and the workspace grep, not core's type
/// system (see the revision report):
///
/// ```compile_fail,E0061
/// use brokkr_core::gate::{Action, AnergyReason, CostimulationGate};
/// use brokkr_core::crypto::Attestation;
/// use brokkr_core::ids::Timestamp;
/// use brokkr_core::intent::IntentProvenanceChain;
/// struct G;
/// impl CostimulationGate for G {
///     fn evaluate(&self, _i: &Attestation, _c: &IntentProvenanceChain, _a: &Action, _n: Timestamp)
///         -> Result<(), AnergyReason> { Ok(()) }
/// }
/// fn call(g: &G, id: &Attestation, ch: &IntentProvenanceChain, a: Action) {
///     // Missing `now`: E0061, this method takes 4 arguments but 3 were supplied.
///     let _ = g.authorize(id, ch, a);
/// }
/// ```
pub trait CostimulationGate: Send + Sync {
    /// Verdict logic. `Ok(())` grants; `Err(reason)` yields anergy. Both Signal 1
    /// (identity) and Signal 2 (chain) must be checked here (OQGF-M-11).
    ///
    /// **`now` is a parameter of the evaluating call, never construction state
    /// (I-13).** Signal 2's chain check enforces OQGF-M-14 freshness, and a gate that
    /// held the time at construction would compare an aging expiry against an equally
    /// aging present — the check passing while enforcing nothing. The current time is
    /// the one input that is wrong the instant after it is read, so it is supplied per
    /// call, not stored.
    fn evaluate(
        &self,
        identity: &Attestation,
        chain: &IntentProvenanceChain,
        action: &Action,
        now: Timestamp,
    ) -> Result<(), AnergyReason>;

    /// The only path to an [`AuthorizedAction`].
    ///
    /// **`now` is passed straight through to [`evaluate`](Self::evaluate) and used for
    /// nothing else here (I-13).** Threading it as an argument does not touch the
    /// sealed-minter guarantee (I-1): `mint` is module-private and `authorize` remains
    /// its only caller, so an override of `authorize` still cannot mint and can only
    /// ever return `Anergy`.
    fn authorize(
        &self,
        identity: &Attestation,
        chain: &IntentProvenanceChain,
        action: Action,
        now: Timestamp,
    ) -> AuthorizationDecision {
        match self.evaluate(identity, chain, &action, now) {
            Ok(()) => AuthorizationDecision::Granted(AuthorizedAction::mint(action)),
            Err(reason) => AuthorizationDecision::Anergy { reason },
        }
    }
}
