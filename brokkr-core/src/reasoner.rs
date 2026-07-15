//! MÍMIR — the advisory reasoner (untrusted), and the [`ClearedContext`] type that
//! makes an ungoverned context unable to reach a model (I-12).

use crate::barrier::{BarrierVerdict, Destination};
use crate::gate::Action;
use crate::ids::{HopId, ModelEndpointId};
use crate::intent::IntentScope;
use alloc::string::String;

/// The working context BROKKR would ship to a model. Untrusted, and — until
/// cleared — unable to reach [`Reasoner::propose`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub payload: String,
}

/// A context that has passed the barrier and may be handed to a model.
///
/// **I-12 — an ungoverned context cannot reach a model.** This type has **no
/// public constructor**. It is minted only inside [`ContextClearance::clear`], the
/// provided method below, which BIFRÖST (Phase 8.5) implements. This is the same
/// structural device as `AuthorizedAction`, pointed at the model's *input*.
///
/// The following does not compile — `inner` is private:
///
/// ```compile_fail,E0616
/// use brokkr_core::reasoner::{ClearedContext, Context};
/// let _ = ClearedContext { inner: Context { payload: "src".into() } };
/// // E0616: field `inner` of struct `ClearedContext` is private
/// ```
///
/// And a raw [`Context`] cannot be passed where a [`ClearedContext`] is required:
///
/// ```compile_fail,E0308
/// use brokkr_core::reasoner::{Reasoner, Context};
/// use brokkr_core::intent::IntentScope;
/// fn feed(r: &dyn Reasoner, raw: Context, scope: &IntentScope) {
///     let _ = r.propose(&raw, scope); // E0308: expected `&ClearedContext`, found `&Context`
/// }
/// ```
pub struct ClearedContext {
    inner: Context,
}

impl ClearedContext {
    /// Module-private. The only caller is [`ContextClearance::clear`].
    fn mint(inner: Context) -> Self {
        Self { inner }
    }

    /// The cleared context, for the reasoner.
    pub fn get(&self) -> &Context {
        &self.inner
    }
}

/// A proposed action emitted by the advisory reasoner. Untrusted; carries no
/// authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub action: Action,
    pub rationale: String,
    pub hop: HopId,
}

error_enum! {
    /// Errors from the reasoner backend (Phase 10).
    pub enum ReasonerError {
        Backend => "reasoner backend error",
        UnregisteredEndpoint => "reasoner endpoint is not registered in REGIN",
    }
}

/// The core seam BIFRÖST (Phase 8.5) implements. Its provided
/// [`clear`](Self::clear) is the **only** minter of [`ClearedContext`], mirroring
/// BROKKR-ARCH 6.10. An implementor supplies only the barrier decision
/// ([`evaluate_context`](Self::evaluate_context)); it cannot mint a
/// [`ClearedContext`] itself.
pub trait ContextClearance: Send + Sync {
    /// Evaluate an outbound context against a destination. Deny/Quarantine block;
    /// Allow/AcceptedRisk proceed (AcceptedRisk keeps its finding visible
    /// elsewhere — AMD-006).
    fn evaluate_context(&self, ctx: &Context, dest: &Destination) -> BarrierVerdict;

    /// Clear a context for the reasoner. Mints a [`ClearedContext`] only on a
    /// proceed verdict; otherwise returns the blocking verdict.
    fn clear(&self, ctx: Context, dest: &Destination) -> Result<ClearedContext, BarrierVerdict> {
        match self.evaluate_context(&ctx, dest) {
            BarrierVerdict::Allow | BarrierVerdict::AcceptedRisk { .. } => {
                Ok(ClearedContext::mint(ctx))
            }
            blocking => Err(blocking),
        }
    }
}

/// The advisory reasoner (MÍMIR, Phase 10). Model-agnostic behind this trait; the
/// trust path never consults it.
///
/// **I-12** — [`propose`](Self::propose) takes a `&ClearedContext`, never a raw
/// [`Context`].
pub trait Reasoner: Send + Sync {
    /// The registered endpoint this reasoner speaks to (REGIN). A `Reasoner` is
    /// meaningless against an unregistered endpoint.
    fn endpoint(&self) -> &ModelEndpointId;

    /// Propose one action, given the *cleared* context and the current attenuated
    /// scope — never more authority than the hop holds.
    fn propose(&self, ctx: &ClearedContext, scope: &IntentScope)
    -> Result<Proposal, ReasonerError>;
}
