//! MÍMIR — the advisory reasoner (untrusted), and the [`ClearedContext`] type that
//! makes an ungoverned context unable to reach a model (I-12).

use crate::barrier::{BarrierVerdict, BoundaryCustodyRecord, Destination, PersonalDataTag};
use crate::classification::Classification;
use crate::gate::Action;
use crate::ids::{DatumRef, HopId, ModelEndpointId, Timestamp};
use crate::intent::IntentScope;
use alloc::string::String;

/// The working context BROKKR would ship to a model. Untrusted, and — until
/// cleared — unable to reach [`Reasoner::propose`].
///
/// **Not a bag of text — a payload plus the custody facts the Barrier decides on**
/// (§6.6, OQGF-I-9/I-10). The four custody fields mirror what a
/// [`BoundaryFlow::Egress`](crate::barrier::BoundaryFlow) needs **minus the
/// destination** (which is the reasoner endpoint passed to
/// [`ContextClearance::clear`]), because Phase 8.5 builds an egress flow out of
/// exactly this.
///
/// **The facts ride on the context, not beside it.** A classification passed to
/// `clear` as a separate argument could be passed wrongly, drift out of sync, or
/// come from a different caller than the one that assembled the material. Carried on
/// the type, the context *is* classified — the same reasoning that put the
/// personal-data tag on the flow (Rev 1.7) rather than leaving it to a parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub payload: String,
    /// Which datum this is, so a custody record can be matched to it (OQGF-I-9).
    pub datum: DatumRef,
    /// **Declared** by whoever assembled the context — the maximum classification of
    /// the material that went into it — and **never inferred from the payload.**
    /// Inferring sensitivity from unlabeled content is what OQGF-I-12 designates
    /// Heuristic, and a Deterministic Gate SHALL NOT take its input from a heuristic
    /// one; the content sentinel stays a backstop, never the gate's input.
    pub classification: Classification,
    /// The personal-data dimension, orthogonal to `classification` (OQGF-P-11.1) — a
    /// context can be Public **and** personal. It travels with the context so Phase 8.5
    /// does not short-circuit a Public personal context.
    pub personal: Option<PersonalDataTag>,
    /// The signed custody record. **Required above Public** (OQGF-I-9); `None` for
    /// Public material.
    pub bcr: Option<BoundaryCustodyRecord>,
}

/// A context that has passed the barrier and may be handed to a model.
///
/// **I-12 — an ungoverned context cannot reach a model.** This type has **no
/// public constructor**. It is minted only inside [`ContextClearance::clear`], the
/// provided method below, which BIFRÖST (Phase 8.5) implements. This is the same
/// structural device as `AuthorizedAction`, pointed at the model's *input*.
///
/// The following does not compile — `inner` is private (the `Context` is built in full
/// so the *only* error is the private field, not a missing-fields error). Constructing a
/// struct literal with a private field is **E0451** — not E0616, which is private-field
/// *access* (`value.inner`); the pre-Rev-1.14 annotation said E0616 and was never enforced
/// by rustdoc (which only checks that compilation fails), corrected here to the code the
/// compiler actually emits, verified by standalone compile:
///
/// ```compile_fail,E0451
/// use brokkr_core::reasoner::{ClearedContext, Context};
/// use brokkr_core::classification::Classification;
/// use brokkr_core::ids::DatumRef;
/// let ctx = Context {
///     payload: "src".into(),
///     datum: DatumRef::new("d"),
///     classification: Classification::Public,
///     personal: None,
///     bcr: None,
/// };
/// let _ = ClearedContext { inner: ctx };
/// // E0451: field `inner` of struct `ClearedContext` is private
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
///
/// **Red-team 14A, attack 2.2 — an overriding `clear` still cannot mint a `ClearedContext`.** As
/// with the gate, `clear` is a provided method an implementor *may* override, but `mint` is
/// module-private, so an override written outside `brokkr_core::reasoner` cannot construct a
/// `ClearedContext` and cannot return `Ok(cleared)` — it can only return the blocking verdict:
///
/// ```compile_fail,E0624
/// use brokkr_core::reasoner::{ClearedContext, Context, ContextClearance};
/// use brokkr_core::barrier::{BarrierVerdict, Destination};
/// use brokkr_core::ids::Timestamp;
/// struct EvilBifrost;
/// impl ContextClearance for EvilBifrost {
///     fn evaluate_context(&self, _c: &Context, _d: &Destination, _n: Timestamp) -> BarrierVerdict {
///         BarrierVerdict::Allow
///     }
///     // Override clear to always mint — impossible: `mint` is private.
///     fn clear(&self, ctx: Context, _d: &Destination, _n: Timestamp)
///         -> Result<ClearedContext, BarrierVerdict> {
///         Ok(ClearedContext::mint(ctx)) // E0624: `mint` is private
///     }
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
///
/// **I-13 — the current time is a call parameter, not construction state.** Omitting
/// `now` does not compile (wrong argument count). As with the gate, this proves the
/// *call site* supplies the time; it does not prove an implementor forwards it rather
/// than ignoring it and reading a stored clock (revision report):
///
/// ```compile_fail,E0061
/// use brokkr_core::reasoner::{Context, ContextClearance};
/// use brokkr_core::barrier::{BarrierVerdict, Destination};
/// use brokkr_core::ids::Timestamp;
/// struct C;
/// impl ContextClearance for C {
///     fn evaluate_context(&self, _c: &Context, _d: &Destination, _n: Timestamp) -> BarrierVerdict {
///         BarrierVerdict::Allow
///     }
/// }
/// fn call(c: &C, ctx: Context, dest: &Destination) {
///     // Missing `now`: E0061, this method takes 3 arguments but 2 were supplied.
///     let _ = c.clear(ctx, dest);
/// }
/// ```
pub trait ContextClearance: Send + Sync {
    /// Evaluate an outbound context against a destination. Deny/Quarantine block;
    /// Allow/AcceptedRisk proceed (AcceptedRisk keeps its finding visible
    /// elsewhere — AMD-006).
    ///
    /// **`now` is a parameter of the evaluating call, never construction state
    /// (I-13).** An implementor delegates the decision to
    /// [`Barrier::evaluate`](crate::barrier::Barrier::evaluate), whose signature
    /// *requires* a [`Timestamp`] — so without `now` here BIFRÖST could not call the
    /// barrier at all, leaving only a wall-clock read (forbidden) or a clock held at
    /// construction (I-13's defect: BCR expiry checked against a time that ages with
    /// the gate, passing while enforcing nothing).
    fn evaluate_context(&self, ctx: &Context, dest: &Destination, now: Timestamp)
    -> BarrierVerdict;

    /// Clear a context for the reasoner. Mints a [`ClearedContext`] only on a
    /// proceed verdict; otherwise returns the blocking verdict.
    ///
    /// **`now` is passed straight through to
    /// [`evaluate_context`](Self::evaluate_context) (I-13).** `clear` remains the sole
    /// minter of [`ClearedContext`] (I-12); threading the current time as an argument
    /// changes nothing about that — the type has no public constructor and this is its
    /// only mint site.
    fn clear(
        &self,
        ctx: Context,
        dest: &Destination,
        now: Timestamp,
    ) -> Result<ClearedContext, BarrierVerdict> {
        match self.evaluate_context(&ctx, dest, now) {
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
