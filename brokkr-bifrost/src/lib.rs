//! # brokkr-bifrost (BIFRÖST)
//!
//! **The guarded crossing to a reasoner** (§6.10). Rev 1.2 wrote that closing the reasoner hole
//! needed *"not machinery … the wire"*; Rev 1.14 gave a [`Context`] the custody facts, and this
//! crate is the wire: it assembles a [`BoundaryFlow::Egress`] from those facts and hands it to
//! **HÚÐ's** egress gate. **One gate, one logic** — BIFRÖST re-implements no egress condition
//! (§6.6). It reaches HÚÐ through the committed [`brokkr_core::barrier::Barrier`] trait, of which
//! `brokkr_barrier::Huth` is the implementation it holds.
//!
//! ## The central property — the channel decides whether the claim is reachable
//!
//! A crossing's **effective authorization** is the lesser of the endpoint's declared ceiling and
//! what the *actually negotiated* channel can carry:
//! `min(endpoint.max_classification, ChannelStrength::from_group(negotiated).permits())`. A
//! handshake that lands on a **classical** group collapses the effective level to **Public**
//! regardless of the endpoint's declared ceiling, and above-Public context is denied. HÚÐ's egress
//! condition 8 performs this collapse (using its injected endpoint-ceiling resolver); BIFRÖST
//! supplies the negotiated group on the flow's [`Destination::Reasoner`] and holds a matching copy
//! of the ceiling only to *record* the effective level, never to re-decide it.
//!
//! ## Four structural facts, no runtime theatre
//!
//! - **mTLS is a type-level guarantee (OQGF-M-5).** `brokkr_core::genome::ModelEndpoint::client_cert`
//!   is a **required** field, not an `Option`. An endpoint that cannot present a client certificate
//!   is not representable, so it cannot be registered and cannot be reached — *"just use the public
//!   API with a bearer token"* is the absence of a constructor, not a policy. BIFRÖST therefore adds
//!   **no** runtime mTLS check: there is nothing to check that the type does not already forbid.
//! - **BIFRÖST mints nothing.** It implements [`ContextClearance::evaluate_context`] (returning a
//!   [`BarrierVerdict`]); it never constructs a [`ClearedContext`], whose only minter is core's
//!   provided [`ContextClearance::clear`] (I-12).
//! - **BIFRÖST never reads the payload.** The classification is *declared* on the `Context`; deriving
//!   it from content is Heuristic (OQGF-I-12), and this is a deterministic path. No code here inspects
//!   `Context::payload`.
//! - **BIFRÖST verifies BCRs; it does not issue them.** Issuance derives the authorized destinations
//!   from REGIN's signed classification policy (§6.6) and belongs to the assembling party, not here.
//!   A `Context` whose `bcr` is `None` above Public is denied by HÚÐ's condition 2.
//!
//! ## Scope (§6.10 — what Phase 8.5 does NOT build)
//!
//! Pure logic over `brokkr-core` and `brokkr-barrier` — no FFI, no `unsafe`, no network I/O. The
//! TLS handshake, real mTLS, and the negotiated-group readback are **inputs** (the negotiated group
//! rides on `Destination::Reasoner`); there are no sockets. No model call (I-6) — BIFRÖST clears a
//! context so MÍMIR (Phase 10) may use it. The crossing record is produced as a **value**; SAGA
//! recording is Phase 11.

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

use brokkr_barrier::{AcceptanceResolver, EndpointCeiling, Huth};
use brokkr_core::barrier::{Barrier, BarrierVerdict, BoundaryFlow, Destination};
use brokkr_core::classification::{
    ChannelStrength, Classification, NamedGroup, effective_authorization,
};
use brokkr_core::ids::{ModelEndpointId, Timestamp};
use brokkr_core::reasoner::{Context, ContextClearance};

/// Raw dual-family public bytes `(ml_dsa_65, slh_dsa_shake_192s)` — the same shape HÚÐ verifies
/// BCR and DAP signatures under.
pub type KeyBytes = (Vec<u8>, Vec<u8>);

/// The material of a recorded crossing (§6.10, OQGF-I-13). Produced as a **value**; Phase 11
/// hands it to SAGA (which signs and appends it). BIFRÖST does not depend on `brokkr-audit`.
///
/// It names **what was agreed**, not what was offered: the negotiated group, the
/// [`ChannelStrength`] derived from it, the endpoint, the effective ceiling the channel actually
/// permits, the context's declared classification, and the barrier's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossingRecord {
    pub endpoint: ModelEndpointId,
    /// The actually-negotiated key-exchange group (a fact, not an offer).
    pub negotiated: NamedGroup,
    /// Derived from `negotiated` — never from an offer list.
    pub strength: ChannelStrength,
    /// `min(endpoint ceiling, channel strength)` — the level the crossing could actually carry.
    pub effective: Classification,
    /// The context's DECLARED classification (never inferred from the payload).
    pub classification: Classification,
    pub verdict: BarrierVerdict,
}

/// BIFRÖST — the guarded crossing.
///
/// Holds HÚÐ (`Huth`, the gate it delegates to) and a copy of the endpoint-ceiling resolver (for
/// the crossing record's effective level — the **same data** HÚÐ gates on, cloned at construction
/// so it cannot drift). Both are **configuration**, fixed at construction.
///
/// **The current time is not held (I-13).** `evaluate_context` takes the evaluation time as a
/// parameter of the evaluating call and passes it straight to HÚÐ, which checks BCR expiry
/// (OQGF-I-9) against it. A gate that stored the time would check an aging expiry against an
/// equally aging present — the check passing while enforcing nothing; the original build did
/// exactly that, storing the time behind a mutex and reading it back at the barrier call, which
/// was the SINDRI held-clock defect a second time (RISK-2026-0006). The struct therefore holds no
/// clock and needs no interior mutability.
///
/// **BIFRÖST cannot mint a [`ClearedContext`] (I-12).** Its only route to one is core's provided
/// [`ContextClearance::clear`]; the type has no public constructor, so this does not compile
/// (constructing a struct literal with a private field is `E0451`):
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
/// let _ = ClearedContext { inner: ctx }; // E0451: field `inner` is private
/// ```
pub struct Bifrost<C: EndpointCeiling + Clone, A: AcceptanceResolver> {
    huth: Huth<C, A>,
    ceiling: C,
}

impl<C: EndpointCeiling + Clone, A: AcceptanceResolver> Bifrost<C, A> {
    /// Construct a crossing. `bcr_key`/`dap_key` are the dual-family public bytes HÚÐ verifies BCR
    /// and acceptance signatures under; `ceiling` resolves an endpoint to its declared ceiling
    /// (REGIN's in production); `acceptances` is the AMD-006 acceptance register seam. HÚÐ is built
    /// from a **clone** of `ceiling`, so the gate and the record read the same ceiling data. There
    /// is **no** `now` here — the evaluation time arrives per call (I-13).
    pub fn new(bcr_key: KeyBytes, dap_key: KeyBytes, ceiling: C, acceptances: A) -> Self {
        Bifrost {
            huth: Huth::new(bcr_key, dap_key, ceiling.clone(), acceptances),
            ceiling,
        }
    }

    /// The material of a crossing to a reasoner (Task 5). Returns `None` for a non-reasoner
    /// destination (only a reasoner crossing has a negotiated group). The effective level is the
    /// same collapse HÚÐ gated on: `min(endpoint ceiling, channel strength)`; an endpoint the
    /// resolver does not know is treated as `Public` (fail-closed, matching HÚÐ's deny).
    pub fn crossing_record(
        &self,
        dest: &Destination,
        classification: Classification,
        verdict: &BarrierVerdict,
    ) -> Option<CrossingRecord> {
        match dest {
            Destination::Reasoner {
                endpoint,
                negotiated,
            } => {
                let strength = ChannelStrength::from_group(*negotiated);
                let endpoint_max = self
                    .ceiling
                    .resolve(endpoint)
                    .unwrap_or(Classification::Public);
                Some(CrossingRecord {
                    endpoint: endpoint.clone(),
                    negotiated: *negotiated,
                    strength,
                    effective: effective_authorization(endpoint_max, strength),
                    classification,
                    verdict: verdict.clone(),
                })
            }
            Destination::LocalPath(_) | Destination::Network { .. } => None,
        }
    }
}

/// **One gate, one logic (§6.6).** `evaluate_context` builds the egress flow from the context's
/// custody facts and the crossing's destination, then delegates the decision to HÚÐ. It
/// **re-implements no egress condition** — the effective-ceiling collapse (condition 8), the BCR
/// checks, and the personal-data rule are all HÚÐ's. It **does not read `payload`** (a deterministic
/// gate never derives classification from content, OQGF-I-12). `now` is the **call parameter**
/// (I-13), threaded straight to HÚÐ for the BCR-expiry check; the negotiated group reaches HÚÐ on
/// `dest`'s [`Destination::Reasoner`].
///
/// **BIFRÖST does not override [`ContextClearance::clear`]** — core's provided `clear` is the sole
/// minter of [`brokkr_core::reasoner::ClearedContext`] (I-12), and BIFRÖST supplies only the verdict
/// half. Nothing in this crate constructs a `ClearedContext`.
impl<C: EndpointCeiling + Clone, A: AcceptanceResolver> ContextClearance for Bifrost<C, A> {
    fn evaluate_context(
        &self,
        ctx: &Context,
        dest: &Destination,
        now: Timestamp,
    ) -> BarrierVerdict {
        let flow = BoundaryFlow::Egress {
            datum: ctx.datum.clone(),
            classification: ctx.classification,
            personal: ctx.personal.clone(),
            destination: dest.clone(),
            bcr: ctx.bcr.clone(),
        };
        self.huth.evaluate(&flow, now)
    }
}
