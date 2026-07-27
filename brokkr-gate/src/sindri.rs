//! SINDRI — the Costimulation Gate, at the Phase-4 scope placed by Architecture Rev 1.3.
//!
//! [`Sindri`] implements [`CostimulationGate::evaluate`] and **nothing that mints**. The
//! provided `authorize` in `brokkr-core` is the sole minter of [`AuthorizedAction`], via a
//! module-private `mint` SINDRI cannot reach. This is I-1 at its strongest point: the
//! worst SINDRI can do is wrongly deny.

use crate::resolver::KeyResolver;
use brokkr_core::crypto::Attestation;
use brokkr_core::gate::{Action, AnergyReason, CostimulationGate};
use brokkr_core::ids::Timestamp;
use brokkr_core::intent::{AttenuationError, IntentProvenanceChain};
use brokkr_crypto::DualPublicKey;
use brokkr_intent::{IntentError, Skuld};

/// The costimulation gate. Generic over the key-resolution seam ([`KeyResolver`]) so it
/// does not know whether a key came from a declared registry (Option B) or a certified
/// attestation (Option A) — that ignorance is deliberate (§6.4.1). Generic rather than
/// boxed: the resolver type is fixed at construction and dispatch is static (zero-cost);
/// no heterogeneous resolvers are needed at runtime, so `dyn` indirection would buy
/// nothing.
///
/// ## Why `now` is held in state
///
/// The committed [`CostimulationGate::evaluate`] signature is
/// `evaluate(&self, identity, chain, action)` — it carries **no** `now`. But freshness
/// (OQGF-M-14) must be checked, and Rev 1.3 §6.4 requires the current time to be a
/// **parameter, never a wall-clock read**. The only way to satisfy both, given the
/// committed trait, is to inject the evaluation time at construction. SINDRI therefore
/// holds `now` and threads it to [`Skuld::verify_chain_public`]; it never reads a clock.
/// The caller (the Phase-11 orchestrator) constructs a `Sindri` with the current time per
/// evaluation. This is a deviation from the §6.4 mermaid, which *illustrates*
/// `evaluate(identity, chain, action, now)`; the committed trait is authoritative and the
/// mermaid is illustrative (as Rev 1.2's `authorize` sketch was). See the phase report.
pub struct Sindri<R: KeyResolver> {
    resolver: R,
    /// The evaluation time, supplied by the caller at construction. Never a wall-clock
    /// read (OQGF-M-14 freshness is a parameter, Rev 1.3 §6.4).
    now: Timestamp,
}

impl<R: KeyResolver> Sindri<R> {
    /// Construct a gate over a resolver and an evaluation time. `now` is the caller's
    /// current time; a fresh `Sindri` (or an updated `now`) is used per evaluation.
    pub fn new(resolver: R, now: Timestamp) -> Self {
        Self { resolver, now }
    }

    /// Signal 1 — identity (OQGF-M-1), per Rev 1.3 §6.4. Two requirements, either failure
    /// yields [`AnergyReason::IdentityUnverified`]:
    ///
    /// - **Resolution:** `identity.subject` resolves to a declared root of trust. A subject
    ///   that is not declared confers nothing (the architectural-anergy property of M-11).
    /// - **Binding:** the presented identity is the identity the chain's cryptography
    ///   actually proves possession for — the final entry's `hop_identity.subject` for a
    ///   chain with hops, or `root.principal` for a root-only chain. Without the binding, a
    ///   declared identity A could be presented alongside a chain whose hops are all B, and
    ///   the two would never be connected. Signal 2 supplies the possession proof.
    ///
    /// The attestation's own `signatures` field is deliberately **not** verified here:
    /// Rev 1.3 §6.4 drops that check as redundant with Signal 2 (which proves possession by
    /// dual-family signature), and the committed types define no attestation signed content.
    fn signal_1(
        &self,
        identity: &Attestation,
        chain: &IntentProvenanceChain,
    ) -> Result<(), AnergyReason> {
        // (a) Resolution: is this subject a declared root of trust?
        if self.resolver.resolve(identity).is_none() {
            return Err(AnergyReason::IdentityUnverified);
        }
        // (b) Binding: does the presented identity match the hop the chain proves?
        let bound_subject = match chain.entries().last() {
            Some(last) => &last.hop_identity.subject, // chain with hops
            None => &chain.root().principal,          // root-only chain
        };
        if identity.subject != *bound_subject {
            return Err(AnergyReason::IdentityUnverified);
        }
        Ok(())
    }

    /// Signal 2 — the Intent Provenance Chain (OQGF-M-8/M-9/M-14), per Rev 1.3 §6.4.
    /// Resolves the root's key (`root.principal`) and every hop's key through the resolver,
    /// then verifies the chain against those public roots of trust with
    /// [`Skuld::verify_chain_public`]. A root or hop that does not resolve yields
    /// [`AnergyReason::IdentityUnverified`] (we resolve fully and never pass a short slice,
    /// so `HopKeyMissing` is unreachable here — though it is still mapped, fail-closed).
    fn signal_2(&self, chain: &IntentProvenanceChain) -> Result<(), AnergyReason> {
        let root = chain.root();
        let entries = chain.entries();

        // The root carries a SubjectId, not an Attestation.
        let root_pub = self
            .resolver
            .resolve_subject(&root.principal)
            .ok_or(AnergyReason::IdentityUnverified)?;

        // Own each hop key so we can build the &[&DualPublicKey] slice the verifier wants.
        let mut hop_pubs: Vec<DualPublicKey> = Vec::with_capacity(entries.len());
        for entry in entries {
            let key = self
                .resolver
                .resolve(&entry.hop_identity)
                .ok_or(AnergyReason::IdentityUnverified)?;
            hop_pubs.push(key);
        }
        let hop_refs: Vec<&DualPublicKey> = hop_pubs.iter().collect();

        // Freshness (`self.now`) is threaded here — never a wall-clock read.
        Skuld
            .verify_chain_public(root, entries, &root_pub, &hop_refs, self.now)
            .map_err(map_intent_error)
    }
}

/// Map the chain verifier's [`IntentError`] to an [`AnergyReason`], **exactly** per the
/// Rev 1.3 §6.4 anergy-mapping table. `WouldBroaden` maps to `ChainInvalid`, not
/// `OutOfScope`: a reconstructed chain whose entries broaden is an **integrity** failure of
/// the chain itself, not a statement about the action.
fn map_intent_error(e: IntentError) -> AnergyReason {
    match e {
        IntentError::HopKeyMissing { .. } => AnergyReason::IdentityUnverified,
        IntentError::Attenuation(AttenuationError::Expired) => AnergyReason::ChainExpired,
        IntentError::Attenuation(AttenuationError::WouldBroaden) => AnergyReason::ChainInvalid,
        IntentError::RootSignatureInvalid => AnergyReason::ChainInvalid,
        IntentError::EntrySignatureInvalid { .. } => AnergyReason::ChainInvalid,
        IntentError::BrokenLink { .. } => AnergyReason::ChainInvalid,
        // `Backend` is produced by SKULD only while *signing*, never by
        // `verify_chain_public`, so this arm is unreachable in practice. It is mapped
        // fail-closed to `ChainInvalid` anyway: an unexpected verifier error denies, never
        // grants. (Deferred conjuncts 3-4 own `OutOfScope`/`InvariantViolated`; this arm
        // must never reach for either.)
        IntentError::Backend => AnergyReason::ChainInvalid,
    }
}

impl<R: KeyResolver> CostimulationGate for Sindri<R> {
    /// The verdict. `Ok(())` grants (the provided `authorize` mints); `Err(reason)` yields
    /// architectural anergy. Signals 1 and 2 are enforced here (Rev 1.3 Phase-4 scope).
    ///
    /// `_action` is unused at Phase 4: conjuncts 3 (action-in-scope) and 4
    /// (action-respects-invariants) are **DEFERRED** under the Deferred-Conjunct Deadline
    /// (Rev 1.3 §6.4). They SHALL be enforced by SINDRI before the executor is wired at
    /// Phase 11, once REGIN (Phase 5) supplies the action-to-capability binding and the
    /// invariant-evaluator seam. Building nothing for them here is why
    /// [`AnergyReason::OutOfScope`] and [`AnergyReason::InvariantViolated`] are unreachable
    /// from this method by construction — no code path below constructs either.
    fn evaluate(
        &self,
        identity: &Attestation,
        chain: &IntentProvenanceChain,
        _action: &Action,
    ) -> Result<(), AnergyReason> {
        self.signal_1(identity, chain)?;
        self.signal_2(chain)?;
        // Conjuncts 3 and 4 land here, before Phase 11 (Deferred-Conjunct Deadline, §6.4).
        Ok(())
    }
}
