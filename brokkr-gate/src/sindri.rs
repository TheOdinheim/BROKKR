//! SINDRI — the Costimulation Gate, at the Phase-4 scope placed by Architecture Rev 1.3.
//!
//! [`Sindri`] implements [`CostimulationGate::evaluate`] and **nothing that mints**. The
//! provided `authorize` in `brokkr-core` is the sole minter of [`AuthorizedAction`], via a
//! module-private `mint` SINDRI cannot reach. This is I-1 at its strongest point: the
//! worst SINDRI can do is wrongly deny.

use crate::resolver::{GenomeResolver, KeyResolver};
use brokkr_core::crypto::Attestation;
use brokkr_core::gate::{Action, AnergyReason, CostimulationGate};
use brokkr_core::ids::Timestamp;
use brokkr_core::intent::{AttenuationError, IntentProvenanceChain};
use brokkr_crypto::DualPublicKey;
use brokkr_intent::{IntentError, Skuld};

/// The costimulation gate. Generic over two resolution seams — the key resolver
/// ([`KeyResolver`], for Signal 2) and the genome resolver ([`GenomeResolver`], for the
/// action-in-scope and action-respects-invariants conjuncts) — so it does not know where
/// either kind of data came from; that ignorance is deliberate and is the migration path.
/// Generic rather than boxed: the resolver types are fixed at construction and dispatch is
/// static (zero-cost); no heterogeneous resolvers are needed at runtime, so `dyn` indirection
/// would buy nothing.
///
/// ## `now` arrives per call, and is never held (I-13)
///
/// The committed [`CostimulationGate::evaluate`] signature is
/// `evaluate(&self, identity, chain, action, now)` (Rev 1.15 §6.4): the current time is a
/// **parameter of the evaluating call**, and SINDRI threads it to
/// [`Skuld::verify_chain_public`] for the OQGF-M-14 freshness check. It is **not** stored.
/// A gate that held `now` at construction would compare an aging expiry against an equally
/// aging present — the check passing while enforcing nothing (I-13); the earlier design did
/// exactly that, and the freshness check was defeated for four phases (RISK-2026-0006).
/// **The resolver is configuration and is fixed at construction; the time is not.** SINDRI
/// never reads a wall clock — the Phase-11 orchestrator supplies the current time at each
/// call.
pub struct Sindri<R: KeyResolver, G: GenomeResolver> {
    resolver: R,
    genome_resolver: G,
}

impl<R: KeyResolver, G: GenomeResolver> Sindri<R, G> {
    /// Construct a gate over the key-resolution and genome-resolution seams. Both resolvers are
    /// configuration and are fixed here; the evaluation time is **not** held — it arrives per
    /// call (I-13).
    pub fn new(resolver: R, genome_resolver: G) -> Self {
        Self {
            resolver,
            genome_resolver,
        }
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
    ///
    /// `now` is the evaluating call's current time (I-13), threaded straight through to the
    /// freshness check; `signal_2` holds no clock of its own.
    fn signal_2(&self, chain: &IntentProvenanceChain, now: Timestamp) -> Result<(), AnergyReason> {
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

        // Freshness (`now`, supplied at the call) is threaded here — never held, never a
        // wall-clock read (I-13 / OQGF-M-14).
        Skuld
            .verify_chain_public(root, entries, &root_pub, &hop_refs, now)
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
        // grants. (Conjuncts 3-4 own `OutOfScope`/`InvariantViolated`; this arm produces
        // neither.)
        IntentError::Backend => AnergyReason::ChainInvalid,
    }
}

impl<R: KeyResolver, G: GenomeResolver> CostimulationGate for Sindri<R, G> {
    /// The verdict. `Ok(())` grants (the provided `authorize` mints); `Err(reason)` yields
    /// architectural anergy. All four conjuncts are enforced here, in order: Signal 1, Signal 2,
    /// action-in-scope, action-respects-invariants.
    fn evaluate(
        &self,
        identity: &Attestation,
        chain: &IntentProvenanceChain,
        action: &Action,
        now: Timestamp,
    ) -> Result<(), AnergyReason> {
        self.signal_1(identity, chain)?;
        self.signal_2(chain, now)?;

        // Conjunct 3 — action in scope. The tool must resolve in the genome, and every
        // capability it requires must be present in the chain's current attenuated scope. An
        // undeclared tool is a denied tool: the register is the closed vocabulary. An empty
        // requirement set is vacuously satisfied — a tool that needs no capability needs no scope.
        let resolved_tool = self
            .genome_resolver
            .resolve_tool(&action.tool)
            .ok_or(AnergyReason::OutOfScope)?;
        let scope = chain.current_scope();
        for cap in &resolved_tool.required_capabilities {
            if !scope.capabilities().contains(cap) {
                return Err(AnergyReason::OutOfScope);
            }
        }

        // Conjunct 4 — action respects invariants. For each accumulated invariant, resolve its
        // predicate and check the tool against it. An invariant with no declared predicate is
        // denied, not passed (the fail-closed backstop). No invariants means nothing to violate.
        let invariants = chain.current_invariants();
        for inv in invariants.iter() {
            let predicate = self
                .genome_resolver
                .resolve_invariant(inv)
                .ok_or(AnergyReason::InvariantViolated)?;
            // Does the tool require any capability this invariant forbids?
            for forbidden in &predicate.forbids_capabilities {
                if resolved_tool.required_capabilities.contains(forbidden) {
                    return Err(AnergyReason::InvariantViolated);
                }
            }
            // Does the tool carry a privilege class this invariant forbids?
            if predicate
                .forbids_privilege
                .contains(&resolved_tool.privilege)
            {
                return Err(AnergyReason::InvariantViolated);
            }
        }

        Ok(())
    }
}
