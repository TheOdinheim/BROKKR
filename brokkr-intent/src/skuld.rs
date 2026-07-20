//! SKULD — the working Intent Provenance Chain (AMD-001).
//!
//! `brokkr-core` already makes broadening *unrepresentable* (the chain is append-only
//! and [`IntentProvenanceChain::extend`] rejects a non-subset scope). SKULD makes the
//! chain a **working, cryptographically enforced** artifact on top of that: real
//! dual-family signing over canonical bytes, real SHA-384 hash-linking, and freshness.
//!
//! The signature commits to `emitted_scope` (via [`crate::canonical`]), so presenting
//! a broadened chain that verifies would require forging a [`DualSignature`] — an
//! ML-DSA-65 *and* an SLH-DSA-SHAKE-192s forgery. That is OQGF-M-9's bar: broadening
//! is computationally infeasible, not merely detectable.
//!
//! Cryptographic posture is inherited from `brokkr-crypto`; this crate makes no
//! stronger claim than `brokkr_crypto::CRYPTO_POSTURE`
//! ("CNSA-2.0-aligned; FIPS module validation pending; current build non-FIPS").

use crate::canonical;
use brokkr_core::crypto::{
    Attestation, CryptoError, Digest, DualSignature, Hasher, Signature, SignatureAlg,
};
use brokkr_core::ids::{Dap, Nonce, SubjectId, Timestamp};
use brokkr_core::intent::{
    AttenuationError, Caveat, IntentChain, IntentChainEntry, IntentProvenanceChain, IntentScope,
    InvariantSet, RootIntent,
};
use brokkr_crypto::{DualKeyPair, DualPublicKey, Sha384Hasher};

/// Errors from constructing or verifying an intent provenance chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentError {
    /// A monotonic-attenuation failure from `brokkr-core` (`WouldBroaden` or
    /// `Expired`).
    Attenuation(AttenuationError),
    /// A crypto-backend error while signing.
    Backend,
    /// The Root Intent signature did not verify.
    RootSignatureInvalid,
    /// The entry signature at `hop` did not verify (index from 0).
    EntrySignatureInvalid { hop: usize },
    /// The hash link at `hop` did not match the recomputed digest of the prior state.
    BrokenLink { hop: usize },
    /// No verifying key was supplied for the hop at `hop`.
    HopKeyMissing { hop: usize },
}

impl core::fmt::Display for IntentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IntentError::Attenuation(e) => write!(f, "attenuation error: {e}"),
            IntentError::Backend => f.write_str("cryptographic backend error while signing"),
            IntentError::RootSignatureInvalid => {
                f.write_str("root intent signature did not verify")
            }
            IntentError::EntrySignatureInvalid { hop } => {
                write!(f, "entry signature at hop {hop} did not verify")
            }
            IntentError::BrokenLink { hop } => {
                write!(
                    f,
                    "hash link broken at hop {hop} (received_digest mismatch)"
                )
            }
            IntentError::HopKeyMissing { hop } => {
                write!(f, "no verifying key supplied for hop {hop}")
            }
        }
    }
}

impl std::error::Error for IntentError {}

/// A placeholder dual signature used only while computing the *signed content*
/// (which excludes the `signature` field entirely), then immediately overwritten
/// with the real signature. Its bytes never enter a canonical encoding.
fn placeholder_signature() -> DualSignature {
    DualSignature {
        lattice: Signature {
            alg: SignatureAlg::MlDsa65,
            bytes: Vec::new(),
        },
        hash_based: Signature {
            alg: SignatureAlg::SlhDsaShake192s,
            bytes: Vec::new(),
        },
    }
}

/// SHA-384 of the given bytes, via the real wolfCrypt backend.
fn digest(bytes: &[u8]) -> Digest {
    Sha384Hasher.hash(bytes)
}

/// A private, brokkr-intent-internal abstraction over "something that can verify a
/// dual-family signature": either a full [`DualKeyPair`] (holds private material) or a
/// [`DualPublicKey`] (public roots of trust only). Both already expose an inherent
/// `verify_dual` with the identical shape; these impls are one-line forwards. Keeping
/// the verification *walk* generic over this trait means the freshness / hash-link /
/// subset / error-mapping logic lives in exactly one place — the keypair path and the
/// public-key path cannot drift. This trait is **private**; it is not part of the API.
trait DualVerify {
    fn verify_dual(&self, msg: &[u8], sig: &DualSignature) -> Result<(), CryptoError>;
}

impl DualVerify for DualKeyPair {
    fn verify_dual(&self, msg: &[u8], sig: &DualSignature) -> Result<(), CryptoError> {
        // Inherent method (takes precedence over the trait method for `Type::method`).
        DualKeyPair::verify_dual(self, msg, sig)
    }
}

impl DualVerify for DualPublicKey {
    fn verify_dual(&self, msg: &[u8], sig: &DualSignature) -> Result<(), CryptoError> {
        DualPublicKey::verify_dual(self, msg, sig)
    }
}

/// Verify a Root Intent signature with any dual verifier — the single place root-sig
/// verification lives. `verify_root` and `verify_root_public` both delegate here, as
/// does the chain walk.
fn check_root_signature<V: DualVerify>(root: &RootIntent, verifier: &V) -> Result<(), IntentError> {
    let bytes = canonical::root_signed_content(root);
    verifier
        .verify_dual(&bytes, &root.signature)
        .map_err(|_| IntentError::RootSignatureInvalid)
}

/// The chain-verification walk, generic over the verifier type — the **one** place the
/// freshness → root-sig → per-hop(hash-link, subset re-check, entry-sig) → advance logic
/// lives. Both [`Skuld::verify_chain`] (keypairs) and [`Skuld::verify_chain_public`]
/// (public keys) delegate here, so they cannot drift. Same error variants, same order,
/// same fail-closed behavior — only the verifying-key type differs.
fn verify_chain_with<V: DualVerify>(
    root: &RootIntent,
    entries: &[IntentChainEntry],
    root_verifier: &V,
    hop_verifiers: &[&V],
    now: Timestamp,
) -> Result<(), IntentError> {
    // 1. Freshness, at the start, before the walk (AMD.5.3 step 2).
    if now > root.expiry {
        return Err(IntentError::Attenuation(AttenuationError::Expired));
    }

    // 2. Root signature.
    check_root_signature(root, root_verifier)?;

    // 3. Walk root -> current.
    let mut prior_full = canonical::root_full(root);
    let mut prior_scope = &root.scope;

    for (hop, entry) in entries.iter().enumerate() {
        // (a) Hash link: recompute the digest of the prior state and compare.
        let expected = digest(&prior_full);
        if entry.received_digest != expected {
            return Err(IntentError::BrokenLink { hop });
        }

        // (b) Subset check — REQUIRED for a reconstructed chain (extend did not run).
        if !entry.emitted_scope.is_subset_of(prior_scope) {
            return Err(IntentError::Attenuation(AttenuationError::WouldBroaden));
        }

        // (c) Entry signature under the hop's verifying key.
        let verifier = *hop_verifiers
            .get(hop)
            .ok_or(IntentError::HopKeyMissing { hop })?;
        let bytes = canonical::entry_signed_content(entry);
        verifier
            .verify_dual(&bytes, &entry.signature)
            .map_err(|_| IntentError::EntrySignatureInvalid { hop })?;

        // (d) Advance.
        prior_full = canonical::entry_full(entry);
        prior_scope = &entry.emitted_scope;
    }

    Ok(())
}

/// SKULD. Stateless; realizes the [`IntentChain`] trait (whose provided `attenuate`
/// routes through `extend`, so no widening path is reachable) and adds the real
/// signing pipeline around it.
pub struct Skuld;

impl IntentChain for Skuld {}

impl Skuld {
    /// Construct and sign a Root Intent. The signature is a real dual-family signature
    /// over the canonical signed content (every field except `signature`).
    #[allow(clippy::too_many_arguments)]
    pub fn sign_root(
        &self,
        principal: SubjectId,
        dap: Dap,
        scope: IntentScope,
        invariants: InvariantSet,
        nonce: Nonce,
        expiry: Timestamp,
        keypair: &DualKeyPair,
    ) -> Result<RootIntent, IntentError> {
        let mut root = RootIntent {
            principal,
            dap,
            scope,
            invariants,
            nonce,
            expiry,
            signature: placeholder_signature(),
        };
        let bytes = canonical::root_signed_content(&root);
        root.signature = keypair
            .sign_dual(&bytes)
            .map_err(|_| IntentError::Backend)?;
        Ok(root)
    }

    /// Verify a Root Intent signature: recompute the canonical bytes and require BOTH
    /// families to verify. (Delegates to the shared root-sig check — behavior unchanged.)
    pub fn verify_root(&self, root: &RootIntent, keypair: &DualKeyPair) -> Result<(), IntentError> {
        check_root_signature(root, keypair)
    }

    /// Verify a Root Intent signature using a **public key only** (no private material).
    /// Same check as [`verify_root`], with a public root of trust.
    pub fn verify_root_public(
        &self,
        root: &RootIntent,
        public: &DualPublicKey,
    ) -> Result<(), IntentError> {
        check_root_signature(root, public)
    }

    /// The real `attenuate`: compute the hash link to the prior chain state, sign the
    /// new entry's canonical content with the hop's dual-family keypair, and append
    /// via the trait's `attenuate` (which routes through `extend` — the subset check
    /// stays exactly where core put it; this never reaches a widening path).
    ///
    /// Freshness (OQGF-M-14): an expired chain SHALL NOT authorize a new hop. `now`
    /// is an explicit parameter — no wall-clock is read internally.
    #[allow(clippy::too_many_arguments)]
    pub fn attenuate_signed(
        &self,
        current: IntentProvenanceChain,
        hop_identity: Attestation,
        emitted_scope: IntentScope,
        added_caveats: Vec<Caveat>,
        added_invariants: InvariantSet,
        hop_keypair: &DualKeyPair,
        now: Timestamp,
    ) -> Result<IntentProvenanceChain, IntentError> {
        // Freshness first: an expired chain authorizes nothing.
        if now > current.root().expiry {
            return Err(IntentError::Attenuation(AttenuationError::Expired));
        }

        // received_digest = SHA-384 of the prior chain state's full canonical bytes
        // (the root for hop 1, the last entry for hop N).
        let prior_bytes = match current.entries().last() {
            None => canonical::root_full(current.root()),
            Some(prev) => canonical::entry_full(prev),
        };
        let received_digest = digest(&prior_bytes);

        // Sign the new entry's canonical content (which commits to emitted_scope).
        let mut entry = IntentChainEntry {
            hop_identity,
            received_digest,
            emitted_scope,
            added_caveats,
            added_invariants,
            signature: placeholder_signature(),
        };
        let bytes = canonical::entry_signed_content(&entry);
        entry.signature = hop_keypair
            .sign_dual(&bytes)
            .map_err(|_| IntentError::Backend)?;

        // Append through the trait's provided attenuate -> extend. `extend` enforces
        // the subset check; a broadening emitted_scope returns Err(WouldBroaden) and
        // the entry is discarded (the wasted signature never appends).
        let IntentChainEntry {
            hop_identity,
            received_digest,
            emitted_scope,
            added_caveats,
            added_invariants,
            signature,
        } = entry;
        self.attenuate(
            current,
            hop_identity,
            received_digest,
            emitted_scope,
            added_caveats,
            added_invariants,
            signature,
        )
        .map_err(IntentError::Attenuation)
    }

    /// Verify a chain presented as its *reconstructed* parts — a `RootIntent` and a
    /// slice of `IntentChainEntry`. This is the adversary model: a deserialized chain
    /// never passed through `extend`, so the type-level subset guarantee did NOT
    /// travel with the bytes and must be re-checked here, alongside the signatures and
    /// the hash links.
    ///
    /// Returns `Ok(())` only if: the chain is fresh; the root signature verifies; and
    /// for every hop the hash link matches, the emitted scope is a subset of the prior
    /// scope, and the entry signature verifies under the supplied hop key.
    pub fn verify_chain(
        &self,
        root: &RootIntent,
        entries: &[IntentChainEntry],
        root_keypair: &DualKeyPair,
        hop_keypairs: &[&DualKeyPair],
        now: Timestamp,
    ) -> Result<(), IntentError> {
        verify_chain_with(root, entries, root_keypair, hop_keypairs, now)
    }

    /// Verify a chain using only declared **public roots of trust** — a `DualPublicKey`
    /// for the root and each hop, holding **no** private material. Identical semantics to
    /// [`verify_chain`] (same freshness → root-sig → per-hop hash-link, subset re-check,
    /// entry-sig order; same error variants; same fail-closed behavior) — only the
    /// verifying-key type differs, and both delegate to the one shared walk.
    ///
    /// This is the SKULD-side path SINDRI (Phase 4) will call, with public keys resolved
    /// from OQGF-M-1 attestations. It closes the public-roots-of-trust half of OQGF-M-8
    /// on the chain-verifier side; wiring attestation→resolved-key→this call is Phase 4.
    pub fn verify_chain_public(
        &self,
        root: &RootIntent,
        entries: &[IntentChainEntry],
        root_public: &DualPublicKey,
        hop_publics: &[&DualPublicKey],
        now: Timestamp,
    ) -> Result<(), IntentError> {
        verify_chain_with(root, entries, root_public, hop_publics, now)
    }
}
