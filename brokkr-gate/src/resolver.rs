//! The key-resolution seam (Architecture Rev 1.3 §6.4.1).
//!
//! SINDRI verifies chain signatures with [`DualPublicKey`] but the committed
//! [`Attestation`] carries no public key, so the gate must obtain each hop's verifying
//! key from somewhere. It depends on the [`KeyResolver`] **interface**, never on a
//! concrete registry: "SINDRI SHALL NOT know where a key came from" (§6.4.1). That
//! ignorance is the migration path — the declared-registry model adopted here (Option B)
//! and the attestation-carried/issuer-certified model (Option A, deferred) sit behind the
//! same trait, and swapping them changes no SINDRI code.

use brokkr_core::crypto::Attestation;
use brokkr_core::ids::SubjectId;
use brokkr_crypto::DualPublicKey;
use std::collections::BTreeMap;

/// Resolves a hop (or root) identity to the dual-family public key that verifies its
/// signatures. `None` means: this subject is **not a declared root of trust**.
///
/// Two methods, because the committed types present identity two ways:
///
/// - [`resolve`](Self::resolve) takes an [`Attestation`] — how each **hop** presents
///   itself (`IntentChainEntry::hop_identity`).
/// - [`resolve_subject`](Self::resolve_subject) takes a [`SubjectId`] — needed for the
///   **root**, which carries `RootIntent::principal: SubjectId` and no `Attestation`.
///
/// `resolve` delegates to `resolve_subject` by default, so an implementor supplies only
/// the subject lookup. See the crate/phase report for why `resolve_subject` is added over
/// the Rev 1.3 §6.4.1 sketch (the sketch shows only `resolve(attestation)`, through which
/// the root's key cannot be obtained — this addition is additive and preserves the placed
/// method unchanged).
pub trait KeyResolver: Send + Sync {
    /// Resolve the verifying key for the subject named by an attestation.
    /// `None` ⇒ not a declared root of trust.
    fn resolve(&self, attestation: &Attestation) -> Option<DualPublicKey> {
        self.resolve_subject(&attestation.subject)
    }

    /// Resolve the verifying key for a subject directly (the root case).
    /// `None` ⇒ not a declared root of trust.
    fn resolve_subject(&self, subject: &SubjectId) -> Option<DualPublicKey>;
}

/// A declared registry of roots of trust: `SubjectId → (ML-DSA-65 public, SLH-DSA-SHAKE-192s
/// public)` raw bytes. This is the **Option B** model adopted at Phase 4 (§6.4.1).
///
/// It stores **bytes**, not keys, because [`DualPublicKey`] does not derive `Clone`; a
/// fresh key is minted per [`resolve_subject`](KeyResolver::resolve_subject) via
/// [`DualPublicKey::from_public_bytes`]. Pairs are supplied **directly** at construction —
/// per §6.4.1, Phase 4 SHALL NOT implement a signed-register loader; that is REGIN's
/// (Phase 5), where the roots-of-trust register becomes a signed, `SelfModifying` genome
/// register (I-7).
#[derive(Debug, Default, Clone)]
pub struct RegistryResolver {
    // subject -> (ml_dsa_65_public_bytes, slh_dsa_shake_192s_public_bytes)
    keys: BTreeMap<SubjectId, (Vec<u8>, Vec<u8>)>,
}

impl RegistryResolver {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Declare a root of trust: a subject and its raw dual-family public keys. Chained
    /// (builder) form for constructing a registry from declared pairs supplied directly.
    #[must_use]
    pub fn with_root(
        mut self,
        subject: SubjectId,
        ml_dsa_public: Vec<u8>,
        slh_dsa_public: Vec<u8>,
    ) -> Self {
        self.keys.insert(subject, (ml_dsa_public, slh_dsa_public));
        self
    }

    /// Declare a root of trust in place.
    pub fn insert_root(
        &mut self,
        subject: SubjectId,
        ml_dsa_public: Vec<u8>,
        slh_dsa_public: Vec<u8>,
    ) {
        self.keys.insert(subject, (ml_dsa_public, slh_dsa_public));
    }
}

impl KeyResolver for RegistryResolver {
    fn resolve_subject(&self, subject: &SubjectId) -> Option<DualPublicKey> {
        let (ml_dsa_public, slh_dsa_public) = self.keys.get(subject)?;
        // Mint a fresh verify-only key from the declared bytes. A malformed declared key
        // yields `None` (fail closed): an unresolvable key is treated as "not a declared
        // root of trust", never granted. `.ok()` collapses the import error to `None` by
        // design — the caller (SINDRI) maps `None` to architectural anergy.
        DualPublicKey::from_public_bytes(ml_dsa_public, slh_dsa_public).ok()
    }
}
