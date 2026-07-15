//! SKULD — the Intent Provenance Chain (AMD-001).
//!
//! I-3 is encoded here: [`IntentProvenanceChain`] is append-only, and its sole
//! append path ([`IntentProvenanceChain::extend`]) rejects an emitted scope that
//! is not a subset of the current scope. Broadening is not detected after the
//! fact — it is unrepresentable (OQGF-M-9).

use crate::crypto::{Attestation, Digest, DualSignature};
use crate::ids::{Dap, Nonce, SubjectId, Timestamp};
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

/// A single unit of authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability(pub String);

impl Capability {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// The authority granted to a hop, as a set of capabilities. Attenuation is set
/// subset (OQGF-M-9).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntentScope {
    caps: BTreeSet<Capability>,
}

impl IntentScope {
    pub fn new(caps: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            caps: caps.into_iter().collect(),
        }
    }

    pub fn empty() -> Self {
        Self {
            caps: BTreeSet::new(),
        }
    }

    pub fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.caps
    }

    /// True iff `self` grants nothing beyond `other` (`self ⊆ other`). This is the
    /// monotonic-attenuation predicate (OQGF-M-9).
    pub fn is_subset_of(&self, other: &IntentScope) -> bool {
        self.caps.is_subset(&other.caps)
    }
}

/// A hard constraint that holds at every hop (OQGF-M-10).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Invariant(pub String);

impl Invariant {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// A set of invariants. It may only grow across hops — invariants may be added,
/// never removed or weakened (OQGF-M-10).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InvariantSet {
    set: BTreeSet<Invariant>,
}

impl InvariantSet {
    pub fn new(invariants: impl IntoIterator<Item = Invariant>) -> Self {
        Self {
            set: invariants.into_iter().collect(),
        }
    }

    pub fn contains(&self, i: &Invariant) -> bool {
        self.set.contains(i)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Invariant> {
        self.set.iter()
    }

    /// The union of two invariant sets. Used to accumulate invariants across a
    /// chain — the result always contains every invariant of both inputs, so
    /// invariants can only be added (OQGF-M-10).
    fn unioned(&self, added: &InvariantSet) -> InvariantSet {
        InvariantSet {
            set: self.set.union(&added.set).cloned().collect(),
        }
    }
}

/// An append-only restriction added at a hop (OQGF-M-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caveat(pub String);

/// The original authorized intent, issued by a DAP or authenticated principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootIntent {
    pub principal: SubjectId,
    pub dap: Dap,
    pub scope: IntentScope,
    pub invariants: InvariantSet,
    pub nonce: Nonce,
    pub expiry: Timestamp,
    pub signature: DualSignature,
}

/// One hop's derivation of intent from the prior chain state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentChainEntry {
    pub hop_identity: Attestation,
    pub received_digest: Digest,
    pub emitted_scope: IntentScope,
    pub added_caveats: Vec<Caveat>,
    pub added_invariants: InvariantSet,
    pub signature: DualSignature,
}

error_enum! {
    /// Why an attenuation was refused.
    pub enum AttenuationError {
        WouldBroaden => "emitted scope is not a subset of the received scope (OQGF-M-9)",
        Expired => "the intent provenance chain has expired (OQGF-M-14)",
    }
}

/// A hash-linked, append-only chain from a [`RootIntent`] to the current hop.
///
/// The `entries` are private and the only mutator is [`extend`](Self::extend),
/// which enforces subset attenuation. There is no widening constructor, no
/// `expand`, no `escalate` (I-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentProvenanceChain {
    root: RootIntent,
    entries: Vec<IntentChainEntry>,
}

impl IntentProvenanceChain {
    pub fn new(root: RootIntent) -> Self {
        Self {
            root,
            entries: Vec::new(),
        }
    }

    pub fn root(&self) -> &RootIntent {
        &self.root
    }

    pub fn entries(&self) -> &[IntentChainEntry] {
        &self.entries
    }

    /// The current, most-attenuated scope (the last entry's, or the root's).
    pub fn current_scope(&self) -> &IntentScope {
        match self.entries.last() {
            Some(entry) => &entry.emitted_scope,
            None => &self.root.scope,
        }
    }

    /// The accumulated invariant set at the current hop: the root's invariants
    /// unioned with every hop's additions. Invariants only accumulate (OQGF-M-10).
    pub fn current_invariants(&self) -> InvariantSet {
        let mut acc = self.root.invariants.clone();
        for entry in &self.entries {
            acc = acc.unioned(&entry.added_invariants);
        }
        acc
    }

    /// The **sole** way to append a hop. An `emitted_scope` that is not a subset
    /// of the current scope is refused with [`AttenuationError::WouldBroaden`]:
    /// broadening is an operation this type cannot perform (I-3 / OQGF-M-9).
    pub fn extend(
        mut self,
        hop_identity: Attestation,
        received_digest: Digest,
        emitted_scope: IntentScope,
        added_caveats: Vec<Caveat>,
        added_invariants: InvariantSet,
        signature: DualSignature,
    ) -> Result<Self, AttenuationError> {
        if !emitted_scope.is_subset_of(self.current_scope()) {
            return Err(AttenuationError::WouldBroaden);
        }
        self.entries.push(IntentChainEntry {
            hop_identity,
            received_digest,
            emitted_scope,
            added_caveats,
            added_invariants,
            signature,
        });
        Ok(self)
    }
}

/// SKULD's contract (implemented with real signing in Phase 3). The provided
/// [`attenuate`](Self::attenuate) routes through [`IntentProvenanceChain::extend`],
/// so no implementor can widen authority (I-3). An implementor may add signing but
/// cannot reach a widening path, because none exists.
pub trait IntentChain: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn attenuate(
        &self,
        current: IntentProvenanceChain,
        hop: Attestation,
        received_digest: Digest,
        emitted: IntentScope,
        added_caveats: Vec<Caveat>,
        added_invariants: InvariantSet,
        signature: DualSignature,
    ) -> Result<IntentProvenanceChain, AttenuationError> {
        current.extend(
            hop,
            received_digest,
            emitted,
            added_caveats,
            added_invariants,
            signature,
        )
    }
}
