//! HÚÐ — the Barrier (AMD-007), and the [`BarrierVerdict`] whose `Deny` has no
//! path to `Allow` (I-2).

use crate::classification::{ChannelStrength, Classification, NamedGroup};
use crate::crypto::DualSignature;
use crate::ids::{
    DatumRef, FindingId, Host, ModelEndpointId, OriginId, ResourcePath, RiskAcceptanceId, Timestamp,
};
use crate::personal_data::{Purpose, RetentionPeriod};
use alloc::string::String;
use alloc::vec::Vec;

/// Which condition of the egress gate failed. **Typed, not prose:** an acceptance scoped
/// to "the precise advisory" (OQGF-P-9.2) needs the advisory to be a *value that can be
/// matched*, not a sentence that can be paraphrased — an acceptance scoped to a sentence
/// breaks when the sentence is reworded. One variant per egress condition that can `Deny`
/// (§6.5 conditions 2–9; condition 1 short-circuits to `Allow`, so it raises no finding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierCondition {
    /// No BCR present for an above-Public (or personal) egress (condition 2).
    MissingCustodyRecord,
    /// `bcr.datum != flow.datum` — an unmatched record (condition 3).
    DatumMismatch,
    /// The BCR signature did not verify (condition 4).
    SignatureInvalid,
    /// `now > bcr.expiry` — the BCR is expired (condition 5).
    Expired,
    /// `bcr.classification != flow.classification` — a record for other data (condition 6).
    ClassificationMismatch,
    /// The destination is not in `bcr.authorized` (condition 7).
    UnauthorizedDestination,
    /// The channel's effective authorization is below `flow.classification` (condition 8).
    ChannelStrengthCollapse,
    /// Personal data crossing without a matching declared Purpose/Retention in its BCR
    /// (condition 9, OQGF-P-11.3/P-11.4).
    PersonalDataUndeclared,
}

/// A still-visible finding attached to a deterministic `Deny` (OQGF-I-10). It is
/// never removed; the only sanctioned way past is an `AcceptedRisk`.
///
/// Rev 1.8 gives a finding the **identity** OQGF-P-9.2 demands — "exact component identity
/// and the precise advisory." Without it, the only acceptance expressible would be "any
/// Secret datum, for this reason," the blanket acceptance P-9.2 forbids by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierFinding {
    /// Exact component identity (OQGF-P-9.2).
    pub datum: DatumRef,
    /// The precise advisory, as a value (OQGF-P-9.2).
    pub condition: BarrierCondition,
    pub classification: Classification,
    /// Human-readable detail. Explanatory, and **NOT part of the match key** — an
    /// acceptance must not turn on the wording of a sentence.
    pub reason: String,
}

/// The exhaustive tag for a [`BarrierCondition`] used in the [`BarrierFinding::finding_id`]
/// encoding. Matched with **no catch-all**, so a new variant forces a compile error rather
/// than colliding with an existing tag.
fn condition_tag(c: BarrierCondition) -> &'static str {
    match c {
        BarrierCondition::MissingCustodyRecord => "missing-custody-record",
        BarrierCondition::DatumMismatch => "datum-mismatch",
        BarrierCondition::SignatureInvalid => "signature-invalid",
        BarrierCondition::Expired => "expired",
        BarrierCondition::ClassificationMismatch => "classification-mismatch",
        BarrierCondition::UnauthorizedDestination => "unauthorized-destination",
        BarrierCondition::ChannelStrengthCollapse => "channel-strength-collapse",
        BarrierCondition::PersonalDataUndeclared => "personal-data-undeclared",
    }
}

impl BarrierFinding {
    /// The deterministic identity an acceptance is scoped to (OQGF-P-9.2): a **pure
    /// function of `datum` and `condition` only** — never `classification`, never `reason`,
    /// never a counter or a clock. A DAP accepts a risk *before* the crossing is attempted,
    /// so the identity must be computable in advance; and it lives here in `brokkr-core` so
    /// the Barrier and any acceptance-issuing tool compute it identically (§6.5).
    ///
    /// **The encoding is unambiguous (injective).** It is `"<len>:<datum>:<condition-tag>"`,
    /// where `<len>` is the byte length of the datum. The length prefix — not a delimiter —
    /// bounds the datum, so a `DatumRef` that itself contains a `:` cannot absorb the
    /// separator or the condition tag: a parser reads the decimal length up to the first
    /// `:`, takes exactly that many bytes as the datum, and the remainder (after the next
    /// `:`) is the condition tag. Distinct `(datum, condition)` pairs therefore never
    /// collide (proven by `tests/negative_invariants.rs`). `brokkr-core` has no hasher, so
    /// this is injective string composition, not a digest.
    pub fn finding_id(&self) -> FindingId {
        let d = self.datum.as_str();
        FindingId::new(alloc::format!(
            "{}:{}:{}",
            d.len(),
            d,
            condition_tag(self.condition)
        ))
    }
}

/// The barrier's verdict on a proposed crossing.
///
/// **I-2 — a `Deny` cannot become an `Allow`.** There is deliberately no method,
/// `impl From`, or conversion of any kind on `Deny` (or on this enum) that yields
/// `Allow`. `AcceptedRisk` is a *distinct variant* — the only sanctioned way past a
/// deterministic `Deny` (AMD-006 / OQGF-P-9) — and it keeps the finding visible; it
/// is not a flag on `Allow`.
///
/// No such conversion exists, so this does not compile:
///
/// ```compile_fail,E0599
/// use brokkr_core::barrier::{BarrierVerdict, BarrierFinding, BarrierCondition};
/// use brokkr_core::classification::Classification;
/// use brokkr_core::ids::DatumRef;
/// let d = BarrierVerdict::Deny {
///     finding: BarrierFinding {
///         datum: DatumRef::new("x"),
///         condition: BarrierCondition::UnauthorizedDestination,
///         classification: Classification::Secret,
///         reason: "x".into(),
///     },
/// };
/// let _allow = d.into_allow(); // E0599: no method named `into_allow` found for enum `BarrierVerdict`
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BarrierVerdict {
    /// The crossing is permitted.
    Allow,
    /// Deterministic, non-suppressible (OQGF-I-10 inheriting OQGF-P-2). The
    /// finding stays visible.
    Deny { finding: BarrierFinding },
    /// Unprovenanced ingress into a privileged context (OQGF-I-11).
    Quarantine { datum: DatumRef },
    /// A DAP recorded a scoped, expiring, signed decision to proceed past a
    /// still-visible `Deny` (AMD-006 / OQGF-P-9). Distinct from `Allow` by
    /// construction.
    AcceptedRisk { entry: RiskAcceptanceId },
}

/// A destination is not merely *where* data goes; it is also the *pipe* it goes
/// through. The `Reasoner` variant is why Rev 1.2 exists: its authorization is
/// conditional on the channel actually negotiated (BROKKR-ARCH 6.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    LocalPath(ResourcePath),
    Network {
        host: Host,
        channel: ChannelStrength,
    },
    Reasoner {
        endpoint: ModelEndpointId,
        negotiated: NamedGroup,
    },
}

/// What a [`BoundaryCustodyRecord`] may pre-authorize: **where** data may go, not over
/// **what pipe**.
///
/// It is deliberately coarser than [`Destination`]. `Destination::Network` carries a live
/// [`ChannelStrength`] and `Destination::Reasoner` a negotiated [`NamedGroup`] — facts
/// about *this* crossing, established at connection time. A BCR is signed *before* the
/// crossing and cannot know them. If a BCR could pre-authorize a `ChannelStrength`, a
/// record written when a strong channel was available would authorize a later crossing
/// over a classical one. Two questions stay separate: *is this destination authorized*
/// (the BCR answers) and *is this channel strong enough* (`effective_authorization`
/// answers, from the negotiated group). Collapsing them would let a valid BCR launder a
/// weak channel (§6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationClass {
    LocalPath(ResourcePath),
    Network { host: Host },
    Reasoner { endpoint: ModelEndpointId },
}

/// Whether an ingress destination is a Privileged Context (AMD-007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextClass {
    /// A training corpus, evaluation dataset, fine-tuning corpus, model registry, or any
    /// AIBOM-governed artifact (OQGF-G-2). Unprovenanced data SHALL NOT enter here.
    Privileged,
    /// Any other context. Unprovenanced data **MAY** be used here (OQGF-I-11) — quarantine
    /// is not denial; only promotion into model-building artifacts is gated.
    NonPrivileged,
}

/// Personal Data's governed dimension (OQGF-P-11.1). It **composes with** [`Classification`]
/// and is **orthogonal** to it — never a tier of it, never a variant of it.
///
/// **Orthogonality is the requirement, not a modelling preference.** A datum may be Public
/// *and* personal, and that combination is precisely the one a sensitivity-only model gets
/// wrong. A `Classification::Personal` variant would make "Public and personal"
/// inexpressible and would satisfy the sensitivity gate while defeating the lifecycle one —
/// so the tag is a **separate type**, presence of which (`Option<PersonalDataTag>`) triggers
/// the lifecycle obligations at every tier, Public included. It carries the two committed
/// value types a Personal-Data crossing needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalDataTag {
    /// The declared reason this data was collected (OQGF-P-11.3).
    pub purpose: Purpose,
    /// The declared span it may be held, tied to the Purpose (OQGF-P-11.4).
    pub retention: RetentionPeriod,
}

/// A Boundary Custody Record — a bill of materials for data in transit, sibling to the
/// CBOM (OQGF-G-1) and AIBOM (OQGF-G-2), and the secretory-IgA analog: a mark that travels
/// with the material and states something verifiable about it (OQGF-I-9).
///
/// One record serves both directions. At egress the `classification` and `authorized`
/// destinations decide; at ingress the `origin` is what makes provenance established — so a
/// separate ingress-provenance type would only duplicate a field this record already
/// carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryCustodyRecord {
    /// Which datum this record covers. A Phase-6 `evaluate` requires it to equal the flow's
    /// `datum`: this is what "matched at the Barrier" means (OQGF-I-9).
    pub datum: DatumRef,
    pub classification: Classification,
    /// The provenance root. At ingress this **is** the established provenance (OQGF-I-11);
    /// there is no separate provenance type.
    pub origin: OriginId,
    /// The destinations this record pre-authorizes — coarsely (see [`DestinationClass`]).
    pub authorized: Vec<DestinationClass>,
    /// The declared Purpose and Retention Period, where this datum is Personal Data
    /// (OQGF-P-11.3, OQGF-P-11.4). `None` for data that is not personal.
    pub personal: Option<PersonalDataTag>,
    pub issued: Timestamp,
    pub expiry: Timestamp,
    pub signature: DualSignature,
}

/// A proposed crossing. **The direction is the type, not a flag.**
///
/// Rev 1.5's `BoundaryFlow` carried a classification and a destination — an egress shape.
/// It could not express an ingress crossing at all, which made
/// [`BarrierVerdict::Quarantine`] **unreachable from `evaluate`**: the method held no
/// [`DatumRef`] to construct one with and no provenance to judge. Folding direction into
/// the type makes an ingress flow carrying a [`Destination`], or an egress flow carrying a
/// [`ContextClass`], **unrepresentable** (§6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryFlow {
    /// Data leaving a controlled compartment (OQGF-I-10). Absent `bcr` above Public is a
    /// `Deny` at Phase 6 — the Barrier does not infer custody it was not given.
    Egress {
        datum: DatumRef,
        classification: Classification,
        /// Orthogonal to `classification`, never a tier of it (OQGF-P-11.1). Declared on
        /// the **flow**, not only on the record: without it `evaluate` cannot distinguish a
        /// Public personal datum from a Public ordinary one when no BCR is presented — which
        /// is exactly what corrected condition 1 short-circuits on (§6.5). The field is what
        /// makes that fix expressible.
        personal: Option<PersonalDataTag>,
        destination: Destination,
        bcr: Option<BoundaryCustodyRecord>,
    },
    /// Data arriving. Provenance is the BCR's `origin`; its absence is what quarantine
    /// responds to (OQGF-I-11).
    Ingress {
        datum: DatumRef,
        personal: Option<PersonalDataTag>,
        bcr: Option<BoundaryCustodyRecord>,
        context: ContextClass,
    },
}

/// HÚÐ's contract (implemented in Phase 6). Evaluation returns a [`BarrierVerdict`]; there
/// is no method anywhere that turns a `Deny` into an `Allow` (I-2).
///
/// `now` is an explicit parameter, **never a wall-clock read**: a BCR's `expiry` is checked
/// against it, and a gate whose verdict depends on an ambient clock is not
/// deterministically testable.
pub trait Barrier: Send + Sync {
    fn evaluate(&self, flow: &BoundaryFlow, now: Timestamp) -> BarrierVerdict;
}
