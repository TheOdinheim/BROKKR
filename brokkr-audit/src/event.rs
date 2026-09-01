//! The record and the typed event (§6.9 "The record").
//!
//! An [`AuditRecord`] is a **chain header** (`seq`, `prev`, `at`, `dap`, `event` — the
//! *signed content*) plus two accumulating attestations that live *outside* the signed
//! content: the [`GenerationSignature`] set and the [`Timestamping`] token. Per ARCH
//! Rev 1.10, the chain links over the signed content **only** — see
//! [`crate::canonical::record_signed_content`] — so appending a signature or a timestamp
//! never disturbs a link.
//!
//! [`AuditEvent`] is a **closed enum over what BROKKR does**, each variant carrying a
//! committed `brokkr-core` payload (or, for the A-1 proposal and the erasure tombstone, a
//! small struct over committed value types). A blob-with-a-kind-tag was rejected (§6.9):
//! it would make the chain unreadable without the writer's private knowledge and let a
//! future subsystem record anything under any label.

use brokkr_core::adapt::{DetectorProvenance, RefinedDetector};
use brokkr_core::barrier::BarrierVerdict;
use brokkr_core::barrier::BoundaryFlow;
use brokkr_core::barrier::PersonalDataTag;
use brokkr_core::capability::EvidenceProvenance;
use brokkr_core::classification::Classification;
use brokkr_core::crypto::{Digest, DualSignature};
use brokkr_core::gate::{Action, AnergyReason};
use brokkr_core::ids::{Dap, GenomeVersion, ModelIdentity, SubjectId, Timestamp};
use brokkr_core::resolution::ResolutionDecision;
use brokkr_core::risk::RiskAcceptance;
use brokkr_core::signal::Signal;
use brokkr_core::tolerance::ToleranceGrant;

/// Which cryptographic generation a signature was produced under (OQGF-A-6). A **label**,
/// not a governance rule: re-signing appends a signature under the prevailing generation,
/// and verification looks up the generation's public key to check it. An open `u32` newtype
/// — there is no fixed cap on how many generations a long-lived audit store outlives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CryptoGeneration(pub u32);

/// One generation's signature over a record's signed content. **Re-signing APPENDS one;**
/// it never replaces or removes an earlier one (OQGF-A-6). The first is the original and is
/// the evidence the record was attested under the cryptography of its own era.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationSignature {
    pub generation: CryptoGeneration,
    pub signed_at: Timestamp,
    pub signature: DualSignature,
}

/// An RFC 3161 token (opaque bytes) from a PQC-signing authority (OQGF-A-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampToken {
    pub token: Vec<u8>,
}

/// Whether a record carries a trusted timestamp — and if not, that fact, **recorded rather
/// than omitted** (OQGF-A-3; the OQGF-I-13 "digest OR a record of its absence" pattern). An
/// enum, never an `Option`: a record either carries a token or states it does not, and a
/// record marked `Unavailable` is still valid and still appends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Timestamping {
    Token(TimestampToken),
    Unavailable { reason: String },
}

/// The audit skeleton that survives crypto-shred erasure (OQGF-P-11.5). Appended to the
/// chain as an [`AuditEvent::Erasure`]; the erased record itself is never modified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureTombstone {
    /// The `seq` of the record whose personal data was erased.
    pub erased: u64,
    pub classification: Classification,
    pub at: Timestamp,
    pub dap: Dap,
}

/// The outcome of a costimulation decision, recorded per Step 0(a).
///
/// **Why not the `AuthorizedAction` itself.** `brokkr_core::gate::AuthorizedAction` has no
/// public constructor and derives neither `Clone` nor `Copy` (I-1), so it cannot be stored
/// in or copied into an event. What the gate *decided* is recorded instead: the [`Action`]
/// (obtained via `AuthorizedAction::action()`, and `Action` is `Clone`) plus this outcome.
/// SAGA records the token's shadow, not the token — I-1 is untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationOutcome {
    Granted,
    Anergy { reason: AnergyReason },
}

/// A recorded authorization decision (Step 0(a)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRecord {
    pub action: Action,
    pub outcome: AuthorizationOutcome,
}

/// A recorded barrier crossing (OQGF-I-13): the verdict, the flow, the BCR digest **or the
/// recorded fact of its absence**, and — where the verdict was `AcceptedRisk` — the
/// accountable DAP. Boundary custody is reconstructable because the record holds what the
/// decision turned on, not merely its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierCrossing {
    pub verdict: BarrierVerdict,
    pub flow: BoundaryFlow,
    pub bcr_digest: Option<Digest>,
    pub dap: Option<Dap>,
}

/// A recorded genome promotion (OQGF-G-4): which genome was promoted, by version and
/// corpus digest. The promotion *gate* is REGIN (Phase 5); this is the audit record of a
/// promotion, placed here for when the orchestrator wires it (Phase 11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenomePromotion {
    pub version: GenomeVersion,
    pub corpus_digest: Digest,
}

/// How a regulated decision's input is stored (OQGF-A-1 "the input **or a privacy-preserving
/// derivative thereof**", reconciled with OQGF-P-11.7). The accountability record SHALL NOT
/// become a store of un-erasable personal data, so the two permitted forms are:
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedInput {
    /// A privacy-preserving derivative — a digest, not the input itself.
    Derivative(Digest),
    /// Personal data held as **ciphertext under a per-subject key** (the crypto-shredding
    /// regime). The record holds only ciphertext; the subject key lives **outside** SAGA, so
    /// erasure (key destruction) renders this irrecoverable while the record stands intact.
    /// The tag carries the declared Purpose/Retention a subject-rights query answers.
    Shredded {
        subject: SubjectId,
        personal: PersonalDataTag,
        ciphertext: Vec<u8>,
    },
}

/// A recorded MÍMIR proposal — the one AI/ML decision in BROKKR (§6.9 "A-1's field list").
/// Carries A-1's full list; `timestamp` and `dap` come from the enclosing record's header
/// (recording a `ModelIdentity` against a deterministic gate's verdict would be a category
/// error, so only this variant carries the model fields). MÍMIR is Phase 10 — the variant
/// is placed and unexercised by a real proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalRecord {
    pub model: ModelIdentity,
    pub aibom_digest: Digest,
    pub input: RecordedInput,
    pub output: String,
    pub explanation: String,
}

/// A closed enum over what BROKKR does. Every variant's payload is a committed `brokkr-core`
/// type or a small struct over committed value types (above). Variants whose emitting
/// subsystem arrives later (HEIMDALL Phase 8, KVASIR Phase 9, MÍMIR Phase 10) are **placed**
/// here; the subsystems are not built this phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// A HÚÐ crossing decision (OQGF-I-13). Phase 6 decides; Phase 7 records.
    BarrierCrossing(BarrierCrossing),
    /// A SINDRI costimulation decision (Step 0(a)).
    Authorization(AuthorizationRecord),
    /// A REGIN promotion (OQGF-G-4).
    GenomePromotion(GenomePromotion),
    /// An EIR de-escalation (OQGF-P-8.2). Phase 8.
    Resolution(ResolutionDecision),
    /// An AMD-006 accountable risk acceptance.
    RiskAcceptance(RiskAcceptance),
    /// A HEIMDALL tolerance grant (OQGF-P-4). Phase 8.
    ToleranceGrant(ToleranceGrant),
    /// A coordinated signal (AMD-004) — including the A.6.1 chain-break trigger, if recorded.
    Signal(Signal),
    /// A KVASIR detector activation (OQGF-P-6.4). Phase 9.
    DetectorActivation {
        detector: RefinedDetector,
        provenance: DetectorProvenance,
    },
    /// A MÍMIR proposal (OQGF-A-1). Phase 10.
    Proposal(ProposalRecord),
    /// A correction is an **event, not an edit** (§6.9): it annotates a prior entry by
    /// sequence number; the corrected entry's bytes, digest, and the chain through it are
    /// unchanged. Reading the chain means reading the corrections with it.
    Correction { corrects: u64, detail: String },
    /// A crypto-shred erasure tombstone (OQGF-P-11.5).
    Erasure(ErasureTombstone),
}

/// One append-only entry: a chain header plus a typed event, plus the accumulating
/// attestations that live outside the signed content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    /// Digest of the PRECEDING record's **signed content** — `seq`, `prev`, `at`, `dap`,
    /// `event` — and of nothing else (ARCH Rev 1.10). Genesis carries the declared genesis
    /// digest.
    pub prev: Digest,
    pub at: Timestamp,
    /// The accountable natural person (OQGF-A-5).
    pub dap: Dap,
    pub event: AuditEvent,
    /// Evidence-source provenance (Organ 5 evidence-capture hardening patch): **how** this record
    /// was captured — the sensor, the capture path, the sensor's timestamp, the coverage, and an
    /// explicit gap where coverage is incomplete. **Part of the signed content**: unlike the
    /// accumulating `signatures` (which is why Rev 1.10 excludes them), provenance is set once at
    /// capture, so it is signed and hash-chained — a non-key-holder cannot alter it undetected.
    /// The governed system SHALL NOT be the authority over its own evidence; where the orchestrator
    /// is itself the sensor, that is stated in `sensor_id` (F-23), never hidden.
    pub provenance: EvidenceProvenance,
    /// Signatures ACCUMULATE across cryptographic generations (OQGF-A-6); the first is the
    /// original and is never removed. **Not** part of the signed content.
    pub signatures: Vec<GenerationSignature>,
    /// A trusted timestamp, or the recorded fact of its absence (OQGF-A-3). **Not** part of
    /// the signed content — a TSA stamps the signed content, so it cannot be inside it.
    pub timestamping: Timestamping,
}

/// The injected RFC 3161 authority (OQGF-A-3). Phase 7 defines the **seam**; no production
/// implementation is provided (the spine performs no network I/O). Absent authority yields
/// [`Timestamping::Unavailable`].
pub trait TimestampAuthority: Send + Sync {
    fn stamp(&self, canonical: &[u8]) -> Result<TimestampToken, TimestampError>;
}

/// Why a timestamp could not be obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampError {
    /// The authority was configured but unreachable.
    Unreachable,
    /// The authority returned a malformed token.
    Malformed,
}

impl core::fmt::Display for TimestampError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TimestampError::Unreachable => f.write_str("timestamp authority unreachable"),
            TimestampError::Malformed => {
                f.write_str("timestamp authority returned a malformed token")
            }
        }
    }
}

impl std::error::Error for TimestampError {}
