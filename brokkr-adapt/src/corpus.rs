//! The evaluation-corpus content seam (Task 1, §6.12).
//!
//! §6.12 places this trait in `brokkr-adapt`, **not** `brokkr-core`: its `samples()` are
//! `(Observation, Option<AttackClass>)` pairs, and `Observation` is a `brokkr-sentinel` type —
//! `brokkr-core` SHALL NOT depend on `brokkr-sentinel` (I-5), so the seam cannot live in core
//! (core's `adapt` module doc records exactly this). It lives here, beside its only consumer,
//! [`crate::Kvasir::select`].
//!
//! REGIN owns the declared `EvaluationCorpus` record (a version); this seam supplies the samples
//! that record names. Selection does **not** trust [`EvaluationCorpusContent::digest`] — it
//! recomputes the digest over `samples()` and binds it to the DAP-declared digest KVASIR holds,
//! the same posture HEIMDALL takes toward `SelfSetCorpus::digest` (a substituted corpus controls
//! its own self-report, so the self-report cannot be the check).

use brokkr_core::adapt::AttackClass;
use brokkr_core::crypto::{Digest, Hasher};
use brokkr_core::ids::CorpusVersion;
use brokkr_crypto::Sha384Hasher;
use brokkr_sentinel::Observation;

/// The labeled evidence Gate 2 selects on (OQGF-P-6.2). Each sample is an [`Observation`]
/// paired with the attack class it exhibits, or `None` for benign. Coverage is measured across
/// the whole set, not only the seeded class.
pub trait EvaluationCorpusContent: Send + Sync {
    fn version(&self) -> CorpusVersion;
    fn samples(&self) -> &[(Observation, Option<AttackClass>)];
    /// The corpus's **self-reported** digest. Selection does not trust this — see the module doc.
    fn digest(&self) -> Digest;
}

/// An in-memory [`EvaluationCorpusContent`] — the seam's test double (§6.12: "a production
/// evaluation corpus" is out of scope; the seam plus a double). A production corpus is labeled
/// evidence about attacks and legitimate work in the deployment, sourced and DAP-signed; a
/// synthetic one would let a candidate beat a benchmark someone made up — the poisoning shape
/// entering through the evidence (§13), which is why this is only a double.
pub struct InMemoryCorpus {
    version: CorpusVersion,
    samples: Vec<(Observation, Option<AttackClass>)>,
}

impl InMemoryCorpus {
    pub fn new(version: CorpusVersion, samples: Vec<(Observation, Option<AttackClass>)>) -> Self {
        Self { version, samples }
    }
}

impl EvaluationCorpusContent for InMemoryCorpus {
    fn version(&self) -> CorpusVersion {
        self.version.clone()
    }
    fn samples(&self) -> &[(Observation, Option<AttackClass>)] {
        &self.samples
    }
    fn digest(&self) -> Digest {
        Sha384Hasher.hash(&crate::canonical::eval_corpus_digest_content(&self.samples))
    }
}
