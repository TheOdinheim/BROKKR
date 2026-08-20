//! KVASIR — the concrete [`MaturationPipeline`] (the four poisoning gates, §6.12).
//!
//! The core `MaturationPipeline` trait is deliberately minimal — its methods take a candidate
//! *spec*, a corpus *version*, a *provenance*, and `now`. The rich context a real refinement
//! needs lives on the concrete [`Kvasir`], supplied through seams: the authored `DetectorDelta`
//! (KVASIR gates, it does not invent — §6.12); the labeled evaluation corpus and the DAP-declared
//! digest it is bound to; the seeding incident's attack class and sample; the runnable candidate
//! and incumbent detectors (a `RefinedDetector` is a spec, not runnable — the authored detection
//! logic is supplied here); the current Self Set and a HEIMDALL to screen against (Gate 3 calls
//! HEIMDALL's `screen`, it does not reimplement it); the confirmed-incident ledger; and the DAP's
//! verify-only key. This is the seam pattern the rest of the spine uses (SINDRI's key resolver,
//! HEIMDALL's Self Set corpus).
//!
//! **`now` and time (I-13).** Only [`Kvasir::activate`] takes `now`, per the committed trait and
//! §6.12 — it is the one method that evaluates a pass *against the present* (the version-equality
//! gate; `now` reaches HEIMDALL's screen). `select` evaluates no expiry — KVASIR has **no**
//! expiry gate, only version-equality and content checks — so it takes no `now`, and the
//! `SelectionPass`'s `produced_at` is a held audit-trail stamp (`produced_at` below), not an
//! evaluated clock. KVASIR holds no stored-clock field, reads no wall clock, keeps no
//! interior-mutable time — the held-clock greps stay empty.

use brokkr_core::adapt::{
    AdaptError, AttackClass, DetectorDelta, DetectorProvenance, DetectorSpecBase, EvaluationCorpus,
    MaturationPipeline, PriorGeneration, RefinedDetector, SeedingIncident, SelectionPass,
};
use brokkr_core::crypto::{Digest, Hasher};
use brokkr_core::ids::{CorpusVersion, Timestamp};
use brokkr_core::tolerance::{DetectorSpec, SelfSet};
use brokkr_crypto::{DualPublicKey, Sha384Hasher};
use brokkr_sentinel::{DetectionVerdict, Detector, Heimdall, Observation};

use crate::canonical;
use crate::corpus::EvaluationCorpusContent;
use crate::ledger::ConfirmedIncidentLedger;

/// The Maturation Pipeline for one refinement. Implements [`MaturationPipeline`]; the fields are
/// the context the minimal trait cannot carry (see the module doc).
pub struct Kvasir<'a> {
    // --- Gate 1: seeding (OQGF-P-6.1) ---
    /// External source of truth for whether the seed is a DAP-confirmed Organ-5 incident.
    pub ledger: &'a dyn ConfirmedIncidentLedger,
    /// The heuristic detector being refined (the candidate's base).
    pub base: DetectorSpecBase,
    /// The **authored** change (§6.12: authored, not derived — no code turns a seed into
    /// detection logic; the author is a human or external tooling, never the reasoner).
    pub delta: DetectorDelta,
    /// The candidate's generation.
    pub generation: u64,

    // --- Gate 2: selection (OQGF-P-6.2) ---
    /// The labeled evaluation corpus (the seam; not trusted for its own digest).
    pub corpus: &'a dyn EvaluationCorpusContent,
    /// The DAP-declared digest the corpus content is bound to. `select` recomputes over
    /// `corpus.samples()` and compares to this — the substituted-corpus check. Held here because
    /// core's `EvaluationCorpus` carries only a version (the analog of `SelfSet.corpus_digest`).
    pub declared_corpus_digest: Digest,
    /// The version that IS current. A `select` arg naming any other version is stale drift.
    pub current_corpus_version: CorpusVersion,
    /// The seeding incident's attack class (select does not receive the seed).
    pub seed_attack_class: AttackClass,
    /// The seeding sample — for the non-containment check.
    pub seeding_sample: Observation,
    /// The runnable candidate detector (the authored logic; a `RefinedDetector` is a spec).
    pub candidate: &'a dyn Detector,
    /// The runnable incumbent — the currently-deployed detector, to compare coverage against.
    pub incumbent: &'a dyn Detector,
    /// The audit-trail stamp for `SelectionPass.produced_at`. NOT an evaluated clock — see the
    /// module doc (KVASIR has no expiry gate; `select` evaluates no time).
    pub produced_at: Timestamp,

    // --- Gate 3: tolerance (OQGF-P-6.3) ---
    /// A HEIMDALL to screen the candidate against, with the candidate **registered** (screen
    /// looks it up by id). Gate 3 calls its `screen`; it does not reimplement screening.
    pub screen: &'a Heimdall,
    /// The current Self Set the candidate is screened against.
    pub current_self_set: SelfSet,

    // --- Gate 4: activation (OQGF-P-6.4/6.5/6.6) ---
    /// The DAP's verify-only key. A provenance signature that does not verify under it is no valid
    /// DAP approval.
    pub dap_public: DualPublicKey,
    /// The generation this activation replaces — the reversibility handle returned on success.
    pub prior_generation: u64,
}

impl MaturationPipeline for Kvasir<'_> {
    /// Gate 1 (OQGF-P-6.1). A refinement may be seeded **only** by a DAP-confirmed incident
    /// recorded in Organ 5, verified through the ledger seam — not the caller's own `confirmed_by`
    /// claim. Then it stamps the **authored** delta into a candidate; it invents nothing.
    fn generate(&self, seed: &SeedingIncident) -> Result<RefinedDetector, AdaptError> {
        match self.ledger.confirmation(&seed.incident_id) {
            // Recorded AND attributed to the DAP the seed claims — a caller cannot assert a
            // confirmation the ledger does not record, nor pin it on a different DAP.
            Some(dap) if dap == seed.confirmed_by => {}
            _ => return Err(AdaptError::UnconfirmedSeed),
        }
        Ok(RefinedDetector::new(
            self.base.clone(),
            self.delta.clone(),
            self.generation,
        ))
    }

    /// Gate 2 (OQGF-P-6.2). Verify the corpus **before** measuring, then measure the candidate
    /// against the incumbent across the corpus.
    fn select(
        &self,
        _candidate: &RefinedDetector,
        corpus: &EvaluationCorpus,
    ) -> Result<SelectionPass, AdaptError> {
        // The runnable candidate is held (`self.candidate`); the spec arg identifies the
        // refinement but carries no runnable logic, so measurement uses the held detector.

        // (1) Selecting against a superseded corpus version — drift, not tampering.
        if corpus.version != self.current_corpus_version {
            return Err(AdaptError::StaleCorpus);
        }
        // (2) Substituted corpus: recompute the digest over the seam's samples and bind it to the
        // DAP-declared digest, BEFORE measuring. Nothing about the candidate is measured here.
        let recomputed = Sha384Hasher.hash(&canonical::eval_corpus_digest_content(
            self.corpus.samples(),
        ));
        if recomputed != self.declared_corpus_digest {
            return Err(AdaptError::SubstitutedCorpus);
        }
        // (3) Non-containment — NOT independence (§13): code verifies the corpus does not
        // *contain* the seed, not that it was *assembled* without the incident in view. A corpus
        // containing the seed lets the candidate improve on its own seed, which IS Overfit.
        if self
            .corpus
            .samples()
            .iter()
            .any(|(obs, _)| obs == &self.seeding_sample)
        {
            return Err(AdaptError::Overfit);
        }
        // (4) Measure. Improvement = catching a seeded-class attack the incumbent missed. Coverage
        // regression = a benign sample the candidate now fires on that the incumbent cleared, or a
        // different attack class the candidate stopped catching that the incumbent caught.
        let mut improvement: u64 = 0;
        let mut coverage_regression = false;
        for (obs, label) in self.corpus.samples() {
            let cand_fired = matches!(self.candidate.observe(obs), DetectionVerdict::Fired { .. });
            let inc_fired = matches!(self.incumbent.observe(obs), DetectionVerdict::Fired { .. });
            match label {
                Some(c) if *c == self.seed_attack_class => {
                    if cand_fired && !inc_fired {
                        improvement += 1;
                    }
                }
                Some(_) => {
                    if inc_fired && !cand_fired {
                        coverage_regression = true;
                    }
                }
                None => {
                    if cand_fired && !inc_fired {
                        coverage_regression = true;
                    }
                }
            }
        }
        // A regression disqualifies regardless of detection gains — a candidate that catches more
        // but breaks legitimate coverage is not an improvement (checked before improvement).
        if coverage_regression {
            return Err(AdaptError::CoverageRegression);
        }
        // No improvement beyond the incumbent, with the seed excluded, means the candidate
        // improved only on its seed — Overfit.
        if improvement == 0 {
            return Err(AdaptError::Overfit);
        }
        Ok(SelectionPass {
            version: self.current_corpus_version.clone(),
            produced_at: self.produced_at,
        })
    }

    /// Gates 3+4 (OQGF-P-6.3/6.4/6.5/6.6). Verify the provenance, that its screen and corpus name
    /// the CURRENT versions, screen the candidate against the current Self Set, and return the
    /// prior generation. Every refusal names the reason it actually is.
    fn activate(
        &self,
        candidate: RefinedDetector,
        provenance: DetectorProvenance,
        now: Timestamp,
    ) -> Result<PriorGeneration, AdaptError> {
        // Gate 4 approval (P-6.6): the DAP's dual-family signature over the provenance IS the
        // approval. A signature that does not verify under the declared DAP key is no valid
        // approval → NeedsApproval (true, not a false claim — GAP-2026-08-19-001 §2.1).
        let body = canonical::provenance_signed_content(&provenance);
        if self
            .dap_public
            .verify_dual(&body, &provenance.signature)
            .is_err()
        {
            return Err(AdaptError::NeedsApproval);
        }
        // Version equality, not recency (§6.12).
        // (a) The screen pass must be against the CURRENT Self Set; a stale screen does not
        // establish tolerance against the current baseline → FailsTolerance.
        if provenance.screen_result.version != self.current_self_set.version {
            return Err(AdaptError::FailsTolerance);
        }
        // (b) The selection must name the CURRENT corpus version → else StaleCorpus (drift).
        if provenance.corpus_version != self.current_corpus_version {
            return Err(AdaptError::StaleCorpus);
        }
        // Gate 3 (P-6.3): HEIMDALL's central-tolerance screen against the current Self Set —
        // called, not reimplemented. Discarded if it raises host harm REGARDLESS of detection
        // gains (this runs after selection has already established the gains — no trade curve).
        let spec = DetectorSpec {
            id: candidate.base().id.clone(),
        };
        if self
            .screen
            .screen(&spec, &self.current_self_set, now)
            .is_err()
        {
            return Err(AdaptError::FailsTolerance);
        }
        // All gates clear. Hand back the generation this activation replaces (P-6.5) — there is no
        // activation that does not return what it replaced.
        Ok(PriorGeneration {
            generation: self.prior_generation,
        })
    }
}
