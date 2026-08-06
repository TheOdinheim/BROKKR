//! SAGA — the append-only, hash-linked, dual-family-signed audit store, its chain
//! self-verification, re-signing, crypto-shred erasure recording, signed export and subject
//! rights, and the two registers Organ 5 persists.
//!
//! ## Structural facts this crate depends on
//!
//! - **The chain links over signed content only** ([`crate::canonical::record_signed_content`],
//!   Rev 1.10), so [`Saga::resign`] — which appends a [`GenerationSignature`] — cannot disturb
//!   any link. Proven as a property, not assumed (`tests/audit.rs`).
//! - **Re-signing cannot resurrect erased data (OQGF-P-11.7), structurally.** [`Saga`] holds
//!   **no** `brokkr_crypto::SubjectKey` and no field offering decryption; [`Saga::resign`]
//!   receives only a `&DualKeyPair` (which offers `sign_dual`/`verify_dual`/`public_key_bytes`
//!   — no decrypt), and it operates over [`crate::canonical::record_signed_content`], which
//!   copies any `ciphertext: Vec<u8>` verbatim into the digest input and never decrypts. The
//!   only type that can turn ciphertext into plaintext (`SubjectKey::unwrap_data_key`) never
//!   appears in `brokkr-audit`, so a decrypt path is **unrepresentable**, not merely un-taken.
//! - **`RiskRegister: Send + Sync`** (brokkr-core) forces [`Saga`] to be `Send + Sync`. The
//!   FFI key types carry `unsafe impl Send/Sync`, so `DualKeyPair` is `Send + Sync`, and the
//!   mutable store sits behind a `Mutex`. No panic on a poisoned lock — the guard is recovered.

use std::sync::Mutex;

use brokkr_core::crypto::{Digest, DualSignature, Hasher, Signature, SignatureAlg};
use brokkr_core::ids::{Dap, Nonce, OrganId, RiskAcceptanceId, SubjectId, Timestamp};
use brokkr_core::personal_data::{Purpose, RetentionPeriod};
use brokkr_core::risk::{RiskAcceptance, RiskEntry, RiskId, RiskRegister};
use brokkr_core::signal::{PostureEffect, Severity, Signal, SignalClass, SignalScope};
use brokkr_crypto::{DualKeyPair, DualPublicKey, Sha384Hasher};

use crate::canonical;
use crate::event::{
    AuditEvent, AuditRecord, CryptoGeneration, ErasureTombstone, GenerationSignature,
    TimestampAuthority, Timestamping,
};

/// Raw dual-family public bytes `(ml_dsa_65, slh_dsa_shake_192s)` for one generation.
type PublicBytes = (Vec<u8>, Vec<u8>);

/// Why a SAGA operation failed. Hand-rolled (no `thiserror`), as `brokkr-core` is.
#[derive(Debug)]
pub enum SagaError {
    /// The cryptographic backend failed (signing / key export).
    Crypto(brokkr_core::crypto::CryptoError),
    /// A referenced record sequence number does not exist.
    NoSuchRecord,
}

impl core::fmt::Display for SagaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SagaError::Crypto(e) => write!(f, "cryptographic backend error: {e}"),
            SagaError::NoSuchRecord => f.write_str("no such record"),
        }
    }
}

impl std::error::Error for SagaError {}

/// The result of a chain self-verification: intact, or broken with the trigger `Signal`.
#[derive(Debug)]
pub enum ChainStatus {
    Intact,
    /// A mismatch was found. The audit-chain-break trigger (OQGF-A.6.1) — a signed `Signal`
    /// from `OrganId::Audit` — is carried, constructed rather than merely returned as an error.
    Broken(Signal),
}

/// One held datum of a subject's personal data (OQGF-P-11.6): its record, declared Purpose
/// and Retention Period, and whether it has been erased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectDatum {
    pub seq: u64,
    pub purpose: Purpose,
    pub retention: RetentionPeriod,
    pub erased: bool,
}

/// A read-only, signed export of the chain (OQGF-A-7). It is a value — there is no path from
/// it back to a mutable store. `signature` covers `records` (with their signatures and
/// timestamps) under the exporter's key; verify it with [`SignedExport::verify`].
#[derive(Debug, Clone)]
pub struct SignedExport {
    pub records: Vec<AuditRecord>,
    pub signer_public: PublicBytes,
    pub signature: DualSignature,
}

impl SignedExport {
    /// Verify the bundle was not altered in transit, under the given expected public key.
    /// Pass the exporter's known public bytes; the embedded `signer_public` is a convenience
    /// and is checked to equal `expected` first (a bundle claiming a different signer fails).
    pub fn verify(&self, expected: &PublicBytes) -> bool {
        if &self.signer_public != expected {
            return false;
        }
        let bytes = canonical::export_signed_content(&self.records);
        verify_under(expected, &bytes, &self.signature)
    }
}

/// Verify a dual-family signature under raw public bytes, minting the verify-only key per
/// call (fail-closed on malformed key). Mirrors the barrier's pattern; keeps `Saga` from
/// storing a non-`Send` key would be unnecessary here, but this is the uniform verify path.
fn verify_under(key: &PublicBytes, msg: &[u8], sig: &DualSignature) -> bool {
    match DualPublicKey::from_public_bytes(&key.0, &key.1) {
        Ok(pk) => pk.verify_dual(msg, sig).is_ok(),
        Err(_) => false,
    }
}

struct SagaState {
    records: Vec<AuditRecord>,
    /// Per-generation verifier keys. Genesis generation registered at construction; each
    /// re-signing generation registered on first use.
    verifiers: Vec<(CryptoGeneration, PublicBytes)>,
    /// The Risk Register (OQGF-P-10.6) — append-only.
    risks: Vec<RiskEntry>,
    /// The Risk-Acceptance Register (OQGF-P-9.5) — append-only, keyed by a SAGA-assigned id.
    acceptances: Vec<(RiskAcceptanceId, RiskAcceptance)>,
    /// Monotonic counter for acceptance ids.
    next_acceptance: u64,
}

/// The Audit Spine.
pub struct Saga {
    signer: DualKeyPair,
    generation: CryptoGeneration,
    genesis: Digest,
    tsa: Option<Box<dyn TimestampAuthority>>,
    state: Mutex<SagaState>,
}

impl Saga {
    /// Create an empty spine that signs new records under `generation` with `signer`, links
    /// its first record to `genesis`, and stamps records via `tsa` if one is supplied
    /// (absent authority yields [`Timestamping::Unavailable`], never a refusal to record).
    pub fn new(
        signer: DualKeyPair,
        generation: CryptoGeneration,
        genesis: Digest,
        tsa: Option<Box<dyn TimestampAuthority>>,
    ) -> Result<Self, SagaError> {
        let public = signer.public_key_bytes().map_err(SagaError::Crypto)?;
        let state = SagaState {
            records: Vec::new(),
            verifiers: vec![(generation, public)],
            risks: Vec::new(),
            acceptances: Vec::new(),
            next_acceptance: 0,
        };
        Ok(Saga {
            signer,
            generation,
            genesis,
            tsa,
            state: Mutex::new(state),
        })
    }

    /// Reconstruct a spine from previously produced records and their verifier keys (the
    /// import counterpart to [`Saga::export`]; disk persistence is a future phase). The caller
    /// SHALL call [`Saga::verify_chain`] afterwards — this does **not** re-verify on load.
    pub fn from_records(
        signer: DualKeyPair,
        generation: CryptoGeneration,
        genesis: Digest,
        tsa: Option<Box<dyn TimestampAuthority>>,
        records: Vec<AuditRecord>,
        verifiers: Vec<(CryptoGeneration, PublicBytes)>,
    ) -> Self {
        let state = SagaState {
            records,
            verifiers,
            risks: Vec::new(),
            acceptances: Vec::new(),
            next_acceptance: 0,
        };
        Saga {
            signer,
            generation,
            genesis,
            tsa,
            state: Mutex::new(state),
        }
    }

    /// Recover the state guard without panicking on a poisoned lock.
    fn state(&self) -> std::sync::MutexGuard<'_, SagaState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The exporter's / signer's public bytes, for a recipient to verify records or exports.
    pub fn signer_public(&self) -> Result<PublicBytes, SagaError> {
        self.signer.public_key_bytes().map_err(SagaError::Crypto)
    }

    /// Append a new record: `seq` increments, `prev` is the digest of the previous record's
    /// **signed content** (genesis for the first), the signed content is signed dual-family
    /// and pushed as the first [`GenerationSignature`], and a timestamp is attached or its
    /// absence recorded. Returns the new record's `seq`.
    pub fn append(&self, event: AuditEvent, dap: Dap, at: Timestamp) -> Result<u64, SagaError> {
        let mut st = self.state();
        let seq = st.records.len() as u64;
        let prev = match st.records.last() {
            None => self.genesis.clone(),
            Some(last) => Sha384Hasher.hash(&canonical::record_signed_content(last)),
        };

        // Build the record; `signatures`/`timestamping` are outside the signed content, so
        // the placeholder values below do not affect what gets signed.
        let mut record = AuditRecord {
            seq,
            prev,
            at,
            dap,
            event,
            signatures: Vec::new(),
            timestamping: Timestamping::Unavailable {
                reason: String::from("pending"),
            },
        };

        let signed = canonical::record_signed_content(&record);
        let signature = self.signer.sign_dual(&signed).map_err(SagaError::Crypto)?;
        record.signatures.push(GenerationSignature {
            generation: self.generation,
            signed_at: at,
            signature,
        });
        record.timestamping = self.stamp(&signed);

        st.records.push(record);
        Ok(seq)
    }

    fn stamp(&self, signed: &[u8]) -> Timestamping {
        match &self.tsa {
            None => Timestamping::Unavailable {
                reason: String::from("no timestamp authority configured"),
            },
            Some(tsa) => match tsa.stamp(signed) {
                Ok(token) => Timestamping::Token(token),
                Err(e) => Timestamping::Unavailable {
                    reason: format!("timestamp authority error: {e}"),
                },
            },
        }
    }

    /// Walk the chain from genesis, recomputing each `prev`, verifying every record's whole
    /// signature set (each under its generation's key), and checking that a record carries at
    /// least one signature. Any mismatch yields [`ChainStatus::Broken`] carrying the signed
    /// audit-chain-break `Signal` (OQGF-A.6.1). Timestamp tokens are checked for presence
    /// only — no external TSA verification is in scope this phase.
    pub fn verify_chain(&self) -> ChainStatus {
        let st = self.state();
        let mut expected_prev = self.genesis.clone();
        for r in &st.records {
            let signed = canonical::record_signed_content(r);
            if r.prev != expected_prev {
                return ChainStatus::Broken(self.chain_break_signal("prev digest mismatch"));
            }
            if r.signatures.is_empty() {
                return ChainStatus::Broken(self.chain_break_signal("record carries no signature"));
            }
            for gs in &r.signatures {
                let key = st
                    .verifiers
                    .iter()
                    .find(|(g, _)| *g == gs.generation)
                    .map(|(_, k)| k);
                let ok = match key {
                    Some(k) => verify_under(k, &signed, &gs.signature),
                    None => false,
                };
                if !ok {
                    return ChainStatus::Broken(
                        self.chain_break_signal("record signature failed to verify"),
                    );
                }
            }
            expected_prev = Sha384Hasher.hash(&signed);
        }
        ChainStatus::Intact
    }

    /// Re-sign record `seq` under `generation` with `new_signer` (OQGF-A-6). **Appends** a
    /// [`GenerationSignature`]; never replaces or removes an earlier one, and never alters
    /// `seq`, `prev`, `at`, `dap`, or `event`. Because the chain links over signed content
    /// only, the following record's `prev` is unchanged by construction.
    ///
    /// `new_signer: &DualKeyPair` offers signing, not decryption — see the module note on why
    /// re-signing cannot resurrect erased data.
    pub fn resign(
        &self,
        seq: u64,
        generation: CryptoGeneration,
        new_signer: &DualKeyPair,
        at: Timestamp,
    ) -> Result<(), SagaError> {
        let idx = usize::try_from(seq).map_err(|_| SagaError::NoSuchRecord)?;
        let mut st = self.state();

        let signed = {
            let r = st.records.get(idx).ok_or(SagaError::NoSuchRecord)?;
            canonical::record_signed_content(r)
        };
        let signature = new_signer.sign_dual(&signed).map_err(SagaError::Crypto)?;
        let public = new_signer.public_key_bytes().map_err(SagaError::Crypto)?;

        if !st.verifiers.iter().any(|(g, _)| *g == generation) {
            st.verifiers.push((generation, public));
        }
        let r = st.records.get_mut(idx).ok_or(SagaError::NoSuchRecord)?;
        r.signatures.push(GenerationSignature {
            generation,
            signed_at: at,
            signature,
        });
        Ok(())
    }

    /// Record a crypto-shred erasure (OQGF-P-11.5): append a signed [`ErasureTombstone`]. The
    /// erased record is **not** modified — its bytes, its digest, and the chain through it are
    /// unchanged; the tombstone is a new appended record. Destroying the subject key is the
    /// crypto layer's job (`SubjectKey::shred`), done by the caller — SAGA never holds a
    /// subject key (see the module note).
    pub fn record_erasure(
        &self,
        tombstone: ErasureTombstone,
        dap: Dap,
        at: Timestamp,
    ) -> Result<u64, SagaError> {
        self.append(AuditEvent::Erasure(tombstone), dap, at)
    }

    /// A read-only, signed export of the whole chain (OQGF-A-7).
    pub fn export(&self) -> Result<SignedExport, SagaError> {
        let records = self.state().records.clone();
        let bytes = canonical::export_signed_content(&records);
        let signature = self.signer.sign_dual(&bytes).map_err(SagaError::Crypto)?;
        let signer_public = self.signer.public_key_bytes().map_err(SagaError::Crypto)?;
        Ok(SignedExport {
            records,
            signer_public,
            signature,
        })
    }

    /// A snapshot of the chain's records.
    pub fn records(&self) -> Vec<AuditRecord> {
        self.state().records.clone()
    }

    /// The per-generation verifier keys, for reconstruction via [`Saga::from_records`].
    pub fn verifiers(&self) -> Vec<(CryptoGeneration, PublicBytes)> {
        self.state().verifiers.clone()
    }

    /// Answer a data subject (OQGF-P-11.6): every record holding personal data relating to
    /// `subject` (as a crypto-shredded input), with its declared Purpose and Retention Period
    /// and whether it has since been erased (a tombstone naming its `seq`).
    pub fn subject_report(&self, subject: &SubjectId) -> Vec<SubjectDatum> {
        let st = self.state();
        let mut out = Vec::new();
        for r in &st.records {
            if let AuditEvent::Proposal(p) = &r.event
                && let crate::event::RecordedInput::Shredded {
                    subject: s,
                    personal,
                    ..
                } = &p.input
                && s == subject
            {
                let erased = st
                    .records
                    .iter()
                    .any(|x| matches!(&x.event, AuditEvent::Erasure(t) if t.erased == r.seq));
                out.push(SubjectDatum {
                    seq: r.seq,
                    purpose: personal.purpose.clone(),
                    retention: personal.retention.clone(),
                    erased,
                });
            }
        }
        out
    }

    // ---- the Risk-Acceptance Register (OQGF-P-9.5) -----------------------------------

    /// Record a risk acceptance, assigning and returning its [`RiskAcceptanceId`]. **SAGA
    /// assigns the id on record** — this is where HÚÐ's acceptance resolver gets its
    /// `(id, record)` pair (§6.9). Append-only.
    pub fn record_acceptance(&self, acceptance: RiskAcceptance) -> RiskAcceptanceId {
        let mut st = self.state();
        let id = RiskAcceptanceId::new(format!("acc-{}", st.next_acceptance));
        st.next_acceptance += 1;
        st.acceptances.push((id.clone(), acceptance));
        id
    }

    /// Resolve an acceptance id back to its record (the resolver's lookup half).
    pub fn resolve_acceptance(&self, id: &RiskAcceptanceId) -> Option<RiskAcceptance> {
        self.state()
            .acceptances
            .iter()
            .find(|(k, _)| k == id)
            .map(|(_, v)| v.clone())
    }

    /// The standing inventory of accepted risks (OQGF-P-9.5), reportable on demand.
    pub fn acceptance_inventory(&self) -> Vec<(RiskAcceptanceId, RiskAcceptance)> {
        self.state().acceptances.clone()
    }

    // ---- the chain-break trigger -----------------------------------------------------

    /// Construct and sign the audit-chain-break `Signal` (OQGF-A.6.1, §11): a
    /// `SignalClass::ThreatDetected` at `Severity::Critical` from `OrganId::Audit`, raise-only.
    /// A broken audit chain is a concrete integrity detection over the store every other organ
    /// reasons from — hence a threat, at the highest severity SAGA can raise.
    fn chain_break_signal(&self, detail: &str) -> Signal {
        let mut signal = Signal {
            source: OrganId::Audit,
            class: SignalClass::ThreatDetected,
            severity: Severity::Critical,
            effect: PostureEffect::Raise {
                detail: format!("audit-chain-break: {detail}"),
            },
            scope: SignalScope {
                detail: String::from("saga-chain"),
            },
            nonce: Nonce(0),
            expiry: Timestamp(0),
            signature: empty_dual_signature(),
        };
        let body = canonical::signal_signed_content(&signal);
        // Fail-closed on the unreachable signing-error path (mirrors `Sha384Hasher`): an
        // empty-bytes signature is obviously invalid and never a fabricated valid one. The
        // alarm is still raised by returning the Signal.
        if let Ok(sig) = self.signer.sign_dual(&body) {
            signal.signature = sig;
        }
        signal
    }
}

/// A well-formed but empty (invalid) dual-family signature, used only as the fail-closed
/// placeholder for the chain-break alarm if signing is unavailable. Never used for a record.
fn empty_dual_signature() -> DualSignature {
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

/// The Risk Register (OQGF-P-10.6). `record` takes `&self` (brokkr-core), so the store is
/// behind interior mutability. Append-only: superseding an entry is a new push; nothing is
/// removed.
impl RiskRegister for Saga {
    fn record(&self, risk: RiskEntry) -> RiskId {
        let mut st = self.state();
        let id = risk.id.clone();
        st.risks.push(risk);
        id
    }

    fn inventory(&self) -> Vec<RiskEntry> {
        self.state().risks.clone()
    }
}
