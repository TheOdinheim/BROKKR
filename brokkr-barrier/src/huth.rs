//! HÚÐ — the Barrier implementation (AMD-007, §6.5).
//!
//! A **Deterministic Gate** under OQGF-P-2: fail-closed and non-suppressible. Egress denies
//! unless all nine §6.5 conditions hold; the only sanctioned way past a `Deny` is an AMD-006
//! `AcceptedRisk`, a **distinct verdict** with the finding preserved — never a flag on
//! `Allow`, and there is no method anywhere turning a `Deny` into an `Allow` (I-2). `now` is
//! an explicit parameter; the Barrier never reads a wall clock.

use crate::canonical;
use crate::resolver::{AcceptanceResolver, EndpointCeiling};
use brokkr_core::barrier::{
    Barrier, BarrierCondition, BarrierFinding, BarrierVerdict, BoundaryCustodyRecord, BoundaryFlow,
    ContextClass, Destination, DestinationClass, PersonalDataTag,
};
use brokkr_core::classification::{ChannelStrength, Classification, effective_authorization};
use brokkr_core::crypto::DualSignature;
use brokkr_core::ids::{DatumRef, FindingId, Timestamp};
use brokkr_core::risk::{DeterministicGateId, RiskAcceptance};
use brokkr_crypto::DualPublicKey;

/// A verify-only key held as raw dual-family public bytes. Stored as bytes (not a
/// `DualPublicKey`) so the Barrier is `Send + Sync` and the key is minted per verification —
/// the same pattern SINDRI's `RegistryResolver` uses. A malformed key fails closed.
type KeyBytes = (Vec<u8>, Vec<u8>);

/// The Barrier. Generic over the two injected seams (endpoint ceiling, acceptance resolver)
/// so it does not know where either answer came from (§6.5, the `KeyResolver` pattern).
///
/// It holds two declared verifying keys, supplied out of band at construction: `bcr_key`
/// verifies Boundary Custody Records (OQGF-I-9), and `dap_key` verifies risk acceptances
/// (AMD-006). Neither is ever read from the artifact it verifies — that would be circular.
pub struct Huth<C: EndpointCeiling, A: AcceptanceResolver> {
    bcr_key: KeyBytes,
    dap_key: KeyBytes,
    ceiling: C,
    acceptances: A,
}

impl<C: EndpointCeiling, A: AcceptanceResolver> Huth<C, A> {
    /// Construct a Barrier. `bcr_key` and `dap_key` are raw dual-family public keys
    /// `(ml_dsa_65, slh_dsa_shake_192s)` for BCR and acceptance signatures respectively.
    pub fn new(bcr_key: KeyBytes, dap_key: KeyBytes, ceiling: C, acceptances: A) -> Self {
        Self {
            bcr_key,
            dap_key,
            ceiling,
            acceptances,
        }
    }

    // ---- signature verification (fail-closed; key minted per call) -------------------

    fn verify_under(key: &KeyBytes, msg: &[u8], sig: &DualSignature) -> bool {
        match DualPublicKey::from_public_bytes(&key.0, &key.1) {
            Ok(pk) => pk.verify_dual(msg, sig).is_ok(),
            Err(_) => false, // a malformed declared key verifies nothing (fail closed)
        }
    }

    // ---- egress (§6.5 conditions 1–9) ------------------------------------------------

    fn egress(
        &self,
        datum: &DatumRef,
        classification: Classification,
        personal: &Option<PersonalDataTag>,
        destination: &Destination,
        bcr: &Option<BoundaryCustodyRecord>,
        now: Timestamp,
    ) -> BarrierVerdict {
        // Condition 1 — short-circuit to Allow ONLY when Public AND non-personal. The
        // personal conjunct is the Rev 1.7 correction: OQGF-P-11.1 governs personal data at
        // every tier, Public included.
        if classification == Classification::Public && personal.is_none() {
            return BarrierVerdict::Allow;
        }
        match self.egress_conditions(datum, classification, personal, destination, bcr, now) {
            Ok(()) => BarrierVerdict::Allow,
            // First-failing condition in §6.5's order names the finding (see the report).
            Err(condition) => self.deny_or_accept(datum, condition, classification, now),
        }
    }

    /// Conditions 2–9 in §6.5 order; returns the **first** failing condition.
    fn egress_conditions(
        &self,
        datum: &DatumRef,
        classification: Classification,
        personal: &Option<PersonalDataTag>,
        destination: &Destination,
        bcr: &Option<BoundaryCustodyRecord>,
        now: Timestamp,
    ) -> Result<(), BarrierCondition> {
        // 2 — a BCR is present.
        let bcr = bcr.as_ref().ok_or(BarrierCondition::MissingCustodyRecord)?;
        // 3 — the record matches the datum.
        if bcr.datum != *datum {
            return Err(BarrierCondition::DatumMismatch);
        }
        // 4 — the signature verifies (dual-family, under the declared BCR key).
        if !Self::verify_under(
            &self.bcr_key,
            &canonical::bcr_signed_content(bcr),
            &bcr.signature,
        ) {
            return Err(BarrierCondition::SignatureInvalid);
        }
        // 5 — not expired.
        if now.0 > bcr.expiry.0 {
            return Err(BarrierCondition::Expired);
        }
        // 6 — the record is for this classification.
        if bcr.classification != classification {
            return Err(BarrierCondition::ClassificationMismatch);
        }
        // 7 — the destination is authorized.
        if !destination_authorized(destination, &bcr.authorized) {
            return Err(BarrierCondition::UnauthorizedDestination);
        }
        // 8 — channel strength (Network and Reasoner only).
        if !self.channel_strong_enough(destination, classification) {
            return Err(BarrierCondition::ChannelStrengthCollapse);
        }
        // 9 — personal data carries a matching declared Purpose/Retention in its BCR.
        if let Some(flow_tag) = personal
            && bcr.personal.as_ref() != Some(flow_tag)
        {
            return Err(BarrierCondition::PersonalDataUndeclared);
        }
        Ok(())
    }

    /// Condition 8. `LocalPath` has no channel, so it is n/a (true). `Network`'s ceiling is
    /// its `ChannelStrength` alone; `Reasoner`'s is the endpoint ceiling combined with the
    /// negotiated group. An **unresolvable** endpoint fails closed as a channel-strength
    /// collapse: without the ceiling the Barrier cannot prove the channel may carry the
    /// data, so it does not.
    fn channel_strong_enough(
        &self,
        destination: &Destination,
        classification: Classification,
    ) -> bool {
        match destination {
            Destination::LocalPath(_) => true,
            Destination::Network { channel, .. } => channel.permits() >= classification,
            Destination::Reasoner {
                endpoint,
                negotiated,
            } => match self.ceiling.resolve(endpoint) {
                Some(endpoint_max) => {
                    effective_authorization(endpoint_max, ChannelStrength::from_group(*negotiated))
                        >= classification
                }
                None => false,
            },
        }
    }

    /// Build the finding for a failed condition and either honor a matching acceptance
    /// (returning the distinct `AcceptedRisk` variant) or let the `Deny` stand.
    fn deny_or_accept(
        &self,
        datum: &DatumRef,
        condition: BarrierCondition,
        classification: Classification,
        now: Timestamp,
    ) -> BarrierVerdict {
        let finding = BarrierFinding {
            datum: datum.clone(),
            condition,
            classification,
            reason: reason_for(condition).into(),
        };
        let finding_id = finding.finding_id();
        if let Some((entry, acceptance)) = self.acceptances.resolve(&finding_id)
            && self.honor(&acceptance, &finding_id, now)
        {
            return BarrierVerdict::AcceptedRisk { entry };
        }
        BarrierVerdict::Deny { finding }
    }

    /// The §6.5 honoring rule — an acceptance is honored only when **all** hold. Otherwise
    /// the `Deny` stands unchanged. On expiry the finding reverts to blocking exactly as if
    /// no entry existed (OQGF-P-9.3): no grace, no renewal, no memory of a lapsed acceptance.
    fn honor(&self, acceptance: &RiskAcceptance, finding_id: &FindingId, now: Timestamp) -> bool {
        acceptance.finding == *finding_id
            && acceptance.gate == Some(DeterministicGateId::Barrier)
            && Self::verify_under(
                &self.dap_key,
                &canonical::acceptance_signed_content(acceptance),
                &acceptance.signature,
            )
            && now.0 <= acceptance.expiry.0
    }

    // ---- ingress (§6.5) --------------------------------------------------------------

    fn ingress(
        &self,
        datum: &DatumRef,
        personal: &Option<PersonalDataTag>,
        bcr: &Option<BoundaryCustodyRecord>,
        context: ContextClass,
        now: Timestamp,
    ) -> BarrierVerdict {
        // Provenance is established when a BCR is present, matches the datum, verifies, and
        // is unexpired.
        let established = bcr
            .as_ref()
            .filter(|b| self.provenance_established(b, datum, now));

        match established {
            Some(b) => {
                // Personal data into a Privileged Context additionally requires a matching
                // declared Purpose/Retention in the BCR (OQGF-P-11.2). This composes with
                // the provenance rule; it does not replace it.
                if matches!(context, ContextClass::Privileged)
                    && personal.is_some()
                    && b.personal.as_ref() != personal.as_ref()
                {
                    return BarrierVerdict::Quarantine {
                        datum: datum.clone(),
                    };
                }
                BarrierVerdict::Allow
            }
            None => match context {
                // Unprovenanced into a Privileged Context is held, not destroyed.
                ContextClass::Privileged => BarrierVerdict::Quarantine {
                    datum: datum.clone(),
                },
                // Unprovenanced into a non-privileged context is allowed — quarantine is not
                // denial; discarding useful public data is non-conformant (OQGF-I-11).
                ContextClass::NonPrivileged => BarrierVerdict::Allow,
            },
        }
    }

    fn provenance_established(
        &self,
        bcr: &BoundaryCustodyRecord,
        datum: &DatumRef,
        now: Timestamp,
    ) -> bool {
        bcr.datum == *datum
            && now.0 <= bcr.expiry.0
            && Self::verify_under(
                &self.bcr_key,
                &canonical::bcr_signed_content(bcr),
                &bcr.signature,
            )
    }
}

impl<C: EndpointCeiling, A: AcceptanceResolver> Barrier for Huth<C, A> {
    fn evaluate(&self, flow: &BoundaryFlow, now: Timestamp) -> BarrierVerdict {
        match flow {
            BoundaryFlow::Egress {
                datum,
                classification,
                personal,
                destination,
                bcr,
            } => self.egress(datum, *classification, personal, destination, bcr, now),
            BoundaryFlow::Ingress {
                datum,
                personal,
                bcr,
                context,
            } => self.ingress(datum, personal, bcr, *context, now),
        }
    }
}

/// Whether a live [`Destination`] matches any coarse [`DestinationClass`] the BCR
/// pre-authorized (§6.5 condition 7). The channel/negotiated-group carried by the live
/// destination is deliberately ignored here — that is condition 8's separate question.
fn destination_authorized(destination: &Destination, authorized: &[DestinationClass]) -> bool {
    authorized.iter().any(|d| match (destination, d) {
        (Destination::LocalPath(p), DestinationClass::LocalPath(q)) => p == q,
        (Destination::Network { host, .. }, DestinationClass::Network { host: h }) => host == h,
        (Destination::Reasoner { endpoint, .. }, DestinationClass::Reasoner { endpoint: e }) => {
            endpoint == e
        }
        _ => false,
    })
}

/// Human-readable detail per condition — the finding's `reason`, which is **outside** the
/// match key (an acceptance turns on `finding_id`, never on this wording).
fn reason_for(condition: BarrierCondition) -> &'static str {
    match condition {
        BarrierCondition::MissingCustodyRecord => {
            "no Boundary Custody Record for an above-Public or personal egress"
        }
        BarrierCondition::DatumMismatch => "the custody record does not cover this datum",
        BarrierCondition::SignatureInvalid => "the custody record signature did not verify",
        BarrierCondition::Expired => "the custody record has expired",
        BarrierCondition::ClassificationMismatch => {
            "the custody record is for a different classification"
        }
        BarrierCondition::UnauthorizedDestination => {
            "this destination is not authorized by the record"
        }
        BarrierCondition::ChannelStrengthCollapse => {
            "the channel's effective authorization is below the data's classification"
        }
        BarrierCondition::PersonalDataUndeclared => {
            "personal data crossing without a matching declared Purpose and Retention"
        }
        BarrierCondition::PersonalDataFieldOutOfScope => {
            "the datum declares a field the signed policy does not permit its declared Purpose"
        }
    }
}
