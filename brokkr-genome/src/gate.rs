//! The OQGF-G-4 promotion gate (§6.2 Rev 1.5).
//!
//! A **Deterministic Gate** under OQGF-P-2: fail-closed and non-suppressible. It is
//! structurally unaddressable by a `ToleranceGrant` — a grant targets a `DetectorId`
//! (`brokkr_core::tolerance::ToleranceGrant::target`) and this gate has none, so there is
//! no value a suppression could point at. At Phase 5 a finding is a hard fail; the only
//! sanctioned path past one (Accountable Risk Acceptance, AMD-006) is Phase 6 and is not
//! present here.
//!
//! The gate evaluates **all seven predicates and returns all findings** — it never stops at
//! the first, so the human reading the report sees everything wrong at once.

use crate::canonical;
use crate::verdict::{CustodyShortfall, Finding, PromotionVerdict, Register};
use brokkr_core::capability::ConformanceTier;
use brokkr_core::genome::{DualControl, Genome, KeyCustody};
use brokkr_core::ids::Timestamp;
use brokkr_crypto::DualPublicKey;

/// 90 days in epoch milliseconds (§6.2 staleness arithmetic).
const NINETY_DAYS_MS: u64 = 7_776_000_000;

/// 365 days in epoch milliseconds — R-6.3's annual recovery-rehearsal bound (AMD-018).
const ONE_YEAR_MS: u64 = 31_536_000_000;

/// Evaluate a genome against the seven OQGF-G-4 promotion predicates.
///
/// `dap_key` is the **genome owner's declared verifying key, supplied out of band** by the
/// caller — non-circular by construction. It is deliberately **not** read from the genome's
/// own `RootsOfTrust` register: that register is itself signed, so verifying it with a key
/// it contains would prove nothing. `now` is an explicit parameter — the gate never reads a
/// wall clock. Returns `Promoted` only if every predicate passes; otherwise `Blocked` with
/// every finding.
pub fn promote(genome: &Genome, dap_key: &DualPublicKey, now: Timestamp) -> PromotionVerdict {
    let mut findings: Vec<Finding> = Vec::new();

    // Predicate 1 (all six registers present) is a TYPE-level guarantee (I-10): `Genome`
    // has no `Option` register, so an incomplete genome is unrepresentable. There is no
    // runtime check here because there is no runtime state in which it could fail.

    check_signatures(genome, dap_key, &mut findings); // predicate 2
    check_disallowed_algorithms(genome, &mut findings); // predicate 3
    check_trust_score_staleness(genome, now, &mut findings); // predicate 4
    check_tool_capabilities(genome, &mut findings); // predicate 5
    check_invariant_wellformedness(genome, &mut findings); // predicate 6
    check_key_custody_tier(genome, now, &mut findings); // predicate 7

    if findings.is_empty() {
        PromotionVerdict::Promoted
    } else {
        PromotionVerdict::Blocked { findings }
    }
}

/// Predicate 2 — every register signature verifies against the DAP root, and the genome
/// signature likewise. Dual-family (both ML-DSA and SLH-DSA required); fail closed on any
/// error.
fn check_signatures(g: &Genome, dap_key: &DualPublicKey, findings: &mut Vec<Finding>) {
    if dap_key
        .verify_dual(
            &canonical::tools_signed_content(&g.tools),
            &g.tools.signature,
        )
        .is_err()
    {
        findings.push(Finding::RegisterSignatureInvalid {
            register: Register::Tools,
        });
    }
    if dap_key
        .verify_dual(&canonical::cbom_signed_content(&g.cbom), &g.cbom.signature)
        .is_err()
    {
        findings.push(Finding::RegisterSignatureInvalid {
            register: Register::Cbom,
        });
    }
    if dap_key
        .verify_dual(
            &canonical::aibom_signed_content(&g.aibom),
            &g.aibom.signature,
        )
        .is_err()
    {
        findings.push(Finding::RegisterSignatureInvalid {
            register: Register::Aibom,
        });
    }
    if dap_key
        .verify_dual(
            &canonical::endpoints_signed_content(&g.endpoints),
            &g.endpoints.signature,
        )
        .is_err()
    {
        findings.push(Finding::RegisterSignatureInvalid {
            register: Register::Endpoints,
        });
    }
    if dap_key
        .verify_dual(
            &canonical::roots_signed_content(&g.roots),
            &g.roots.signature,
        )
        .is_err()
    {
        findings.push(Finding::RegisterSignatureInvalid {
            register: Register::Roots,
        });
    }
    if dap_key
        .verify_dual(
            &canonical::policy_signed_content(&g.policy),
            &g.policy.signature,
        )
        .is_err()
    {
        findings.push(Finding::RegisterSignatureInvalid {
            register: Register::Policy,
        });
    }
    if dap_key
        .verify_dual(&canonical::genome_signed_content(g), &g.signature)
        .is_err()
    {
        findings.push(Finding::GenomeSignatureInvalid);
    }
}

/// Predicate 3 — no algorithm in the CBOM inventory is on the policy disallow-list.
fn check_disallowed_algorithms(g: &Genome, findings: &mut Vec<Finding>) {
    for alg in &g.cbom.algorithms {
        if g.policy.disallowed.contains(alg) {
            findings.push(Finding::DisallowedAlgorithm { algorithm: *alg });
        }
    }
}

/// Predicate 4 — no stale (or future) trust score. Stale when `now - reviewed` exceeds 90
/// days; the subtraction saturates (never panics), and a `reviewed` in the future fails as
/// malformed.
fn check_trust_score_staleness(g: &Genome, now: Timestamp, findings: &mut Vec<Finding>) {
    for ep in &g.endpoints.endpoints {
        let reviewed = ep.trust_score.reviewed.0;
        if reviewed > now.0 {
            findings.push(Finding::FutureTrustScore {
                endpoint: ep.id.clone(),
            });
        } else if now.0.saturating_sub(reviewed) > NINETY_DAYS_MS {
            findings.push(Finding::StaleTrustScore {
                endpoint: ep.id.clone(),
            });
        }
    }
}

/// Predicate 5 — every capability a tool requires is in `policy.capabilities`.
fn check_tool_capabilities(g: &Genome, findings: &mut Vec<Finding>) {
    let vocabulary = &g.policy.capabilities;
    for tool in &g.tools.entries {
        for cap in &tool.required_capabilities {
            if !vocabulary.contains(cap) {
                findings.push(Finding::ToolCapabilityNotInVocabulary {
                    tool: tool.id.clone(),
                    capability: cap.clone(),
                });
            }
        }
    }
}

/// Predicate 6 (Rev 1.5) — every policy invariant is well-formed: every forbidden
/// capability is in the vocabulary, and the invariant forbids at least one thing.
///
/// Per Rev 1.5, forbidding a **recognized** capability that no tool currently requires is
/// legitimate forward-looking policy and does **not** fail — Rev 1.4's "no tool declares
/// it" clause is deliberately not re-added.
fn check_invariant_wellformedness(g: &Genome, findings: &mut Vec<Finding>) {
    let vocabulary = &g.policy.capabilities;
    for inv in &g.policy.invariants {
        for cap in &inv.forbids_capabilities {
            if !vocabulary.contains(cap) {
                findings.push(Finding::InvariantForbidsUnknownCapability {
                    invariant: inv.invariant.clone(),
                    capability: cap.clone(),
                });
            }
        }
        if inv.forbids_capabilities.is_empty() && inv.forbids_privilege.is_empty() {
            findings.push(Finding::InvariantForbidsNothing {
                invariant: inv.invariant.clone(),
            });
        }
    }
}

/// Predicate 7 (Rev 1.21, made buildable by Rev 1.22) — the declared key custody satisfies
/// the AMD-018 obligation for the genome's **declared** conformance tier.
///
/// **This is a tier-consistency check, not a presence check.** Presence is a type-level
/// guarantee: `Cbom::custody` and `Genome::tier` are both required fields, so a genome
/// missing either is unrepresentable and a runtime presence test could never fire — the
/// defect Rev 1.5 corrected in predicate 5 and predicate 6 condemns by name.
///
/// **What it proves and what it does not.** It proves a custody claim was made, is signed
/// into the genome, and is consistent with the tier the genome declares. It does **not**
/// prove the claim is true: a genome declaring `HardwareBacked` over keys held in process
/// memory passes here and violates R-6.2 entirely. AMD-018 §AMD.2.1 assigns that case to
/// assessment — "a declared custody model that overstates the separation actually achieved
/// is a conformance failure, not a documentation defect" — tested by requesting an export
/// and attempting a single-operator issuance against a live system, neither of which a gate
/// can do. The gate checks that a claim was made and that the claim, if true, meets the tier.
fn check_key_custody_tier(g: &Genome, now: Timestamp, findings: &mut Vec<Finding>) {
    let tier = g.tier;
    if let Some(element) = custody_shortfall(&g.cbom.custody, tier, now) {
        findings.push(Finding::KeyCustodyBelowTier { tier, element });
    }
}

/// The AMD-018 obligation per tier (ARCH §6.11's tier table). `None` means the declaration
/// meets the tier.
fn custody_shortfall(
    custody: &KeyCustody,
    tier: ConformanceTier,
    now: Timestamp,
) -> Option<CustodyShortfall> {
    match tier {
        // R-6.1 — any variant, `SoftwareInProcess` included. The obligation is that a
        // protection mechanism is *declared*, and every variant declares one by
        // construction: `ExtractionProtection` has no absent state. Nothing can fail here,
        // and that is the correct reading of R-6.1 rather than a vacuous check — the
        // firing half of this predicate lives at Enhanced and above.
        ConformanceTier::Baseline => None,

        // R-6.2 — a hardware boundary AND two-party issuance.
        ConformanceTier::Enhanced => custody_meets_r62(custody),

        // R-6.3 — R-6.2 plus a conformant threshold declaration.
        ConformanceTier::HighAssurance => {
            if let Some(shortfall) = custody_meets_r62(custody) {
                return Some(shortfall);
            }
            match custody {
                KeyCustody::Threshold {
                    quorum,
                    custodians,
                    last_rehearsal,
                    ..
                } => {
                    if quorum.validate().is_err() {
                        return Some(CustodyShortfall::QuorumBelowFloor);
                    }
                    // AMD-018 §AMD.3: fewer than `k` independent parties does not satisfy
                    // R-6.3, however well-formed the quorum is. Checked against `k` rather
                    // than `n` — a declared 3-of-5 held by one party fails on its own
                    // stated numbers.
                    if custodians.independent_parties < quorum.k {
                        return Some(CustodyShortfall::InsufficientCustodialSeparation);
                    }
                    // "SHALL rehearse recovery at least annually with the rehearsal
                    // recorded." Saturating arithmetic (§6 forbids panics); a rehearsal
                    // dated in the future is malformed and fails, exactly as predicate 4
                    // treats a future trust-score review.
                    if last_rehearsal.0 > now.0
                        || now.0.saturating_sub(last_rehearsal.0) > ONE_YEAR_MS
                    {
                        return Some(CustodyShortfall::RehearsalStale);
                    }
                    None
                }
                // R-6.2 passed, so this is `HardwareBacked` — a boundary and dual control
                // but no k-of-n custody.
                _ => Some(CustodyShortfall::NoThresholdCustody),
            }
        }
    }
}

/// R-6.2's two elements: a hardware boundary, and dual control on issuance and rotation.
/// Both are required — AMD-018 §AMD.5 is explicit that a FIPS validation is not by itself
/// evidence of dual control.
fn custody_meets_r62(custody: &KeyCustody) -> Option<CustodyShortfall> {
    let dual_control = match custody {
        KeyCustody::SoftwareInProcess { .. } => {
            return Some(CustodyShortfall::NoHardwareBoundary);
        }
        KeyCustody::HardwareBacked { dual_control, .. } => dual_control,
        KeyCustody::Threshold { dual_control, .. } => dual_control,
    };
    match dual_control {
        DualControl::SingleOperator => Some(CustodyShortfall::NoDualControl),
        DualControl::TwoParty { .. } => None,
    }
}
