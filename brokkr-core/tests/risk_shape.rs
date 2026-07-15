//! Construction / shape tests for the AMD-008 (OQGF-P-10) Risk Register family and the
//! AMD-009 (OQGF-P-11) core value types (Phase 1 revision). Integration test: a separate
//! crate, so it may use `unwrap`/`panic`. Existing tests are untouched.
//!
//! There is no new *numbered* invariant here (the DAP asked, and the answer is: the four
//! dispositions are mutually exclusive by enum construction, and the residual is non-empty
//! by required `Box` field — both are ordinary type facts, not I-13). The compile-time
//! "Reduce needs a residual" proof is a `compile_fail,E0063` doctest on
//! `brokkr_core::risk::Disposition`.

use brokkr_core::crypto::{DualSignature, Signature, SignatureAlg};
use brokkr_core::ids::{Dap, RiskAcceptanceId, Timestamp};
use brokkr_core::personal_data::{Purpose, RetentionPeriod};
use brokkr_core::risk::{
    DeterministicGateId, Disposition, Impact, Likelihood, RiskAcceptance, RiskEntry, RiskId,
    RiskRegister, RiskSource, TransferMechanism, TreatmentPlan, TreatmentStatus,
};
use core::time::Duration;

fn dual_sig() -> DualSignature {
    DualSignature {
        lattice: Signature {
            alg: SignatureAlg::MlDsa65,
            bytes: vec![1, 2, 3],
        },
        hash_based: Signature {
            alg: SignatureAlg::SlhDsaShake192s,
            bytes: vec![4, 5, 6],
        },
    }
}

fn dap() -> Dap {
    Dap::new("Jeremy Rose", "dap-1")
}

fn gate_acceptance() -> RiskAcceptance {
    RiskAcceptance {
        finding: RiskAcceptanceId::new("ra-1"),
        gate: Some(DeterministicGateId::Genome),
        dap: dap(),
        justification: "quantum-vulnerable dependency; removal scheduled".into(),
        expiry: Timestamp(100),
        signature: dual_sig(),
    }
}

fn entry_with(disposition: Disposition) -> RiskEntry {
    RiskEntry {
        id: RiskId::new("risk-1"),
        description: "model drift on a shifting population".into(),
        context: "production classifier".into(),
        likelihood: Likelihood::Possible,
        impact: Impact::Major,
        owner: dap(),
        source: RiskSource::ThreatModel,
        disposition,
    }
}

#[test]
fn test_p10_accept_holds_a_risk_acceptance() {
    // OQGF-P-10.4: Accept carries the AMD-006 RiskAcceptance accountability record.
    let entry = entry_with(Disposition::Accept {
        acceptance: gate_acceptance(),
    });
    match entry.disposition {
        Disposition::Accept { acceptance } => {
            assert_eq!(acceptance.finding, RiskAcceptanceId::new("ra-1"));
            assert_eq!(acceptance.gate, Some(DeterministicGateId::Genome));
            assert_eq!(acceptance.dap, dap());
        }
        _ => panic!("expected Accept"),
    }
}

#[test]
fn test_p10_accept_supports_a_non_gate_risk() {
    // OQGF-P-10.4: a non-gate risk has no gate to attach to -> gate is None.
    let acceptance = RiskAcceptance {
        gate: None,
        ..gate_acceptance()
    };
    assert_eq!(acceptance.gate, None);
    let entry = entry_with(Disposition::Accept { acceptance });
    assert!(matches!(entry.disposition, Disposition::Accept { .. }));
}

#[test]
fn test_p10_reduce_and_transfer_carry_a_residual() {
    // The residual is Box<RiskEntry>, non-empty by type. Building WITHOUT one is a
    // compile error (missing field) — proven by the compile_fail,E0063 doctest on
    // Disposition. Here we build WITH a residual and confirm the shape holds.
    let residual = Box::new(entry_with(Disposition::Avoid {
        plan: TreatmentPlan {
            owner: dap(),
            target: Timestamp(200),
            status: TreatmentStatus::Open,
        },
    }));

    let reduce = Disposition::Reduce {
        plan: TreatmentPlan {
            owner: dap(),
            target: Timestamp(300),
            status: TreatmentStatus::Open,
        },
        residual: residual.clone(),
    };
    let transfer = Disposition::Transfer {
        mechanism: TransferMechanism::Insurance,
        residual,
    };

    // The residual is present and is itself a full RiskEntry.
    if let Disposition::Reduce { residual, .. } = &reduce {
        assert_eq!(residual.id, RiskId::new("risk-1"));
    } else {
        panic!("expected Reduce");
    }
    assert!(matches!(transfer, Disposition::Transfer { .. }));
}

#[test]
fn test_p10_avoid_carries_a_tracked_plan() {
    let avoid = Disposition::Avoid {
        plan: TreatmentPlan {
            owner: dap(),
            target: Timestamp(1),
            status: TreatmentStatus::Executed,
        },
    };
    if let Disposition::Avoid { plan } = avoid {
        assert_eq!(plan.status, TreatmentStatus::Executed);
    } else {
        panic!("expected Avoid");
    }
}

/// A trivial in-memory RiskRegister, proving the trait is implementable with the core
/// types (the real append-only, Organ-5 register is Phase 7).
struct MockRegister;
impl RiskRegister for MockRegister {
    fn record(&self, risk: RiskEntry) -> RiskId {
        risk.id
    }
    fn inventory(&self) -> Vec<RiskEntry> {
        Vec::new()
    }
}

#[test]
fn test_p10_risk_register_trait_is_implementable() {
    let reg = MockRegister;
    let id = reg.record(entry_with(Disposition::Accept {
        acceptance: gate_acceptance(),
    }));
    assert_eq!(id, RiskId::new("risk-1"));
    assert!(reg.inventory().is_empty());
}

#[test]
fn test_p11_purpose_and_retention_are_value_types() {
    // OQGF-P-11.3 / P-11.4: declared purpose and retention span. Value types only —
    // no crypto-shredding, no key handle, no erasure logic in core.
    let purpose = Purpose {
        description: "fraud-detection model training".into(),
    };
    let retention = RetentionPeriod {
        duration: Duration::from_secs(7 * 365 * 24 * 3600),
    };
    assert_eq!(purpose.description, "fraud-detection model training");
    assert_eq!(retention.duration.as_secs(), 7 * 365 * 24 * 3600);
}
