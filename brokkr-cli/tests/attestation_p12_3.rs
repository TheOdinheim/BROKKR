//! OQGF-P-12.3 — environment attestation, end to end (ARCH Rev 1.23 §6.13).
//!
//! Two things this file establishes and one it deliberately does not.
//!
//! **Establishes:** BROKKR's *declared* envelope attests `Discrepant` on an unconfined host, and a
//! `Discrepant` attestation denies a hop before any gate. **Does not:** soften a probe to make a
//! rig pass. A test that needs a passing attestation supplies a **double** (`AttestedProbe` below);
//! `LinuxProbe` is never weakened, and no fixture's envelope is adjusted to flatter it.

use brokkr_cli::probe::{EnvironmentProbe, LinuxProbe};
use brokkr_core::capability::{
    AttestationOutcome, CapabilityEnvelope, CapabilityProperty, ConformanceTier,
    EnvironmentAttestation, ProbeOutcome,
};
use brokkr_core::ids::Timestamp;

/// BROKKR's declared envelope: `CodeExecution` + `NetworkAccess(localhost:8443)` +
/// `ExternalEffect(filesystem)` at Enhanced (ARCH §1.4, §6.13).
fn brokkr_envelope() -> CapabilityEnvelope {
    let mut env = CapabilityEnvelope::permissive();
    env.system_id = "brokkr".to_string();
    env.properties = vec![
        CapabilityProperty::CodeExecution,
        CapabilityProperty::NetworkAccess {
            declared_destinations: vec!["localhost:8443".to_string()],
        },
        CapabilityProperty::ExternalEffect {
            targets: vec!["filesystem".to_string()],
        },
    ];
    env.capability_tier = ConformanceTier::Enhanced;
    env.data_tier = ConformanceTier::Baseline;
    env.governing_tier = ConformanceTier::Enhanced;
    assert!(
        env.validate().is_ok(),
        "the declared envelope must validate"
    );
    env
}

/// **The expected and confirmed consequence (ARCH Rev 1.23 §6.13).** A normal Linux process can
/// spawn children, read `/proc/self/environ`, and write outside its sandbox, so capabilities
/// BROKKR's envelope declares absent are reachable and the attestation is `Discrepant`.
///
/// **This is the probe working, not failing.** The correct closure is OS-level confinement —
/// seccomp-bpf, network namespaces, a read-only root, dropped `capabilities(7)` — which is
/// deployment work. No change in this repository can make an unconfined process confined.
#[test]
fn test_p12_3_brokkr_fails_its_own_attestation_on_an_unconfined_host() {
    let attestation = LinuxProbe::default().attest(&brokkr_envelope(), Timestamp(1));

    let reachable = match &attestation.outcome {
        AttestationOutcome::Discrepant { reachable } => reachable,
        other => panic!(
            "an unconfined host must attest Discrepant; got {other:?}. If this now passes, the \
             host is confined — verify that before relaxing the test."
        ),
    };
    assert!(
        !reachable.is_empty(),
        "Discrepant must name what was reachable"
    );

    // Capabilities the envelope declares present are not probed: a declared capability is the
    // declaration being honoured, not a discrepancy.
    for p in &attestation.probes {
        if p.declared {
            assert!(
                matches!(p.outcome, ProbeOutcome::NotProbeable { .. }),
                "a declared capability is not probed; got {:?}",
                p.outcome
            );
        }
    }

    // Four variants are NotProbeable by construction and always will be.
    let unprobeable = attestation.unprobed().len();
    assert!(
        unprobeable >= 4,
        "at least four variants are unprobeable by construction; found {unprobeable}"
    );
}

/// `NotProbeable` must never be readable as confinement. Even with nothing reachable, an
/// attestation with an untested capability is `Incomplete`, never `Attested`.
#[test]
fn test_p12_3_incomplete_is_not_attested() {
    let attestation = LinuxProbe::default().attest(&brokkr_envelope(), Timestamp(1));
    assert!(
        !matches!(attestation.outcome, AttestationOutcome::Attested),
        "an attestation with untested capabilities must never read as Attested"
    );
}

/// A test double — the sanctioned way to obtain a passing attestation. It fabricates an
/// `Attested` outcome; it does **not** make `LinuxProbe` lenient.
struct AttestedProbe;
impl EnvironmentProbe for AttestedProbe {
    fn attest(&self, envelope: &CapabilityEnvelope, now: Timestamp) -> EnvironmentAttestation {
        EnvironmentAttestation {
            system_id: envelope.system_id.clone(),
            probes: Vec::new(),
            outcome: AttestationOutcome::Attested,
            probed_at: now,
        }
    }
}

#[test]
fn test_p12_3_double_supplies_a_passing_attestation_without_softening_the_probe() {
    let a = AttestedProbe.attest(&brokkr_envelope(), Timestamp(5));
    assert!(matches!(a.outcome, AttestationOutcome::Attested));

    // The real probe, on the same envelope and host, still says Discrepant. The double changed
    // the rig, not the probe.
    let real = LinuxProbe::default().attest(&brokkr_envelope(), Timestamp(5));
    assert!(matches!(
        real.outcome,
        AttestationOutcome::Discrepant { .. }
    ));
}
