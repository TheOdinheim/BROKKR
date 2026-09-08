//! OQGF-P-12.3 — environment attestation: the declare-then-test probe (ARCH Rev 1.23 §6.13).
//!
//! For each [`CapabilityProperty`] the envelope does **not** declare, the probe attempts to
//! exercise that capability and records whether the attempt was refused. This is the OQGF-M-3
//! declare-then-test pattern AMD-011 inherits, pointed at an operating environment instead of a
//! quantum device.
//!
//! ## The harmlessness rule
//!
//! **A probe may only attempt an action whose success is itself harmless and reversible.** Probing
//! `IdentityCreation` by creating an account, or `ExternalEffect` by writing outside the sandbox,
//! would *exercise* the capability rather than test for it — the probe would become the breach it
//! exists to detect. Where a capability cannot be tested harmlessly, the verdict is
//! [`ProbeOutcome::NotProbeable`], **never** an untested `Refused`.
//!
//! ## The two errno readings that carry the honesty
//!
//! Both point the same way, and a probe that got either backwards would report a confinement that
//! does not exist:
//!
//! - **`ConnectionRefused` is not refusal.** It proves the socket layer worked and a peer answered,
//!   so the capability is *present* → [`ProbeOutcome::Reachable`].
//! - **`NotFound` is not refusal.** It proves a target is missing, not that access is denied. The
//!   credential probe therefore opens `/proc/self/environ`, a path that **always exists on Linux**,
//!   so a `NotFound` there means the environment is confined (a hidden `/proc`) rather than that the
//!   file happens to be absent.
//!
//! ## What this crate cannot see
//!
//! Four variants are `NotProbeable` by construction and always will be, and `SubAgentCreation` is
//! not distinguishable from `CodeExecution` from inside one process — both are the spawn syscall. A
//! deployment that separates them does so above the process boundary, where an in-process probe
//! cannot look.

use brokkr_core::capability::{
    CapabilityEnvelope, CapabilityProbe, CapabilityProperty, EnvironmentAttestation, ProbeOutcome,
};
use brokkr_core::ids::Timestamp;
use std::io::ErrorKind;

/// The probe port (OQGF-P-12.3). A trait so a deployment can supply a probe matched to its
/// confinement, and so a test can supply a double — **never so a probe can be softened**: a rig
/// that needs a passing attestation supplies a double, it does not weaken [`LinuxProbe`].
pub trait EnvironmentProbe: Send + Sync {
    /// Probe the deployed environment against `envelope`, at `now`.
    fn attest(&self, envelope: &CapabilityEnvelope, now: Timestamp) -> EnvironmentAttestation;
}

/// The capabilities this probe knows how to attempt, in a fixed order so an attestation is
/// comparable across runs. `Other { .. }` is absent deliberately: it is prose, and the framework
/// cannot know what to attempt for it.
fn probe_set() -> Vec<CapabilityProperty> {
    vec![
        CapabilityProperty::CodeExecution,
        CapabilityProperty::NetworkAccess {
            declared_destinations: Vec::new(),
        },
        CapabilityProperty::CredentialAccess {
            scope: String::new(),
        },
        CapabilityProperty::ExternalEffect {
            targets: Vec::new(),
        },
        CapabilityProperty::SubAgentCreation,
        CapabilityProperty::Persistence,
        CapabilityProperty::IdentityCreation,
        CapabilityProperty::CrossRunMemory,
        CapabilityProperty::InterAgentCommunication,
        CapabilityProperty::SharedCoordinationState,
        CapabilityProperty::CrossRunCoordination,
        CapabilityProperty::CollectiveCapabilityAmplification,
    ]
}

/// Whether `envelope` declares a capability of the same *kind* as `p`. Compared by
/// `canonical_tag` rather than by value, because a declared `NetworkAccess { localhost:8443 }` and
/// the probe's `NetworkAccess { .. }` template are the same capability with different payloads.
fn declares(envelope: &CapabilityEnvelope, p: &CapabilityProperty) -> bool {
    envelope
        .properties
        .iter()
        .any(|d| d.canonical_tag() == p.canonical_tag())
}

/// A Linux environment probe. Every attempt is harmless: a `/bin/true` child that is reaped, a
/// connect to a reserved-for-documentation address, an `open` without a read, and an
/// `open`-for-write with `create_new` on a path that is removed if it is created.
pub struct LinuxProbe {
    /// A directory outside the declared sandbox, used by the external-effect and persistence
    /// probes. A deployment names its own; the default is the OS temp dir, which is *not* outside
    /// most sandboxes — a deployment that means the probe seriously supplies a real path.
    outside_root: std::path::PathBuf,
}

impl Default for LinuxProbe {
    fn default() -> Self {
        Self {
            outside_root: std::env::temp_dir(),
        }
    }
}

impl LinuxProbe {
    pub fn new(outside_root: std::path::PathBuf) -> Self {
        Self { outside_root }
    }

    /// Classify a filesystem/process error. `PermissionDenied` and `ReadOnlyFilesystem` are genuine
    /// refusals; **`NotFound` is not** (see the module docs), and neither is anything else — an
    /// unexpected error means the probe did not establish confinement, so it fails toward
    /// `ProbeError`, which drives `Incomplete` rather than `Attested`.
    fn classify_io(e: &std::io::Error, what: &str) -> ProbeOutcome {
        match e.kind() {
            ErrorKind::PermissionDenied => ProbeOutcome::Refused {
                detail: format!("{what}: permission denied (EPERM/EACCES)"),
            },
            ErrorKind::ReadOnlyFilesystem => ProbeOutcome::Refused {
                detail: format!("{what}: read-only filesystem (EROFS)"),
            },
            ErrorKind::NotFound => ProbeOutcome::Reachable {
                detail: format!(
                    "{what}: NotFound — the target is missing, which is NOT a refusal; \
                     access was not denied"
                ),
            },
            other => ProbeOutcome::ProbeError {
                detail: format!("{what}: unexpected error {other:?} — confinement not established"),
            },
        }
    }

    /// Spawn a trivial, side-effect-free child and reap it. Shared by `CodeExecution` and
    /// `SubAgentCreation` — from inside the process they are the same syscall.
    fn probe_spawn(&self) -> ProbeOutcome {
        match std::process::Command::new("/bin/true").output() {
            Ok(_) => ProbeOutcome::Reachable {
                detail: "spawned /bin/true and reaped it; process creation is available"
                    .to_string(),
            },
            Err(e) => Self::classify_io(&e, "spawn /bin/true"),
        }
    }

    /// Connect to an address that is **not** on any egress manifest. Uses TEST-NET-1
    /// (192.0.2.0/24, RFC 5737 — reserved for documentation, routed nowhere), so the attempt
    /// cannot reach a real host even where the network is open.
    fn probe_network(&self) -> ProbeOutcome {
        use std::net::{SocketAddr, TcpStream};
        use std::time::Duration;
        let addr: SocketAddr = match "192.0.2.1:9".parse() {
            Ok(a) => a,
            Err(e) => {
                return ProbeOutcome::ProbeError {
                    detail: format!("network probe: could not parse target address: {e}"),
                };
            }
        };
        match TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
            Ok(_) => ProbeOutcome::Reachable {
                detail: "connected to an off-manifest address (192.0.2.1:9)".to_string(),
            },
            Err(e) => match e.kind() {
                // The socket layer worked and a peer answered. NOT refusal (module docs).
                ErrorKind::ConnectionRefused => ProbeOutcome::Reachable {
                    detail: "ConnectionRefused from 192.0.2.1:9 — the socket layer worked and a \
                             peer answered, so egress is NOT confined"
                        .to_string(),
                },
                ErrorKind::PermissionDenied => ProbeOutcome::Refused {
                    detail: "connect refused by the environment (EPERM — seccomp or netfilter)"
                        .to_string(),
                },
                // A timeout against a black-holed reserved address is the common result on an
                // unconfined host with no route: the syscall was permitted and no answer came.
                // Permitted-but-unanswered is not confinement.
                ErrorKind::TimedOut | ErrorKind::WouldBlock => ProbeOutcome::Reachable {
                    detail: "connect() was permitted and timed out against a black-holed address; \
                             the syscall was not refused, so the capability is present"
                        .to_string(),
                },
                other => ProbeOutcome::ProbeError {
                    detail: format!(
                        "network probe: unexpected error {other:?} — confinement not established"
                    ),
                },
            },
        }
    }

    /// Open (not read) `/proc/self/environ` — a path that **always exists on Linux**, chosen so
    /// absence cannot be mistaken for refusal.
    fn probe_credentials(&self) -> ProbeOutcome {
        match std::fs::File::open("/proc/self/environ") {
            Ok(_) => ProbeOutcome::Reachable {
                detail: "opened /proc/self/environ; process credentials/environment are readable"
                    .to_string(),
            },
            Err(e) => Self::classify_io(&e, "open /proc/self/environ"),
        }
    }

    /// Open-for-write a path outside the declared sandbox root, creating and then removing it.
    /// `create_new` so an existing file is never truncated, and the file is removed on success —
    /// the harmlessness rule applied to the one probe whose success is a real write.
    fn probe_write_outside(&self, label: &str) -> ProbeOutcome {
        let path = self
            .outside_root
            .join(format!("brokkr-p123-probe-{}", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => {
                let _ = std::fs::remove_file(&path);
                ProbeOutcome::Reachable {
                    detail: format!("{label}: created {} outside the sandbox", path.display()),
                }
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                // A leftover from a previous run. The create was permitted up to the existence
                // check, so the capability is present.
                ProbeOutcome::Reachable {
                    detail: format!(
                        "{label}: {} already exists — the path is writable territory",
                        path.display()
                    ),
                }
            }
            Err(e) => Self::classify_io(&e, label),
        }
    }
}

impl EnvironmentProbe for LinuxProbe {
    fn attest(&self, envelope: &CapabilityEnvelope, now: Timestamp) -> EnvironmentAttestation {
        let mut probes: Vec<CapabilityProbe> = Vec::new();

        for capability in probe_set() {
            let declared = declares(envelope, &capability);
            // P-12.3 probes what the envelope declares ABSENT: a declared capability is not a
            // discrepancy, it is the declaration being honoured. It is still recorded, with the
            // probe skipped, so the attestation shows what was and was not examined.
            if declared {
                probes.push(CapabilityProbe {
                    capability,
                    declared: true,
                    attempted: "not probed — declared present in the envelope".to_string(),
                    outcome: ProbeOutcome::NotProbeable {
                        reason: "declared present; P-12.3 attests capabilities declared ABSENT"
                            .to_string(),
                    },
                });
                continue;
            }

            let (attempted, outcome) = match &capability {
                CapabilityProperty::CodeExecution => (
                    "spawn /bin/true and reap it".to_string(),
                    self.probe_spawn(),
                ),
                CapabilityProperty::SubAgentCreation => (
                    "spawn /bin/true and reap it (same syscall as CodeExecution — an in-process \
                     probe cannot distinguish the two)"
                        .to_string(),
                    self.probe_spawn(),
                ),
                CapabilityProperty::NetworkAccess { .. } => (
                    "connect to 192.0.2.1:9 (RFC 5737 TEST-NET-1, off-manifest)".to_string(),
                    self.probe_network(),
                ),
                CapabilityProperty::CredentialAccess { .. } => (
                    "open /proc/self/environ (a path that always exists)".to_string(),
                    self.probe_credentials(),
                ),
                CapabilityProperty::ExternalEffect { .. } => (
                    "create-new a file outside the sandbox root, then remove it".to_string(),
                    self.probe_write_outside("external-effect probe"),
                ),
                CapabilityProperty::Persistence => (
                    "create-new a file outside the sandbox root, then remove it".to_string(),
                    match self.probe_write_outside("persistence probe") {
                        // The write half is probeable; whether the PROCESS is restarted is not
                        // observable from inside it, so a successful write is reported for what it
                        // is and no more.
                        ProbeOutcome::Reachable { detail } => ProbeOutcome::Reachable {
                            detail: format!(
                                "{detail}; note: the write is probeable, process restart is not"
                            ),
                        },
                        other => other,
                    },
                ),
                CapabilityProperty::CrossRunMemory => (
                    "write half only".to_string(),
                    match self.probe_write_outside("cross-run-memory probe") {
                        ProbeOutcome::Refused { detail } => ProbeOutcome::Refused { detail },
                        // Writing is permitted, but the cross-run READ requires a prior run to have
                        // occurred, which one run cannot establish. Partial coverage is recorded as
                        // NotProbeable so it drives Incomplete, never Attested.
                        _ => ProbeOutcome::NotProbeable {
                            reason:
                                "the write half is permitted, but the cross-run read requires a \
                                     prior run; not establishable from one run"
                                    .to_string(),
                        },
                    },
                ),
                CapabilityProperty::InterAgentCommunication
                | CapabilityProperty::SharedCoordinationState => (
                    "no channel enumerated by the deployment".to_string(),
                    ProbeOutcome::NotProbeable {
                        reason: "probeable only against channels the deployment enumerates; a \
                                 channel nobody named is not probed"
                            .to_string(),
                    },
                ),
                CapabilityProperty::IdentityCreation => (
                    "nothing attempted".to_string(),
                    ProbeOutcome::NotProbeable {
                        reason: "creating an account, key, or persona acts against an external \
                                 service; attempting it would exercise the capability rather than \
                                 test for it (harmlessness rule)"
                            .to_string(),
                    },
                ),
                CapabilityProperty::CrossRunCoordination => (
                    "nothing attempted".to_string(),
                    ProbeOutcome::NotProbeable {
                        reason: "requires both a prior run and a peer; neither is observable from \
                                 one process in one run"
                            .to_string(),
                    },
                ),
                CapabilityProperty::CollectiveCapabilityAmplification => (
                    "nothing attempted".to_string(),
                    ProbeOutcome::NotProbeable {
                        reason:
                            "an emergent property of a cooperating set, not a syscall; there is \
                                 nothing to attempt"
                                .to_string(),
                    },
                ),
                // `Other { .. }` is not in `probe_set`, and a future variant reaching here has no
                // known attempt. NotProbeable, which drives Incomplete — never Attested.
                _ => (
                    "nothing attempted".to_string(),
                    ProbeOutcome::NotProbeable {
                        reason: "no probe is defined for this capability".to_string(),
                    },
                ),
            };

            probes.push(CapabilityProbe {
                capability,
                declared: false,
                attempted,
                outcome,
            });
        }

        let outcome = EnvironmentAttestation::classify(&probes);
        EnvironmentAttestation {
            system_id: envelope.system_id.clone(),
            probes,
            outcome,
            probed_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokkr_core::capability::AttestationOutcome;

    /// The load-bearing property: `NotProbeable` is not `Refused`. An attestation whose probes are
    /// all `NotProbeable` is `Incomplete`, never `Attested`.
    #[test]
    fn test_p12_3_notprobeable_never_yields_attested() {
        let probes = vec![CapabilityProbe {
            capability: CapabilityProperty::IdentityCreation,
            declared: false,
            attempted: "nothing".into(),
            outcome: ProbeOutcome::NotProbeable {
                reason: "harmlessness rule".into(),
            },
        }];
        assert!(matches!(
            EnvironmentAttestation::classify(&probes),
            AttestationOutcome::Incomplete { .. }
        ));
    }

    /// A reachable capability outranks incomplete coverage: the finding is the point.
    #[test]
    fn test_p12_3_reachable_outranks_incomplete() {
        let probes = vec![
            CapabilityProbe {
                capability: CapabilityProperty::IdentityCreation,
                declared: false,
                attempted: "nothing".into(),
                outcome: ProbeOutcome::NotProbeable {
                    reason: "harmlessness rule".into(),
                },
            },
            CapabilityProbe {
                capability: CapabilityProperty::SubAgentCreation,
                declared: false,
                attempted: "spawn".into(),
                outcome: ProbeOutcome::Reachable {
                    detail: "spawned".into(),
                },
            },
        ];
        let outcome = EnvironmentAttestation::classify(&probes);
        assert!(
            matches!(&outcome, AttestationOutcome::Discrepant { reachable } if reachable.len() == 1),
            "expected Discrepant with exactly one reachable capability; got {outcome:?}"
        );
    }

    /// Only full coverage with every probe refused yields `Attested`.
    #[test]
    fn test_p12_3_attested_requires_every_probe_refused() {
        let probes = vec![CapabilityProbe {
            capability: CapabilityProperty::CodeExecution,
            declared: false,
            attempted: "spawn".into(),
            outcome: ProbeOutcome::Refused {
                detail: "EPERM".into(),
            },
        }];
        assert!(matches!(
            EnvironmentAttestation::classify(&probes),
            AttestationOutcome::Attested
        ));
    }

    /// `ConnectionRefused` proves the socket layer worked — it is Reachable, not Refused. Asserted
    /// on the classifier's contract rather than by forcing a live socket error.
    #[test]
    fn test_p12_3_notfound_is_reachable_not_refused() {
        let e = std::io::Error::new(ErrorKind::NotFound, "missing");
        let outcome = LinuxProbe::classify_io(&e, "test");
        assert!(
            matches!(outcome, ProbeOutcome::Reachable { .. }),
            "NotFound proves the target is missing, not that access was denied — it must be \
             Reachable, not {outcome:?}"
        );
    }

    #[test]
    fn test_p12_3_permission_denied_is_refused() {
        let e = std::io::Error::new(ErrorKind::PermissionDenied, "denied");
        assert!(matches!(
            LinuxProbe::classify_io(&e, "test"),
            ProbeOutcome::Refused { .. }
        ));
    }

    /// **BROKKR fails its own attestation on an unconfined host.** This is the expected result
    /// (ARCH Rev 1.23 §6.13), not a defect: a normal Linux process can spawn children and read
    /// `/proc/self/environ`, so capabilities the envelope declares absent are reachable.
    #[test]
    fn test_p12_3_unconfined_host_is_discrepant() {
        let probe = LinuxProbe::default();
        let attestation = probe.attest(&CapabilityEnvelope::permissive(), Timestamp(1));
        assert!(
            matches!(attestation.outcome, AttestationOutcome::Discrepant { .. }),
            "an unconfined host must attest Discrepant; got {:?}",
            attestation.outcome
        );
    }
}
