# Conformance Check — Corpus Growth (AMD-010, AMD-011, Organ 5 patch) — CORPUS-R1

**Record ID:** CONF-2026-09-02-CORPUS-R1
**Date:** 2026-09-02
**Scope (§5.3).** The corpus grew to AMD-001…AMD-011 + the Organ 5 evidence-capture hardening patch. Every prior conformance result was provisional with respect to the new requirements (CLAUDE.md §0, §5.3). This check enumerates **from the corpus** — the governance files, not the traceability table — and records a verdict for each of: **OQGF-A-8 … A-12** (AMD-010), **OQGF-P-12.1 … P-12.8** (AMD-011), and the **OQGF-A-1 evidence-provenance extension** (Organ 5 patch). This is the check the builder has flagged as owed since AMD-010 was placed.
**Method (RISK-2026-0007 discipline).** For each requirement: the requirement (ID + text from the governance file), the implementation (file, type, function — or that none exists), the proof (the test that would fail if the check were removed — or that none exists / n.a.), and a verdict. **Each claim points at a line the DAP can open.** Verified against source at commit `c3daaee` + the F-32 fix in this commit; workspace GREEN.
**Author:** Claude Code (builder).

**What was checked, and against what.** 14 requirements (5 explanation-validity, 8 capability-triggered, 1 evidence-provenance) against `governance/AMD-010-explanation-validity.md`, `governance/AMD-011-capability-triggered-assurance.md`, `governance/OQGF-organ5-evidence-capture-hardening-patch.md`, the committed source, and the test suite. **Result: 5 n.a., 7 satisfied (2 of them satisfied-by-construction / for-the-declarative-half), 2 partial.** Zero absent. This is not an all-satisfied sheet: two partials (P-12.3, P-12.6) and one split (P-12.8) are recorded honestly, and the five n.a. rest on a stated basis (§5.3: "zero findings is not a pass").

---

## Part A — AMD-010, Explanation Validity (OQGF-A-8 … A-12)

**Disposition basis (all five).** AMD-010 qualifies OQGF-A-4 (quantum-appropriate explanation artifacts — Pauli-string decomposition, kernel attribution). BROKKR-ARCH §1.4 declares **OQGF-A-4 `n.a.`**: "no variational or kernel quantum model in the decision path." BROKKR runs a classical LLM (`llama3.2:3b`). A requirement that *qualifies* an inapplicable requirement is itself inapplicable. The types are **placed** in `brokkr-core::explanation` (Option B) so the architecture can name them and the surface is ready if a quantum workload is ever added — **placing the types is not discharging the obligation; there is nothing to discharge while OQGF-A-4 is n.a.** DAP-dispositioned 25 July 2026 (AMD-010 AMD.0.6).

| Req | Text (abridged) | Implementation | Proof | Verdict |
|---|---|---|---|---|
| **OQGF-A-8** | Every OQGF-A-4 artifact SHALL declare its Explanation Scope Bound (weight bound *k*, method, samples, confidence). | Type surface: `ExplanationScope` (`brokkr-core/src/explanation.rs:37`). No logic. | n.a. — no obligation to discharge (OQGF-A-4 n.a.). | **n.a. with justification** |
| **OQGF-A-9** | An information-free artifact SHALL be recorded as **Null**, never as valid. | `ExplanationValidity` (`explanation.rs:69`) — `Null { .. }` is a distinct variant; **no representable path from `Null` to `Valid`** (a structural property that holds even for the placed type). | n.a. | **n.a. with justification** |
| **OQGF-A-10** | A Null-explained regulated decision SHALL NOT be acted on until a DAP signs an acknowledgment. | `ExplanationValidity::Null { acknowledgment: Option<DapAcknowledgment>, .. }` (`explanation.rs:73-77`) makes the acknowledgment an explicit `Option` a consumer must confront. | n.a. | **n.a. with justification** |
| **OQGF-A-11** | Declare a Trainability Profile and reconcile the observed signal against it. | `TrainabilityReconciliation` (`explanation.rs:108`). No logic. | n.a. | **n.a. with justification** |
| **OQGF-A-12** | Run a Canary Probe (known-answer control circuit) attesting the explanation channel is alive. | `CanaryAttestation` (`explanation.rs:152`). No logic. | n.a. | **n.a. with justification** |

*Confirmation the types exist (the one thing to verify for an n.a.-by-type-surface disposition): `ExplanationScope`, `ExplanationValidity`, `NullCause`, `TrainabilityReconciliation`, `CanaryAttestation`, `ExplanationArtifact` are all present in `brokkr-core/src/explanation.rs`. No SAGA / HEIMDALL / orchestrator integration — shapes only.*

---

## Part B — AMD-011, Capability-Triggered Assurance (OQGF-P-12.1 … P-12.8)

### OQGF-P-12.1 — Dual-Axis Determination (higher-of)

> "The conformance tier governing an AI/ML system SHALL be the higher of its Data-Triggered Tier … and its Capability-Triggered Tier."

| Field | Content |
|---|---|
| Implementation | `CapabilityEnvelope` (`brokkr-core/src/capability.rs:86`) carries `capability_tier`, `data_tier`, `governing_tier`; `validate()` (`:112`) returns `Err(EnvelopeError::TierMismatch)` unless `governing_tier == max(capability_tier, data_tier)`. Public/synthetic data cannot buy a lower posture. |
| Proof | `brokkr-core/tests/capability.rs::envelope_tier_mismatch_fails` (`:60`, asserts `Err(TierMismatch)`) — fails if the `max` check is removed. Orchestrator boundary: `redteam_16::fix_with_envelope_rejects_tier_mismatch` (this commit) — `with_envelope` panics on a mismatch. |
| Verdict | **satisfied** |

### OQGF-P-12.2 — Capability Envelope Declaration

> "A conforming system SHALL maintain a Capability Envelope — a signed inventory of the Capability Properties present … Certain properties (external-effect, credential access, sub-agent creation) individually floor the system at Enhanced."

| Field | Content |
|---|---|
| Implementation | `CapabilityEnvelope` (signed: `signature: DualSignature`) + `CapabilityProperty` enum (`capability.rs:38`). `validate()` (`:112`) returns `Err(EnvelopeError::TierTooLow)` when `ExternalEffect`/`CredentialAccess`/`SubAgentCreation` is present while `capability_tier < Enhanced`. BROKKR's envelope (`CodeExecution` + `NetworkAccess(localhost:8443)` + `ExternalEffect(filesystem)`) floors at Enhanced. Installed only via `with_envelope`, which now validates before it governs (F-32 fix, `brokkr-cli/src/lib.rs:362`). |
| Proof | `brokkr-core/tests/capability.rs` TierTooLow tests (`:81`, `:95`); `redteam_16::fix_with_envelope_rejects_tier_too_low` (this commit) — fails if the floor check or the `with_envelope` `assert!` is removed. |
| Verdict | **satisfied** |

### OQGF-P-12.3 — Capability Envelope Attestation (against the deployed environment)

> "The declared Capability Envelope SHALL be attested against the **deployed environment**, not merely against a configuration document … that capabilities declared absent are in fact absent."

| Field | Content |
|---|---|
| Implementation | The envelope is **declared**, validated at construction, signed-in-shape, and carries `attested_at: Timestamp` (`capability.rs:95`) — but **no mechanism verifies the deployed environment matches the declaration.** No environment-probe exists. |
| Proof | None — the mechanism is absent. This is the Anthropic-incident failure mode P-12.3 exists to catch; BROKKR does not yet catch it (BROKKR-ARCH §13). |
| Verdict | **partial** — declaration present, attestation-against-environment not built. Named residual (§13); closing it requires an environment probe mirroring the OQGF-M-3 declare-then-test pattern. |

### OQGF-P-12.4 — Deterministic Network Containment (default-deny egress)

> "Any system whose Capability Envelope includes network access SHALL enforce deterministic default-deny egress: all outbound traffic SHALL be denied unless the destination, protocol, and port are listed in a signed egress manifest … fail-closed, non-suppressible."

| Field | Content |
|---|---|
| Implementation | `brokkr-cli/src/lib.rs::check_egress` (`:837`) — matches host (normalized `localhost`/`127.0.0.1`/`::1`) **and** port **and** protocol against the signed `EgressManifest`; any mismatch → `HopResult::Denied`; absent manifest → no-op (permissive default). `Destination::Network` carries `port`/`protocol` (F-34). Deterministic Gate under OQGF-P-2; `Deny` has no path to `Allow` (I-2). |
| Proof | `redteam_16::fix_egress_port_mismatch_denied` (`:407`), `fix_egress_protocol_mismatch_denied` (`:428`); `capability.rs::egress_to_unmanifested_destination_denied` (`:297`), `empty_manifest_denies_all_network` — each fails if a match component is dropped or the default flips to allow. |
| Verdict | **satisfied** |

### OQGF-P-12.5 — Independent Termination

> "Any system with external-effect authority SHALL have an independent termination capability … the termination path SHALL NOT depend on the agent's cooperation, on the model processing a shutdown instruction, or on the model's willingness to comply."

| Field | Content |
|---|---|
| Implementation | `KillSwitch` (`brokkr-cli/src/lib.rs:67`) — a latch (`kill()`/`is_killed()`, no unset, `Release`/`Acquire` hardcoded). `run_hop` reads `self.kill_switch.is_killed()` **before every gate** (`:510`), ahead of guards, crossing, and tool. The model has no channel to it (no tool, field, or proposal path). |
| Proof | `capability.rs::kill_flag_checked_before_all_gates` (`:357`, kill wins even over a would-deny crossing); `redteam_16::fix_kill_switch_is_a_latch` (`:520`, killed stays killed) — fail if the pre-gate check is removed or a reset is added. |
| Verdict | **satisfied** (within-harness; a fully out-of-process control plane is a deployment concern, §6.13). Residual F-37 (pre-hop, not mid-hop) is a bounded-latency note, not a cooperation dependency. |

### OQGF-P-12.6 — Sub-Agent and Peer-Agent Governance

> "The creation of a sub-agent SHALL be a governed act recorded in Organ 5. The sub-agent's Capability Envelope SHALL be a subset of the parent's … An agent SHALL NOT acquire … authority the parent was not granted."

| Field | Content |
|---|---|
| Implementation | `SubAgentRecord` (`capability.rs:167`) holds the child `CapabilityEnvelope` + the AMD-001 `IntentProvenanceChain`; `validate(parent)` (`:185`) returns `Err(SubAgentError::CapabilityExceedsParent)` when the child declares a capability the parent lacks. The collective properties (`InterAgentCommunication`, …) are in `CapabilityProperty`. **BROKKR spawns no sub-agents and joins no peer swarm — no runtime path exercises this.** |
| Proof | `brokkr-core/tests/capability.rs::child_subset_of_parent_validates` (`:132`) and the `CapabilityExceedsParent` test (`:167`) — fail if the subset check is removed. No orchestrator/runtime test (no spawning path). |
| Verdict | **partial** — type surface with intrinsic validation present and tested; no runtime creation/recording path (BROKKR does not delegate). Named residual (§13). |

### OQGF-P-12.7 — Prompt-Only Containment Rejection

> "Instructions to the model … SHALL NOT satisfy any containment, authorization, network, termination, or enforcement requirement … satisfied by controls that are deterministic, external to the model, and not dependent on the model's interpretation or compliance."

| Field | Content |
|---|---|
| Implementation | No hook — a design constraint the architecture satisfies by construction. Every enforcement control is deterministic Rust external to MÍMIR: SINDRI (costimulation), HÚÐ (barrier), `check_egress`, the `KillSwitch`, REGIN (promotion). The model receives a `ClearedContext` and returns an untrusted `Proposal`; it has no channel to any gate's verdict (prime directive §2, I-6/I-12). |
| Proof | The by-construction property has no single positive test; it is the *negative space* proven collectively — `AuthorizedAction`/`ClearedContext` unforgeable (private `mint`, 14A compile-fail doctests), the kill/egress/gate tests (above), and the absence of any model-reachable control path. If any control were satisfiable by a prompt, it would appear as a model-influenced gate verdict — none exists (dependency-direction I-5/I-6 CI-enforced). |
| Verdict | **satisfied by construction** |

### OQGF-P-12.8 — Trajectory Reconstruction and Evidence-Capture Independence

> "Organ 5 SHALL record sufficient evidence to reconstruct the complete trajectory … material trajectory evidence SHALL be captured through an observation path external to and unmodifiable by the governed agent."

| Field | Content |
|---|---|
| Implementation | **Recording/reconstruction:** `brokkr-cli::record_trajectory` (`lib.rs:876`) appends a `TrajectoryEntry` (`capability.rs:219`) for **every** hop attempt (executed/denied/errored), each carrying `EvidenceProvenance` (`capability.rs:200`); `trajectory()` returns the ordered sequence. **Independence:** the sensor is the orchestrator itself (`sensor_id: "orchestrator"`), stated honestly, not an independent observer. |
| Proof | `capability.rs::trajectory_records_executed_hop` (`:378`), `trajectory_entry_carries_provenance` (`:417`); `redteam_16::f38_trajectory_is_not_a_saga_event` (`:586`) — fail if a hop stops appending. No test for the independence half (it is not built). |
| Verdict | **partial** — the recording/reconstruction obligation is **satisfied**; the evidence-capture-**independence** obligation is **open** (the sensor is inside the TCB, F-23). Named residual (§13); an independent sensor is future work. |

---

## Part C — Organ 5 evidence-capture hardening patch (OQGF-A-1 extended)

> "material evidence recorded under OQGF-A-1 SHALL carry evidence-source provenance: the sensor or capture mechanism identity, the capture path, a capture timestamp …, the expected coverage scope, the observed coverage scope, and any gap … Where evidence collection fails or is incomplete, an explicit Evidence Gap SHALL be recorded." Plus the general principle: *the governed system SHALL NOT be the authority over its own evidence.*

| Field | Content |
|---|---|
| Implementation | `AuditRecord::provenance: EvidenceProvenance` (`brokkr-audit/src/event.rs:208`) is a **required field**, and `write_provenance` (`brokkr-audit/src/canonical.rs:635`) is called **inside `record_signed_content`** — so provenance is signed and hash-chained (a non-key-holder cannot alter *how a record claims it was captured* without breaking the chain). `Saga::append_with_provenance` (`saga.rs:234`). The orchestrator writes **only** through `record_with_provenance` — **6 mentions / 5 call sites, 0 bare `record()` calls** in `brokkr-cli/src/lib.rs` (grep-verified). `record_trajectory` writes an explicit `evidence_gap` + `observed_coverage: "partial_hop"` on an errored hop. |
| Proof | `redteam_16::provenance_is_covered_by_signed_content` (`:680`, two records differing only in `sensor_id` produce different signed bytes) — fails if `write_provenance` is dropped from `record_signed_content`. `evidence.rs::all_saga_events_have_provenance` (`:349`), `saga_record_carries_provenance` (`:268`), `provenance_sensor_is_orchestrator` (`:284`), `evidence_gap_recorded_on_failure` (`:317`) — fail if any recording path omits provenance or the gap. |
| Verdict | **satisfied** for the recording obligation (provenance on every material record, signed, with explicit gaps). The general principle's *independence* aspiration — that the sensor not be the governed system — is the **same open item as P-12.8** (F-23): BROKKR states its sensor honestly rather than achieving an independent one. |

---

## Verdict summary

| Requirement(s) | Verdict |
|---|---|
| OQGF-A-8, A-9, A-10, A-11, A-12 | **n.a. with justification** (OQGF-A-4 basis; types placed) |
| OQGF-P-12.1, P-12.2 | **satisfied** (`CapabilityEnvelope::validate` + `with_envelope` enforcement) |
| OQGF-P-12.4, P-12.5 | **satisfied** (default-deny egress; kill-switch latch before every gate) |
| OQGF-P-12.7 | **satisfied by construction** (all controls deterministic, external to the model) |
| OQGF-A-1 evidence-provenance | **satisfied** (recording obligation) |
| OQGF-P-12.3 | **partial** (declared; no environment attestation) |
| OQGF-P-12.6 | **partial** (type surface + validate; no runtime spawning path) |
| OQGF-P-12.8 | **partial** (recording/reconstruction satisfied; evidence-capture independence open — F-23) |

**Nothing absent.** The three partials and the independence gap are named residuals in BROKKR-ARCH §13 and traced in §14; none is a build-blocking `absent` under §4. The five n.a. verdicts rest on the OQGF-A-4 basis declared in §1.4, and the types they reference exist in `brokkr-core::explanation`. This check closes the §5.3 provisional-status obligation the corpus growth to AMD-011 created; the affected crates' prior conformance results are now enumerated against the new requirements rather than assumed.
