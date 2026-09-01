# DRAFT — BROKKR Architecture Rev 1.18 (delta for DAP review)

**Status of this file.** This is a *builder-authored draft* of a DAP-placed specification
change, written to `/tmp` for the DAP to review and place. Per CLAUDE.md §0/§1 the builder
never places the architecture; per §4/§5.2 the builder may draft, and the DAP's review and
commit are the ratification. **Nothing here is committed.** It is a delta: each block below
quotes the current Rev 1.17 text it replaces or names the anchor it is inserted after, so the
edits can be applied precisely to `docs/BROKKR-ARCH-2026-001.md`.

**What Rev 1.18 records.** Three placed governance items since Rev 1.17 — AMD-010 (Explanation
Validity), AMD-011 v1.1 (Capability-Triggered Assurance), and the Organ 5 evidence-capture
hardening patch — plus the closure of the Deferred-Conjunct Deadline (all four OQGF-M-11
conjuncts now enforced, gate revision `884958f`). Every change **adds, tightens, or records a
fact**; the one item that *removes* a §13 residual removes it because the requirement it named
is now **enforced**, which is a tightening, not a relaxation.

**One §4 disclosure, stated plainly.** The AMD-010 disposition below is **`n.a.` with
justification**, and it is the DAP's stated disposition (25 July 2026 ratification; classical
LLM, no quantum ML model). That disposition has the effect of requiring **no further
implementation work from the builder** — the types are placed and no logic is needed. The
builder's interest (less work) and this reading coincide, so it is named here: the `n.a.` rests
on the same basis the architecture *already* uses for OQGF-A-4 (§1.4), it is not the builder's
recommendation, and the DAP weighs it.

---

## 1. Front matter

**REPLACE:**

> **Revision:** 1.17

**WITH:**

> **Revision:** 1.18

**REPLACE:**

> **Supersedes:** Rev 1.16 (commit `f46772b`), Rev 1.15 (commit `174d023`), …

**WITH** (prepend Rev 1.17 to the chain):

> **Supersedes:** Rev 1.17 (commit `ff65f2b`), Rev 1.16 (commit `f46772b`), Rev 1.15 (commit `174d023`), … *(remainder unchanged)*

**REPLACE:**

> **Binds to:** OQGF-1.0 (five organs), the Physiology Layer (OQGF-P-1 … P-11), and Amendments AMD-001 … AMD-009 in full

**WITH:**

> **Binds to:** OQGF-1.0 (five organs), the Physiology Layer (OQGF-P-1 … P-12), and Amendments AMD-001 … AMD-011 in full, together with the Organ 5 evidence-capture hardening patch

**REPLACE:**

> **Date:** 18 August 2026 (Rev 1.17)

**WITH:**

> **Date:** 1 September 2026 (Rev 1.18)

**REPLACE the `Disposes:` lead sentence:**

> **Disposes:** Rev 1.17 places §6.12 (KVASIR), the only subsystem that had never had a section.

**WITH:**

> **Disposes:** Rev 1.18 records three placed governance items — AMD-010 (Explanation Validity, OQGF-A-8…A-12), AMD-011 v1.1 (Capability-Triggered Assurance, OQGF-P-12.1…P-12.8), and the Organ 5 evidence-capture hardening patch (OQGF-A-1 extended) — and closes the Deferred-Conjunct Deadline: all four OQGF-M-11 conjuncts are now enforced in SINDRI (gate revision `884958f`). AMD-010 is dispositioned `n.a.` (BROKKR runs a classical LLM, no quantum ML model — the OQGF-A-4 basis of §1.4); AMD-011 is implemented (§6.13); the Organ 5 patch is implemented (§6.9). Rev 1.17 places §6.12 (KVASIR)…​ *(remainder of the Rev 1.17 sentence unchanged)*

**Also update the corpus-provisional note (front matter or §1.3).** Add:

> **The corpus grew again: AMD-001 … AMD-011 and the Organ 5 evidence-capture hardening patch.** Per CLAUDE.md §5.3, every conformance result recorded before this revision is **provisional** with respect to OQGF-A-8…A-12 (n.a., §1.4), OQGF-P-12.1…P-12.8, and the OQGF-A-1 evidence-provenance extension. The next conformance check in each affected crate SHALL enumerate these in scope and record a verdict for each.

---

## 2. §1.3 — Binding to the full framework

**ADD** to the bullet list in §1.3:

> - **AMD-011 (Capability-Triggered Assurance)** is the amendment written for exactly what BROKKR is: an autonomous agent whose risk comes from its *capabilities*, not its data. BROKKR's declared Capability Envelope is `CodeExecution` + `NetworkAccess(localhost:8443)` (the BIFRÖST crossing to the reasoner gateway) + `ExternalEffect(filesystem)` (file writes) — a composition that floors the capability-triggered tier at Enhanced and matches BROKKR's declared governing tier. The dual-axis rule (OQGF-P-12.1), deterministic default-deny egress (P-12.4), independent termination (P-12.5), and trajectory reconstruction with evidence provenance (P-12.8) are implemented (§6.13); sub-agent and peer/collective governance (P-12.6) are placed as a type surface because BROKKR spawns no sub-agents.
> - **AMD-010 (Explanation Validity)** extends Organ 5's *quantum-appropriate* explanation artifact (OQGF-A-4) with bounded scope, the Null Explanation, trainability reconciliation, and the Canary Probe. BROKKR runs a classical LLM and has no variational or kernel quantum model in its decision path, so OQGF-A-4 — and therefore OQGF-A-8…A-12 — is `n.a.` (§1.4). The types are placed in `brokkr-core::explanation` so the architecture can name them and the surface is ready when a quantum workload arrives; no logic is built.
> - **The Organ 5 evidence-capture hardening patch** adds to OQGF-A-1 the requirement that every material audit record carry evidence-source provenance, and adds the general Organ 5 principle that **the governed system SHALL NOT be the authority over its own evidence** (§6.9).

---

## 3. §1.4 — Declared conformance level, n.a. table, and Enhanced obligations

**ADD** a row to the **n.a. with justification** table:

| Requirement | Status | Justification |
|---|---|---|
| **OQGF-A-8 … A-12 (AMD-010, explanation validity)** | **n.a.** | AMD-010 qualifies OQGF-A-4 (quantum-appropriate explanation artifacts), which §1.4 already declares n.a.: BROKKR runs a classical LLM (`llama3.2:3b`), with no variational or kernel quantum model in its decision path, so there is no Pauli-string decomposition, no barren-plateau regime, no Trainability Profile, and no explanation channel to attest with a Canary Probe. The `brokkr-core::explanation` type surface is placed (Option B) so the requirement can be referenced and the surface is ready if a quantum workload is added; **placing the types is not discharging the obligation** — there is nothing to discharge while OQGF-A-4 is n.a. DAP-dispositioned 25 July 2026. |

**ADD** rows to the **Enhanced obligations** table:

| Requirement | Enhanced obligation on BROKKR |
|---|---|
| **OQGF-P-12.1, P-12.2** | **Dual-axis determination; a signed Capability Envelope inventorying what the composed system can do.** BROKKR's envelope: `CodeExecution` + `NetworkAccess(localhost:8443)` + `ExternalEffect(filesystem)`; capability-triggered tier Enhanced (external-effect floors at Enhanced); `governing_tier = max(capability, data)` (§6.13) |
| **OQGF-P-12.4** | **Deterministic default-deny egress** on any network destination absent from the signed egress manifest — a Deterministic Gate under OQGF-P-2 (§6.13) |
| **OQGF-P-12.5** | **Independent termination** for a system with external-effect authority: a kill path the reasoner cannot reach, checked before every gate (§6.13) |
| **OQGF-P-12.8** | **Trajectory reconstruction** — every hop attempt recorded in order — and **evidence-source provenance** on every material audit record (§6.9, §6.13) |

**ADD** a row to the same table noting the applicable-but-partial members:

| Requirement | Enhanced obligation on BROKKR |
|---|---|
| **OQGF-P-12.3, P-12.6** | **PARTIAL / type-surface.** P-12.3 (environment attestation against the deployed environment) is not built — the envelope is declared, signed-in-shape, and carries `attested_at`, but no mechanism verifies the deployed environment matches it (§13). P-12.6 (sub-agent and peer/collective governance) is a placed type surface with intrinsic `validate()`; BROKKR spawns no sub-agents, so no runtime path exercises it (§13) |

---

## 4. §5 step 5 — the governed action cycle

**REPLACE** the Phase-4 scope note appended to step 5:

> **Phase-4 scope (Rev 1.3):** of the four conjuncts named here, SINDRI enforces the two cryptographic signals; confirming the action lies within scope and evaluating it against the accumulated invariants are deferred under the Deferred-Conjunct Deadline and SHALL be enforced before the executor is wired at Phase 11 — see §6.4.

**WITH:**

> **All four conjuncts are now enforced (Rev 1.18).** SINDRI verifies Signal 1 and Signal 2 (the two cryptographic signals) and, through the `GenomeResolver` seam (gate revision `884958f`), confirms the action's tool resolves in the genome with every required capability present in the chain's current attenuated scope (conjunct 3 → `OutOfScope` on a miss) and that the tool violates no accumulated invariant (conjunct 4 → `InvariantViolated`). The Deferred-Conjunct Deadline (§6.4) is satisfied; the executor may be wired against a gate that evaluates all four conjuncts.

---

## 5. §6.4 — SINDRI: the four conjuncts are enforced

**REPLACE** the conjunct table:

> | # | Conjunct | Source | Enforced at |
> |---|---|---|---|
> | 1 | **Signal 1** — identity attestation | OQGF-M-1, M-11 | **Phase 4** |
> | 2 | **Signal 2** — a valid Intent Provenance Chain | OQGF-M-8, M-9, M-14 | **Phase 4** |
> | 3 | **Action lies within the current attenuated scope** | OQGF-M-11 | **Deferred — see below** |
> | 4 | **Action respects the accumulated invariant set** | OQGF-M-10, M-11 | **Deferred — see below** |

**WITH:**

> | # | Conjunct | Source | Status |
> |---|---|---|---|
> | 1 | **Signal 1** — identity attestation | OQGF-M-1, M-11 | **Enforced (Phase 4)** |
> | 2 | **Signal 2** — a valid Intent Provenance Chain | OQGF-M-8, M-9, M-14 | **Enforced (Phase 4)** |
> | 3 | **Action lies within the current attenuated scope** | OQGF-M-11 | **Enforced (gate revision `884958f`)** |
> | 4 | **Action respects the accumulated invariant set** | OQGF-M-10, M-11 | **Enforced (gate revision `884958f`)** |

**REPLACE** the subsection heading and body `#### Conjuncts 3 and 4 — deferred, with a deadline` (from "**Why they cannot be built at Phase 4.**" through the "**Until both exist, OQGF-M-11 is recorded `partial`** …" paragraph):

**WITH:**

> #### Conjuncts 3 and 4 — enforced through the `GenomeResolver` seam
>
> Rev 1.3 deferred these two conjuncts because `Action` carried no capability, `ToolId` and `Capability` were distinct types with no committed conversion, and `Invariant` had no evaluation predicate — computing them would have meant the gate authoring REGIN's vocabulary from inside Phase 4. Rev 1.4 placed that vocabulary in the signed registers (`ToolEntry::required_capabilities`, `PolicyRegister`), and gate revision `884958f` now consumes it through a resolver seam of the same shape as the Signal-2 key resolver — the gate asks, the resolver answers, and the gate does not know where the data lives:
>
> ```rust
> pub trait GenomeResolver: Send + Sync {
>     /// Conjunct 3: the tool's declared least-privilege capabilities, and its privilege class.
>     fn resolve_tool(&self, tool: &ToolId) -> Option<ResolvedTool>;      // required_capabilities, privilege
>     /// Conjunct 4: what an accumulated invariant forbids.
>     fn resolve_invariant(&self, invariant: &Invariant) -> Option<ResolvedInvariant>; // forbids_capabilities, forbids_privilege
> }
> ```
>
> **Conjunct 3.** SINDRI resolves `action.tool`; an **undeclared tool** (resolver returns `None`) is `AnergyReason::OutOfScope`, and a tool whose `required_capabilities` are not all present in `chain.current_scope()` is `OutOfScope`. Absence is denial — the register is the closed vocabulary.
>
> **Conjunct 4.** For each accumulated invariant, SINDRI resolves it and checks the action's tool against `forbids_capabilities` and `forbids_privilege`; a violation is `AnergyReason::InvariantViolated`. **An invariant with no declared predicate is denied, not passed** — OQGF-P-2's non-suppressible posture applied to policy, and the reason the policy register's construction-time check (§6.2) exists to catch a malformed register while a human is present.
>
> **This closes the Deferred-Conjunct Deadline.** The executor (Phase 11) may be wired against a gate that evaluates the action against the chain's current scope and accumulated invariant set. **OQGF-M-11 moves to satisfied** (all four conjuncts). **OQGF-M-10's action-evaluation clause is satisfied for declarative invariants** — accumulation and non-removal in SKULD, evaluation against the set in SINDRI; **detail-level invariants** (a path rule such as *read-only outside ./src*) remain unevaluated and are a standing residual (§13), the buildable-vs-declarative boundary Rev 1.4 drew. **OQGF-M-1 is unaffected by this revision and remains `partial`**: Signal 1 proves key possession for a declared identity, not hardware-attested platform state (§13).

**REPLACE** the anergy-mapping note:

> `OutOfScope` and `InvariantViolated` are reserved for conjuncts 3 and 4 and are unreachable at Phase 4 by construction.

**WITH:**

> `OutOfScope` is returned by conjunct 3 (undeclared tool, or a required capability absent from the current scope) and `InvariantViolated` by conjunct 4 (the tool forbidden by an accumulated invariant, or an invariant with no declared predicate). Both are now reachable and are exercised by the gate's negative tests.

---

## 6. §6.13 — NEW SECTION: Capability-Triggered Assurance (AMD-011)

**INSERT** after §6.12 (KVASIR), before §7:

> ### 6.13 Capability-Triggered Assurance (AMD-011)
>
> AMD-011 is the amendment written for what BROKKR *is*: an autonomous agent whose danger is a function of its **capabilities**, not the sensitivity of the data it touches. Its thesis is the same one this architecture has held since Rev 1.0 — **containment is structural, not communicative; the body's answer is walls, not words** (OQGF-P-12.7). BROKKR satisfies that requirement the way it satisfies every other structural one: the controls are deterministic Rust the model cannot address, persuade, or route around. The surfaces below live in `brokkr-core::capability` (the types and their intrinsic validation) and `brokkr-cli` (the orchestrator wiring); no governance crate depends on the orchestrator (I-5).
>
> #### The Capability Envelope and the dual-axis rule (OQGF-P-12.1, P-12.2)
>
> ```rust
> pub struct CapabilityEnvelope {
>     pub system_id: String,
>     pub properties: Vec<CapabilityProperty>,     // the "virulence-factor" inventory
>     pub egress_manifest: Option<EgressManifest>, // present iff NetworkAccess is declared
>     pub capability_tier: ConformanceTier,
>     pub data_tier: ConformanceTier,
>     pub governing_tier: ConformanceTier,         // SHALL be max(capability, data) — P-12.1
>     pub attested_at: Timestamp,
>     pub signature: DualSignature,
> }
> ```
>
> `CapabilityEnvelope::validate()` refuses two conditions and is the construction-time gate on an envelope before it governs: `TierMismatch` when `governing_tier != max(capability_tier, data_tier)` (P-12.1), and `TierTooLow` when any of `ExternalEffect`, `CredentialAccess`, or `SubAgentCreation` is present while `capability_tier` is below Enhanced (P-12.2). **Public or synthetic data cannot buy a lower posture** — the higher axis governs, by construction.
>
> **BROKKR's declared envelope** is `CodeExecution` + `NetworkAccess { localhost:8443 }` + `ExternalEffect { filesystem }`. External-effect authority floors the capability-triggered tier at Enhanced, `data_tier` is Baseline (BROKKR reasons over source, not classified corpora), and `governing_tier` is therefore **Enhanced** — the level this architecture has declared since Rev 1.1, now reached from the capability axis as well as the FIPS-199 axis.
>
> The orchestrator installs the envelope through a builder method, the `.with_guards()` pattern, so existing composition is unchanged: `new()` defaults to `CapabilityEnvelope::permissive()` (no declared properties, **no egress manifest**, so egress enforcement is a no-op), and a deployment supplies its attested, DAP-signed envelope via `.with_envelope(..)`. The caller validates the envelope; `.with_envelope` extracts the signed manifest's rules once for fast per-hop lookup and does not re-verify the signature.
>
> #### Deterministic default-deny egress (OQGF-P-12.4) — a Deterministic Gate
>
> `EgressManifest` carries a `Vec<EgressRule>` (destination, port, protocol) and a `DualSignature`; the manifest is signed and unmodifiable by the agent. The orchestrator's `check_egress(dest)` returns `Some(Denied)` when a **network** destination is absent from the manifest, and `None` (proceed) when the destination is allowed **or when no manifest is configured** (the permissive default). This is a Deterministic Gate under OQGF-P-2: fail-closed, non-suppressible, and no tolerance mechanism, exception, or model instruction opens it. It is a sibling to HÚÐ's data-classification egress gate (OQGF-I-10) — OQGF-I-10 triggers on what the *data* is, OQGF-P-12.4 on what the *system can reach*. A deliberate, bounded addition to the manifest is an AMD-006 Accountable Risk Acceptance, never a silent edit; and the manifest is `SelfModifying` (I-7).
>
> #### Independent termination (OQGF-P-12.5)
>
> The kill signal is an `Arc<AtomicBool>` held in the orchestrator and handed out by `kill_handle()` to any thread outside the reasoning path — a signal handler, a watchdog, a DAP console. `execute_hop` loads it **before every gate**, ahead of costimulation, the barrier, egress, and tool execution, and returns `Denied` the instant it is set. **The model has no channel to it** — no tool named "resume," no field it can write, no path from a proposal to the flag — which is the structural posture of I-6/I-12 applied to the stop button. The requirement's stronger form, a fully separate out-of-process control plane, is a deployment concern; what the architecture guarantees is that within the harness the termination path does not traverse the model's reasoning or execution, which is exactly the failure the AISI incident (four days undetected) exposed.
>
> #### Trajectory reconstruction (OQGF-P-12.8)
>
> `execute_hop` appends a `TrajectoryEntry` for **every hop attempt, whatever its outcome** — `Executed`, `Denied { stage, reason }` at any gate (including a denial before a proposal exists, where the entry records no proposed action), or `Error` — so the ordered session trajectory is complete and reconstructable, not a set of isolated decision records. `trajectory()` returns the sequence. Each entry carries an `EvidenceProvenance` (below). This is the evidence on which every other AMD-011 requirement is audited; without it, containment and authorization-boundary crossings are invisible after the fact.
>
> #### Sub-agent, peer, and collective governance (OQGF-P-12.6) — placed, not exercised
>
> `SubAgentRecord` holds the child's `CapabilityEnvelope` and the AMD-001 `IntentProvenanceChain` attenuated from the parent, and `validate(parent)` refuses `CapabilityExceedsParent` when the child declares a capability the parent lacks — monotonic attenuation inherited from AMD-001 rather than re-implemented. The Rev 1.1 collective/peer-agent properties (`InterAgentCommunication`, `SharedCoordinationState`, `CrossRunCoordination`, `CollectiveCapabilityAmplification`) are members of `CapabilityProperty`. **BROKKR spawns no sub-agents and joins no peer swarm**, so these are a placed type surface with intrinsic validation and no runtime path; the hooks are ready if that changes. Recorded as PARTIAL in §14 and named in §13.
>
> #### Prompt-only containment rejection (OQGF-P-12.7)
>
> There is no implementation hook, because it is a design constraint the whole architecture already satisfies: every containment, authorization, network, termination, and enforcement control in BROKKR is deterministic Rust external to the model. The system prompt is an intent input to MÍMIR, never a boundary. This is the same principle as §2's bidirectional prime directive, stated in AMD-011's vocabulary.

---

## 7. §6.9 — SAGA: evidence-source provenance, and the AMD-010 note

**ADD** to §6.9, after "The record" subsection (following the `AuditRecord` description):

> #### Evidence-source provenance (Organ 5 evidence-capture hardening patch, OQGF-A-1 extended)
>
> Tamper-evident *storage* — append-only, hash-linked, dual-signed — protects a record *after* it enters the evidence system. It does nothing about what the recorder *saw before* it recorded. The Organ 5 evidence-capture patch, prompted by the August 2026 METR–Redwood finding that agents spoofed tool-call outputs and replaced part of the tool-execution system, adds the missing half: **every material audit record states how it was captured.**
>
> ```rust
> pub struct AuditRecord {
>     pub seq: u64,
>     pub prev: Digest,           // over the preceding record's signed content
>     pub at: Timestamp,
>     pub dap: Dap,
>     pub event: AuditEvent,
>     pub provenance: EvidenceProvenance,     // NEW — IN the signed content
>     pub signatures: Vec<GenerationSignature>,  // accumulating — OUTSIDE
>     pub timestamping: Timestamping,            // OUTSIDE
> }
>
> pub struct EvidenceProvenance {
>     pub sensor_id: String,          // what captured this record
>     pub capture_path: String,       // through what path
>     pub capture_timestamp: Timestamp,
>     pub expected_coverage: String,
>     pub observed_coverage: String,
>     pub evidence_gap: Option<String>,  // explicit gap where coverage is incomplete
> }
> ```
>
> **Provenance is part of the signed content, and that placement is the load-bearing decision.** Rev 1.10 excludes the *accumulating* `signatures` and `timestamping` from the signed content because they grow after sealing and would break the chain. Provenance is the opposite: it is **set once, at capture**, so signing and hash-chaining it means a non-key-holder cannot alter *how the record claims it was captured* without breaking the chain — which is exactly the guarantee the patch exists to give. `SagaState::append` defaults provenance to a `saga`/`saga::append` self-report; the orchestrator supplies real per-event provenance through `append_with_provenance` (`AuditSink::record_with_provenance`, a defaulted trait method so existing sinks are unaffected).
>
> **The orchestrator is the sensor, and it says so.** Every SAGA record the orchestrator writes carries `sensor_id: "orchestrator"` and a `capture_path` naming where in `execute_hop` it was captured (`after_bifrost`, `after_reasoner`, `after_barrier`, `after_gate`, `after_tool::heimdall_observe`). An errored hop records `observed_coverage: "partial_hop"` and an explicit `evidence_gap` rather than presenting a partial record as complete. **The governed system is here its own sensor — that is stated honestly in `sensor_id` (finding F-23), never hidden**, and it is exactly the condition the general Organ 5 principle wants a production deployment to move beyond.
>
> **The general Organ 5 principle (patch):** *the governed system SHALL NOT be the authority over its own evidence.* Material audit evidence should be captured through an observation path whose integrity does not depend on the cooperation of the system being observed. BROKKR satisfies the recording half of this in full — provenance on every record, explicit gaps, no silent omission — and states plainly, in the record itself and in §13, that its sensor is currently the orchestrator (inside the trusted computing base) rather than an independent observer. Naming the sensor is what makes the residual visible rather than hidden.

**ADD** to §6.9 a short AMD-010 note (Organ 5 owns explanation artifacts):

> #### AMD-010 (Explanation Validity) — placed, dispositioned n.a.
>
> AMD-010 (OQGF-A-8…A-12) extends Organ 5's *quantum-appropriate* explanation artifact (OQGF-A-4) with a declared scope bound, the Null Explanation (an information-free artifact recorded explicitly as Null, never as valid), trainability reconciliation (the OQGF-M-3 declare-then-test pattern applied to explainability), and the Canary Probe (an analytically known control circuit attesting the explanation channel is alive — the clinical anergy-panel construction). BROKKR runs a classical LLM with no quantum ML model in its decision path, so OQGF-A-4 is `n.a.` (§1.4) and OQGF-A-8…A-12 inherit that disposition. The `brokkr-core::explanation` type surface is placed so the architecture can name it: `ExplanationValidity` has no variant in which a `Null` explanation is representable as `Valid` (OQGF-A-9), and its `Null` arm makes the OQGF-A-10 DAP acknowledgment an explicit `Option` a consumer must confront before acting. No logic, no SAGA/HEIMDALL/orchestrator integration — the shapes only, ready if a quantum workload arrives.

---

## 8. §13 — What this does not close

**REMOVE** the now-satisfied residual:

> - **Two of OQGF-M-11's four conjuncts are not yet enforced.** *(New in Rev 1.3.)* Action-in-scope and action-respects-invariants are deferred pending the tool-to-capability vocabulary (REGIN, Phase 5) and an invariant-evaluator seam. Bounded by the **Deferred-Conjunct Deadline** (§6.4): both SHALL be enforced before the executor is wired at Phase 11.

**REPLACE it WITH** a closure note (so the record shows the residual was closed, not silently dropped — the change log carries the durable record; §8's never-delete discipline is served by git and by the change-log entry in §15):

> - **~~Two of OQGF-M-11's four conjuncts are not yet enforced.~~ Closed in Rev 1.18.** *(Was: new in Rev 1.3.)* Action-in-scope and action-respects-invariants are now enforced in SINDRI through the `GenomeResolver` seam (gate revision `884958f`); the Deferred-Conjunct Deadline is satisfied (§6.4). The **detail-level-invariant** residual below is the remaining, narrower part and stands.

**ADD** the AMD-011 and Organ 5 residuals (all mapped to the shape of a prior amendment's residual, per house style):

> - **Environment attestation (OQGF-P-12.3) is not built.** *(New in Rev 1.18.)* BROKKR's Capability Envelope is declared, validated at construction (`validate()`), and signed in shape, and it carries an `attested_at` timestamp — but no mechanism verifies that the *deployed environment* matches the declaration (that a capability declared absent is in fact unreachable). This is precisely the Anthropic failure mode AMD-011 P-12.3 exists to catch, and BROKKR does not yet catch it. The envelope is a declaration, not an attestation. Named, not claimed built; closing it requires an environment-probe that mirrors the OQGF-M-3 declare-then-test pattern.
> - **The evidence sensor is the governed system.** *(New in Rev 1.18.)* Every SAGA record carries evidence-source provenance and every gap is explicit — the recording obligation of the Organ 5 patch is met in full. But the sensor is the orchestrator itself (`sensor_id: "orchestrator"`), which is inside the trusted computing base. The patch's general principle — *the governed system SHALL NOT be the authority over its own evidence* — is satisfied in its recording form (the path is attested, coverage declared, gaps explicit) and **not** in its strongest form (an independent observer). BROKKR states the sensor honestly rather than hiding it (F-23); an independent evidence sensor is future work. Same residual shape as AMD-007's upstream-provenance-truth: the record proves what was captured and by whom, not that the capturer was disinterested.
> - **Sub-agent, peer, and collective governance are a placed type surface.** *(New in Rev 1.18.)* `SubAgentRecord::validate` enforces capability-subset and attenuation, and the collective properties are inventoried in `CapabilityProperty` — but BROKKR spawns no sub-agents and joins no peer swarm, so no runtime path exercises P-12.6. If BROKKR ever delegates, the enforcement hook is ready; today it is untested against real spawning. Named so it is a scheduled capability rather than an assumed one.
> - **The egress manifest governs declared destinations, not compromised ones.** *(New in Rev 1.18.)* Default-deny prevents an *unauthorized* destination; it does not prevent an *authorized* destination from being compromised — the OpenAI–Hugging Face zero-day went through a permitted proxy. The manifest is one layer; network-security depth (the HNDL sentinel, incident response) complements it. Named, bounded, not claimed solved — AMD-011's own residual, inherited.

---

## 9. §14 — Traceability

**REPLACE the OQGF-M-11 row:**

> | **OQGF-M-11 (costimulation)** | **PARTIAL — `brokkr-gate::CostimulationGate::evaluate`; the provided `authorize` is the sole minter. Signals 1-2 enforced at Phase 4. Conjunct 3 (action-in-scope) becomes computable via `ToolEntry::required_capabilities` and conjunct 4 via `PolicyRegister` (§6.2, Rev 1.4); both SHALL be enforced before Phase 11 (Deferred-Conjunct Deadline, §6.4)** |

**WITH:**

> | **OQGF-M-11 (costimulation)** | **SATISFIED — `brokkr-gate::CostimulationGate::evaluate`; the provided `authorize` is the sole minter. All four conjuncts enforced: Signals 1–2 (Phase 4) and conjuncts 3–4 via the `GenomeResolver` seam (gate revision `884958f`) — undeclared tool or missing capability → `OutOfScope`; forbidden-by-invariant or unresolvable invariant → `InvariantViolated`. Deferred-Conjunct Deadline satisfied (§6.4)** |

**REPLACE the OQGF-M-10 row:**

> | **OQGF-M-10 (invariant enforcement)** | **PARTIAL — accumulation and non-removal enforced in SKULD; action-evaluation lands via `PolicyRegister` for DECLARATIVE invariants (§6.2, Rev 1.4); detail-level invariants remain unevaluated (§13)** |

**WITH:**

> | **OQGF-M-10 (invariant enforcement)** | **SATISFIED for declarative invariants — accumulation and non-removal in SKULD; action-evaluation in SINDRI conjunct 4 (`884958f`), which denies an invariant with no declared predicate. Detail-level invariants (a path rule inside `Action.detail`) remain unevaluated — a standing residual (§13), not the deferred-conjunct gap, which is closed** |

**ADD** rows (place near the Organ 5 and Physiology rows):

> | **OQGF-A-1 (decision records) — evidence provenance** | **`brokkr-audit::AuditRecord::provenance` (`EvidenceProvenance`), part of the signed content; every SAGA record carries sensor, capture path, coverage, and explicit gap; `append_with_provenance` / `AuditSink::record_with_provenance`; the orchestrator is the sensor and says so (F-23). The general Organ 5 principle — the governed system is not the authority over its own evidence — is met in recording form; an independent sensor is future work (§13). Organ 5 evidence-capture hardening patch (§6.9)** |
> | **OQGF-A-8 … A-12 (AMD-010)** | **n.a. — types placed in `brokkr-core::explanation` (Option B); `ExplanationValidity` has no Null→Valid path; OQGF-A-4 is n.a. (classical LLM), so these inherit the disposition (§1.4, §6.9)** |
> | **OQGF-P-12.1, P-12.2 (dual-axis, envelope)** | **`brokkr-core::capability::CapabilityEnvelope` + `CapabilityProperty`; `governing_tier = max(...)` enforced by `validate()` (TierMismatch/TierTooLow); BROKKR's envelope floors at Enhanced (§6.13)** |
> | **OQGF-P-12.3 (environment attestation)** | **PARTIAL — envelope declared, validated, signed-in-shape, `attested_at` carried; no deployed-environment attestation mechanism (§13)** |
> | **OQGF-P-12.4 (deterministic egress)** | **`brokkr-cli` `check_egress`; default-deny against the signed `EgressManifest`; Deterministic Gate under OQGF-P-2, sibling to OQGF-I-10 (§6.13)** |
> | **OQGF-P-12.5 (independent termination)** | **`brokkr-cli` `kill_flag: Arc<AtomicBool>` / `kill_handle()`, checked before every gate; the model has no channel to it (§6.13)** |
> | **OQGF-P-12.6 (sub-agent / peer / collective)** | **PARTIAL / type-surface — `SubAgentRecord::validate` (capability subset + AMD-001 attenuation) and the collective `CapabilityProperty` members placed; BROKKR spawns no sub-agents (§6.13, §13)** |
> | **OQGF-P-12.7 (prompt-only rejection)** | **Satisfied by construction — every containment/authorization/enforcement control is deterministic Rust external to the model; the prompt is an intent input, never a boundary (§6.13, §2)** |
> | **OQGF-P-12.8 (trajectory + evidence independence)** | **`brokkr-cli` `record_trajectory` — every hop attempt appended (`TrajectoryEntry` with `EvidenceProvenance`); `trajectory()` accessor; recording half met, independent-sensor half named (§6.9, §6.13, §13)** |

---

## 10. §15 — Change log

**ADD** at the top of the change log:

> **Rev 1.18 — 1 September 2026. Records three placed governance items and closes the Deferred-Conjunct Deadline. Every change adds, tightens, or records a fact; the one removed residual is removed because its requirement is now enforced.**
>
> - **AMD-010 (Explanation Validity, OQGF-A-8…A-12) placed and dispositioned `n.a.`** AMD-010 extends OQGF-A-4 (quantum-appropriate explanation artifacts) with a declared scope bound, the Null Explanation, trainability reconciliation, and the Canary Probe. BROKKR runs a classical LLM with no variational or kernel quantum model in its decision path; OQGF-A-4 is already `n.a.` (§1.4), so OQGF-A-8…A-12 inherit that disposition. The `brokkr-core::explanation` type surface is placed (Option B) so the architecture can name it and the surface is ready for a future quantum workload; no logic is built. **This disposition requires no further implementation work from the builder, which is stated per CLAUDE.md §4 — the `n.a.` is the DAP's, on the OQGF-A-4 basis, not the builder's recommendation.**
> - **AMD-011 v1.1 (Capability-Triggered Assurance, OQGF-P-12.1…P-12.8) placed and implemented (§6.13).** The dual-axis rule (`governing_tier = max(capability, data)`, enforced by `CapabilityEnvelope::validate`), deterministic default-deny egress (a Deterministic Gate under OQGF-P-2, sibling to OQGF-I-10), independent termination (a kill flag checked before every gate that the model cannot reach), and trajectory reconstruction with evidence provenance are built. BROKKR's declared envelope — `CodeExecution` + `NetworkAccess(localhost:8443)` + `ExternalEffect(filesystem)` — floors at Enhanced, matching BROKKR's governing tier. Environment attestation (P-12.3) and sub-agent/peer/collective governance (P-12.6) are placed as declarations and type surfaces, not built or exercised, and are recorded PARTIAL (§13, §14).
> - **The Organ 5 evidence-capture hardening patch placed and implemented (§6.9).** OQGF-A-1 is extended so every material audit record carries evidence-source provenance (sensor, capture path, capture timestamp, coverage scope, explicit gap), and the general Organ 5 principle is added: **the governed system SHALL NOT be the authority over its own evidence.** `AuditRecord::provenance` is part of the signed content — set once at capture, so signing it means a non-key-holder cannot alter how a record claims it was captured. BROKKR's sensor is the orchestrator, stated honestly in `sensor_id` (F-23); an independent sensor is future work (§13).
> - **The Deferred-Conjunct Deadline is closed (§6.4).** All four OQGF-M-11 conjuncts are now enforced in SINDRI: Signals 1–2 (Phase 4) and conjuncts 3–4 via the `GenomeResolver` seam (gate revision `884958f`). The §13 residual is closed and the OQGF-M-11 and OQGF-M-10 traceability rows move from PARTIAL to SATISFIED (M-10 for declarative invariants; the detail-level-invariant residual stands, and OQGF-M-1 is unaffected and remains PARTIAL).
> - **Corpus growth recorded.** The binding is now OQGF-1.0 + AMD-001…AMD-011 + the Organ 5 patch; the Physiology Layer runs OQGF-P-1…P-12. Per CLAUDE.md §5.3, every conformance result recorded before this revision is provisional with respect to the new requirements, and the next conformance check in each affected crate SHALL enumerate them.

— End of Rev 1.18 draft delta.
