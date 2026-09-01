# DRAFT — CLAUDE.md v1.8 (delta for DAP review)

**Status of this file.** This is a *builder-authored draft* of a DAP-placed change to
`CLAUDE.md`, written to `/tmp` for the DAP to review and place. Per §4/§5.2 the builder may
draft add-only rules; the DAP's review and commit are the ratification, and per §5.2 a revision
to `CLAUDE.md` is committed **before** any work begins under it. **Nothing here is committed.**
Each block quotes its anchor or names where it is inserted.

**What v1.8 does.** Records the corpus growth (AMD-010, AMD-011, the Organ 5 evidence-capture
patch), adds structural invariants and build rules for the new AMD-011 and Organ 5 surfaces, and
logs the change. **Every change adds or tightens; nothing is relaxed** — the guardrail of §4.

**One item flagged for the DAP's decision.** The DAP's instruction named four build rules to add
(CapabilityEnvelope validation at construction; kill-flag check before all gates; trajectory
recording after every hop; provenance on every SAGA record). The draft renders these as
invariants **I-14 … I-17**. It also adds **I-18 (deterministic default-deny egress)**, which the
DAP did *not* enumerate but which AMD-011 P-12.4 classifies as a Deterministic Gate under
OQGF-P-2 — a structural containment control the build rules ought to carry alongside the other
four. It is add-only and the DAP may keep or drop it; it is marked clearly so the choice is easy.

---

## 1. §0 — the normative corpus (corpus growth)

**ADD** a new paragraph after the existing AMD-008/AMD-009 growth paragraph (the one beginning
"The corpus grew on 15 July 2026…"):

> **The corpus grew again on 1 September 2026: the binding is now OQGF-1.0 + AMD-001 … AMD-011 + the Organ 5 evidence-capture hardening patch.** AMD-010 (Explanation Validity) adds OQGF-A-8…A-12 — bounded explanation scope, the Null Explanation, trainability reconciliation, and the Canary Probe — extending Organ 5's *quantum-appropriate* explanation artifact (OQGF-A-4). AMD-011 v1.1 (Capability-Triggered Assurance) adds OQGF-P-12.1…P-12.8 — the dual-axis (data **and** capability) tier determination, the signed Capability Envelope, deterministic default-deny egress, independent termination, sub-agent/peer/collective governance, prompt-only-containment rejection, and trajectory reconstruction with evidence-capture independence. The Organ 5 evidence-capture hardening patch extends OQGF-A-1 to require evidence-source provenance on every material audit record and adds the general Organ 5 principle: **the governed system SHALL NOT be the authority over its own evidence.** **Every conformance result recorded before this date is provisional** with respect to these requirements; the next conformance check in each affected crate SHALL enumerate OQGF-A-8…A-12, OQGF-P-12.1…P-12.8, and the OQGF-A-1 evidence-provenance extension in scope and record a verdict — `satisfied`, `partial`, `absent`, or `n.a. with justification` — for each. Silence is not a pass (§5.3).
>
> **Where the new requirements land** (a pointer, not a substitute for the check): **AMD-010's** `ExplanationArtifact` / `ExplanationValidity` / `CanaryAttestation` types are placed in `brokkr-core::explanation` as a **type surface only**, because BROKKR runs a classical LLM and the architecture declares OQGF-A-4 — and therefore OQGF-A-8…A-12 — `n.a.` (BROKKR-ARCH §1.4, §6.9). **AMD-011's** `CapabilityEnvelope` / `CapabilityProperty` / `EgressManifest` / `SubAgentRecord` / `TrajectoryEntry` / `EvidenceProvenance` types are `brokkr-core::capability` shapes with intrinsic `validate()`; the enforcement — default-deny egress, the kill flag, trajectory recording — is `brokkr-cli` orchestrator wiring (BROKKR-ARCH §6.13). **The Organ 5 patch's** `EvidenceProvenance` rides on `brokkr-audit::AuditRecord` **inside the signed content** and is populated by the orchestrator (BROKKR-ARCH §6.9). Whether each is discharged, partial, or n.a. is a delta check, not an assumption, and it runs in the next conformance pass of each affected crate.

**REPLACE** the count sentence at the head of §0 (if present — "**The corpus grew on 15 July 2026: it is now nine amendments, not seven…**"):

> The corpus is now **eleven amendments (AMD-001 … AMD-011)** plus the **Organ 5 evidence-capture hardening patch** — **thirteen governance documents** counting OQGF-1.0 itself. *(Arithmetic correction to the count only; the same documents are imported and binding. Keep the existing dated growth paragraphs beneath, per §8 — they are historical, and this line is the operative count.)*

**Note on imports.** If the DAP wishes the new documents loaded on every session like the rest of
the corpus, add to the `@`-import block in §0:

> ```
> @governance/AMD-010-explanation-validity.md
> @governance/AMD-011-capability-triggered-assurance.md
> @governance/OQGF-organ5-evidence-capture-hardening-patch.md
> ```
>
> *(These three are already committed under `governance/`. Adding the imports is the DAP's call; they are read-only like the rest, §0.)*

---

## 2. §3 — new structural invariants

**ADD** after I-13. These are add-only; each carries at least one negative test naming its ID
(§7). Where a property is enforced by the type system it is stated as such; where it is enforced
by control flow (the recording rules), that is stated honestly rather than dressed as a type
guarantee.

> **I-14 — A Capability Envelope is validated before it governs.**
> `CapabilityEnvelope::validate` returns `Err(EnvelopeError::TierMismatch)` when `governing_tier != max(capability_tier, data_tier)` and `Err(EnvelopeError::TierTooLow)` when an `ExternalEffect`, `CredentialAccess`, or `SubAgentCreation` property is present while `capability_tier` is below Enhanced (OQGF-P-12.1, P-12.2). An envelope is validated before it is installed to govern a run. `governing_tier` is `max` of the two axes by construction, so **public or synthetic data cannot buy a lower governance posture** — the higher axis wins. There is no constructor that lowers the governing tier below either axis.
>
> **I-15 — Independent termination is checked before every gate, and the model cannot reach it.**
> The kill signal is an out-of-band `Arc<AtomicBool>` handed out by `kill_handle()` to threads outside the reasoning path; `execute_hop` loads it **before** costimulation, the barrier, egress, and tool execution, and stops the hop the instant it is set (OQGF-P-12.5). There is no tool, field, or path by which a model proposal can set, clear, delay, observe, or route around it — the structural posture of I-6/I-12 applied to the stop button. A termination path that traversed the reasoner's own execution would not satisfy this invariant.
>
> **I-16 — Every hop attempt is recorded.**
> `execute_hop` appends a `TrajectoryEntry` for every attempt, whatever its outcome — `Executed`, `Denied` at any stage (including a denial before a proposal exists), or `Error` — so the ordered session trajectory is complete and reconstructable (OQGF-P-12.8). A hop that took an action and left no trajectory entry is not a reachable state. *(Control-flow-enforced, not type-enforced: the negative test drives every outcome and asserts a trajectory entry for each.)*
>
> **I-17 — No audit record without stated provenance.**
> `AuditRecord::provenance` is a required field of type `EvidenceProvenance` (never an `Option`), and it is part of the record's **signed, hash-chained content** (Organ 5 evidence-capture patch; OQGF-P-12.8). A record that does not state how it was captured — its sensor, capture path, coverage, and any explicit gap — is unrepresentable, and because provenance is signed and chained (it is set once at capture, unlike the accumulating signatures Rev 1.10 excludes), a non-key-holder cannot alter how a record claims it was captured without breaking the chain. **The governed system is not the authority over its own evidence:** where the orchestrator is itself the sensor, `sensor_id` states it (F-23), never hides it, and an errored hop records an explicit `evidence_gap` rather than presenting a partial record as complete.
>
> **I-18 — Egress is default-deny by construction.** *(Added beyond the four rules the DAP enumerated — AMD-011 P-12.4 classifies this as a Deterministic Gate under OQGF-P-2; the DAP may keep or drop it.)*
> Any system whose Capability Envelope declares network access enforces deterministic default-deny egress: a network destination absent from the signed, agent-unmodifiable `EgressManifest` is denied (`check_egress` returns `Denied`), fail-closed and non-suppressible — no tolerance mechanism, exception, or model instruction opens it (OQGF-P-12.4, OQGF-P-2). This is a sibling to HÚÐ's data-classification egress gate (OQGF-I-10): I-10 triggers on what the *data* is, this on what the *system can reach*. A deliberate, bounded addition to the manifest is an AMD-006 Accountable Risk Acceptance, and the manifest is `SelfModifying` (I-7), never a silent edit.

**ADD** to the closing paragraph of §3 (the one requiring a negative test per invariant):

> I-14 … I-18 each carry a negative test naming the invariant ID, on the same footing as I-1 … I-13. I-15 and I-18 are the load-bearing containment tests for the agentic surface: I-15 proves the stop button cannot be reached by the thing it stops, and I-18 proves an undeclared destination is denied rather than reached.

---

## 3. §5.1 — build order (note, no phase reordering)

**ADD** a note after the build-order table (no phase is inserted — these surfaces live in
existing crates):

> **AMD-010, AMD-011, and the Organ 5 evidence-capture patch add no new phase.** AMD-010's types are placed in `brokkr-core` (Phase 1 surface, type-only, n.a.). AMD-011's types are placed in `brokkr-core` (Phase 1 surface) with intrinsic `validate()`; its enforcement — default-deny egress (I-18), independent termination (I-15), and trajectory recording (I-16) — is `brokkr-cli` orchestrator wiring at the executor phase (Phase 11), which is exactly where a containment control on live tool execution belongs. The Organ 5 evidence-provenance field is a `brokkr-audit` (Phase 7 surface) change, populated by the orchestrator (Phase 11). Because these ride on existing crates, the spine-first / executor-last ordering is unchanged, and the containment controls are wired **with** the executor they contain, never before it exists.

---

## 4. §7 — negative-test naming examples

**ADD** to the list of test-name examples in §7:

> `test_i14_envelope_governing_tier_must_be_max`, `test_i14_external_effect_floors_at_enhanced`, `test_i15_kill_flag_checked_before_every_gate`, `test_i15_model_has_no_channel_to_kill_flag`, `test_i16_every_hop_outcome_records_a_trajectory_entry`, `test_i17_audit_record_provenance_is_required_and_signed`, `test_p12_8_errored_hop_records_evidence_gap`, `test_i18_egress_absent_destination_denied`, `test_p12_4_egress_deny_is_non_suppressible`, `test_p12_6_sub_agent_capability_must_be_subset_of_parent`.

---

## 5. §10 — the hard list

**ADD** items to the hard list (continuing the numbering after item 16):

> 17. Never wire a termination path that a model can reach, influence, delay, or route around — the stop button is checked before every gate and the model has no channel to it (I-15, OQGF-P-12.5).
> 18. Never let a network destination cross without being on the signed egress manifest — default-deny is by construction, and the only way to add a destination is an AMD-006 risk acceptance, never a silent edit (I-18, OQGF-P-12.4).
> 19. Never write an audit record that does not state how it was captured — provenance is a required, signed field, and where the governed system is its own sensor, say so; never present a partial record as complete (I-17, OQGF-A-1 as extended).
> 20. Never let a Capability Envelope govern a run before it validates, and never let public or synthetic data buy a lower governing tier than the system's capabilities demand (I-14, OQGF-P-12.1).

*(The existing closing line — "When any of these come into conflict with finishing the task, the task loses." — stands unchanged and now covers items 17–20.)*

---

## 6. §12 — change log

**ADD** at the top of the change log:

> **v1.8 — 1 September 2026.** Records the corpus growth to AMD-001 … AMD-011 plus the Organ 5 evidence-capture hardening patch, and adds structural invariants and build rules for the new AMD-011 and Organ 5 surfaces, aligning to Architecture Rev 1.18. Every change adds or tightens; nothing is relaxed.
>
> - **§0 — corpus growth recorded.** AMD-010 (OQGF-A-8…A-12), AMD-011 v1.1 (OQGF-P-12.1…P-12.8), and the Organ 5 evidence-capture patch (OQGF-A-1 extended) are added to the binding corpus; the count is corrected to eleven amendments plus the patch (thirteen governance documents). Prior conformance results are declared provisional with respect to the new requirements, and the next conformance check in each affected crate SHALL enumerate them (§5.3). Where each is expected to land is stated as a pointer, not a substitute for the check. **AMD-010 is placed as a `brokkr-core::explanation` type surface only** — BROKKR runs a classical LLM and the architecture declares OQGF-A-4, hence OQGF-A-8…A-12, `n.a.` (BROKKR-ARCH §1.4).
> - **§3 — five structural invariants, I-14 … I-18.** I-14 (a Capability Envelope validates before it governs, and the governing tier is the higher of the two axes by construction — public data cannot buy a lower posture); I-15 (independent termination is checked before every gate and the model cannot reach it); I-16 (every hop attempt is recorded, so the trajectory is complete); I-17 (no audit record without stated, signed evidence provenance — the governed system is not the authority over its own evidence); and I-18 (egress is default-deny by construction — a Deterministic Gate under OQGF-P-2). I-18 was added beyond the four rules named in the placing instruction because AMD-011 P-12.4 classifies default-deny egress as a Deterministic Gate, and the build rules must carry every Deterministic Gate.
> - **§5.1 — no phase reordering.** The new surfaces ride on existing crates (`brokkr-core` types, `brokkr-audit` field, `brokkr-cli` enforcement at Phase 11), so the spine-first / executor-last order is unchanged and the containment controls are wired with the executor they contain.
> - **§7 and §10 — negative-test names and hard-list items** added for the new invariants. Items 17–20 forbid a model-reachable kill path, an off-manifest egress, an audit record without stated provenance, and an ungoverned or under-tiered Capability Envelope.
>
> **What this version does not change.** No prior structural invariant, no code standard, no existing hard-list item, and no conformance verdict is weakened. AMD-010's `n.a.` disposition and AMD-011's implementation are transcribed from placed governance and committed code, not invented here. The one item added beyond the placing instruction (I-18) is flagged as such for the DAP's decision. Placed by the DAP.

— End of CLAUDE.md v1.8 draft delta.
