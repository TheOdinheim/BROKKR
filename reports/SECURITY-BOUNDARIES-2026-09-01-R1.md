# Security Boundaries — Phase 16 Addenda — R1

**Record ID:** SECURITY-BOUNDARIES-2026-09-01-R1
**Date:** 2026-09-01
**Supersedes nothing; extends** `SECURITY-BOUNDARIES-2026-08-30-R1.md` (M-3, F-27/F-28/F-30/F-31, DAP root-of-trust, TLS CA custody, I-14 uncontrolled channels). A **new dated file** rather than an edit to the 2026-08-30 record — §8 (never overwrite a record; every run is a new dated file). Read the two together.
**Author:** Claude Code (builder)

This record documents the Phase-16 findings that Phase-16-FIX **accepted** rather than fixed: the architectural / by-design ones, and the two MEDIUM findings **referred to the DAP** because closing them is a design or governing-type decision, not a builder fix.

---

## Accepted — by design

### F-37 — the kill switch is pre-hop, not a mid-hop abort

The `KillSwitch` (16-FIX) is read at the top of every `run_hop`, before any gate. A hop already inside tool execution runs to completion; the latch stops the **next** hop. Termination latency is therefore bounded by the longest single tool call — a **bound**, not a dependency on the agent's cooperation (OQGF-P-12.5 forbids the latter, and the pre-hop read does not traverse the model's reasoning). Aborting a tool mid-execution could leave the filesystem in an inconsistent state; the defense is that the tool is sandboxed (`SandboxedTool`) and its action was already authorized before it began. **Mitigation for lower latency:** keep tool calls bounded; a truly immediate abort would require cooperative cancellation inside each tool, which the tool layer does not currently offer.

### F-38 — the trajectory is in-memory, not a SAGA event

`TrajectoryEntry` lives in the orchestrator's `Mutex<Vec<..>>` and has no `AuditEvent` variant; it is volatile (lost on process exit/crash). This is the **same shape as F-30** (SAGA end-truncation ⇐ external witness): durable, tamper-evident reconstruction of a session rests on the individual SAGA event records (proposal / barrier / gate / signal), which *are* signed and hash-chained. The in-memory trajectory is a convenience snapshot for live inspection. **Mitigation:** if the trajectory itself must be durable, append it to SAGA or persist it alongside; today the SAGA event stream is the durable record.

---

## Accepted — referred to the DAP (design / governing-type decisions)

These three are genuine gaps between AMD-011 and the orchestrator wiring. The 16-FIX task prescribed three specific fixes and did **not** prescribe these; per §4 the builder does not unilaterally change a construction default or a governing type, so each is recorded here with the decision the DAP would make. All three also intersect the **Rev 1.18 / v1.8 drafts** now under DAP review, where the drafted invariant I-14 ("a Capability Envelope is validated before it governs") is **stronger than the shipped code** — a mismatch this red-team surfaced.

### F-32 — `with_envelope` does not call `validate()`

`Orchestrator::with_envelope` installs a caller-supplied `CapabilityEnvelope` without calling `validate()`, so an orchestrator can run with a `TierTooLow` / `TierMismatch` envelope. **Structural guarantee that holds:** the type *can* catch it (`validate()` is correct), and Fix 3 now guarantees the *library-provided* default (`permissive()`) is valid. **Residual:** the orchestrator boundary does not enforce validation on a caller-supplied envelope. **DAP decision:** add a validating install path (e.g., `try_with_envelope(env) -> Result<Self, EnvelopeError>`), or a debug-assert mirroring Fix 3, or leave `with_envelope` as a documented caller-contract. Recorded as the P-12.1/2 PARTIAL in `CONF-2026-09-01-P16FIX-R1.md`.

### F-33 — capability governance is fail-open by default

`Orchestrator::new()` defaults `envelope = permissive()` and `egress_rules = None`, so an orchestrator built without `.with_envelope(..)` performs no egress enforcement — in contrast to `guards = Guards::production()` (fail-safe default). **Structural guarantee that holds:** BROKKR's shipped composition supplies a signed, valid envelope via `.with_envelope(..)`. **Residual:** the *default* is fail-open, an inconsistent safety posture vs the guards default. **DAP decision:** default to a deny-safe envelope (empty manifest → deny all network), or require an envelope at `new()`, or accept the permissive default as a dev/test convenience. Recorded as the P-12.1/2 PARTIAL.

### F-34 — the egress manifest's port and protocol are unenforceable

`EgressRule` declares `{ destination, port, protocol }` (as OQGF-P-12.4 requires), but `Destination::Network` (`brokkr-core::barrier`) carries only `{ host, channel }`, so `check_egress` matches host alone (now representation-robust after Fix 2, but still host-only). A manifest intending "localhost:8443 HTTPS" admits "localhost, any port, any protocol." **Structural guarantee that holds:** an unauthorized *host* is denied; latent today (no `Destination::Network` tool exists — current tools produce `LocalPath`, and the reasoner crossing is `Reasoner`, gated by HÚÐ). **Residual:** port/protocol granularity. **DAP decision:** add `port`/`protocol` to `Destination::Network` and a full-tuple match — a governing `brokkr-core::barrier` type change that touches HÚÐ, hence the DAP's call, not a hardening-pass fix. Recorded as the P-12.4 PARTIAL.

---

## Summary

| Finding | Class | Guarantee that holds | Residual | Mitigation / decision |
|---|---|---|---|---|
| F-37 | by design | pre-hop read doesn't traverse the model | latency ≤ longest tool call | bounded tool calls; sandboxed tools |
| F-38 | by design | SAGA event stream is signed + chained | in-memory trajectory volatile | rely on SAGA events; persist trajectory if needed |
| F-32 | referred | `validate()` correct; default guaranteed valid | boundary doesn't validate caller envelope | DAP: validating install path? |
| F-33 | referred | shipped composition supplies a valid envelope | default is fail-open | DAP: deny-safe default? |
| F-34 | referred | unauthorized host denied; latent | port/protocol unenforceable | DAP: `Destination::Network` type change |

None is a code defect in the shipped composition. F-32/F-33/F-34 are the substantive gaps and all three sit with the DAP, intersecting the pending Rev 1.18 / v1.8 placement.
