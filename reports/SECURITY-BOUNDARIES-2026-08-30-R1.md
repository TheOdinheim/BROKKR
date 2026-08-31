# BROKKR — Security Trust Boundaries

**Record ID:** SECURITY-BOUNDARIES-2026-08-30-R1
**Date:** 2026-08-30
**Type:** Reference — the consolidated list of BROKKR's **named trust boundaries**: properties that are *not* code defects but are the deliberate edges where the spine's structural guarantees end and operational / key-custody / external-witness controls begin. Every one was surfaced by the red-team campaign (13A–15C) or the `/security-review` audit and is already implied by BROKKR-ARCH §13; this document collects them in one place so a deployment knows exactly which controls it must supply.
**Author:** Claude Code (builder)
**Sources:** `reports/REDTEAM-15C-2026-08-24-R1.md` (§5 terminal observation, F-30), `reports/SECURITY-REVIEW-2026-08-30-R1.md` (M-3), BROKKR-ARCH §13, OQGF-R-6 / R-5.

---

## The governing principle

BROKKR is an **authorization** system, not an omnipotent one. Its type system makes unauthorized *action* structurally impossible (I-1, I-2, I-12) and makes forgery *without the keys* computationally infeasible (dual-family PQC). What it cannot do by cryptography alone is constrain the **holder of the trust anchors** — the DAP and the signing keys. Every boundary below is an instance of that single fact: *a framework can make the accountable party named, signed, recorded, and reviewable; it cannot make them trustworthy.* These are named, not hidden, and each has an operational mitigation.

---

## The named boundaries

### M-3 — SAGA integrity against a key-holding insider rests on key custody, not the hash chain
**What:** SAGA's hash chain links over each record's *signed content* `(seq, prev, at, dap, event)` and **not** its signature (`saga.rs:216, 233`). The hash chain protects **ordering and completeness** (it detects a non-key-holder's edits, reorderings, and middle-deletions); the dual-family signature protects **authorship**. An insider **with the audit-signing key** can modify a record's `event`, re-sign it, recompute the forward `prev` links, and re-sign the suffix — and `verify_chain` returns `Intact`. For the tail record, no forward rewrite is needed.
**Why it is not a code defect:** covering the signature in the hash would make OQGF-A-6 re-signing report itself as an integrity break (the Rev 1.10 rationale), and it would *not* stop a key-holder, who would simply re-sign. The property is inherent to any signed append-only log.
**Mitigation (operational):** signing-key custody — **OQGF-R-6** threshold (3-of-5) / HSM with dual-control issuance denies any single insider the unilateral rewrite — plus an **external witness** (below). Recorded PARTIAL in BROKKR-ARCH §1.4/§6.11.
**Source:** `/security-review` M-3 (`SECURITY-REVIEW-2026-08-30-R1.md`).

### F-30 — SAGA end-truncation is undetectable without an external witness
**What:** `verify_chain` (`saga.rs:268-298`) recomputes every `prev` and verifies every signature, so modification, reordering, and middle-deletion all yield `ChainStatus::Broken`. But removing the most-recent *k* records leaves a valid *shorter* chain (record 0 → genesis intact, all remaining links intact), which verifies `Intact` — the chain has no notion of expected length.
**Why it is not a code defect:** detecting removal-from-the-tail is impossible for any append-only log using only its own contents; it requires knowing the expected head. Realizable only against a persisted store with write access (SAGA is in-memory in this build).
**Mitigation (operational):** an external length witness — a monotonic head-sequence checkpoint stored independently, or **OQGF-R-5** cross-jurisdictional replication. Shares its mitigation with M-3.
**Source:** Red Team 15C F-30 (`REDTEAM-15C-2026-08-24-R1.md`).

### The DAP is the root of trust the spine cannot constrain
**What:** the DAP scopes the Root Intent, owns the genome and Self Set, signs SAGA, configures the guards, and holds the keys. The spine makes the DAP *accountable* (named natural person, signed decisions, recorded, reviewed — OQGF-A-5, OQGF-P-9.5); it has no mechanism to constrain a malicious or coerced DAP.
**Mitigation:** second-DAP review (High-Assurance), periodic review, and the same key-custody controls as M-3.
**Source:** 15C §5 terminal observation; 15A F-1.1; OQGF-M-13.

### Content-blind auditing — the action is recorded, its effect is not (F-31)
**What:** SAGA records the action *detail* (e.g. the path written), never the tool's `ToolOutcome.output` or the bytes a tool wrote. A fully-authorized action's *effect* is outside the audit trail. By design — the spine governs *authority*, not *content*.
**Mitigation:** tool-level content logging / filesystem monitoring / DLP on outputs, supplied at the tool layer.
**Source:** 15C F-31.

### Tool-layer boundaries — output and reads are ungoverned (F-27, F-28)
**What:** `ToolOutcome.output` is unvalidated (a covert/exfiltration channel to the caller — F-27), and a tool's filesystem *reads* are unrestricted (`SandboxedTool` gates *writes* only — F-28).
**Mitigation:** OS-level sandboxing of tool execution (seccomp / namespaces / read-only mounts).
**Source:** 15B F-27, F-28.

### TLS channel trust rests on private-CA key custody (LOW hardening open)
**What:** the mTLS client verifies the server chain against the loaded CA but does not explicitly set `WOLFSSL_VERIFY_PEER` (relies on the wolfSSL client default) nor check the hostname against the cert. Bounded by the operator-controlled single-CA deployment model (§6.10.1); channel security rests on CA key protection.
**Mitigation:** explicit `wolfSSL_CTX_set_verify` + `wolfSSL_check_domain_name`; protect the CA private key.
**Source:** full audit Finding 1; 15A F-1.4.

### Uncontrolled channels are enumerated, not enforced (OQGF-I-14)
**What:** data leaving through a channel BROKKR does not operate (a developer's own terminal, a personal device) is outside HÚÐ's reach.
**Mitigation:** enumerate and reduce reliance (make the governed path frictionless); OS/network controls.
**Source:** BROKKR-ARCH §13; AMD-007 OQGF-I-14.

---

## Reading guide

| Boundary | Structural guarantee that *does* hold | The residual (this document) | Operational mitigation |
|---|---|---|---|
| M-3 | forgery without the key needs breaking 2 PQC families; ordering/completeness verified | a key-holder can rewrite + re-sign | R-6 key custody + external witness |
| F-30 | modification / reorder / middle-deletion detected | tail-truncation undetectable | external length witness / R-5 |
| DAP | every DAP decision signed, recorded, reviewable | a malicious DAP is not constrained | 2nd-DAP review; key custody |
| F-31 | the authorized action is recorded | its content/effect is not | tool-level content logging |
| F-27/F-28 | tool input authority is gated | tool output/reads ungoverned | OS sandbox |
| TLS | chain-to-CA verified | no explicit verify flag / hostname check | explicit verify + CA custody |
| I-14 | governed crossings gated by HÚÐ | uncontrolled channels unreachable | enumerate + reduce |

**The common root:** every row's residual is the trust anchor — the DAP and the keys. The spine reduces the attack surface to exactly these named points and makes the anchor accountable; the deployment supplies key custody, an external witness, OS sandboxing, and DAP review. None of these is a code defect; all are documented so they are managed rather than assumed.
