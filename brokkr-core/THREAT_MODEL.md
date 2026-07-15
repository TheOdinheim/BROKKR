# THREAT_MODEL — brokkr-core

**Crate:** `brokkr-core` (Phase 1). **Date:** 14 July 2026.

`brokkr-core` is the type layer of the deterministic spine. It performs no I/O, no
cryptography, and no network access. Its security value is entirely **structural**:
it makes certain unsafe states unrepresentable so that later crates cannot express
them. This threat model is therefore about what the *types* prevent, not about a
running attack surface (there is none in this crate).

## Trust boundaries

`brokkr-core` sits below every other crate and trusts none of them. It exposes
traits that later, less-trusted crates implement (`Signer`, `CostimulationGate`,
`ContextClearance`, `Barrier`, `Reasoner`, …). The load-bearing property is that an
implementor of these traits **cannot** reach the private minting paths for
`AuthorizedAction` (gate) or `ClearedContext` (clearance): those are minted only
inside provided methods defined in this crate.

## Assets

- The **invariants** I-1 … I-12 as type-level facts.
- The **algorithm-identifier enums** (`SignatureAlg`, `HashAlg`, `KemAlg`,
  `NamedGroup`) — typed, never strings (OQGF-G-5).

## Threats considered, and the structural mitigation

| # | Threat (STRIDE) | Mitigation in this crate |
|---|---|---|
| T1 | *Elevation* — a downstream crate forges an `AuthorizedAction` to execute ungoverned (I-1). | No public constructor; `mint` is module-private; the only caller is the provided `CostimulationGate::authorize`. Overriding `authorize` cannot mint (mint is private) — worst case is fail-safe deny. |
| T2 | *Tampering* — a `Deny` is converted to an `Allow` (I-2). | No method, `From`, or conversion of any kind yields `Allow` from `Deny`; `AcceptedRisk` is a separate variant. Proven by a `compile_fail` doctest and the absence of any such API. |
| T3 | *Elevation* — intent scope widened across hops (I-3). | The only append path (`IntentProvenanceChain::extend`) rejects a non-subset emitted scope. No widening constructor exists. |
| T4 | *Tampering* — a deterministic gate silently suppressed (I-4). | `ToleranceController::grant` refuses a `Deterministic` target with `Err(NonSuppressibleGate)` in a core-provided method no implementor can skip. |
| T5 | *Elevation* — a learned detector becomes/modifies a deterministic gate (I-9). | `RefinedDetector::response_class` is private and fixed to `Heuristic`; no path sets `Deterministic`. |
| T6 | *Spoofing* — a reasoner reached over one-sided TLS (I-11). | `ModelEndpoint::client_cert` is a required field, not `Option`; an anonymous endpoint is unconstructable. |
| T7 | *Information disclosure* — an ungoverned context shipped to a model (I-12). | `Reasoner::propose` accepts only a `ClearedContext`, which has no public constructor and is minted only by `ContextClearance::clear` on a proceed verdict. |
| T8 | *Repudiation* — an escalation with no way down, or a de-escalation with no accountable party (I-8). | `EscalationType` is unconstructable without a resolution path and baseline; `ResolutionDecision` is unconstructable without a DAP and signature. |
| T9 | *Supply chain* — a transitive dependency compromises the foundational crate. | Zero dependencies. `#![forbid(unsafe_code)]`. `no_std`. |

## Explicitly out of scope for this crate

- **Cryptographic correctness.** `brokkr-core` holds only opaque bytes and typed
  algorithm identifiers; verification/signing is Phase 2 (`brokkr-crypto`). A wrong
  or forged signature is not something this crate can detect — it defines the seam.
- **Running enforcement.** The gate, barrier, sentinel, resolution engine, and
  maturation pipeline are traits here; their logic is Phases 4–9.
- **I-5, I-6, I-7** (dependency direction, single-model-caller, self-modification
  DAP-gating) are cross-crate / CI properties, enforced across the workspace, not by
  a single type in this crate.
