# BROKKR

**The governed autonomous coding agent.**
Repository: BROKKR — Odin's LLC. DAP: Jeremy Rose, CEO.

---

## What BROKKR is

BROKKR is an autonomous coding agent, written in Rust, whose every action is governed
by a deterministic control spine derived from OQGF-1.0. It reads a codebase, reasons
about a task through a swappable frontier reasoning model (MÍMIR), and edits files,
runs commands, and calls tools — with one property that defines the whole design:

> **No action BROKKR takes reaches the real world without first passing a deterministic
> gate that the reasoning model cannot influence, suppress, or talk its way past.**

The reasoning model proposes; the deterministic spine disposes. The model is never in
the trust path for any decision to block, permit, raise, or lower posture. Governance
is **structural** — enforced by Rust types and gates that contain no model — not
**behavioral** (a prompt asking a model to please behave).

The full specification is `docs/BROKKR-ARCH-2026-001.md`. The normative authority is
the corpus under `governance/`.

## The seven subsystems

| Subsystem | Role |
|---|---|
| **MÍMIR** | The advisory reasoner (frontier LLM behind a trait). Proposes; never acts. |
| **REGIN** | The Tool Genome. Signed registry of every tool, each with a privilege class. |
| **SKULD** | The Intent Provenance Chain. Carries the Root Intent across hops; attenuates. |
| **SINDRI** | The Costimulation Gate — the deterministic spine. Mints `AuthorizedAction`. |
| **HÚÐ** | The Barrier. Data-custody control on file and network crossings. |
| **HEIMDALL** | The Sentinel. Behavioral anomaly and cross-hop reconciliation. |
| **SAGA** | The Audit Spine. Signed, append-only record of every proposal and decision. |

## What is in this repository

```
BROKKR/
├── CLAUDE.md                      # Build rules — binding on every build action
├── README.md                      # This file
├── governance/                    # READ-ONLY normative corpus (OQGF-1.0 + AMD-001..007)
├── docs/
│   └── BROKKR-ARCH-2026-001.md    # The architecture specification (do not edit)
├── reports/                       # Phase and readiness reports + INDEX
├── gaps/                          # Amendment-gap reports (Section 4) + INDEX
├── audits/                        # Security-audit records + INDEX
└── tests/records/                 # Functionality/verification test records + INDEX
```

`governance/` and `docs/BROKKR-ARCH-2026-001.md` are read-only. They are the
specification BROKKR is built *from*; they are not amended by the builder. A belief
that one of them is wrong is an amendment-gap report, not an edit.

## Current status

**Specification complete. No code.** As of Phase 0 (13 July 2026), the repository
contains the governance corpus, the architecture document, the build rules, and the
record-keeping scaffolding. No Rust, no Cargo workspace, no crates, and no build
artifacts exist yet. See `reports/READINESS-2026-07-13-R1.md`.

## Build order

BROKKR is built **spine first, executor last**, so no ungoverned execution path ever
exists in the tree, even transiently. No phase begins without explicit DAP approval of
the previous phase (CLAUDE.md Section 5).

| Phase | Crate / work |
|---|---|
| 0 | Readiness. Prove imports, normalize structure. Build nothing. |
| 1 | `brokkr-core` — governance types; invariants I-1…I-4; negative tests |
| 2 | `brokkr-crypto` — wolfCrypt FFI; ML-DSA, SLH-DSA, HMAC-SHA-384 |
| 3 | `brokkr-intent` (SKULD) — IPC, attenuation, invariants, freshness |
| 4 | `brokkr-gate` (SINDRI) — the costimulation gate; `AuthorizedAction` minting |
| 5 | `brokkr-genome` (REGIN) — tool registry, signing, privilege classes |
| 6 | `brokkr-barrier` (HÚÐ) — egress Deny, ingress Quarantine, custody records |
| 7 | `brokkr-audit` (SAGA) — signed append-only, re-signing, signed export |
| 8 | `brokkr-sentinel` (HEIMDALL) — reconciliation, tolerance controller |
| 9 | `brokkr-reasoner` (MÍMIR) + `brokkr-tools` — the untrusted proposer and tools |
| 10 | `brokkr-cli` — the orchestrator loop. The executor is wired **last**. |

## Governing principle for the builder

The model proposes; the DAP ratifies. The builder does not decide what BROKKR should
be, does not resolve ambiguity to stay unblocked, and does not relax a requirement to
make a build pass. When finishing the task conflicts with a rule in CLAUDE.md, the
task loses. See CLAUDE.md Section 10, "the hard list."
