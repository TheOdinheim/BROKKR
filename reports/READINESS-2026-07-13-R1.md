# BROKKR Readiness Report — Phase 0

**Report ID:** READINESS-2026-07-13-R1
**Phase:** 0 (Readiness)
**Date:** 13 July 2026
**Prepared by:** Claude Code (the builder)
**For:** Jeremy Rose, DAP — Odin's LLC
**Status:** Complete. Awaiting DAP approval to enter Phase 1.

> **No code was built.** No Rust, no Cargo workspace, no crates, no dependencies, no
> installs, and no build artifacts of any kind were produced in this phase. This report
> is a readiness attestation only.

---

## 1. Import proof

Every `@import` line in CLAUDE.md was resolved on disk, measured, and — the load-bearing
check — a requirement was quoted from deep inside each file to prove the contents are
actually held, not merely that a path resolves.

| # | Path | Exists | Lines | Words |
|---|---|---|---|---|
| 1 | `governance/OQGF-1_0.md` | yes | 864 | 8,909 |
| 2 | `governance/AMD-001-intent-binding.md` | yes | 323 | 2,398 |
| 3 | `governance/AMD-002-self-tolerance.md` | yes | 381 | 3,736 |
| 4 | `governance/AMD-003-adaptation.md` | yes | 223 | 1,927 |
| 5 | `governance/AMD-004-coordinated-signaling.md` | yes | 230 | 2,034 |
| 6 | `governance/AMD-005-resolution-homeostasis.md` | yes | 228 | 1,965 |
| 7 | `governance/AMD-006-accountable-risk-acceptance.md` | yes | 435 | 3,872 |
| 8 | `governance/AMD-007-barrier-data-custody.md` | yes | 247 | 4,595 |
| 9 | `docs/BROKKR-ARCH-2026-001.md` | yes | 401 | 5,353 |

### Deep-content quotes (one requirement per import)

1. **`OQGF-1_0.md` — OQGF-G-5** (Cryptographic agility): "Cryptographic agility SHALL be
   designed in from first commit: no algorithm identifier may be hard-coded; all
   algorithms SHALL be selected through a negotiation layer that supports at minimum one
   classical and one PQC alternative per primitive class."

2. **`AMD-001-intent-binding.md` — OQGF-M-11** (Costimulation Gate): "No actor SHALL be
   granted privileged action on the basis of identity attestation (Signal 1) alone. A
   privileged action SHALL require both a valid identity attestation per OQGF-M-1 and a
   valid Intent Provenance Chain per OQGF-M-8 (Signal 2)." An actor with valid identity but
   absent or invariant-violating intent provenance "SHALL be placed in architectural
   anergy: all privileged action denied."

3. **`AMD-002-self-tolerance.md` — OQGF-P-2** (Tolerance Scope / the innate-adaptive
   boundary): "Self-tolerance SHALL apply only to Heuristic Responses. It SHALL NOT apply
   to Deterministic Gates. No tolerance mechanism, suppression, exception, or operator
   action defined anywhere in OQGF SHALL cause a quantum-vulnerable artifact to pass the
   Genetic Layer gate (OQGF-G-4), nor an unattested actor to be admitted past MHC
   verification (OQGF-M-1)." This is the framework's load-bearing safety constraint.

4. **`AMD-003-adaptation.md` — OQGF-P-6.3** (Tolerance-Gated Activation): "No Refined
   Detector SHALL activate until it passes central-tolerance screening (OQGF-P-3) against
   the current Self Set. A refinement that improves detection but raises host harm above
   the declared bound SHALL be discarded regardless of its detection gains."

5. **`AMD-004-coordinated-signaling.md` — OQGF-P-7.4** (Raise-Only Autonomy): "An
   autonomous Signal MAY only raise defensive posture. Lowering posture (de-escalation)
   SHALL NOT be performed in response to a raw Signal and SHALL be governed by Resolution
   (OQGF-P-8)." A forged or replayed Signal therefore cannot stand the system down.

6. **`AMD-005-resolution-homeostasis.md` — OQGF-P-8.5** (Resolution Authority / Fail-Safe
   Asymmetry): "Autonomous action MAY raise posture (OQGF-P-7.4) but SHALL NOT autonomously
   de-escalate above Baseline. De-escalation above Baseline SHALL require the Resolution
   Path criteria to be met and DAP confirmation. Where the system is uncertain, it SHALL
   remain escalated."

7. **`AMD-006-accountable-risk-acceptance.md` — OQGF-P-9.4** (Boundary Against Tolerance):
   "A Risk-Acceptance Entry under OQGF-P-9 is not a Tolerance Grant under OQGF-P-4 and SHALL
   NOT be construed, recorded, or implemented as one. No mechanism SHALL permit a
   Risk-Acceptance Entry to be used to suppress (remove or hide) a finding, and no
   mechanism SHALL permit a Tolerance Grant to attach to a Deterministic Gate."

8. **`AMD-007-barrier-data-custody.md` — OQGF-I-10** (Egress Control — Deterministic,
   Fail-Closed): "Data of a declared classification above Public SHALL NOT cross a
   Controlled Boundary to a destination not authorized for that classification. ...
   Enforcement of a declared classification against an unauthorized destination is a
   Deterministic Gate under OQGF-P-2: it is fail-closed and non-suppressible, and no
   tolerance mechanism, exception, or operator action SHALL open it."

9. **`docs/BROKKR-ARCH-2026-001.md` — the governing principle and the `AuthorizedAction`
   encoding** (§2, §6.4): "The model proposes; the deterministic spine disposes. The
   reasoning model is never in the trust path for any decision to block, permit, raise, or
   lower posture." And the structural heart (invariant I-1): `AuthorizedAction` is "Produced
   ONLY by a successful SINDRI authorization. There is no public constructor. An action
   cannot be executed without one of these, and one of these cannot exist without having
   passed the gate."

All nine imports are present, measured, and quoted from depth. The corpus is held.

---

## 2. Context cost measurement

| Metric | 9 imports | + CLAUDE.md (240 ln / 2,506 wd) |
|---|---|---|
| Lines | 3,332 | 3,572 |
| Words | 34,789 | 37,295 |
| Est. tokens (words × 1.3) | ~45,226 | ~48,484 |

Against a 200,000-token context window, the imported corpus consumes roughly **23%**
(with CLAUDE.md, ~24%) before any work begins. That is a standing baseline present in
every session.

### Honest assessment and recommendation (not acted upon)

**Sustainable, but not free.** ~23% of the window on a fixed baseline is affordable for
the early phases, where the working set is small. The concern is the back half of the
build: Phases 8–10 carry substantial Rust across many crates, plus test output and
diffs, all competing with a corpus that never shrinks. A quarter of the window
permanently spoken-for is a real tax when the code context grows.

**Recommendation (a recommendation only — not acted upon):** Keep `CLAUDE.md` and
`docs/BROKKR-ARCH-2026-001.md` as always-on imports — they are the operative build
contract and are consulted constantly. Also keep `OQGF-1_0.md`, `AMD-001`, `AMD-002`,
`AMD-006`, and `AMD-007` always-on: these are load-bearing for Phases 1–7 (the spine,
the costimulation gate, the non-suppressible-gate constraint, risk acceptance, the
barrier). Consider moving `AMD-003` (Adaptation), `AMD-004` (Coordinated Signaling), and
`AMD-005` (Resolution) to **on-demand reading**: they govern HEIMDALL / the sentinel and
the physiology loop, which are Phase 8 work, and re-reading three files at that phase
costs little while returning ~6,000 words (~7,800 tokens) to the working budget for the
phases before it. This is the builder's honest read; the DAP decides whether to change
the import set, and CLAUDE.md is not edited to enact it without that decision.

---

## 3. Current repository tree

After Phase 0 structure normalization (governance and the architecture document
untouched):

```
BROKKR/
├── .gitattributes
├── .gitignore
├── CLAUDE.md                       # updated to v1.1 (added Section 11, auto-memory boundary)
├── README.md                       # NEW (Phase 0)
├── docs/
│   └── BROKKR-ARCH-2026-001.md     # untouched
├── governance/                     # untouched, read-only
│   ├── OQGF-1_0.md
│   ├── AMD-001-intent-binding.md
│   ├── AMD-002-self-tolerance.md
│   ├── AMD-003-adaptation.md
│   ├── AMD-004-coordinated-signaling.md
│   ├── AMD-005-resolution-homeostasis.md
│   ├── AMD-006-accountable-risk-acceptance.md
│   └── AMD-007-barrier-data-custody.md
├── reports/
│   ├── INDEX.md                    # NEW
│   └── READINESS-2026-07-13-R1.md  # NEW (this file)
├── gaps/
│   └── INDEX.md                    # NEW (no gaps filed)
├── audits/
│   └── INDEX.md                    # NEW
└── tests/
    └── records/
        └── INDEX.md                # NEW
```

Auto-memory scaffolding (outside the repository, outside git) was created under the new
Section 11 boundary and holds facts only:
`/home/jerem/.claude/projects/-home-jerem-BROKKR/memory/` (`MEMORY.md` +
`toolchain-and-wolfssl.md`).

---

## 4. Toolchain status (report only — nothing installed)

**Rust:** installed and on PATH.
- `rustc 1.94.1 (e408947bf 2026-03-25)`
- `cargo 1.94.1 (29ea6fb6a 2026-03-24)`
- Edition 2024 is available in this toolchain. No `rust-toolchain.toml` pin exists in the
  repository yet (a Phase 1 prerequisite).

**wolfSSL / wolfCrypt:** source present, not installed system-wide.
- Source tree: `/home/jerem/wolfssl`.
- A built shared library exists: `/home/jerem/wolfssl/build/libwolfssl.so.45.0.0`
  (`.so` and `.so.45` symlinks alongside it), built via cmake (no autotools
  `config.status`).
- **Not installed for consumption:** no `/usr/include/wolfssl` headers, and
  `pkg-config --exists wolfssl` fails. An FFI crate (`brokkr-crypto`, Phase 2) would need
  headers and a discoverable library, which are not yet in place.
- **PQC symbol check (honest, from the built `.so`):** ML-DSA is present
  (`wc_MlDsaKey_Init`, `wc_MlDsaKey_MakeKey`, `wc_MlDsaKey_Sign`-family,
  `mldsa_get_oid_sum`, etc.). **SLH-DSA / SPHINCS+ symbols did not appear** in this build.
  The architecture requires ML-DSA **and** SLH-DSA (`brokkr-crypto`, Phase 2), so this
  build likely needs SLH-DSA enabled and rebuilt before Phase 2. Reported, not acted upon.
  Per the FFI honesty rule, no algorithm identity is asserted here beyond what the exported
  symbols show.

---

## 5. What Phase 1 needs that does not yet exist

Phase 1 builds `brokkr-core` (governance types; invariants I-1…I-4 encoded; negative
tests). None of the following exist yet; all are Phase 1 work, to be built only after DAP
approval:

- **Workspace scaffolding:** a workspace `Cargo.toml`; `rust-toolchain.toml` pinning the
  toolchain; a committed `Cargo.lock`; `.cargo/` config for `--locked` reproducible builds.
- **The `brokkr-core` crate itself:** the re-implemented OQGF governance types named in
  the architecture (`ResponseClass`, `IntentProvenanceChain`, `CostimulationGate`,
  `AuthorizedAction`, `BarrierVerdict`, `Signal`, plus agent types `Proposal`,
  `ToolGenome`, `Reasoner` trait), `no_std + alloc` where feasible.
- **Structural encoding of invariants I-1…I-4** at the type level in core:
  - I-1 — `AuthorizedAction` has no public constructor.
  - I-2 — no `Deny → Allow` conversion of any kind.
  - I-3 — `IntentChain::attenuate` returns `Err(WouldBroaden)`; no widening path.
  - I-4 — `ToleranceController::grant` returns `Err(NonSuppressibleGate)` on a
    `Deterministic` target.
- **The negative tests** carrying invariant IDs in their names (the load-bearing tests),
  e.g. `test_i1_*`, `test_i2_*`, `test_i3_attenuate_rejects_broadening`,
  `test_i4_*` / `test_oqgf_p_2_*`.
- **Lint and safety discipline wired in:** `#![forbid(unsafe_code)]` in `brokkr-core`;
  `clippy::unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `todo`,
  `unimplemented`, `unreachable` set to `deny`.
- **Supply-chain config (may land with Phase 1 or its CI):** `deny.toml`, `cargo-audit`
  config; `cargo-vet` setup. No dependency will be added without asking the DAP first.

Note on Phase ordering: I-1 references `CostimulationGate::authorize` (the concrete gate
is Phase 4) and I-2 references the barrier (Phase 6). In Phase 1 these are encoded as
**type-level guarantees in core** — the private constructor and the absence of any
widening/relaxing conversion — so the structural property holds from Phase 1 forward and
the later phases supply the concrete minting/gate logic. This is consistent with the
architecture (§6, §8) and is not a framework gap.

---

## 6. Amendment gaps encountered

**None.** No situation in Phase 0 required a rule the framework does not supply. The
one action that touched a governance-adjacent surface — adding the auto-memory boundary
to CLAUDE.md — was explicitly pre-authorized as a permitted, add-only auto-draft under
Section 4 (it adds a constraint and relaxes nothing), and CLAUDE.md is neither under
`governance/` nor the architecture document. The `gaps/INDEX.md` table is therefore empty.

The SLH-DSA symbol absence (Section 4 above) is an environment/toolchain fact and a
Phase 2 prerequisite, not an amendment gap; it is recorded as a fact, not filed under
`gaps/`.

---

## 7. Attestation

- All nine imports are present on disk, measured, and quoted from depth (Section 1).
- The record-keeping scaffolding required by CLAUDE.md Section 8 exists (Section 3).
- CLAUDE.md was updated to v1.1 with the auto-memory boundary (Section 11); nothing under
  `governance/` was created, edited, moved, renamed, or reformatted, and
  `docs/BROKKR-ARCH-2026-001.md` was not edited.
- **No code was built. No dependencies were added. Nothing was installed.**
- The build has stopped at the Phase 0 checkpoint and is waiting for explicit DAP approval
  before any Phase 1 work begins.

— End of readiness report.
