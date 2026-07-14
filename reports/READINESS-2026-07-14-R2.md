# BROKKR Re-Readiness Report — Phase 0.5 (Conformance)

**Report ID:** READINESS-2026-07-14-R2
**Phase:** 0.5 (Conformance)
**Date:** 14 July 2026
**Prepared by:** Claude Code (the builder)
**For:** Jeremy Rose, DAP
**Status:** Complete. **Build stopped** on eight ABSENT conformance findings (GAP-2026-07-14-001), pending DAP disposition. Not entering Phase 1.

> **No code was built.** No Rust, no Cargo, no crates, no dependencies, no installs.

---

## 1. Spec-version confirmation — I hold the new spec, not the old one

**Loaded now:** `CLAUDE.md` re-read from disk at **v1.2** (and drafted forward to **v1.3** in task 4, below); `docs/BROKKR-ARCH-2026-001.md` re-read at **Rev 1.1**. Both were read in full from disk this phase, not carried from the session-start import.

Proof by quotation of three things that did not exist in the previous versions:

- **Invariant I-8** (new in CLAUDE.md v1.2): *"An `EscalationType` cannot be constructed without a resolution path and a baseline posture — the fields are not optional, so an escalation with no way down is not a thing this code can express (OQGF-P-8.1: there are no one-way ratchets)."* And: *"Autonomous signals may raise posture. Nothing autonomous lowers it. Where the system is uncertain, it stays escalated."*

- **Invariant I-9** (new in v1.2): *"A `RefinedDetector` is `Heuristic` by construction. There is no path — no constructor, no conversion, no configuration — by which a learned artifact becomes, or modifies, a Deterministic Gate (OQGF-P-2)."* And: *"BROKKR can learn to see better. It cannot learn to see less."*

- **CLAUDE.md Section 5.3** (new — "The conformance check — mandatory at every phase"), which carries the two rules this phase is built on: *"Reading a requirement is not checking it. You can quote a requirement perfectly and still build straight past it."* and *"Zero findings is not a pass. A clean report may mean nothing was wrong, or it may mean nothing was looked at — and from the outside those are indistinguishable."* Section 5.3 records the specific Phase 0 failure it exists to prevent: the builder quoted OQGF-P-8.5 verbatim and reported zero gaps in the same document.

And to confirm the architecture is Rev 1.1, not Rev 1.0: §6.7 opens *"Rev 1.0 had no way down. HEIMDALL raised posture and nothing ever lowered it. That is a one-way ratchet, and OQGF-P-8.1 forbids it in exactly those words … EIR closes it."* Rev 1.1 adds the subsystems EIR (§6.7) and KVASIR (§6.8), the host-harm bound (§6.6), the declared conformance level (§1.4), and the CBOM/AIBOM in REGIN (§6.2) — none of which were in the Rev 1.0 I held at session start.

Imports are not stale. I hold the current spec.

---

## 2. Conformance check — summary

Full record: `conformance/CONF-2026-07-14-P0.5-R1.md`. Enumerated **85 numbered normative
requirements** from the corpus (`OQGF-1_0.md` + `AMD-001…007`), quoting each operative
`SHALL`, and tested `BROKKR-ARCH` Rev 1.1 against each. **Ground truth was the corpus; the
architecture was the subject; the architecture's own Section 13 table was not used as the
enumeration source** (that would be the circular audit Section 7 forbids).

**Counts by verdict: SPECIFIED 52 · PARTIAL 16 · ABSENT 8 · N.A. 9.**

The architecture is strong exactly where Rev 1.1 was revised to be: **the amendment layer
(AMD-001 through AMD-007) is 37 SPECIFIED / 6 PARTIAL / 0 ABSENT.** All eight ABSENT findings
are in **OQGF-1.0's Organ-level operational requirements**, with one shared root cause: the
architecture's applicability treatment (§1.4) declares `n.a.` only for the quantum-specific
requirements and leaves a set of non-quantum Organ requirements neither mapped nor declared.

### 2.1 ABSENT (8) — build-stopping. Filed as GAP-2026-07-14-001.

Each is neither specified with a BROKKR hook nor declared `n.a.`:

| ID | Missing |
|---|---|
| OQGF-G-7 | Mosca key-lifetime / rotation for BROKKR's signing keys |
| OQGF-I-1 | HNDL sentinel on outbound TLS |
| OQGF-I-2 | Classical-TLS-as-graded-risk on that channel |
| OQGF-I-5 | HNDL risk score per session/asset |
| OQGF-M-5 | Mutual authentication on the reasoner-API / network connections |
| OQGF-M-6 | Per-supplier (model-provider) trust score |
| OQGF-R-6 | Threshold/Shamir custody of long-lived signing keys |
| OQGF-A.6.1 | Quantum-and-AI-aware incident-response plan + annual tabletop |

Several are *plausibly* `n.a.` for a coding agent (the HNDL TLS-sentinel cluster; the IR
plan), but "plausibly n.a. and undeclared" is the silently-missing case Section 5.3 names,
and adopting that reading myself is the Section-4-forbidden move of choosing what unblocks
me. Disposition — declare `n.a.`, add a hook, or defer — is the DAP's, placed as an
architecture revision. Per-finding recommendations are in the gap report; I do not adopt
them.

### 2.2 PARTIAL (16) — not build-stopping; stated plainly

G-6 (FIPS posture stated, dated SHALL unresolved), G-8, G-9, I-4, M-1 (attestation HW-RoT
rooting), M-4, M-7, R-3, A-3 (dual-sign present, RFC 3161 TSA absent), A.6.2, P-7.2 (declared
coupling matrix in Organ 5), P-7.3, P-7.5, I-9/AMD-007 (BCR type not enumerated in
`brokkr-core`), I-12 (data-content sentinel surface), I-15 (bypass detector claimed in §13,
absent from §6.5 prose). Several are Phase-appropriate and will be re-checked at their
crate's conformance gate rather than assumed closed now.

---

## 3. Phase 2 crypto prerequisite — the finding (report only; nothing built or installed)

Requested command:

```
$ grep -c "SLH_DSA\|SLHDSA" /home/jerem/wolfssl/CMakeLists.txt
7
```

**The cmake build system exposes SLH-DSA. Phase 2 needs a cmake rebuild, not an autotools
rebuild.** Evidence:

- `CMakeLists.txt:837` — `add_option(WOLFSSL_SLHDSA "Enable the wolfSSL SLH-DSA implementation (default: disabled)")`; on enable it sets `-DWOLFSSL_HAVE_SLHDSA` / `-DWOLFSSL_WC_SLHDSA` (lines 843–848) and prints `Looking for WOLFSSL_SLHDSA - found` (line 850).
- `cmake/functions.cmake:226–227` sets `BUILD_WC_SLHDSA`, and `:1079–1080` appends `wolfcrypt/src/wc_slhdsa.c` to the library sources when it is set.
- `cmake/options.h.in:418–421` carries the `#cmakedefine WOLFSSL_HAVE_SLHDSA` / `WOLFSSL_WC_SLHDSA` hooks.
- `tests/api/test_slhdsa.c` is wired into the cmake test list (`CMakeLists.txt:2951`).

The autotools path (`configure.ac:1976`, `--enable-slhdsa`, six parameter sets) exists too,
but it is **not required**: the existing build is cmake, and cmake can turn SLH-DSA on. The
current shared library was simply built with the default (`WOLFSSL_SLHDSA` off), which is why
the Phase 0 symbol scan saw ML-DSA but no SLH-DSA symbols.

**Phase 2 action (for when Phase 2 is approved):** reconfigure the existing cmake build with
`-DWOLFSSL_SLHDSA=yes` (or `=ON`) and rebuild. No source change, no autotools migration, no
architecture conflict — consistent with BROKKR-ARCH §9 and CLAUDE.md §7. Version in use
remains wolfSSL v5.9.2-stable, stock non-FIPS; recording it as FIPS-validated would be a
false CBOM entry and is prohibited.

---

## 4. Task 4 — checkpoint-commit rule drafted; CLAUDE.md v1.3

Drafted the checkpoint-commit rule into CLAUDE.md **Section 5.2** and bumped the version
header to **v1.3** with a change-log entry. The rule: every approved checkpoint ends in a
commit; a phase is not complete until its artifacts are committed and pushed; builder work
and DAP-placed specification changes are separate commits, never mixed; and a revision to
CLAUDE.md or the architecture is committed before any work begins under it. It adds a
constraint and relaxes nothing, so it is a permitted add-only auto-draft under Section 4. I
operate under it from now. (It also corrects the Section 5.2 cross-reference to auto memory
from §12 to §11.)

**Consistent with that new rule, I have not committed.** The task frames the CLAUDE.md draft
as: *"the DAP reviews the diff and the commit is the ratification"* — and my standing
discipline is to commit only when asked, and to branch before committing to `main`. The
working tree is diff-ready for DAP review. Recommended closing structure once approved (two
separate commits, per the rule):

- **Commit A — builder work (Phase 0.5):** `conformance/`, `gaps/GAP-2026-07-14-001.md`,
  `reports/READINESS-2026-07-14-R2.md`, and the three `INDEX.md` updates.
- **Commit B — builder-authored governance draft:** `CLAUDE.md` v1.3 (the checkpoint-commit
  rule), kept separate so `git log` shows the rules change apart from the phase artifacts.

I am ready to run these on your word.

---

## 5. Gaps filed this phase

- **GAP-2026-07-14-001** (OPEN) — eight OQGF-1.0 Organ requirements neither specified nor
  declared `n.a.` in the architecture (G-7, I-1, I-2, I-5, M-5, M-6, R-6, A.6.1). Per
  Section 5.3, the build stops on ABSENT findings. Recommendation stated in the gap; not
  adopted.

---

## 6. Attestation

- The conformance check enumerated requirements from the governance corpus and audited the
  architecture against them; the architecture's Section 13 table was not the ground truth.
- This is not a zero-findings report; §14.3 of the conformance record states what was checked
  (85 numbered requirements) and against what (the two corpus files), and the depth limit
  (numbered-requirement granularity, not every atomized sub-clause `SHALL`).
- Eight ABSENT findings are filed as one consolidated gap; the build is **stopped** pending
  DAP disposition. I am **not** beginning Phase 1.
- Nothing under `governance/` was touched; `docs/BROKKR-ARCH-2026-001.md` was not edited.
- **No code was built. No dependencies were added. Nothing was installed.**

— End of re-readiness report.
