# Phase 8.5 Rebuild Report — PHASE-8.5-REBUILD-2026-08-18-R2

**Crate:** `brokkr-bifrost` (BIFRÖST)
**This is a rebuild of Phase 8.5, not a restart.** The original Phase 8.5 (`PHASE-8.5-2026-08-17-R1`,
built against ARCH Rev 1.14) stands as the design; this revision adopts the I-13 surface Rev 1.15
added and **removes the held clock** the original carried — the SINDRI defect a second time
(RISK-2026-0006). The record shows a correction, not a redo.
**Date:** 18 August 2026
**Scope:** `brokkr-bifrost` ONLY (plus the workspace `Cargo.toml`/`Cargo.lock` member entry, already
present). No `brokkr-core`, `-crypto`, `-intent`, `-gate`, `-genome`, `-barrier`, `-audit`,
`-sentinel`, `governance/`, `docs/`, or `CLAUDE.md`. Builder work, one commit, **not committed**
pending DAP review.

---

## Step 0 — grounding (before any edit)

Read CLAUDE.md §3 I-13 (v1.7); ARCH §6.6 (Rev 1.15 `ContextClearance` block), §6.10, §6.5;
`brokkr-core/src/reasoner.rs` (committed `evaluate_context(&self, ctx, dest, now)` +
sole-minter `clear`); `brokkr-gate/src/sindri.rs` (how SINDRI was corrected — delete the held field,
thread the call-site `now`); `brokkr-gate/tests/costimulation.rs` (the two-verdict pattern);
`brokkr-bifrost/src/lib.rs` and `tests/bifrost.rs`; `risks/REGISTER.md` RISK-2026-0006.

**brokkr-bifrost's held-clock constructs (before):** `use std::sync::Mutex`; field
`now: Mutex<Timestamp>`; `new(…, now: Timestamp)` + `now: Mutex::new(now)`; `set_now`, `now_guard`,
`now()`; and the read `self.now()` at the barrier call. **The 4 arity errors:** the lib
`evaluate_context(&self, ctx, dest)` (E0050, the one cargo shows before halting), plus in tests once
the lib compiles: 8× `evaluate_context(&ctx, &dest)` missing `now`, `clear(ctx, &dest)` missing
`now`, and `Bifrost::new(…, Timestamp(NOW))` now over-supplied.

**All tasks buildable against committed types — no gap for the bifrost work.** (A separate,
incidental finding surfaced in Task 4 — see below — and is filed as GAP-2026-08-18-001; it does not
block this deliverable.)

## Task 1 — remove the held clock

Deleted `use std::sync::Mutex`, the `now: Mutex<Timestamp>` field, `set_now`, `now_guard`, `now()`,
and the `now` parameter from `new`. **The endpoint-ceiling resolver and the acceptance seam stay** —
they are configuration. `evaluate_context` takes `now: Timestamp` per the trait and passes it to
`self.huth.evaluate(&flow, now)`; nothing reads a stored time.

**Interior mutability is gone (reported per Task 1).** Removing the `Mutex` left the struct as
`{ huth, ceiling }`, both owned and read through `&self`; **no interior mutability remains and none
is needed.** The struct doc now states this.

**CONFIRMED — the four-pattern held-clock grep on `brokkr-bifrost/src` is empty:** `self\.now`,
`now:.*Timestamp,` (field form), `Mutex<Timestamp>`, `fn now(` all return nothing. (A first pass had
two hits — in my *own doc prose* describing the removed defect, literally `Mutex<Timestamp>` and
`self.now()`. I reworded the prose to keep the history without the literal tokens, so the grep is a
clean signal and does not read as a live clock to a future auditor.) The only `now: Timestamp` in the
crate is the `evaluate_context` parameter — what I-13 requires.

## Task 2 — clear is not overridden

**CONFIRMED, re-verified:** no `fn clear` in `brokkr-bifrost/src` (BIFRÖST supplies only
`evaluate_context`; core's provided `clear` is the sole minter). The one `ClearedContext {`
occurrence is inside the `compile_fail,E0451` doctest that **proves** the construction cannot
compile — not a real construction. **I-12 is unchanged by this revision.**

## Task 3 — the two-verdict test, BIFRÖST's analogue

Added `test_oqgf_m_14_i13_i9_bcr_expiry_evaluated_against_call_time_not_a_held_clock`: one `Bifrost`
instance, one context and destination (a BCR expiring at 5_000, over a PQC channel so nothing else
denies), `clear` called twice — `now = 1_000` (< expiry) clears (mints a `ClearedContext`); `now =
10_000` (> expiry) Denies with the `Expired` condition. A held clock is one stored value and cannot
produce two verdicts from one instance, so this test cannot pass against the pre-I-13 design.

**Reviewed every existing test for the same flaw (reported).** All seven original tests constructed
`Bifrost::new(…, Timestamp(NOW))` — injecting the time at **construction** — and evaluated **once**.
Every one of them therefore shared the defect's assumption and **none could have detected the held
clock**; that is precisely why the two-verdict test is required and is not redundant with them. The
change to those seven: the injected-at-construction time became a **call-site** argument
(`Timestamp(NOW)` on each `evaluate_context`/`clear`), which is correct under I-13, but a
single-evaluation test cannot on its own catch a held clock — the detection is the new test's job.

## Task 4 — verification (run, not assumed)

- `cargo build --locked -p brokkr-bifrost`: clean. `cargo test --locked -p brokkr-bifrost`:
  **8 passed** (7 → 8, the two-verdict test) **+ 1 doctest**, 0 failed — real wolfSSL, real HÚÐ gate.
- **Whole workspace GREEN — the first green workspace since the I-13 core revision.**
  `cargo build --locked --workspace`: clean. `cargo test --locked --workspace`: **153 passed, 0
  failed** across all suites (every line `test result: ok`; no FAILED, no `error[`).
- `cargo clippy --locked -p brokkr-bifrost --all-targets`: clean (deny-list). `cargo fmt`: applied
  and clean. **I-5/I-6:** `cargo tree -e no-dev` = `{core, barrier, crypto (transitive)}` — no
  reasoner/tools/cli, no model call, no network, no `unsafe`. **No new external dependency.** The
  `Cargo.toml` member entry for `brokkr-bifrost` is already present.

**The RISK-2026-0006 closure grep — and what it found.** The four-pattern grep across **all** crates:
`self\.now`, `Mutex<Timestamp>`, `fn now(` are **empty workspace-wide**; `now:.*Timestamp,` matches
only I-13-compliant **function parameters** — **except two struct fields**: `EirState.now`
(`brokkr-sentinel/src/eir.rs:54`) and `HeimdallState.now` (`heimdall.rs:42`). **Both engines check an
expiry against the held clock** — EIR the resolution-decision expiry (`eir.rs:242`, OQGF-P-8.5),
HEIMDALL the tolerance-grant expiry (`heimdall.rs:268`, OQGF-P-4). **This is a third held clock, in
`brokkr-sentinel`, and it is a genuine I-13 violation** (verified by reading the code, not fixed —
sentinel is out of scope). It predates I-13 (sentinel is Phase 8; I-13 is Rev 1.15) and was never
reviewed against it because sentinel's `now` was never a trait parameter and so never broke a build.
Filed as **GAP-2026-08-18-001**.

## What survived from the original build, and what changed

**Survived, unchanged:** the entire design — the "one gate, one logic" delegation to HÚÐ; the
`CrossingRecord` value (§6.10 / I-13-recording material); the four structural facts (mTLS type-level,
mints nothing, no payload read, verifies-not-issues BCRs); `crossing_record`'s `min(endpoint,
channel)` effective-level logic; and six of the seven tests' meaning. **Changed:** the held clock is
gone (`Mutex<Timestamp>`, `set_now`, `now_guard`, `now()` deleted; no interior mutability); `now`
arrives per call on `evaluate_context`; the seven tests supply the time at the call; a two-verdict
freshness test was added; a `signed_bcr_expiring` helper (with an explicit expiry) was factored out
so `signed_bcr` delegates to it. **This is a correction of one defect in an otherwise-correct crate,
not a rebuild from scratch.**

## Task 5 — conformance

`conformance/CONF-2026-08-18-P8.5-R2.md`, **superseding** `CONF-2026-08-17-P8.5-R1` (annotated in
place per §8; the prior record audited a clock-holding crate against Rev 1.14). **0 absent for
`brokkr-bifrost`.** OQGF-M-14/I-9-expiry SATISFIED on the two-verdict test (forward move); M-5
unchanged (re-verified); I-10, P-11.1 satisfied for the crossing; I-12, I-5, I-6 hold; **I-13 holds
for this crate but not workspace-wide** (the sentinel finding, §5.3 backward note).

## Task 6 — risk register

RISK-2026-0006 UPDATE appended: **the BIFRÖST half is corrected** (this revision), and the SINDRI
half was corrected 18 Aug — but the risk is **NOT closed**, because its closure condition (empty
**workspace** grep) is unmet: GAP-2026-08-18-001 found a third held clock in `brokkr-sentinel`. The
closure this revision delivers covers the **BIFRÖST half only**. The two residuals are explicitly
**not** closed: no signature can prove an implementor forwards the time rather than storing one; and
the deeper residual (a conformance verdict recorded on a test that could not have failed) is
untreated — and now demonstrated a **third** time by the sentinel finding. `risks/INDEX.md` updated;
`gaps/INDEX.md` updated.

## Task 7 — records

This report; `CONF-2026-08-18-P8.5-R2.md` (+ annotation of R1); `tests/records/FUNC-2026-08-18-R3.md`;
`gaps/GAP-2026-08-18-001.md`; INDEX rows in reports/conformance/tests-records/gaps/risks. §8 dated
naming. **Auto-memory: unchanged** — the verification lesson (the four-pattern grep over-matches
`now:` parameters, so a held-clock audit must distinguish a struct field from a call parameter, and
`self.now` alone misses a `st.now` guard read) is a governance-verification technique for the
DAP-reviewed conformance/gap records, not the advisory layer (§11).

## What this revision does NOT do

- It does **not** touch `brokkr-sentinel` — the third held clock is filed (GAP-2026-08-18-001) and
  left for a DAP-placed revision, not fixed here.
- It does **not** close RISK-2026-0006 — the workspace grep is not empty.
- It does **not** touch any other crate, `governance/`, `docs/`, or `CLAUDE.md`.
- No governance interpretation was invented; the `now` parameter and I-13 are transcribed from ARCH
  Rev 1.15 and CLAUDE.md v1.7.

— End of Phase 8.5 rebuild report R2.
