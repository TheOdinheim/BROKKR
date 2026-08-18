# Phase 8.5 Report — brokkr-bifrost (BIFRÖST), the guarded crossing

**Report ID:** PHASE-8.5-2026-08-17-R1
**Phase:** 8.5 (`brokkr-bifrost` / BIFRÖST — the guarded crossing to a reasoner), BROKKR-ARCH §6.10 / §6.6
Rev 1.14, build rules v1.6
**Date:** 17 August 2026
**Builder:** Claude Code. **For ratification by:** Jeremy Rose, DAP.
**Status:** Complete; builds `--locked`; 7 tests + 1 compile_fail doctest pass with real crypto; clippy
clean (deny-list, all targets); fmt clean; no `unsafe`; I-5/I-6/I-12 hold; not committed (awaiting DAP
review).

---

## 1. Step-0 buildability determination — all six tasks buildable (done before writing code)

Read from disk: ARCH §6.10 (BIFRÖST), §6.6 (Rev 1.14 — what a crossing carries, where its BCR comes from),
§6.5's egress conditions; committed `brokkr-core` `reasoner.rs` (`Context` five fields, `ClearedContext`,
`ContextClearance`), `barrier.rs` (`BoundaryFlow::Egress`, `Destination::Reasoner`, `BarrierVerdict`,
`BarrierCondition`, the `Barrier` trait), `classification.rs` (`ChannelStrength::from_group`, `permits`,
`effective_authorization`), `genome.rs` (`ModelEndpoint`), `signal.rs`, `ids.rs`, `crypto.rs`; and
`brokkr-barrier` (`Huth`, `EndpointCeiling`, `AcceptanceResolver`, `InMemoryCeiling`, `InMemoryAcceptances`,
`canonical::bcr_signed_content`). **§6.10/§6.6 and the committed types agree; no STOP.**

**The committed seam, and the one thing §6.10's sketch does not reflect.** §6.10 sketches a `Bifrost` trait
with its own `clear(ctx, c, e)` that mints a `ClearedContext`. The **committed** seam is
`brokkr_core::reasoner::ContextClearance`: an implementor supplies `evaluate_context(&Context, &Destination)
-> BarrierVerdict`, and the **provided** `clear` is the **sole minter** of `ClearedContext` (I-12). Per Task
2, BIFRÖST implements `evaluate_context` and does **not** override `clear` or construct a `ClearedContext`.
The §6.10 sketch is the Rev 1.2 vision; the committed core is authoritative.

| Task | Buildable | Basis |
|---|---|---|
| 1 — the crossing's egress flow | Yes | every field comes from committed sources — `Context.{datum, classification, personal, bcr}` (Rev 1.14) and `Destination::Reasoner { endpoint, negotiated }`; none synthesized |
| 2 — clearing (`ContextClearance`) | Yes | implement `evaluate_context`; delegate to `Huth`'s `Barrier::evaluate`; do not override `clear` |
| 3 — the effective ceiling | Yes | HÚÐ's egress condition 8 computes it via HÚÐ's `EndpointCeiling`; `ChannelStrength::from_group`/`effective_authorization` are committed |
| 4 — mTLS structural (OQGF-M-5) | Yes | `ModelEndpoint::client_cert` is required (not `Option`) — a type-level guarantee; no runtime check |
| 5 — the crossing record | Yes | a value over committed types (`NamedGroup`, `ChannelStrength`, `Classification`, `ModelEndpointId`, `BarrierVerdict`) |
| 6 — the uncontrolled-channel lesson | Yes | reporting task; BIFRÖST is the enumerated controlled crossing |

**Real signatures confirmed before building:** `ContextClearance::{evaluate_context, clear(provided)}`;
`Huth::new(bcr_key: (Vec<u8>,Vec<u8>), dap_key, ceiling: C, acceptances: A)` and `Huth: Barrier` with
`evaluate(&BoundaryFlow, Timestamp) -> BarrierVerdict`; `EndpointCeiling::resolve(&ModelEndpointId) ->
Option<Classification>`; `ChannelStrength::{from_group(NamedGroup)->Self, permits()->Classification}`;
`effective_authorization(Classification, ChannelStrength) -> Classification`;
`brokkr_barrier::canonical::bcr_signed_content(&BoundaryCustodyRecord) -> Vec<u8>`;
`DualKeyPair::{generate, sign_dual, public_key_bytes}`.

## 2. The three Step-0 readings the prompt required — resolved and reported

**(a) How the negotiated `NamedGroup` and `now` reach `evaluate_context`.** `evaluate_context(&Context,
&Destination)` carries **no** channel or `now`. Both arrive without a wall-clock read or an assumed group:

- **The negotiated group rides on `dest`.** `Destination::Reasoner { endpoint, negotiated }` carries the
  negotiated `NamedGroup` (Rev 1.2 core). BIFRÖST reads it there; it does **not** read a socket. The group
  is an input, established by the (out-of-scope) handshake and passed in.
- **`now` is injected into BIFRÖST's state** (`Mutex<Timestamp>` + `set_now`), and passed to
  `huth.evaluate(&flow, now)`. Never a wall-clock read — determinism, the same discipline SINDRI/EIR use.

Neither requires reading a clock or defaulting a group → **no gap**.

**(b) Where BIFRÖST learns what was actually negotiated.** From `Destination::Reasoner.negotiated` — a
**fact carried on the destination**, agreed by the handshake and supplied by the caller (Phase 11 / the
out-of-scope TLS layer). §6.10 is explicit that this is what was *agreed*, never what was *offered*;
`ChannelStrength::from_group` maps only the negotiated group. The committed types provide the observation
point (the `Destination`), so there is **no gap** — BIFRÖST never defaults to a value.

**(c) Issue vs verify BCRs.** Phase 8.5 **verifies**, it does **not** issue. Issuance derives the authorized
destinations from REGIN's signed classification policy (§6.6) and is the assembling party's job (out of
scope; REGIN policy is a seam). BIFRÖST hands the context's BCR to HÚÐ, which verifies it (condition 4
signature, condition 2 presence, conditions 3/5/6/7). **A `Context` whose `bcr` is `None` above Public is
denied by HÚÐ's condition 2** (`MissingCustodyRecord`) — tested. So BIFRÖST issues nothing and there is no
gap.

## 3. Dependency determination and its justification

**BIFRÖST depends on `brokkr-core` and `brokkr-barrier` (direct); `brokkr-crypto` is transitive through
`brokkr-barrier`.** `cargo tree -e no-dev -p brokkr-bifrost` = `{brokkr-barrier → (brokkr-core,
brokkr-crypto), brokkr-core}`. This matches CLAUDE.md I-5 (*"brokkr-bifrost is a governance crate: it
depends on brokkr-crypto and brokkr-barrier"*) and ARCH §9, and honors I-5's forbidden list (no
`brokkr-reasoner`, `brokkr-tools`, or `brokkr-cli` — grep-confirmed).

**Why brokkr-barrier, not just the core `Barrier` trait.** Two things pull the dependency in: (1) *"one gate,
one logic"* (§6.6) means the egress decision is **HÚÐ's actual gate** (`Huth`), not a re-implementation — so
BIFRÖST holds a `Huth` and delegates; and (2) the crossing record's **effective ceiling** needs the
endpoint's declared ceiling, resolved through HÚÐ's `EndpointCeiling` seam. BIFRÖST holds a `Huth<C, A>` and
a **clone** of the same `EndpointCeiling` `C`, so the gate and the record read the **same ceiling data** and
cannot drift. `brokkr-crypto` is not a direct dependency — BIFRÖST signs and verifies nothing itself; HÚÐ
verifies BCRs, and SAGA (Phase 11) signs the crossing record. (The tests dev-depend on `brokkr-crypto` to
build valid signed BCRs.)

## 4. What was built, and the four structural confirmations

- **`Bifrost<C: EndpointCeiling + Clone, A: AcceptanceResolver>`** — holds `huth: Huth<C, A>`, a `ceiling: C`
  copy, and `now: Mutex<Timestamp>`. Implements `ContextClearance::evaluate_context`: builds the egress flow
  from `ctx.{datum, classification, personal, bcr}` + `dest`, then `self.huth.evaluate(&flow, now)`.
- **`CrossingRecord`** — a value carrying the negotiated group, the derived `ChannelStrength`, the endpoint,
  the effective ceiling (`min(endpoint ceiling, channel strength)`, resolved from BIFRÖST's ceiling copy),
  the declared classification, and the verdict. Produced by `crossing_record`; `None` for a non-reasoner
  destination.

**The four structural facts (Task 1/2/4/6), confirmed:**

- **Task 4 — mTLS is type-level, not a runtime check.** `ModelEndpoint::client_cert` is a required field in
  `brokkr-core/genome.rs`; an endpoint without a client certificate is **unrepresentable**, so it cannot be
  registered or reached. BIFRÖST adds **no** runtime mTLS check — there is nothing to check the type does not
  already forbid. *"Just use the public API with a bearer token"* is the absence of a constructor.
- **Task 2 — BIFRÖST mints nothing.** It implements `evaluate_context` (returns `BarrierVerdict`); it does
  not override the provided `clear` (core's sole `ClearedContext` minter, I-12). **Grep: no `ClearedContext`
  construction in `brokkr-bifrost/src`** (the only occurrence is a doc comment and a `compile_fail` doctest
  that *proves* it cannot be constructed — `E0451`).
- **Task 1/6 — BIFRÖST never reads `payload`.** Deriving classification from content is Heuristic
  (OQGF-I-12), and this is a deterministic path. **Grep: no code in `brokkr-bifrost/src` reads
  `Context::payload`** (the only occurrences are doc comments and a doctest that *sets* a payload while
  constructing a `Context`). Behaviourally confirmed by `test_no_payload_inspection` (two contexts differing
  only in payload → identical verdict).
- **Task 6 — the enumerated controlled crossing.** Rev 1.1's failure was the reasoner channel being an
  Uncontrolled Channel that *had not been recognized as a channel at all*. BIFRÖST is now the enumerated,
  controlled crossing: every reasoner-bound context is evaluated by the same deterministic gate as any other
  egress. **What remains uncontrolled is named, not hidden** (§6.10, §13): a context's *declared*
  classification can be wrong (no signature fixes a mis-declaration — the §6.6 residual), and the gateway
  deployment posture *relocates* M-5 rather than satisfying it (§6.10.1) — source code still leaves the
  operator's boundary if the gateway forwards to a public API. Neither is this crate's to close; both are
  recorded.

## 5. The central property, executed (Task 3)

`test_oqgf_m_5_classical_group_collapses_to_public`: an endpoint declared **Secret**, a handshake on a
**classical** group (`X25519`), an Internal context with an otherwise-valid signed BCR → **Deny
(ChannelStrengthCollapse)**. The effective level collapsed to Public regardless of the endpoint's ceiling.
`test_effective_is_min_not_endpoint`: a **Public**-ceiling endpoint over a strong PQC channel still caps at
Public — the channel does not *raise* the endpoint. `test_pqc_group_permits_declared_ceiling`: a Secret
context over a PQC-hybrid group at a Secret endpoint clears (`Allow`), and `bifrost.clear(...)` yields a
`ClearedContext` (via core's provided minter). **The record states the claim; the channel decides whether
the claim is reachable.**

## 6. I-5, I-6, I-12

- **I-5 — holds.** `cargo tree -e no-dev` = `{brokkr-core, brokkr-barrier, brokkr-crypto (transitive)}`; no
  `brokkr-reasoner`/`brokkr-tools`/`brokkr-cli`. The dependency direction is preserved (reasoner will depend
  on bifrost, never the reverse).
- **I-6 — holds.** BIFRÖST does not call a model; no network I/O, no FFI; `#![forbid(unsafe_code)]`. It
  *clears* a context so MÍMIR (Phase 10) may use one.
- **I-12 — holds.** BIFRÖST does not mint `ClearedContext`; the `compile_fail,E0451` doctest proves the type
  cannot be constructed, and BIFRÖST supplies only the `evaluate_context` half of core's `clear`.

## 7. Verification

- `cargo test --locked -p brokkr-bifrost` → **7 tests + 1 doctest pass**, real wolfSSL v5.9.2 (non-FIPS), no
  mocks — the tests exercise the **real HÚÐ gate** (not a mock barrier) with real signed BCRs
  (`tests/records/FUNC-2026-08-17-R2.md`).
- `cargo test --locked --workspace` → all crates green, **0 failures** (total in the test record).
- Clippy `--all-targets` (deny-list): 0. `--locked` build clean. `fmt` clean.

## 8. Conformance and risk

- `conformance/CONF-2026-08-17-P8.5-R1.md` (corpus-enumerated: AMD-001 M-5; AMD-007 I-9/I-10/I-12/I-13/
  I-14; AMD-009 P-11.1). **OQGF-M-5 satisfied** (mTLS structural + effective-ceiling collapse). **OQGF-I-10
  satisfied for the reasoner crossing** (the deterministic egress gate, delegated to HÚÐ, denies above the
  effective ceiling and without a BCR). **I-9 satisfied** (a BCR above Public is required and verified —
  HÚÐ). **I-12 confirmed** (declared classification; no payload inference). **I-13 PARTIAL** — the crossing
  record's *material* is produced; SAGA *recording* is Phase 11. **I-14** is `brokkr-barrier`'s register and
  is not duplicated here. **P-11.1** satisfied for the crossing (a Public personal context does not
  short-circuit). §6.10.1's gateway paragraph means M-5 can be **relocated** by a deployment choice — that
  is a deployment posture, not a change to this phase's verdict (the crate enforces the crossing that is made;
  what the operator points it at is the operator's classification policy). **0 absent.**
- **No risk-register change.** This phase builds the crossing; it introduces no new tracked risk and changes
  no existing one. The mis-declared-classification residual (§6.6/§13) and the gateway-relocation residual
  (§6.10.1) are existing named architecture residuals, not new risks. Per the instruction I say so rather
  than edit.

## 9. Auto-memory

No auto-memory change warranted. Nothing new about the environment/toolchain surfaced — a pure-logic crate
built and tested against the existing wolfSSL setup. Design facts (the seam over §6.10's sketch, the three
Step-0 readings, the dependency determination, the structural confirmations) live in this report and the
conformance check, not a self-note (§11).

## 10. Scope

- **New crate `brokkr-bifrost`:** `Cargo.toml`, `src/lib.rs`, `tests/bifrost.rs`. Workspace `Cargo.toml`
  gains `"brokkr-bifrost"`; `Cargo.lock` gains its entry.
- **No other crate modified.** `brokkr-core`, `brokkr-crypto`, `brokkr-intent`, `brokkr-gate`,
  `brokkr-genome`, `brokkr-barrier`, `brokkr-audit`, `brokkr-sentinel`, `governance/`, `docs/` untouched. Not
  committed. Phase 9 not started.

— End of Phase 8.5 report PHASE-8.5-2026-08-17-R1.
