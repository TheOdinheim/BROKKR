# Comprehensive Security Review — Final (Post-Campaign) — R1

**Record ID:** SECURITY-REVIEW-2026-09-02-R1
**Date:** 2026-09-02
**Type:** Read-only whole-workspace security audit. The final review after the 16-phase red-team campaign (F-1…F-38), four hardening passes (13/14/15/16-FIX), and three amendment implementations (AMD-010, AMD-011, Organ 5). Workspace GREEN 408/0.
**Method:** every source file in the audit scope read and each claim verified against real file:line. No code changed.
**Author:** Claude Code (builder / auditor)

---

## 1. Verdict

**0 CRITICAL, 0 HIGH, 0 new authorization bypass, 0 memory-safety defect, 0 forgeable authority.** The structural guarantees proven across the campaign hold under a fresh read. Two **new low-severity observations** (A-1 LOW, A-2 INFO), both in the `unsafe` FFI layer, neither exploitable today. The known architectural trust boundaries (M-3, F-30, F-32, F-23, F-31, F-37, F-38) are **reaffirmed, not re-litigated** — each was documented in a prior record and none is a code defect.

| # | Focus area | Result |
|---|---|---|
| 1 | Memory safety (`brokkr-crypto/{ffi,tls}.rs`) | Sound — buffers over-allocated past probed `sizeof`, sign buffers dynamically sized + truncated, all `_New` null-checked, Drop once-per-type. **A-1 (LOW)**, **A-2 (INFO)** |
| 2 | Authorization (`execute_hop`) | Sound — `AuthorizedAction`/`ClearedContext` unforgeable (private `mint`); kill/egress/guards/gates all fail-closed. Residual F-32 (accepted) |
| 3 | FFI boundary | Sound — signatures matched to wolfSSL 5.9.2 headers, every return `check()`ed, null-checked. Documented `SignCtx`/`VerifyCtx` deviation is not a defect |
| 4 | Audit integrity (SAGA) | Sound within its boundary — chain + signature both cover signed content incl. provenance; key behind Mutex, no decrypt exposed. M-3 / F-30 reaffirmed |
| 5 | Parser (`parse_action`) | Sound — strict, first-pair-wins (F-16), fail-closed to `unknown`; the `Action` carries no authority |
| 6 | Intent chain | Sound — freshness → root-sig → hash-link → subset → entry-sig, re-verified on reconstruction |
| 7 | Dependency direction | **Satisfied** — all 10 governance crates clean of reasoner/tools/cli |
| 8 | Crate boundary | **Satisfied** — `#![forbid(unsafe_code)]` everywhere except `brokkr-crypto` (per-module forbid; `unsafe` only in `ffi.rs`/`tls.rs`) |
| 9 | AMD-011 surfaces | Sound — envelope hard-validates (F-33), KillSwitch latch (F-36), egress host+port+protocol (F-34), normalization (F-35), trajectory every hop. Residuals F-37/F-38 (accepted) |
| 10 | Organ 5 provenance | **Satisfied** — every SAGA write path carries provenance; evidence gap on failure. Residual F-23 (accepted) |

---

## 2. Findings

### A-1 (LOW) — `MlKem768` post-`destroy()` methods pass a null pointer to wolfCrypt

**File:** `brokkr-crypto/src/ffi.rs:610` (`ciphertext_size`), `:616` (`shared_secret_size`), `:623` (`encapsulate`).
**What it is.** `destroy()` (`:651`) sets `self.ptr = null_mut()` and `destroyed = true`. `decapsulate()` (`:635`) guards `if self.destroyed { return Err(-99) }` before using the pointer — but `encapsulate`, `ciphertext_size`, and `shared_secret_size` **do not**. After a `destroy()`, a subsequent call to any of the three (both take `&self`, so the call sequence `k.destroy(); k.encapsulate();` is expressible through the safe API) passes the null `self.ptr` to `wc_MlKemKey_CipherTextSize` / `wc_MlKemKey_Encapsulate`. Each of those `SAFETY:` comments asserts "self.ptr live", which is false in that case.
**What it enables.** **No UB in practice:** wolfCrypt's `wc_MlKemKey_*` functions null-check their key argument and return `BAD_FUNC_ARG`, surfaced here as `Err`. So the finding is a **defense-in-depth / invariant asymmetry**, not an exploitable dereference: the null-pointer safety rests on wolfCrypt's guard rather than on a Rust check, and the `SAFETY:` invariant is stated incorrectly for the post-destroy case. It is also not reachable in BROKKR's own flow (a shredded key is dropped, not re-encapsulated); the exposure is to a future caller of the `pub` API.
**Recommendation (not fixed — audit, not a fix pass).** Guard `destroyed` in `encapsulate`/`ciphertext_size`/`shared_secret_size` symmetrically with `decapsulate` (return `Err`), and correct the three `SAFETY:` notes. A one-line guard each; no behavioural change for correct callers.

### A-2 (INFO) — `as Word32` truncation on >4 GiB slice lengths (unreachable)

**File:** `brokkr-crypto/src/ffi.rs` — `msg.len() as Word32` / `buf.len() as Word32` / `aad.len() as Word32` (e.g. `:244`, `:269`, `:421`, `:529`), and `tls.rs` `sz as c_int` (bounded by `.min(c_int::MAX)` at `:271`).
**What it is.** A slice longer than `u32::MAX` (4 GiB) passed to a wolfCrypt call would have its length truncated. **This is a correctness issue, not a memory-safety one:** a truncated length makes wolfCrypt read/hash/sign/fill *fewer* bytes than the slice holds — the pointer remains valid for the whole slice, so there is no out-of-bounds access.
**What it enables.** Nothing reachable. Every input to these paths is bounded far below 4 GiB upstream — the F-3 1 MiB `Action.detail` cap, the F-19 10 MiB `MAX_RESPONSE_BYTES` TLS bound, and 48/1952/16224-byte key/sig sizes. `tls.rs` already `.min(c_int::MAX)`-clamps its write length (`:271`). Recorded for completeness; no action needed.

---

## 3. Per-area detail (evidence)

### 1 & 3 — Memory safety and the FFI boundary

- **Buffer sizes vs probed `sizeof`** (`ffi.rs:73-78`): `SlhDsaKeyBuf`=1024 ≥ 984, `Sha384Buf`=256 ≥ 224, `AesBuf`=896 ≥ 848, all `align(16)`. Opaque library-allocated types (`WcMlDsaKey`, `WcMlKemKey`, `WcRng`) used only behind pointers — no size assumption.
- **NIST sizes** (`ffi.rs:44-55`): ML-DSA-65 sig 3309, pub 1952; SLH-DSA-SHAKE-192s sig 16224 (the `s` set, not the `f` set's 35664 — F-18), pub 48; SHA-384 48. Keygen cross-checks `sig_size()` against the constant (`:396`, `:504`) — a mis-parameterized key fails at generation.
- **Sign buffers** are `vec![0u8; self.sig_size()?]` then `truncate(sig_len)` (`:410/427`, `:519/536`) — sized by the library, no fixed-size overflow.
- **Null handling:** every `_New`/`_new`/method/`connect`/`new` return is null-checked (`ffi.rs:233,386,597,691`; `tls.rs:185,189,217,256`).
- **Drop:** each key type frees exactly once (`ffi.rs:248,466,571,664,729,788`); `MlKem768::destroy` is idempotent and nulls the handle so Drop cannot double-free (`:651-661`). `TlsClient` frees ssl-then-ctx once, `TcpStream` closes the fd last (`tls.rs:339-347`); error paths free via `free_ctx_err`/`free_ssl_ctx_err` before any `TlsClient` exists, so Drop never double-frees.
- **Reads/writes:** `write_all` uses `.get(off..)` and `.min(c_int::MAX)` (`tls.rs:267-277`); `read_until_close` uses `buf.get(..n)` and enforces the 10 MiB bound (`tls.rs:298-305`) — no indexing panic, no OOB.
- **mTLS:** CA load + client cert + client key (`tls.rs:198-208`); server verification is wolfSSL's client default with CAs loaded — consistent with the Phase-12 M-5 conformance record (reaffirmed, not re-audited here).

### 2 & 9 — Authorization and the AMD-011 surfaces (`brokkr-cli/src/lib.rs`, `brokkr-core`)

- **Unforgeable authority:** `AuthorizedAction` has one private field and a **private** `mint` (`gate.rs:113-120`); `ClearedContext` likewise (`reasoner.rs:106-114`). `Granted` wraps an `AuthorizedAction` external code cannot build. Confirmed by the co-located `E0624` compile-fail doctests.
- **`execute_hop` gate order** (`run_hop`): kill-switch latch (before every gate) → deterministic default-deny egress → driver guards (rate/monotonic/replay) → BIFRÖST clear → reasoner propose → REGIN genome check → SINDRI costimulation (mints the token) → HÚÐ barrier → tool. Any denial short-circuits with a recorded trajectory + audit.
- **Kill switch (F-36 fixed):** `KillSwitch` is a latch — only `kill()`/`is_killed()`/`handle()`, no unset, `Release`/`Acquire` hardcoded (`lib.rs`, the `KillSwitch` type). The model has no channel to it.
- **Egress (F-34/F-35 fixed):** `check_egress` matches host (normalized `localhost`/`127.0.0.1`/`::1`) **and** port **and** protocol against the signed manifest; any mismatch denies; no manifest → no-op.
- **Envelope (F-33 fixed):** `CapabilityEnvelope::permissive()` ends with a hard `assert!(validate().is_ok())` (`capability.rs`).
- **Accepted residual F-32:** `with_envelope` does not validate a *caller-supplied* envelope — a documented caller-contract, referred to the DAP (`CONF-2026-09-01-P16FIX-R2`).

### 4 & 10 — SAGA and Organ 5 provenance (`brokkr-audit`, `brokkr-cli`)

- **Chain + signature both cover signed content, which includes provenance:** `append_with_provenance` sets `prev = hash(record_signed_content(last))` (`saga.rs:245`) and signs `record_signed_content(record)` (`:263-266`); `record_signed_content` encodes `seq,prev,at,dap,event,provenance` (`canonical.rs`, `write_provenance`). So a non-key-holder cannot alter a record — including *how it claims it was captured* — without breaking both the chain and the signature.
- **Every recording path carries provenance:** the orchestrator makes **five** `record_with_provenance` calls (`lib.rs:546,588,704,777,793`) and **zero** bare `record()` calls — verified by grep. `record_trajectory` writes `evidence_gap: Some(..)` and `observed_coverage: "partial_hop"` on an errored hop.
- **Signing key protection:** `Saga` holds the keypair behind a `Mutex` and is handed only a `&DualKeyPair` exposing `sign_dual`/`verify_dual`/`public_key_bytes` — **no decrypt** (`saga.rs:12-13,141`).
- **Reaffirmed boundaries (not new):** **M-3** — the chain and signature both cover *signed content*, so a party holding the signing key can modify a record and re-sign undetected (integrity ⇐ key custody, `SECURITY-REVIEW-2026-08-30-R1`). **F-30** — end-truncation of the chain is undetectable without an external witness. Both are architectural, previously filed.

### 5 — Parser (`brokkr-reasoner/src/ollama.rs`)

- `parse_action` (`:209-233`): strict `TOOL:`/`PATH:` (case-insensitive), **first-pair-wins** via `get_or_insert_with` (F-16, `:217-220`), no lenient prose-mining (F-6), empty/absent → `unknown` (`:224-226`) which the genome denies. `json_string_field` uses `.get()` throughout and returns `None` on a truncated escape/unterminated string (F-17, `:170,198`). **The parser is not a trust boundary:** any `Action` it emits is fully governed by SINDRI (declared/in-scope/invariant) and HÚÐ — a crafted response cannot manufacture *authority*, only a proposal the gate then denies.

### 6 — Intent chain (`brokkr-intent/src/skuld.rs`)

- `verify_chain_with` (`:132-178`): (1) freshness `now > root.expiry` → `Expired`; (2) root signature over `root_signed_content`; per hop (3a) hash-link `received_digest == digest(prior_full)` else `BrokenLink`, (3b) `emitted_scope.is_subset_of(prior_scope)` else `WouldBroaden` — **re-verified on reconstruction, not trusted from the emitter** (I-3), (3c) entry signature under the hop key, `HopKeyMissing` fail-closed if absent. `now` is a parameter (I-13). Forge needs a private key; broaden is refused; replay within expiry is bounded by the orchestrator's nonce ledger (13-FIX F-1 / F-29), by design a separate control.

### 7 & 8 — Dependency direction and crate boundary

- **#7:** `[dependencies]` of all 10 governance crates (`brokkr-core/crypto/bifrost/genome/intent/gate/barrier/sentinel/adapt/audit`) contain **no** `brokkr-reasoner`/`tools`/`cli` (per-crate `awk` over the dependencies section — clean). I-5 holds; also CI-enforced.
- **#8:** all 12 non-crypto crates carry `#![forbid(unsafe_code)]`; `brokkr-crypto` forbids per-module (`hash.rs`/`sign.rs`/`shred.rs`) and confines `unsafe` to `ffi.rs` + `tls.rs` only (grep-verified). `brokkr-tools`/`brokkr-audit` "unsafe" hits are comments/doctests demonstrating the forbid.

---

## 4. Reaffirmed trust boundaries (previously filed; no new action)

None is a code defect; each is an architectural residual already recorded and, where relevant, referred to the DAP:

- **M-3** — SAGA integrity ⇐ signing-key custody (`SECURITY-REVIEW-2026-08-30-R1`, `SECURITY-BOUNDARIES-2026-08-30-R1`).
- **F-30** — SAGA end-truncation ⇐ external witness (in-memory today).
- **F-31** — content-blind audit: the action is recorded, the tool's content is not.
- **F-32** — `with_envelope` does not validate a caller-supplied envelope (referred to the DAP, `CONF-2026-09-01-P16FIX-R2`).
- **F-23** — the orchestrator is the evidence sensor (in the TCB); stated honestly in `sensor_id`, not hidden (`SECURITY-BOUNDARIES-2026-09-01-R1`).
- **F-37** — the kill switch is a pre-hop check, not a mid-hop abort (by design).
- **F-38** — the trajectory is in-memory; durable reconstruction rests on the SAGA event stream.

## 5. Scope note

This is a read-only review; no code was changed and no test was added. A-1 is a genuine (low) defense-in-depth gap in the `unsafe` layer and is the one item worth a follow-up fix at the DAP's direction; A-2 is informational. The workspace stands at 408 tests / 0 failures from `48dff41`.
