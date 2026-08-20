# Phase 11.5 (brokkr-cli / Real Subsystem Integration) Report — R1

**Record ID:** PHASE-11.5-2026-08-20-R1
**Date:** 2026-08-20
**Crate:** `brokkr-cli` (integration-test addition — no new crate, no subsystem source change)
**Architecture:** BROKKR-ARCH Rev 1.17 §4/§5 (the governed action cycle)
**Author:** Claude Code (builder)
**Status:** Complete. Workspace GREEN. One tool ran through the full cycle with real PQC crypto and wrote a real file.

---

## 0. Step-0 buildability determination

Every real subsystem is constructible from committed constructors — no invention. Recorded exactly:

| Subsystem | Constructor (committed) | Notes |
|---|---|---|
| SINDRI | `Sindri::new(resolver: R, genome_resolver: G)` | `RegistryResolver::new().with_root(subject, ml_pub, slh_pub)` is the committed `KeyResolver`. **No committed `GenomeResolver` impl exists** → a declared one is built in the test file. |
| SAGA | `Saga::new(signer: DualKeyPair, generation: CryptoGeneration, genesis: Digest, tsa: Option<Box<dyn TimestampAuthority>>) -> Result<Self, SagaError>` | `append(&self, event, dap, at)` takes `&self` (interior `Mutex`). `records() -> Vec<AuditRecord>` for read-back. |
| HEIMDALL | `Heimdall::new(corpus: Box<dyn SelfSetCorpus>, dap_public: (Vec<u8>,Vec<u8>), signing: DualKeyPair, bound: f64, blast_radius: Option<u64>, sustained_threshold: u32)` | `register_detector` is separate; **no committed `SelfSetCorpus` impl** → a trivial empty one is built in the test. Empty detector set (task permits). |
| HÚÐ | `Huth::new(bcr_key: (Vec<u8>,Vec<u8>), dap_key: (Vec<u8>,Vec<u8>), ceiling: C, acceptances: A)` | `InMemoryCeiling::new()` + `InMemoryAcceptances::new()` are the committed seams. |
| Tool | `ToolExecutor` trait | **No committed filesystem tool** (`brokkr-tools` has only `NoOpTool`/`FixedResultTool`) → a filesystem tool is built in the test. |
| SKULD | `Skuld.sign_root(principal, dap, scope, invariants, nonce, expiry, &DualKeyPair) -> Result<RootIntent, IntentError>` | `Skuld` is a unit struct; real dual-family signature over canonical content. |
| Crypto | `DualKeyPair::generate() -> Result<Self, CryptoError>`, `.public_key_bytes() -> (Vec<u8>,Vec<u8>)`, `.sign_dual` | ML-DSA-65 + SLH-DSA-SHAKE-192s via wolfSSL. FFI key types carry `unsafe impl Send + Sync`, so `Saga`/`Heimdall`/`Huth` are `Send + Sync` and fit the orchestrator's `Box<dyn Trait: Send + Sync>` ports. |

**wolfSSL rpath** is configured in `.cargo/config.toml` (used by every prior real-crypto integration test).

**Test infrastructure built in the test file** (not production code, not a new crate, no subsystem source changed — all permitted by the task §5):
1. `DeclaredGenome` — a `HashMap<ToolId, ResolvedTool>` declaring `write_file` (requires capability `write`, `Privileged`). It implements **both** `GenomeResolver` (SINDRI's conjuncts 3/4) and the orchestrator's `GenomeCheck` port (step 4), so the two agree on what is declared. Fail-closed for undeclared tools.
2. `FsWriteTool` — implements `ToolExecutor`; writes the fixed content to the path in the authorized action's `detail`.
3. `EmptyCorpus` — a trivial `SelfSetCorpus` (not exercised: no detectors, and the orchestrator calls `observe`, never `screen`).
4. Three adapters: `SagaSink` (SAGA → `AuditSink`), `RecordingHeimdall` (real `Heimdall` → `Sentinel`, tapping the feed), `RecordingSignals` (`SignalRouter`).
5. Controlled doubles `ClearAll` (BIFRÖST — clears unconditionally) and `FixedProposer` (MÍMIR — one fixed proposal: write to the temp file).

## 1. What the test does

`brokkr-cli/tests/real_integration.rs`, one test `real_governed_hop_writes_a_file_with_real_pqc`:

1. Generates **four real dual-family key pairs** (principal, SAGA signer, HEIMDALL signer, HÚÐ keys) via wolfSSL.
2. Signs a **real Root Intent** with the principal key pair (`Skuld::sign_root`), scope `{write}`, no invariants, expiry well after `now`.
3. Builds a `RegistryResolver` declaring the principal's public key, and a `DeclaredGenome` declaring `write_file`.
4. Constructs **real SINDRI** (`Sindri::new(registry, DeclaredGenome::new())`).
5. Constructs **real SAGA** (`Saga::new(saga_kp, CryptoGeneration(1), genesis, None)`), wrapped in `Arc` so the test can read `records()` after the hop.
6. Constructs **real HEIMDALL** (`Heimdall::new(...)`, empty detector set), wrapped in `RecordingHeimdall`.
7. Constructs **real HÚÐ** (`Huth::new(...)`, `InMemoryCeiling`/`InMemoryAcceptances`).
8. Constructs the **real filesystem tool** (`FsWriteTool`) for a unique temp path (`std::env::temp_dir()/brokkr-test-<pid>.txt`, removed on drop).
9. Wires the `Orchestrator` — real everything except BIFRÖST/MÍMIR.
10. Calls `execute_hop` with the real identity, real chain, and the controlled proposal (write to the temp file), `now = 1000`.
11. **Asserts:** `HopResult::Executed` naming the path; the file exists on disk with content `hello from BROKKR`; SAGA recorded a `Proposal` and a **`Granted`** `Authorization` (the grant came from real SINDRI verifying the real signed chain); every SAGA record carries ≥1 real dual-family generation signature; real HEIMDALL received `Observation::Hop { executed: Some(..) }`.

**The grant is real, not stipulated.** The file is written only because real SINDRI verified the real dual-family Root-Intent signature against the declared public root (Signal 2), bound the identity to `root.principal` (Signal 1), confirmed `write ∈ scope` (conjunct 3), and found no invariant to violate (conjunct 4). A wrong key, an expired chain, an undeclared tool, or a missing capability would have produced `Anergy` and no file.

## 2. Verification (Section 6)

| Check | Result |
|---|---|
| `cargo build --workspace` | green |
| `cargo test --locked --workspace` | **204 passed, 0 failed** (203 prior + 1 new; real crypto) |
| `cargo test -p brokkr-cli --test real_integration` | **1 passed, 0 failed** — 19.4s (real PQC keygen + sign + verify) |
| the temp file was created during the test | asserted in-test (`read_to_string` == `hello from BROKKR`); removed on drop |
| `cargo clippy -p brokkr-cli --all-targets` | no warnings |
| `cargo clippy --workspace --all-targets` | no warnings |
| `cargo fmt --all -- --check` | clean |
| held-clock grep (`brokkr-cli/src`) | unchanged — only `Orchestrator::now()`; the test holds no clock (`now` passed to `execute_hop`) |
| no unsafe | none in `brokkr-cli` (only `#![forbid(unsafe_code)]`) |
| dependency direction | unchanged — `brokkr-cli` is still the leaf; no source change |

## 3. Invariants (unchanged, exercised with real components)

- **I-1** — the file was written only via a real `AuthorizedAction` minted by real SINDRI's `authorize`; the orchestrator constructs none.
- **I-12** — MÍMIR (double) is reached only through a `ClearedContext` from the BIFRÖST double's provided `clear`.
- **I-13** — `now` is the `execute_hop` parameter; no subsystem holds a clock.
- **OQGF-R-1 (dual PQC)** — SAGA dual-signs every appended record; the test asserts each carries a generation signature.

## 4. Honest limitations (named, not hidden)

- **BIFRÖST and MÍMIR are controlled doubles** — by design (no model endpoint / no mTLS client). Everything downstream of the proposal is real.
- **HÚÐ takes its Public short-circuit.** The action crossing is `Public` + `LocalPath` + no BCR, so egress **condition 1** allows before the ceiling/BCR/acceptance machinery is consulted. HÚÐ is real and constructed with real seams, but this Public local write does not exercise its custody-record path. Stated plainly.
- **HEIMDALL runs with an empty detector set** (the task permits this). Its `observe` loop runs over the real reconciliation feed, but no detector fires and no signal is raised — detection *content* is not exercised, only that the executed action reaches the real subsystem.
- **The genome is declared test data, not a signed REGIN genome.** REGIN exposes no committed per-hop surface (Phase 11 finding), so the `GenomeCheck` port and SINDRI's `GenomeResolver` are backed by the same in-test `HashMap`. Production backs them from the signed genome.
- **The attestation's `signatures` field is a real signature but is not verified by SINDRI** (Rev 1.3 §6.4 drops that check as redundant with Signal 2). Consistent with OQGF-M-1 recorded PARTIAL.
- **The HEIMDALL feed is asserted via a recording tap.** The committed `HeimdallSentinel` delegates without exposing the feed; `RecordingHeimdall` records the input **and runs the real `Heimdall::observe`**, so the real subsystem does the work while the assertion sees what it received.

## 5. What this does not build

No production BIFRÖST (mTLS client); no production MÍMIR (HTTP model client); no new crate; no change to any subsystem's source; no CLI wiring (`main.rs` unchanged); no architecture revision.

## 6. Commit

Single commit (`brokkr-cli` test addition + these records). The tree was clean at the start (Phase 11 committed at `a7046fa`), so this commits cleanly on top, builder work only, no spec change bundled.
