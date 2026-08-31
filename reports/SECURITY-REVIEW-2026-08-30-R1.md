# Security Review — Full-Codebase Audit (Claude Code /security-review)

**Record ID:** SECURITY-REVIEW-2026-08-30-R1
**Date:** 2026-08-30
**Type:** Read-only security audit of the entire workspace (no code changed). Run after the complete red-team campaign (Phases 13A–15C + three FIX passes; 368 tests; findings F-1 … F-31).
**Method:** Every finding was verified against source before disposition, per CLAUDE.md §7 (a summary is not evidence — each disposition points at a line the reviewer can open). Confidence-scored; only findings surviving source verification are recorded.
**Author:** Claude Code (reviewer)
**Result:** **5 findings. 4 false positives** (each refuted by an existing control, cited below). **1 real finding, M-3, which is an architectural trust boundary, not a code defect** — documented as such in `reports/SECURITY-BOUNDARIES-2026-08-30-R1.md` alongside F-30.

---

## 0. Summary

| ID | Claim | Disposition | Evidence |
|---|---|---|---|
| **M-1** | ML-KEM/ML-DSA `_New` return not null-checked → deref of NULL | **FALSE POSITIVE** | the null check exists at every `_New` site |
| **M-2** | Signature buffer undersized → overflow when the library writes the signature | **FALSE POSITIVE** | the buffer is runtime-sized from `sig_size()` |
| **M-3** | SAGA's hash chain does not cover the signature → a key-holding insider can modify + re-sign a record undetected | **REAL — architectural trust boundary** | `saga.rs:216,233` (chain links over signed content only) |
| **M-4** | `read_until_close` is unbounded → memory exhaustion | **FALSE POSITIVE** | `MAX_RESPONSE_BYTES` is enforced in the read loop |
| **I-1** | FFI struct layout mismatch (missing `repr(C)`) → UB | **FALSE POSITIVE** | all opaque/byte-buffer FFI structs are `#[repr(C)]` |

**No CRITICAL or HIGH.** The type-system security spine (I-1 `AuthorizedAction`, I-12 `ClearedContext`, dual-family chain crypto, SAGA integrity, `#![forbid(unsafe_code)]` confinement, one-way dependency graph) is sound; this was independently confirmed by the campaign (14A structural, 15A conjuncts, 14C memory safety) and re-verified here.

---

## 1. The four false positives (refuted against source)

### M-1 — "null check missing on the FFI key constructors"
**Refuted.** Every wolfCrypt/wolfSSL `_New`/`_new`/`_CTX_new` return is null-checked before use, and on failure the wrapper returns an error without dereferencing:
- `brokkr-crypto/src/ffi.rs:233` (`Rng::new`), `:386` (`MlDsa65::generate`), `:597` (`MlKem768::generate`), `:691` (`MlDsa65Public::from_public_bytes`).
- `brokkr-crypto/src/tls.rs:185` (`method`), `:189` (`ctx`), `:217` (`ssl`), `:256` (`get_curve_name` result).

A NULL from the library becomes `Err(-1)` / `TlsError::Context`, never a dereference. No defect.

### M-2 — "signature buffer overflow: the library writes a signature larger than the buffer"
**Refuted.** The signature buffer is allocated to the library's own reported size at runtime, not a fixed constant, and the length is passed to the library so it writes ≤ capacity:
- `brokkr-crypto/src/ffi.rs:410` — `let mut sig = vec![0u8; self.sig_size()?];` (ML-DSA), `:519` (SLH-DSA), where `sig_size()` queries `wc_MlDsaKey_SigSize` / `wc_SlhDsaKey_SigSize`.
- `sig_len` is passed as the capacity and updated to the actual length; `sig.truncate(sig_len as usize)` only ever shrinks (a misbehaving larger value would be a no-op, not an OOB).

The `SLHDSA192S_SIG_SIZE`/`MLDSA65_SIG_SIZE` constants are used only as a keygen *cross-check* (F-18), never to size a write buffer. No overflow path.

### M-4 — "read_until_close is unbounded → OOM"
**Refuted.** The accumulation is bounded and aborts past the cap:
- `brokkr-crypto/src/tls.rs:140` — `pub const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;`
- `:303-305` — inside the read loop, `if out.len() > MAX_RESPONSE_BYTES { return Err(TlsError::ResponseTooLarge); }`.

This is the F-19 fix, and it is wired into the live loop (not just declared). No unbounded read. (Resource exhaustion is out of the review's severity scope regardless.)

### I-1 — "FFI struct layout mismatch (missing repr(C)) → UB"
**Refuted.** Every FFI-facing struct carries an explicit C layout:
- Opaque handles `WcMlDsaKey`/`WcMlKemKey`/`WcRng` and `WolfsslMethod`/`WolfsslCtx`/`Wolfssl` are `#[repr(C)]` with a zero-length `_private` field (used only behind a pointer).
- Byte-buffer structs for constructor-less library types are `#[repr(C, align(16))]`: `SlhDsaKeyBuf`, `Sha384Buf`, `AesBuf` — over-allocated past the probed `sizeof()` and 16-byte aligned.
- Counts: `grep -c 'repr(C'` = 6 in `ffi.rs`, 3 in `tls.rs`.

Raw FFI types never escape their module. No layout-mismatch UB.

---

## 2. The one real finding — M-3 (architectural, not a code defect)

### M-3 — SAGA's hash chain covers the signed content, not the signature; a key-holding insider can rewrite records
* **Severity:** trust boundary (not CRITICAL/HIGH/MEDIUM as a *code defect* — it is a property of the design, deliberately chosen).
* **Location:** `brokkr-audit/src/saga.rs:216` (`prev = Sha384Hasher.hash(&canonical::record_signed_content(last))`) and `:233` (`signed = canonical::record_signed_content(&record)`); `canonical::record_signed_content` covers `(seq, prev, at, dap, event)` and **excludes** `signatures` (built empty at `:227`, pushed at `:238` *after* signing).
* **What it is.** The hash chain and the signature protect **different** things:
  - the **hash chain** (`prev` links) protects **ordering and completeness** — it detects a non-key-holder's edits, reorderings, and middle-deletions (`verify_chain`, `saga.rs:268-298`, `ChainStatus::Broken`);
  - the **dual-family signature** protects **authorship** — forging a record without the signing key requires breaking ML-DSA-65 *and* SLH-DSA-SHAKE-192s.

  Because the chain links over signed content only, it does not add a **key-independent** integrity layer. An insider **who holds the signing key** can modify a record's `event`, re-sign it (the signature verifies, since they hold the key), and — for any record with successors — recompute the forward `prev` links and re-sign the suffix. `verify_chain` then returns `Intact`. For the tail record, no forward rewrite is even needed.
* **Why the chain-links-over-signed-content design is nonetheless correct.** This is the Rev 1.10 decision (`saga.rs` module note): if the chain covered the signature, then OQGF-A-6 **re-signing** (appending a `GenerationSignature`) or any post-seal attestation would change the bytes the next record committed to, so scheduled re-signing would report itself as an integrity break. Covering the signature would *also not stop a key-holding insider* — they would simply re-sign. So the property M-3 names is inherent to any signed append-only log, not a fix a bigger hash would deliver.
* **What actually bounds it (the trust boundary).** SAGA's tamper-evidence against a **key holder** rests entirely on **signing-key custody** and an **external witness**, not on the hash chain:
  - **Key custody** — OQGF-R-6 (threshold / HSM custody of the audit-signing key), recorded PARTIAL in BROKKR-ARCH §1.4/§6.11. A key held under 3-of-5 threshold or in an HSM with dual-control issuance denies any single insider the unilateral rewrite M-3 describes.
  - **External witness** — the same mitigation F-30 (SAGA end-truncation) requires: a monotonic head-sequence checkpoint or OQGF-R-5 cross-jurisdictional replication, so a rewritten (or shortened) chain diverges from an independent record.
* **Consistency with the campaign.** M-3 is the SAGA-side instance of the 15C terminal observation: **every residual roots in the trust anchor** (the DAP and the keys it holds). A framework can make the key-holder *named, signed, recorded, and reviewable*; it cannot make the key-holder *trustworthy* by cryptography alone. M-3 is filed alongside F-30 in `reports/SECURITY-BOUNDARIES-2026-08-30-R1.md`.

**Disposition:** documented as a known trust boundary. No code change — the design is correct for its stated model, and the mitigation is operational (key custody + external witness), the same family as F-30, R-6, and the DAP root-of-trust residual the architecture already names.

---

## 3. What the review confirmed sound (the PASS list)

Unchanged from the full audit already on record: I-1 (`AuthorizedAction` unforgeable — private field + private `mint`, no `Clone`/`Default`); I-12 (`ClearedContext` identically sealed); SINDRI `evaluate` fail-closed across all four conjuncts with every verification error mapped to a deny; the intent-chain canonical encoding domain-separated and length-prefixed, committing `emitted_scope` in full (OQGF-M-9); AES-GCM using a fresh IV **and** fresh KEK per wrap (no nonce reuse); every FFI key type single-free on `Drop` with `MlKem768` double-free-guarded; `#![forbid(unsafe_code)]` in all 12 non-crypto crates with unsafe confined to `ffi.rs`/`tls.rs`; and the one-way dependency graph (no governance crate depends on `brokkr-reasoner`/`brokkr-tools`/`brokkr-cli`).

Two prior LOW hardening items remain open and are *not* re-raised as defects: explicit `wolfSSL_CTX_set_verify` + `wolfSSL_check_domain_name` on the TLS client, and tightening `Sync` on the lower-level signing FFI types (the `DualKeyPair` path is already `!Sync` + `Mutex`-guarded per 13-FIX F-4).

## 4. Scope honesty

This was a read-only audit; no source was modified and no new tests were added. The workspace's last verified state stands (15-FIX: 368 passed, 0 failed; clippy/fmt clean). The four false positives are recorded with their refuting line numbers so the disposition is independently checkable; M-3 is recorded as a trust boundary with its mitigation named, not closed by cryptography.
