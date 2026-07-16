# THREAT_MODEL — brokkr-crypto

**Crate:** `brokkr-crypto` (Phase 2). **Date:** 16 July 2026.

`brokkr-crypto` is the FFI backend that implements the `brokkr-core` crypto traits
against wolfCrypt (wolfSSL v5.9.2, non-FIPS). It is the one crate permitted `unsafe`,
confined to `src/ffi.rs`. Its security value is a correct, memory-safe boundary to a
verified C library.

## Trust boundaries

- **The Rust ↔ C boundary (`ffi.rs`).** Every `extern "C"` signature must match the
  wolfCrypt header prototype exactly; a mismatch is undefined behavior. All signatures
  were matched to the v5.9.2 headers and the exported symbols (`nm -D`).
- **The library identity.** Binding a wrong-but-linkable symbol (e.g. legacy
  `dilithium`) would be a silent algorithm substitution. Mitigated: `ffi.rs` declares
  only `wc_MlDsaKey_*` / `wc_SlhDsaKey_*` / `wc_MlKemKey_*`; the linked test binary
  imports exactly those and **zero** `dilithium`/`falcon`/`kyber` symbols (verified via
  `nm -u`).

## Assets

- The private keys held by `MlDsa65`, `SlhDsaShake192s`, `MlKem768` (opaque, owned).
- The per-subject ML-KEM key whose destruction crypto-shreds wrapped data.

## Threats and mitigations

| # | Threat (STRIDE) | Mitigation |
|---|---|---|
| T1 | *Tampering* — a wrong FFI signature corrupts memory | Every prototype matched to the header; struct sizes for constructor-less types (`SlhDsaKey`, `Sha384`, `Aes`) come from a `sizeof()` probe, over-allocated and 16-aligned. Raw pointers/structs never leave `ffi.rs`. |
| T2 | *Spoofing* — the wrong algorithm is bound and passes tests | Symbol-level proof (`nm -u`): no `dilithium`/`falcon`/`kyber`; ML-DSA-65 signature is exactly 3309 B (FIPS-204). Enum values (`WC_ML_KEM_768=1`, `WC_ML_DSA_65=3`) probed, not guessed. |
| T3 | *Repudiation of dual-family* — a single-family signature passes as "dual" | `DualKeyPair::verify_dual` requires BOTH families; corrupting either half fails the whole. The core `DualSignature` type structurally carries two `Signature` fields. |
| T4 | *Information disclosure* — a leaked memory-safety bug in cryptography | `#![forbid(unsafe_code)]` in every module except `ffi.rs`; `ffi.rs` uses RAII (`Drop` frees keys) and never indexes. |
| T5 | *HNDL on erased data* — a "shredded" record recovered by a future CRQC | The shredding key is ML-KEM-wrapped, never RSA/ECDH (OQGF-G-7); crypto-shred survives a CRQC. Proven irrecoverable after key destruction. |
| T6 | *False FIPS claim* | The build is non-FIPS (zero FIPS symbols, verified). `CRYPTO_POSTURE` and `WOLFCRYPT_CBOM` state exactly that; no stronger claim exists anywhere. |

## Out of scope for this crate (named, not hidden)

- **Entropy diversification (OQGF-R-4).** Keygen draws from wolfCrypt's Hash-DRBG
  (`ffi::Rng`). The ≥2-independent-source requirement and SP 800-90B continuous health
  tests are a wolfCrypt-build / OS / deployment configuration, not this crate's Rust
  surface, and are **not** met by the current single non-FIPS DRBG. Flagged in the
  conformance record and the phase report.
- **Signed CBOM assembly (OQGF-G-1).** This crate provides the truthful CBOM *facts*
  (`WOLFCRYPT_CBOM`); the signed CycloneDX document is Phase 5 (REGIN).
- **The erasure lifecycle (OQGF-P-11).** Retention sweeps, the erasure tombstone,
  subject-rights plumbing are Phase 7. This crate builds only the shredding *primitive*.
