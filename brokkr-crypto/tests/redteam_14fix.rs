//! Phase 14-FIX — regression tests for the white-box crypto findings:
//! **F-18** (SLH-DSA signature-size cross-check at keygen) and **F-19** (bounded TLS read).
//!
//! F-13/F-14/F-15/F-20 (orchestrator/tool) live in `brokkr-cli/tests/redteam_14fix.rs`;
//! F-16/F-17 (parser) in `brokkr-reasoner::ollama`.

use brokkr_crypto::DualKeyPair;
use brokkr_crypto::ffi::SLHDSA192S_SIG_SIZE;
use brokkr_crypto::tls::{MAX_RESPONSE_BYTES, TlsError};

/// F-18 — `SlhDsaShake192s::generate` now cross-checks `sig_size()` against the FIPS-205 constant
/// (symmetric with `MlDsa65::generate`). A wrong parameter set is caught at keygen. This test
/// proves the check passes for the correct key and that the signature it produces is exactly the
/// declared size. It also documents the value the earlier red-team report got wrong: the `192s`
/// (small) signature is 16224 bytes, **not** the `192f` (fast) variant's 35664.
#[test]
fn fix_f18_slhdsa_sig_size_checked() {
    assert_eq!(
        SLHDSA192S_SIG_SIZE, 16224,
        "SLH-DSA-SHAKE-192s (small) signature size per FIPS-205, probed against libwolfssl"
    );
    assert_ne!(
        SLHDSA192S_SIG_SIZE, 35664,
        "35664 is the 192f (fast) variant — the wrong constant would fail every keygen"
    );
    // generate() succeeds only because sig_size() matches the constant (the F-18 guard).
    let mut kp = DualKeyPair::generate().expect("keygen (implies the F-18 sig-size guard passed)");
    let sig = kp.sign_dual(b"regression").expect("sign");
    assert_eq!(
        sig.hash_based.bytes.len(),
        SLHDSA192S_SIG_SIZE,
        "the produced SLH-DSA signature is exactly the checked size"
    );
}

/// F-19 — `TlsClient::read_until_close` is bounded by `MAX_RESPONSE_BYTES`, and the overflow is a
/// clean `TlsError::ResponseTooLarge` value (never an OOM). An infinite-stream peer cannot be
/// exercised hermetically, so this verifies the bound exists, is reasonable, and renders.
#[test]
fn fix_f19_response_bound_exists_and_reasonable() {
    // Generous enough for any model response, bounded enough to prevent OOM.
    assert!(
        (1024 * 1024..=100 * 1024 * 1024).contains(&MAX_RESPONSE_BYTES),
        "response cap is in a sane range (1 MiB..=100 MiB): {MAX_RESPONSE_BYTES}"
    );
    // The overflow error is a value (Display works — it is surfaced, not a panic).
    let e = TlsError::ResponseTooLarge;
    assert!(!e.to_string().is_empty());
    assert_eq!(e, TlsError::ResponseTooLarge);
}
