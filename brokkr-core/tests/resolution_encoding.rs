//! Rev 1.12 — properties of the `resolution_signed_content` canonical encoding.
//!
//! Byte composition only; no crypto backend needed (a dummy `DualSignature` is built from
//! core types). These prove the three properties a two-party signed encoding depends on.

use brokkr_core::crypto::{DualSignature, Signature, SignatureAlg};
use brokkr_core::ids::{Dap, EscalationId, Nonce, Timestamp};
use brokkr_core::resolution::{ClearEvidence, ResolutionDecision, resolution_signed_content};

fn sig(byte: u8) -> DualSignature {
    DualSignature {
        lattice: Signature {
            alg: SignatureAlg::MlDsa65,
            bytes: vec![byte],
        },
        hash_based: Signature {
            alg: SignatureAlg::SlhDsaShake192s,
            bytes: vec![byte],
        },
    }
}

fn decision(esc: &str, cleared: &str, sig_byte: u8) -> ResolutionDecision {
    ResolutionDecision::new(
        EscalationId::new(esc),
        ClearEvidence {
            detail: cleared.to_string(),
        },
        Dap::new("D", "1"),
        Timestamp(5),
        Nonce(7),
        Timestamp(1000),
        sig(sig_byte),
    )
}

#[test]
fn test_resolution_encoding_is_deterministic() {
    // The same decision always produces identical bytes — the issuer and verifier agree.
    let a = decision("esc-1", "cleared", 1);
    let b = decision("esc-1", "cleared", 1);
    assert_eq!(resolution_signed_content(&a), resolution_signed_content(&b));
}

#[test]
fn test_resolution_encoding_is_unambiguous() {
    // Without length prefixes, ("ab","c") and ("a","bc") would concatenate to the same bytes
    // across the two adjacent string fields. The fixed-width length prefixes keep them
    // distinct, so no two distinct decisions collide.
    let x = decision("ab", "c", 1);
    let y = decision("a", "bc", 1);
    assert_ne!(resolution_signed_content(&x), resolution_signed_content(&y));
}

#[test]
fn test_resolution_signature_is_excluded() {
    // Two decisions differing ONLY in their signature produce identical signed content — the
    // property a refactor is most likely to break silently (signing over your own signature).
    let a = decision("esc-1", "cleared", 1);
    let b = decision("esc-1", "cleared", 99);
    assert_ne!(a.signature, b.signature);
    assert_eq!(resolution_signed_content(&a), resolution_signed_content(&b));
}
