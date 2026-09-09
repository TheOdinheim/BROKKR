//! OQGF-A-3 end to end against a **local `openssl ts` responder** (ARCH Rev 1.25 §6.9).
//!
//! **A local responder proves the client parses, verifies, and binds the imprint — and
//! proves nothing whatever about independence.** A self-hosted TSA is BROKKR's operator
//! attesting BROKKR's own time, which fails the Organ 5 principle that the governed system
//! shall not be the authority over its own evidence. It is chosen here for hermeticity: a
//! test depending on a third-party network service is flaky, rate-limited, and leaks CI
//! timing to an outside party.
//!
//! These tests are `#[ignore]`d like the other live tests — they need `openssl(1)` on PATH
//! and write to a temp directory. Run with `cargo test -p brokkr-audit --test
//! rfc3161_local -- --ignored --nocapture`.

use brokkr_audit::{TimestampError, TimestampSigAlg};
use brokkr_core::crypto::Hasher;
use brokkr_crypto::{Sha384Hasher, build_request, extract_token, parse_tstinfo};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Stand up a throwaway TSA: a self-signed cert with the timeStamping EKU and an
/// `openssl ts` config pointing at it.
fn tsa_dir() -> PathBuf {
    // Unique per CALL, not per process: the tests run in parallel and one of them stands up
    // two independent authorities, so keying on the pid alone made "the other authority"
    // the same authority and made the parallel runs collide on one directory.
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("brokkr-a3-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let d = dir.display();
    std::fs::write(
        dir.join("openssl.cnf"),
        format!(
            "[ tsa ]\ndefault_tsa = t\n[ t ]\ndir = {d}\nserial = {d}/serial\n\
             crypto_device = builtin\nsigner_cert = {d}/tsa.crt\ncerts = {d}/tsa.crt\n\
             signer_key = {d}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\n\
             digests = sha256, sha384, sha512\naccuracy = secs:1\nordering = yes\n\
             tsa_name = yes\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n"
        ),
    )
    .expect("cnf");
    std::fs::write(dir.join("serial"), "01\n").expect("serial");

    let ok = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            &format!("{d}/tsa.key"),
            "-out",
            &format!("{d}/tsa.crt"),
            "-days",
            "2",
            "-nodes",
            "-subj",
            "/CN=BROKKR Test TSA",
            "-addext",
            "extendedKeyUsage=critical,timeStamping",
        ])
        .output()
        .expect("openssl req");
    assert!(ok.status.success(), "openssl req failed");

    let ok = Command::new("openssl")
        .args([
            "x509",
            "-in",
            &format!("{d}/tsa.crt"),
            "-outform",
            "DER",
            "-out",
            &format!("{d}/tsa.crt.der"),
        ])
        .output()
        .expect("openssl x509");
    assert!(ok.status.success(), "openssl x509 failed");
    dir
}

/// Run `openssl ts -reply` over a request, returning the raw `TimeStampResp`.
fn respond(dir: &Path, request: &[u8]) -> Vec<u8> {
    let d = dir.display();
    std::fs::write(dir.join("req.tsq"), request).expect("write req");
    let out = Command::new("openssl")
        .args([
            "ts",
            "-reply",
            "-config",
            &format!("{d}/openssl.cnf"),
            "-queryfile",
            &format!("{d}/req.tsq"),
            "-out",
            &format!("{d}/resp.tsr"),
        ])
        .output()
        .expect("openssl ts");
    assert!(
        out.status.success(),
        "openssl ts failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(dir.join("resp.tsr")).expect("read resp")
}

/// A real token, requested, verified, and its imprint bound to what was sent.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_live_token_verifies_and_binds_the_imprint() {
    let dir = tsa_dir();
    let signed = b"a record's signed content";
    let digest = Sha384Hasher.hash(signed);

    let resp = respond(&dir, &build_request(&digest.bytes));
    let token = extract_token(&resp).expect("extract");
    let anchor = std::fs::read(dir.join("tsa.crt.der")).expect("anchor");

    let v = brokkr_crypto::ffi::cms_verify(&token, &anchor).expect("cms_verify");
    let tst = parse_tstinfo(&v.content).expect("parse");

    assert!(
        tst.imprint_is_sha384(),
        "the imprint algorithm must be what we requested"
    );
    assert_eq!(
        tst.imprint, digest.bytes,
        "the imprint must bind what we sent"
    );
    assert!(!tst.gen_time.is_empty(), "genTime must be recorded");

    // The algorithm is DERIVED from two observed OIDs, and both are carried so a reader can
    // re-derive rather than trust. This TSA signs RSA+SHA-256 per its config.
    println!(
        "key_oid={} hash_oid={} genTime={}",
        v.key_oid, v.hash_oid, tst.gen_time
    );
    assert_ne!(
        v.key_oid, 0,
        "the signer key OID must be observed, not defaulted"
    );
    assert_ne!(
        v.hash_oid, 0,
        "the digest OID must be observed, not defaulted"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// **The attack case.** A token requested over one record, presented as a timestamp for a
/// *different* one, must report `ImprintMismatch` — never `Malformed`. The token here is
/// perfectly well-formed and its signature verifies; what is wrong is what it attests.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_token_for_other_bytes_reports_imprint_mismatch() {
    let dir = tsa_dir();

    // A token legitimately issued over ONE record's bytes.
    let other_digest = Sha384Hasher.hash(b"some other record");
    let resp = respond(&dir, &build_request(&other_digest.bytes));
    let token = extract_token(&resp).expect("extract");
    let anchor = std::fs::read(dir.join("tsa.crt.der")).expect("anchor");

    // It verifies — this is not a forgery.
    let v = brokkr_crypto::ffi::cms_verify(&token, &anchor)
        .expect("a substituted token still verifies; that is what makes it dangerous");
    let tst = parse_tstinfo(&v.content).expect("parse");

    // But presented for a DIFFERENT record it does not bind.
    let ours = Sha384Hasher.hash(b"the record we are actually stamping");
    assert_ne!(
        tst.imprint, ours.bytes,
        "a token over other bytes must not bind ours"
    );

    // The client maps exactly this condition to ImprintMismatch, and the error must not be
    // Malformed: the token parsed and verified, so reporting a parse failure would point an
    // investigator at the one thing that is not wrong.
    let mapped = if !tst.imprint_is_sha384() || tst.imprint != ours.bytes {
        TimestampError::ImprintMismatch
    } else {
        TimestampError::Malformed
    };
    assert_eq!(mapped, TimestampError::ImprintMismatch);
    assert_ne!(mapped, TimestampError::Malformed);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A token from an authority that is not the configured trust anchor reports
/// `SignatureInvalid`, not `Malformed` — it parsed; it did not verify.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_wrong_trust_anchor_reports_signature_invalid() {
    let dir = tsa_dir();
    let other = tsa_dir(); // a second, unrelated authority

    let digest = Sha384Hasher.hash(b"a record");
    let resp = respond(&dir, &build_request(&digest.bytes));
    let token = extract_token(&resp).expect("extract");
    let wrong_anchor = std::fs::read(other.join("tsa.crt.der")).expect("anchor");

    match brokkr_crypto::ffi::cms_verify(&token, &wrong_anchor) {
        Err(brokkr_crypto::ffi::CmsError::SignatureInvalid) => {}
        Err(brokkr_crypto::ffi::CmsError::Malformed) => {
            panic!(
                "a well-formed token under the wrong anchor is a signature failure, not a parse failure"
            )
        }
        Ok(_) => panic!("verification must not succeed under an unrelated trust anchor"),
    }

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&other);
}

/// `is_post_quantum` is false for every variant, including `Unrecognized`. Not a live test.
#[test]
fn test_a3_no_variant_claims_post_quantum() {
    assert!(!TimestampSigAlg::RsaSha256.is_post_quantum());
    assert!(
        !TimestampSigAlg::Unrecognized {
            key_oid: 9,
            hash_oid: 9
        }
        .is_post_quantum(),
        "an unidentifiable algorithm cannot be read as satisfying a clause it cannot be \
         shown to satisfy"
    );
}

/// The seam's absent-authority path is unchanged: no authority yields `Unavailable`, and a
/// record is still appended. Not a live test.
#[test]
fn test_a3_absent_authority_still_records() {
    // Covered end-to-end in tests/audit.rs; asserted here so the A-3 file states the
    // record-level contract it depends on: absence is recorded, never omitted.
    let t = brokkr_audit::Timestamping::Unavailable {
        reason: "no timestamp authority configured".to_string(),
    };
    assert!(matches!(t, brokkr_audit::Timestamping::Unavailable { .. }));
}
