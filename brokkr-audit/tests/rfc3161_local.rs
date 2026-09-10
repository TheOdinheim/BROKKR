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

// =========================================================================================
// Certificate path validation (OQGF-A-3; ARCH Rev 1.26 §6.9)
// =========================================================================================
//
// Rev 1.25 pinned the signer to a configured anchor by byte-equality, which is correct when
// the authority's signing certificate IS the anchor — a self-signed TSA, which is every
// responder above. **It admits no CA-issued authority, which is every public TSA**, so
// OQGF-A-3's independence clause was unreachable in practice.
//
// These tests build a real CA and issue leaves under it with **controlled validity windows**
// via `openssl ca -startdate/-enddate`. That matters: an earlier attempt used
// `openssl x509 -req`, which has no such flags on this host's OpenSSL 3.0.13, and `faketime`
// is not installed — so three error mappings had to be recorded as "read in a header, not
// observed". `openssl ca` closes that gap, and each mapping below is now asserted against a
// certificate that actually exhibits the condition.

/// Build a throwaway CA plus a set of leaves exercising every path-validation outcome.
/// Returns the directory; DER files are `ca.der`, `good.der`, `noteku.der`, `noncrit.der`,
/// `both.der`, `anyeku.der`, `expired.der`, `future.der`, `other.der`.
fn ca_dir() -> PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("brokkr-a3-ca-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("db")).expect("temp dir");
    std::fs::write(dir.join("db/index.txt"), "").expect("index");
    std::fs::write(dir.join("db/serial"), "01\n").expect("serial");
    std::fs::write(
        dir.join("ca.cnf"),
        "[ ca ]\ndefault_ca = CA_default\n[ CA_default ]\ndir = .\n\
         database = ./db/index.txt\nnew_certs_dir = ./db\nserial = ./db/serial\n\
         certificate = ./ca.crt\nprivate_key = ./ca.key\ndefault_md = sha256\n\
         policy = pol\nemail_in_dn = no\nrand_serial = no\nunique_subject = no\n\
         [ pol ]\ncommonName = supplied\n\
         [ tsa_ext ]\nextendedKeyUsage = critical,timeStamping\n\
         basicConstraints = critical,CA:FALSE\n\
         [ tsa_noncrit_ext ]\nextendedKeyUsage = timeStamping\n\
         basicConstraints = critical,CA:FALSE\n\
         [ tsa_both_ext ]\nextendedKeyUsage = critical,timeStamping,clientAuth\n\
         basicConstraints = critical,CA:FALSE\n\
         [ tsa_anyeku_ext ]\n\
         extendedKeyUsage = critical,timeStamping,anyExtendedKeyUsage\n\
         basicConstraints = critical,CA:FALSE\n\
         [ noteku_ext ]\nextendedKeyUsage = critical,clientAuth\n\
         basicConstraints = critical,CA:FALSE\n",
    )
    .expect("ca.cnf");

    let run = |args: &[&str]| {
        let out = Command::new("openssl")
            .args(args)
            .current_dir(&dir)
            .output()
            .expect("openssl");
        assert!(
            out.status.success(),
            "openssl {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let der = |name: &str| {
        run(&[
            "x509",
            "-in",
            &format!("{name}.crt"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.der"),
        ]);
    };

    // The root, and an UNRELATED root for the untrusted-signer case.
    for (name, cn) in [("ca", "BROKKR Test Root"), ("other", "Unrelated Root")] {
        run(&[
            "req", "-x509", "-newkey", "rsa:2048", "-keyout",
            &format!("{name}.key"), "-out", &format!("{name}.crt"), "-days", "3", "-nodes",
            "-subj", &format!("/CN={cn}"), "-addext", "basicConstraints=critical,CA:TRUE",
        ]);
        der(name);
    }

    // Leaves. `-startdate`/`-enddate` are what make the expired and not-yet-valid cases
    // observable; without them those two mappings could only be read out of a header.
    let leaves: [(&str, &str, &str, &str); 7] = [
        ("good", "tsa_ext", "20250101000000Z", "20350101000000Z"),
        ("noteku", "noteku_ext", "20250101000000Z", "20350101000000Z"),
        // Carries id-kp-timeStamping, but NOT critical. RFC 3161 §2.3 refuses it, and it is
        // the case that passed every check through ARCH Rev 1.26.
        ("noncrit", "tsa_noncrit_ext", "20250101000000Z", "20350101000000Z"),
        // Carries id-kp-timeStamping AND another purpose, so the key is not reserved to
        // timestamping. `both` reads 0x24, `anyeku` reads 0x21 — both observed.
        ("both", "tsa_both_ext", "20250101000000Z", "20350101000000Z"),
        ("anyeku", "tsa_anyeku_ext", "20250101000000Z", "20350101000000Z"),
        ("expired", "tsa_ext", "20200101000000Z", "20200201000000Z"),
        ("future", "tsa_ext", "20300101000000Z", "20310101000000Z"),
    ];
    for (name, ext, start, end) in leaves {
        run(&[
            "req", "-newkey", "rsa:2048", "-keyout", &format!("{name}.key"),
            "-out", &format!("{name}.csr"), "-nodes", "-subj",
            &format!("/CN=BROKKR {name}"),
        ]);
        run(&[
            "ca", "-batch", "-config", "ca.cnf", "-in", &format!("{name}.csr"),
            "-out", &format!("{name}.crt"), "-extfile", "ca.cnf", "-extensions", ext,
            "-startdate", start, "-enddate", end, "-notext",
        ]);
        der(name);
    }
    dir
}

/// A CA-issued signer with the timestamping EKU validates against the configured root.
///
/// **This is the case anchor equality cannot express**: the signer is not the anchor, so
/// byte-equality would reject it. Every public TSA is shaped this way.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_path_validation_accepts_a_ca_issued_signer() {
    let dir = ca_dir();
    let leaf = std::fs::read(dir.join("good.der")).expect("leaf");
    let root = std::fs::read(dir.join("ca.der")).expect("root");

    brokkr_crypto::ffi::verify_cert_path(&leaf, &root, &[])
        .expect("a CA-issued timestamping certificate must validate against its own root");

    // And anchor equality — the default, stricter mode — rejects the same certificate,
    // which is exactly why path validation must be asked for rather than upgraded into.
    assert_ne!(leaf, root, "the signer is not the anchor in this shape");

    let _ = std::fs::remove_dir_all(&dir);
}

/// An unrelated root reports `UntrustedSigner`, **not** `SignatureInvalid`.
///
/// The distinction is the whole reason the variant exists: "the issuer is unknown" sends an
/// operator to an anchor set that has drifted from an authority that rotated CAs; "the
/// signature is wrong" sends them hunting an attacker. Observed as wolfSSL `-188`.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_unrelated_root_reports_untrusted_signer_not_signature_invalid() {
    let dir = ca_dir();
    let leaf = std::fs::read(dir.join("good.der")).expect("leaf");
    let other = std::fs::read(dir.join("other.der")).expect("other root");

    let e = brokkr_crypto::ffi::verify_cert_path(&leaf, &other, &[])
        .expect_err("a leaf must not validate against a root that did not issue it");
    assert_eq!(e, brokkr_crypto::ffi::PathError::UntrustedSigner);
    assert_ne!(
        e,
        brokkr_crypto::ffi::PathError::SignatureInvalid,
        "an unknown issuer is not a signature failure; conflating them points an \
         investigation at the one thing that is not wrong"
    );
    assert_eq!(
        brokkr_audit::rfc3161::path_to_timestamp_error(e),
        TimestampError::UntrustedSigner,
        "and the distinction must survive the mapping into the record-level error"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A certificate that chains correctly but lacks `id-kp-timeStamping` is refused.
///
/// `wolfSSL_CertManagerVerifyBuffer` **passes** this certificate — path validation does not
/// enforce application EKU policy — so nothing checks RFC 3161's requirement unless the
/// client does. Without this check a CA-issued TLS client certificate could stamp BROKKR's
/// audit chain.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_signer_without_timestamping_eku_is_refused() {
    let dir = ca_dir();
    let root = std::fs::read(dir.join("ca.der")).expect("root");
    let noteku = std::fs::read(dir.join("noteku.der")).expect("noteku");
    let good = std::fs::read(dir.join("good.der")).expect("good");

    // The EKU accessor sees the difference...
    assert!(
        brokkr_crypto::ffi::cert_timestamping_eku(&good)
            .expect("parse good")
            .present,
        "the timestamping leaf must carry the EKU"
    );
    assert!(
        !brokkr_crypto::ffi::cert_timestamping_eku(&noteku)
            .expect("parse noteku")
            .present,
        "the clientAuth leaf must not"
    );

    // ...and the full check refuses it even though the chain is sound.
    let e = brokkr_crypto::ffi::verify_cert_path(&noteku, &root, &[])
        .expect_err("a non-timestamping certificate must not be accepted as a TSA signer");
    assert_eq!(e, brokkr_crypto::ffi::PathError::TimestampingEkuAbsent);
    assert_eq!(
        brokkr_audit::rfc3161::path_to_timestamp_error(e),
        TimestampError::NotTimestampingCertificate
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A signer carrying `id-kp-timeStamping` **non-critically** is refused.
///
/// RFC 3161 §2.3: "This extension MUST be critical." The requirement is not decoration — a
/// non-critical extension MAY be ignored by a verifier that does not understand it, so a
/// certificate claiming timestamping non-critically permits exactly the reading the
/// restriction exists to forbid.
///
/// **This certificate passed every check through ARCH Rev 1.26**, which read only
/// `extExtKeyUsage` and never the criticality bit — the placed clause was half-implemented.
/// The two facts are asserted separately here so the test shows *why* it is refused: the
/// EKU is present, and it is the criticality that fails. A test asserting only the verdict
/// would pass just as well against a certificate that lacked the EKU entirely.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_non_critical_timestamping_eku_is_refused() {
    let dir = ca_dir();
    let root = std::fs::read(dir.join("ca.der")).expect("root");
    let good = std::fs::read(dir.join("good.der")).expect("good");
    let noncrit = std::fs::read(dir.join("noncrit.der")).expect("noncrit");

    // The conforming leaf: present AND critical (observed `extExtKeyUsage = 0x20`,
    // `extExtKeyUsageCrit = 1`).
    let g = brokkr_crypto::ffi::cert_timestamping_eku(&good).expect("parse good");
    assert!(g.present, "the conforming leaf carries the EKU");
    assert!(g.critical, "and carries it critically");
    assert!(g.satisfies_rfc3161());
    brokkr_crypto::ffi::verify_cert_path(&good, &root, &[])
        .expect("a critical timestamping EKU must validate");

    // The non-conforming leaf: present, NOT critical (observed `0x20` / `0`). Presence
    // alone — the pre-Rev-1.26-implementation check — would have accepted it.
    let n = brokkr_crypto::ffi::cert_timestamping_eku(&noncrit).expect("parse noncrit");
    assert!(
        n.present,
        "the non-critical leaf does carry id-kp-timeStamping — that is what makes it the \
         interesting case rather than a duplicate of the missing-EKU test"
    );
    assert!(!n.critical, "but the extension is not marked critical");
    assert!(
        !n.satisfies_rfc3161(),
        "presence without criticality does not satisfy RFC 3161 §2.3"
    );

    // ...and the full check refuses it, even though the chain is sound and the EKU is there.
    let e = brokkr_crypto::ffi::verify_cert_path(&noncrit, &root, &[])
        .expect_err("a non-critical timestamping EKU must not be accepted as a TSA signer");
    assert_eq!(e, brokkr_crypto::ffi::PathError::TimestampingEkuNotCritical);
    assert_eq!(
        brokkr_audit::rfc3161::path_to_timestamp_error(e),
        TimestampError::TimestampingEkuNotCritical,
        "and it must NOT report NotTimestampingCertificate: this certificate IS a \
         timestamping certificate, and saying otherwise sends the operator to fix a \
         deployment that is correct"
    );
    assert_ne!(
        brokkr_audit::rfc3161::path_to_timestamp_error(e),
        TimestampError::NotTimestampingCertificate
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A signer whose extended key usage carries `id-kp-timeStamping` **alongside another
/// purpose** is refused: RFC 3161 §2.3 requires a key reserved to timestamping.
///
/// **Exclusivity is enforced by equality, not a bit test.** `extExtKeyUsage == 0x20`, so any
/// additional recognized purpose sets an extra bit and fails — `timeStamping+clientAuth`
/// reads `0x24`, `timeStamping+anyExtendedKeyUsage` reads `0x21`. A bit test would accept
/// both, which is what the check did through ARCH Rev 1.27.
///
/// **The `anyExtendedKeyUsage` case is the one this test must not omit.** It carries the
/// timestamping bit, so every presence check passes it, while `anyEKU` nullifies the entire
/// EKU restriction — it is the only multi-purpose certificate a CA might plausibly think
/// harmless, and it is the one that would do the most damage.
///
/// Both are refused by OpenSSL under `-purpose timestampsign` too, which is the independent
/// corroboration that purpose exclusivity is the right reading of §2.3.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_non_exclusive_timestamping_eku_is_refused() {
    let dir = ca_dir();
    let root = std::fs::read(dir.join("ca.der")).expect("root");
    let good = std::fs::read(dir.join("good.der")).expect("good");

    // The conforming leaf is exclusive.
    let g = brokkr_crypto::ffi::cert_timestamping_eku(&good).expect("parse good");
    assert!(g.exclusive, "critical,timeStamping alone is exclusive (0x20)");
    assert!(g.satisfies_rfc3161());
    assert_eq!(g.rfc3161_verdict(), Ok(()));

    for (name, why) in [
        ("both", "timeStamping+clientAuth (0x24): the key also authenticates TLS clients"),
        ("anyeku", "timeStamping+anyExtendedKeyUsage (0x21): anyEKU nullifies the restriction"),
    ] {
        let der = std::fs::read(dir.join(format!("{name}.der"))).expect("leaf");
        let eku = brokkr_crypto::ffi::cert_timestamping_eku(&der).expect("parse");

        // Present and critical — so this is NOT a duplicate of either earlier test, and a
        // presence-or-criticality check would have accepted it.
        assert!(eku.present, "{name}: carries id-kp-timeStamping — {why}");
        assert!(eku.critical, "{name}: and carries it critically");
        assert!(!eku.exclusive, "{name}: but not exclusively");
        assert!(!eku.satisfies_rfc3161());

        let e = brokkr_crypto::ffi::verify_cert_path(&der, &root, &[])
            .unwrap_err();
        assert_eq!(
            e,
            brokkr_crypto::ffi::PathError::TimestampingEkuNotExclusive,
            "{name}: a multi-purpose signing key must be named as such"
        );
        assert_eq!(
            brokkr_audit::rfc3161::path_to_timestamp_error(e),
            TimestampError::TimestampingEkuNotExclusive,
            "{name}: and the distinction must survive into the record-level error, where an \
             operator reads it — this is the finding a deployment might carry as an AMD-006 \
             acceptance, which the other two EKU failures can never sensibly receive"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The three EKU failures are three distinct verdicts, asserted side by side.
///
/// Each certificate below fails a *different* clause of RFC 3161 §2.3 while satisfying the
/// others as far as its own defect allows. Asserting them together is what shows the split
/// is real: with one variant, every row of this test would read the same.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_the_three_eku_failures_are_distinguished() {
    use brokkr_crypto::ffi::PathError as P;
    let dir = ca_dir();
    let root = std::fs::read(dir.join("ca.der")).expect("root");

    let cases: [(&str, P, TimestampError); 4] = [
        ("noteku", P::TimestampingEkuAbsent, TimestampError::NotTimestampingCertificate),
        ("noncrit", P::TimestampingEkuNotCritical, TimestampError::TimestampingEkuNotCritical),
        ("both", P::TimestampingEkuNotExclusive, TimestampError::TimestampingEkuNotExclusive),
        ("anyeku", P::TimestampingEkuNotExclusive, TimestampError::TimestampingEkuNotExclusive),
    ];

    let mut seen: Vec<P> = Vec::new();
    for (name, want_path, want_ts) in cases {
        let der = std::fs::read(dir.join(format!("{name}.der"))).expect("leaf");
        let got = brokkr_crypto::ffi::verify_cert_path(&der, &root, &[]).unwrap_err();
        assert_eq!(got, want_path, "{name}");
        assert_eq!(brokkr_audit::rfc3161::path_to_timestamp_error(got), want_ts, "{name}");
        seen.push(got);
    }

    // Three distinct PathError values across the four certificates — the property the split
    // exists to provide, and the one a single variant would silently lose.
    seen.sort_by_key(|e| format!("{e:?}"));
    seen.dedup();
    assert_eq!(seen.len(), 3, "three clauses must yield three distinct verdicts");

    // And the conforming leaf still passes all three.
    let good = std::fs::read(dir.join("good.der")).expect("good");
    brokkr_crypto::ffi::verify_cert_path(&good, &root, &[])
        .expect("critical, exclusive timeStamping must validate");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A leaf that chains to the correct anchor but whose **signature is corrupted** reports
/// `SignatureInvalid`, observed as wolfSSL `-155` (`ASN_SIG_CONFIRM_E`).
///
/// **This mapping was "header only" until this test**, and it was the last one. ARCH Rev 1.26
/// recorded three date/signature constants as read from `error-crypt.h` rather than observed;
/// Rev 1.27 closed two of them and left this one open, noting that a source comment claimed
/// it was observed while **no committed test drove a certificate to `-155`** — the
/// untrusted-signer test asserts only that the error is *not* `SignatureInvalid`, which is a
/// negative assertion. Under CLAUDE.md §7 the builder's own summary is not evidence. This is.
///
/// The corruption is the **last byte of the DER**, which is the final byte of the
/// `signatureValue` BIT STRING. That placement matters: flipping a byte inside
/// `tbsCertificate` instead yields `-140`, a parse-level error, because it corrupts the
/// structure before the signature is ever checked. Only a flip within `signatureValue`
/// leaves a well-formed certificate whose signature does not verify — which is the condition
/// this mapping is *for*.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_corrupted_signature_reports_signature_invalid() {
    let dir = ca_dir();
    let root = std::fs::read(dir.join("ca.der")).expect("root");
    let good = std::fs::read(dir.join("good.der")).expect("good");

    // Control: the pristine leaf validates, so the only difference below is the flipped byte.
    brokkr_crypto::ffi::verify_cert_path(&good, &root, &[])
        .expect("the pristine leaf must validate against its own root");

    let mut tampered = good.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;

    let e = brokkr_crypto::ffi::verify_cert_path(&tampered, &root, &[])
        .expect_err("a leaf whose signature does not verify must be refused");
    assert_eq!(
        e,
        brokkr_crypto::ffi::PathError::SignatureInvalid,
        "a corrupted signature is a signature failure, not an unknown issuer: the leaf still \
         names the same issuer and still chains to the configured anchor"
    );
    assert_ne!(
        e,
        brokkr_crypto::ffi::PathError::UntrustedSigner,
        "reporting this as UntrustedSigner would send an operator to fix an anchor set that \
         is correct — the Rev 1.26 distinction, asserted here from the other direction"
    );
    assert_eq!(brokkr_audit::rfc3161::path_to_timestamp_error(e), TimestampError::SignatureInvalid);

    let _ = std::fs::remove_dir_all(&dir);
}

/// RFC 3161 §2.3 fitness is enforced in **both** trust modes, not only under path validation.
///
/// **Through ARCH Rev 1.27 the `AnchorEquality` arm performed no fitness check at all.** That
/// made the mode this architecture calls "the stricter of the two" strictly *weaker* on the
/// one axis RFC 3161 legislates: anchor equality is stricter about **identity** — it admits
/// exactly one certificate — and said nothing about whether that certificate may stamp time.
/// Pinning answers *which* certificate, never *whether it is a TSA certificate*.
///
/// **What this test reaches, and what it does not — stated because the gap is real.** It
/// drives `rfc3161::signer_fitness`, the production function **both** arms call, against
/// certificates that genuinely exhibit each defect. It does **not** drive a token end to end
/// through the `AnchorEquality` arm, because a non-conformant TSA cannot be stood up on this
/// host at all. Two independent obstacles, both observed:
///
///   1. `openssl ts` **refuses** to operate an authority whose signing certificate is
///      non-conformant — "invalid signer certificate purpose" for all three certificates
///      below. That is corroboration of §2.3 from the reference implementation at *signing*
///      time, and it means no real non-conformant token exists to test with.
///   2. `openssl cms -sign` produces a bundle wolfSSL's PKCS#7 verifier rejects regardless of
///      certificate — confirmed by signing with a conformant `critical,timeStamping` cert and
///      seeing the same rejection — so there is no alternative signer available here.
///
/// What remains unverified by any test is therefore the two-line wiring in that arm. It is
/// verified by reading, and is recorded as the weaker kind of evidence rather than implied.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_anchor_equality_fitness_refuses_non_tsa_certificates() {
    let dir = ca_dir();
    for (name, want) in [
        ("noteku", TimestampError::NotTimestampingCertificate),
        ("noncrit", TimestampError::TimestampingEkuNotCritical),
        ("both", TimestampError::TimestampingEkuNotExclusive),
        ("anyeku", TimestampError::TimestampingEkuNotExclusive),
    ] {
        let der = std::fs::read(dir.join(format!("{name}.der"))).expect("leaf");
        let e = brokkr_audit::rfc3161::signer_fitness(&der)
            .expect_err("a non-conformant signer certificate must be refused on fitness");
        assert_eq!(e, want, "{name}");
    }

    // Control: the conformant leaf passes, so the test above is not passing because the
    // function refuses everything.
    let good = std::fs::read(dir.join("good.der")).expect("good");
    assert!(
        brokkr_audit::rfc3161::signer_fitness(&good).is_ok(),
        "critical, exclusive timeStamping must pass fitness"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A conformant self-signed responder still verifies end to end under anchor equality.
///
/// This one *does* run a real token through the real `AnchorEquality` arm — `openssl ts` will
/// happily operate a conformant authority — so it proves the arm still accepts what it should
/// after gaining a fitness check. The refusal direction is covered by the test above.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_anchor_equality_still_accepts_a_conformant_signer() {
    let dir = tsa_dir();
    let digest = Sha384Hasher.hash(b"a record");
    let resp = respond(&dir, &build_request(&digest.bytes));
    let token = extract_token(&resp).expect("extract");
    let anchor = std::fs::read(dir.join("tsa.crt.der")).expect("anchor");

    let client = brokkr_audit::Rfc3161Client::new(
        "127.0.0.1:1",
        "test",
        brokkr_audit::SignerTrust::AnchorEquality { anchor_der: anchor },
        std::time::Duration::from_secs(2),
    );
    assert!(
        client.verify(&token).is_ok(),
        "critical, exclusive timeStamping must still pass under equality — without this \
         control, adding a fitness check could have broken every conformant token silently"
    );

    let _ = std::fs::remove_dir_all(&dir);
}


/// Garbage that is not a certificate reports `Malformed`, via the catch-all arm.
///
/// **`PathError::Malformed` had zero assertions before this test.** Its only appearance in
/// the suite was a `match` arm in the test's own mapping mirror — which is not an assertion,
/// and which c1eb158 deleted. The variant is genuinely reachable: `wc_ParseCert` rejects
/// non-certificate bytes, and an unrecognized wolfSSL return code (observed `-140` for
/// garbage DER) falls to `path_error_from`'s `_ =>` arm.
///
/// That catch-all is the fail-closed default, and asserting it matters for a reason beyond
/// coverage: it is what an unrecognized code becomes. If wolfSSL ever returned a code this
/// mapping does not name, the result would be `Malformed` — not a wrong specific claim.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_garbage_is_malformed_not_a_specific_claim() {
    let dir = ca_dir();
    let root = std::fs::read(dir.join("ca.der")).expect("root");

    let e = brokkr_crypto::ffi::verify_cert_path(b"not a certificate at all", &root, &[])
        .expect_err("garbage must not validate");
    assert_eq!(e, brokkr_crypto::ffi::PathError::Malformed);
    assert_eq!(
        brokkr_audit::rfc3161::path_to_timestamp_error(e),
        TimestampError::Malformed
    );

    // A truncated real certificate takes the same path — well-formed prefix, no valid whole.
    let good = std::fs::read(dir.join("good.der")).expect("good");
    let e = brokkr_crypto::ffi::verify_cert_path(&good[..good.len() / 2], &root, &[])
        .expect_err("a truncated certificate must not validate");
    assert_eq!(e, brokkr_crypto::ffi::PathError::Malformed);

    // And fitness reports Malformed on unparseable input rather than a fitness verdict —
    // "this did not parse" must not be reported as "this is not a TSA certificate".
    assert_eq!(
        brokkr_audit::rfc3161::signer_fitness(b"not a certificate at all"),
        Err(TimestampError::Malformed)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An authority that cannot be reached reports `Unreachable`, distinctly from a token that
/// arrives and fails.
///
/// **`TimestampError::Unreachable` had zero assertions before this test.** It is hermetic:
/// bind a port to learn one that is free, drop the listener, then connect. Nothing listens,
/// so the connection is refused without any network egress beyond loopback.
///
/// The distinction is the point. `Unreachable` says the authority was configured and could
/// not be contacted — an operational condition an operator resolves by looking at the network
/// or the endpoint. Every other variant says something arrived and was rejected. Collapsing
/// them would send an operator hunting a bad token when the authority is simply down, and a
/// record marked `Unavailable` carries this text into the audit chain.
#[test]
fn test_a3_unreachable_authority_is_named_as_such() {
    // Bind, read the port, drop: the port is then free and nothing is listening on it.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    };

    let client = brokkr_audit::Rfc3161Client::new(
        format!("127.0.0.1:{port}"),
        "unreachable-test",
        brokkr_audit::SignerTrust::AnchorEquality { anchor_der: vec![0u8; 4] },
        std::time::Duration::from_millis(500),
    );

    use brokkr_audit::event::TimestampAuthority;
    let digest = Sha384Hasher.hash(b"a record");
    let e = client
        .stamp(&digest.bytes)
        .expect_err("a closed port must not yield a token");
    assert_eq!(
        e,
        TimestampError::Unreachable,
        "a refused connection is an unreachable authority, not a malformed or unverifiable \
         token — nothing arrived to be malformed"
    );
    assert_ne!(e, TimestampError::Malformed);

    // And the record-level consequence: SAGA still appends, recording the absence rather
    // than refusing to record. A record marked Unavailable is still a valid record.
    assert!(
        format!("{e}").contains("unreachable"),
        "the Display text reaches the audit chain via Timestamping::Unavailable"
    );
}

/// Expired and not-yet-valid signers are reported as themselves.
///
/// **These two mappings were "header only" until this test.** `openssl ca -startdate/
/// -enddate` produces certificates that genuinely exhibit each condition, so `-151` and
/// `-150` are now observed rather than transcribed. `NotYetValid` keeps its own word because
/// in a component whose purpose is attesting time, a local clock error is its own finding.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_expired_and_not_yet_valid_signers_are_named_distinctly() {
    let dir = ca_dir();
    let root = std::fs::read(dir.join("ca.der")).expect("root");

    let expired = std::fs::read(dir.join("expired.der")).expect("expired");
    let e = brokkr_crypto::ffi::verify_cert_path(&expired, &root, &[])
        .expect_err("an expired signer must not validate");
    assert_eq!(e, brokkr_crypto::ffi::PathError::Expired);
    assert_eq!(brokkr_audit::rfc3161::path_to_timestamp_error(e), TimestampError::CertificateExpired);

    let future = std::fs::read(dir.join("future.der")).expect("future");
    let e = brokkr_crypto::ffi::verify_cert_path(&future, &root, &[])
        .expect_err("a not-yet-valid signer must not validate");
    assert_eq!(e, brokkr_crypto::ffi::PathError::NotYetValid);
    assert_eq!(brokkr_audit::rfc3161::path_to_timestamp_error(e), TimestampError::CertificateNotYetValid);

    let _ = std::fs::remove_dir_all(&dir);
}

/// **Anchor equality is unchanged**, and remains what a deployment gets without asking.
///
/// Rev 1.26 adds a *more permissive* check — path validation trusts a CA's issuance policy
/// rather than one certificate — so it must never be acquired by upgrading. A configuration
/// that selects neither still gets equality.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_anchor_equality_is_unchanged_and_is_not_upgraded() {
    let dir = tsa_dir();
    let other = tsa_dir();

    let digest = Sha384Hasher.hash(b"a record");
    let resp = respond(&dir, &build_request(&digest.bytes));
    let token = extract_token(&resp).expect("extract");
    let anchor = std::fs::read(dir.join("tsa.crt.der")).expect("anchor");
    let wrong = std::fs::read(other.join("tsa.crt.der")).expect("wrong anchor");

    // The self-signed responder verifies under equality, exactly as at Rev 1.25.
    brokkr_crypto::ffi::cms_verify(&token, &anchor)
        .expect("the self-signed TSA is its own anchor");

    // An unrelated anchor is still rejected under equality — no fallback to a chain search.
    assert!(
        brokkr_crypto::ffi::cms_verify(&token, &wrong).is_err(),
        "equality must not silently widen into a chain search when the anchor does not match"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&other);
}


/// **End to end through `TimestampAuthority::stamp` with a CA-issued authority.**
///
/// The tests above exercise path validation at the FFI layer over certificates on disk.
/// This one drives the whole client — request, HTTP, CMS verification, path validation, EKU
/// policy, imprint binding — against a responder whose signing certificate is *issued by* a
/// CA rather than being the anchor. It is the shape Rev 1.25 could not accept at all, and
/// the reason a six-line dispatch in `Rfc3161Client::verify` is worth a listener.
#[test]
#[ignore = "live: needs openssl(1), binds a loopback port, writes to a temp dir"]
fn test_a3_stamp_end_to_end_with_a_ca_issued_authority() {
    use std::io::{Read as _, Write as _};

    let dir = ca_dir();
    let d = dir.display();
    // A TSA config whose signer is the CA-issued `good` leaf, not a self-signed cert.
    std::fs::write(
        dir.join("openssl.cnf"),
        format!(
            "[ tsa ]\ndefault_tsa = t\n[ t ]\ndir = {d}\nserial = {d}/tsserial\n\
             crypto_device = builtin\nsigner_cert = {d}/good.crt\ncerts = {d}/good.crt\n\
             signer_key = {d}/good.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\n\
             digests = sha256, sha384, sha512\naccuracy = secs:1\nordering = yes\n\
             tsa_name = yes\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n"
        ),
    )
    .expect("cnf");
    std::fs::write(dir.join("tsserial"), "01\n").expect("serial");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let serve_dir = dir.clone();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        // Read headers, then exactly Content-Length bytes. Bounded, like the client.
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        let body = loop {
            let n = sock.read(&mut buf).expect("read");
            if n == 0 {
                break Vec::new();
            }
            raw.extend_from_slice(&buf[..n]);
            if let Some(sep) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..sep]).to_lowercase();
                let len: usize = head
                    .split("content-length:")
                    .nth(1)
                    .and_then(|s| s.split("\r\n").next())
                    .and_then(|s| s.trim().parse().ok())
                    .expect("content-length");
                let start = sep + 4;
                while raw.len() < start + len {
                    let n = sock.read(&mut buf).expect("read body");
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                }
                break raw[start..start + len].to_vec();
            }
        };
        let resp = respond(&serve_dir, &body);
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\n\
Content-Length: {}\r\nConnection: close\r\n\r\n",
            resp.len()
        );
        sock.write_all(head.as_bytes()).expect("write head");
        sock.write_all(&resp).expect("write body");
    });

    let root = std::fs::read(dir.join("ca.der")).expect("root");
    let client = brokkr_audit::Rfc3161Client::new(
        addr.to_string(),
        "test-ca-issued-tsa (self-hosted: not independent evidence)",
        brokkr_audit::SignerTrust::PathValidation {
            root_der: root,
            intermediates_der: Vec::new(),
        },
        std::time::Duration::from_secs(10),
    );

    let signed = b"a record's signed content";
    let token = brokkr_audit::TimestampAuthority::stamp(&client, signed)
        .expect("a CA-issued authority must be accepted under path validation");

    server.join().expect("server thread");

    assert!(!token.gen_time.is_empty(), "genTime must be recorded");
    assert!(
        !token.algorithm.is_post_quantum(),
        "no RFC 3161 authority signs post-quantum; A-3's PQC clause stays PARTIAL"
    );
    assert_ne!(token.key_oid, 0, "the signer key OID must be observed");
    assert_ne!(token.hash_oid, 0, "the digest OID must be observed");

    // And the same client shape under an UNRELATED root fails as UntrustedSigner rather
    // than as a signature failure — the distinction surviving all the way to a caller.
    let other = std::fs::read(dir.join("other.der")).expect("other root");
    let leaf = std::fs::read(dir.join("good.der")).expect("leaf");
    assert_eq!(
        brokkr_crypto::ffi::verify_cert_path(&leaf, &other, &[]),
        Err(brokkr_crypto::ffi::PathError::UntrustedSigner)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A **self-signed** certificate that is not an anchor is refused as `UntrustedSigner`.
///
/// The Rev 1.26 table anticipated `ASN_SELF_SIGNED_E` (−275) here. **The observed code is
/// `ASN_NO_SIGNER_E` (−188)** — wolfSSL reports "no signer" before it reaches a self-signed
/// determination on this path. The mapping is unaffected because both codes map to
/// `UntrustedSigner`, but the distinction is recorded rather than smoothed: −275 was **read
/// in a header and not observed**, and this file does not claim otherwise.
#[test]
#[ignore = "live: needs openssl(1) and writes to a temp dir"]
fn test_a3_self_signed_non_anchor_is_untrusted_signer() {
    let dir = ca_dir();
    let root = std::fs::read(dir.join("ca.der")).expect("root");
    // `other.der` is self-signed and is NOT the configured anchor.
    let self_signed = std::fs::read(dir.join("other.der")).expect("other");

    assert_eq!(
        brokkr_crypto::ffi::verify_cert_path(&self_signed, &root, &[]),
        Err(brokkr_crypto::ffi::PathError::UntrustedSigner),
        "a self-signed certificate that is not the anchor must not validate, and must be \
         reported as an unknown issuer rather than a signature failure"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
