/*
 * brokkr_pkcs7_shim.c — OQGF-A-3 accessor shim (ARCH Rev 1.25 §6.9).
 *
 * wolfSSL implements CMS, not RFC 3161. wc_PKCS7_VerifySignedData verifies the
 * SignedData signature and returns a status code, but RFC 3161's TSTInfo — carrying
 * messageImprint and genTime — is the CMS eContent, reachable only through the struct
 * field pkcs7->content. None of the 54 exported wc_PKCS7_* symbols returns it
 * (GAP-2026-09-08-001).
 *
 * WHY THIS FILE EXISTS RATHER THAN RUST OFFSET-READS:
 * pkcs7.h guards streamOutCb/streamCtx behind #ifdef BEFORE the fields needed here, so a
 * Rust-side offset would be an independent opinion about a layout that C preprocessor
 * state determines — silently wrong under a different build, and a silently wrong offset
 * yields a false messageImprint comparison in a signed audit record. This file is
 * compiled against the same headers with the same flags as the linked library, so it is
 * TOLD the layout by the compiler rather than guessing it.
 *
 * WHAT THIS FILE DOES NOT DO — and the bound is the safety argument, not a style note:
 * it exposes fields. It does not parse, allocate, loop, or branch beyond a null check.
 * Parsing the exposed TSTInfo happens in safe Rust (brokkr-crypto::tstinfo) over bytes
 * the CMS signature has already authenticated. A shim that grew logic would become a
 * second place where cryptographic decisions are made, in the language with the fewest
 * guarantees — and cargo-audit/deny/vet are blind to it, so smallness is the only review
 * this repository can honestly claim over it.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/asn.h>

/* The DER TSTInfo (CMS eContent). NULL if absent or the handle is NULL. */
const unsigned char *brokkr_pkcs7_content(const wc_PKCS7 *p7) {
    if (p7 == 0) {
        return 0;
    }
    return p7->content;
}

/* Its length. 0 if absent or the handle is NULL. */
unsigned int brokkr_pkcs7_content_sz(const wc_PKCS7 *p7) {
    if (p7 == 0) {
        return 0;
    }
    return (unsigned int)p7->contentSz;
}

/* The signer's key type OID (RSAk, ECDSAk, ...), from the certificate that verified
 * this token. One half of the derived signature algorithm; SignerInfo.signatureAlgorithm
 * itself is consumed during parsing and retained in no field, so it cannot be exposed. */
unsigned int brokkr_pkcs7_public_key_oid(const wc_PKCS7 *p7) {
    if (p7 == 0) {
        return 0;
    }
    return (unsigned int)p7->publicKeyOID;
}

/* The digest algorithm OID from the SignerInfo. The other half of the derivation. */
unsigned int brokkr_pkcs7_hash_oid(const wc_PKCS7 *p7) {
    if (p7 == 0) {
        return 0;
    }
    return (unsigned int)p7->hashOID;
}

/* The certificate wolfSSL ACTUALLY used to verify the signature — taken from the bundle's
 * own cert array, not from what the caller supplied. Exposing it is what lets the caller
 * check that the signer is the configured anchor rather than whoever the token nominated:
 * an RFC 3161 token embeds its signer cert, so wc_PKCS7_VerifySignedData alone establishes
 * that a token is INTERNALLY CONSISTENT, not that it came from a trusted authority. */
const unsigned char *brokkr_pkcs7_verify_cert(const wc_PKCS7 *p7) {
    if (p7 == 0) {
        return 0;
    }
    return p7->verifyCert;
}

unsigned int brokkr_pkcs7_verify_cert_sz(const wc_PKCS7 *p7) {
    if (p7 == 0) {
        return 0;
    }
    return (unsigned int)p7->verifyCertSz;
}

/* ---- certificate accessors (OQGF-A-3 path validation, ARCH Rev 1.26) ----------------
 *
 * The extended-key-usage bitfield of a parsed certificate. RFC 3161 requires the TSA's
 * signing certificate to carry id-kp-timeStamping (EXTKEYUSE_TIMESTAMP, 0x20), and
 * wolfSSL_CertManagerVerifyBuffer performs path validation WITHOUT enforcing application
 * EKU policy — so nothing checks it unless the caller does.
 *
 * Same rationale as the PKCS#7 accessors: `extExtKeyUsage` itself is unguarded, but fields
 * BEFORE it in DecodedCert sit behind WOLFSSL_ASN_CA_ISSUER and WOLFSSL_AKID_NAME, so its
 * offset depends on build flags. A shim compiled with the library's own flags is told the
 * layout by the compiler rather than guessing at it. */
unsigned int brokkr_cert_ext_key_usage(const DecodedCert *dc) {
    if (dc == 0) {
        return 0;
    }
    return (unsigned int)dc->extExtKeyUsage;
}

/* Whether that extended-key-usage extension is marked CRITICAL. RFC 3161 §2.3 requires it,
 * and the requirement is not decoration: a non-critical extension MAY be ignored by a
 * verifier that does not understand it, so a certificate claiming timestamping
 * non-critically permits exactly the reading the restriction exists to forbid. Presence
 * without criticality is therefore a refusal, not a lesser pass.
 *
 * `extExtKeyUsageCrit` is a WC_BITFIELD (asn.h:2122) and bitfields BEFORE it sit behind
 * #ifdefs (WOLFSSL_ASN_CA_ISSUER, WOLFSSL_AKID_NAME, the name-constraint flags), so its bit
 * position is build-flag dependent. Rust cannot compute a bitfield offset at all; the shim
 * is told it by the compiler. Returns 0 — the refusing value — for a NULL handle. */
unsigned int brokkr_cert_ext_key_usage_crit(const DecodedCert *dc) {
    if (dc == 0) {
        return 0;
    }
    return (unsigned int)dc->extExtKeyUsageCrit;
}

/* The EXTKEYUSE_TIMESTAMP bit, so Rust does not hard-code a constant that belongs to the
 * library. */
unsigned int brokkr_extkeyuse_timestamp(void) {
    return (unsigned int)EXTKEYUSE_TIMESTAMP;
}

/* sizeof(DecodedCert), for the same opaque-buffer reason as sizeof(wc_PKCS7). */
unsigned int brokkr_decoded_cert_sizeof(void) {
    return (unsigned int)sizeof(DecodedCert);
}

/* sizeof(wc_PKCS7), so Rust can heap-allocate a correctly sized opaque buffer without
 * assuming a size — the ffi.rs pattern (probed sizes, opaque pointers), obtained from the
 * compiler instead of from a probe. */
unsigned int brokkr_pkcs7_sizeof(void) {
    return (unsigned int)sizeof(wc_PKCS7);
}
