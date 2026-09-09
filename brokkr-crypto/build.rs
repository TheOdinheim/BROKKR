//! Link configuration for brokkr-crypto.
//!
//! Choice (stated per the Phase 2 prompt): I emit explicit
//! `rustc-link-search` + `rustc-link-lib` rather than relying on `PKG_CONFIG_PATH`,
//! because the two `wolfssl.pc` files are not on the default pkg-config path and
//! hard-coding a single verified library location is more transparent and has no
//! pkg-config dependency. I also emit an rpath so the test binaries load
//! `libwolfssl.so.45` at runtime without needing `LD_LIBRARY_PATH`.
//!
//! The library is the exact one whose symbols were verified for Phase 2:
//! `/home/jerem/wolfssl/build/libwolfssl.so.45.0.0` (wolfSSL v5.9.2, non-FIPS),
//! rebuilt with `-DWOLFSSL_PKCS7=yes` for OQGF-A-3 (ARCH Rev 1.24 §6.9).
//!
//! ## The PKCS#7 accessor shim (ARCH Rev 1.25 §6.9)
//!
//! `csrc/brokkr_pkcs7_shim.c` is compiled here and linked as a static archive. §6 reserves
//! dependency decisions to the DAP, and the DAP directed the **direct-invocation** route
//! rather than the `cc` crate — so this file invokes the compiler itself and adds no
//! `[build-dependencies]`. That matches the repository's hand-rolled precedents
//! (`ollama.rs`'s HTTP, `canonical.rs`'s encoding) at the cost of doing flag discovery by
//! hand, which is bounded here because there is exactly one target and one library.
//!
//! **The shim is compiled against the same headers as the linked library** — that is the
//! entire reason it is sound (§6.9): it is told the `wc_PKCS7` layout by the compiler
//! rather than guessing at a layout C preprocessor state determines.

use std::process::Command;

fn main() {
    let wolfssl_build = "/home/jerem/wolfssl/build";
    let wolfssl_src = "/home/jerem/wolfssl";
    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| String::from("."));

    // ---- the PKCS#7 accessor shim ------------------------------------------------------
    // Compiled with the same include path as the library it reads the layout of. The
    // wolfSSL build directory carries the generated `options.h` that records the flags the
    // library was built with; including it before `pkcs7.h` is what makes this shim see the
    // same struct layout wolfSSL does.
    let cc = std::env::var("CC").unwrap_or_else(|_| String::from("cc"));
    let obj = format!("{out_dir}/brokkr_pkcs7_shim.o");
    let lib = format!("{out_dir}/libbrokkr_pkcs7_shim.a");

    let status = Command::new(&cc)
        .args([
            "-c",
            "-O2",
            "-fPIC",
            "-Wall",
            "-Wextra",
            "-Werror",
            // The library's own generated options header and its public headers.
            &format!("-I{wolfssl_build}"),
            &format!("-I{wolfssl_src}"),
            "-o",
            &obj,
            "csrc/brokkr_pkcs7_shim.c",
        ])
        .status()
        .expect("failed to invoke the C compiler for the PKCS#7 accessor shim");
    assert!(status.success(), "compiling brokkr_pkcs7_shim.c failed");

    let status = Command::new("ar")
        .args(["crus", &lib, &obj])
        .status()
        .expect("failed to invoke ar for the PKCS#7 accessor shim");
    assert!(status.success(), "archiving brokkr_pkcs7_shim.a failed");

    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static=brokkr_pkcs7_shim");
    println!("cargo:rerun-if-changed=csrc/brokkr_pkcs7_shim.c");

    // ---- wolfSSL -----------------------------------------------------------------------
    // Where to find libwolfssl.so at link time.
    println!("cargo:rustc-link-search=native={wolfssl_build}");
    // Link the shared library (libwolfssl.so -> .so.45 -> .so.45.0.0).
    println!("cargo:rustc-link-lib=dylib=wolfssl");
    // Embed an rpath so `cargo test` binaries find the .so at runtime.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{wolfssl_build}");

    println!("cargo:rerun-if-changed=build.rs");
}
