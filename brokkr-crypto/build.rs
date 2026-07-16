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
//! `/home/jerem/wolfssl/build/libwolfssl.so.45.0.0` (wolfSSL v5.9.2, non-FIPS).

fn main() {
    let wolfssl_build = "/home/jerem/wolfssl/build";

    // Where to find libwolfssl.so at link time.
    println!("cargo:rustc-link-search=native={wolfssl_build}");
    // Link the shared library (libwolfssl.so -> .so.45 -> .so.45.0.0).
    println!("cargo:rustc-link-lib=dylib=wolfssl");
    // Embed an rpath so `cargo test` binaries find the .so at runtime.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{wolfssl_build}");

    println!("cargo:rerun-if-changed=build.rs");
}
