//! wolfSSL **TLS 1.3 client** FFI, and a safe [`TlsClient`] wrapper over it.
//!
//! This is the second `unsafe` module in the crate (alongside [`ffi`](crate::ffi)); it is confined
//! to this file for the same reason and under the same discipline — every `unsafe` block carries a
//! `// SAFETY:` note, raw FFI types never escape, and the raw declarations are matched to the
//! wolfSSL v5.9.2 headers and the exported symbols in `libwolfssl.so.45` (verified via `nm -D`).
//!
//! **Why here and not in `brokkr-bifrost`.** BIFRÖST needs a real mTLS handshake to read the
//! negotiated key-exchange group, but (1) CLAUDE.md §6 forbids `unsafe` in every crate except this
//! one, and (2) `brokkr-crypto` is the sole crate that `links = "wolfssl"`. So the TLS client lives
//! here as a safe wrapper; BIFRÖST (and MÍMIR's model backend) call it without any `unsafe` of
//! their own.
//!
//! **Scope.** A minimal blocking TLS 1.3 client: mutual-auth handshake (client cert + CA
//! verification), negotiated-group readback ([`wolfSSL_get_curve_name`]), and blocking
//! write/read. No async, no pooling, no retry — a Phase-12 dev client against a known gateway.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::ffi::{CStr, CString};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::Once;

// wolfSSL return/format constants (verified against ssl.h).
const WOLFSSL_SUCCESS: c_int = 1;
const WOLFSSL_FILETYPE_PEM: c_int = 1;

// Opaque library types — only ever used behind a pointer.
#[repr(C)]
struct WolfsslMethod {
    _private: [u8; 0],
}
#[repr(C)]
struct WolfsslCtx {
    _private: [u8; 0],
}
#[repr(C)]
struct Wolfssl {
    _private: [u8; 0],
}

// ---------------------------------------------------------------------------
// Raw declarations. Private. Matched to the wolfSSL 5.9.2 ssl.h prototypes and the
// symbols exported by libwolfssl.so.45 (nm -D).
// ---------------------------------------------------------------------------
#[allow(non_snake_case)]
unsafe extern "C" {
    fn wolfSSL_Init() -> c_int;
    fn wolfTLSv1_3_client_method() -> *mut WolfsslMethod;
    fn wolfSSL_CTX_new(method: *mut WolfsslMethod) -> *mut WolfsslCtx;
    fn wolfSSL_CTX_load_verify_locations(
        ctx: *mut WolfsslCtx,
        file: *const c_char,
        path: *const c_char,
    ) -> c_int;
    fn wolfSSL_CTX_use_certificate_file(
        ctx: *mut WolfsslCtx,
        file: *const c_char,
        format: c_int,
    ) -> c_int;
    fn wolfSSL_CTX_use_PrivateKey_file(
        ctx: *mut WolfsslCtx,
        file: *const c_char,
        format: c_int,
    ) -> c_int;
    fn wolfSSL_CTX_free(ctx: *mut WolfsslCtx);
    fn wolfSSL_new(ctx: *mut WolfsslCtx) -> *mut Wolfssl;
    fn wolfSSL_set_fd(ssl: *mut Wolfssl, fd: c_int) -> c_int;
    fn wolfSSL_connect(ssl: *mut Wolfssl) -> c_int;
    fn wolfSSL_get_curve_name(ssl: *mut Wolfssl) -> *const c_char;
    fn wolfSSL_write(ssl: *mut Wolfssl, data: *const c_void, sz: c_int) -> c_int;
    fn wolfSSL_read(ssl: *mut Wolfssl, data: *mut c_void, sz: c_int) -> c_int;
    fn wolfSSL_free(ssl: *mut Wolfssl);
    fn wolfSSL_get_error(ssl: *const Wolfssl, ret: c_int) -> c_int;
}

static INIT: Once = Once::new();

/// One-time library init. `wolfSSL_Init` is reference-counted in wolfSSL, but a single call is
/// sufficient and avoids any ambiguity.
fn ensure_init() {
    INIT.call_once(|| {
        // SAFETY: no arguments; wolfSSL_Init is safe to call once at startup.
        unsafe {
            let _ = wolfSSL_Init();
        }
    });
}

/// Where and how to connect: the gateway address and the mTLS material (all PEM files).
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub host: String,
    pub port: u16,
    /// CA to verify the server against.
    pub ca_file: String,
    /// The client certificate to present (mutual TLS).
    pub client_cert_file: String,
    /// The client private key.
    pub client_key_file: String,
}

/// Why a TLS operation failed. The `i32` is the wolfSSL return / error code where applicable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    /// A path contained an interior NUL and could not be a C string.
    BadPath,
    /// `wolfTLSv1_3_client_method` / `wolfSSL_CTX_new` returned NULL.
    Context,
    /// `wolfSSL_CTX_load_verify_locations` failed (CA not loaded).
    LoadCa(i32),
    /// `wolfSSL_CTX_use_certificate_file` failed.
    LoadClientCert(i32),
    /// `wolfSSL_CTX_use_PrivateKey_file` failed.
    LoadClientKey(i32),
    /// The TCP connection to the gateway failed.
    Tcp(String),
    /// `wolfSSL_new` returned NULL.
    NewSsl,
    /// `wolfSSL_set_fd` failed.
    SetFd(i32),
    /// The TLS handshake failed (bad cert chain, client cert rejected, protocol error). Carries
    /// the `wolfSSL_get_error` code.
    Handshake(i32),
    /// A `wolfSSL_write` returned a non-positive result.
    Write(i32),
    /// A `wolfSSL_read` returned a negative result (a hard error, distinct from a clean close).
    Read(i32),
}

impl core::fmt::Display for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "tls error: {self:?}")
    }
}
impl std::error::Error for TlsError {}

fn cstr(path: &str) -> Result<CString, TlsError> {
    CString::new(path).map_err(|_| TlsError::BadPath)
}

/// A live TLS 1.3 client connection with mutual authentication.
///
/// Owns the `WOLFSSL` session, its `WOLFSSL_CTX`, and the `TcpStream` whose file descriptor the
/// session uses. Drop order frees the session, then the context; the `TcpStream` closes the socket
/// last. Not `Sync`/`Send` — a connection is used from one place at a time (each caller opens its
/// own; no pooling in Phase 12).
pub struct TlsClient {
    ssl: *mut Wolfssl,
    ctx: *mut WolfsslCtx,
    // Keeps the fd alive for the lifetime of the session (wolfSSL uses but does not own it).
    _stream: TcpStream,
}

impl TlsClient {
    /// Open a TCP connection and complete a mutual-TLS 1.3 handshake: present the client cert, and
    /// verify the server against the CA. On success the caller can read the negotiated group and
    /// exchange data.
    pub fn connect(cfg: &TlsConfig) -> Result<Self, TlsError> {
        ensure_init();
        let ca = cstr(&cfg.ca_file)?;
        let cert = cstr(&cfg.client_cert_file)?;
        let key = cstr(&cfg.client_key_file)?;

        // Connect the TCP socket first; keep the stream alive for the session's lifetime.
        let stream = TcpStream::connect((cfg.host.as_str(), cfg.port))
            .map_err(|e| TlsError::Tcp(e.to_string()))?;
        let fd = stream.as_raw_fd();

        // SAFETY: wolfTLSv1_3_client_method allocates a method; CTX_new consumes it. Both are
        // NULL-checked. On any failure below we free what we have and return, so no leak escapes.
        let ctx = unsafe {
            let method = wolfTLSv1_3_client_method();
            if method.is_null() {
                return Err(TlsError::Context);
            }
            let ctx = wolfSSL_CTX_new(method);
            if ctx.is_null() {
                return Err(TlsError::Context);
            }
            ctx
        };

        // Load CA (server verification) and the client cert+key (mutual auth). On failure free ctx.
        // SAFETY: ctx is a live context; the CString pointers are valid for the call.
        let load = unsafe {
            let r = wolfSSL_CTX_load_verify_locations(ctx, ca.as_ptr(), ptr::null());
            if r != WOLFSSL_SUCCESS {
                return Err(free_ctx_err(ctx, TlsError::LoadCa(r)));
            }
            let r = wolfSSL_CTX_use_certificate_file(ctx, cert.as_ptr(), WOLFSSL_FILETYPE_PEM);
            if r != WOLFSSL_SUCCESS {
                return Err(free_ctx_err(ctx, TlsError::LoadClientCert(r)));
            }
            let r = wolfSSL_CTX_use_PrivateKey_file(ctx, key.as_ptr(), WOLFSSL_FILETYPE_PEM);
            if r != WOLFSSL_SUCCESS {
                return Err(free_ctx_err(ctx, TlsError::LoadClientKey(r)));
            }
            Ok(())
        };
        load?;

        // SAFETY: ctx is live and configured; wolfSSL_new is NULL-checked. On failure we free ctx.
        let ssl = unsafe {
            let ssl = wolfSSL_new(ctx);
            if ssl.is_null() {
                return Err(free_ctx_err(ctx, TlsError::NewSsl));
            }
            ssl
        };

        // Bind the socket fd and handshake. On failure free ssl+ctx.
        // SAFETY: ssl is live; fd is a valid open socket owned by `stream` (kept alive below).
        let handshake = unsafe {
            let r = wolfSSL_set_fd(ssl, fd);
            if r != WOLFSSL_SUCCESS {
                return Err(free_ssl_ctx_err(ssl, ctx, TlsError::SetFd(r)));
            }
            let r = wolfSSL_connect(ssl);
            if r != WOLFSSL_SUCCESS {
                let e = wolfSSL_get_error(ssl, r);
                return Err(free_ssl_ctx_err(ssl, ctx, TlsError::Handshake(e)));
            }
            Ok(())
        };
        handshake?;

        Ok(TlsClient {
            ssl,
            ctx,
            _stream: stream,
        })
    }

    /// The **actually negotiated** key-exchange group name (e.g. `"SECP384R1"`,
    /// `"SECP384R1_MLKEM1024"`), read from the live session via `wolfSSL_get_curve_name`. This is
    /// the fact BIFRÖST maps to a channel strength — never an offered list. `None` if wolfSSL
    /// reports no name.
    pub fn negotiated_group(&self) -> Option<String> {
        // SAFETY: self.ssl is a live, handshaked session. The returned pointer, when non-NULL, is a
        // static/interned C string owned by wolfSSL; we copy it into an owned String and never
        // retain the pointer.
        unsafe {
            let p = wolfSSL_get_curve_name(self.ssl);
            if p.is_null() {
                return None;
            }
            CStr::from_ptr(p).to_str().ok().map(|s| s.to_string())
        }
    }

    /// Write all of `data`, looping over partial writes.
    pub fn write_all(&mut self, data: &[u8]) -> Result<(), TlsError> {
        let mut off = 0usize;
        while off < data.len() {
            let remaining = match data.get(off..) {
                Some(r) => r,
                None => break, // unreachable while off < len, but no indexing/panic
            };
            let len = remaining.len().min(c_int::MAX as usize) as c_int;
            // SAFETY: self.ssl is live; the pointer/len describe a valid readable slice.
            let n = unsafe { wolfSSL_write(self.ssl, remaining.as_ptr() as *const c_void, len) };
            if n <= 0 {
                return Err(TlsError::Write(n));
            }
            off += n as usize;
        }
        Ok(())
    }

    /// Read the entire response until the peer closes the connection (send `Connection: close` so
    /// this terminates). Returns all bytes received. A clean close (`read` returns 0) ends the
    /// loop; a negative `read` is a hard error.
    pub fn read_until_close(&mut self) -> Result<Vec<u8>, TlsError> {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            // SAFETY: self.ssl is live; buf is a valid writable slice of `len` bytes.
            let n = unsafe {
                wolfSSL_read(
                    self.ssl,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len() as c_int,
                )
            };
            if n > 0 {
                if let Some(chunk) = buf.get(..n as usize) {
                    out.extend_from_slice(chunk);
                }
            } else if n == 0 {
                break; // clean peer close
            } else {
                // A negative return after we already have a full response is common on close;
                // treat "we have data" as success, otherwise surface the error.
                if out.is_empty() {
                    return Err(TlsError::Read(n));
                }
                break;
            }
        }
        Ok(out)
    }
}

/// Free a context and return the given error (used on a construction failure before an `ssl`
/// exists).
fn free_ctx_err(ctx: *mut WolfsslCtx, e: TlsError) -> TlsError {
    // SAFETY: ctx is a live context we are abandoning; freeing it once is correct.
    unsafe { wolfSSL_CTX_free(ctx) };
    e
}

/// Free a session and its context and return the given error (used on a handshake failure).
fn free_ssl_ctx_err(ssl: *mut Wolfssl, ctx: *mut WolfsslCtx, e: TlsError) -> TlsError {
    // SAFETY: ssl and ctx are live and being abandoned; free session before context, each once.
    unsafe {
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
    }
    e
}

impl Drop for TlsClient {
    fn drop(&mut self) {
        // SAFETY: self.ssl and self.ctx are live and owned; free the session before the context,
        // each exactly once. The TcpStream drops afterward, closing the fd wolfSSL used.
        unsafe {
            wolfSSL_free(self.ssl);
            wolfSSL_CTX_free(self.ctx);
        }
    }
}
