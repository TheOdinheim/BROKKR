//! The FFI boundary to wolfCrypt. **This is the only file in the workspace that
//! contains `unsafe`.** Every other module forbids it (`#![forbid(unsafe_code)]`).
//!
//! ## What is bound, and the ground truth
//!
//! Every `extern "C"` declaration below is matched to the prototype in the wolfSSL
//! v5.9.2 headers (`/home/jerem/wolfssl/wolfssl/wolfcrypt/*.h`) and the exported
//! symbol in `/home/jerem/wolfssl/build/libwolfssl.so.45.0.0` (verified via `nm -D`).
//!
//! ## Naming findings (verified, load-bearing)
//!
//! - **ML-DSA is `wc_MlDsaKey_*`, never `dilithium`.** No `dilithium`/`falcon`
//!   symbol is declared in this file. `wc_mldsa.h` is the canonical FIPS-204 API.
//! - **`wc_MlDsaKey_Sign` / `wc_MlDsaKey_Verify` do NOT exist as exported symbols**
//!   in this build (they are header-only legacy wrappers). `wc_mldsa.h:704` directs:
//!   *"New code should use `wc_MlDsaKey_SignCtx()` with ctx=NULL/ctxLen=0"*. This file
//!   binds the exported `wc_MlDsaKey_SignCtx` / `wc_MlDsaKey_VerifyCtx` with a NULL,
//!   zero-length context — the same ML-DSA algorithm and `wc_MlDsaKey` type. This
//!   deviates from the Phase-2 prompt's symbol list and is reported as a finding.
//! - **ML-KEM is `wc_MlKemKey_*`; `WC_ML_KEM_768 = 1`** (probed — a wrong value would
//!   silently select ML-KEM-512).
//!
//! ## Struct sizes
//!
//! `wc_MlDsaKey`, `MlKemKey`, and `WC_RNG` are allocated by the library's own
//! `_New`/`_new` constructors (opaque pointers — no size assumption). `SlhDsaKey`,
//! `wc_Sha384`, and `Aes` have no constructor, so they are heap byte buffers whose
//! sizes come from a `sizeof()` probe compiled against the real headers and linked
//! against the real `.so`: `SlhDsaKey`=984, `wc_Sha384`=224, `Aes`=848. The buffers
//! below are over-allocated past those sizes and 16-byte aligned (C uses only its
//! struct's real bytes within). Pinned to wolfSSL 5.9.2.

use core::ffi::{c_int, c_void};
use core::ptr;

type Byte = u8;
type Word32 = u32;

// --- Typed enum values (probed from the real headers; never strings, OQGF-G-5) ---
const WC_ML_DSA_65: Byte = 3; // wc_mldsa.h
const SLHDSA_SHAKE192S: c_int = 2; // wc_slhdsa.h enum SlhDsaParam
const WC_ML_KEM_768: c_int = 1; // wc_mlkem.h (probed)

/// ML-DSA-65 signature size (WC_MLDSA_65_SIG_SIZE, FIPS-204 params).
pub const MLDSA65_SIG_SIZE: usize = 3309;
/// SHA-384 digest size.
pub const SHA384_DIGEST_SIZE: usize = 48;
/// ML-DSA-65 public-key size (WC_MLDSA_65_PUB_KEY_SIZE; probed = 1952).
pub const MLDSA65_PUB_SIZE: usize = 1952;
/// SLH-DSA-SHAKE-192s public-key size (wc_SlhDsaKey_PublicSizeFromParam; probed = 48).
pub const SLHDSA192S_PUB_SIZE: usize = 48;
/// SLH-DSA-SHAKE-192s signature size (FIPS-205 params; probed against the linked
/// `libwolfssl` = 16224). The "small" (`s`) parameter set; distinct from the `f`/fast
/// variant's 35664. Used to cross-check the key parameterization at keygen (F-18).
pub const SLHDSA192S_SIG_SIZE: usize = 16224;

// --- Opaque, heap-allocated key types (only ever used behind a pointer) ---
#[repr(C)]
struct WcMlDsaKey {
    _private: [u8; 0],
}
#[repr(C)]
struct WcMlKemKey {
    _private: [u8; 0],
}
#[repr(C)]
struct WcRng {
    _private: [u8; 0],
}

// --- Byte-buffer structs for library types without a constructor. Sizes are the
// probed sizeof() plus margin; 16-byte alignment covers the actual (<=8) alignment.
#[repr(C, align(16))]
struct SlhDsaKeyBuf([u8; 1024]); // probe: sizeof(SlhDsaKey)=984
#[repr(C, align(16))]
struct Sha384Buf([u8; 256]); // probe: sizeof(wc_Sha384)=224
#[repr(C, align(16))]
struct AesBuf([u8; 896]); // probe: sizeof(Aes)=848

// ---------------------------------------------------------------------------
// Raw declarations. Private. Matched exactly to the header prototypes.
// ---------------------------------------------------------------------------
#[allow(non_snake_case)]
unsafe extern "C" {
    // random.h
    fn wc_rng_new(nonce: *mut Byte, nonceSz: Word32, heap: *mut c_void) -> *mut WcRng;
    fn wc_rng_free(rng: *mut WcRng);
    fn wc_RNG_GenerateBlock(rng: *mut WcRng, b: *mut Byte, sz: Word32) -> c_int;

    // wc_mldsa.h
    fn wc_MlDsaKey_New(heap: *mut c_void, devId: c_int) -> *mut WcMlDsaKey;
    fn wc_MlDsaKey_Delete(key: *mut WcMlDsaKey, key_p: *mut *mut WcMlDsaKey) -> c_int;
    fn wc_MlDsaKey_SetParams(key: *mut WcMlDsaKey, level: Byte) -> c_int;
    fn wc_MlDsaKey_MakeKey(key: *mut WcMlDsaKey, rng: *mut WcRng) -> c_int;
    fn wc_MlDsaKey_SigSize(key: *mut WcMlDsaKey) -> c_int;
    fn wc_MlDsaKey_ExportPubRaw(key: *mut WcMlDsaKey, out: *mut Byte, outLen: *mut Word32)
    -> c_int;
    fn wc_MlDsaKey_ImportPubRaw(key: *mut WcMlDsaKey, in_: *const Byte, inLen: Word32) -> c_int;
    fn wc_MlDsaKey_SignCtx(
        key: *mut WcMlDsaKey,
        ctx: *const Byte,
        ctxLen: Byte,
        sig: *mut Byte,
        sigLen: *mut Word32,
        msg: *const Byte,
        msgLen: Word32,
        rng: *mut WcRng,
    ) -> c_int;
    fn wc_MlDsaKey_VerifyCtx(
        key: *mut WcMlDsaKey,
        sig: *const Byte,
        sigLen: Word32,
        ctx: *const Byte,
        ctxLen: Byte,
        msg: *const Byte,
        msgLen: Word32,
        res: *mut c_int,
    ) -> c_int;

    // wc_slhdsa.h
    fn wc_SlhDsaKey_Init(
        key: *mut SlhDsaKeyBuf,
        param: c_int,
        heap: *mut c_void,
        devId: c_int,
    ) -> c_int;
    fn wc_SlhDsaKey_Free(key: *mut SlhDsaKeyBuf);
    fn wc_SlhDsaKey_MakeKey(key: *mut SlhDsaKeyBuf, rng: *mut WcRng) -> c_int;
    fn wc_SlhDsaKey_SigSize(key: *mut SlhDsaKeyBuf) -> c_int;
    fn wc_SlhDsaKey_ExportPublic(
        key: *mut SlhDsaKeyBuf,
        out: *mut Byte,
        outLen: *mut Word32,
    ) -> c_int;
    fn wc_SlhDsaKey_ImportPublic(key: *mut SlhDsaKeyBuf, in_: *const Byte, inLen: Word32) -> c_int;
    fn wc_SlhDsaKey_Sign(
        key: *mut SlhDsaKeyBuf,
        ctx: *const Byte,
        ctxSz: Byte,
        msg: *const Byte,
        msgSz: Word32,
        sig: *mut Byte,
        sigSz: *mut Word32,
        rng: *mut WcRng,
    ) -> c_int;
    fn wc_SlhDsaKey_Verify(
        key: *mut SlhDsaKeyBuf,
        ctx: *const Byte,
        ctxSz: Byte,
        msg: *const Byte,
        msgSz: Word32,
        sig: *const Byte,
        sigSz: Word32,
    ) -> c_int;

    // wc_mlkem.h
    fn wc_MlKemKey_New(type_: c_int, heap: *mut c_void, devId: c_int) -> *mut WcMlKemKey;
    fn wc_MlKemKey_Delete(key: *mut WcMlKemKey, key_p: *mut *mut WcMlKemKey) -> c_int;
    fn wc_MlKemKey_MakeKey(key: *mut WcMlKemKey, rng: *mut WcRng) -> c_int;
    fn wc_MlKemKey_CipherTextSize(key: *mut WcMlKemKey, len: *mut Word32) -> c_int;
    fn wc_MlKemKey_SharedSecretSize(key: *mut WcMlKemKey, len: *mut Word32) -> c_int;
    fn wc_MlKemKey_Encapsulate(
        key: *mut WcMlKemKey,
        ct: *mut Byte,
        ss: *mut Byte,
        rng: *mut WcRng,
    ) -> c_int;
    fn wc_MlKemKey_Decapsulate(
        key: *mut WcMlKemKey,
        ss: *mut Byte,
        ct: *const Byte,
        len: Word32,
    ) -> c_int;

    // sha512.h (SHA-384)
    fn wc_InitSha384(sha: *mut Sha384Buf) -> c_int;
    fn wc_Sha384Update(sha: *mut Sha384Buf, data: *const Byte, len: Word32) -> c_int;
    fn wc_Sha384Final(sha: *mut Sha384Buf, hash: *mut Byte) -> c_int;
    fn wc_Sha384Free(sha: *mut Sha384Buf);

    // aes.h (AES-256-GCM)
    fn wc_AesInit(aes: *mut AesBuf, heap: *mut c_void, devId: c_int) -> c_int;
    fn wc_AesFree(aes: *mut AesBuf);
    fn wc_AesGcmSetKey(aes: *mut AesBuf, key: *const Byte, len: Word32) -> c_int;
    fn wc_AesGcmEncrypt(
        aes: *mut AesBuf,
        out: *mut Byte,
        in_: *const Byte,
        sz: Word32,
        iv: *const Byte,
        ivSz: Word32,
        tag: *mut Byte,
        tagSz: Word32,
        aad: *const Byte,
        aadSz: Word32,
    ) -> c_int;
    fn wc_AesGcmDecrypt(
        aes: *mut AesBuf,
        out: *mut Byte,
        in_: *const Byte,
        sz: Word32,
        iv: *const Byte,
        ivSz: Word32,
        tag: *const Byte,
        tagSz: Word32,
        aad: *const Byte,
        aadSz: Word32,
    ) -> c_int;

    // ---- PKCS#7 / CMS (RFC 3161 token verification, OQGF-A-3) ----------------------
    // Enabled by the -DWOLFSSL_PKCS7=yes rebuild. `wc_PKCS7` is opaque here: it is only
    // ever held behind a pointer and sized by the shim, never laid out in Rust.
    fn wc_PKCS7_Init(pkcs7: *mut c_void, heap: *mut c_void, devId: c_int) -> c_int;
    fn wc_PKCS7_InitWithCert(pkcs7: *mut c_void, der: *mut Byte, derSz: Word32) -> c_int;
    fn wc_PKCS7_VerifySignedData(pkcs7: *mut c_void, pkiMsg: *mut Byte, pkiMsgSz: Word32) -> c_int;
    fn wc_PKCS7_Free(pkcs7: *mut c_void);

    // ---- the accessor shim (csrc/brokkr_pkcs7_shim.c; ARCH Rev 1.25 §6.9) ----------
    // Compiled with the library's own headers, so these read the same struct layout
    // wolfSSL does. They expose fields and do nothing else.
    fn brokkr_pkcs7_sizeof() -> Word32;
    fn brokkr_pkcs7_content(p7: *const c_void) -> *const Byte;
    fn brokkr_pkcs7_content_sz(p7: *const c_void) -> Word32;
    fn brokkr_pkcs7_public_key_oid(p7: *const c_void) -> Word32;
    fn brokkr_pkcs7_hash_oid(p7: *const c_void) -> Word32;
    fn brokkr_pkcs7_verify_cert(p7: *const c_void) -> *const Byte;
    fn brokkr_pkcs7_verify_cert_sz(p7: *const c_void) -> Word32;

}

/// A wolfCrypt error return (0 = success).
pub type WcResult = Result<(), i32>;

fn check(ret: c_int) -> WcResult {
    if ret == 0 { Ok(()) } else { Err(ret) }
}

// ---------------------------------------------------------------------------
// Safe RAII wrappers. Raw pointers/structs never escape this module.
// ---------------------------------------------------------------------------

/// A wolfCrypt CSPRNG (the entropy source that feeds keygen — OQGF-R-4). Seeded by
/// wolfCrypt's own `Hash-DRBG` over the platform entropy source.
pub struct Rng {
    ptr: *mut WcRng,
}

impl Rng {
    pub fn new() -> Result<Self, i32> {
        // SAFETY: wc_rng_new allocates and seeds a WC_RNG. NULL nonce (len 0) and
        // NULL heap are valid per random.h. Returns NULL on failure, checked here.
        let ptr = unsafe { wc_rng_new(ptr::null_mut(), 0, ptr::null_mut()) };
        if ptr.is_null() {
            Err(-1)
        } else {
            Ok(Rng { ptr })
        }
    }

    /// Fill `buf` with cryptographically random bytes.
    pub fn fill(&self, buf: &mut [u8]) -> WcResult {
        // SAFETY: self.ptr is a live WC_RNG (owned, not freed). buf is a valid
        // writable slice of buf.len() bytes; we pass its pointer and exact length.
        check(unsafe { wc_RNG_GenerateBlock(self.ptr, buf.as_mut_ptr(), buf.len() as Word32) })
    }
}

impl Drop for Rng {
    fn drop(&mut self) {
        // SAFETY: self.ptr came from wc_rng_new and is freed exactly once here.
        unsafe { wc_rng_free(self.ptr) };
    }
}

/// One-shot SHA-384.
pub fn sha384(msg: &[u8]) -> Result<[u8; SHA384_DIGEST_SIZE], i32> {
    let mut buf = Box::new(Sha384Buf([0u8; 256]));
    let p = &mut *buf as *mut Sha384Buf;
    let mut out = [0u8; SHA384_DIGEST_SIZE];
    // SAFETY: p points to a 256-byte, 16-aligned buffer >= sizeof(wc_Sha384)=224.
    // Init/Update/Final/Free operate on that struct; msg is a valid slice; out is
    // exactly 48 bytes (SHA-384 digest). Free is called once, unconditionally.
    let ret = unsafe {
        let r = wc_InitSha384(p);
        if r != 0 {
            wc_Sha384Free(p);
            return Err(r);
        }
        let r = wc_Sha384Update(p, msg.as_ptr(), msg.len() as Word32);
        if r != 0 {
            wc_Sha384Free(p);
            return Err(r);
        }
        let r = wc_Sha384Final(p, out.as_mut_ptr());
        wc_Sha384Free(p);
        r
    };
    check(ret).map(|()| out)
}

/// AES-256-GCM encrypt. `key` is 32 bytes, `iv` 12 bytes, tag 16 bytes.
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), i32> {
    let mut aes = Box::new(AesBuf([0u8; 896]));
    let p = &mut *aes as *mut AesBuf;
    let mut ct = vec![0u8; plaintext.len()];
    let mut tag = [0u8; 16];
    // SAFETY: p is a 896-byte 16-aligned buffer >= sizeof(Aes)=848. key is 32 bytes
    // (AES-256). ct matches plaintext length. iv is 12 bytes, tag 16. Init and Free
    // bracket the use; Free runs once on every path.
    let ret = unsafe {
        let r = wc_AesInit(p, ptr::null_mut(), -2 /* INVALID_DEVID */);
        if r != 0 {
            wc_AesFree(p);
            return Err(r);
        }
        let r = wc_AesGcmSetKey(p, key.as_ptr(), 32);
        if r != 0 {
            wc_AesFree(p);
            return Err(r);
        }
        let r = wc_AesGcmEncrypt(
            p,
            ct.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len() as Word32,
            iv.as_ptr(),
            12,
            tag.as_mut_ptr(),
            16,
            aad.as_ptr(),
            aad.len() as Word32,
        );
        wc_AesFree(p);
        r
    };
    check(ret).map(|()| (ct, tag))
}

/// AES-256-GCM decrypt. Returns Err on any failure, including an auth-tag mismatch
/// (the integrity guarantee the crypto-shred proof relies on).
pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    ciphertext: &[u8],
    tag: &[u8; 16],
    aad: &[u8],
) -> Result<Vec<u8>, i32> {
    let mut aes = Box::new(AesBuf([0u8; 896]));
    let p = &mut *aes as *mut AesBuf;
    let mut pt = vec![0u8; ciphertext.len()];
    // SAFETY: as in aes256_gcm_encrypt; a wrong key or tampered tag makes
    // wc_AesGcmDecrypt return nonzero (AES_GCM_AUTH_E), surfaced as Err.
    let ret = unsafe {
        let r = wc_AesInit(p, ptr::null_mut(), -2);
        if r != 0 {
            wc_AesFree(p);
            return Err(r);
        }
        let r = wc_AesGcmSetKey(p, key.as_ptr(), 32);
        if r != 0 {
            wc_AesFree(p);
            return Err(r);
        }
        let r = wc_AesGcmDecrypt(
            p,
            pt.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as Word32,
            iv.as_ptr(),
            12,
            tag.as_ptr(),
            16,
            aad.as_ptr(),
            aad.len() as Word32,
        );
        wc_AesFree(p);
        r
    };
    check(ret).map(|()| pt)
}

/// An ML-DSA-65 keypair (FIPS-204, lattice family). Holds priv+pub after keygen, so
/// it can both sign and verify.
pub struct MlDsa65 {
    ptr: *mut WcMlDsaKey,
    rng: Rng,
}

// SAFETY: MlDsa65 exclusively owns its key object and RNG; the pointee has no
// Rust-visible fields, so there is no Rust aliasing of its bytes. wolfCrypt key
// objects are not shared across threads in this crate's use.
unsafe impl Send for MlDsa65 {}
unsafe impl Sync for MlDsa65 {}

impl MlDsa65 {
    pub fn generate() -> Result<Self, i32> {
        let rng = Rng::new()?;
        // SAFETY: New allocates the opaque key (NULL heap, INVALID_DEVID=-2). We
        // check for NULL. SetParams(level=3=ML-DSA-65) then MakeKey with our RNG.
        let ptr = unsafe { wc_MlDsaKey_New(ptr::null_mut(), -2) };
        if ptr.is_null() {
            return Err(-1);
        }
        let me = MlDsa65 { ptr, rng };
        // SAFETY: me.ptr is a live key; level 3 is ML-DSA-65; me.rng is live.
        unsafe {
            check(wc_MlDsaKey_SetParams(me.ptr, WC_ML_DSA_65))?;
            check(wc_MlDsaKey_MakeKey(me.ptr, me.rng.ptr))?;
        }
        // Guard against silently binding a wrong-parameter algorithm.
        if me.sig_size()? != MLDSA65_SIG_SIZE {
            return Err(-2);
        }
        Ok(me)
    }

    pub fn sig_size(&self) -> Result<usize, i32> {
        // SAFETY: self.ptr is a live, parameterized key.
        let n = unsafe { wc_MlDsaKey_SigSize(self.ptr) };
        if n <= 0 { Err(n) } else { Ok(n as usize) }
    }

    /// Sign with an empty FIPS-204 context (ctx=NULL, ctxLen=0), per wc_mldsa.h:704.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, i32> {
        let mut sig = vec![0u8; self.sig_size()?];
        let mut sig_len = sig.len() as Word32;
        // SAFETY: self.ptr live; sig buffer is sig_size() bytes with sig_len set to
        // its capacity (updated to the actual length); msg is a valid slice; rng live.
        let ret = unsafe {
            wc_MlDsaKey_SignCtx(
                self.ptr,
                ptr::null(),
                0,
                sig.as_mut_ptr(),
                &mut sig_len,
                msg.as_ptr(),
                msg.len() as Word32,
                self.rng.ptr,
            )
        };
        check(ret)?;
        sig.truncate(sig_len as usize);
        Ok(sig)
    }

    /// Returns `Ok(true)` if valid, `Ok(false)` if not (any non-success is treated
    /// as not-verified, fail-closed).
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let mut res: c_int = 0;
        // SAFETY: self.ptr live; sig/msg are valid slices with their lengths; res is
        // a valid out-param. VerifyCtx uses ctx=NULL/0 to match signing.
        let ret = unsafe {
            wc_MlDsaKey_VerifyCtx(
                self.ptr,
                sig.as_ptr(),
                sig.len() as Word32,
                ptr::null(),
                0,
                msg.as_ptr(),
                msg.len() as Word32,
                &mut res,
            )
        };
        ret == 0 && res == 1
    }

    /// Export the raw ML-DSA-65 public key (1952 bytes) for a signer to publish.
    pub fn export_public(&self) -> Result<Vec<u8>, i32> {
        let mut out = vec![0u8; MLDSA65_PUB_SIZE];
        let mut out_len = out.len() as Word32;
        // SAFETY: self.ptr is a live keypair (holds the public part after MakeKey); out
        // is MLDSA65_PUB_SIZE bytes with out_len its capacity (updated to the actual
        // length written).
        let ret = unsafe { wc_MlDsaKey_ExportPubRaw(self.ptr, out.as_mut_ptr(), &mut out_len) };
        check(ret)?;
        out.truncate(out_len as usize);
        Ok(out)
    }
}

impl Drop for MlDsa65 {
    fn drop(&mut self) {
        let mut p = self.ptr;
        // SAFETY: self.ptr came from wc_MlDsaKey_New; Delete frees it once and nulls
        // our local handle.
        unsafe { wc_MlDsaKey_Delete(self.ptr, &mut p) };
    }
}

/// An SLH-DSA-SHAKE-192s keypair (FIPS-205, hash-based family).
pub struct SlhDsaShake192s {
    buf: Box<SlhDsaKeyBuf>,
    rng: Rng,
}

// SAFETY: as MlDsa65 — exclusive ownership, opaque pointee, single-threaded use.
unsafe impl Send for SlhDsaShake192s {}
unsafe impl Sync for SlhDsaShake192s {}

impl SlhDsaShake192s {
    pub fn generate() -> Result<Self, i32> {
        let rng = Rng::new()?;
        let mut me = SlhDsaShake192s {
            buf: Box::new(SlhDsaKeyBuf([0u8; 1024])),
            rng,
        };
        let p = &mut *me.buf as *mut SlhDsaKeyBuf;
        // SAFETY: p is a 1024-byte 16-aligned buffer >= sizeof(SlhDsaKey)=984. Init
        // with param SLHDSA_SHAKE192S=2, then MakeKey with our live RNG. Free is
        // handled in Drop.
        unsafe {
            check(wc_SlhDsaKey_Init(p, SLHDSA_SHAKE192S, ptr::null_mut(), -2))?;
            check(wc_SlhDsaKey_MakeKey(p, me.rng.ptr))?;
        }
        // Guard against silently binding a wrong-parameter key — symmetric with `MlDsa65::generate`
        // (F-18). The sign buffer is always sized from `sig_size()`, so this is defense-in-depth,
        // not a memory-safety fix: it catches a mis-parameterized SLH-DSA key at keygen rather than
        // trusting the library.
        if me.sig_size()? != SLHDSA192S_SIG_SIZE {
            return Err(-2);
        }
        Ok(me)
    }

    pub fn sig_size(&self) -> Result<usize, i32> {
        let p = &*self.buf as *const SlhDsaKeyBuf as *mut SlhDsaKeyBuf;
        // SAFETY: p points to the live, initialized key.
        let n = unsafe { wc_SlhDsaKey_SigSize(p) };
        if n <= 0 { Err(n) } else { Ok(n as usize) }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, i32> {
        let p = &*self.buf as *const SlhDsaKeyBuf as *mut SlhDsaKeyBuf;
        let mut sig = vec![0u8; self.sig_size()?];
        let mut sig_len = sig.len() as Word32;
        // SAFETY: p live; ctx=NULL/0; msg valid; sig buffer is sig_size() bytes with
        // sig_len its capacity; rng live.
        let ret = unsafe {
            wc_SlhDsaKey_Sign(
                p,
                ptr::null(),
                0,
                msg.as_ptr(),
                msg.len() as Word32,
                sig.as_mut_ptr(),
                &mut sig_len,
                self.rng.ptr,
            )
        };
        check(ret)?;
        sig.truncate(sig_len as usize);
        Ok(sig)
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let p = &*self.buf as *const SlhDsaKeyBuf as *mut SlhDsaKeyBuf;
        // SAFETY: p live; msg/sig valid slices. Verify returns 0 iff valid.
        let ret = unsafe {
            wc_SlhDsaKey_Verify(
                p,
                ptr::null(),
                0,
                msg.as_ptr(),
                msg.len() as Word32,
                sig.as_ptr(),
                sig.len() as Word32,
            )
        };
        ret == 0
    }

    /// Export the raw SLH-DSA-SHAKE-192s public key (48 bytes) for a signer to publish.
    pub fn export_public(&self) -> Result<Vec<u8>, i32> {
        let p = &*self.buf as *const SlhDsaKeyBuf as *mut SlhDsaKeyBuf;
        let mut out = vec![0u8; SLHDSA192S_PUB_SIZE];
        let mut out_len = out.len() as Word32;
        // SAFETY: p is a live, initialized key (holds the public part after MakeKey); out
        // is SLHDSA192S_PUB_SIZE bytes with out_len its capacity.
        let ret = unsafe { wc_SlhDsaKey_ExportPublic(p, out.as_mut_ptr(), &mut out_len) };
        check(ret)?;
        out.truncate(out_len as usize);
        Ok(out)
    }
}

impl Drop for SlhDsaShake192s {
    fn drop(&mut self) {
        let p = &mut *self.buf as *mut SlhDsaKeyBuf;
        // SAFETY: p is the live key initialized in generate(); Free runs once.
        unsafe { wc_SlhDsaKey_Free(p) };
    }
}

/// An ML-KEM-768 keypair. Encapsulation uses the public part, decapsulation the
/// private part; both live in one key object after keygen.
pub struct MlKem768 {
    ptr: *mut WcMlKemKey,
    rng: Rng,
    destroyed: bool,
}

// SAFETY: as MlDsa65.
unsafe impl Send for MlKem768 {}
unsafe impl Sync for MlKem768 {}

impl MlKem768 {
    pub fn generate() -> Result<Self, i32> {
        let rng = Rng::new()?;
        // SAFETY: New(type=WC_ML_KEM_768=1) allocates the opaque key; checked for
        // NULL. MakeKey with our RNG.
        let ptr = unsafe { wc_MlKemKey_New(WC_ML_KEM_768, ptr::null_mut(), -2) };
        if ptr.is_null() {
            return Err(-1);
        }
        let me = MlKem768 {
            ptr,
            rng,
            destroyed: false,
        };
        // SAFETY: me.ptr live; me.rng live.
        unsafe { check(wc_MlKemKey_MakeKey(me.ptr, me.rng.ptr))? };
        Ok(me)
    }

    pub fn ciphertext_size(&self) -> Result<usize, i32> {
        // A-1 — guard against use after destroy(), symmetric with decapsulate: once destroyed,
        // self.ptr is null, so refuse here rather than pass a null pointer across the FFI.
        if self.destroyed {
            return Err(-99);
        }
        let mut n: Word32 = 0;
        // SAFETY: guarded above, so self.ptr is a live key (not the post-destroy null); n is a
        // valid out-param.
        check(unsafe { wc_MlKemKey_CipherTextSize(self.ptr, &mut n) }).map(|()| n as usize)
    }

    pub fn shared_secret_size(&self) -> Result<usize, i32> {
        // A-1 — guard against use after destroy() (see ciphertext_size).
        if self.destroyed {
            return Err(-99);
        }
        let mut n: Word32 = 0;
        // SAFETY: guarded above, so self.ptr is a live key (not the post-destroy null); n is a
        // valid out-param.
        check(unsafe { wc_MlKemKey_SharedSecretSize(self.ptr, &mut n) }).map(|()| n as usize)
    }

    /// Encapsulate to this key's public part. Returns (ciphertext, shared_secret).
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), i32> {
        // A-1 — guard against use after destroy(), symmetric with decapsulate. (The size queries
        // below also guard, but the explicit check keeps the invariant local and the SAFETY note
        // honest.)
        if self.destroyed {
            return Err(-99);
        }
        let mut ct = vec![0u8; self.ciphertext_size()?];
        let mut ss = vec![0u8; self.shared_secret_size()?];
        // SAFETY: guarded above, so self.ptr is a live key (not the post-destroy null); ct/ss
        // buffers are sized by the library's own size queries above; rng live.
        let ret = unsafe {
            wc_MlKemKey_Encapsulate(self.ptr, ct.as_mut_ptr(), ss.as_mut_ptr(), self.rng.ptr)
        };
        check(ret).map(|()| (ct, ss))
    }

    /// Decapsulate with this key's private part. Fails if the key was destroyed.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Vec<u8>, i32> {
        if self.destroyed {
            return Err(-99);
        }
        let mut ss = vec![0u8; self.shared_secret_size()?];
        // SAFETY: self.ptr live (not destroyed); ss sized by the library; ct is a
        // valid slice with its length.
        let ret = unsafe {
            wc_MlKemKey_Decapsulate(self.ptr, ss.as_mut_ptr(), ct.as_ptr(), ct.len() as Word32)
        };
        check(ret).map(|()| ss)
    }

    /// Durably destroy the private key — the crypto-shred act. After this, the key
    /// object is freed and decapsulation is impossible, so anything wrapped to it is
    /// irrecoverable. Idempotent.
    pub fn destroy(&mut self) {
        if !self.destroyed {
            let mut p = self.ptr;
            // SAFETY: self.ptr came from wc_MlKemKey_New; Delete zeroizes and frees
            // the key material once. We mark destroyed so no further use occurs and
            // Drop does not double-free.
            unsafe { wc_MlKemKey_Delete(self.ptr, &mut p) };
            self.ptr = ptr::null_mut();
            self.destroyed = true;
        }
    }
}

impl Drop for MlKem768 {
    fn drop(&mut self) {
        self.destroy();
    }
}

/// A **verify-only** ML-DSA-65 public key — holds no private material. Built by
/// importing raw public-key bytes (e.g. from an OQGF-M-1 attestation).
pub struct MlDsa65Public {
    ptr: *mut WcMlDsaKey,
}

// SAFETY: exclusive ownership of an opaque public-only key; no Rust-visible pointee
// fields; single-threaded use.
unsafe impl Send for MlDsa65Public {}
unsafe impl Sync for MlDsa65Public {}

impl MlDsa65Public {
    /// Import a raw ML-DSA-65 public key. **Fail-closed** on a wrong length: a malformed
    /// attestation key must not sail through.
    pub fn from_public_bytes(pubkey: &[u8]) -> Result<Self, i32> {
        if pubkey.len() != MLDSA65_PUB_SIZE {
            return Err(-100); // malformed key: wrong public-key length
        }
        // SAFETY: New allocates the opaque key (checked for NULL). SetParams(65) so the
        // raw bytes are interpreted as ML-DSA-65, then ImportPubRaw loads the public key.
        let ptr = unsafe { wc_MlDsaKey_New(ptr::null_mut(), -2) };
        if ptr.is_null() {
            return Err(-1);
        }
        let me = MlDsa65Public { ptr };
        // SAFETY: me.ptr live; pubkey is exactly MLDSA65_PUB_SIZE bytes.
        unsafe {
            check(wc_MlDsaKey_SetParams(me.ptr, WC_ML_DSA_65))?;
            check(wc_MlDsaKey_ImportPubRaw(
                me.ptr,
                pubkey.as_ptr(),
                pubkey.len() as Word32,
            ))?;
        }
        Ok(me)
    }

    /// Verify with the imported public key. `true` iff valid; any non-success is
    /// not-verified (fail-closed).
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let mut res: c_int = 0;
        // SAFETY: self.ptr is a live public key; sig/msg valid slices; res a valid
        // out-param; ctx=NULL/0 matches signing.
        let ret = unsafe {
            wc_MlDsaKey_VerifyCtx(
                self.ptr,
                sig.as_ptr(),
                sig.len() as Word32,
                ptr::null(),
                0,
                msg.as_ptr(),
                msg.len() as Word32,
                &mut res,
            )
        };
        ret == 0 && res == 1
    }
}

impl Drop for MlDsa65Public {
    fn drop(&mut self) {
        let mut p = self.ptr;
        // SAFETY: self.ptr came from wc_MlDsaKey_New; Delete frees it once.
        unsafe { wc_MlDsaKey_Delete(self.ptr, &mut p) };
    }
}

/// A **verify-only** SLH-DSA-SHAKE-192s public key — holds no private material.
pub struct SlhDsaShake192sPublic {
    buf: Box<SlhDsaKeyBuf>,
}

// SAFETY: as SlhDsaShake192s — exclusive ownership, opaque pointee, single-threaded use.
unsafe impl Send for SlhDsaShake192sPublic {}
unsafe impl Sync for SlhDsaShake192sPublic {}

impl SlhDsaShake192sPublic {
    /// Import a raw SLH-DSA-SHAKE-192s public key. **Fail-closed** on a wrong length.
    pub fn from_public_bytes(pubkey: &[u8]) -> Result<Self, i32> {
        if pubkey.len() != SLHDSA192S_PUB_SIZE {
            return Err(-100);
        }
        let me = SlhDsaShake192sPublic {
            buf: Box::new(SlhDsaKeyBuf([0u8; 1024])),
        };
        let p = &*me.buf as *const SlhDsaKeyBuf as *mut SlhDsaKeyBuf;
        // SAFETY: p is a 1024-byte 16-aligned buffer >= sizeof(SlhDsaKey)=984. Init sets
        // the SHAKE-192s param, then ImportPublic loads the public key. Free in Drop.
        // pubkey is exactly SLHDSA192S_PUB_SIZE bytes.
        unsafe {
            check(wc_SlhDsaKey_Init(p, SLHDSA_SHAKE192S, ptr::null_mut(), -2))?;
            check(wc_SlhDsaKey_ImportPublic(
                p,
                pubkey.as_ptr(),
                pubkey.len() as Word32,
            ))?;
        }
        Ok(me)
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let p = &*self.buf as *const SlhDsaKeyBuf as *mut SlhDsaKeyBuf;
        // SAFETY: p is a live public key; msg/sig valid slices. Verify returns 0 iff valid.
        let ret = unsafe {
            wc_SlhDsaKey_Verify(
                p,
                ptr::null(),
                0,
                msg.as_ptr(),
                msg.len() as Word32,
                sig.as_ptr(),
                sig.len() as Word32,
            )
        };
        ret == 0
    }
}

impl Drop for SlhDsaShake192sPublic {
    fn drop(&mut self) {
        let p = &mut *self.buf as *mut SlhDsaKeyBuf;
        // SAFETY: p is the live key initialized in from_public_bytes; Free runs once.
        unsafe { wc_SlhDsaKey_Free(p) };
    }
}

// =========================================================================================
// PKCS#7 / CMS verification for RFC 3161 (OQGF-A-3; ARCH Rev 1.25 §6.9)
// =========================================================================================

/// What a verified CMS `SignedData` yields: the authenticated eContent and the two OIDs
/// the signature algorithm is **derived** from.
///
/// `SignerInfo.signatureAlgorithm` — the field that names the algorithm outright — is
/// consumed by wolfSSL during parsing and retained in no struct field, so no accessor can
/// expose it (ARCH Rev 1.25 §6.9, recorded as an unplaced rule in the §5.4 table). Both
/// OIDs are carried out raw so the derivation can be checked rather than trusted.
pub struct VerifiedCms {
    /// The DER `TSTInfo`. **Authenticated** — the CMS signature over it verified against
    /// the supplied trust anchor — but not thereby *trustworthy*: a compromised authority
    /// can sign arbitrary content.
    pub content: Vec<u8>,
    /// `wc_PKCS7::publicKeyOID` — the signer's key type.
    pub key_oid: u32,
    /// `wc_PKCS7::hashOID` — the digest algorithm from the `SignerInfo`.
    pub hash_oid: u32,
    /// The certificate wolfSSL actually used to verify — checked against the configured
    /// anchor by [`cms_verify`], because a token embeds its own signer certificate.
    pub used_cert: Vec<u8>,
}

/// Why a CMS verification failed.
///
/// **The two variants are kept apart deliberately**, because the caller maps them to
/// `TimestampError::Malformed` and `TimestampError::SignatureInvalid`, and ARCH Rev 1.24
/// §6.9 is explicit that *"`Malformed` means 'this did not parse'"* and must not absorb a
/// signature failure. Collapsing them here would make that distinction unrecoverable at
/// the only layer that can report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmsError {
    /// The bundle did not parse as CMS `SignedData` (`ASN_PARSE_E`, `ASN_INPUT_E`, or a
    /// setup failure before any signature was examined).
    Malformed,
    /// It parsed, and the signature did not verify against the supplied trust anchor
    /// (`ASN_SIG_CONFIRM_E`, `SIG_VERIFY_E`).
    SignatureInvalid,
}

/// `wolfssl/wolfcrypt/error-crypt.h`: ASN parsing error, invalid input.
const ASN_PARSE_E: c_int = -140;
/// `error-crypt.h`: ASN signature error, confirm failure.
const ASN_SIG_CONFIRM_E: c_int = -155;
/// `error-crypt.h`: wolfcrypt signature verify error.
const SIG_VERIFY_E: c_int = -229;

/// Map a `wc_PKCS7_VerifySignedData` return code to the two outcomes the caller must tell
/// apart. Anything that is neither a recognized parse error nor a recognized signature
/// error is reported as `Malformed` — **the fail-closed direction**: an unrecognized
/// failure has not established that a signature was checked and found wrong, so claiming
/// `SignatureInvalid` would assert more than was observed.
fn cms_error_from(rc: c_int) -> CmsError {
    match rc {
        ASN_SIG_CONFIRM_E | SIG_VERIFY_E => CmsError::SignatureInvalid,
        ASN_PARSE_E => CmsError::Malformed,
        _ => CmsError::Malformed,
    }
}

/// Verify a CMS `SignedData` bundle against `trust_anchor_der`, returning the
/// authenticated eContent and the derivation OIDs.
pub fn cms_verify(bundle: &[u8], trust_anchor_der: &[u8]) -> Result<VerifiedCms, CmsError> {
    // The wc_PKCS7 handle is opaque: sized by the shim (which asks the compiler) and only
    // ever held behind a pointer. This is the ffi.rs discipline — no Rust-side layout
    // assumption — with the size obtained from the compiler rather than from a probe.
    // SAFETY: brokkr_pkcs7_sizeof is a pure `sizeof` in the shim; no pointers involved.
    let size = unsafe { brokkr_pkcs7_sizeof() } as usize;
    if size == 0 {
        return Err(CmsError::Malformed);
    }
    let mut handle: Vec<u8> = vec![0u8; size];
    let p = handle.as_mut_ptr().cast::<c_void>();

    let mut anchor = trust_anchor_der.to_vec();
    let mut msg = bundle.to_vec();

    // SAFETY: `p` points to a zeroed buffer of exactly sizeof(wc_PKCS7), which is what
    // wc_PKCS7_Init requires. heap=NULL and devId=INVALID_DEVID(-2) match the crate's
    // existing calls. On any failure we free before returning, and the buffer outlives
    // every call because `handle` is not dropped until the end of the function.
    let out = unsafe {
        if wc_PKCS7_Init(p, ptr::null_mut(), -2) != 0 {
            return Err(CmsError::Malformed);
        }
        // InitWithCert supplies the trust anchor. wolfSSL takes the cert by pointer for
        // the lifetime of the handle; `anchor` outlives the Free below.
        if wc_PKCS7_InitWithCert(p, anchor.as_mut_ptr(), anchor.len() as Word32) != 0 {
            wc_PKCS7_Free(p);
            return Err(CmsError::Malformed);
        }
        let rc = wc_PKCS7_VerifySignedData(p, msg.as_mut_ptr(), msg.len() as Word32);
        if rc != 0 {
            wc_PKCS7_Free(p);
            return Err(cms_error_from(rc));
        }
        // Only after a successful verify are the content accessors meaningful.
        let content_ptr = brokkr_pkcs7_content(p);
        let content_sz = brokkr_pkcs7_content_sz(p) as usize;
        let content = if content_ptr.is_null() || content_sz == 0 {
            Vec::new()
        } else {
            core::slice::from_raw_parts(content_ptr, content_sz).to_vec()
        };
        // WHICH certificate actually verified this signature. An RFC 3161 token EMBEDS its
        // signer certificate, so `wc_PKCS7_VerifySignedData` succeeding establishes only
        // that the token is **internally consistent** — the token vouching for itself. That
        // is the circularity ARCH Rev 1.24 §6.9 forbids ("a pre-configured trust anchor,
        // never one taken from the token itself"), and it is caught here rather than
        // assumed away: found because a token verified under an unrelated anchor.
        let cert_ptr = brokkr_pkcs7_verify_cert(p);
        let cert_sz = brokkr_pkcs7_verify_cert_sz(p) as usize;
        let used_cert = if cert_ptr.is_null() || cert_sz == 0 {
            Vec::new()
        } else {
            core::slice::from_raw_parts(cert_ptr, cert_sz).to_vec()
        };
        let v = VerifiedCms {
            content,
            key_oid: brokkr_pkcs7_public_key_oid(p),
            hash_oid: brokkr_pkcs7_hash_oid(p),
            used_cert,
        };
        wc_PKCS7_Free(p);
        v
    };

    // **Anchor pinning.** The signature verified — but under whose certificate? Require it
    // to be the one configured. `SignatureInvalid` is the honest mapping: the requirement
    // is that the signature verify *against the configured trust anchor*, and it did not.
    //
    // LIMIT, stated rather than implied: this is **pinning, not chain validation**. It
    // holds when the authority's signing certificate IS the anchor (a self-signed TSA, and
    // the local test responder). A TSA whose signing certificate is issued by a CA would
    // need path building and validation, which is not implemented here.
    if out.used_cert != trust_anchor_der {
        return Err(CmsError::SignatureInvalid);
    }

    if out.content.is_empty() {
        return Err(CmsError::Malformed);
    }
    Ok(out)
}
