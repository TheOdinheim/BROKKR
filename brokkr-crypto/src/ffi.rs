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
        let mut n: Word32 = 0;
        // SAFETY: self.ptr live; n is a valid out-param.
        check(unsafe { wc_MlKemKey_CipherTextSize(self.ptr, &mut n) }).map(|()| n as usize)
    }

    pub fn shared_secret_size(&self) -> Result<usize, i32> {
        let mut n: Word32 = 0;
        // SAFETY: self.ptr live; n is a valid out-param.
        check(unsafe { wc_MlKemKey_SharedSecretSize(self.ptr, &mut n) }).map(|()| n as usize)
    }

    /// Encapsulate to this key's public part. Returns (ciphertext, shared_secret).
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), i32> {
        let mut ct = vec![0u8; self.ciphertext_size()?];
        let mut ss = vec![0u8; self.shared_secret_size()?];
        // SAFETY: self.ptr live; ct/ss buffers are sized by the library's own size
        // queries above; rng live.
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
