//! Safe wrapper over the Lean-extracted follower core (through glue.c), and the oracle symbols
//! the Lean code calls.
use std::ffi::c_void;

use crate::{Candidate, Config, TipView};

type Obj = *mut c_void;

unsafe extern "C" {
    fn kzg_init() -> i32;
    fn kzg_new(epoch_length: u64, from_epoch: u64, key: *const u8, key_len: usize) -> Obj;
    fn kzg_step(
        state: *mut Obj,
        height: u64,
        digest: *const u8,
        digest_len: usize,
        parent: *const u8,
        parent_len: usize,
        state_root: *const u8,
        state_root_len: usize,
        cert: *const u8,
        cert_len: usize,
        has_dkg: u8,
        dkg_epoch: u64,
        dkg_key: *const u8,
        dkg_key_len: usize,
    ) -> u8;
    fn kzg_tip_height(s: Obj) -> u64;
    fn kzg_has_tip(s: Obj) -> u8;
    fn kzg_tip_digest(s: Obj) -> Obj;
    fn kzg_tip_state_root(s: Obj) -> Obj;
    fn kzg_bytes_ptr(a: Obj) -> *const u8;
    fn kzg_bytes_len(a: Obj) -> usize;
    fn kzg_dec(o: Obj);
}

fn bytes<'a>(o: Obj) -> &'a [u8] {
    unsafe {
        let n = kzg_bytes_len(o);
        if n == 0 {
            return &[];
        }
        std::slice::from_raw_parts(kzg_bytes_ptr(o), n)
    }
}

/// Called by the Lean core: @[extern "kz_verify_finalization"]. ByteArray arguments are borrowed.
#[unsafe(no_mangle)]
pub extern "C" fn kz_verify_finalization(
    key: Obj,
    epoch: u64,
    view: u64,
    parent: u64,
    payload: Obj,
    sig: Obj,
) -> u8 {
    crate::oracle::verify_sig(bytes(key), epoch, view, parent, bytes(payload), bytes(sig)) as u8
}

/// Called by the Lean core: @[extern "kz_verify_execution"]. ByteArray arguments are borrowed.
#[unsafe(no_mangle)]
pub extern "C" fn kz_verify_execution(pre: Obj, digest: Obj, post: Obj) -> u8 {
    crate::oracle::verify_exec(bytes(pre), bytes(digest), bytes(post)) as u8
}

pub struct Core {
    state: Obj,
}

impl Core {
    pub fn new(cfg: &Config) -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            assert_eq!(
                unsafe { kzg_init() },
                0,
                "Lean module initialization failed"
            )
        });
        let k = &cfg.network_key;
        Self {
            state: unsafe { kzg_new(cfg.epoch_length, cfg.from_epoch, k.as_ptr(), k.len()) },
        }
    }

    pub fn step(&mut self, c: &Candidate) -> u8 {
        let (has, e, k) = match &c.dkg {
            Some((e, k)) => (1, *e, k.as_slice()),
            None => (0, 0, &[][..]),
        };
        unsafe {
            kzg_step(
                &mut self.state,
                c.height,
                c.digest.as_ptr(),
                c.digest.len(),
                c.parent.as_ptr(),
                c.parent.len(),
                c.state_root.as_ptr(),
                c.state_root.len(),
                c.cert.as_ptr(),
                c.cert.len(),
                has,
                e,
                k.as_ptr(),
                k.len(),
            )
        }
    }

    pub fn tip(&self) -> TipView {
        unsafe {
            if kzg_has_tip(self.state) == 0 {
                return None;
            }
            let h = kzg_tip_height(self.state);
            let d = kzg_tip_digest(self.state);
            let digest = bytes(d).to_vec();
            kzg_dec(d);
            let r = kzg_tip_state_root(self.state);
            let root = bytes(r).to_vec();
            kzg_dec(r);
            Some((h, digest, root))
        }
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        unsafe { kzg_dec(self.state) }
    }
}
