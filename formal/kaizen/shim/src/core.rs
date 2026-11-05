//! Safe wrapper over the Lean-extracted follower core (through glue.c).
use std::ffi::c_void;

type Obj = *mut c_void;

unsafe extern "C" {
    fn kzg_init() -> i32;
    fn kzg_new(epoch_length: u64, from_epoch: u64, key: *const u8, key_len: usize) -> Obj;
    fn kzg_step(
        state: *mut Obj,
        height: u64,
        digest: *const u8,
        parent: *const u8,
        cert: *const u8,
        cert_len: usize,
        has_dkg: u8,
        dkg_epoch: u64,
        dkg_key: *const u8,
        dkg_key_len: usize,
    ) -> u8;
    fn kzg_tip_height(s: Obj) -> u64;
    fn kzg_has_tip(s: Obj) -> u8;
    fn kzg_tip_digest(s: Obj, out: *mut u8);
    fn kzg_bytes_ptr(a: Obj) -> *const u8;
    fn kzg_bytes_len(a: Obj) -> usize;
    fn kzg_dec(o: Obj);
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
    let bytes = |o: Obj| unsafe { std::slice::from_raw_parts(kzg_bytes_ptr(o), kzg_bytes_len(o)) };
    crate::verify_finalization(bytes(key), epoch, view, parent, bytes(payload), bytes(sig)) as u8
}

pub(crate) struct Core {
    state: Obj,
}

impl Core {
    pub(crate) fn new(epoch_length: u64, from_epoch: u64, key: &[u8]) -> eyre::Result<Self> {
        static INIT: std::sync::Once = std::sync::Once::new();
        let mut rc = 0;
        INIT.call_once(|| rc = unsafe { kzg_init() });
        if rc != 0 {
            eyre::bail!("Lean module initialization failed");
        }
        Ok(Self {
            state: unsafe { kzg_new(epoch_length, from_epoch, key.as_ptr(), key.len()) },
        })
    }

    pub(crate) fn step(&mut self, c: &crate::Candidate) -> u8 {
        let (has, e, k) = match &c.dkg {
            Some((e, k)) => (1, *e, k.as_slice()),
            None => (0, 0, &[][..]),
        };
        unsafe {
            kzg_step(
                &mut self.state,
                c.height,
                c.digest.as_ptr(),
                c.parent.as_ptr(),
                c.certificate.as_ptr(),
                c.certificate.len(),
                has,
                e,
                k.as_ptr(),
                k.len(),
            )
        }
    }

    pub(crate) fn tip_height(&self) -> u64 {
        unsafe { kzg_tip_height(self.state) }
    }

    #[allow(dead_code)]
    pub(crate) fn has_tip(&self) -> bool {
        unsafe { kzg_has_tip(self.state) != 0 }
    }

    pub(crate) fn tip_digest(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe { kzg_tip_digest(self.state, out.as_mut_ptr()) };
        out
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        unsafe { kzg_dec(self.state) }
    }
}

/// Result codes of the Lean core's step function (Kaizen/FFI.lean).
pub(crate) fn describe(code: u8) -> &'static str {
    match code {
        0 => "accepted",
        1 => "malformed certificate",
        2 => "certificate payload is not the block digest",
        3 => "certificate epoch does not contain the block height",
        4 => "no identity for the epoch",
        5 => "bad threshold signature",
        6 => "height is not tip + 1",
        7 => "parent digest is not the tip digest",
        8 => "round not increasing",
        9 => "boundary block without DKG outcome",
        10 => "DKG outcome for the wrong epoch",
        11 => "bad configuration",
        _ => "unknown code",
    }
}
