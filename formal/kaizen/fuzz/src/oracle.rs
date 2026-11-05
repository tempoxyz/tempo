//! Oracles shared by both sides. The Lean core reaches them through the C symbols
//! kz_verify_finalization / kz_verify_execution (core.rs); the reference calls them directly.
//! Every call is logged so the harness can check both sides query the oracles identically.
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    sync::Mutex,
};

use commonware_codec::DecodeExt as _;
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf::{Certificate, Scheme},
        types::{Finalization, Proposal},
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    ed25519::PublicKey,
    sha256::Digest,
};
use commonware_parallel::Sequential;
use sha2::{Digest as _, Sha256};

/// Tempo's consensus namespace (crates/consensus/src/config.rs).
pub const NAMESPACE: &[u8] = b"TEMPO";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Deterministic fake signatures (fake_sig) and execution (exec_root), so generators can
    /// build valid chains.
    Fake,
    /// Every signature and execution is valid (replaying real certificates in the fuzzer).
    AcceptAll,
    /// Real BLS12-381 threshold verification (copied from shim's verify_finalization),
    /// execution always valid.
    RealBls,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    Sig {
        key: Vec<u8>,
        epoch: u64,
        view: u64,
        parent: u64,
        payload: Vec<u8>,
        sig: Vec<u8>,
        ok: bool,
    },
    Exec {
        pre: Vec<u8>,
        digest: Vec<u8>,
        post: Vec<u8>,
        ok: bool,
    },
}

thread_local! {
    static MODE: Cell<Mode> = const { Cell::new(Mode::Fake) };
    static LOG: RefCell<Vec<Call>> = const { RefCell::new(Vec::new()) };
}

pub fn set_mode(m: Mode) {
    MODE.with(|c| c.set(m));
}

pub fn mode() -> Mode {
    MODE.with(|c| c.get())
}

/// Take the calls logged since the last take.
pub fn take_log() -> Vec<Call> {
    LOG.with(|l| std::mem::take(&mut *l.borrow_mut()))
}

fn log(c: Call) {
    LOG.with(|l| l.borrow_mut().push(c));
}

/// First 96 bytes of sha256-expanded(key || epoch || view || parent || payload)
/// (block i = sha256(i || len(key) || key || epoch || view || parent || payload)).
pub fn fake_sig(key: &[u8], epoch: u64, view: u64, parent: u64, payload: &[u8]) -> [u8; 96] {
    let mut out = [0u8; 96];
    for i in 0..3u8 {
        let mut h = Sha256::new();
        h.update([i]);
        h.update((key.len() as u64).to_be_bytes());
        h.update(key);
        h.update(epoch.to_be_bytes());
        h.update(view.to_be_bytes());
        h.update(parent.to_be_bytes());
        h.update(payload);
        out[32 * i as usize..32 * (i as usize + 1)].copy_from_slice(&h.finalize());
    }
    out
}

/// Fake execution: post-state root = sha256(pre || digest).
pub fn exec_root(pre: &[u8], digest: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((pre.len() as u64).to_be_bytes());
    h.update(pre);
    h.update(digest);
    h.finalize().into()
}

pub fn verify_sig(
    key: &[u8],
    epoch: u64,
    view: u64,
    parent: u64,
    payload: &[u8],
    sig: &[u8],
) -> bool {
    let ok = match mode() {
        Mode::Fake => sig == fake_sig(key, epoch, view, parent, payload).as_slice(),
        Mode::AcceptAll => true,
        Mode::RealBls => verify_finalization(key, epoch, view, parent, payload, sig),
    };
    log(Call::Sig {
        key: key.to_vec(),
        epoch,
        view,
        parent,
        payload: payload.to_vec(),
        sig: sig.to_vec(),
        ok,
    });
    ok
}

pub fn verify_exec(pre: &[u8], digest: &[u8], post: &[u8]) -> bool {
    let ok = match mode() {
        Mode::Fake => post == exec_root(pre, digest).as_slice(),
        Mode::AcceptAll | Mode::RealBls => true,
    };
    log(Call::Exec {
        pre: pre.to_vec(),
        digest: digest.to_vec(),
        post: post.to_vec(),
        ok,
    });
    ok
}

/// Copied from shim/src/main.rs: does the threshold signature finalize exactly this proposal
/// under this identity?
pub fn verify_finalization(
    key: &[u8],
    epoch: u64,
    view: u64,
    parent: u64,
    payload: &[u8],
    sig: &[u8],
) -> bool {
    static SCHEMES: Mutex<Option<HashMap<Vec<u8>, Scheme<PublicKey, MinSig>>>> = Mutex::new(None);
    let Ok(payload) = <[u8; 32]>::try_from(payload) else {
        return false;
    };
    let Ok(certificate) = Certificate::<MinSig>::decode(sig) else {
        return false;
    };
    let scheme = {
        let mut guard = SCHEMES.lock().unwrap();
        let map = guard.get_or_insert_with(HashMap::new);
        match map.get(key) {
            Some(s) => s.clone(),
            None => {
                let Ok(identity) = <MinSig as Variant>::Public::decode(key) else {
                    return false;
                };
                let s = Scheme::<PublicKey, MinSig>::certificate_verifier(NAMESPACE, identity);
                map.insert(key.to_vec(), s.clone());
                s
            }
        }
    };
    let finalization = Finalization::<Scheme<PublicKey, MinSig>, Digest> {
        proposal: Proposal::new(
            Round::new(Epoch::new(epoch), View::new(view)),
            View::new(parent),
            Digest(payload),
        ),
        certificate,
    };
    finalization.verify(&mut rand::rng(), &scheme, &Sequential)
}
