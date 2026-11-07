//! Candidate generators driven by arbitrary::Unstructured: fully random candidates, replays,
//! and valid next blocks (encoded with commonware's Encode, signed by the fake oracle) followed
//! by field mutations, non-canonical/oversized varint encodings and byte-level mutations.
use arbitrary::{Result, Unstructured};
use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::types::Proposal,
    types::{Epoch, Round, View},
};
use commonware_cryptography::sha256::Digest;
use sha2::{Digest as _, Sha256};

use crate::{
    Candidate, Config,
    oracle::{exec_root, fake_sig},
    reference::RefState,
};

/// Deterministic 96-byte keys.
pub fn pool_key(i: u8) -> Vec<u8> {
    fake_sig(b"pool", i as u64, 0, 0, b"key").to_vec()
}

pub fn config(u: &mut Unstructured) -> Result<Config> {
    let epoch_length = match u.int_in_range(0u8..=31)? {
        0 => 0,
        1 => 1,
        2..=7 => 2,
        8..=12 => 3,
        13..=15 => 4,
        16..=17 => 5,
        18..=19 => 7,
        20..=21 => 10,
        22..=23 => 21600,
        24 => u64::MAX,
        25 => u64::MAX / 2 + 1,
        26 => 1 << 32,
        27..=28 => u.int_in_range(2u64..=64)?,
        _ => u.arbitrary()?,
    };
    let from_epoch = match u.int_in_range(0u8..=7)? {
        0..=3 => 0,
        4 => 1,
        5 => 2,
        6 => u.int_in_range(0u64..=10)?,
        _ => u.arbitrary()?,
    };
    let network_key = match u.int_in_range(0u8..=7)? {
        0..=5 => pool_key(0),
        6 => pool_key(1),
        _ => {
            let n = u.int_in_range(0usize..=100)?;
            u.bytes(n)?.to_vec()
        }
    };
    Ok(Config {
        epoch_length,
        from_epoch,
        network_key,
    })
}

/// How a varint field is written.
#[derive(Clone, Copy, Debug)]
enum VarMode {
    Canonical,
    /// Canonical, then k extra zero-valued continuation bytes ending in 0x00 (non-canonical).
    PadZero(u8),
    /// 10 bytes whose last carries more than one data bit (overflow past u64).
    Overflow10(u8),
    /// 11 bytes (too long).
    Long11,
    /// Last byte keeps its continuation bit (runs into the next field).
    Unterminated,
}

fn write_varint(out: &mut Vec<u8>, v: u64, mode: VarMode) {
    let mut canon = Vec::new();
    let mut x = v;
    loop {
        let b = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            canon.push(b);
            break;
        }
        canon.push(b | 0x80);
    }
    match mode {
        VarMode::Canonical => out.extend(canon),
        VarMode::PadZero(k) => {
            let n = canon.len();
            canon[n - 1] |= 0x80;
            for _ in 1..k.max(1) {
                canon.push(0x80);
            }
            canon.push(0);
            out.extend(canon);
        }
        VarMode::Overflow10(last) => {
            let mut x = v;
            for _ in 0..9 {
                out.push((x & 0x7f) as u8 | 0x80);
                x >>= 7;
            }
            out.push(last.max(2) & 0x7f);
        }
        VarMode::Long11 => {
            let mut x = v;
            for _ in 0..10 {
                out.push((x & 0x7f) as u8 | 0x80);
                x >>= 7;
            }
            out.push(1);
        }
        VarMode::Unterminated => {
            let n = canon.len();
            canon[n - 1] |= 0x80;
            out.extend(canon);
        }
    }
}

fn var_mode(u: &mut Unstructured) -> Result<VarMode> {
    Ok(match u.int_in_range(0u8..=15)? {
        0..=10 => VarMode::Canonical,
        11 | 12 => VarMode::PadZero(u.int_in_range(1u8..=10)?),
        13 => VarMode::Overflow10(u.arbitrary()?),
        14 => VarMode::Long11,
        _ => VarMode::Unterminated,
    })
}

/// The certificate fields before encoding.
#[derive(Clone, Debug)]
pub struct Fields {
    pub epoch: u64,
    pub view: u64,
    pub parent_view: u64,
    pub payload: [u8; 32],
    pub sig: Vec<u8>,
}

impl Fields {
    /// commonware's own encoding: Proposal::encode followed by the certificate's raw bytes
    /// (Finalization's Write; the vrf Certificate is a Lazy<Signature> written verbatim).
    pub fn encode_commonware(&self) -> Vec<u8> {
        let p = Proposal::new(
            Round::new(Epoch::new(self.epoch), View::new(self.view)),
            View::new(self.parent_view),
            Digest(self.payload),
        );
        let mut out = p.encode().to_vec();
        out.extend_from_slice(&self.sig);
        out
    }

    fn encode_with(&self, modes: [VarMode; 3]) -> Vec<u8> {
        let mut out = Vec::new();
        write_varint(&mut out, self.epoch, modes[0]);
        write_varint(&mut out, self.view, modes[1]);
        write_varint(&mut out, self.parent_view, modes[2]);
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.sig);
        out
    }
}

/// Generator statistics (what kinds of inputs were produced).
#[derive(Clone, Debug, Default)]
pub struct GenStats {
    pub random: u64,
    pub replay: u64,
    pub structured_random: u64,
    pub valid_next: u64,
    pub unmutated: u64,
    pub field_mutations: [u64; 24],
    pub noncanonical_encodings: u64,
    pub byte_mutations: u64,
}

pub struct Gen {
    pub cfg: Config,
    counter: u64,
    history: Vec<Candidate>,
    pub stats: GenStats,
}

fn flip(u: &mut Unstructured, b: &mut [u8]) -> Result<()> {
    if !b.is_empty() {
        let i = u.choose_index(b.len())?;
        let bit = u.int_in_range(0u8..=7)?;
        b[i] ^= 1 << bit;
    }
    Ok(())
}

impl Gen {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            counter: 0,
            history: Vec::new(),
            stats: GenStats::default(),
        }
    }

    fn fresh(&mut self, u: &mut Unstructured, tag: &[u8]) -> Result<[u8; 32]> {
        self.counter += 1;
        let salt: u32 = u.arbitrary()?;
        let mut h = Sha256::new();
        h.update(tag);
        h.update(self.counter.to_be_bytes());
        h.update(salt.to_be_bytes());
        Ok(h.finalize().into())
    }

    fn small_or_any(u: &mut Unstructured) -> Result<u64> {
        Ok(match u.int_in_range(0u8..=7)? {
            0..=5 => u.int_in_range(0u64..=20)?,
            6 => u64::MAX - u.int_in_range(0u64..=2)?,
            _ => u.arbitrary()?,
        })
    }

    fn start_height(&self, u: &mut Unstructured) -> Result<u64> {
        let l = self.cfg.epoch_length;
        let fe = self.cfg.from_epoch;
        Ok(match u.int_in_range(0u8..=9)? {
            0..=6 => {
                let e = match u.int_in_range(0u8..=6)? {
                    0 => 0,
                    1 => 1,
                    2 => 2,
                    3 => fe.saturating_sub(1),
                    4 => fe,
                    5 => fe.saturating_add(1),
                    _ => u.int_in_range(0u64..=50)?,
                };
                let off = match u.int_in_range(0u8..=5)? {
                    0 => 0,
                    1 => 1,
                    2 => l.wrapping_sub(1),
                    3 => l.wrapping_sub(2),
                    4 => l.wrapping_sub(3),
                    _ => u.int_in_range(0..=l.saturating_sub(1))?,
                };
                e.saturating_mul(l).saturating_add(off)
            }
            7 => u64::MAX - u.int_in_range(0u64..=3 * l.min(1 << 20))?,
            8 => u.int_in_range(0u64..=100)?,
            _ => u.arbitrary()?,
        })
    }

    pub fn next(&mut self, u: &mut Unstructured, st: &RefState) -> Result<Candidate> {
        let c = match u.int_in_range(0u8..=19)? {
            0 => {
                self.stats.random += 1;
                let n = u.int_in_range(0usize..=200)?;
                let cert = u.bytes(n)?.to_vec();
                let dl = if u.ratio(1, 8)? {
                    u.int_in_range(0usize..=40)?
                } else {
                    32
                };
                Candidate {
                    height: u.arbitrary()?,
                    digest: u.bytes(dl)?.to_vec(),
                    parent: u.bytes(32)?.to_vec(),
                    state_root: u.bytes(32)?.to_vec(),
                    cert,
                    dkg: if u.arbitrary()? {
                        let n = u.int_in_range(0usize..=96)?;
                        Some((u.arbitrary()?, u.bytes(n)?.to_vec()))
                    } else {
                        None
                    },
                }
            }
            1 if !self.history.is_empty() => {
                self.stats.replay += 1;
                let i = u.choose_index(self.history.len())?;
                self.history[i].clone()
            }
            2 => {
                self.stats.structured_random += 1;
                let digest = self.fresh(u, b"digest")?;
                let f = Fields {
                    epoch: Self::small_or_any(u)?,
                    view: Self::small_or_any(u)?,
                    parent_view: Self::small_or_any(u)?,
                    payload: if u.ratio(3, 4)? {
                        digest
                    } else {
                        self.fresh(u, b"payload")?
                    },
                    sig: u.bytes(96)?.to_vec(),
                };
                let tip = st.tip.as_ref();
                Candidate {
                    height: match tip {
                        Some(t) if u.arbitrary()? => t.height.get().wrapping_add(1),
                        _ => self.start_height(u)?,
                    },
                    digest: digest.to_vec(),
                    parent: tip.map_or_else(|| vec![0; 32], |t| t.digest.clone()),
                    state_root: self.fresh(u, b"root")?.to_vec(),
                    cert: f.encode_commonware(),
                    dkg: None,
                }
            }
            _ => self.valid_next(u, st)?,
        };
        if self.history.len() < 16 {
            self.history.push(c.clone());
        } else {
            let i = (self.counter % 16) as usize;
            self.history[i] = c.clone();
        }
        Ok(c)
    }

    fn valid_next(&mut self, u: &mut Unstructured, st: &RefState) -> Result<Candidate> {
        self.stats.valid_next += 1;
        let l = self.cfg.epoch_length;
        let lnz = l.max(1);
        let tip = st.tip.clone();
        let mut height = match &tip {
            Some(t) => t.height.get().wrapping_add(1),
            None => self.start_height(u)?,
        };
        let mut epoch = height / lnz;
        let mut view = match &tip {
            Some(t) if t.round.epoch().get() == epoch => t
                .round
                .view()
                .get()
                .saturating_add(1 + u.int_in_range(0u64..=2)?),
            _ => Self::small_or_any(u)?,
        };
        let mut parent_view = match u.int_in_range(0u8..=3)? {
            0 | 1 => view.saturating_sub(1),
            2 => 0,
            _ => Self::small_or_any(u)?,
        };
        let digest = self.fresh(u, b"digest")?;
        let mut digest_v = digest.to_vec();
        let mut payload = digest;
        let mut parent = match &tip {
            Some(t) => t.digest.clone(),
            None => self.fresh(u, b"parent")?.to_vec(),
        };
        let mut state_root = match &tip {
            Some(t) => exec_root(&t.state_root, &digest).to_vec(),
            None => self.fresh(u, b"root")?.to_vec(),
        };
        let key_for = |st: &RefState, e: u64, u: &mut Unstructured| -> Result<Vec<u8>> {
            Ok(match st.identity(Epoch::new(e)) {
                Some((k, _)) => k.to_vec(),
                None => pool_key(u.int_in_range(0u8..=3)?),
            })
        };
        let key = key_for(st, epoch, u)?;
        let mut sig = fake_sig(&key, epoch, view, parent_view, &payload).to_vec();
        let boundary = l > 0 && height % l == l - 1;
        let mut dkg = if boundary {
            Some((epoch.wrapping_add(1), pool_key(1 + (epoch % 3) as u8)))
        } else if u.ratio(1, 8)? {
            Some((epoch.wrapping_add(1), pool_key(2)))
        } else {
            None
        };

        let nmut = match u.int_in_range(0u8..=7)? {
            0..=3 => 0,
            m => m - 3,
        };
        if nmut == 0 {
            self.stats.unmutated += 1;
        }
        let mut resign = false;
        for _ in 0..nmut {
            let m = u.int_in_range(0u8..=23)?;
            self.stats.field_mutations[m as usize] += 1;
            let tv = tip
                .as_ref()
                .map(|t| (t.round.epoch().get(), t.round.view().get()));
            match m {
                0 => epoch = epoch.wrapping_add(1),
                1 => epoch = epoch.wrapping_sub(1),
                2 => {
                    if let Some((te, tvw)) = tv {
                        epoch = te;
                        view = tvw;
                    }
                }
                3 => {
                    if let Some((te, tvw)) = tv {
                        epoch = te;
                        view = tvw.wrapping_sub(1);
                    }
                }
                4 => {
                    if let Some((te, _)) = tv {
                        epoch = te.wrapping_sub(1);
                    }
                }
                5 => parent_view = u.arbitrary()?,
                6 => flip(u, &mut payload)?,
                7 => flip(u, &mut sig)?,
                8 => {
                    sig = fake_sig(
                        &pool_key(u.int_in_range(0u8..=3)?),
                        epoch,
                        view,
                        parent_view,
                        &payload,
                    )
                    .to_vec()
                }
                9 => height = height.wrapping_add(1),
                10 => height = height.wrapping_sub(1),
                11 => flip(u, &mut parent)?,
                12 => flip(u, &mut state_root)?,
                13 => dkg = None,
                14 => dkg = Some((epoch, pool_key(1))),
                15 => dkg = Some((epoch.wrapping_add(2), pool_key(1))),
                16 => {
                    let n = u.int_in_range(0usize..=100)?;
                    let e = dkg.as_ref().map_or(epoch.wrapping_add(1), |d| d.0);
                    dkg = Some((e, u.bytes(n)?.to_vec()));
                }
                17 => {
                    if u.arbitrary()? {
                        digest_v.pop();
                    } else {
                        digest_v.push(u.arbitrary()?);
                    }
                }
                18 => resign = true,
                19 => {
                    // A different block on the same parent: payload and digest agree, but the
                    // state root was computed for the original digest.
                    let d = self.fresh(u, b"digest2")?;
                    payload = d;
                    digest_v = d.to_vec();
                }
                20 => {
                    height = u64::MAX - u.int_in_range(0u64..=1)?;
                    epoch = height / lnz;
                }
                21 => view = u64::MAX - u.int_in_range(0u64..=1)?,
                22 => epoch = u64::MAX - u.int_in_range(0u64..=1)?,
                _ => {
                    // Wrong signature length.
                    if u.arbitrary()? {
                        sig.pop();
                    } else {
                        sig.push(u.arbitrary()?);
                    }
                }
            }
        }
        if resign && sig.len() == 96 {
            let key = key_for(st, epoch, u)?;
            sig = fake_sig(&key, epoch, view, parent_view, &payload).to_vec();
        }
        let f = Fields {
            epoch,
            view,
            parent_view,
            payload,
            sig,
        };
        let mut cert = if u.ratio(3, 4)? {
            f.encode_commonware()
        } else {
            let modes = [var_mode(u)?, var_mode(u)?, var_mode(u)?];
            if modes.iter().any(|m| !matches!(m, VarMode::Canonical)) {
                self.stats.noncanonical_encodings += 1;
            }
            f.encode_with(modes)
        };
        if u.ratio(1, 6)? {
            self.stats.byte_mutations += 1;
            for _ in 0..u.int_in_range(1u8..=3)? {
                match u.int_in_range(0u8..=5)? {
                    0 => flip(u, &mut cert)?,
                    1 => {
                        let i = u.int_in_range(0..=cert.len())?;
                        cert.insert(i, u.arbitrary()?);
                    }
                    2 => {
                        if !cert.is_empty() {
                            let i = u.choose_index(cert.len())?;
                            cert.remove(i);
                        }
                    }
                    3 => {
                        let n = u.int_in_range(0..=cert.len())?;
                        cert.truncate(n);
                    }
                    4 => {
                        let n = u.int_in_range(1usize..=3)?;
                        cert.extend_from_slice(u.bytes(n)?);
                    }
                    _ => {
                        // Overwrite a byte in the varint header region.
                        let n = cert.len().min(12);
                        if n > 0 {
                            let i = u.choose_index(n)?;
                            cert[i] = u.arbitrary()?;
                        }
                    }
                }
            }
        }
        Ok(Candidate {
            height,
            digest: digest_v,
            parent,
            state_root,
            cert,
            dkg,
        })
    }
}
