//! Running the Lean core and the reference side by side.
use std::fmt::Write as _;

use arbitrary::Unstructured;

use crate::{
    Candidate, Config, TipView,
    core::Core,
    generate::Gen,
    oracle::{self, Call, Mode},
    reference::{Outcome, RefState},
};

pub struct Pair {
    pub lean: Core,
    pub reference: RefState,
}

#[derive(Clone, Debug)]
pub struct Divergence {
    pub step: usize,
    pub what: String,
    pub lean_code: u8,
    pub ref_code: u8,
    pub lean_tip: TipView,
    pub ref_tip: TipView,
    pub lean_calls: Vec<Call>,
    pub ref_calls: Vec<Call>,
}

#[derive(Clone, Copy, Debug)]
pub enum StepResult {
    Code(u8),
    Unsupported { reason: &'static str, lean_code: u8 },
}

impl Pair {
    pub fn new(cfg: &Config) -> Self {
        Self {
            lean: Core::new(cfg),
            reference: RefState::new(cfg),
        }
    }

    pub fn step(&mut self, step: usize, c: &Candidate) -> Result<StepResult, Divergence> {
        oracle::take_log();
        let lean_code = self.lean.step(c);
        let lean_calls = oracle::take_log();
        let out = self.reference.step(c);
        let ref_calls = oracle::take_log();
        let ref_code = match out {
            Outcome::Code(x) => x,
            Outcome::Unsupported(reason) => {
                return Ok(StepResult::Unsupported { reason, lean_code });
            }
        };
        let lean_tip = self.lean.tip();
        let ref_tip = self.reference.tip_view();
        let what = if lean_code != ref_code {
            "result code"
        } else if lean_tip != ref_tip {
            "tip"
        } else if lean_calls != ref_calls {
            "oracle calls"
        } else {
            return Ok(StepResult::Code(lean_code));
        };
        Err(Divergence {
            step,
            what: what.into(),
            lean_code,
            ref_code,
            lean_tip,
            ref_tip,
            lean_calls,
            ref_calls,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub scenarios: u64,
    pub steps: u64,
    pub codes: [u64; 13],
    pub unsupported: u64,
    pub unsupported_reasons: std::collections::BTreeMap<&'static str, u64>,
    pub unsupported_lean_accepts: u64,
    pub longest_chain: u64,
    pub register_conflicts: u64,
}

impl Stats {
    pub fn merge(&mut self, o: &Stats) {
        self.scenarios += o.scenarios;
        self.steps += o.steps;
        for i in 0..13 {
            self.codes[i] += o.codes[i];
        }
        self.unsupported += o.unsupported;
        for (k, v) in &o.unsupported_reasons {
            *self.unsupported_reasons.entry(k).or_default() += v;
        }
        self.unsupported_lean_accepts += o.unsupported_lean_accepts;
        self.longest_chain = self.longest_chain.max(o.longest_chain);
        self.register_conflicts += o.register_conflicts;
    }
}

/// A failing scenario: enough to replay it.
#[derive(Clone, Debug)]
pub struct Failure {
    pub mode: Mode,
    pub cfg: Config,
    pub cands: Vec<Candidate>,
    pub div: Divergence,
}

/// Run a fixed candidate list; returns the stats or the first divergence.
pub fn run_list(
    mode: Mode,
    cfg: &Config,
    cands: &[Candidate],
    stats: &mut Stats,
) -> Result<(), Failure> {
    oracle::set_mode(mode);
    let mut pair = Pair::new(cfg);
    stats.scenarios += 1;
    let mut chain = 0;
    for (i, c) in cands.iter().enumerate() {
        stats.steps += 1;
        match pair.step(i, c) {
            Ok(StepResult::Code(x)) => {
                stats.codes[x.min(12) as usize] += 1;
                if x == 0 {
                    chain += 1;
                    stats.longest_chain = stats.longest_chain.max(chain);
                }
            }
            Ok(StepResult::Unsupported { reason, lean_code }) => {
                stats.unsupported += 1;
                *stats.unsupported_reasons.entry(reason).or_default() += 1;
                if lean_code == 0 {
                    stats.unsupported_lean_accepts += 1;
                }
                break;
            }
            Err(div) => {
                return Err(Failure {
                    mode,
                    cfg: cfg.clone(),
                    cands: cands[..=i].to_vec(),
                    div,
                });
            }
        }
    }
    stats.register_conflicts += pair.reference.register_conflicts;
    Ok(())
}

/// Run one fuzz input: either the replay format (first byte 0xFF) or generator-driven.
pub fn run_input(data: &[u8], max_steps: usize, stats: &mut Stats) -> Result<(), Failure> {
    if data.first() == Some(&0xFF) {
        let Some((mode, cfg, cands)) = decode_replay(data) else {
            return Ok(());
        };
        return run_list(mode, &cfg, &cands[..cands.len().min(max_steps)], stats);
    }
    let mut u = Unstructured::new(data);
    let Ok(cfg) = crate::generate::config(&mut u) else {
        return Ok(());
    };
    oracle::set_mode(Mode::Fake);
    let mut generator = Gen::new(cfg.clone());
    let mut pair = Pair::new(&cfg);
    let mut cands = Vec::new();
    stats.scenarios += 1;
    let mut chain = 0;
    for i in 0..max_steps {
        if u.is_empty() {
            break;
        }
        let Ok(c) = generator.next(&mut u, &pair.reference) else {
            break;
        };
        cands.push(c.clone());
        stats.steps += 1;
        match pair.step(i, &c) {
            Ok(StepResult::Code(x)) => {
                stats.codes[x.min(12) as usize] += 1;
                if x == 0 {
                    chain += 1;
                    stats.longest_chain = stats.longest_chain.max(chain);
                }
            }
            Ok(StepResult::Unsupported { reason, lean_code }) => {
                stats.unsupported += 1;
                *stats.unsupported_reasons.entry(reason).or_default() += 1;
                if lean_code == 0 {
                    stats.unsupported_lean_accepts += 1;
                }
                break;
            }
            Err(div) => {
                return Err(Failure {
                    mode: Mode::Fake,
                    cfg,
                    cands,
                    div,
                });
            }
        }
    }
    stats.register_conflicts += pair.reference.register_conflicts;
    Ok(())
}

/// Greedy minimization: drop candidates (keeping the last, diverging one) while it still diverges.
pub fn minimize(f: &Failure) -> Failure {
    let mut best = f.clone();
    let mut i = 0;
    while i + 1 < best.cands.len() {
        let mut trial = best.cands.clone();
        trial.remove(i);
        let mut s = Stats::default();
        match run_list(best.mode, &best.cfg, &trial, &mut s) {
            Err(nf) if nf.div.what == best.div.what => best = nf,
            _ => i += 1,
        }
    }
    best
}

fn mode_byte(m: Mode) -> u8 {
    match m {
        Mode::Fake => 0,
        Mode::AcceptAll => 1,
        Mode::RealBls => 2,
    }
}

/// Replay format: 0xFF, mode, L u64, from_epoch u64, key (u16 len), then per candidate:
/// height u64, digest (u8 len), parent (u8 len), stateRoot (u8 len), cert (u16 len),
/// dkg flag u8 [epoch u64, key (u16 len)]. Integers little-endian.
pub fn encode_replay(mode: Mode, cfg: &Config, cands: &[Candidate]) -> Vec<u8> {
    let mut o = vec![0xFF, mode_byte(mode)];
    o.extend(cfg.epoch_length.to_le_bytes());
    o.extend(cfg.from_epoch.to_le_bytes());
    o.extend((cfg.network_key.len() as u16).to_le_bytes());
    o.extend(&cfg.network_key);
    for c in cands {
        o.extend(c.height.to_le_bytes());
        for b in [&c.digest, &c.parent, &c.state_root] {
            o.push(b.len() as u8);
            o.extend(b);
        }
        o.extend((c.cert.len() as u16).to_le_bytes());
        o.extend(&c.cert);
        match &c.dkg {
            None => o.push(0),
            Some((e, k)) => {
                o.push(1);
                o.extend(e.to_le_bytes());
                o.extend((k.len() as u16).to_le_bytes());
                o.extend(k);
            }
        }
    }
    o
}

struct Rd<'a>(&'a [u8]);
impl Rd<'_> {
    fn take(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a.to_vec())
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|v| v[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|v| u16::from_le_bytes([v[0], v[1]]))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|v| u64::from_le_bytes(v.try_into().unwrap()))
    }
}

pub fn decode_replay(data: &[u8]) -> Option<(Mode, Config, Vec<Candidate>)> {
    let mut r = Rd(data.get(1..)?);
    // RealBls is not used from the fuzzer (too slow); map it to AcceptAll.
    let mode = match r.u8()? % 3 {
        0 => Mode::Fake,
        _ => Mode::AcceptAll,
    };
    let epoch_length = r.u64()?;
    let from_epoch = r.u64()?;
    let n = r.u16()? as usize;
    let network_key = r.take(n)?;
    let cfg = Config {
        epoch_length,
        from_epoch,
        network_key,
    };
    let mut cands = Vec::new();
    let one = |r: &mut Rd| -> Option<Candidate> {
        let height = r.u64()?;
        let n = r.u8()? as usize;
        let digest = r.take(n)?;
        let n = r.u8()? as usize;
        let parent = r.take(n)?;
        let n = r.u8()? as usize;
        let state_root = r.take(n)?;
        let n = r.u16()? as usize;
        let cert = r.take(n)?;
        let dkg = if r.u8()? & 1 == 1 {
            let e = r.u64()?;
            let n = r.u16()? as usize;
            Some((e, r.take(n)?))
        } else {
            None
        };
        Some(Candidate {
            height,
            digest,
            parent,
            state_root,
            cert,
            dkg,
        })
    };
    while let Some(c) = one(&mut r) {
        cands.push(c);
    }
    Some((mode, cfg, cands))
}

pub fn describe(f: &Failure) -> String {
    let mut s = String::new();
    let d = &f.div;
    let _ = writeln!(
        s,
        "DIVERGENCE ({}) at step {} of {} (mode {:?})",
        d.what,
        d.step,
        f.cands.len(),
        f.mode
    );
    let _ = writeln!(
        s,
        "  config: L={} from_epoch={} key={}",
        f.cfg.epoch_length,
        f.cfg.from_epoch,
        hex::encode(&f.cfg.network_key)
    );
    for (i, c) in f.cands.iter().enumerate() {
        let _ = writeln!(
            s,
            "  [{i}] height={} digest={} parent={} root={} dkg={:?} cert={}",
            c.height,
            hex::encode(&c.digest),
            hex::encode(&c.parent),
            hex::encode(&c.state_root),
            c.dkg.as_ref().map(|(e, k)| (e, hex::encode(k))),
            hex::encode(&c.cert)
        );
    }
    let _ = writeln!(
        s,
        "  lean: code {} tip {:?}",
        d.lean_code,
        d.lean_tip
            .as_ref()
            .map(|t| (t.0, hex::encode(&t.1), hex::encode(&t.2)))
    );
    let _ = writeln!(
        s,
        "  ref:  code {} tip {:?}",
        d.ref_code,
        d.ref_tip
            .as_ref()
            .map(|t| (t.0, hex::encode(&t.1), hex::encode(&t.2)))
    );
    if d.what == "oracle calls" {
        let _ = writeln!(
            s,
            "  lean calls: {:?}\n  ref calls: {:?}",
            d.lean_calls, d.ref_calls
        );
    }
    let _ = writeln!(
        s,
        "  replay bytes: {}",
        hex::encode(encode_replay(f.mode, &f.cfg, &f.cands))
    );
    s
}
