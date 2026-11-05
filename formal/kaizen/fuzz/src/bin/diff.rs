//! Deterministic differential runner (no nightly or libFuzzer needed), replay of saved inputs,
//! and the real-testnet mode.
//!
//!   diff --iters 2000000 [--seed 1]          generator-driven, seeded ChaCha8 bytes
//!   diff --replay FILE                        replay a saved input (binary or hex)
//!   diff --real 2000 [--start H] [--mutations 3] [--write-corpus DIR]
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use alloy_consensus::{BlockHeader as _, Sealable as _};
use commonware_codec::{DecodeExt as _, Encode as _, ReadExt as _};
use commonware_consensus::Epochable as _;
use futures::{StreamExt as _, stream};
use kaizen_fuzz::{
    Candidate, Config,
    diff::{self, Failure, Stats, describe, minimize},
    generate::Fields,
    oracle::Mode,
    reference::Fin,
};
use rand_chacha::{
    ChaCha8Rng,
    rand_core::{RngCore as _, SeedableRng as _},
};
use serde::Deserialize;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_primitives::{BlockBody, TempoHeader};

const EPOCH_LENGTH: u64 = 21600;

struct Args {
    iters: u64,
    seed: u64,
    steps: usize,
    replay: Option<String>,
    real: u64,
    start: Option<u64>,
    mutations: u32,
    write_corpus: Option<String>,
    rpc: String,
    out_dir: String,
}

fn parse() -> Args {
    let mut a = Args {
        iters: 0,
        seed: 1,
        steps: 64,
        replay: None,
        real: 0,
        start: None,
        mutations: 3,
        write_corpus: None,
        rpc: "https://rpc.testnet.tempo.xyz".into(),
        out_dir: "divergences".into(),
    };
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--iters" => a.iters = val.parse().unwrap(),
            "--seed" => a.seed = val.parse().unwrap(),
            "--steps" => a.steps = val.parse().unwrap(),
            "--replay" => a.replay = Some(val),
            "--real" => a.real = val.parse().unwrap(),
            "--start" => a.start = Some(val.parse().unwrap()),
            "--mutations" => a.mutations = val.parse().unwrap(),
            "--write-corpus" => a.write_corpus = Some(val),
            "--rpc" => a.rpc = val,
            "--out" => a.out_dir = val,
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    a
}

fn print_stats(label: &str, s: &Stats, secs: f64) {
    println!(
        "{label}: {} scenarios, {} steps in {secs:.1}s ({:.0} steps/s); longest accepted chain {}",
        s.scenarios,
        s.steps,
        s.steps as f64 / secs.max(1e-9),
        s.longest_chain
    );
    let names = [
        "accepted",
        "malformed",
        "digestMismatch",
        "epochMismatch",
        "identityUnavailable",
        "badSignature",
        "heightNotNext",
        "parentMismatch",
        "roundNotIncreasing",
        "missingDkg",
        "dkgEpochMismatch",
        "badConfig",
        "executionInvalid",
    ];
    for (i, n) in names.iter().enumerate() {
        println!("  {i:>2} {n:<20} {}", s.codes[i]);
    }
    println!(
        "  unsupported by Tempo (sequence stopped): {} (Lean accepted {}) {:?}",
        s.unsupported, s.unsupported_lean_accepts, s.unsupported_reasons
    );
    println!(
        "  SchemeProvider::register conflicts (Tempo would panic): {}",
        s.register_conflicts
    );
}

struct Report {
    seen: BTreeMap<String, u64>,
    out_dir: String,
}

impl Report {
    fn record(&mut self, f: &Failure) {
        let m = minimize(f);
        let d = &m.div;
        let last = m.cands.last().unwrap();
        let key = format!("{}: lean {} ref {}", d.what, d.lean_code, d.ref_code);
        let n = self.seen.entry(key.clone()).or_default();
        *n += 1;
        if *n <= 3 {
            println!("{}", describe(&m));
            let _ = std::fs::create_dir_all(&self.out_dir);
            let name = format!(
                "{}/{}-{}.hex",
                self.out_dir,
                key.replace([' ', ':'], "_"),
                n
            );
            let _ = std::fs::write(
                &name,
                hex::encode(diff::encode_replay(m.mode, &m.cfg, &m.cands)),
            );
            let _ = last;
        }
    }
}

fn deterministic(a: &Args) {
    let mut rng = ChaCha8Rng::seed_from_u64(a.seed);
    let mut total = Stats::default();
    let mut rep = Report {
        seen: BTreeMap::new(),
        out_dir: a.out_dir.clone(),
    };
    let t0 = Instant::now();
    let mut last = Instant::now();
    let mut buf = Vec::new();
    while total.steps < a.iters {
        let n = 256 + (rng.next_u32() as usize % 8192);
        buf.resize(n, 0);
        rng.fill_bytes(&mut buf);
        let mut s = Stats::default();
        if let Err(f) = diff::run_input(&buf, a.steps, &mut s) {
            rep.record(&f);
        }
        total.merge(&s);
        if last.elapsed() > Duration::from_secs(30) {
            eprintln!(
                "... {} steps, {} divergences",
                total.steps,
                rep.seen.values().sum::<u64>()
            );
            last = Instant::now();
        }
    }
    print_stats("deterministic", &total, t0.elapsed().as_secs_f64());
    println!("divergence classes: {:?}", rep.seen);
}

fn replay(path: &str) {
    let raw = std::fs::read(path).unwrap();
    let data = match hex::decode(String::from_utf8_lossy(&raw).trim()) {
        Ok(d) => d,
        Err(_) => raw,
    };
    let mut s = Stats::default();
    match diff::run_input(&data, usize::MAX, &mut s) {
        Ok(()) => print_stats("replay", &s, 0.0),
        Err(f) => println!("{}", describe(&f)),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcCertified {
    certificate: String,
    block: RpcBlock,
}

#[derive(Deserialize)]
struct RpcBlock {
    header: TempoHeader,
    #[allow(dead_code)]
    body: BlockBody,
}

async fn fetch(
    client: &reqwest::Client,
    url: &str,
    q: serde_json::Value,
) -> eyre_like::Result<RpcCertified> {
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "consensus_getFinalization", "params": [q]});
    let mut attempt = 0;
    loop {
        attempt += 1;
        let r: eyre_like::Result<RpcCertified> = async {
            let resp = client
                .post(url)
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
            let mut v: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            if let Some(err) = v.get("error") {
                return Err(format!("rpc error {err}"));
            }
            serde_json::from_value(v["result"].take()).map_err(|e| e.to_string())
        }
        .await;
        match r {
            Ok(x) => return Ok(x),
            Err(e) if attempt < 8 => {
                eprintln!("retry {q}: {e}");
                tokio::time::sleep(Duration::from_millis(300 * attempt)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

mod eyre_like {
    pub type Result<T> = std::result::Result<T, String>;
}

fn to_candidate(c: &RpcCertified) -> Candidate {
    let h = &c.block.header;
    let height = h.number();
    let dkg = if (height + 1) % EPOCH_LENGTH == 0 {
        let mut extra = h.extra_data().as_ref();
        let outcome =
            OnchainDkgOutcome::read(&mut extra).expect("boundary block carries a DKG outcome");
        Some((outcome.epoch, outcome.network_identity().encode().to_vec()))
    } else {
        None
    };
    Candidate {
        height,
        digest: h.hash_slow().0.to_vec(),
        parent: h.parent_hash().0.to_vec(),
        state_root: h.state_root().0.to_vec(),
        cert: alloy_primitives::hex::decode(&c.certificate).unwrap(),
        dkg,
    }
}

fn fields_of(cert: &[u8]) -> Fields {
    let f = Fin::decode(cert).expect("real certificate decodes");
    let p = &f.proposal;
    Fields {
        epoch: f.epoch().get(),
        view: p.round.view().get(),
        parent_view: p.parent.get(),
        payload: p.payload.0,
        sig: f.certificate.encode().to_vec(),
    }
}

/// Mutated variants of a real candidate (all expected to be rejected).
fn mutate(
    rng: &mut ChaCha8Rng,
    c: &Candidate,
    prev: Option<&Candidate>,
    other_sig: &[u8],
) -> (u32, Candidate) {
    let mut m = c.clone();
    let mut f = fields_of(&c.cert);
    let k = rng.next_u32() % 17;
    let bit = |rng: &mut ChaCha8Rng, b: &mut [u8]| {
        let i = rng.next_u32() as usize % b.len();
        b[i] ^= 1 << (rng.next_u32() % 8);
    };
    match k {
        0 => {
            bit(rng, &mut f.payload);
            m.cert = f.encode_commonware();
        }
        1 => {
            bit(rng, &mut f.payload);
            m.cert = f.encode_commonware();
            m.digest = f.payload.to_vec();
        }
        2 => {
            f.view += 1;
            m.cert = f.encode_commonware();
        }
        3 => {
            f.parent_view ^= 1;
            m.cert = f.encode_commonware();
        }
        4 => {
            bit(rng, &mut f.sig);
            m.cert = f.encode_commonware();
        }
        5 => {
            f.sig = other_sig.to_vec();
            m.cert = f.encode_commonware();
        }
        6 => {
            f.epoch += 1;
            m.cert = f.encode_commonware();
        }
        7 => {
            let n = rng.next_u32() as usize % m.cert.len();
            m.cert.truncate(n);
        }
        8 => m.cert.push(rng.next_u32() as u8),
        9 => {
            // Non-canonical epoch varint: last byte gets a continuation bit, then 0x00.
            let mut e = Vec::new();
            let mut x = f.epoch;
            loop {
                let b = (x & 0x7f) as u8;
                x >>= 7;
                if x == 0 {
                    e.push(b | 0x80);
                    e.push(0);
                    break;
                }
                e.push(b | 0x80);
            }
            let canon = commonware_codec::varint::UInt(f.epoch).encode().len();
            let mut cert = e;
            cert.extend_from_slice(&m.cert[canon..]);
            m.cert = cert;
        }
        10 => m.height += 1,
        11 => bit(rng, &mut m.parent),
        12 => {
            if let Some(p) = prev {
                m = p.clone()
            } else {
                m.height -= 1
            }
        }
        13 => m.dkg = None,
        14 => m.dkg = m.dkg.map(|(e, k)| (e + 1, k)),
        15 => {
            bit(rng, &mut m.digest);
        }
        _ => {
            f.view = f.view.saturating_sub(1);
            m.cert = f.encode_commonware();
        }
    }
    (k, m)
}

#[tokio::main]
async fn real(a: &Args) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let ident: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../testnet-network-identity.json")).unwrap();
    let from_epoch = ident["from_epoch"].as_u64().unwrap();
    let key = hex::decode(ident["identity"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let start = match a.start {
        Some(s) => s,
        None => {
            let latest = fetch(&client, &a.rpc, serde_json::json!("latest"))
                .await
                .unwrap();
            let head = latest.block.header.number();
            // Straddle the latest boundary whose both sides are available.
            let boundary = (head.saturating_sub(a.real / 2 + 10) / EPOCH_LENGTH) * EPOCH_LENGTH;
            let s = boundary.saturating_sub(a.real / 2);
            eprintln!(
                "head {head}; replaying {} blocks from {s} across boundary {}",
                a.real,
                boundary.saturating_sub(1)
            );
            s
        }
    };
    let t0 = Instant::now();
    let heights: Vec<u64> = (start..start + a.real).collect();
    let mut fetched: Vec<(u64, RpcCertified)> = stream::iter(heights)
        .map(|h| {
            let c = &client;
            let url = &a.rpc;
            async move {
                (
                    h,
                    fetch(c, url, serde_json::json!({"height": h}))
                        .await
                        .unwrap(),
                )
            }
        })
        .buffer_unordered(32)
        .collect()
        .await;
    fetched.sort_by_key(|x| x.0);
    let cands: Vec<Candidate> = fetched.iter().map(|(_, c)| to_candidate(c)).collect();
    eprintln!(
        "fetched {} blocks in {:.1}s",
        cands.len(),
        t0.elapsed().as_secs_f64()
    );

    let cfg = Config {
        epoch_length: EPOCH_LENGTH,
        from_epoch,
        network_key: key.clone(),
    };
    // Interleave mutated variants before each genuine block.
    let mut rng = ChaCha8Rng::seed_from_u64(a.seed);
    let mut seq = Vec::new();
    let mut kinds = [0u64; 17];
    for (i, c) in cands.iter().enumerate() {
        let prev = i.checked_sub(1).map(|j| &cands[j]);
        let other = fields_of(&cands[(i + 7) % cands.len()].cert).sig;
        // The first block anchors the follower (trust on first verified block): mutate only
        // blocks after it, or a validly signed mutant (e.g. height + 1) becomes the anchor.
        let muts = if i == 0 { 0 } else { a.mutations };
        for _ in 0..muts {
            let (k, m) = mutate(&mut rng, c, prev, &other);
            kinds[k as usize] += 1;
            seq.push(m);
        }
        if let Some((e, k)) = c.dkg.as_ref().filter(|_| i > 0) {
            // Boundary block: missing outcome, outcome for the wrong epoch, outcome on the
            // previous height (not a boundary there, so ignored).
            for d in [None, Some((e + 1, k.clone())), Some((e - 1, k.clone()))] {
                let mut m = c.clone();
                m.dkg = d;
                seq.push(m);
            }
        }
        seq.push(c.clone());
    }
    let t1 = Instant::now();
    let mut s = Stats::default();
    let mut rep = Report {
        seen: BTreeMap::new(),
        out_dir: a.out_dir.clone(),
    };
    // Run in chunks so a divergence is reported and the replay continues from a fresh anchor.
    let mut from = 0;
    while from < seq.len() {
        match diff::run_list(Mode::RealBls, &cfg, &seq[from..], &mut s) {
            Ok(()) => break,
            Err(f) => {
                eprintln!("divergence at sequence index {}", from + f.div.step);
                rep.record(&f);
                from += f.div.step + 1;
            }
        }
    }
    print_stats("real", &s, t1.elapsed().as_secs_f64());
    println!(
        "real blocks: {} (heights {}..={}), mutation kinds {:?}",
        cands.len(),
        start,
        start + a.real - 1,
        kinds
    );
    println!("divergence classes: {:?}", rep.seen);
    let genuine_accepted = s.codes[0];
    println!(
        "accepted {genuine_accepted} of {} genuine blocks",
        cands.len()
    );

    if let Some(dir) = &a.write_corpus {
        std::fs::create_dir_all(dir).unwrap();
        let mut n = 0;
        for (i, w) in cands.windows(8).enumerate().step_by(25) {
            let data = diff::encode_replay(Mode::AcceptAll, &cfg, w);
            std::fs::write(format!("{dir}/real-chain-{i:05}"), data).unwrap();
            n += 1;
        }
        // A short-epoch config makes real certificates reach the epoch/boundary checks too.
        for (i, c) in cands.iter().enumerate().step_by(50) {
            let data = diff::encode_replay(Mode::Fake, &cfg, std::slice::from_ref(c));
            std::fs::write(format!("{dir}/real-single-{i:05}"), data).unwrap();
            n += 1;
        }
        if let Some(b) = cands.iter().position(|c| c.dkg.is_some()) {
            let lo = b.saturating_sub(4);
            let data =
                diff::encode_replay(Mode::AcceptAll, &cfg, &cands[lo..(b + 5).min(cands.len())]);
            std::fs::write(format!("{dir}/real-boundary"), data).unwrap();
            n += 1;
        }
        eprintln!("wrote {n} corpus seeds to {dir}");
    }
}

fn main() {
    let a = parse();
    if let Some(p) = &a.replay {
        replay(p);
    } else if a.real > 0 {
        real(&a);
    } else {
        deterministic(&a);
    }
}
