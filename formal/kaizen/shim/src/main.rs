//! Kaizen stage III: the unverified shim around the Lean-verified Simplex follower core.
//!
//! The shim fetches certified blocks from a Tempo node's consensus RPC, does the
//! application-specific work the Lean model takes as parameters (header hashing,
//! body-against-header commitments, DKG outcome parsing, BLS threshold signature
//! verification), and hands every candidate to the extracted Lean step function,
//! which alone decides whether the follower's tip advances.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
    time::{Duration, Instant},
};

use alloy_consensus::{BlockHeader as _, Sealable as _, proofs};
use clap::Parser;
use commonware_codec::{DecodeExt as _, ReadExt as _};
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
use eyre::{OptionExt as _, WrapErr as _, bail, eyre};
use futures::{StreamExt as _, stream};
use serde::Deserialize;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_primitives::{BlockBody, TempoHeader};

mod core;

/// Tempo's consensus namespace (crates/consensus/src/config.rs).
const NAMESPACE: &[u8] = b"TEMPO";

#[derive(Parser, Debug)]
#[command(
    about = "Sync a Tempo chain's finalized blocks through the Lean-verified Simplex follower core"
)]
struct Args {
    /// Consensus RPC (HTTP) of an untrusted upstream node.
    #[arg(long, default_value = "https://rpc.testnet.tempo.xyz")]
    rpc: String,
    /// First height to sync: a number, "latest", or "epoch:N" for the first block of epoch N.
    #[arg(long, default_value = "latest")]
    from: String,
    /// Stop after this many accepted blocks (0 = follow forever).
    #[arg(long, default_value_t = 0)]
    count: u64,
    /// Concurrent RPC requests.
    #[arg(long, default_value_t = 16)]
    concurrency: usize,
    /// Network identity JSON ({"from_epoch", "identity"}), defaults to the compiled testnet one.
    #[arg(long)]
    identity: Option<std::path::PathBuf>,
    /// Epoch length in blocks (testnet and mainnet genesis: 21600).
    #[arg(long, default_value_t = 21600)]
    epoch_length: u64,
    /// Only check the BLS oracle against the latest finalization, decoded by commonware, and exit.
    #[arg(long)]
    check_oracle: bool,
}

#[derive(Deserialize)]
struct IdentityFile {
    from_epoch: u64,
    identity: String,
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
    body: BlockBody,
}

/// What the shim hands the verified core for one block.
struct Candidate {
    height: u64,
    digest: [u8; 32],
    parent: [u8; 32],
    certificate: Vec<u8>,
    dkg: Option<(u64, Vec<u8>)>,
    txs: usize,
}

struct Rpc {
    client: reqwest::Client,
    url: String,
}

impl Rpc {
    async fn finalization(&self, query: serde_json::Value) -> eyre::Result<Option<RpcCertified>> {
        let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "consensus_getFinalization", "params": [query]});
        let mut attempt = 0;
        loop {
            attempt += 1;
            let res = async {
                let resp = self
                    .client
                    .post(&self.url)
                    .header("content-type", "application/json")
                    .body(body.to_string())
                    .send()
                    .await?;
                let status = resp.status();
                let bytes = resp.bytes().await?;
                if !status.is_success() {
                    bail!("HTTP {status}");
                }
                let mut v: serde_json::Value = serde_json::from_slice(&bytes)?;
                if let Some(err) = v.get("error") {
                    // 204: the upstream does not have it (yet).
                    if err.get("code").and_then(|c| c.as_i64()) == Some(204) {
                        return Ok(None);
                    }
                    bail!("rpc error: {err}");
                }
                Ok(Some(serde_json::from_value(v["result"].take())?))
            }
            .await;
            match res {
                Ok(r) => return Ok(r),
                Err(e) if attempt < 8 => {
                    eprintln!("retrying {query} after error: {e:#}");
                    tokio::time::sleep(Duration::from_millis(250 * attempt)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// Application-specific checks the Lean model abstracts (Kaizen phase 6): the block's
/// digest is the keccak of its header, its body matches the header's commitments, and
/// a boundary block's extra_data carries the next epoch's DKG outcome.
fn prepare(c: RpcCertified, epoch_length: u64) -> eyre::Result<Candidate> {
    let RpcBlock { header, body } = c.block;
    let height = header.number();
    if proofs::calculate_transaction_root(&body.transactions) != header.transactions_root() {
        bail!("block {height}: transactions root mismatch");
    }
    if proofs::calculate_ommers_root(&body.ommers) != header.ommers_hash() {
        bail!("block {height}: ommers hash mismatch");
    }
    match (&body.withdrawals, header.withdrawals_root()) {
        (Some(w), Some(root)) if proofs::calculate_withdrawals_root(w) != root => {
            bail!("block {height}: withdrawals root mismatch")
        }
        (Some(_), None) | (None, Some(_)) => bail!("block {height}: withdrawals presence mismatch"),
        _ => {}
    }
    let digest = header.hash_slow().0;
    let parent = header.parent_hash().0;
    let is_boundary = (height + 1) % epoch_length == 0;
    let dkg = if is_boundary {
        let mut extra = header.extra_data().as_ref();
        let outcome = OnchainDkgOutcome::read(&mut extra)
            .wrap_err_with(|| format!("boundary block {height}: no DKG outcome"))?;
        let key = commonware_codec::Encode::encode(outcome.network_identity()).to_vec();
        Some((outcome.epoch, key))
    } else {
        None
    };
    let certificate = alloy_primitives::hex::decode(&c.certificate)?;
    Ok(Candidate {
        height,
        digest,
        parent,
        certificate,
        dkg,
        txs: body.transactions.len(),
    })
}

/// The verification oracle the Lean core calls (the model's VAF-like parameter):
/// does the threshold signature finalize exactly this proposal under this identity?
pub(crate) fn verify_finalization(
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

fn load_identity(path: Option<&std::path::Path>) -> eyre::Result<(u64, Vec<u8>)> {
    let text = match path {
        Some(p) => std::fs::read_to_string(p)?,
        None => include_str!("../../../../testnet-network-identity.json").to_string(),
    };
    let f: IdentityFile = serde_json::from_str(&text)?;
    let key = alloy_primitives::hex::decode(f.identity.trim_start_matches("0x"))?;
    <MinSig as Variant>::Public::decode(key.as_slice()).map_err(|e| eyre!("bad identity: {e}"))?;
    Ok((f.from_epoch, key))
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    let (from_epoch, key) = load_identity(args.identity.as_deref())?;
    let rpc = Rpc {
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?,
        url: args.rpc.clone(),
    };

    let start = match args.from.as_str() {
        "latest" => {
            let latest = rpc
                .finalization(serde_json::json!("latest"))
                .await?
                .ok_or_eyre("no latest finalization")?;
            latest.block.header.number()
        }
        s if s.starts_with("epoch:") => s[6..].parse::<u64>()? * args.epoch_length,
        s => s.parse()?,
    };

    if args.check_oracle {
        let latest = rpc
            .finalization(serde_json::json!("latest"))
            .await?
            .ok_or_eyre("no latest finalization")?;
        let bytes = alloy_primitives::hex::decode(&latest.certificate)?;
        let f = Finalization::<Scheme<PublicKey, MinSig>, Digest>::decode(bytes.as_slice())
            .map_err(|e| eyre!("{e}"))?;
        let sig = commonware_codec::Encode::encode(&f.certificate).to_vec();
        let p = &f.proposal;
        let (e, v, pv) = (p.round.epoch().get(), p.round.view().get(), p.parent.get());
        let ok = verify_finalization(&key, e, v, pv, &p.payload.0, &sig);
        let mut tampered = p.payload.0;
        tampered[0] ^= 1;
        let bad = verify_finalization(&key, e, v, pv, &tampered, &sig);
        let digest_ok = p.payload.0 == latest.block.header.hash_slow().0;
        println!(
            "height {} epoch {e} view {v} parent {pv}: signature {ok}, tampered payload {bad}, payload == keccak(header) {digest_ok}",
            latest.block.header.number()
        );
        return Ok(());
    }

    let mut core = core::Core::new(args.epoch_length, from_epoch, &key)?;
    eprintln!(
        "kaizen-follower: verified core ready; network identity from epoch {from_epoch}; syncing from height {start} via {}",
        args.rpc
    );

    let t0 = Instant::now();
    let mut accepted = 0u64;
    let mut txs = 0usize;
    let mut next = start;
    let mut last_report = Instant::now();
    let mut head = start;
    loop {
        if next > head {
            let latest = rpc
                .finalization(serde_json::json!("latest"))
                .await?
                .ok_or_eyre("no latest finalization")?;
            head = latest.block.header.number();
            if next > head {
                tokio::time::sleep(Duration::from_millis(300)).await;
                continue;
            }
        }
        // Fetch a window of heights concurrently, then feed them to the core strictly in order.
        let end = head.min(next + args.concurrency as u64 * 4 - 1);
        let window: Vec<u64> = (next..=end).collect();
        let fetched: BTreeMap<u64, eyre::Result<Option<RpcCertified>>> =
            stream::iter(window.clone())
                .map(|h| {
                    let rpc = &rpc;
                    async move { (h, rpc.finalization(serde_json::json!({"height": h})).await) }
                })
                .buffer_unordered(args.concurrency)
                .collect()
                .await;
        let mut progressed = false;
        for (h, res) in fetched {
            let Some(c) = res? else { break };
            let cand = prepare(c, args.epoch_length)?;
            if cand.height != h {
                bail!("upstream returned height {} for query {h}", cand.height);
            }
            let code = core.step(&cand);
            if code != 0 {
                bail!(
                    "verified core rejected block {h} with code {code} ({})",
                    core::describe(code)
                );
            }
            if let Some((e, _)) = &cand.dkg {
                eprintln!(
                    "height {h}: epoch boundary accepted; core registered identity for epoch {e}"
                );
            }
            accepted += 1;
            txs += cand.txs;
            next = h + 1;
            progressed = true;
            if args.count != 0 && accepted >= args.count {
                break;
            }
        }
        if last_report.elapsed() > Duration::from_secs(10)
            || (args.count != 0 && accepted >= args.count)
        {
            let rate = accepted as f64 / t0.elapsed().as_secs_f64();
            eprintln!(
                "tip {} (0x{}) accepted {accepted} blocks, {txs} txs, {rate:.1} blocks/s",
                core.tip_height(),
                alloy_primitives::hex::encode(core.tip_digest())
            );
            last_report = Instant::now();
        }
        if args.count != 0 && accepted >= args.count {
            break;
        }
        if !progressed {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
    println!(
        "{{\"accepted\":{accepted},\"tip_height\":{},\"tip_digest\":\"0x{}\",\"seconds\":{:.1}}}",
        core.tip_height(),
        alloy_primitives::hex::encode(core.tip_digest()),
        t0.elapsed().as_secs_f64()
    );
    Ok(())
}
