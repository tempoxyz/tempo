//! Kaizen stage III: the unverified shim around the Lean-verified Simplex follower core.
//!
//! The shim fetches certified blocks from a Tempo node's consensus RPC, does the
//! application-specific work the Lean model takes as parameters (header hashing,
//! body-against-header commitments, DKG outcome parsing, BLS threshold signature
//! verification), and hands every candidate to the extracted Lean step function,
//! which alone decides whether the follower's tip advances.

use std::{
    collections::{BTreeMap, HashMap},
    num::{NonZeroU64, NonZeroUsize},
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
mod exec;
mod mpt;

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
    #[arg(long, default_value = "16")]
    concurrency: NonZeroUsize,
    /// Network identity JSON ({"from_epoch", "identity"}), defaults to the compiled testnet one.
    #[arg(long)]
    identity: Option<std::path::PathBuf>,
    /// Epoch length in blocks (testnet and mainnet genesis: 21600).
    #[arg(long, default_value = "21600")]
    epoch_length: NonZeroU64,
    /// Only check the BLS oracle against the latest finalization, decoded by commonware, and exit.
    #[arg(long)]
    check_oracle: bool,
    /// Only re-execute these many blocks ending at --from (or the latest) and compare state roots.
    #[arg(long)]
    check_exec: Option<u64>,
    /// RPC serving eth_getProof/eth_getCode for the execution oracle (rpc.testnet.tempo.xyz refuses eth_getProof).
    #[arg(long, default_value = "https://rpc.moderato.tempo.xyz")]
    proof_rpc: String,
    /// Concurrent block re-executions.
    #[arg(long, default_value = "8")]
    exec_concurrency: NonZeroUsize,
    /// Do not re-execute blocks: the execution oracle answers true (consensus-only mode).
    #[arg(long)]
    trust_execution: bool,
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
    state_root: [u8; 32],
    certificate: Vec<u8>,
    dkg: Option<(u64, Vec<u8>)>,
    txs: usize,
}

struct Rpc {
    client: reqwest::Client,
    url: String,
    /// Retry transient errors forever (follow mode) instead of giving up after a few attempts.
    retry_forever: bool,
}

/// Largest response body accepted from the untrusted upstream (a full block is a few MiB).
const MAX_RESPONSE_BYTES: usize = 64 << 20;

/// Reads a response body, refusing more than [`MAX_RESPONSE_BYTES`] before allocating it.
async fn read_capped(mut resp: reqwest::Response) -> eyre::Result<Vec<u8>> {
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
    {
        bail!("response body over {MAX_RESPONSE_BYTES} bytes");
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if out.len() + chunk.len() > MAX_RESPONSE_BYTES {
            bail!("response body over {MAX_RESPONSE_BYTES} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

impl Rpc {
    /// The latest finalization. A restarting upstream answers "not available" until its next
    /// finalization; in follow mode that is waited out like any other transient error.
    async fn latest(&self) -> eyre::Result<RpcCertified> {
        loop {
            match self.finalization(serde_json::json!("latest")).await? {
                Some(c) => return Ok(c),
                None if self.retry_forever => {
                    eprintln!("upstream has no latest finalization yet; waiting");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                None => bail!("no latest finalization"),
            }
        }
    }

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
                if !status.is_success() {
                    bail!("HTTP {status}");
                }
                let bytes = read_capped(resp).await?;
                let mut v: serde_json::Value = serde_json::from_slice(&bytes)?;
                if let Some(err) = v.get("error") {
                    // 204 (NotReady) and 503 (Missing): the upstream does not have it (yet).
                    if matches!(err.get("code").and_then(|c| c.as_i64()), Some(204 | 503)) {
                        return Ok(None);
                    }
                    bail!("rpc error: {err}");
                }
                Ok(Some(serde_json::from_value(v["result"].take())?))
            }
            .await;
            match res {
                Ok(r) => return Ok(r),
                Err(e) if self.retry_forever || attempt < 8 => {
                    eprintln!("retrying {query} after error: {e:#}");
                    tokio::time::sleep(Duration::from_millis((250 * attempt).min(5_000))).await;
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
    let state_root = header.state_root().0;
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
        state_root,
        certificate,
        dkg,
        txs: body.transactions.len(),
    })
}

/// Post-state roots of blocks re-executed by [`exec::execute`], keyed by (pre-state root, digest).
static EXECUTED: std::sync::LazyLock<Mutex<HashMap<([u8; 32], [u8; 32]), [u8; 32]>>> =
    std::sync::LazyLock::new(Default::default);
static TRUST_EXECUTION: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The execution oracle the Lean core calls: did re-executing this block on the state with root
/// `pre` reach `post`?
pub(crate) fn verify_execution(pre: &[u8], digest: &[u8], post: &[u8]) -> bool {
    if TRUST_EXECUTION.load(std::sync::atomic::Ordering::Relaxed) {
        return true;
    }
    let (Ok(pre), Ok(digest)) = (<[u8; 32]>::try_from(pre), <[u8; 32]>::try_from(digest)) else {
        return false;
    };
    EXECUTED
        .lock()
        .unwrap()
        .get(&(pre, digest))
        .is_some_and(|p| p[..] == post[..])
}

/// Loads the 256 block hashes before `start` for BLOCKHASH, each checked against its successor's
/// parent hash down from block `start`. Block `start` itself is checked by the core.
/// Build the blocking proof client on a blocking thread: reqwest's blocking builder enters (and,
/// in debug builds, creates and drops) a Tokio runtime, which panics on an async worker.
async fn new_proof_rpc(url: String) -> eyre::Result<exec::ProofRpc> {
    tokio::task::spawn_blocking(move || exec::ProofRpc::new(url)).await?
}

/// Fetch the 256 ancestors of start for BLOCKHASH, linked by parent hashes to the header the
/// upstream serves at start. That header is recorded in hashes too, so the main loop can
/// insist that the block the core certifies at start is the same one the ancestors hang from.
async fn backfill_hashes(
    rpc: &Rpc,
    start: u64,
    hashes: &std::sync::Arc<Mutex<BTreeMap<u64, alloy_primitives::B256>>>,
    concurrency: usize,
) -> eyre::Result<()> {
    let from = start.saturating_sub(256);
    let headers: BTreeMap<u64, TempoHeader> = stream::iter(from..=start)
        .map(|h| async move { (h, rpc.finalization(serde_json::json!({"height": h})).await) })
        .buffer_unordered(concurrency)
        .map(|(h, r)| {
            r.and_then(|c| c.ok_or_eyre("missing ancestor"))
                .map(|c| (h, c.block.header))
        })
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<eyre::Result<_>>()?;
    let mut expected = headers[&start].parent_hash();
    let mut map = hashes.lock().unwrap();
    map.insert(start, headers[&start].hash_slow());
    for h in (from..start).rev() {
        let hash = headers[&h].hash_slow();
        if hash != expected {
            bail!("ancestor {h} does not link to its successor");
        }
        map.insert(h, hash);
        expected = headers[&h].parent_hash();
    }
    Ok(())
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
        retry_forever: args.count == 0,
    };

    let start = match args.from.as_str() {
        "latest" => {
            let latest = rpc.latest().await?;
            latest.block.header.number()
        }
        s if s.starts_with("epoch:") => s[6..]
            .parse::<u64>()?
            .checked_mul(args.epoch_length.get())
            .ok_or_eyre("epoch:N overflows the height")?,
        s => s.parse()?,
    };

    if let Some(n) = args.check_exec {
        let proof_rpc = new_proof_rpc(args.proof_rpc.clone()).await?;
        let end = start;
        let hashes = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
        backfill_hashes(&rpc, end, &hashes, args.concurrency.get()).await?;
        let mut ok = 0;
        for h in end + 1 - n..=end {
            let parent = rpc
                .finalization(serde_json::json!({"height": h - 1}))
                .await?
                .ok_or_eyre("missing parent")?;
            let block = rpc
                .finalization(serde_json::json!({"height": h}))
                .await?
                .ok_or_eyre("missing block")?;
            let pre = parent.block.header.state_root();
            let want = block.block.header.state_root();
            let (header, body) = (block.block.header.clone(), block.block.body.clone());
            let (pr, hs) = (proof_rpc.clone(), hashes.clone());
            let t = Instant::now();
            let res =
                tokio::task::spawn_blocking(move || exec::execute(&pr, &header, &body, pre, hs))
                    .await?;
            match res {
                Ok(o) => {
                    let m = o.post_root == want;
                    ok += m as u64;
                    println!(
                        "height {h}: {} txs, post-state root {} header ({} accounts, {} slots, {} reveals, {:.0} ms)",
                        block.block.body.transactions.len(),
                        if m { "==" } else { "!=" },
                        o.accounts,
                        o.slots,
                        o.reveals,
                        t.elapsed().as_secs_f64() * 1e3
                    );
                }
                Err(e) => println!("height {h}: execution error: {e:#}"),
            }
        }
        println!("{ok}/{n} blocks re-executed to the header's state root");
        return Ok(());
    }

    if args.check_oracle {
        let latest = rpc.latest().await?;
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

    let mut core = core::Core::new(args.epoch_length.get(), from_epoch, &key)?;
    eprintln!(
        "kaizen-follower: verified core ready; network identity from epoch {from_epoch}; syncing from height {start} via {}",
        args.rpc
    );

    let t0 = Instant::now();
    let mut accepted = 0u64;
    let mut txs = 0usize;
    let mut next = start;
    let mut last_report = Instant::now();
    let (mut executed, mut exec_accounts, mut exec_slots, mut reveals) =
        (0u64, 0usize, 0usize, 0usize);
    TRUST_EXECUTION.store(args.trust_execution, std::sync::atomic::Ordering::Relaxed);
    if args.trust_execution {
        eprintln!(
            "WARNING: --trust-execution: blocks are not re-executed; the core accepts any state root"
        );
    }
    let proof_rpc = new_proof_rpc(args.proof_rpc.clone()).await?;
    let hashes = std::sync::Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    if !args.trust_execution {
        backfill_hashes(&rpc, start, &hashes, args.concurrency.get()).await?;
    }
    let mut head = start;
    loop {
        if next > head {
            let latest = rpc.latest().await?;
            head = latest.block.header.number();
            if next > head {
                tokio::time::sleep(Duration::from_millis(300)).await;
                continue;
            }
        }
        // Fetch a window of heights concurrently, then feed them to the core strictly in order.
        let window_len =
            (args.concurrency.get() as u64 * 4).max(args.exec_concurrency.get() as u64);
        let end = head.min(next + window_len - 1);
        let window: Vec<u64> = (next..=end).collect();
        let fetched: BTreeMap<u64, eyre::Result<Option<RpcCertified>>> =
            stream::iter(window.clone())
                .map(|h| {
                    let rpc = &rpc;
                    async move { (h, rpc.finalization(serde_json::json!({"height": h})).await) }
                })
                .buffer_unordered(args.concurrency.get())
                .collect()
                .await;
        let mut progressed = false;
        let mut prepared = Vec::new();
        for (h, res) in fetched {
            let Some(c) = res? else { break };
            let block = (c.block.header.clone(), c.block.body.clone());
            let cand = prepare(c, args.epoch_length.get())?;
            if cand.height != h {
                bail!("upstream returned height {} for query {h}", cand.height);
            }
            let digest = alloy_primitives::B256::from(cand.digest);
            if let Some(prev) = hashes.lock().unwrap().insert(h, digest)
                && prev != digest
            {
                bail!("block {h} differs from the one its BLOCKHASH ancestors were linked to");
            }
            prepared.push((cand, block));
        }
        if !args.trust_execution {
            // Re-execute every block whose parent state root is known (the tip's, then each
            // predecessor's in the window), concurrently; the core consults the results.
            let mut pre = core.has_tip().then(|| core.tip_state_root());
            let mut jobs = Vec::new();
            for (cand, (header, body)) in &prepared {
                if let Some(p) = pre {
                    jobs.push((p, cand.digest, header.clone(), body.clone()));
                }
                pre = Some(cand.state_root);
            }
            let results: Vec<_> = stream::iter(jobs)
                .map(|(p, d, header, body)| {
                    let (pr, hs) = (proof_rpc.clone(), hashes.clone());
                    async move {
                        let h = header.number();
                        let r = tokio::task::spawn_blocking(move || {
                            exec::execute(&pr, &header, &body, alloy_primitives::B256::from(p), hs)
                        })
                        .await;
                        (p, d, h, r)
                    }
                })
                .buffer_unordered(args.exec_concurrency.get())
                .collect()
                .await;
            for (p, d, h, r) in results {
                match r {
                    Ok(Ok(o)) => {
                        executed += 1;
                        exec_accounts += o.accounts;
                        exec_slots += o.slots;
                        reveals += o.reveals;
                        EXECUTED.lock().unwrap().insert((p, d), o.post_root.0);
                    }
                    Ok(Err(e)) => eprintln!("height {h}: re-execution failed: {e:#}"),
                    Err(e) => eprintln!("height {h}: re-execution panicked: {e}"),
                }
            }
        }
        for (cand, _) in prepared {
            let h = cand.height;
            // A block whose re-execution did not finish (proof RPC unavailable, reveal limit)
            // has no verdict yet: stall and retry it rather than letting the core read the
            // missing result as a state-root mismatch. Code 12 stays for computed mismatches.
            let exec_key = core.has_tip().then(|| (core.tip_state_root(), cand.digest));
            if !args.trust_execution
                && let Some(key) = exec_key
                && !EXECUTED.lock().unwrap().contains_key(&key)
            {
                eprintln!("height {h}: re-execution unavailable; retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
                break;
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
            // Keep memory bounded while following forever: drop the consumed execution result
            // and block hashes the EVM can no longer read (BLOCKHASH sees the last 256).
            if let Some(key) = exec_key {
                EXECUTED.lock().unwrap().remove(&key);
            }
            hashes.lock().unwrap().retain(|&k, _| k + 256 >= h);
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
                "tip {} (0x{}) state 0x{} accepted {accepted} blocks, {txs} txs, {rate:.1} blocks/s; re-executed {executed} ({exec_accounts} accounts, {exec_slots} slots proven, {reveals} extra trie reveals)",
                core.tip_height(),
                alloy_primitives::hex::encode(core.tip_digest()),
                alloy_primitives::hex::encode(core.tip_state_root())
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
