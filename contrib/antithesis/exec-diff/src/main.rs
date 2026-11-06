//! Bounded, finalized-state differential checks between independently configured execution nodes.

use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_rpc_types_eth::{EIP1186AccountProofResponse, Header};
use alloy_trie::{Nibbles, TrieAccount, nodes::TrieNode, proof::verify_proof};
use antithesis_instrumentation as _;
use antithesis_sdk::{assert_always, assert_sometimes};
use eyre::{Context, OptionExt, Result, bail, ensure};
use serde::Deserialize;
use serde_json::json;
use std::{collections::HashSet, env, fs, num::NonZeroU64, time::Duration};
use tokio::time::{sleep, timeout};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    endpoints: Vec<Endpoint>,
    subjects: Vec<Subject>,
    rpc_timeout_ms: NonZeroU64,
    eventual_timeout_ms: NonZeroU64,
    retry_interval_ms: NonZeroU64,
}

impl Config {
    fn validate(&self) -> Result<()> {
        ensure!(
            (2..=16).contains(&self.endpoints.len()),
            "expected 2..=16 endpoints"
        );
        ensure!(
            (1..=64).contains(&self.subjects.len()),
            "expected 1..=64 subjects"
        );
        let mut profiles = HashSet::new();
        let mut urls = HashSet::new();
        for endpoint in &self.endpoints {
            ensure!(
                !endpoint.profile.trim().is_empty(),
                "profile must not be empty"
            );
            ensure!(
                profiles.insert(&endpoint.profile),
                "profile labels must be distinct"
            );
            ensure!(urls.insert(&endpoint.url), "endpoint URLs must be distinct");
        }
        let mut addresses = HashSet::new();
        for subject in &self.subjects {
            ensure!(addresses.insert(subject.address), "duplicate subject");
            ensure!(subject.slots.len() <= 64, "at most 64 slots per subject");
            ensure!(
                subject.slots.iter().collect::<HashSet<_>>().len() == subject.slots.len(),
                "duplicate slot"
            );
        }
        ensure!(
            self.rpc_timeout_ms.get() <= 60_000,
            "RPC timeout exceeds 60 seconds"
        );
        ensure!(
            self.eventual_timeout_ms.get() <= 600_000,
            "eventual deadline exceeds 10 minutes"
        );
        ensure!(
            self.retry_interval_ms.get() <= 60_000,
            "retry interval exceeds 60 seconds"
        );
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    profile: String,
    url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Subject {
    address: Address,
    slots: Vec<B256>,
}

#[derive(Debug, PartialEq, Eq)]
struct Verified {
    account: Option<TrieAccount>,
    storage: Vec<U256>,
}

#[derive(Clone, Copy)]
enum Mode {
    Anytime,
    Eventually,
}

#[tokio::main]
async fn main() -> Result<()> {
    antithesis_sdk::antithesis_init();
    let mut comparisons = 0;
    let mut compared_height = None;
    let result = run(&mut comparisons, &mut compared_height).await;
    // This is evaluated on every invocation, including unavailable nodes and invalid input.
    assert_sometimes!(
        comparisons > 0,
        "Distinct execution profiles compare independently proven state",
        &json!({"comparisons": comparisons})
    );
    assert_sometimes!(
        compared_height.is_some_and(|number| number > 0),
        "Execution differential reaches finalized non-genesis state",
        &json!({"height": compared_height})
    );
    result
}

async fn run(comparisons: &mut usize, compared_height: &mut Option<u64>) -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 3,
        "usage: exec-diff-antithesis CONFIG.json anytime|eventually"
    );
    let mode = match args[2].as_str() {
        "anytime" => Mode::Anytime,
        "eventually" => Mode::Eventually,
        _ => bail!("mode must be anytime or eventually"),
    };
    ensure!(
        fs::metadata(&args[1]).wrap_err("stat config")?.len() <= 1_048_576,
        "config exceeds 1 MiB"
    );
    let config: Config = serde_json::from_slice(&fs::read(&args[1]).wrap_err("read config")?)
        .wrap_err("decode config")?;
    config.validate()?;
    let mut providers = Vec::with_capacity(config.endpoints.len());
    for endpoint in &config.endpoints {
        let url = endpoint.url.parse().wrap_err("invalid endpoint URL")?;
        // connect_http only supports HTTP transports; reject other schemes before sampling.
        ensure!(
            endpoint.url.starts_with("http://") || endpoint.url.starts_with("https://"),
            "endpoint must use HTTP or HTTPS"
        );
        providers.push(ProviderBuilder::new().connect_http(url).erased());
    }
    let duration = Duration::from_millis(config.eventual_timeout_ms.get());
    // The configured deadline bounds the whole command, including anytime's single pass.
    let result = match timeout(
        duration,
        check(&config, &providers, mode, comparisons, compared_height),
    )
    .await
    {
        Ok(result) => result,
        Err(error) if matches!(mode, Mode::Eventually) => {
            assert_always!(
                false,
                "Eventually sampled finalized execution state is available"
            );
            Err(eyre::Report::new(error).wrap_err("eventual availability deadline expired"))
        }
        Err(_) => Ok(false),
    };
    if matches!(mode, Mode::Eventually) && result.as_ref().is_ok_and(|complete| *complete) {
        assert_always!(
            true,
            "Eventually sampled finalized execution state is available"
        );
    }
    println!(
        "{}",
        json!({"coverage": result.as_ref().is_ok_and(|complete| *complete), "comparisons": comparisons})
    );
    result.map(|_| ())
}

async fn check(
    config: &Config,
    providers: &[DynProvider],
    mode: Mode,
    comparisons: &mut usize,
    compared_height: &mut Option<u64>,
) -> Result<bool> {
    let rpc_timeout = Duration::from_millis(config.rpc_timeout_ms.get());
    let mut target = None;
    let mut completed: Vec<Option<Vec<Verified>>> = (0..providers.len()).map(|_| None).collect();
    let mut samples: Vec<Vec<Option<Verified>>> = (0..providers.len())
        .map(|_| (0..config.subjects.len()).map(|_| None).collect())
        .collect();
    loop {
        for (index, provider) in providers.iter().enumerate() {
            if completed[index].is_some() {
                continue;
            }
            let response = timeout(rpc_timeout, async {
                provider
                    .get_block_by_number(BlockNumberOrTag::Finalized)
                    .await
            })
            .await;
            let finalized = match response {
                Ok(Ok(Some(block))) => block.header,
                other => {
                    eprintln!(
                        "{}: finalized unavailable: {other:?}",
                        config.endpoints[index].profile
                    );
                    continue;
                }
            };
            // The first independently finalized header pins the target for this entire command.
            let pinned = target.get_or_insert_with(|| finalized.clone());
            if finalized.number < pinned.number {
                continue;
            }
            let response = timeout(rpc_timeout, async {
                provider.get_block_by_number(pinned.number.into()).await
            })
            .await;
            let header = match response {
                Ok(Ok(Some(block))) => block.header,
                _ => continue,
            };
            let same_hash = header.hash == pinned.hash && header.inner == pinned.inner;
            assert_always!(
                same_hash,
                "Independently finalized execution histories agree",
                &json!({
                    "profile": config.endpoints[index].profile, "number": pinned.number,
                    "expected": pinned.hash, "actual": header.hash
                })
            );
            ensure!(same_hash, "independently finalized block hashes diverge");
            let mut proofs = Vec::with_capacity(config.subjects.len());
            for (subject_index, subject) in config.subjects.iter().enumerate() {
                if samples[index][subject_index].is_some() {
                    continue;
                }
                match timeout(rpc_timeout, async {
                    provider
                        .get_proof(subject.address, subject.slots.clone())
                        .block_id(BlockId::hash_canonical(pinned.hash))
                        .await
                })
                .await
                {
                    Ok(Ok(proof)) => proofs.push((subject_index, proof)),
                    other => {
                        eprintln!(
                            "{}: proof unavailable: {other:?}",
                            config.endpoints[index].profile
                        );
                    }
                }
            }
            // Check canonicality again after hash-pinned proof requests.
            let response = timeout(rpc_timeout, async {
                provider.get_block_by_number(pinned.number.into()).await
            })
            .await;
            match response {
                Ok(Ok(Some(block))) if block.header == header => {}
                _ => continue,
            }
            for (subject_index, proof) in &proofs {
                let subject = &config.subjects[*subject_index];
                let result = verify(&header, subject, proof);
                assert_always!(
                    result.is_ok(),
                    "Execution account and storage proofs verify independently",
                    &json!({
                        "profile": config.endpoints[index].profile, "address": subject.address,
                        "block_hash": header.hash, "error": result.as_ref().err().map(|error| format!("{error:#}"))
                    })
                );
                samples[index][*subject_index] = Some(result?);
            }
            if samples[index].iter().any(Option::is_none) {
                continue;
            }
            let verified = samples[index]
                .iter_mut()
                .filter_map(Option::take)
                .collect::<Vec<_>>();
            if let Some(reference) = completed.iter().flatten().next() {
                let equal = reference == &verified;
                assert_always!(
                    equal,
                    "Proven execution account and storage fields agree at identical block hash",
                    &json!({
                        "profile": config.endpoints[index].profile, "block_hash": header.hash
                    })
                );
                ensure!(equal, "proven fields diverge at identical block hash");
                *comparisons += 1;
                *compared_height = Some(pinned.number);
            }
            completed[index] = Some(verified);
        }
        if completed.iter().all(Option::is_some) {
            return Ok(true);
        }
        if matches!(mode, Mode::Anytime) {
            return Ok(false);
        }
        // This retries unfinished finalized-state samples, not transport failures or completed work.
        sleep(Duration::from_millis(config.retry_interval_ms.get())).await;
    }
}

fn verify(
    header: &Header,
    subject: &Subject,
    proof: &EIP1186AccountProofResponse,
) -> Result<Verified> {
    ensure!(proof.address == subject.address, "proof address mismatch");
    let key = Nibbles::unpack(keccak256(subject.address));
    let account = if verify_proof(
        header.state_root,
        key,
        None,
        hashed_nodes(&proof.account_proof),
    )
    .is_ok()
    {
        None
    } else {
        let mut account = None;
        for node in &proof.account_proof {
            if let TrieNode::Leaf(leaf) =
                alloy_rlp::decode_exact::<TrieNode>(node).wrap_err("decode account proof node")?
                && verify_proof(
                    header.state_root,
                    key,
                    Some(leaf.value.clone()),
                    hashed_nodes(&proof.account_proof),
                )
                .is_ok()
            {
                account = Some(
                    alloy_rlp::decode_exact::<TrieAccount>(&leaf.value)
                        .wrap_err("decode Tempo account including extension")?,
                );
                break;
            }
        }
        Some(account.ok_or_eyre("no independently verified account leaf")?)
    };
    let fields = account.clone().unwrap_or_default();
    ensure!(
        fields.nonce == proof.nonce
            && fields.balance == proof.balance
            && (fields.code_hash == proof.code_hash
                || (account.is_none() && proof.code_hash.is_zero()))
            && (fields.storage_root == proof.storage_hash
                || (account.is_none() && proof.storage_hash.is_zero())),
        "RPC account fields do not match proven account"
    );
    ensure!(
        proof.storage_proof.len() == subject.slots.len(),
        "storage proof count mismatch"
    );
    let mut storage = Vec::with_capacity(subject.slots.len());
    for slot in &subject.slots {
        let mut matches = proof
            .storage_proof
            .iter()
            .filter(|entry| entry.key.as_b256() == *slot);
        let entry = matches
            .next()
            .ok_or_eyre("missing requested storage proof")?;
        ensure!(matches.next().is_none(), "duplicate storage proof");
        let expected = (!entry.value.is_zero()).then(|| alloy_rlp::encode(entry.value));
        verify_proof(
            fields.storage_root,
            Nibbles::unpack(keccak256(slot)),
            expected,
            hashed_nodes(&entry.proof),
        )
        .wrap_err("verify storage proof")?;
        storage.push(entry.value);
    }
    Ok(Verified { account, storage })
}

// Inline descendants are already authenticated and traversed by alloy's verifier. Some RPCs
// redundantly append them, whereas the verifier expects only the root and hashed descendants.
fn hashed_nodes(proof: &[Bytes]) -> impl Iterator<Item = &Bytes> {
    proof
        .iter()
        .enumerate()
        .filter(|(index, node)| *index == 0 || node.len() >= 32)
        .map(|(_, node)| node)
}
