//! Corpus blocks as fuzz harness inputs, read straight from the corpus: each block, on the exact
//! pre-state it read, becomes a [`TempoHarnessInput::Blockchain`] on the corpus's chain. A block
//! list file names a subset of a corpus, such as the blocks a corpus minimizer kept.

use crate::{
    code,
    store::{self, Catalog, Store},
    types::Chunk,
};
use alloy_eips::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, U256};
use reth_chainspec::{EthChainSpec, ForkCondition};
use slatedb::DbReader;
use std::{collections::BTreeMap, fs, path::Path};
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
    spec::{MODERATO, PRESTO},
};
use tempo_fuzz_types::{
    AccountInput, BlockHeaderInput, ChainSpecInput, NonEmpty, PreState, StateInput, TempoBlock,
    TempoBlockchainInput, TempoHarnessInput,
};
use tempo_primitives::Block;
use tokio::runtime::Runtime;

/// A complete corpus, open at its published checkpoint.
pub struct Corpus {
    runtime: Runtime,
    reader: DbReader,
    catalog: Catalog,
    chain_spec: ChainSpecInput,
}

impl Corpus {
    /// Opens the complete corpus at `url` (`s3://bucket/prefix` or `file:///directory`). S3 reads
    /// go to `endpoint` when given, with the standard AWS credential chain.
    pub fn open(url: &str, endpoint: Option<&str>) -> eyre::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (reader, catalog, tip) = runtime.block_on(async {
            let store = Store::open(url, endpoint).await?;
            let (catalog, _) = store
                .catalog()
                .await?
                .ok_or_else(|| eyre::eyre!("no corpus catalog at {url}"))?;
            eyre::ensure!(catalog.complete, "corpus {url} is not complete");
            let reader = store.reader(&catalog).await?;
            let tip = store::tip_timestamp(&reader, &catalog.context).await?;
            eyre::Ok((reader, catalog, tip))
        })?;
        let chain_spec = chain_spec_input(&catalog, tip)?;
        Ok(Self {
            runtime,
            reader,
            catalog,
            chain_spec,
        })
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// `block`'s harness input.
    pub fn input(&self, block: u64) -> eyre::Result<TempoHarnessInput> {
        let chunk = self
            .runtime
            .block_on(store::published(&self.reader, block))?
            .1;
        let input = harness_input(&chunk, self.chain_spec.clone())?;
        Ok(TempoHarnessInput::Blockchain(input))
    }

    /// Each of `blocks` with its harness input, in the order given.
    pub fn inputs(
        &self,
        blocks: impl IntoIterator<Item = u64>,
    ) -> impl Iterator<Item = eyre::Result<(u64, TempoHarnessInput)>> {
        blocks
            .into_iter()
            .map(|block| Ok((block, self.input(block)?)))
    }
}

/// The harness chain of `catalog`'s corpus: its chain ID and hardfork schedule, from the known
/// chain it was captured from, whose forks must agree with the corpus up to its `tip` timestamp
/// ([`store::forks_agree`]). A hardfork that chain never activates is scheduled at `u64::MAX`.
fn chain_spec_input(catalog: &Catalog, tip: u64) -> eyre::Result<ChainSpecInput> {
    let context = &catalog.context;
    let spec: &TempoChainSpec = [&**PRESTO, &**MODERATO]
        .into_iter()
        .find(|spec| {
            context.chain_id == spec.chain_id()
                && context.genesis == spec.genesis_hash().to_string()
                && store::forks_agree(&context.forks, &spec.display_hardforks().to_string(), tip)
        })
        .ok_or_else(|| eyre::eyre!("corpus chain {} is not a known chain", context.chain_id))?;
    let hardforks = TempoHardfork::VARIANTS
        .iter()
        .map(|&fork| match spec.tempo_fork_activation(fork) {
            ForkCondition::Timestamp(at) => Ok((fork, at)),
            ForkCondition::Never => Ok((fork, u64::MAX)),
            condition => eyre::bail!("{fork:?} activates by {condition:?}, not by timestamp"),
        })
        .collect::<eyre::Result<_>>()?;
    Ok(ChainSpecInput {
        chain_id: spec.chain_id(),
        hardforks,
    })
}

/// `chunk`'s blocks on the exact pre-state they read. Its code must be resolved
/// ([`store::resolve_code`]).
fn harness_input(chunk: &Chunk, chain_spec: ChainSpecInput) -> eyre::Result<TempoBlockchainInput> {
    let mut accounts = BTreeMap::<Address, AccountInput>::new();
    // `Chunk::validate` ensures every key's first version is the state before the chunk.
    for (address, versions) in &chunk.accounts {
        let Some(info) = &versions[0].1 else {
            accounts.insert(Address::from(*address), AccountInput::default());
            continue;
        };
        let account = info.account();
        let code = match account.bytecode_hash {
            Some(hash) => code::code_bytes(&hash.0)
                .ok_or_else(|| eyre::eyre!("unresolved corpus code {hash}"))?,
            None => Bytes::new(),
        };
        accounts.insert(
            Address::from(*address),
            AccountInput {
                balance: account.balance,
                nonce: account.nonce,
                code,
                storage: BTreeMap::new(),
            },
        );
    }
    for ((address, slot), versions) in &chunk.storage {
        accounts
            .entry(Address::from(*address))
            .or_default()
            .storage
            .insert(
                U256::from_be_bytes(*slot),
                U256::from_be_bytes(versions[0].1),
            );
    }
    let blocks = chunk
        .blocks
        .iter()
        .map(|input| {
            let block: Block = alloy_rlp::decode_exact(&input.rlp)?;
            Ok(TempoBlock {
                header: BlockHeaderInput::Rlp(alloy_rlp::encode(&block.header).into()),
                txs: block
                    .body
                    .transactions
                    .iter()
                    .map(|tx| tx.encoded_2718().into())
                    .collect(),
                senders: input.senders.iter().copied().map(Address::from).collect(),
            })
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    Ok(TempoBlockchainInput {
        chain_spec,
        pre_state: PreState::Exact {
            state: StateInput { accounts },
            block_hashes: chunk
                .hashes
                .iter()
                .map(|(n, hash)| (*n, B256::from(*hash)))
                .collect(),
        },
        blocks: NonEmpty::try_from(blocks).map_err(|err| eyre::eyre!(err))?,
    })
}

/// A block list section naming `catalog`'s corpus and `blocks` of it, one per line. A block list
/// file holds one section per corpus.
pub fn block_list(catalog: &Catalog, blocks: &[u64]) -> String {
    let context = &catalog.context;
    let header = format!(
        "# corpus {}..{} tip {} checkpoint {}\n",
        context.start,
        context.end,
        context.tip,
        catalog.checkpoint.as_deref().unwrap_or("none")
    );
    blocks
        .iter()
        .fold(header, |text, block| text + &format!("{block}\n"))
}

/// The blocks of `catalog`'s corpus a block list file lists: those under a section header naming
/// its tip, and those before any header, which must be in its range.
pub fn read_blocks(path: &Path, catalog: &Catalog) -> eyre::Result<Vec<u64>> {
    let context = &catalog.context;
    let tip = format!(" tip {} ", context.tip);
    let (mut blocks, mut ours) = (Vec::new(), true);
    for line in fs::read_to_string(path)?.lines().map(str::trim) {
        if let Some(header) = line.strip_prefix('#') {
            ours = header.contains(&tip);
        } else if ours && !line.is_empty() {
            let block: u64 = line.parse()?;
            eyre::ensure!(
                (context.start..context.end).contains(&block),
                "block {block} is outside the corpus"
            );
            blocks.push(block);
        }
    }
    Ok(blocks)
}
