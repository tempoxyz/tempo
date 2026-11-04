//! Corpus blocks as fuzz harness inputs. Each block, on the exact pre-state it read, becomes a
//! [`TempoHarnessInput::Blockchain`] on the corpus's chain. A block list file names a subset of a
//! corpus, such as the blocks a minimizer kept.

use crate::{
    code,
    store::{self, Catalog, Lease, Store},
    types::Input,
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
use tracing::warn;

/// A corpus, open at its published checkpoint. A fill extending it meanwhile does not change
/// what this reads.
pub struct Corpus {
    runtime: Runtime,
    store: Store,
    /// Keeps the snapshot readable while a fill extends the corpus; taken when dropped.
    lease: Option<Lease>,
    reader: DbReader,
    catalog: Catalog,
    chain_spec: ChainSpecInput,
}

impl Corpus {
    /// Opens the published blocks of the corpus at `url` (`s3://bucket/prefix` or
    /// `file:///directory`), with S3 reads going to `endpoint` when given.
    pub fn open(url: &str, endpoint: Option<&str>) -> eyre::Result<Self> {
        // One worker renews the lease while the caller is not reading.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let (store, mut catalog) = runtime.block_on(async {
            let store = Store::open(url, endpoint).await?;
            let (catalog, _) = store
                .catalog()
                .await?
                .ok_or_else(|| eyre::eyre!("no corpus catalog at {url}"))?;
            eyre::Ok((store, catalog))
        })?;
        let lease = store.lease_published(&runtime, &mut catalog, || {})?;
        let (reader, tip) = runtime.block_on(async {
            let reader = store.reader(&catalog).await?;
            let tip = store::tip_timestamp(&reader, &catalog.cursor).await?;
            eyre::Ok((reader, tip))
        })?;
        let chain_spec = chain_spec_input(&catalog, tip)?;
        Ok(Self {
            runtime,
            store,
            lease: Some(lease),
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
        eyre::ensure!(
            !self.lease.as_ref().is_some_and(Lease::expiring),
            "corpus lease expires before it can be renewed"
        );
        let stored = self
            .runtime
            .block_on(store::published(&self.reader, block))?
            .1;
        let input = harness_input(&stored, self.chain_spec.clone())?;
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

impl Drop for Corpus {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take()
            && let Err(error) = lease.release(&self.runtime, &self.store)
        {
            warn!(%error, "Releasing the corpus lease failed; it expires on its own");
        }
    }
}

/// The harness chain of `catalog`'s corpus, taken from the known chain whose forks agree with it
/// up to its `tip` timestamp ([`store::forks_agree`]). Forks that never activate get `u64::MAX`.
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

/// `stored`'s block on the exact pre-state it read. Its code must be resolved
/// ([`store::resolve_code`]).
fn harness_input(stored: &Input, chain_spec: ChainSpecInput) -> eyre::Result<TempoBlockchainInput> {
    let mut accounts = BTreeMap::<Address, AccountInput>::new();
    for (address, info) in &stored.accounts {
        let Some(info) = info else {
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
    for ((address, slot), value) in &stored.storage {
        accounts
            .entry(Address::from(*address))
            .or_default()
            .storage
            .insert(U256::from_be_bytes(*slot), U256::from_be_bytes(*value));
    }
    let block: Block = alloy_rlp::decode_exact(&stored.block.rlp)?;
    let block = TempoBlock {
        header: BlockHeaderInput::Rlp(alloy_rlp::encode(&block.header).into()),
        txs: block
            .body
            .transactions
            .iter()
            .map(|tx| tx.encoded_2718().into())
            .collect(),
        senders: stored
            .block
            .senders
            .iter()
            .copied()
            .map(Address::from)
            .collect(),
    };
    Ok(TempoBlockchainInput {
        chain_spec,
        pre_state: PreState::Exact {
            state: StateInput { accounts },
            block_hashes: stored
                .hashes
                .iter()
                .map(|(n, hash)| (*n, B256::from(*hash)))
                .collect(),
        },
        blocks: NonEmpty::try_from(vec![block]).map_err(|err| eyre::eyre!(err))?,
    })
}

/// A block list section naming `catalog`'s corpus and `blocks` of it, one per line. A block list
/// file holds one section per corpus.
pub fn block_list<'a>(catalog: &Catalog, blocks: impl IntoIterator<Item = &'a u64>) -> String {
    let context = &catalog.context;
    let header = format!(
        "# corpus {}..{} parent {} tip {} checkpoint {}\n",
        context.start,
        catalog.cursor.next,
        context.parent,
        B256::from(catalog.cursor.parent),
        catalog.checkpoint.as_deref().unwrap_or("none")
    );
    blocks
        .into_iter()
        .fold(header, |text, block| text + &format!("{block}\n"))
}

/// The blocks a block list file lists for `catalog`'s corpus: those under its section header, and
/// any before the first header, which must be in its range. Other `#` lines are comments.
pub fn read_blocks(path: &Path, catalog: &Catalog) -> eyre::Result<Vec<u64>> {
    let context = &catalog.context;
    // A corpus grows at its tip, so a section names it by the parent of its first block, and one
    // that ends where this corpus does must also share its tip: another history can share the
    // parent. Sections written before that name it by the tip it had then, which matches only an
    // unextended corpus. Other `#` lines are comments.
    let end = format!("..{}", catalog.cursor.next);
    let parent = format!(" parent {} ", context.parent);
    let tip = format!(" tip {} ", B256::from(catalog.cursor.parent));
    let (mut blocks, mut ours) = (Vec::new(), true);
    for line in fs::read_to_string(path)?.lines().map(str::trim) {
        if let Some(header) = line.strip_prefix("# corpus ") {
            ours = if header.contains(" parent ") {
                header.contains(&parent)
                    && (header.contains(&tip)
                        || !header
                            .split_once(' ')
                            .is_some_and(|(range, _)| range.ends_with(&end)))
            } else {
                header.contains(&tip)
            };
        } else if ours && !line.is_empty() && !line.starts_with('#') {
            let block: u64 = line.parse()?;
            eyre::ensure!(
                (context.start..catalog.cursor.next).contains(&block),
                "block {block} is outside the corpus"
            );
            blocks.push(block);
        }
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::catalog;

    #[test]
    fn read_blocks_skips_comments_and_other_sections() -> eyre::Result<()> {
        let mut ours = catalog(10, 10, 0);
        ours.cursor.next = 20;
        let mut other = catalog(15, 5, 0);
        other.cursor.next = 20;
        // Same tip, another start parent.
        other.context.parent = B256::repeat_byte(1).to_string();
        // Same start parent and end, another tip.
        let mut fork = ours.clone();
        fork.cursor.parent = [1; 32];
        let list = format!(
            "{}# dex hits\n13\n{}16\n{}",
            block_list(&ours, &[12]),
            block_list(&other, &[17]),
            block_list(&fork, &[18]),
        );
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("blocks");
        fs::write(&path, list)?;
        assert_eq!(read_blocks(&path, &ours)?, [12, 13]);
        assert_eq!(read_blocks(&path, &other)?, [17, 16]);
        assert_eq!(read_blocks(&path, &fork)?, [18]);
        Ok(())
    }
}
