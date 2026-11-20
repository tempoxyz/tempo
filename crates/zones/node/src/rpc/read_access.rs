//! Which accounts' private data an authenticated caller may read through the redacted RPC.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, BlockNumber};
use alloy_rpc_types_eth::Log;
use reth_provider::{ChainSpecProvider, HeaderProvider};
use reth_storage_api::StateProviderFactory;
use std::collections::{BTreeMap, btree_map::Entry};
use tempo_chainspec::TempoHardforks;
use tempo_evm::TempoStateAccess as _;
use tempo_precompiles::storage::StorageActions;
use zone_precompiles::zone_identity::ZoneIdentity;

/// How a reader may read an account's private data: balance, nonce, transactions, and logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReadAccess {
    /// The reader is the account and reads all of it.
    Own,
    /// `ZoneIdentity.canRead` allows `reader` to view private data of `account` at block `latest`.
    Delegated {
        reader: Address,
        account: Address,
        latest: BlockNumber,
    },
}

impl ReadAccess {
    /// `reader`'s access to `account`'s data, or `None` if `canRead` denies it at the latest block.
    pub(super) fn at_latest<P>(
        provider: &P,
        reader: Address,
        account: Address,
    ) -> eyre::Result<Option<Self>>
    where
        P: HeaderProvider + StateProviderFactory + ChainSpecProvider<ChainSpec: TempoHardforks>,
    {
        if reader == account {
            return Ok(Some(Self::Own));
        }
        let latest = provider.best_block_number()?;
        Ok(
            can_read_at(provider, reader, account, latest)?.then_some(Self::Delegated {
                reader,
                account,
                latest,
            }),
        )
    }

    /// Whether the access covers `block`, where delegated access also needs `canRead`.
    pub(super) fn covers<P>(&self, provider: &P, block: BlockNumber) -> eyre::Result<bool>
    where
        P: HeaderProvider + StateProviderFactory + ChainSpecProvider<ChainSpec: TempoHardforks>,
    {
        match *self {
            Self::Own => Ok(true),
            Self::Delegated { latest, .. } if block == latest => Ok(true),
            Self::Delegated {
                reader, account, ..
            } => can_read_at(provider, reader, account, block),
        }
    }

    /// `logs` without those from uncovered blocks, keeping pending logs.
    pub(super) fn covered_logs<P>(&self, provider: &P, mut logs: Vec<Log>) -> eyre::Result<Vec<Log>>
    where
        P: HeaderProvider + StateProviderFactory + ChainSpecProvider<ChainSpec: TempoHardforks>,
    {
        let mut covered = BTreeMap::new();
        for block in logs.iter().filter_map(|log| log.block_number) {
            if let Entry::Vacant(entry) = covered.entry(block) {
                entry.insert(self.covers(provider, block)?);
            }
        }
        logs.retain(|log| log.block_number.is_none_or(|block| covered[&block]));
        Ok(logs)
    }
}

/// Whether `ZoneIdentity.canRead` allows `reader` to read `account` at `block`.
/// False before `ZoneIdentity` exists and for blocks the node does not have.
fn can_read_at<P>(
    provider: &P,
    reader: Address,
    account: Address,
    block: BlockNumber,
) -> eyre::Result<bool>
where
    P: HeaderProvider + StateProviderFactory + ChainSpecProvider<ChainSpec: TempoHardforks>,
{
    let Some(header) = provider.header_by_number(block)? else {
        return Ok(false);
    };
    let spec = provider.chain_spec().tempo_hardfork_at(header.timestamp());
    if !spec.is_t15() {
        return Ok(false);
    }
    let mut state = provider.history_by_block_number(block)?;
    Ok(
        state.with_read_only_storage_ctx(spec, StorageActions::disabled(), || {
            ZoneIdentity::new().can_read(reader, account)
        })?,
    )
}
