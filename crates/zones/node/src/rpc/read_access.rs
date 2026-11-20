//! Which accounts' private data an authenticated caller may read through the redacted RPC.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, BlockNumber};
use reth_provider::ChainSpecProvider;
use reth_storage_api::{BlockReaderIdExt, StateProviderFactory};
use tempo_chainspec::TempoHardforks;
use tempo_evm::TempoStateAccess as _;
use tempo_precompiles::storage::StorageActions;
use zone_precompiles::zone_identity::ZoneIdentity;

/// How a reader may read all of an account's private data: balance, nonce, transactions, and logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReadAccess {
    /// The reader is the account.
    Own,
    /// `ZoneIdentity.canRead` allows the reader at block `latest`.
    Delegated { latest: BlockNumber },
}

impl ReadAccess {
    /// `reader`'s access to `account`'s data, or `None` if `canRead` denies it at the latest block.
    pub(super) fn at_latest<P>(
        provider: &P,
        reader: Address,
        account: Address,
    ) -> eyre::Result<Option<Self>>
    where
        P: BlockReaderIdExt + StateProviderFactory + ChainSpecProvider<ChainSpec: TempoHardforks>,
    {
        if reader == account {
            return Ok(Some(Self::Own));
        }
        let Some(header) = provider.latest_header()? else {
            return Ok(None);
        };
        let spec = provider.chain_spec().tempo_hardfork_at(header.timestamp());
        if !spec.is_t15() {
            return Ok(None);
        }
        let readable = provider
            .state_by_block_hash(header.hash())?
            .with_read_only_storage_ctx(spec, StorageActions::disabled(), || {
                ZoneIdentity::new().can_read(reader, account)
            })?;
        Ok(readable.then_some(Self::Delegated {
            latest: header.number(),
        }))
    }
}
