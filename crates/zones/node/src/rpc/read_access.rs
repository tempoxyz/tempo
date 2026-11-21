//! Which accounts' private data an authenticated caller may read through the redacted RPC.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, BlockNumber};
use eyre::OptionExt as _;
use reth_primitives_traits::SealedHeader;
use reth_provider::{ChainSpecProvider, HeaderProvider};
use reth_storage_api::{BlockReaderIdExt, StateProviderFactory};
use tempo_chainspec::TempoHardforks;
use tempo_evm::TempoStateAccess as _;
use tempo_precompiles::storage::StorageActions;
use zone_precompiles::zone_identity::{DelegatedRead, ZoneIdentity};

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
        let read = DelegatedRead { reader, account };
        let latest = provider.latest_header()?.ok_or_eyre("no latest block")?;
        let delegated = decide_reads(provider, &latest, [read])? == [(read, true)];

        Ok(delegated.then_some(Self::Delegated {
            latest: latest.number(),
        }))
    }
}

/// Each of `reads` with whether `ZoneIdentity.canRead` allows it at `latest`, false before T15.
pub(super) fn decide_reads<P>(
    provider: &P,
    latest: &SealedHeader<P::Header>,
    reads: impl IntoIterator<Item = DelegatedRead>,
) -> eyre::Result<Vec<(DelegatedRead, bool)>>
where
    P: HeaderProvider + StateProviderFactory + ChainSpecProvider<ChainSpec: TempoHardforks>,
{
    let spec = provider.chain_spec().tempo_hardfork_at(latest.timestamp());
    if !spec.is_t15() {
        return Ok(reads.into_iter().map(|read| (read, false)).collect());
    }
    Ok(provider
        .state_by_block_hash(latest.hash())?
        .with_read_only_storage_ctx(spec, StorageActions::disabled(), || {
            let identity = ZoneIdentity::new();
            reads
                .into_iter()
                .map(|read| Ok((read, identity.can_read(read.reader, read.account)?)))
                .collect::<zone_precompiles::Result<_>>()
        })?)
}
