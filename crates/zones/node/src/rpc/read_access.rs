//! Which accounts' and orgs' private data a caller may read through the redacted RPC.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, BlockNumber};
use eyre::OptionExt as _;
use reth_provider::ChainSpecProvider;
use reth_storage_api::{BlockReaderIdExt, StateProviderFactory};
use tempo_chainspec::TempoHardforks;
use tempo_evm::TempoStateAccess as _;
use tempo_precompiles::storage::StorageActions;
use zone_precompiles::zone_identity::ZoneIdentity;
use zone_rpc::filter::LogScope;

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
    pub(super) fn check<P>(
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
        let latest = identity_allows(provider, |identity| identity.can_read(reader, account))?;
        Ok(latest.map(|latest| Self::Delegated { latest }))
    }
}

/// Whether `reader` may read `scope`'s logs at the latest block.
pub(super) fn can_read_logs<P>(provider: &P, reader: Address, scope: LogScope) -> eyre::Result<bool>
where
    P: BlockReaderIdExt + StateProviderFactory + ChainSpecProvider<ChainSpec: TempoHardforks>,
{
    Ok(match scope {
        LogScope::Account(account) => ReadAccess::check(provider, reader, account)?.is_some(),
        LogScope::Org(org) => {
            identity_allows(provider, |identity| identity.can_read_org(reader, org))?.is_some()
        }
    })
}

/// The latest block's number if `allows` holds for its `ZoneIdentity`; `None` otherwise or pre-T15.
pub(super) fn identity_allows<P>(
    provider: &P,
    allows: impl FnOnce(ZoneIdentity) -> zone_precompiles::Result<bool>,
) -> eyre::Result<Option<BlockNumber>>
where
    P: BlockReaderIdExt + StateProviderFactory + ChainSpecProvider<ChainSpec: TempoHardforks>,
{
    let latest = provider.latest_header()?.ok_or_eyre("no latest block")?;
    let spec = provider.chain_spec().tempo_hardfork_at(latest.timestamp());
    if !spec.is_t15() {
        return Ok(None);
    }
    let allowed = provider
        .state_by_block_hash(latest.hash())?
        .with_read_only_storage_ctx(spec, StorageActions::disabled(), || {
            allows(ZoneIdentity::new())
        })?;
    Ok(allowed.then_some(latest.number()))
}
