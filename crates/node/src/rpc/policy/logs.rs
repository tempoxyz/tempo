use crate::rpc::{
    TempoPolicy,
    logs::filter_logs,
    policy::{
        PolicyAddress,
        addresses::{AddressesParams, AddressesResponse},
    },
};
use alloy::sol_types::SolEvent;
use alloy_primitives::U256;
use alloy_rpc_types_eth::Filter;
use itertools::Itertools;
use jsonrpsee::core::RpcResult;
use reth_errors::RethError;
use reth_primitives_traits::NodePrimitives;
use reth_provider::BlockIdReader;
use reth_rpc_eth_api::{EthApiTypes, RpcNodeCore, RpcNodeCoreExt, helpers::SpawnBlocking};
use reth_rpc_eth_types::EthApiError;
use reth_tracing::tracing::debug;
use reth_transaction_pool::TransactionPool;
use tempo_evm::TempoEvmConfig;
use tempo_precompiles::tip403_registry::ITIP403Registry::{BlacklistUpdated, WhitelistUpdated};
use tempo_primitives::TempoHeader;

impl<EthApi> TempoPolicy<EthApi>
where
    EthApi: RpcNodeCore<Evm = TempoEvmConfig, Primitives: NodePrimitives<BlockHeader = TempoHeader>>
        + SpawnBlocking
        + RpcNodeCoreExt<Provider: BlockIdReader, Pool: TransactionPool>
        + EthApiTypes
        + 'static,
{
    pub async fn addresses_using_logs(
        &self,
        params: AddressesParams,
    ) -> RpcResult<AddressesResponse> {
        let authorized = params
            .params
            .filters
            .as_ref()
            .map(|v| v.authorized)
            .unwrap_or(None);

        let filter = Filter::new()
            .select(0u64..)
            .event_signature(WhitelistUpdated::SIGNATURE_HASH)
            .topic1(U256::from(params.policy_id));

        let whitelist_addresses = filter_logs(self.eth_api.clone(), filter)
            .await?
            .into_iter()
            .map(|v| {
                v.log_decode::<WhitelistUpdated>().map(|v| PolicyAddress {
                    address: v.inner.data.account,
                    authorized: v.inner.data.allowed,
                })
            })
            .filter_ok(|v| match authorized {
                Some(authorized) => authorized == v.authorized,
                None => true,
            });

        let filter = Filter::new()
            .select(0u64..)
            .event_signature(BlacklistUpdated::SIGNATURE_HASH)
            .topic1(U256::from(params.policy_id));

        let blacklist_addresses = filter_logs(self.eth_api.clone(), filter)
            .await?
            .into_iter()
            .map(|v| {
                v.log_decode::<BlacklistUpdated>().map(|v| PolicyAddress {
                    address: v.inner.data.account,
                    authorized: !v.inner.data.restricted,
                })
            })
            .filter_ok(|v| match authorized {
                Some(authorized) => authorized == v.authorized,
                None => true,
            });

        let addresses = whitelist_addresses
            .chain(blacklist_addresses)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                debug!(
                    target: "rpc::policy::addresses",
                    ?err,
                    "decode logs"
                );

                EthApiError::Internal(RethError::Other(Box::new(err)))
            })?;

        Ok(AddressesResponse {
            next_cursor: None,
            addresses,
        })
    }
}
