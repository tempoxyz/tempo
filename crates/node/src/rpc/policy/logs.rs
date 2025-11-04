use crate::rpc::{
    TempoPolicy,
    logs::filter_logs,
    paginate,
    pagination::SortOrder,
    policy::{
        PolicyAddress,
        addresses::{AddressesParams, AddressesResponse},
    },
};
use alloy::sol_types::SolEvent;
use alloy_primitives::U256;
use alloy_rpc_types_eth::Filter;
use jsonrpsee::core::RpcResult;
use reth_errors::RethError;
use reth_primitives_traits::NodePrimitives;
use reth_provider::BlockIdReader;
use reth_rpc_eth_api::{EthApiTypes, RpcNodeCore, RpcNodeCoreExt, helpers::SpawnBlocking};
use reth_rpc_eth_types::EthApiError;
use reth_tracing::tracing::debug;
use reth_transaction_pool::TransactionPool;
use std::collections::HashSet;
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
        let mut whitelist = HashSet::new();

        let filter = Filter::new()
            .select(0u64..)
            .event_signature(WhitelistUpdated::SIGNATURE_HASH)
            .topic1(U256::from(params.policy_id));

        let whitelist_events = filter_logs(self.eth_api.clone(), filter)
            .await?
            .into_iter()
            .map(|v| v.log_decode::<WhitelistUpdated>().map(|v| v.inner.data));

        for event in whitelist_events {
            let event = event.map_err(decode_err)?;

            if event.allowed {
                whitelist.insert(event.account);
            } else {
                whitelist.remove(&event.account);
            }
        }

        let mut blacklist = HashSet::new();

        if whitelist.is_empty() {
            let filter = Filter::new()
                .select(0u64..)
                .event_signature(BlacklistUpdated::SIGNATURE_HASH)
                .topic1(U256::from(params.policy_id));

            let blacklist_events = filter_logs(self.eth_api.clone(), filter)
                .await?
                .into_iter()
                .map(|v| v.log_decode::<BlacklistUpdated>().map(|v| v.inner.data));

            for event in blacklist_events {
                let event = event.map_err(decode_err)?;

                if event.restricted {
                    blacklist.insert(event.account);
                } else {
                    blacklist.remove(&event.account);
                }
            }
        }

        let authorized = params
            .params
            .filters
            .as_ref()
            .map(|v| v.authorized)
            .unwrap_or(None);

        // Collect deduplicated addresses with authorization filter applied
        let mut addresses = whitelist
            .into_iter()
            .map(PolicyAddress::allowed)
            .chain(blacklist.into_iter().map(PolicyAddress::blocked))
            .filter(|v| !matches!(authorized, Some(authorized) if v.authorized != authorized))
            .collect::<Vec<_>>();

        // Apply sorting
        if let Some(sort) = &params.params.sort {
            match sort.on.as_str() {
                "address" => match sort.order {
                    SortOrder::Asc => addresses.sort_by(|a, b| a.address.cmp(&b.address)),
                    SortOrder::Desc => addresses.sort_by(|a, b| b.address.cmp(&a.address)),
                },
                _ => {
                    return Err(EthApiError::InvalidParams(format!(
                        "Unsupported sort field: {}. Only 'address' is supported",
                        sort.on
                    ))
                    .into());
                }
            }
        } else {
            // Default sort: ascending by address for stable pagination
            addresses.sort_by(|a, b| a.address.cmp(&b.address));
        }

        // Apply pagination using generic helper
        let paginated = paginate(
            addresses,
            params.params.cursor.as_ref(),
            params.params.limit,
            |addr| addr.address,
        )
        .map_err(|e| {
            debug!(
                target: "rpc::policy::addresses",
                error = ?e,
                "pagination error"
            );
            EthApiError::InvalidParams(e)
        })?;

        Ok(AddressesResponse {
            next_cursor: paginated.next_cursor,
            addresses: paginated.items,
        })
    }
}

fn decode_err(err: alloy::sol_types::Error) -> EthApiError {
    debug!(
        target: "rpc::policy::addresses",
        ?err,
        "decode logs"
    );

    EthApiError::Internal(RethError::Other(Box::new(err)))
}
