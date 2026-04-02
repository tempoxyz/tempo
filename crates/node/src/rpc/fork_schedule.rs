use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_chainspec::{EthereumHardfork, ForkCondition, ForkId, Hardforks, Head};
use reth_primitives_traits::AlloyBlockHeader as _;
use reth_provider::{BlockNumReader, ChainSpecProvider, HeaderProvider};
use serde::{Deserialize, Serialize};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};

/// Response for `tempo_forkSchedule`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkSchedule {
    /// Ordered list of Tempo-specific forks (excludes Genesis and Ethereum forks).
    pub schedule: Vec<ForkInfo>,
    /// Name of the latest active Tempo fork at the chain head.
    pub active: String,
    /// EIP-2124 fork identifier at the chain head (comparable with `eth_config`).
    pub fork_id: ForkId,
}

/// Information about a single Tempo fork.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkInfo {
    /// Fork name (e.g. "T0", "T1", "T2").
    pub name: String,
    /// Activation timestamp.
    pub activation_time: u64,
    /// Whether this fork is active at the chain head.
    pub active: bool,
}

#[rpc(server, namespace = "tempo")]
pub trait TempoForkScheduleApi {
    /// Returns the Tempo fork schedule, the currently active fork, and the EIP-2124 fork ID.
    #[method(name = "forkSchedule")]
    async fn fork_schedule(&self) -> RpcResult<ForkSchedule>;
}

/// Implementation of `tempo_forkSchedule`.
#[derive(Debug, Clone)]
pub struct TempoForkScheduleRpc<P> {
    provider: P,
}

impl<P> TempoForkScheduleRpc<P> {
    /// Create a new fork schedule RPC handler.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

fn internal_err(msg: impl ToString) -> jsonrpsee::types::ErrorObject<'static> {
    jsonrpsee::types::ErrorObject::owned(-32000, msg.to_string(), None::<()>)
}

#[async_trait::async_trait]
impl<P> TempoForkScheduleApiServer for TempoForkScheduleRpc<P>
where
    P: ChainSpecProvider<ChainSpec = TempoChainSpec>
        + BlockNumReader
        + HeaderProvider
        + Send
        + Sync
        + 'static,
{
    async fn fork_schedule(&self) -> RpcResult<ForkSchedule> {
        let chain_spec = self.provider.chain_spec();

        let best_number = self.provider.best_block_number().map_err(internal_err)?;
        let header = self
            .provider
            .header_by_number(best_number)
            .map_err(internal_err)?
            .ok_or_else(|| internal_err("head header not found"))?;
        let head_timestamp = header.timestamp();

        // Only Tempo forks (exclude Ethereum hardforks and Genesis).
        let schedule = chain_spec
            .forks_iter()
            .filter(|(fork, _)| {
                let name = fork.name();
                name != "Genesis" && !EthereumHardfork::VARIANTS.iter().any(|h| h.name() == name)
            })
            .filter_map(|(fork, condition)| {
                let ForkCondition::Timestamp(ts) = condition else {
                    return None;
                };
                Some(ForkInfo {
                    name: fork.name().to_string(),
                    activation_time: ts,
                    active: ts <= head_timestamp,
                })
            })
            .collect();

        let active = chain_spec
            .tempo_hardfork_at(head_timestamp)
            .name()
            .to_string();

        let fork_id = chain_spec.fork_id(&Head {
            number: best_number,
            timestamp: head_timestamp,
            ..Default::default()
        });

        Ok(ForkSchedule {
            schedule,
            active,
            fork_id,
        })
    }
}
