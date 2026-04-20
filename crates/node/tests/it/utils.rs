//! Test utility functions for integration tests.
//!
//! This module provides helper functions for setting up and managing test environments,
//! including test token creation and node setup for integration testing.

/// Chain profile for integration tests.
///
/// Each variant uses the test dev genesis allocations (funded accounts, precompile state) but
/// overlays hardfork timestamps from the corresponding network config.
/// Forks whose activation timestamp is in the future (relative to the current wall-clock time)
/// are deactivated (`u64::MAX`); forks already active are activated at t=0.
///
/// This lets the same test run against different fork schedules via `#[test_case]`:
///
/// ```ignore
/// #[test_case(ForkSchedule::Devnet ; "devnet")]
/// #[test_case(ForkSchedule::Testnet ; "testnet")]
/// #[test_case(ForkSchedule::Mainnet ; "mainnet")]
/// #[tokio::test(flavor = "multi_thread")]
/// async fn test_estimate_gas(schedule: ForkSchedule) -> eyre::Result<()> {
///     let setup = TestNodeBuilder::new()
///         .with_schedule(schedule)
///         .build_http_only()
///         .await?;
///     // ...
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub(crate) enum ForkSchedule {
    /// Preserves test dev genesis hardfork schedule: typically all active at t=0.
    Devnet,
    /// Fork schedule matching testnet (moderato): only forks active *now* are set to t=0.
    Testnet,
    /// Fork schedule matching mainnet (presto): only forks active *now* are set to t=0.
    Mainnet,
}

impl ForkSchedule {
    /// Returns the reference genesis JSON whose fork timestamps should be used.
    fn reference_genesis(&self) -> Option<&'static str> {
        match self {
            Self::Devnet => None,
            Self::Testnet => Some(include_str!("../../../chainspec/src/genesis/moderato.json")),
            Self::Mainnet => Some(include_str!("../../../chainspec/src/genesis/presto.json")),
        }
    }

    /// Returns whether the given Tempo hardfork is active for this schedule.
    ///
    /// For [`Devnet`](Self::Devnet) all forks from the dev genesis are active.
    /// For other schedules, a fork is active only if its timestamp in the
    /// reference genesis is in the past.
    pub(crate) fn is_active(&self, fork: TempoHardfork) -> bool {
        let Some(reference_json) = self.reference_genesis() else {
            return true; // devnet: all forks active
        };
        let reference: serde_json::Value =
            serde_json::from_str(reference_json).expect("reference genesis must parse");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let time_key = format!("{}Time", fork.to_string().to_lowercase());
        matches!(reference["config"][&time_key].as_u64(), Some(ts) if ts <= now)
    }

    /// Apply this profile's fork timestamps to a test genesis JSON value.
    ///
    /// Scans the test genesis config for all `*Time` keys and checks each
    /// against the reference network genesis. Forks active *now* on the
    /// reference network are set to `0`; forks that are still in the future
    /// or absent from the reference are set to `u64::MAX`.
    pub(crate) fn apply(&self, genesis: &mut serde_json::Value) {
        let Some(reference_json) = self.reference_genesis() else {
            return; // keep test genesis timestamps unchanged
        };

        let reference: serde_json::Value =
            serde_json::from_str(reference_json).expect("reference genesis must parse");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let config = genesis["config"]
            .as_object_mut()
            .expect("genesis must have config");

        for (key, value) in config.iter_mut().filter(|(k, _)| k.ends_with("Time")) {
            let ts = match reference["config"][key].as_u64() {
                Some(ts) if ts <= now => 0u64,
                _ => u64::MAX,
            };
            *value = serde_json::json!(ts);
        }
    }
}

/// Build a genesis JSON string from `test-genesis.json` with only forks up to
/// (and including) `last_active` enabled.  All subsequent forks are removed so
/// the node starts in a "pre-<next fork>" configuration.
///
/// This scales automatically when new hardforks are appended to
/// `TempoHardfork` — no manual maintenance required.
pub(crate) fn make_genesis_at(last_active: TempoHardfork) -> String {
    let mut genesis: serde_json::Value =
        serde_json::from_str(include_str!("../assets/test-genesis.json"))
            .expect("test-genesis.json must parse");
    let config = genesis["config"]
        .as_object_mut()
        .expect("genesis must have config");

    let mut past_cutoff = false;
    for &fork in TempoHardfork::VARIANTS {
        if fork == TempoHardfork::Genesis {
            continue;
        }
        if past_cutoff {
            let key = format!("{}Time", fork.name().to_lowercase());
            config.remove(&key);
        }
        if fork == last_active {
            past_cutoff = true;
        }
    }
    serde_json::to_string(&genesis).expect("genesis must serialize")
}

/// Standard test mnemonic phrase used across integration tests
pub(crate) const TEST_MNEMONIC: &str =
    "test test test test test test test test test test test junk";

use alloy::{
    network::Ethereum,
    primitives::Address,
    providers::{PendingTransactionBuilder, Provider},
    sol_types::SolEvent,
    transports::http::reqwest::Url,
};
use alloy_primitives::B256;
use alloy_rpc_types_engine::PayloadAttributes;
use reth_e2e_test_utils::setup;
use reth_ethereum::tasks::Runtime;
use reth_node_api::FullNodeComponents;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle, rpc::RethRpcAddOns};
use reth_node_core::args::RpcServerArgs;
use reth_rpc_builder::RpcModuleSelection;
use std::{sync::Arc, time::Duration};
use tempo_chainspec::{
    hardfork::{TempoHardfork, TempoHardforks},
    spec::TempoChainSpec,
};
use tempo_contracts::precompiles::{
    IRolesAuth,
    ITIP20::{self, ITIP20Instance},
    ITIP20Factory,
};
use tempo_node::node::TempoNode;
use tempo_payload_types::TempoPayloadAttributes;
use tempo_precompiles::{PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS, tip20::ISSUER_ROLE};

/// Creates a test TIP20 token with issuer role granted to the caller
pub(crate) async fn setup_test_token<P>(
    provider: P,
    caller: Address,
) -> eyre::Result<ITIP20Instance<impl Clone + Provider>>
where
    P: Provider + Clone,
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let salt = B256::random();
    let receipt = factory
        .createToken(
            "Test".to_string(),
            "TEST".to_string(),
            "USD".to_string(),
            PATH_USD_ADDRESS,
            caller,
            salt,
        )
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    let event = ITIP20Factory::TokenCreated::decode_log(&receipt.logs()[1].inner).unwrap();

    let token_addr = event.token;
    let token = ITIP20::new(token_addr, provider.clone());
    let roles = IRolesAuth::new(*token.address(), provider);

    roles
        .grantRole(*ISSUER_ROLE, caller)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    Ok(token)
}

/// Node source for integration testing
pub(crate) enum NodeSource {
    ExternalRpc(Url),
    LocalNode(String),
}

/// Type alias for a local test node and task manager
pub(crate) type LocalTestNode = (Box<dyn TestNodeHandle>, Runtime);

/// Trait wrapper around NodeHandle to simplify function return types
pub(crate) trait TestNodeHandle: Send {}

/// Generic [`TestNodeHandle`] implementation for NodeHandle
impl<Node, AddOns> TestNodeHandle for NodeHandle<Node, AddOns>
where
    Node: FullNodeComponents,
    AddOns: RethRpcAddOns<Node>,
{
}

/// Set up a test node from the provided source configuration
pub(crate) async fn setup_test_node(
    source: NodeSource,
) -> eyre::Result<(Url, Option<LocalTestNode>)> {
    let setup = match source {
        NodeSource::ExternalRpc(url) => {
            TestNodeBuilder::new()
                .with_external_rpc(url)
                .build_http_only()
                .await?
        }
        NodeSource::LocalNode(genesis_content) => {
            TestNodeBuilder::new()
                .with_genesis(genesis_content)
                .build_http_only()
                .await?
        }
    };

    Ok((setup.http_url, setup.local_node))
}

pub(crate) async fn await_receipts(
    pending_txs: &mut Vec<PendingTransactionBuilder<Ethereum>>,
) -> eyre::Result<()> {
    for (i, tx) in pending_txs.drain(..).enumerate() {
        let receipt = tx.get_receipt().await?;
        assert!(
            receipt.status(),
            "tx {} failed: hash={:?}, gas_used={}",
            i,
            receipt.transaction_hash,
            receipt.gas_used
        );
    }

    Ok(())
}

/// Result type for single node setup
pub(crate) struct SingleNodeSetup {
    /// The node handle for direct manipulation (inject_tx, advance_block, etc.)
    pub node: reth_e2e_test_utils::NodeHelperType<TempoNode>,
    /// Latest Tempo hardfork active at genesis (timestamp 0).
    pub hardfork: TempoHardfork,
}

/// Result type for multi-node setup
pub(crate) struct MultiNodeSetup {
    /// Node handles for direct manipulation
    pub nodes: Vec<reth_e2e_test_utils::NodeHelperType<TempoNode>>,
}

/// Result type for HTTP-only setup (no direct node access)
pub(crate) struct HttpOnlySetup {
    /// HTTP RPC URL for provider connections
    pub http_url: Url,
    /// Optional local node and task manager (None if using external RPC)
    pub local_node: Option<LocalTestNode>,
}

/// Builder for creating test nodes
pub(crate) struct TestNodeBuilder {
    genesis_content: String,
    custom_gas_limit: Option<String>,
    node_count: usize,
    is_dev: bool,
    external_rpc: Option<Url>,
    custom_validator: Option<Address>,
    dynamic_validator: Option<Arc<std::sync::Mutex<Address>>>,
    schedule: ForkSchedule,
}

impl TestNodeBuilder {
    /// Create a new builder with default test genesis
    pub(crate) fn new() -> Self {
        Self {
            genesis_content: include_str!("../assets/test-genesis.json").to_string(),
            custom_gas_limit: None,
            node_count: 1,
            is_dev: true,
            external_rpc: None,
            custom_validator: None,
            dynamic_validator: None,
            schedule: ForkSchedule::Devnet,
        }
    }

    /// Set the fork schedule (Devnet, Testnet, or Mainnet)
    pub(crate) fn with_schedule(mut self, schedule: ForkSchedule) -> Self {
        self.schedule = schedule;
        self
    }

    /// Use custom genesis JSON content
    pub(crate) fn with_genesis(mut self, genesis_content: String) -> Self {
        self.genesis_content = genesis_content;
        self
    }

    /// Set custom gas limit (overrides genesis value)
    pub(crate) fn with_gas_limit(mut self, gas_limit: &str) -> Self {
        self.custom_gas_limit = Some(gas_limit.to_string());
        self
    }

    /// Set number of nodes to create for multi-node scenarios
    pub(crate) fn with_node_count(mut self, count: usize) -> Self {
        self.node_count = count;
        self
    }

    /// Use external RPC instead of local node
    pub(crate) fn with_external_rpc(mut self, url: Url) -> Self {
        self.external_rpc = Some(url);
        self
    }

    /// Set a dynamic validator that can be changed at runtime
    pub(crate) fn with_dynamic_validator(
        mut self,
        validator: Arc<std::sync::Mutex<Address>>,
    ) -> Self {
        self.dynamic_validator = Some(validator);
        self
    }

    /// Build a single node with direct access (NodeHelperType)
    pub(crate) async fn build_with_node_access(self) -> eyre::Result<SingleNodeSetup> {
        if self.node_count != 1 {
            return Err(eyre::eyre!(
                "build_with_node_access requires node_count=1, use build_multi_node for multiple nodes"
            ));
        }

        if self.external_rpc.is_some() {
            return Err(eyre::eyre!(
                "build_with_node_access cannot be used with external RPC"
            ));
        }

        let chain_spec = self.build_chain_spec()?;
        let hardfork = chain_spec.tempo_hardfork_at(0);

        let (mut nodes, _wallet) = setup::<TempoNode>(
            1,
            Arc::new(chain_spec),
            self.is_dev,
            default_attributes_generator,
        )
        .await?;

        let node = nodes.remove(0);

        Ok(SingleNodeSetup { node, hardfork })
    }

    /// Build multiple nodes with direct access
    pub(crate) async fn build_multi_node(self) -> eyre::Result<MultiNodeSetup> {
        if self.node_count < 2 {
            return Err(eyre::eyre!(
                "build_multi_node requires node_count >= 2, use build_with_node_access for single node"
            ));
        }

        if self.external_rpc.is_some() {
            return Err(eyre::eyre!(
                "build_multi_node cannot be used with external RPC"
            ));
        }

        let chain_spec = self.build_chain_spec()?;

        let (nodes, _wallet) = setup::<TempoNode>(
            self.node_count,
            Arc::new(chain_spec),
            self.is_dev,
            default_attributes_generator,
        )
        .await?;

        Ok(MultiNodeSetup { nodes })
    }

    /// Build HTTP-only setup
    pub(crate) async fn build_http_only(self) -> eyre::Result<HttpOnlySetup> {
        self.build_http_only_with_api(RpcModuleSelection::All).await
    }

    /// Build HTTP-only setup with a custom RPC module selection.
    pub(crate) async fn build_http_only_with_api(
        self,
        http_api: RpcModuleSelection,
    ) -> eyre::Result<HttpOnlySetup> {
        if let Some(url) = self.external_rpc {
            return Ok(HttpOnlySetup {
                http_url: url,
                local_node: None,
            });
        }

        let runtime = Runtime::test();
        let chain_spec = self.build_chain_spec()?;
        let static_validator = self
            .custom_validator
            .unwrap_or(chain_spec.inner.genesis.coinbase);
        let dynamic_validator = self.dynamic_validator.clone();

        let mut node_config = NodeConfig::new(Arc::new(chain_spec))
            .with_unused_ports()
            .dev()
            .with_rpc(
                RpcServerArgs::default()
                    .with_unused_ports()
                    .with_http()
                    .with_http_api(http_api),
            );
        node_config.txpool.max_account_slots = usize::MAX;
        node_config.dev.block_time = Some(Duration::from_millis(100));

        let node_handle = NodeBuilder::new(node_config.clone())
            .testing_node(runtime.clone())
            .node(TempoNode::default())
            .launch_with_debug_capabilities()
            .map_debug_payload_attributes(move |mut attributes| {
                let validator = dynamic_validator
                    .as_ref()
                    .map(|v| *v.lock().unwrap())
                    .unwrap_or(static_validator);
                attributes.suggested_fee_recipient = validator;
                attributes
            })
            .await?;

        let http_url = node_handle
            .node
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();

        Ok(HttpOnlySetup {
            http_url,
            local_node: Some((Box::new(node_handle), runtime)),
        })
    }

    /// Helper to build chain spec from genesis
    fn build_chain_spec(&self) -> eyre::Result<TempoChainSpec> {
        let mut genesis: serde_json::Value = serde_json::from_str(&self.genesis_content)?;
        if let Some(gas_limit) = &self.custom_gas_limit {
            genesis["gasLimit"] = serde_json::json!(gas_limit);
        }

        self.schedule.apply(&mut genesis);

        Ok(TempoChainSpec::from_genesis(serde_json::from_value(
            genesis,
        )?))
    }
}

/// Default attributes generator for payload building
fn default_attributes_generator(timestamp: u64) -> TempoPayloadAttributes {
    PayloadAttributes {
        timestamp,
        prev_randao: alloy::primitives::B256::ZERO,
        suggested_fee_recipient: alloy::primitives::Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(alloy::primitives::B256::ZERO),
        slot_number: None,
    }
    .into()
}
