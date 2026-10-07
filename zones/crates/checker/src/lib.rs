//! Durable observe-only solvency checker for one Tempo Zone.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod accounting;
mod bootstrap;
mod l1;
mod l2;
mod persistence;
mod runtime;
mod telemetry;

use std::{fmt, path::PathBuf, str::FromStr};

use alloy_primitives::Address;
use eyre::WrapErr as _;
use reth_chainspec::ChainSpecProvider;
use reth_exex::ExExContext;
use reth_node_api::FullNodeComponents;
use reth_storage_api::{BlockNumReader, StateProviderFactory};
use tempo_chainspec::spec::TempoHardforks;

/// Whether an operation should be retried or disable the checker.
#[derive(Debug)]
pub(crate) enum AttemptError {
    /// Retry after the configured delay.
    Retry(eyre::Report),
    /// Stop verification while leaving Zone execution running.
    Disable(eyre::Report),
}

impl AttemptError {
    /// Retry the operation after the configured delay.
    pub(crate) fn retry(error: impl Into<eyre::Report>) -> Self {
        Self::Retry(error.into())
    }

    /// Disable verification without stopping Zone execution.
    pub(crate) fn disable(error: impl Into<eyre::Report>) -> Self {
        Self::Disable(error.into())
    }
}

/// Decode a known event and reject a non-canonical ABI representation.
pub(crate) fn decode_event<E: alloy_sol_types::SolEvent>(
    log: &alloy_primitives::Log,
    name: &str,
    block: u64,
) -> eyre::Result<E> {
    let event = E::decode_log_validate(log)
        .wrap_err_with(|| format!("malformed {name} in block {block}"))?;
    eyre::ensure!(
        event.data.encode_log_data() == log.data,
        "non-canonical {name} encoding in block {block}"
    );
    Ok(event.data)
}

/// Whether the checker ExEx is installed in the Zone node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CheckerMode {
    #[default]
    Off,
    /// Verify and report without affecting Zone execution.
    Observe,
}

impl fmt::Display for CheckerMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Observe => "observe",
        })
    }
}

impl FromStr for CheckerMode {
    type Err = eyre::Report;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "observe" => Ok(Self::Observe),
            other => Err(eyre::eyre!(
                "unsupported checker mode `{other}`, expected `off` or `observe`"
            )),
        }
    }
}

impl CheckerMode {
    /// Parse a value for the node CLI without depending on clap.
    pub fn parse(value: &str) -> Result<Self, eyre::Report> {
        value.parse()
    }
}

/// Node-owned identity and storage configuration.
#[derive(Debug, Clone)]
pub struct CheckerConfig {
    /// Archive-capable Tempo endpoint used for authenticated history and custody reads.
    pub l1_rpc_url: String,
    /// Portal whose bridge liabilities are checked.
    pub portal_address: Address,
    /// ZoneFactory identifier bound to the local chain.
    pub zone_id: u32,
    /// Local Zone chain ID used to reject cross-chain databases.
    pub zone_chain_id: u64,
    /// Dedicated MDBX directory below the node data directory.
    pub database_path: PathBuf,
    /// Receipt-authenticated Tempo observations shared with the Zone node.
    pub l1_block_tracker: zone_l1::L1BlockTracker,
}

/// Observe-only checker execution extension.
pub struct CheckerExEx {
    config: CheckerConfig,
}

impl CheckerExEx {
    /// Create a checker from node-owned configuration.
    pub const fn new(config: CheckerConfig) -> Self {
        Self { config }
    }

    /// Run until the ExEx notification stream closes.
    pub async fn run<Node>(self, mut ctx: ExExContext<Node>) -> eyre::Result<()>
    where
        Node: FullNodeComponents,
        Node::Provider: BlockNumReader + ChainSpecProvider + StateProviderFactory,
        <Node::Provider as ChainSpecProvider>::ChainSpec: TempoHardforks,
    {
        runtime::run(self.config, &mut ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::CheckerMode;

    #[test]
    fn checker_mode_round_trip() {
        assert_eq!(CheckerMode::default(), CheckerMode::Off);
        assert_eq!(
            "OBSERVE".parse::<CheckerMode>().unwrap(),
            CheckerMode::Observe
        );
        assert_eq!(CheckerMode::Observe.to_string(), "observe");
        assert!("enforce".parse::<CheckerMode>().is_err());
    }
}
