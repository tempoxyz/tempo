//! `tempo corpus`: capture an archive range into an object-store corpus and replay it.

use reth_cli_commands::node::NoArgs;
use std::sync::Arc;
use tempo_chainspec::spec::{TempoChainSpec, TempoChainSpecParser};
use tempo_corpus::cli::CliChain;
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_node::node::TempoNode;

/// Historical execution corpus commands.
pub type CorpusCommand = tempo_corpus::cli::CorpusCommand<TempoL1>;

/// Tempo L1, whose blocks read no L1 state.
#[derive(Debug)]
pub struct TempoL1;

impl CliChain for TempoL1 {
    type ChainSpecParser = TempoChainSpecParser;
    type Node = TempoNode;
    type Chain = TempoEvmConfig;
    type Source = TempoEvmConfig;
    type Consensus = TempoConsensus;
    type FillArgs = NoArgs;

    fn chain(spec: Arc<TempoChainSpec>) -> TempoEvmConfig {
        TempoEvmConfig::new(spec)
    }

    fn source(spec: Arc<TempoChainSpec>, _: NoArgs) -> TempoEvmConfig {
        TempoEvmConfig::new(spec)
    }

    fn consensus(spec: Arc<TempoChainSpec>) -> TempoConsensus {
        TempoConsensus::new(spec)
    }
}
