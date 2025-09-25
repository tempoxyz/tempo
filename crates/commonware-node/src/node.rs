use crate::{consensus::engine::ConsensusEngineBuilder, network::CommonwareNetwork};
use commonware_runtime::Metrics as _;
use eyre::{WrapErr as _, eyre};
use tempo_node::TempoFullNode;

pub struct CommonwareNode;

impl CommonwareNode {
    pub async fn run(
        context: &commonware_runtime::tokio::Context,
        config: &tempo_commonware_node_config::Config,
        execution_node: TempoFullNode,
    ) -> eyre::Result<()> {
        let (commonware_network, oracle) = CommonwareNetwork::new(context, config).await?;
        let consensus_engine = ConsensusEngineBuilder::new(
            config,
            execution_node,
            oracle,
            context.with_label("engine"),
        )
        .build()
        .await
        .wrap_err("failed initializing consensus engine")?;

        let CommonwareNetwork {
            network,
            pending,
            recovered,
            resolver,
            broadcaster,
            backfill,
        } = commonware_network;

        let (network_task, consensus_task) = (
            network.start(),
            consensus_engine.start(pending, recovered, resolver, broadcaster, backfill),
        );

        tokio::select! {
            ret = network_task => {
                ret.map_err(eyre::Report::from)
                    .and_then(|()| Err(eyre!("exited unexpectedly")))
                    .wrap_err("network task failed")
            }

            ret = consensus_task => {
                ret.map_err(eyre::Report::from)
                    .and_then(|ret| ret.and_then(|()| Err(eyre!("exited unexpectedly"))))
                    .wrap_err("consensus engine task failed")
            }
        }
    }
}
