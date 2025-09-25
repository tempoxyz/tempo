use crate::{consensus::engine::ConsensusEngineBuilder, network::CommonwareNetworkHandle};
use commonware_p2p::authenticated::discovery;
use commonware_runtime::Metrics as _;
use eyre::{WrapErr as _, eyre};
use tempo_node::TempoFullNode;

pub struct CommonwareNode {
    network_handle: CommonwareNetworkHandle,
    consensus_engine: crate::consensus::engine::Engine<
        discovery::Oracle<
            commonware_runtime::tokio::Context,
            tempo_commonware_node_cryptography::PublicKey,
        >,
        commonware_runtime::tokio::Context,
    >,
}

impl CommonwareNode {
    pub async fn new(
        context: &commonware_runtime::tokio::Context,
        config: &tempo_commonware_node_config::Config,
        execution_node: TempoFullNode,
    ) -> eyre::Result<Self> {
        let (network_handle, oracle) = CommonwareNetworkHandle::new(context, config).await?;
        let consensus_engine = ConsensusEngineBuilder::new(
            config,
            execution_node,
            oracle,
            context.with_label("engine"),
        )
        .build()
        .await
        .wrap_err("failed initializing consensus engine")?;

        Ok(Self {
            network_handle,
            consensus_engine,
        })
    }

    pub async fn run(self) -> eyre::Result<()> {
        let CommonwareNetworkHandle {
            network,
            pending,
            recovered,
            resolver,
            broadcaster,
            backfill,
        } = self.network_handle;

        let (network_task, consensus_task) = (
            network.start(),
            self.consensus_engine
                .start(pending, recovered, resolver, broadcaster, backfill),
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
