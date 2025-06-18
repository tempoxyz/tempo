use clap::{Args, Parser};
use library::cli::{Cli, MalachiteChainSpecParser};
use library::context::MalachiteContext;
use library::node::MalachiteNode;
use reth::builder::NodeHandle;

use library::state::{Address, Config, Genesis, State};
use reth::payload::PayloadBuilderHandle;

/// No Additional arguments
#[derive(Debug, Clone, Copy, Default, Args)]
#[non_exhaustive]
struct NoArgs;

fn main() -> eyre::Result<()> {
    reth_cli_util::sigsegv_handler::install();

    let ctx = MalachiteContext::default();
    let config = Config::new();
    let genesis = Genesis::new("1".to_string());
    let address = Address::new([0; 20]);
    let store_path = Path::new("malachite.db");

    Cli::<MalachiteChainSpecParser, NoArgs>::parse().run(|builder, _: NoArgs| async move {
        let state = State::new(ctx, config, genesis, address, store_path);

        let malachite_node = MalachiteNode::new();
        let NodeHandle {
            node,
            node_exit_future,
        } = builder.node(malachite_node).launch().await?;

        let engine_handle = node.add_ons_handle.beacon_engine_handle;

        node_exit_future.await
    })?;

    Ok(())
}
