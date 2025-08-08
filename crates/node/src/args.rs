use reth_malachite::cli::MalachiteArgs;
use reth_node_core::args::RessArgs;

#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct TempoArgs {
    #[command(flatten)]
    pub ress_args: RessArgs,

    #[command(flatten)]
    pub malachite_args: MalachiteArgs,
}
