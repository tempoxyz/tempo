use tempo_faucet::args::FaucetArgs;

#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct TempoArgs {
    /// Start the node without consensus
    #[arg(long)]
    pub no_consensus: bool,

    #[command(flatten)]
    pub faucet_args: FaucetArgs,
}
