use tempo_faucet::args::FaucetArgs;

#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct TempoArgs {
    /// Start the node without consensus
    #[arg(long)]
    pub follow: bool,

    /// URL to follow
    #[arg(long)]
    pub follow_url: String,

    #[command(flatten)]
    pub faucet_args: FaucetArgs,
}
