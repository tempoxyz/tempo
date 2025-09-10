use tempo_faucet::args::FaucetArgs;

#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct TempoArgs {
    /// Start the node without consensus
    #[arg(long)]
    pub no_consensus: bool,

    #[clap(long, value_name = "FILE")]
    pub consensus_config: camino::Utf8PathBuf,

    #[command(flatten)]
    pub faucet_args: FaucetArgs,
}
