use reth_malachite::cli::MalachiteArgs;

#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct TempoArgs {
    #[command(flatten)]
    pub malachite_args: MalachiteArgs,
}
