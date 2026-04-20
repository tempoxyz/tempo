use std::path::PathBuf;

use eyre::WrapErr as _;

use crate::genesis_args::GenesisArgs;

#[derive(clap::Parser, Debug)]
pub(crate) struct GenerateGenesis {
    /// Output file path
    #[arg(short, long)]
    output: PathBuf,

    #[clap(flatten)]
    genesis_args: GenesisArgs,
}

impl GenerateGenesis {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            output,
            genesis_args,
        } = self;
        let (genesis, consensus_config) = genesis_args
            .generate_genesis()
            .await
            .wrap_err("failed generating genesis")?;

        tempo_genesis::write_genesis(&output, &genesis, consensus_config.as_ref())
    }
}
