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
        let genesis = self
            .genesis_args
            .generate_genesis()
            .await
            .wrap_err("failed generating genesis")?;

        let json =
            serde_json::to_string_pretty(&genesis).wrap_err("failed encoding genesis as JSON")?;
        std::fs::write(&self.output, json).wrap_err_with(|| {
            format!(
                "failed writing genesiss to file `{}`",
                self.output.display()
            )
        })?;
        Ok(())
    }
}
