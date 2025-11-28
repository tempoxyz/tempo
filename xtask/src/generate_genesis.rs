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

        let json =
            serde_json::to_string_pretty(&genesis).wrap_err("failed encoding genesis as JSON")?;
        std::fs::write(&output, json)
            .wrap_err_with(|| format!("failed writing genesis to file `{}`", output.display()))?;

        if let Some(consensus_config) = consensus_config {
            println!(
                "consensus config generated for `{}` validators; writing to disk...",
                consensus_config.validators.len()
            );
            for validator in consensus_config.validators {
                let parent = output.parent().expect("must not specify /");
                std::fs::create_dir_all(validator.dst_dir(parent)).wrap_err_with(|| {
                    format!(
                        "failed creating target directory to store validator specifici keys at `{}`",
                        validator.dst_dir(&output).display()
                    )
                })?;
                let signing_key_dst = validator.dst_signing_key(parent);
                validator
                    .signing_key
                    .write_to_file(&signing_key_dst)
                    .wrap_err_with(|| {
                        format!(
                            "failed writing ed25519 signing key to `{}`",
                            signing_key_dst.display()
                        )
                    })?;
                let signing_share_dst = validator.dst_signing_share(parent);
                validator
                    .signing_share
                    .write_to_file(&signing_share_dst)
                    .wrap_err_with(|| {
                        format!(
                            "failed writing bls12381 signing share to `{}`",
                            signing_share_dst.display()
                        )
                    })?;
                println!(
                    "validator keys written to `{}`, `{}`",
                    signing_key_dst.display(),
                    signing_share_dst.display()
                );
            }
        } else {
            println!("no consensus config generated; likely didn't provide --validators flag");
        }

        Ok(())
    }
}
