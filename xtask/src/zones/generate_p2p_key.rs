use crate::admin::secret_file::{WriteSecretOptions, write_secret_file};
use commonware_codec::Encode as _;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_math::algebra::Random as _;
use std::path::PathBuf;

/// Generate an Ed25519 identity for multi-sequencer P2P communication.
#[derive(Debug, clap::Parser)]
pub(crate) struct GenerateP2pKey {
    /// Destination for the unencrypted hex-encoded private key.
    #[arg(long = "out", short, default_value = "p2p.key", value_name = "PATH")]
    output: PathBuf,

    /// Replace the destination if it already exists.
    #[arg(long, short)]
    force: bool,
}

impl GenerateP2pKey {
    pub(crate) fn run(self) -> eyre::Result<()> {
        let key = PrivateKey::random(rand::rng());
        let encoded_key = format!("{}\n", const_hex::encode_prefixed(key.encode().as_ref()));
        write_secret_file(
            &self.output,
            encoded_key.as_bytes(),
            WriteSecretOptions {
                overwrite: self.force,
            },
        )?;

        println!("{}", const_hex::encode_prefixed(key.public_key().as_ref()));
        Ok(())
    }
}
