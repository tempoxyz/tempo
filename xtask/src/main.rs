//! xtask is a Swiss army knife of tools that help with running and testing tempo.
use std::{net::SocketAddr, path::PathBuf};

use crate::{
    generate_devnet::GenerateDevnet, generate_genesis::GenerateGenesis,
    generate_localnet::GenerateLocalnet,
};

use alloy::signers::{local::MnemonicBuilder, utils::secret_key_to_address};
use clap::Parser as _;
use commonware_codec::DecodeExt;
use commonware_cryptography::{PrivateKeyExt as _, Signer, ed25519::PrivateKey};
use eyre::Context;
use rand::SeedableRng as _;
use tempo_commonware_node_config::SigningKey;

mod generate_devnet;
mod generate_genesis;
mod generate_localnet;
mod genesis_args;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();
    match args.action {
        Action::GenerateGenesis(args) => args.run().await.wrap_err("failed generating genesis"),
        Action::GenerateDevnet(args) => {
            args.run().await.wrap_err("failed to generate devnet configs")
        }
        Action::GenerateLocalnet(args) => {
            args.run().await.wrap_err("failed to generate localnet configs")
        }
        Action::GenerateAddPeer(cfg) => generate_config_to_add_peer(cfg),
        Action::GenerateSigningKey(args) => args.run(),
    }
}

#[derive(Debug, clap::Parser)]
#[command(author)]
#[command(version)]
#[command(about)]
#[command(long_about = None)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, clap::Subcommand)]
#[expect(
    clippy::enum_variant_names,
    reason = "the variant names map to actual cli inputs and are desired"
)]
enum Action {
    GenerateGenesis(GenerateGenesis),
    GenerateDevnet(GenerateDevnet),
    GenerateLocalnet(GenerateLocalnet),
    GenerateAddPeer(GenerateAddPeer),
    GenerateSigningKey(GenerateSigningKey),
}

/// Generates an ed25519 signing key pair to be used in consensus.
#[derive(Debug, clap::Args)]
struct GenerateSigningKey {
    /// Destination of the generated signing key.
    #[arg(long, short, value_name = "FILE")]
    output: PathBuf,
    /// AVOID IN PRODUCTION.
    /// Optional seed for the random generator used when generating the key.
    /// Use this only in environments that require reproducible keys.
    #[arg(long, value_name = "NUMBER")]
    seed: Option<u64>,
}

impl GenerateSigningKey {
    fn run(self) -> eyre::Result<()> {
        let Self { output, seed } = self;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed.unwrap_or_else(rand::random::<u64>));
        let signing_key = PrivateKey::from_rng(&mut rng);
        let validating_key = signing_key.public_key();
        let signing_key = SigningKey::from(signing_key);
        signing_key
            .write_to_file(&output)
            .wrap_err_with(|| format!("failed writing signing key to `{}`", output.display()))?;
        println!(
            "wrote signing key to: {}\nvalidating/public key: {validating_key}",
            output.display()
        );
        Ok(())
    }
}

#[derive(Debug, clap::Args)]
struct GenerateAddPeer {
    #[arg(long)]
    public_key: String,

    #[arg(long)]
    inbound_address: SocketAddr,

    #[arg(long)]
    rpc_endpoint: String,

    #[arg(long, default_value_t = 0)]
    admin_index: u32,

    #[arg(long, default_value_t = 20)]
    validator_index: u32,

    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    pub mnemonic: String,
}

fn generate_config_to_add_peer(
    GenerateAddPeer {
        public_key,
        inbound_address,
        admin_index,
        validator_index,
        rpc_endpoint,
        mnemonic,
    }: GenerateAddPeer,
) -> eyre::Result<()> {
    use tempo_precompiles::VALIDATOR_CONFIG_ADDRESS;
    let public_key_bytes = const_hex::decode(&public_key)?;
    let public_key = commonware_cryptography::ed25519::PublicKey::decode(&public_key_bytes[..])?;

    let admin_key = const_hex::encode(
        MnemonicBuilder::from_phrase_nth(&mnemonic, admin_index).credential().to_bytes(),
    );

    let validator_address = {
        secret_key_to_address(
            MnemonicBuilder::from_phrase_nth(mnemonic, validator_index).credential(),
        )
    };
    let inbound = inbound_address.to_string();
    let outbound = inbound_address.to_string();
    println!(
        "\
        cast send {VALIDATOR_CONFIG_ADDRESS} \
        \\\n\"addValidator(address newValidatorAddress, bytes32 publicKey, bool active, string calldata inboundAddress, string calldata outboundAddress)\" \
        \\\n\"{validator_address}\" \
        \\\n\"{public_key}\" \
        \\\n\"true\" \
        \\\n\"{inbound}\" \
        \\\n\"{outbound}\" \
        \\\n--private-key {admin_key} \
        \\\n-r {rpc_endpoint}"
    );
    Ok(())
}
