//! xtask is a Swiss army knife of tools that help with running and testing tempo.
use std::net::SocketAddr;

use crate::{
    generate_devnet::GenerateDevnet, generate_genesis::GenerateGenesis,
    generate_localnet::GenerateLocalnet, generate_state_bloat::GenerateStateBloat,
    get_dkg_outcome::GetDkgOutcome,
};

use alloy::signers::{local::MnemonicBuilder, utils::secret_key_to_address};
use clap::Parser as _;
use commonware_codec::DecodeExt;
use eyre::Context;

mod generate_devnet;
mod generate_genesis;
mod generate_localnet;
mod generate_state_bloat;
mod genesis_args;
mod get_dkg_outcome;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();
    match args.action {
        Action::GetDkgOutcome(args) => args.run().await.wrap_err("failed to get DKG outcome"),
        Action::GenerateGenesis(args) => args.run().await.wrap_err("failed generating genesis"),
        Action::GenerateDevnet(args) => args
            .run()
            .await
            .wrap_err("failed to generate devnet configs"),
        Action::GenerateLocalnet(args) => args
            .run()
            .await
            .wrap_err("failed to generate localnet configs"),
        Action::GenerateAddPeer(cfg) => generate_config_to_add_peer(cfg),
        Action::GenerateStateBloat(args) => args
            .run()
            .await
            .wrap_err("failed to generate state bloat file"),
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
enum Action {
    GetDkgOutcome(GetDkgOutcome),
    GenerateGenesis(GenerateGenesis),
    GenerateDevnet(GenerateDevnet),
    GenerateLocalnet(GenerateLocalnet),
    GenerateAddPeer(GenerateAddPeer),
    GenerateStateBloat(GenerateStateBloat),
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
        MnemonicBuilder::from_phrase_nth(&mnemonic, admin_index)
            .credential()
            .to_bytes(),
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
