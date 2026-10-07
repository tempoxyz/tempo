//! xtask is a Swiss army knife of tools that help with running and testing tempo.
use std::net::SocketAddr;

use crate::{
    bootstrap_shadowfork::BootstrapShadowfork, check_abi::CheckAbi,
    generate_devnet::GenerateDevnet, generate_genesis::GenerateGenesis,
    generate_hardfork::AddHardfork, generate_localnet::GenerateLocalnet,
    generate_shadowfork::GenerateShadowfork, get_dkg_outcome::GetDkgOutcome,
    identity_transitions::GetIdentityTransitions,
};

use alloy::signers::{local::MnemonicBuilder, utils::secret_key_to_address};
use clap::Parser as _;
use commonware_codec::DecodeExt;
use eyre::Context;
use tempo_state_bloat::GenerateStateBloat;

mod bootstrap_shadowfork;
mod check_abi;
mod generate_devnet;
mod generate_genesis;
mod generate_hardfork;
mod generate_localnet;
mod generate_shadowfork;
mod genesis_args;
mod get_dkg_outcome;
mod identity_transitions;
mod shadowfork;
mod zones;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Zones enables a second rustls backend; select one for all xtask commands.
    // Respect a provider that has already been installed.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let args = Args::parse();
    match args.action {
        Action::Zones(args) => args.run().await,
        Action::CheckAbi(args) => args.run().wrap_err("failed ABI alignment check"),
        Action::GetDkgOutcome(args) => args.run().await.wrap_err("failed to get DKG outcome"),
        Action::GetIdentityTransitions(args) => args
            .run()
            .await
            .wrap_err("failed to get identity transitions"),
        Action::GenerateGenesis(args) => args.run().await.wrap_err("failed generating genesis"),
        Action::AddHardfork(args) => args.run().wrap_err("failed adding hardfork plumbing"),
        Action::GenerateDevnet(args) => args
            .run()
            .await
            .wrap_err("failed to generate devnet configs"),
        Action::GenerateLocalnet(args) => args
            .run()
            .await
            .wrap_err("failed to generate localnet configs"),
        Action::GenerateShadowfork(args) => args
            .run()
            .await
            .wrap_err("failed to generate shadow fork configs"),
        Action::BootstrapShadowfork(args) => args
            .run()
            .wrap_err("failed to bootstrap shadow fork configs"),
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
    /// Zones administration and development tools.
    Zones(zones::Zones),
    CheckAbi(CheckAbi),
    GetDkgOutcome(GetDkgOutcome),
    GetIdentityTransitions(GetIdentityTransitions),
    GenerateGenesis(GenerateGenesis),
    AddHardfork(AddHardfork),
    GenerateDevnet(GenerateDevnet),
    GenerateLocalnet(GenerateLocalnet),
    GenerateShadowfork(GenerateShadowfork),
    BootstrapShadowfork(BootstrapShadowfork),
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

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_tree_is_valid() {
        Args::command().debug_assert();
    }

    #[test]
    fn root_and_zones_abi_commands_remain_distinct() {
        assert!(matches!(
            Args::try_parse_from(["xtask", "check-abi"]).unwrap().action,
            Action::CheckAbi(_)
        ));
        assert!(matches!(
            Args::try_parse_from(["xtask", "zones", "check-abi"])
                .unwrap()
                .action,
            Action::Zones(_)
        ));
    }

    #[test]
    fn zones_contract_defaults_use_the_migrated_tree() {
        let root = Args::command();
        let zones = root.find_subcommand("zones").unwrap();
        for (command, argument, expected) in [
            ("check-abi", "artifacts", "crates/zones/contracts/out"),
            ("deploy-router", "specs_out", "crates/zones/contracts/out"),
            (
                "install-reference-zone-factory",
                "specs_out",
                "crates/zones/contracts/out",
            ),
            (
                "deploy-neobank-fixtures",
                "specs_out",
                "crates/zones/contracts/benchmark-out",
            ),
        ] {
            let arg = zones
                .find_subcommand(command)
                .unwrap()
                .get_arguments()
                .find(|arg| arg.get_id().as_str() == argument)
                .unwrap();
            assert_eq!(arg.get_default_values(), &[std::ffi::OsStr::new(expected)]);
        }
    }

    #[test]
    fn zones_artifact_path_can_be_overridden() {
        let matches = Args::command()
            .try_get_matches_from([
                "xtask",
                "zones",
                "check-abi",
                "--artifacts",
                "custom/artifacts",
            ])
            .unwrap();
        let abi = matches
            .subcommand_matches("zones")
            .unwrap()
            .subcommand_matches("check-abi")
            .unwrap();
        assert_eq!(
            abi.get_one::<std::path::PathBuf>("artifacts").unwrap(),
            &std::path::PathBuf::from("custom/artifacts")
        );
    }

    #[test]
    fn zones_commands_require_the_namespace() {
        assert!(Args::try_parse_from(["xtask", "generate-p2p-key"]).is_err());
        assert!(matches!(
            Args::try_parse_from(["xtask", "zones", "generate-p2p-key"])
                .unwrap()
                .action,
            Action::Zones(_)
        ));
    }
}
