use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use clap::Args;
use tempo_alloy::{TempoNetwork, fillers::FeeTokenFiller, provider::ext::TempoProviderBuilderExt};
use tempo_precompiles::DEFAULT_FEE_TOKEN;

/// Faucet-specific CLI arguments
#[derive(Debug, Clone, Default, Args, PartialEq, Eq)]
#[command(next_help_heading = "Faucet")]
pub struct FaucetArgs {
    /// Whether the faucet is enabled
    #[arg(
        id = "faucet.enabled",
        long = "faucet.enabled",
        default_value_t = false
    )]
    pub enabled: bool,

    /// Faucet funding private key
    #[arg(
        long = "faucet.private-key",
        requires = "faucet.enabled",
        required_if_eq("faucet.enabled", "true")
    )]
    pub private_key: Option<B256>,

    /// Amount for each faucet funding transaction
    #[arg(
        long = "faucet.amount",
        requires = "faucet.enabled",
        required_if_eq("faucet.enabled", "true")
    )]
    pub amount: Option<U256>,

    /// Target token address for the faucet to be funding with
    #[arg(
        long = "faucet.address",
        requires = "faucet.enabled",
        required_if_eq("faucet.enabled", "true"),
        num_args(1..)
    )]
    pub token_addresses: Option<Vec<Address>>,

    #[arg(
        long = "faucet.node-address",
        default_value = "http://localhost:8545",
        requires = "faucet.enabled"
    )]
    pub node_address: String,
}

impl FaucetArgs {
    pub fn wallet(&self) -> EthereumWallet {
        let signer: PrivateKeySigner = PrivateKeySigner::from_bytes(
            &self.private_key.expect("No faucet private key provided"),
        )
        .expect("Failed to decode private key");
        EthereumWallet::new(signer)
    }

    pub fn addresses(&self) -> Vec<Address> {
        self.token_addresses
            .clone()
            .expect("No TIP20 token addresses provided")
    }

    pub fn amount(&self) -> U256 {
        self.amount.expect("No TIP20 token amount provided")
    }

    pub fn provider(&self) -> DynProvider<TempoNetwork> {
        ProviderBuilder::new_with_network::<TempoNetwork>()
            .with_expiring_nonces()
            .filler(FeeTokenFiller::new(DEFAULT_FEE_TOKEN))
            .wallet(self.wallet())
            .connect_http(
                self.node_address
                    .parse()
                    .expect("Failed to parse node address"),
            )
            .erased()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A helper type to parse Args more easily
    #[derive(Parser)]
    struct CommandParser {
        #[command(flatten)]
        args: FaucetArgs,
    }

    const TEST_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d4d2e724d419db3c1bc70c9296eb9c1d68f1c456";
    const TEST_TOKEN_A: &str = "0x20c0000000000000000000000000000000000000";
    const TEST_TOKEN_B: &str = "0x20c0000000000000000000000000000000000001";

    #[test]
    fn faucet_args_default_sanity_test() {
        assert!(CommandParser::try_parse_from(["tempo"]).is_ok());
    }

    #[test]
    fn faucet_enabled_without_address_values_is_rejected() {
        let result = CommandParser::try_parse_from([
            "tempo",
            "--faucet.enabled",
            "--faucet.private-key",
            TEST_PRIVATE_KEY,
            "--faucet.amount",
            "1",
            "--faucet.address",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn faucet_enabled_with_single_address_is_accepted() {
        let parser = CommandParser::try_parse_from([
            "tempo",
            "--faucet.enabled",
            "--faucet.private-key",
            TEST_PRIVATE_KEY,
            "--faucet.amount",
            "1",
            "--faucet.address",
            TEST_TOKEN_A,
        ])
        .expect("single-token faucet config should parse");

        let addresses = parser
            .args
            .token_addresses
            .expect("token addresses should be present");
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0], TEST_TOKEN_A.parse().unwrap());
    }

    #[test]
    fn faucet_enabled_with_multiple_addresses_is_accepted() {
        let parser = CommandParser::try_parse_from([
            "tempo",
            "--faucet.enabled",
            "--faucet.private-key",
            TEST_PRIVATE_KEY,
            "--faucet.amount",
            "1",
            "--faucet.address",
            TEST_TOKEN_A,
            TEST_TOKEN_B,
        ])
        .expect("multi-token faucet config should parse");

        let addresses = parser
            .args
            .token_addresses
            .expect("token addresses should be present");
        assert_eq!(addresses.len(), 2);
    }
}
