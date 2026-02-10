use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use clap::Args;
use tempo_alloy::{TempoNetwork, provider::ext::TempoProviderBuilderExt};

/// Faucet-specific CLI arguments
#[derive(Debug, Clone, Default, Args, PartialEq, Eq)]
#[command(next_help_heading = "Faucet")]
pub struct FaucetArgs {
    /// Whether the faucet is enabled
    #[arg(long = "faucet.enabled", default_value_t = false)]
    pub enabled: bool,

    /// Faucet funding private key
    #[arg(
        long = "faucet.private-key",
        requires = "enabled",
        required_if_eq("enabled", "true")
    )]
    pub private_key: Option<B256>,

    /// Amount for each faucet funding transaction
    #[arg(
        long = "faucet.amount",
        requires = "enabled",
        required_if_eq("enabled", "true")
    )]
    pub amount: Option<U256>,

    /// Target token address for the faucet to be funding with
    #[arg(
        long = "faucet.address",
        requires = "enabled",
        required_if_eq("enabled", "true"),
        num_args(0..)
    )]
    pub token_addresses: Option<Vec<Address>>,

    #[arg(
        long = "faucet.node-address",
        default_value = "http://localhost:8545",
        requires = "enabled"
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
            .wallet(self.wallet())
            .connect_http(
                self.node_address
                    .parse()
                    .expect("Failed to parse node address"),
            )
            .erased()
    }
}
