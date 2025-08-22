use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    signers::local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English},
};
use clap::Args;
use std::str::FromStr;

/// Faucet-specific CLI arguments
#[derive(Debug, Clone, Default, Args, PartialEq, Eq)]
#[command(next_help_heading = "Faucet")]
pub struct FaucetArgs {
    /// Whether the faucet is enabled
    #[arg(long = "faucet.enabled")]
    pub enabled: bool,

    /// Faucet funding mnemonic
    #[arg(
        long = "faucet.mnemonic",
        default_value = "test test test test test test test test test test test junk"
    )]
    pub mnemonic: String,

    /// Faucet funding mnemonic's wallet index
    #[arg(long = "faucet.wallet-index", default_value_t = 10000)]
    pub wallet_index: u32,

    /// Amount for each faucet funding transaction
    #[arg(long = "faucet.amount", default_value_t = 100000000u64.try_into().expect(""))]
    pub amount: U256,

    /// Target token address for the faucet to be funding with
    #[arg(long = "faucet.address", default_value_t = Address::from_str("0x20c0000000000000000000000000000000000000").expect(""))]
    pub token_address: Address,
}

impl FaucetArgs {
    pub fn wallet(&self) -> EthereumWallet {
        let signer: PrivateKeySigner = MnemonicBuilder::<English>::default()
            .phrase(&self.mnemonic)
            .index(self.wallet_index)
            .unwrap()
            .build()
            .unwrap();
        EthereumWallet::new(signer)
    }
}
