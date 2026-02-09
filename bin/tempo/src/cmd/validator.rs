use std::time::Duration;

use alloy_network::EthereumWallet;
use alloy_primitives::{Address, B256};
use alloy_provider::{Provider, ProviderBuilder, network::TxSigner};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::SolCall;
use eyre::WrapErr as _;
use foundry_wallets::WalletOpts;
use tempo_alloy::{
    TempoNetwork, provider::ext::TempoProviderBuilderExt, rpc::TempoTransactionRequest,
};
use tempo_contracts::precompiles::{IValidatorConfig, VALIDATOR_CONFIG_ADDRESS};

#[derive(Debug, clap::Args)]
pub(crate) struct AddValidator {
    /// RPC URL to query. Defaults to <https://rpc.presto.tempo.xyz>
    #[arg(long, default_value = "https://rpc.presto.tempo.xyz")]
    rpc_url: String,

    /// The on-chain validator address to add.
    #[arg(long, value_name = "ADDRESS")]
    new_validator_address: Address,

    /// The validator's ed25519 public key (32-byte hex).
    #[arg(long, value_name = "HEX")]
    public_key: B256,

    /// Whether the validator should be active.
    #[arg(long, default_value_t = true)]
    active: bool,

    /// The validator's inbound address, formatted as <hostname|ip>:<port>.
    #[arg(long)]
    inbound_address: String,

    /// The validator's outbound address, formatted as <ip>:<port>.
    #[arg(long)]
    outbound_address: String,

    #[command(flatten)]
    wallet: WalletOpts,
}

impl AddValidator {
    pub(crate) fn run(self) -> eyre::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .wrap_err("failed constructing async runtime")?
            .block_on(self.run_async())
    }

    async fn run_async(self) -> eyre::Result<()> {
        let signer = self
            .wallet
            .signer()
            .await
            .wrap_err("failed to load signer")?;
        let from = TxSigner::address(&signer);

        let mut wallet = EthereumWallet::new(signer);
        if let Some(from_override) = self.wallet.from {
            wallet
                .set_default_signer(from_override)
                .wrap_err("wallet does not contain the requested sender")?;
        }

        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .with_random_2d_nonces()
            .wallet(wallet)
            .connect(&self.rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let request = TempoTransactionRequest::from(
            TransactionRequest::default()
                .from(from)
                .to(VALIDATOR_CONFIG_ADDRESS)
                .input(
                    IValidatorConfig::addValidatorCall {
                        newValidatorAddress: self.new_validator_address,
                        publicKey: self.public_key,
                        active: self.active,
                        inboundAddress: self.inbound_address,
                        outboundAddress: self.outbound_address,
                    }
                    .abi_encode()
                    .into(),
                ),
        );

        let receipt = provider
            .send_transaction(request)
            .await
            .wrap_err("failed to send addValidator transaction")?
            .with_timeout(Some(Duration::from_secs(120)))
            .get_receipt()
            .await
            .wrap_err("failed waiting for addValidator transaction receipt")?;

        println!("{}", serde_json::to_string_pretty(&receipt)?);
        Ok(())
    }
}
