//! Registers the sequencer's encryption key on the ZonePortal.
//!
//! Calls the shared sequencer registration helper, which derives the secp256k1
//! public key, constructs the proof-of-possession signature, and submits it to
//! the portal contract.

use alloy::{primitives::Address, providers::ProviderBuilder};
use eyre::WrapErr as _;
use tempo_alloy::TempoNetwork;
use zone_sequencer::register_encryption_key;

use crate::zone_utils::{L1_EXPLORER, parse_private_key};

#[derive(Debug, clap::Parser)]
pub(crate) struct SetEncryptionKey {
    /// Tempo L1 RPC URL.
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: String,

    /// ZonePortal contract address on Tempo L1.
    #[arg(long, env = "L1_PORTAL_ADDRESS")]
    portal: Address,

    /// Encryption private key (hex). Also signs the transaction unless
    /// `transaction_private_key` is provided.
    #[arg(long, env = "PRIVATE_KEY", hide_env_values = true)]
    private_key: String,

    /// Private key of the active sequencer that submits the L1 transaction.
    /// Defaults to `private_key` for single-sequencer zones.
    #[arg(long, env = "TRANSACTION_PRIVATE_KEY", hide_env_values = true)]
    transaction_private_key: Option<String>,
}

impl SetEncryptionKey {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let encryption_signer = parse_private_key(&self.private_key)?;
        let transaction_signer = parse_private_key(
            self.transaction_private_key
                .as_deref()
                .unwrap_or(&self.private_key),
        )?;

        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(transaction_signer)
            .connect(&self.l1_rpc_url)
            .await?;

        println!(
            "Sending setSequencerEncryptionKey to portal {}...",
            self.portal
        );
        let tx_hash = register_encryption_key(&provider, self.portal, &encryption_signer)
            .await
            .wrap_err("failed to send setSequencerEncryptionKey")?;

        println!("Encryption key registered!");
        println!("Explorer: {L1_EXPLORER}/{tx_hash}");

        Ok(())
    }
}
