//! Transaction submitter - calls write() on destination bridge.

use alloy::{
    primitives::{Address, Bytes},
    providers::{Provider, ProviderBuilder, WalletProvider},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall,
};

use crate::{
    attestation::AggregatedSignature,
    config::ChainConfig,
    eip2537::g1_to_eip2537,
    error::{BridgeError, Result},
    message::Message,
};

sol! {
    #[derive(Debug)]
    function write(
        address sender,
        bytes32 messageHash,
        uint64 originChainId,
        bytes signature
    );
}

/// Submits attestations to destination bridge contracts.
pub struct Submitter {
    chain_id: u64,
    rpc_url: String,
    bridge_address: Address,
    /// Optional private key for signing transactions.
    /// If None, transactions are only simulated.
    signer: Option<PrivateKeySigner>,
}

impl Submitter {
    /// Create a new submitter (simulation-only mode).
    pub async fn new(config: ChainConfig) -> Result<Self> {
        let bridge_address = config
            .bridge_address
            .parse::<Address>()
            .map_err(|e| BridgeError::Config(format!("invalid bridge address: {e}")))?;

        Ok(Self {
            chain_id: config.chain_id,
            rpc_url: config.rpc_url,
            bridge_address,
            signer: None,
        })
    }

    /// Create a new submitter with a private key for sending real transactions.
    pub async fn with_signer(config: ChainConfig, private_key: &str) -> Result<Self> {
        let bridge_address = config
            .bridge_address
            .parse::<Address>()
            .map_err(|e| BridgeError::Config(format!("invalid bridge address: {e}")))?;

        let signer: PrivateKeySigner = private_key
            .parse()
            .map_err(|e| BridgeError::Config(format!("invalid private key: {e}")))?;

        Ok(Self {
            chain_id: config.chain_id,
            rpc_url: config.rpc_url,
            bridge_address,
            signer: Some(signer),
        })
    }

    /// Submit an attestation to the bridge.
    ///
    /// Converts the aggregated signature from compressed G1 (48 bytes) to
    /// EIP-2537 uncompressed format (128 bytes) before submission.
    /// Uses MinSig variant: G1 signatures, G2 public keys.
    pub async fn submit(
        &self,
        message: &Message,
        signature: &AggregatedSignature,
    ) -> Result<alloy::primitives::B256> {
        // Convert G1 signature to EIP-2537 format (128 bytes uncompressed)
        let eip2537_signature = g1_to_eip2537(&signature.signature)?;

        let call = writeCall {
            sender: message.sender,
            messageHash: message.message_hash,
            originChainId: message.origin_chain_id,
            signature: Bytes::from(eip2537_signature.to_vec()),
        };

        let tx = TransactionRequest::default()
            .to(self.bridge_address)
            .input(call.abi_encode().into());

        let rpc_url = self
            .rpc_url
            .parse()
            .map_err(|e| BridgeError::Config(format!("invalid rpc url: {e}")))?;

        match &self.signer {
            Some(signer) => {
                // Send real transaction with signer
                let wallet = alloy::network::EthereumWallet::from(signer.clone());
                let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

                tracing::info!(
                    chain_id = self.chain_id,
                    bridge = %self.bridge_address,
                    message_hash = %message.message_hash,
                    from = %provider.default_signer_address(),
                    "submitting attestation transaction"
                );

                let pending = provider
                    .send_transaction(tx)
                    .await
                    .map_err(|e| BridgeError::Submission(e.to_string()))?;

                let tx_hash = *pending.tx_hash();

                tracing::info!(
                    chain_id = self.chain_id,
                    %tx_hash,
                    "transaction submitted, waiting for confirmation"
                );

                // Wait for the transaction to be included
                let receipt = pending
                    .get_receipt()
                    .await
                    .map_err(|e| BridgeError::Submission(e.to_string()))?;

                if !receipt.status() {
                    return Err(BridgeError::Submission(format!(
                        "transaction reverted: {tx_hash:?}"
                    )));
                }

                tracing::info!(
                    chain_id = self.chain_id,
                    %tx_hash,
                    block = ?receipt.block_number,
                    "attestation confirmed on-chain"
                );

                Ok(tx_hash)
            }
            None => {
                // Simulation-only mode
                let provider = ProviderBuilder::new().connect_http(rpc_url);

                tracing::debug!(
                    chain_id = self.chain_id,
                    bridge = %self.bridge_address,
                    message_hash = %message.message_hash,
                    "simulating attestation call (no signer configured)"
                );

                let result = provider
                    .call(tx.clone())
                    .await
                    .map_err(|e| BridgeError::Submission(e.to_string()))?;

                tracing::debug!(
                    chain_id = self.chain_id,
                    result_len = result.len(),
                    "simulation successful"
                );

                // Return zero hash to indicate simulation-only
                Ok(alloy::primitives::B256::ZERO)
            }
        }
    }

    /// Check if this submitter has a signer configured for real transactions.
    pub fn has_signer(&self) -> bool {
        self.signer.is_some()
    }
}
