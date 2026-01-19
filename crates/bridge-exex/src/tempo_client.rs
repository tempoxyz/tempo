//! Tempo RPC client for submitting bridge transactions.

use alloy::{
    eips::BlockNumberOrTag,
    network::EthereumWallet,
    primitives::{keccak256, Address, B256},
    providers::{Provider, ProviderBuilder, RootProvider},
    signers::local::PrivateKeySigner,
    sol_types::{SolCall, SolEvent, SolType},
};
use eyre::Result;
use tempo_contracts::precompiles::{
    IBridge, IValidatorConfig, BRIDGE_ADDRESS, VALIDATOR_CONFIG_ADDRESS,
};
use tracing::{debug, info, warn};

use crate::retry::with_retry;

/// Type alias for the complex provider type with wallet filler
type WalletProvider = alloy::providers::fillers::FillProvider<
    alloy::providers::fillers::JoinFill<
        alloy::providers::fillers::JoinFill<
            alloy::providers::Identity,
            alloy::providers::fillers::JoinFill<
                alloy::providers::fillers::GasFiller,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        alloy::providers::fillers::WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

/// Type alias for a provider without wallet filler (read-only operations)
type ReadOnlyProvider = alloy::providers::fillers::FillProvider<
    alloy::providers::fillers::JoinFill<
        alloy::providers::Identity,
        alloy::providers::fillers::JoinFill<
            alloy::providers::fillers::GasFiller,
            alloy::providers::fillers::JoinFill<
                alloy::providers::fillers::BlobGasFiller,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::NonceFiller,
                    alloy::providers::fillers::ChainIdFiller,
                >,
            >,
        >,
    >,
    RootProvider,
>;

/// Client for submitting transactions to Tempo chain
pub struct TempoClient {
    provider: WalletProvider,
    /// The validator address used for attestation (always the attestation signer's address)
    validator_address: Address,
    /// Optional secondary RPC provider for quorum verification
    secondary_provider: Option<ReadOnlyProvider>,
    /// Whether to require quorum (error on mismatch) or just warn
    require_quorum: bool,
}

impl TempoClient {
    /// Create a new Tempo client.
    ///
    /// The provided signer is used for both transaction signing (broadcasting) and attestation.
    /// Use [`Self::with_broadcaster_signer`] to set a separate signer for broadcasting transactions.
    pub async fn new(rpc_url: &str, signer: PrivateKeySigner) -> Result<Self> {
        let validator_address = signer.address();
        let wallet = EthereumWallet::from(signer);

        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(rpc_url)
            .await?;

        Ok(Self {
            provider,
            validator_address,
            secondary_provider: None,
            require_quorum: false,
        })
    }

    /// Set a separate signer for broadcasting transactions.
    ///
    /// When set, this signer will be used for signing transactions, while the original
    /// signer's address remains the validator address used for attestation.
    pub async fn with_broadcaster_signer(
        self,
        rpc_url: &str,
        broadcaster: PrivateKeySigner,
    ) -> Result<Self> {
        let wallet = EthereumWallet::from(broadcaster);

        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(rpc_url)
            .await?;

        Ok(Self {
            provider,
            validator_address: self.validator_address,
            secondary_provider: self.secondary_provider,
            require_quorum: self.require_quorum,
        })
    }

    /// Configure a secondary RPC for block hash quorum verification.
    ///
    /// When set, the client will verify that block hashes match between the primary
    /// and secondary RPC before submitting transactions.
    ///
    /// # Arguments
    /// * `secondary_url` - URL of the secondary RPC endpoint
    /// * `require_quorum` - If true, transaction submission fails on mismatch.
    ///                      If false, logs a warning but proceeds.
    pub async fn with_secondary_rpc(
        self,
        secondary_url: &str,
        require_quorum: bool,
    ) -> Result<Self> {
        let secondary_provider = ProviderBuilder::new().connect(secondary_url).await?;

        Ok(Self {
            provider: self.provider,
            validator_address: self.validator_address,
            secondary_provider: Some(secondary_provider),
            require_quorum,
        })
    }

    /// Get the validator address (attestation signer's address)
    pub fn validator_address(&self) -> Address {
        self.validator_address
    }

    /// Verify that the block hash at the given block number matches between primary and secondary RPC.
    ///
    /// Returns Ok if:
    /// - No secondary provider is configured
    /// - Block hashes match
    /// - Block hashes mismatch but require_quorum is false (logs warning)
    ///
    /// Returns Err if block hashes mismatch and require_quorum is true.
    async fn verify_block_hash(&self, block_number: u64, expected_hash: B256) -> Result<()> {
        let Some(ref secondary) = self.secondary_provider else {
            return Ok(());
        };

        let secondary_block = with_retry("get_block_by_number_secondary", || async {
            secondary
                .get_block_by_number(BlockNumberOrTag::Number(block_number))
                .await?
                .ok_or_else(|| {
                    eyre::eyre!(
                        "Secondary RPC returned no block for block number {}",
                        block_number
                    )
                })
        })
        .await?;

        let secondary_hash = secondary_block.header.hash;

        if secondary_hash != expected_hash {
            if self.require_quorum {
                return Err(eyre::eyre!(
                    "Block hash mismatch at block {}: primary={}, secondary={}",
                    block_number,
                    expected_hash,
                    secondary_hash
                ));
            } else {
                warn!(
                    block_number,
                    primary_hash = %expected_hash,
                    secondary_hash = %secondary_hash,
                    "Block hash mismatch between primary and secondary RPC, proceeding anyway"
                );
            }
        }

        Ok(())
    }

    /// Perform quorum verification before submitting a transaction.
    ///
    /// Gets the current block from primary RPC and verifies hash against secondary.
    async fn verify_quorum_before_submit(&self) -> Result<()> {
        if self.secondary_provider.is_none() {
            return Ok(());
        }

        let block = with_retry("get_block_by_number_latest", || async {
            self.provider
                .get_block_by_number(BlockNumberOrTag::Latest)
                .await?
                .ok_or_else(|| eyre::eyre!("Primary RPC returned no latest block"))
        })
        .await?;

        let block_number = block.header.number;
        let block_hash = block.header.hash;

        self.verify_block_hash(block_number, block_hash).await
    }

    /// Check if validator has already signed a deposit
    pub async fn has_signed_deposit(&self, request_id: B256) -> Result<bool> {
        let call = IBridge::hasValidatorSignedDepositCall {
            requestId: request_id,
            validator: self.validator_address,
        };

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(BRIDGE_ADDRESS)
            .input(call.abi_encode().into());

        let result = with_retry("has_signed_deposit", || async {
            Ok(self.provider.call(tx.clone()).await?)
        })
        .await?;
        let decoded = <alloy::sol_types::sol_data::Bool as SolType>::abi_decode(&result)?;
        Ok(decoded)
    }

    /// Get deposit status
    pub async fn get_deposit(&self, request_id: B256) -> Result<IBridge::DepositRequest> {
        let call = IBridge::getDepositCall {
            requestId: request_id,
        };

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(BRIDGE_ADDRESS)
            .input(call.abi_encode().into());

        let result = with_retry("get_deposit", || async {
            Ok(self.provider.call(tx.clone()).await?)
        })
        .await?;
        let decoded = IBridge::DepositRequest::abi_decode(&result)?;
        Ok(decoded)
    }

    /// Register a deposit on the bridge precompile
    pub async fn register_deposit(
        &self,
        origin_chain_id: u64,
        origin_escrow: Address,
        origin_token: Address,
        origin_tx_hash: B256,
        origin_log_index: u32,
        tempo_recipient: Address,
        amount: u64,
        origin_block_number: u64,
    ) -> Result<B256> {
        let call = IBridge::registerDepositCall {
            originChainId: origin_chain_id,
            originEscrow: origin_escrow,
            originToken: origin_token,
            originTxHash: origin_tx_hash,
            originLogIndex: origin_log_index,
            tempoRecipient: tempo_recipient,
            amount,
            originBlockNumber: origin_block_number,
        };

        debug!(
            origin_chain_id,
            %origin_token,
            %tempo_recipient,
            amount,
            "Registering deposit on bridge"
        );

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(BRIDGE_ADDRESS)
            .input(call.abi_encode().into());

        let pending = self.provider.send_transaction(tx).await?;
        let receipt = pending.get_receipt().await?;

        info!(
            tx_hash = %receipt.transaction_hash,
            "Deposit registered"
        );

        // Parse request ID from logs
        for log in receipt.inner.logs() {
            if let Ok(event) = IBridge::DepositRegistered::decode_log(&log.inner) {
                return Ok(event.requestId);
            }
        }

        eyre::bail!("DepositRegistered event not found in receipt")
    }

    /// Submit a validator vote for a deposit.
    ///
    /// Security model: The validator's vote is authenticated by the transaction sender address.
    /// No separate signature is required because submitting this transaction from a registered
    /// validator address already proves the validator's intent to vote for this deposit.
    pub async fn submit_deposit_vote(&self, request_id: B256) -> Result<B256> {
        // Check if already voted
        if self.has_signed_deposit(request_id).await? {
            warn!(
                %request_id,
                validator = %self.validator_address,
                "Already voted for this deposit, skipping"
            );
            return Ok(B256::ZERO);
        }

        // Verify quorum before submitting
        self.verify_quorum_before_submit().await?;

        let call = IBridge::submitDepositVoteCall {
            requestId: request_id,
        };

        debug!(
            %request_id,
            validator = %self.validator_address,
            "Submitting deposit vote"
        );

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(BRIDGE_ADDRESS)
            .input(call.abi_encode().into());

        let pending = self.provider.send_transaction(tx).await?;
        let receipt = pending.get_receipt().await?;

        info!(
            tx_hash = %receipt.transaction_hash,
            %request_id,
            "Deposit vote submitted"
        );

        Ok(receipt.transaction_hash)
    }

    /// Register and finalize a deposit with bundled validator signatures.
    ///
    /// This is the preferred method - it submits all signatures in one transaction,
    /// which can be called by any account (doesn't need to be a validator).
    #[allow(clippy::too_many_arguments)]
    pub async fn register_and_finalize_with_signatures(
        &self,
        origin_chain_id: u64,
        origin_escrow: Address,
        origin_token: Address,
        origin_tx_hash: B256,
        origin_log_index: u32,
        tempo_recipient: Address,
        amount: u64,
        origin_block_number: u64,
        signatures: Vec<alloy::primitives::Bytes>,
    ) -> Result<B256> {
        // Verify quorum before submitting
        self.verify_quorum_before_submit().await?;

        let call = IBridge::registerAndFinalizeWithSignaturesCall {
            originChainId: origin_chain_id,
            originEscrow: origin_escrow,
            originToken: origin_token,
            originTxHash: origin_tx_hash,
            originLogIndex: origin_log_index,
            tempoRecipient: tempo_recipient,
            amount,
            originBlockNumber: origin_block_number,
            signatures,
        };

        debug!(
            origin_chain_id,
            %origin_token,
            %tempo_recipient,
            amount,
            "Submitting registerAndFinalizeWithSignatures"
        );

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(BRIDGE_ADDRESS)
            .input(call.abi_encode().into());

        let pending = self.provider.send_transaction(tx).await?;
        let receipt = pending.get_receipt().await?;

        info!(
            tx_hash = %receipt.transaction_hash,
            "Deposit registered and finalized with signatures"
        );

        // Parse request ID from logs
        for log in receipt.inner.logs() {
            if let Ok(event) = IBridge::DepositFinalized::decode_log(&log.inner) {
                return Ok(event.requestId);
            }
        }

        eyre::bail!("DepositFinalized event not found in receipt")
    }

    /// Attempt to finalize a deposit if threshold is reached
    pub async fn try_finalize_deposit(&self, request_id: B256) -> Result<Option<B256>> {
        // Get deposit status first
        let deposit = self.get_deposit(request_id).await?;

        if deposit.status == IBridge::DepositStatus::Finalized {
            debug!(%request_id, "Deposit already finalized");
            return Ok(None);
        }

        // Verify quorum before submitting
        self.verify_quorum_before_submit().await?;

        let call = IBridge::finalizeDepositCall {
            requestId: request_id,
        };

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(BRIDGE_ADDRESS)
            .input(call.abi_encode().into());

        match self.provider.send_transaction(tx).await {
            Ok(pending) => {
                let receipt = pending.get_receipt().await?;
                info!(
                    tx_hash = %receipt.transaction_hash,
                    %request_id,
                    "Deposit finalized"
                );
                Ok(Some(receipt.transaction_hash))
            }
            Err(e) => {
                // Threshold not yet reached is expected
                debug!(%request_id, error = %e, "Could not finalize deposit yet");
                Ok(None)
            }
        }
    }

    /// Fetch a block header by block number.
    ///
    /// Returns the block header data needed for proof generation and header relay.
    pub async fn get_block_header(
        &self,
        block_number: u64,
    ) -> Result<crate::proof::TempoBlockHeader> {
        use alloy::network::BlockResponse;

        let block = with_retry("get_block_header", || async {
            self.provider
                .get_block_by_number(BlockNumberOrTag::Number(block_number))
                .await?
                .ok_or_else(|| eyre::eyre!("Block {} not found", block_number))
        })
        .await?;

        let header = block.header();
        Ok(crate::proof::TempoBlockHeader {
            block_number,
            block_hash: header.hash,
            state_root: header.state_root,
            receipts_root: header.receipts_root,
        })
    }

    /// Fetch all receipts for a block.
    ///
    /// Returns receipts needed for proof generation.
    pub async fn get_block_receipts(
        &self,
        block_number: u64,
    ) -> Result<Vec<alloy::rpc::types::TransactionReceipt>> {
        use alloy::eips::BlockId;

        let receipts = with_retry("get_block_receipts", || async {
            self.provider
                .get_block_receipts(BlockId::Number(BlockNumberOrTag::Number(block_number)))
                .await?
                .ok_or_else(|| eyre::eyre!("Receipts for block {} not found", block_number))
        })
        .await?;

        Ok(receipts)
    }

    /// Health check - verify RPC connectivity.
    pub async fn health_check(&self) -> Result<()> {
        let _ = self.provider.get_block_number().await?;
        Ok(())
    }

    /// Get all validators from the ValidatorConfig precompile.
    pub async fn get_validators(&self) -> Result<Vec<IValidatorConfig::Validator>> {
        let call = IValidatorConfig::getValidatorsCall {};

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(VALIDATOR_CONFIG_ADDRESS)
            .input(call.abi_encode().into());

        let result = with_retry("get_validators", || async {
            Ok(self.provider.call(tx.clone()).await?)
        })
        .await?;

        let decoded =
            <alloy::sol_types::sol_data::Array<IValidatorConfig::Validator> as SolType>::abi_decode(
                &result,
            )?;
        Ok(decoded)
    }

    /// Compute the validator set hash for the current active validator set.
    ///
    /// This must match the computation in the precompile (`ValidatorConfig::compute_validator_set_hash`).
    /// The hash is: `keccak256(sorted_active_validator_addresses)`
    pub async fn compute_validator_set_hash(&self) -> Result<B256> {
        let validators = self.get_validators().await?;

        let mut active_addresses: Vec<Address> = validators
            .iter()
            .filter(|v| v.active)
            .map(|v| v.validatorAddress)
            .collect();

        // Sort for deterministic ordering (must match precompile)
        active_addresses.sort();

        // Compute hash of concatenated addresses
        let mut buf = Vec::with_capacity(active_addresses.len() * 20);
        for addr in &active_addresses {
            buf.extend_from_slice(addr.as_slice());
        }

        Ok(keccak256(&buf))
    }

    /// Find the transaction index for a specific burn ID in a block's receipts.
    ///
    /// Returns (tx_index, log_index) if found.
    pub fn find_burn_in_receipts(
        receipts: &[alloy::rpc::types::TransactionReceipt],
        burn_id: B256,
    ) -> Option<(usize, u64)> {
        for (tx_index, receipt) in receipts.iter().enumerate() {
            for log in receipt.inner.logs() {
                // Check if this is a BurnInitiated event
                if log.topics().first() == Some(&IBridge::BurnInitiated::SIGNATURE_HASH) {
                    if let Ok(decoded) = IBridge::BurnInitiated::decode_log(&log.inner) {
                        if decoded.burnId == burn_id {
                            let log_index = log.log_index.unwrap_or(0);
                            return Some((tx_index, log_index));
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_address() {
        assert!(!BRIDGE_ADDRESS.is_zero());
    }
}
