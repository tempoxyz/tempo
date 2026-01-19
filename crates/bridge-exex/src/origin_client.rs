//! Origin chain client for header relay and burn finalization.

use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall,
};
use eyre::Result;
use tracing::{debug, info, warn};

use crate::retry::with_retry;

sol! {
    /// Tempo Light Client contract on origin chains
    interface ITempoLightClient {
        /// Submit a Tempo block header with validator signatures (BLS mode)
        /// @param height Block height
        /// @param parentHash Parent block hash (used as block hash for header relay)
        /// @param stateRoot State root
        /// @param receiptsRoot Receipts root
        /// @param epoch Validator set epoch
        /// @param signature Aggregated BLS signature (G1 point, 128 bytes)
        function submitHeader(
            uint64 height,
            bytes32 parentHash,
            bytes32 stateRoot,
            bytes32 receiptsRoot,
            uint64 epoch,
            bytes calldata signature
        ) external;

        /// Check if a header is finalized
        function isHeaderFinalized(uint64 blockNumber) external view returns (bool);

        /// Get the latest finalized block number
        function latestFinalizedBlock() external view returns (uint64);
    }

    /// Stablecoin Escrow contract on origin chains
    interface IStablecoinEscrow {
        /// Unlock tokens after burn on Tempo is proven
        function unlockWithProof(
            bytes32 burnId,
            address recipient,
            uint256 amount,
            bytes calldata proof
        ) external;

        /// Check if a burn has been unlocked
        function isUnlocked(bytes32 burnId) external view returns (bool);
    }
}

/// Provider type with wallet filler
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
    alloy::providers::RootProvider,
>;

/// Provider type without wallet (for secondary/read-only)
type ReadProvider = alloy::providers::fillers::FillProvider<
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
    alloy::providers::RootProvider,
>;

/// Client for interacting with origin chain contracts
pub struct OriginClient {
    chain_name: String,
    chain_id: u64,
    rpc_url: String,
    provider: WalletProvider,
    broadcaster_wallet: Option<WalletProvider>,
    secondary_provider: Option<ReadProvider>,
    require_quorum: bool,
    light_client_address: Address,
    escrow_address: Address,
}

impl OriginClient {
    /// Create a new origin chain client
    pub async fn new(
        chain_name: String,
        chain_id: u64,
        rpc_url: &str,
        signer: PrivateKeySigner,
        light_client_address: Address,
        escrow_address: Address,
    ) -> Result<Self> {
        let wallet = EthereumWallet::from(signer);

        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(rpc_url)
            .await?;

        Ok(Self {
            chain_name,
            chain_id,
            rpc_url: rpc_url.to_string(),
            provider,
            broadcaster_wallet: None,
            secondary_provider: None,
            require_quorum: false,
            light_client_address,
            escrow_address,
        })
    }

    /// Set a separate broadcaster signer for sending transactions
    pub async fn with_broadcaster_signer(mut self, broadcaster: PrivateKeySigner) -> Result<Self> {
        let wallet = EthereumWallet::from(broadcaster);

        let broadcaster_provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(&self.rpc_url)
            .await?;

        self.broadcaster_wallet = Some(broadcaster_provider);
        Ok(self)
    }

    /// Add a secondary RPC for quorum verification
    pub async fn with_secondary_rpc(
        mut self,
        secondary_url: &str,
        require_quorum: bool,
    ) -> Result<Self> {
        let secondary = ProviderBuilder::new().connect(secondary_url).await?;

        self.secondary_provider = Some(secondary);
        self.require_quorum = require_quorum;
        Ok(self)
    }

    /// Verify block consistency between primary and secondary RPC
    async fn verify_block_consistency(&self, block_number: u64) -> Result<()> {
        let Some(secondary) = &self.secondary_provider else {
            return Ok(());
        };

        let primary_block = with_retry("get_block_by_number_primary", || async {
            self.provider
                .get_block_by_number(block_number.into())
                .await?
                .ok_or_else(|| eyre::eyre!("Block {} not found on primary RPC", block_number))
        })
        .await?;

        let secondary_block = with_retry("get_block_by_number_secondary", || async {
            secondary
                .get_block_by_number(block_number.into())
                .await?
                .ok_or_else(|| eyre::eyre!("Block {} not found on secondary RPC", block_number))
        })
        .await?;

        let primary_hash = primary_block.header.hash;
        let secondary_hash = secondary_block.header.hash;

        if primary_hash != secondary_hash {
            if self.require_quorum {
                return Err(eyre::eyre!(
                    "RPC quorum verification failed: block {} hash mismatch (primary: {}, secondary: {})",
                    block_number,
                    primary_hash,
                    secondary_hash
                ));
            } else {
                warn!(
                    chain = %self.chain_name,
                    block_number,
                    %primary_hash,
                    %secondary_hash,
                    "RPC block hash mismatch detected"
                );
            }
        }

        Ok(())
    }

    /// Get the provider to use for sending transactions
    fn tx_provider(&self) -> &WalletProvider {
        self.broadcaster_wallet.as_ref().unwrap_or(&self.provider)
    }

    /// Get the chain name
    pub fn chain_name(&self) -> &str {
        &self.chain_name
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Submit a Tempo header to the light client with validator signatures.
    ///
    /// # Arguments
    /// * `height` - Block height
    /// * `parent_hash` - Parent block hash (used as block identifier)
    /// * `state_root` - State root of the block
    /// * `receipts_root` - Receipts root of the block
    /// * `epoch` - Validator set epoch
    /// * `signature` - Aggregated BLS signature (G1 point, 128 bytes uncompressed)
    pub async fn submit_header(
        &self,
        height: u64,
        parent_hash: B256,
        state_root: B256,
        receipts_root: B256,
        epoch: u64,
        signature: Bytes,
    ) -> Result<B256> {
        // Check if already finalized
        if self.is_header_finalized(height).await? {
            debug!(
                chain = %self.chain_name,
                height,
                "Header already finalized"
            );
            return Ok(B256::ZERO);
        }

        // Verify RPC consistency before submitting
        self.verify_block_consistency(height).await?;

        let call = ITempoLightClient::submitHeaderCall {
            height,
            parentHash: parent_hash,
            stateRoot: state_root,
            receiptsRoot: receipts_root,
            epoch,
            signature,
        };

        info!(
            chain = %self.chain_name,
            height,
            %parent_hash,
            epoch,
            "Submitting Tempo header to light client"
        );

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(self.light_client_address)
            .input(call.abi_encode().into());

        let pending = self.tx_provider().send_transaction(tx).await?;
        let receipt = pending.get_receipt().await?;

        info!(
            chain = %self.chain_name,
            tx_hash = %receipt.transaction_hash,
            height,
            "Header submitted successfully"
        );

        Ok(receipt.transaction_hash)
    }

    /// Check if a header is finalized on the light client
    pub async fn is_header_finalized(&self, block_number: u64) -> Result<bool> {
        let call = ITempoLightClient::isHeaderFinalizedCall {
            blockNumber: block_number,
        };

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(self.light_client_address)
            .input(call.abi_encode().into());

        let result = with_retry("is_header_finalized", || async {
            Ok(self.provider.call(tx.clone()).await?)
        })
        .await?;

        use alloy::sol_types::SolType;
        let decoded = <alloy::sol_types::sol_data::Bool as SolType>::abi_decode(&result)?;
        Ok(decoded)
    }

    /// Get the latest finalized block number
    pub async fn latest_finalized_block(&self) -> Result<u64> {
        let call = ITempoLightClient::latestFinalizedBlockCall {};

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(self.light_client_address)
            .input(call.abi_encode().into());

        let result = with_retry("latest_finalized_block", || async {
            Ok(self.provider.call(tx.clone()).await?)
        })
        .await?;

        use alloy::sol_types::SolType;
        let decoded = <alloy::sol_types::sol_data::Uint<64> as SolType>::abi_decode(&result)?;
        Ok(decoded)
    }

    /// Unlock tokens on origin chain with burn proof
    pub async fn unlock_with_proof(
        &self,
        burn_id: B256,
        recipient: Address,
        amount: u64,
        proof: Bytes,
        origin_block_number: u64,
    ) -> Result<B256> {
        // Check if already unlocked
        if self.is_unlocked(burn_id).await? {
            debug!(
                chain = %self.chain_name,
                %burn_id,
                "Burn already unlocked"
            );
            return Ok(B256::ZERO);
        }

        // Verify RPC consistency before submitting
        self.verify_block_consistency(origin_block_number).await?;

        let call = IStablecoinEscrow::unlockWithProofCall {
            burnId: burn_id,
            recipient,
            amount: U256::from(amount),
            proof,
        };

        info!(
            chain = %self.chain_name,
            %burn_id,
            %recipient,
            amount,
            "Unlocking tokens on origin chain"
        );

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(self.escrow_address)
            .input(call.abi_encode().into());

        let pending = self.tx_provider().send_transaction(tx).await?;
        let receipt = pending.get_receipt().await?;

        info!(
            chain = %self.chain_name,
            tx_hash = %receipt.transaction_hash,
            %burn_id,
            "Tokens unlocked successfully"
        );

        Ok(receipt.transaction_hash)
    }

    /// Check if a burn has been unlocked
    pub async fn is_unlocked(&self, burn_id: B256) -> Result<bool> {
        let call = IStablecoinEscrow::isUnlockedCall { burnId: burn_id };

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(self.escrow_address)
            .input(call.abi_encode().into());

        let result = with_retry("is_unlocked", || async {
            Ok(self.provider.call(tx.clone()).await?)
        })
        .await?;

        use alloy::sol_types::SolType;
        let decoded = <alloy::sol_types::sol_data::Bool as SolType>::abi_decode(&result)?;
        Ok(decoded)
    }
}
