//! Anvil test harness for end-to-end bridge integration tests.
//!
//! This module provides a reusable test harness for spinning up Anvil,
//! deploying bridge contracts, and testing deposit/burn flows.

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, Bytes, B256, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, Log as RpcLog, TransactionReceipt},
    signers::{local::PrivateKeySigner, Signer},
    sol,
    sol_types::SolEvent,
};
use eyre::{eyre, Result};
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tracing::{debug, info};

use super::fixtures::{anvil_accounts, ANVIL_CHAIN_ID};
use crate::signer::BridgeSigner;

sol! {
    #[sol(rpc)]
    contract MockUSDC {
        function mint(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function decimals() external view returns (uint8);
    }

    #[sol(rpc)]
    contract TempoLightClient {
        constructor(uint64 tempoChainId, uint64 initialEpoch);
        function addValidator(address validator) external;
        function removeValidator(address validator) external;
        function isHeaderFinalized(uint64 height) external view returns (bool);
        function getReceiptsRoot(uint64 height) external view returns (bytes32);
        function latestFinalizedHeight() external view returns (uint64);
        function threshold() external view returns (uint256);
        function validatorCount() external view returns (uint256);

        function submitHeader(
            uint64 height,
            bytes32 parentHash,
            bytes32 stateRoot,
            bytes32 receiptsRoot,
            uint64 epoch,
            bytes[] calldata signatures
        ) external;

        bytes32 public constant HEADER_DOMAIN;
    }

    #[sol(rpc)]
    contract StablecoinEscrow {
        constructor(address lightClient, uint64 tempoChainId);
        function addToken(address token) external;
        function removeToken(address token) external;
        function deposit(address token, uint256 amount, address tempoRecipient) external returns (bytes32 depositId);
        function isUnlocked(bytes32 burnId) external view returns (bool);
        function isBurnSpent(bytes32 burnId) external view returns (bool);
        function depositNonces(address depositor) external view returns (uint64);

        event Deposited(
            bytes32 indexed depositId,
            address indexed token,
            address indexed depositor,
            uint64 amount,
            address tempoRecipient,
            uint64 nonce
        );
    }
}

pub(super) const TEMPO_CHAIN_ID: u64 = 62049;

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

/// Anvil process wrapper that kills the process on drop
struct AnvilProcess {
    child: Child,
    port: u16,
}

impl AnvilProcess {
    fn spawn() -> Result<Self> {
        // Find an available port
        let port = portpicker::pick_unused_port().ok_or_else(|| eyre!("No available port"))?;

        let child = Command::new("anvil")
            .args(["--port", &port.to_string()])
            .args(["--chain-id", &ANVIL_CHAIN_ID.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| eyre!("Failed to spawn anvil: {}. Is anvil installed?", e))?;

        // Wait for anvil to start
        std::thread::sleep(Duration::from_millis(500));

        Ok(Self { child, port })
    }

    fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for AnvilProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Anvil test harness for bridge integration tests
pub(super) struct AnvilHarness {
    #[allow(dead_code)]
    anvil: AnvilProcess,
    pub rpc_url: String,
    pub accounts: Vec<(Address, PrivateKeySigner)>,
    pub provider: WalletProvider,
    pub usdc: Address,
    pub light_client: Address,
    pub escrow: Address,
    pub validators: Vec<Address>,
}

/// Detected deposit event from escrow contract
#[derive(Debug, Clone)]
pub(super) struct DepositEvent {
    pub deposit_id: B256,
    pub token: Address,
    pub depositor: Address,
    pub amount: u64,
    pub tempo_recipient: Address,
    pub nonce: u64,
    pub tx_hash: B256,
    pub block_number: u64,
    pub log_index: u64,
}

impl AnvilHarness {
    /// Spawn a new Anvil instance and deploy all bridge contracts
    pub async fn spawn() -> Result<Self> {
        let anvil = AnvilProcess::spawn()?;
        let rpc_url = anvil.endpoint();
        let accounts = anvil_accounts();

        let (deployer_addr, deployer_signer) = accounts[0].clone();
        let wallet = EthereumWallet::from(deployer_signer);

        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(&rpc_url)
            .await?;

        info!(rpc_url = %rpc_url, deployer = %deployer_addr, "Anvil harness spawned");

        let mut harness = Self {
            anvil,
            rpc_url,
            accounts,
            provider,
            usdc: Address::ZERO,
            light_client: Address::ZERO,
            escrow: Address::ZERO,
            validators: Vec::new(),
        };

        harness.deploy_all().await?;

        Ok(harness)
    }

    /// Deploy all bridge contracts (MockUSDC, TempoLightClient, StablecoinEscrow)
    async fn deploy_all(&mut self) -> Result<()> {
        let artifacts_dir = Self::find_artifacts_dir()?;

        // Deploy MockUSDC
        let usdc_bytecode = Self::load_bytecode(&artifacts_dir, "Bridge.t.sol", "MockUSDC")?;
        self.usdc = self.deploy_contract(usdc_bytecode, Bytes::new()).await?;
        info!(usdc = %self.usdc, "MockUSDC deployed");

        // Deploy TempoLightClient
        // Constructor args: (uint64 tempoChainId, uint64 initialEpoch)
        let light_client_bytecode =
            Self::load_bytecode(&artifacts_dir, "TempoLightClient.sol", "TempoLightClient")?;
        let light_client_args = alloy::sol_types::SolValue::abi_encode(&(TEMPO_CHAIN_ID, 1u64));
        self.light_client = self
            .deploy_contract(light_client_bytecode, light_client_args.into())
            .await?;
        info!(light_client = %self.light_client, "TempoLightClient deployed");

        // Deploy StablecoinEscrow
        // Constructor args: (address lightClient, uint64 tempoChainId)
        let escrow_bytecode =
            Self::load_bytecode(&artifacts_dir, "StablecoinEscrow.sol", "StablecoinEscrow")?;
        let escrow_args =
            alloy::sol_types::SolValue::abi_encode(&(self.light_client, TEMPO_CHAIN_ID));
        self.escrow = self
            .deploy_contract(escrow_bytecode, escrow_args.into())
            .await?;
        info!(escrow = %self.escrow, "StablecoinEscrow deployed");

        // Add USDC as supported token
        let escrow = StablecoinEscrow::new(self.escrow, &self.provider);
        escrow
            .addToken(self.usdc)
            .send()
            .await?
            .get_receipt()
            .await?;
        info!("USDC added as supported token");

        // Add default validators (first 3 accounts)
        let light_client = TempoLightClient::new(self.light_client, &self.provider);
        for i in 0..3 {
            let (validator_addr, _) = &self.accounts[i];
            light_client
                .addValidator(*validator_addr)
                .send()
                .await?
                .get_receipt()
                .await?;
            self.validators.push(*validator_addr);
        }
        info!(count = self.validators.len(), "Validators added");

        Ok(())
    }

    fn find_artifacts_dir() -> Result<PathBuf> {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));

        // Try relative to crate
        let crate_relative = manifest_dir.join("../../contracts/bridge/out");
        if crate_relative.exists() {
            return Ok(crate_relative.canonicalize()?);
        }

        // Try from workspace root
        let workspace_relative = PathBuf::from("contracts/bridge/out");
        if workspace_relative.exists() {
            return Ok(workspace_relative.canonicalize()?);
        }

        Err(eyre!(
            "Could not find contracts/bridge/out artifacts directory. Run `forge build` first."
        ))
    }

    fn load_bytecode(artifacts_dir: &PathBuf, source_file: &str, contract: &str) -> Result<Bytes> {
        let artifact_path = artifacts_dir
            .join(source_file)
            .join(format!("{contract}.json"));

        let content = std::fs::read_to_string(&artifact_path).map_err(|e| {
            eyre!(
                "Failed to read artifact {}: {}. Run `forge build` first.",
                artifact_path.display(),
                e
            )
        })?;

        let json: serde_json::Value = serde_json::from_str(&content)?;

        let bytecode_str = json["bytecode"]["object"]
            .as_str()
            .ok_or_else(|| eyre!("Missing bytecode.object in {}", artifact_path.display()))?;

        let bytecode_hex = bytecode_str.strip_prefix("0x").unwrap_or(bytecode_str);
        let bytecode = hex::decode(bytecode_hex)?;

        Ok(Bytes::from(bytecode))
    }

    async fn deploy_contract(&self, bytecode: Bytes, constructor_args: Bytes) -> Result<Address> {
        let mut deploy_data = bytecode.to_vec();
        deploy_data.extend_from_slice(&constructor_args);

        let tx = alloy::rpc::types::TransactionRequest::default()
            .with_deploy_code(deploy_data);

        let pending = self.provider.send_transaction(tx).await?;
        let receipt = pending.get_receipt().await?;

        receipt
            .contract_address
            .ok_or_else(|| eyre!("Contract deployment failed: no contract address in receipt"))
    }

    /// Mint USDC to an address
    pub async fn mint_usdc(&self, to: Address, amount: u64) -> Result<()> {
        let usdc = MockUSDC::new(self.usdc, &self.provider);
        usdc.mint(to, U256::from(amount))
            .send()
            .await?
            .get_receipt()
            .await?;
        debug!(to = %to, amount, "USDC minted");
        Ok(())
    }

    /// Approve USDC spending for escrow
    pub async fn approve_usdc(&self, owner: &PrivateKeySigner, amount: u64) -> Result<()> {
        let wallet = EthereumWallet::from(owner.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(&self.rpc_url)
            .await?;

        let usdc = MockUSDC::new(self.usdc, &provider);
        usdc.approve(self.escrow, U256::from(amount))
            .send()
            .await?
            .get_receipt()
            .await?;
        debug!(owner = %owner.address(), amount, "USDC approved");
        Ok(())
    }

    /// Get USDC balance
    pub async fn usdc_balance(&self, account: Address) -> Result<u64> {
        let usdc = MockUSDC::new(self.usdc, &self.provider);
        let balance: U256 = usdc.balanceOf(account).call().await?;
        Ok(balance.try_into().unwrap_or(u64::MAX))
    }

    /// Deposit USDC to the escrow and return the deposit event
    pub async fn deposit_usdc(
        &self,
        depositor: &PrivateKeySigner,
        amount: u64,
        tempo_recipient: Address,
    ) -> Result<(TransactionReceipt, DepositEvent)> {
        let wallet = EthereumWallet::from(depositor.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(&self.rpc_url)
            .await?;

        let escrow = StablecoinEscrow::new(self.escrow, &provider);
        let pending = escrow
            .deposit(self.usdc, U256::from(amount), tempo_recipient)
            .send()
            .await?;
        let receipt = pending.get_receipt().await?;

        // Parse Deposited event from logs
        let deposit_event = self.parse_deposit_event(&receipt)?;

        info!(
            deposit_id = %deposit_event.deposit_id,
            amount = deposit_event.amount,
            recipient = %deposit_event.tempo_recipient,
            "Deposit completed"
        );

        Ok((receipt, deposit_event))
    }

    fn parse_deposit_event(&self, receipt: &TransactionReceipt) -> Result<DepositEvent> {
        for (log_index, log) in receipt.inner.logs().iter().enumerate() {
            if log.address() == self.escrow {
                // Convert RPC log to primitive log for decoding
                let primitive_log = alloy::primitives::Log {
                    address: log.address(),
                    data: log.inner.data.clone(),
                };
                if let Ok(decoded) = StablecoinEscrow::Deposited::decode_log(&primitive_log) {
                    return Ok(DepositEvent {
                        deposit_id: decoded.data.depositId,
                        token: decoded.data.token,
                        depositor: decoded.data.depositor,
                        amount: decoded.data.amount,
                        tempo_recipient: decoded.data.tempoRecipient,
                        nonce: decoded.data.nonce,
                        tx_hash: receipt.transaction_hash,
                        block_number: receipt.block_number.unwrap_or(0),
                        log_index: log_index as u64,
                    });
                }
            }
        }
        Err(eyre!("Deposited event not found in receipt"))
    }

    /// Mine blocks on Anvil
    pub async fn mine_blocks(&self, count: u64) -> Result<()> {
        for _ in 0..count {
            self.provider
                .raw_request::<_, ()>("evm_mine".into(), ())
                .await?;
        }
        debug!(count, "Blocks mined");
        Ok(())
    }

    /// Get current block number
    pub async fn block_number(&self) -> Result<u64> {
        Ok(self.provider.get_block_number().await?)
    }

    /// Submit a header to the light client with validator signatures (ECDSA mode)
    pub async fn submit_header(
        &self,
        height: u64,
        parent_hash: B256,
        state_root: B256,
        receipts_root: B256,
        epoch: u64,
        validator_signers: &[&PrivateKeySigner],
    ) -> Result<B256> {
        let light_client = TempoLightClient::new(self.light_client, &self.provider);

        // Get the header domain from the contract
        let header_domain: B256 = light_client.HEADER_DOMAIN().call().await?;

        // Compute header digest
        let digest = alloy::primitives::keccak256(
            [
                header_domain.as_slice(),
                &TEMPO_CHAIN_ID.to_be_bytes(),
                &height.to_be_bytes(),
                parent_hash.as_slice(),
                state_root.as_slice(),
                receipts_root.as_slice(),
                &epoch.to_be_bytes(),
            ]
            .concat(),
        );

        // Create signatures sorted by validator address
        let mut signer_addr_pairs: Vec<_> = validator_signers
            .iter()
            .map(|s| (s.address(), *s))
            .collect();
        signer_addr_pairs.sort_by_key(|(addr, _)| *addr);

        let mut signatures: Vec<Bytes> = Vec::new();
        for (_, signer) in signer_addr_pairs {
            let sig = signer.sign_hash(&digest).await?;
            let sig_bytes: [u8; 65] = sig.into();
            signatures.push(Bytes::copy_from_slice(&sig_bytes));
        }

        let receipt = light_client
            .submitHeader(height, parent_hash, state_root, receipts_root, epoch, signatures)
            .send()
            .await?
            .get_receipt()
            .await?;

        info!(height, tx = %receipt.transaction_hash, "Header submitted");
        Ok(receipt.transaction_hash)
    }

    /// Check if a header is finalized
    pub async fn is_header_finalized(&self, height: u64) -> Result<bool> {
        let light_client = TempoLightClient::new(self.light_client, &self.provider);
        Ok(light_client.isHeaderFinalized(height).call().await?)
    }

    /// Get the receipts root for a height
    pub async fn get_receipts_root(&self, height: u64) -> Result<B256> {
        let light_client = TempoLightClient::new(self.light_client, &self.provider);
        Ok(light_client.getReceiptsRoot(height).call().await?)
    }

    /// Check if a burn is unlocked
    #[allow(dead_code)]
    pub async fn is_burn_unlocked(&self, burn_id: B256) -> Result<bool> {
        let escrow = StablecoinEscrow::new(self.escrow, &self.provider);
        Ok(escrow.isUnlocked(burn_id).call().await?)
    }

    /// Get the validator threshold
    pub async fn get_threshold(&self) -> Result<u64> {
        let light_client = TempoLightClient::new(self.light_client, &self.provider);
        let threshold: U256 = light_client.threshold().call().await?;
        Ok(threshold.try_into().unwrap_or(0))
    }

    /// Get the validator count
    pub async fn get_validator_count(&self) -> Result<u64> {
        let light_client = TempoLightClient::new(self.light_client, &self.provider);
        let count: U256 = light_client.validatorCount().call().await?;
        Ok(count.try_into().unwrap_or(0))
    }

    /// Add a validator to the light client
    #[allow(dead_code)]
    pub async fn add_validator(&mut self, validator: Address) -> Result<()> {
        let light_client = TempoLightClient::new(self.light_client, &self.provider);
        light_client
            .addValidator(validator)
            .send()
            .await?
            .get_receipt()
            .await?;
        self.validators.push(validator);
        Ok(())
    }

    /// Get logs for a filter
    #[allow(dead_code)]
    pub async fn get_logs(&self, filter: Filter) -> Result<Vec<RpcLog>> {
        Ok(self.provider.get_logs(&filter).await?)
    }

    /// Create bridge signers from validator accounts
    pub fn create_bridge_signers(&self, count: usize) -> Result<Vec<BridgeSigner>> {
        let mut signers = Vec::new();
        for i in 0..count.min(self.accounts.len()) {
            let (_, signer) = &self.accounts[i];
            signers.push(BridgeSigner::from_bytes(&signer.to_bytes())?);
        }
        Ok(signers)
    }

    /// Take a snapshot of the current chain state
    pub async fn snapshot(&self) -> Result<u64> {
        let snapshot_id: alloy::primitives::U256 = self
            .provider
            .raw_request("evm_snapshot".into(), ())
            .await?;
        let id: u64 = snapshot_id.try_into().unwrap_or(0);
        debug!(snapshot_id = id, "Chain snapshot taken");
        Ok(id)
    }

    /// Revert to a previous snapshot (simulates chain rollback)
    pub async fn revert_snapshot(&self, snapshot_id: u64) -> Result<bool> {
        let result: bool = self
            .provider
            .raw_request(
                "evm_revert".into(),
                (alloy::primitives::U256::from(snapshot_id),),
            )
            .await?;
        debug!(snapshot_id, reverted = result, "Chain snapshot reverted");
        Ok(result)
    }

    /// Simulate a reorg by reverting to a snapshot and mining new blocks.
    /// Returns the new block number after mining.
    pub async fn reorg_to_height(&self, snapshot_id: u64, new_blocks: u64) -> Result<u64> {
        self.revert_snapshot(snapshot_id).await?;

        if new_blocks > 0 {
            self.mine_blocks(new_blocks).await?;
        }

        let new_height = self.block_number().await?;
        info!(
            snapshot_id,
            new_blocks, new_height, "Chain reorg simulated"
        );
        Ok(new_height)
    }

    /// Get block hash at a specific block number
    pub async fn get_block_hash(&self, block_number: u64) -> Result<B256> {
        let block = self
            .provider
            .get_block_by_number(block_number.into())
            .await?
            .ok_or_else(|| eyre!("Block {} not found", block_number))?;
        Ok(block.header.hash)
    }

    /// Query Deposited events from escrow contract in a block range
    pub async fn query_deposits(&self, from_block: u64, to_block: u64) -> Result<Vec<DepositEvent>> {
        let filter = Filter::new()
            .address(self.escrow)
            .event_signature(StablecoinEscrow::Deposited::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block);

        let logs = self.provider.get_logs(&filter).await?;
        let mut events = Vec::new();

        for log in logs {
            let primitive_log = alloy::primitives::Log {
                address: log.address(),
                data: log.inner.data.clone(),
            };

            if let Ok(decoded) = StablecoinEscrow::Deposited::decode_log(&primitive_log) {
                events.push(DepositEvent {
                    deposit_id: decoded.data.depositId,
                    token: decoded.data.token,
                    depositor: decoded.data.depositor,
                    amount: decoded.data.amount,
                    tempo_recipient: decoded.data.tempoRecipient,
                    nonce: decoded.data.nonce,
                    tx_hash: log.transaction_hash.unwrap_or_default(),
                    block_number: log.block_number.unwrap_or(0),
                    log_index: log.log_index.unwrap_or(0),
                });
            }
        }

        Ok(events)
    }
}

/// Pick an unused port
mod portpicker {
    use std::net::TcpListener;

    pub fn pick_unused_port() -> Option<u16> {
        TcpListener::bind("127.0.0.1:0")
            .ok()
            .map(|l| l.local_addr().unwrap().port())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "Requires Anvil binary and forge build artifacts"]
    async fn test_harness_spawn() {
        let harness = AnvilHarness::spawn().await.expect("Failed to spawn harness");

        assert!(!harness.usdc.is_zero());
        assert!(!harness.light_client.is_zero());
        assert!(!harness.escrow.is_zero());
        assert_eq!(harness.validators.len(), 3);

        let threshold = harness.get_threshold().await.unwrap();
        assert_eq!(threshold, 2); // 2/3 of 3 validators
    }

    #[tokio::test]
    #[ignore = "Requires Anvil binary and forge build artifacts"]
    async fn test_deposit_flow() {
        let harness = AnvilHarness::spawn().await.expect("Failed to spawn harness");

        let (depositor_addr, depositor_signer) = harness.accounts[0].clone();
        let tempo_recipient = Address::repeat_byte(0x42);
        let amount = 1_000_000u64; // 1 USDC

        // Mint and approve
        harness.mint_usdc(depositor_addr, amount).await.unwrap();
        harness
            .approve_usdc(&depositor_signer, amount)
            .await
            .unwrap();

        // Check balance before
        let balance_before = harness.usdc_balance(harness.escrow).await.unwrap();
        assert_eq!(balance_before, 0);

        // Deposit
        let (_receipt, deposit_event) = harness
            .deposit_usdc(&depositor_signer, amount, tempo_recipient)
            .await
            .unwrap();

        assert!(!deposit_event.deposit_id.is_zero());
        assert_eq!(deposit_event.amount, amount);
        assert_eq!(deposit_event.tempo_recipient, tempo_recipient);

        // Check balance after
        let balance_after = harness.usdc_balance(harness.escrow).await.unwrap();
        assert_eq!(balance_after, amount);
    }

    #[tokio::test]
    #[ignore = "Requires Anvil binary and forge build artifacts"]
    async fn test_header_submission() {
        let harness = AnvilHarness::spawn().await.expect("Failed to spawn harness");

        let height = 1u64;
        let parent_hash = B256::ZERO;
        let state_root = B256::random();
        let receipts_root = B256::random();
        let epoch = 1u64;

        // Get 2 signers (threshold is 2 for 3 validators)
        let signers: Vec<_> = harness.accounts[..2].iter().map(|(_, s)| s).collect();

        harness
            .submit_header(
                height,
                parent_hash,
                state_root,
                receipts_root,
                epoch,
                &signers,
            )
            .await
            .unwrap();

        assert!(harness.is_header_finalized(height).await.unwrap());
        assert_eq!(
            harness.get_receipts_root(height).await.unwrap(),
            receipts_root
        );
    }
}
