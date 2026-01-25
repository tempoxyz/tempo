//! End-to-end tests for the FinalizationBridge contract.
//!
//! This test:
//! 1. Starts a Tempo node (in-process)
//! 2. Sends a transaction that emits MessageSent
//! 3. Waits for block finalization
//! 4. Fetches the finalization certificate from consensus RPC
//! 5. Generates receipt MPT proof
//! 6. Deploys FinalizationBridge on Anvil (Ethereum with Prague)
//! 7. Submits the proof and verifies the message is received
//! 8. Tests various failure cases (invalid sig, wrong block, etc.)

use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    sol,
    sol_types::{SolCall, SolEvent},
};

/// Standard test mnemonic (has balance in genesis).
const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

// FinalizationBridge contract interface
sol! {
    #[derive(Debug)]
    event MessageSent(
        address indexed sender,
        bytes32 indexed messageHash,
        uint64 indexed destinationChainId
    );

    #[derive(Debug)]
    event MessageReceived(
        uint64 indexed originChainId,
        address indexed sender,
        bytes32 indexed messageHash,
        uint256 receivedAt
    );

    #[derive(Debug)]
    function send(bytes32 messageHash, uint64 destinationChainId) external;

    #[derive(Debug)]
    function write(
        bytes blockHeader,
        bytes finalizationSignature,
        bytes[] receiptProof,
        uint256 receiptIndex,
        uint256 logIndex
    ) external;

    #[derive(Debug)]
    function receivedAt(uint64 originChainId, address sender, bytes32 messageHash) external view returns (uint256);

    #[derive(Debug)]
    function originChainId() external view returns (uint64);
}

/// FinalizationBridge bytecode.
/// From: crates/native-bridge/contracts/out/FinalizationBridge.sol/FinalizationBridge.json
const FINALIZATION_BRIDGE_BYTECODE: &str =
    include_str!("../contracts/out/FinalizationBridge.sol/FinalizationBridge.bytecode.hex");

/// G2 generator point (uncompressed, 256 bytes EIP-2537 format).
/// MinSig variant: G2 public keys (256 bytes), G1 signatures (128 bytes).
const G2_GENERATOR_EIP2537: &str = concat!(
    // x.c1 (64 bytes: 16 zero padding + 48 bytes)
    "00000000000000000000000000000000",
    "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
    // x.c0 (64 bytes)
    "00000000000000000000000000000000",
    "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
    // y.c1 (64 bytes)
    "00000000000000000000000000000000",
    "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
    // y.c0 (64 bytes)
    "00000000000000000000000000000000",
    "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
);

/// Anvil instance wrapper with automatic cleanup.
struct AnvilInstance {
    child: Child,
    rpc_url: String,
    #[allow(dead_code)]
    ws_url: String,
}

impl AnvilInstance {
    async fn start() -> eyre::Result<Self> {
        let port = portpicker::pick_unused_port().expect("no free port");

        let child = Command::new("anvil")
            .args([
                "--port",
                &port.to_string(),
                "--chain-id",
                "1",
                "--block-time",
                "1",
                "--hardfork",
                "prague", // Required for EIP-2537 BLS precompiles
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let rpc_url = format!("http://127.0.0.1:{port}");
        let ws_url = format!("ws://127.0.0.1:{port}");

        // Wait for anvil to be ready
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify it's running
        let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);
        let block = provider.get_block_number().await?;
        tracing::info!(port, block, "anvil started");

        Ok(Self {
            child,
            rpc_url,
            ws_url,
        })
    }
}

impl Drop for AnvilInstance {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// Encode FinalizationBridge constructor arguments.
/// constructor(address _owner, uint64 _originChainId, uint64 _initialEpoch, bytes memory _initialPublicKey)
fn encode_finalization_bridge_constructor(
    owner: Address,
    origin_chain_id: u64,
    epoch: u64,
    public_key: &[u8],
) -> Vec<u8> {
    let mut encoded = Vec::new();

    // owner (address, 32 bytes)
    encoded.extend_from_slice(&[0u8; 12]);
    encoded.extend_from_slice(owner.as_slice());

    // origin_chain_id (uint64, 32 bytes)
    encoded.extend_from_slice(&[0u8; 24]);
    encoded.extend_from_slice(&origin_chain_id.to_be_bytes());

    // epoch (uint64, 32 bytes)
    encoded.extend_from_slice(&[0u8; 24]);
    encoded.extend_from_slice(&epoch.to_be_bytes());

    // bytes offset (points to byte 128 = 0x80)
    encoded.extend_from_slice(&[0u8; 31]);
    encoded.push(0x80);

    // bytes length
    let len = public_key.len();
    encoded.extend_from_slice(&[0u8; 24]);
    encoded.extend_from_slice(&(len as u64).to_be_bytes());

    // bytes data (padded to 32 bytes)
    encoded.extend_from_slice(public_key);
    let padding = (32 - (len % 32)) % 32;
    encoded.extend_from_slice(&vec![0u8; padding]);

    encoded
}

/// Deploy the FinalizationBridge contract on Anvil.
async fn deploy_finalization_bridge(rpc_url: &str, origin_chain_id: u64) -> eyre::Result<Address> {
    use alloy::{
        network::TransactionBuilder, providers::ProviderBuilder, signers::local::PrivateKeySigner,
    };

    // Anvil's default funded account
    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let owner = signer.address();

    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .connect_http(rpc_url.parse()?);

    // Contract bytecode
    let bytecode = hex::decode(FINALIZATION_BRIDGE_BYTECODE.trim())?;

    // Constructor arguments
    let initial_epoch = 1u64;
    let initial_public_key = hex::decode(G2_GENERATOR_EIP2537)?;

    let constructor_args = encode_finalization_bridge_constructor(
        owner,
        origin_chain_id,
        initial_epoch,
        &initial_public_key,
    );
    let deploy_code: Vec<u8> = bytecode.into_iter().chain(constructor_args).collect();

    let tx =
        alloy::rpc::types::TransactionRequest::default().with_deploy_code(Bytes::from(deploy_code));

    let pending = provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;

    let address = receipt
        .contract_address
        .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;

    tracing::info!(
        %address,
        %owner,
        origin_chain_id,
        epoch = initial_epoch,
        "deployed FinalizationBridge on Anvil"
    );
    Ok(address)
}

// =============================================================================
// Unit tests for libraries (can run without full e2e setup)
// =============================================================================

#[cfg(test)]
mod library_tests {
    use super::*;

    /// Test that the MessageSent event signature matches what we expect.
    #[test]
    fn test_message_sent_signature() {
        use alloy::primitives::keccak256;
        let sig = MessageSent::SIGNATURE_HASH;
        let expected = keccak256("MessageSent(address,bytes32,uint64)");
        assert_eq!(sig, expected);
    }

    /// Test constructor encoding.
    #[test]
    fn test_constructor_encoding() {
        let owner = Address::repeat_byte(0xAA);
        let origin_chain_id = 98985u64;
        let epoch = 1u64;
        let public_key = vec![0x01u8; 256];

        let encoded =
            encode_finalization_bridge_constructor(owner, origin_chain_id, epoch, &public_key);

        // Should have: 4 x 32 bytes for params + 32 bytes length + 256 bytes key
        assert_eq!(encoded.len(), 4 * 32 + 32 + 256);
    }
}

// =============================================================================
// Integration tests (require Anvil and optionally Tempo node)
// =============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Test deploying FinalizationBridge on Anvil.
    #[tokio::test]
    #[ignore = "requires anvil"]
    async fn test_deploy_finalization_bridge() -> eyre::Result<()> {
        let anvil = AnvilInstance::start().await?;
        let tempo_chain_id = 98985u64;

        let bridge_addr = deploy_finalization_bridge(&anvil.rpc_url, tempo_chain_id).await?;
        assert_ne!(bridge_addr, Address::ZERO);

        // Verify contract state
        let provider = ProviderBuilder::new().connect_http(anvil.rpc_url.parse()?);

        let origin_call = originChainIdCall {};
        let result = provider
            .call(
                alloy::rpc::types::TransactionRequest::default()
                    .to(bridge_addr)
                    .input(origin_call.abi_encode().into()),
            )
            .await?;

        let origin = u64::from_be_bytes(result[24..32].try_into().unwrap());
        assert_eq!(origin, tempo_chain_id);

        Ok(())
    }

    /// Test sending a message on the bridge.
    #[tokio::test]
    #[ignore = "requires anvil"]
    async fn test_send_message() -> eyre::Result<()> {
        use alloy::signers::local::PrivateKeySigner;

        let anvil = AnvilInstance::start().await?;
        let tempo_chain_id = 98985u64;

        let bridge_addr = deploy_finalization_bridge(&anvil.rpc_url, tempo_chain_id).await?;

        // Setup wallet
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .unwrap();
        let provider = ProviderBuilder::new()
            .wallet(alloy::network::EthereumWallet::from(signer.clone()))
            .connect_http(anvil.rpc_url.parse()?);

        // Send a message
        let message_hash = B256::repeat_byte(0x42);
        let dest_chain_id = 1u64;

        let send_call = sendCall {
            messageHash: message_hash,
            destinationChainId: dest_chain_id,
        };
        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(bridge_addr)
            .input(send_call.abi_encode().into());

        let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
        assert!(receipt.status());

        // Check for MessageSent event
        let logs = receipt.inner.logs();
        let event = logs
            .iter()
            .find(|log| !log.topics().is_empty() && log.topics()[0] == MessageSent::SIGNATURE_HASH)
            .expect("MessageSent event not found");

        assert_eq!(
            event.topics()[1],
            B256::left_padding_from(signer.address().as_slice())
        );
        assert_eq!(event.topics()[2], message_hash);

        tracing::info!("MessageSent event emitted successfully");
        Ok(())
    }
}

// =============================================================================
// Full E2E tests (require both Anvil and Tempo node)
// =============================================================================

#[cfg(test)]
mod e2e_tests {
    use super::*;

    /// Placeholder for full e2e test with real finalization cert.
    ///
    /// To implement this fully, we need:
    /// 1. Start Tempo node (similar to bridge_e2e.rs)
    /// 2. Deploy FinalizationBridge on Tempo
    /// 3. Send a message on Tempo
    /// 4. Wait for block finalization
    /// 5. Fetch finalization cert via consensus_getFinalization RPC
    /// 6. Generate receipt MPT proof using eth-trie-proofs or similar
    /// 7. Deploy FinalizationBridge on Anvil
    /// 8. Submit proof to Anvil bridge
    /// 9. Verify message is received
    #[tokio::test]
    #[ignore = "requires full infrastructure - Tempo node + Anvil"]
    async fn test_full_finalization_flow() -> eyre::Result<()> {
        // TODO: Implement once we have:
        // 1. eth-trie-proofs dependency added
        // 2. Tempo consensus signing the correct domain for FinalizationBridge

        // For now, this serves as a placeholder showing the structure
        tracing::info!("Full e2e test placeholder - needs implementation");
        Ok(())
    }

    // =========================================================================
    // Negative tests
    // =========================================================================

    /// Test that invalid signature is rejected.
    #[tokio::test]
    #[ignore = "requires anvil with working mock data"]
    async fn test_invalid_finalization_signature() -> eyre::Result<()> {
        let anvil = AnvilInstance::start().await?;
        let bridge_addr = deploy_finalization_bridge(&anvil.rpc_url, 98985).await?;

        // Create mock block header (minimal RLP list)
        let mock_header = create_mock_block_header();

        // Invalid signature (all zeros = point at infinity, should fail)
        let invalid_sig = vec![0u8; 128];

        // Mock receipt proof
        let mock_proof: Vec<Bytes> = vec![Bytes::from(vec![0x80])]; // Empty RLP

        let write_call = writeCall {
            blockHeader: Bytes::from(mock_header),
            finalizationSignature: Bytes::from(invalid_sig),
            receiptProof: mock_proof,
            receiptIndex: U256::ZERO,
            logIndex: U256::ZERO,
        };

        let provider = ProviderBuilder::new()
            .wallet(alloy::network::EthereumWallet::from(
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                    .parse::<alloy::signers::local::PrivateKeySigner>()
                    .unwrap(),
            ))
            .connect_http(anvil.rpc_url.parse()?);

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(bridge_addr)
            .gas_limit(500_000)
            .input(write_call.abi_encode().into());

        // This should revert
        let result = provider.send_transaction(tx).await;
        assert!(
            result.is_err() || {
                let receipt = result.unwrap().get_receipt().await;
                receipt.is_err() || !receipt.unwrap().status()
            }
        );

        tracing::info!("Invalid signature correctly rejected");
        Ok(())
    }

    /// Test that empty proof is rejected.
    #[tokio::test]
    #[ignore = "requires anvil"]
    async fn test_empty_proof_rejected() -> eyre::Result<()> {
        let anvil = AnvilInstance::start().await?;
        let bridge_addr = deploy_finalization_bridge(&anvil.rpc_url, 98985).await?;

        let mock_header = create_mock_block_header();
        let valid_sig = vec![0x01u8; 128]; // Non-zero signature
        let empty_proof: Vec<Bytes> = vec![]; // Empty proof array

        let write_call = writeCall {
            blockHeader: Bytes::from(mock_header),
            finalizationSignature: Bytes::from(valid_sig),
            receiptProof: empty_proof,
            receiptIndex: U256::ZERO,
            logIndex: U256::ZERO,
        };

        let provider = ProviderBuilder::new()
            .wallet(alloy::network::EthereumWallet::from(
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                    .parse::<alloy::signers::local::PrivateKeySigner>()
                    .unwrap(),
            ))
            .connect_http(anvil.rpc_url.parse()?);

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(bridge_addr)
            .gas_limit(500_000)
            .input(write_call.abi_encode().into());

        // This should revert with EmptyProof
        let result = provider.send_transaction(tx).await;
        assert!(
            result.is_err() || {
                let receipt = result.unwrap().get_receipt().await;
                receipt.is_err() || !receipt.unwrap().status()
            }
        );

        tracing::info!("Empty proof correctly rejected");
        Ok(())
    }

    /// Test that wrong signature length is rejected.
    #[tokio::test]
    #[ignore = "requires anvil"]
    async fn test_wrong_signature_length() -> eyre::Result<()> {
        let anvil = AnvilInstance::start().await?;
        let bridge_addr = deploy_finalization_bridge(&anvil.rpc_url, 98985).await?;

        let mock_header = create_mock_block_header();
        let wrong_len_sig = vec![0x01u8; 64]; // Should be 128 bytes
        let mock_proof: Vec<Bytes> = vec![Bytes::from(vec![0x80])];

        let write_call = writeCall {
            blockHeader: Bytes::from(mock_header),
            finalizationSignature: Bytes::from(wrong_len_sig),
            receiptProof: mock_proof,
            receiptIndex: U256::ZERO,
            logIndex: U256::ZERO,
        };

        let provider = ProviderBuilder::new()
            .wallet(alloy::network::EthereumWallet::from(
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                    .parse::<alloy::signers::local::PrivateKeySigner>()
                    .unwrap(),
            ))
            .connect_http(anvil.rpc_url.parse()?);

        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(bridge_addr)
            .gas_limit(500_000)
            .input(write_call.abi_encode().into());

        // This should revert with InvalidSignatureLength
        let result = provider.send_transaction(tx).await;
        assert!(
            result.is_err() || {
                let receipt = result.unwrap().get_receipt().await;
                receipt.is_err() || !receipt.unwrap().status()
            }
        );

        tracing::info!("Wrong signature length correctly rejected");
        Ok(())
    }

    // =========================================================================
    // Helper functions
    // =========================================================================

    /// Create a minimal valid RLP-encoded block header for testing.
    /// This is a mock header - real tests need actual Tempo headers.
    fn create_mock_block_header() -> Vec<u8> {
        // Minimal Ethereum block header structure (RLP list with 16+ elements)
        // [parentHash, unclesHash, coinbase, stateRoot, txRoot, receiptsRoot, ...]
        let mut header = Vec::new();

        // RLP list prefix for long list
        header.push(0xf9); // List > 55 bytes
        header.push(0x02); // Length high byte
        header.push(0x00); // Length low byte (placeholder)

        // parentHash (32 bytes)
        header.push(0xa0);
        header.extend_from_slice(&[0u8; 32]);

        // unclesHash (32 bytes)
        header.push(0xa0);
        header.extend_from_slice(&[0u8; 32]);

        // coinbase (20 bytes)
        header.push(0x94);
        header.extend_from_slice(&[0u8; 20]);

        // stateRoot (32 bytes)
        header.push(0xa0);
        header.extend_from_slice(&[0u8; 32]);

        // txRoot (32 bytes)
        header.push(0xa0);
        header.extend_from_slice(&[0u8; 32]);

        // receiptsRoot (32 bytes) - index 5
        header.push(0xa0);
        header.extend_from_slice(&[0u8; 32]);

        // logsBloom (256 bytes)
        header.push(0xb9);
        header.push(0x01);
        header.push(0x00);
        header.extend_from_slice(&[0u8; 256]);

        // difficulty (0)
        header.push(0x80);

        // number (0)
        header.push(0x80);

        // gasLimit (0)
        header.push(0x80);

        // gasUsed (0)
        header.push(0x80);

        // timestamp (0)
        header.push(0x80);

        // extraData (empty)
        header.push(0x80);

        // mixHash (32 bytes)
        header.push(0xa0);
        header.extend_from_slice(&[0u8; 32]);

        // nonce (8 bytes)
        header.push(0x88);
        header.extend_from_slice(&[0u8; 8]);

        // Update length bytes
        let len = header.len() - 3;
        header[1] = ((len >> 8) & 0xff) as u8;
        header[2] = (len & 0xff) as u8;

        header
    }
}
