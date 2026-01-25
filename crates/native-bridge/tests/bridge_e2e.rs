//! End-to-end tests for the bridge sidecar.
//!
//! This test:
//! 1. Starts an Anvil instance (Ethereum with Prague hardfork for EIP-2537)
//! 2. Starts a Tempo node (in-process via TestNodeBuilder)
//! 3. Deploys the REAL MessageBridge contract to both
//! 4. Sends messages and verifies event subscription works
//! 5. Full flow test: Ethereum → sign → aggregate → submit to Tempo

use std::{
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    signers::local::MnemonicBuilder,
    sol,
    sol_types::SolEvent,
};
use alloy_primitives::B256;
use commonware_codec::Encode;
use commonware_cryptography::bls12381::{dkg, primitives::sharing::Mode};
use commonware_utils::{N3f1, NZU32};
use futures::StreamExt;
use rand::{SeedableRng, rngs::StdRng};
use reth_ethereum::tasks::TaskManager;
use reth_node_builder::{NodeBuilder, NodeConfig};
use reth_node_core::args::RpcServerArgs;
use reth_rpc_builder::RpcModuleSelection;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_native_bridge::{
    eip2537::g2_to_eip2537,
    message::{G2_COMPRESSED_LEN, Message},
    sidecar::aggregator::Aggregator,
    signer::BLSSigner,
};
use tempo_node::node::TempoNode;
use tempo_precompiles::{PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS, tip20::ISSUER_ROLE};
use tokio::time::timeout;

/// Standard test mnemonic (has balance in genesis).
const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

// MessageBridge contract interface
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
        address sender,
        bytes32 messageHash,
        uint64 originChainId,
        bytes signature
    ) external;

    #[derive(Debug)]
    function receivedAt(uint64 originChainId, address sender, bytes32 messageHash) external view returns (uint256);
}

/// Encode MessageBridge constructor arguments.
/// constructor(address _owner, uint64 _initialEpoch, bytes memory _initialPublicKey)
fn encode_message_bridge_constructor(owner: Address, epoch: u64, public_key: &[u8]) -> Vec<u8> {
    // ABI encode: (address, uint64, bytes)
    // address is padded to 32 bytes
    // uint64 is padded to 32 bytes
    // bytes is encoded as: offset (32) + length (32) + data (padded to 32)
    let mut encoded = Vec::new();

    // owner (address, 32 bytes)
    encoded.extend_from_slice(&[0u8; 12]); // 12 bytes padding
    encoded.extend_from_slice(owner.as_slice());

    // epoch (uint64, 32 bytes)
    encoded.extend_from_slice(&[0u8; 24]); // 24 bytes padding
    encoded.extend_from_slice(&epoch.to_be_bytes());

    // bytes offset (points to byte 96 = 0x60)
    encoded.extend_from_slice(&[0u8; 31]);
    encoded.push(0x60);

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

/// Anvil instance wrapper with automatic cleanup.
struct AnvilInstance {
    child: Child,
    rpc_url: String,
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

/// Real MessageBridge bytecode.
/// Uses EIP-2537 BLS12-381 precompiles (available on Prague+ hardfork and Tempo).
/// From: crates/native-bridge/contracts/out/MessageBridge.sol/MessageBridge.json
const MESSAGE_BRIDGE_BYTECODE: &str =
    include_str!("../contracts/out/MessageBridge.sol/MessageBridge.bytecode.hex");

/// Real TokenBridge bytecode.
/// From: crates/native-bridge/contracts/out/TokenBridge.sol/TokenBridge.json
const TOKEN_BRIDGE_BYTECODE: &str =
    include_str!("../contracts/out/TokenBridge.sol/TokenBridge.bytecode.hex");

/// MockERC20 bytecode for testing on Anvil (Ethereum).
/// From: crates/native-bridge/contracts/out/MockERC20.sol/MockERC20.json
const MOCK_ERC20_BYTECODE: &str =
    include_str!("../contracts/out/MockERC20.sol/MockERC20.bytecode.hex");

/// G2 generator point (uncompressed, 256 bytes EIP-2537 format) for test deployment.
/// This is a valid BLS12-381 G2 point that can be used as the initial public key.
/// The MessageBridge uses MinSig variant: G2 public keys (256 bytes), G1 signatures (128 bytes).
/// Format: 4 × 64-byte Fp elements (each with 16 bytes zero padding + 48 bytes value)
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

/// Deploy the real MessageBridge contract (for Anvil with Prague hardfork).
async fn deploy_message_bridge_anvil(rpc_url: &str) -> eyre::Result<Address> {
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
    let bytecode = hex::decode(MESSAGE_BRIDGE_BYTECODE.trim())?;

    // Constructor arguments: owner, initial epoch, initial public key (G2 generator)
    let initial_epoch = 1u64;
    let initial_public_key = hex::decode(G2_GENERATOR_EIP2537)?;

    // Encode constructor args and append to bytecode
    let constructor_args =
        encode_message_bridge_constructor(owner, initial_epoch, &initial_public_key);
    let deploy_code: Vec<u8> = bytecode.into_iter().chain(constructor_args).collect();

    let tx =
        alloy::rpc::types::TransactionRequest::default().with_deploy_code(Bytes::from(deploy_code));

    let pending = provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;

    let address = receipt
        .contract_address
        .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;

    tracing::info!(%address, %owner, epoch = initial_epoch, "deployed MessageBridge on Anvil");
    Ok(address)
}

/// Deploy the real MessageBridge contract on Tempo.
async fn deploy_message_bridge_tempo(rpc_url: &str) -> eyre::Result<Address> {
    use alloy::{network::TransactionBuilder, providers::ProviderBuilder};

    // Use the funded mnemonic wallet
    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let owner = wallet.address();

    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(wallet))
        .connect_http(rpc_url.parse()?);

    // Contract bytecode
    let bytecode = hex::decode(MESSAGE_BRIDGE_BYTECODE.trim())?;

    // Constructor arguments: owner, initial epoch, initial public key (G2 generator)
    let initial_epoch = 1u64;
    let initial_public_key = hex::decode(G2_GENERATOR_EIP2537)?;

    // Encode constructor args and append to bytecode
    let constructor_args =
        encode_message_bridge_constructor(owner, initial_epoch, &initial_public_key);
    let deploy_code: Vec<u8> = bytecode.into_iter().chain(constructor_args).collect();

    let tx =
        alloy::rpc::types::TransactionRequest::default().with_deploy_code(Bytes::from(deploy_code));

    let pending = provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;

    let address = receipt
        .contract_address
        .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;

    tracing::info!(%address, %owner, epoch = initial_epoch, "deployed MessageBridge on Tempo");
    Ok(address)
}

#[tokio::test]
async fn test_anvil_event_subscription() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("bridge_e2e=debug,tempo_native_bridge=debug")
        .try_init()
        .ok();

    // Start Anvil
    let anvil = AnvilInstance::start().await?;
    tracing::info!(rpc = %anvil.rpc_url, ws = %anvil.ws_url, "anvil running");

    // Deploy mock bridge
    let bridge_address = deploy_message_bridge_anvil(&anvil.rpc_url).await?;

    // Connect via WebSocket and subscribe to events
    let ws_provider = ProviderBuilder::new().connect(&anvil.ws_url).await?;

    let filter = Filter::new()
        .address(bridge_address)
        .event_signature(MessageSent::SIGNATURE_HASH);

    let sub = ws_provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();

    tracing::info!("subscribed to MessageSent events");

    // Send a message using HTTP provider
    let signer: alloy::signers::local::PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();

    let http_provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .connect_http(anvil.rpc_url.parse()?);

    // Send a transaction that emits MessageSent
    let message_hash = B256::repeat_byte(0x42);
    let dest_chain_id = 12345u64;

    let call = sendCall {
        messageHash: message_hash,
        destinationChainId: dest_chain_id,
    };

    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(bridge_address)
        .input(alloy::sol_types::SolCall::abi_encode(&call).into());

    let pending = http_provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;
    tracing::info!(tx_hash = %receipt.transaction_hash, "sent message");

    // Wait for the event
    let event = timeout(Duration::from_secs(10), stream.next())
        .await?
        .ok_or_else(|| eyre::eyre!("no event received"))?;

    tracing::info!(?event, "received event");

    // Verify event data
    let topics = event.topics();
    assert!(topics.len() >= 4, "expected 4 topics");

    let received_sender = Address::from_slice(&topics[1].as_slice()[12..]);
    let received_hash = B256::from(topics[2]);
    let received_dest = u64::from_be_bytes(topics[3].as_slice()[24..].try_into()?);

    tracing::info!(
        sender = %received_sender,
        hash = %received_hash,
        dest = received_dest,
        "parsed event"
    );

    assert_eq!(received_hash, message_hash);
    assert_eq!(received_dest, dest_chain_id);

    tracing::info!("test passed!");
    Ok(())
}

#[tokio::test]
async fn test_anvil_polling_fallback() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("bridge_e2e=debug")
        .try_init()
        .ok();

    // Start Anvil
    let anvil = AnvilInstance::start().await?;

    // Deploy mock bridge
    let bridge_address = deploy_message_bridge_anvil(&anvil.rpc_url).await?;

    // Use HTTP provider (polling mode)
    let provider = ProviderBuilder::new().connect_http(anvil.rpc_url.parse()?);

    let start_block = provider.get_block_number().await?;

    // Send a message
    let signer: alloy::signers::local::PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();

    let tx_provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .connect_http(anvil.rpc_url.parse()?);

    let message_hash = B256::repeat_byte(0x11);

    let call = sendCall {
        messageHash: message_hash,
        destinationChainId: 1u64,
    };

    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(bridge_address)
        .input(alloy::sol_types::SolCall::abi_encode(&call).into());

    let pending = tx_provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;
    tracing::info!(tx_hash = %receipt.transaction_hash, "sent message");

    // Wait a bit for block to be mined
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Poll for logs
    let end_block = provider.get_block_number().await?;

    let filter = Filter::new()
        .address(bridge_address)
        .event_signature(MessageSent::SIGNATURE_HASH)
        .from_block(start_block)
        .to_block(end_block);

    let logs = provider.get_logs(&filter).await?;
    tracing::info!(count = logs.len(), "fetched logs");

    assert!(!logs.is_empty(), "expected at least one log");

    let log = &logs[0];
    let received_hash = B256::from(log.topics()[2]);
    assert_eq!(received_hash, message_hash);

    tracing::info!("polling test passed!");
    Ok(())
}

/// Test genesis JSON for Tempo node tests.
const TEST_GENESIS: &str = include_str!("../../node/tests/assets/test-genesis.json");

/// Start an in-process Tempo node for testing.
async fn start_tempo_node() -> eyre::Result<(String, String, TaskManager)> {
    let genesis: serde_json::Value = serde_json::from_str(TEST_GENESIS)?;
    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_value(genesis)?);
    let validator = chain_spec.inner.genesis.coinbase;

    let tasks = TaskManager::current();

    let mut node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(
            RpcServerArgs::default()
                .with_unused_ports()
                .with_http()
                .with_ws()
                .with_http_api(RpcModuleSelection::All)
                .with_ws_api(RpcModuleSelection::All),
        );
    node_config.dev.block_time = Some(Duration::from_millis(500));

    let node_handle = NodeBuilder::new(node_config)
        .testing_node(tasks.executor())
        .node(TempoNode::default())
        .launch_with_debug_capabilities()
        .map_debug_payload_attributes(move |mut attributes| {
            attributes.suggested_fee_recipient = validator;
            attributes
        })
        .await?;

    let http_url = node_handle
        .node
        .rpc_server_handle()
        .http_url()
        .ok_or_else(|| eyre::eyre!("no HTTP URL"))?;

    let ws_url = node_handle
        .node
        .rpc_server_handle()
        .ws_url()
        .ok_or_else(|| eyre::eyre!("no WS URL"))?;

    tracing::info!(%http_url, %ws_url, "tempo node started");

    // Keep the node handle alive by leaking it (task manager keeps it running)
    std::mem::forget(node_handle);

    Ok((http_url, ws_url, tasks))
}

#[tokio::test]
async fn test_tempo_event_subscription() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("bridge_e2e=debug,tempo_native_bridge=debug,tempo=info")
        .try_init()
        .ok();

    // Start Tempo node
    let (http_url, ws_url, _tasks) = start_tempo_node().await?;
    tracing::info!(http = %http_url, ws = %ws_url, "tempo node running");

    // Deploy mock bridge contract (use Tempo deployer with funded wallet)
    let bridge_address = deploy_message_bridge_tempo(&http_url).await?;

    // Connect via WebSocket and subscribe to events
    let ws_provider = ProviderBuilder::new().connect(&ws_url).await?;

    let filter = Filter::new()
        .address(bridge_address)
        .event_signature(MessageSent::SIGNATURE_HASH);

    let sub = ws_provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();

    tracing::info!("subscribed to MessageSent events on Tempo");

    // Send a message using HTTP provider with funded wallet
    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;

    let http_provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(wallet))
        .connect_http(http_url.parse()?);

    // Send a transaction that emits MessageSent
    let message_hash = B256::repeat_byte(0x99);
    let dest_chain_id = 1u64; // Ethereum mainnet

    let call = sendCall {
        messageHash: message_hash,
        destinationChainId: dest_chain_id,
    };

    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(bridge_address)
        .input(alloy::sol_types::SolCall::abi_encode(&call).into());

    let pending = http_provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;
    tracing::info!(tx_hash = %receipt.transaction_hash, "sent message on Tempo");

    // Wait for the event
    let event = timeout(Duration::from_secs(10), stream.next())
        .await?
        .ok_or_else(|| eyre::eyre!("no event received from Tempo"))?;

    tracing::info!(?event, "received event from Tempo");

    // Verify event data
    let topics = event.topics();
    assert!(topics.len() >= 4, "expected 4 topics");

    let received_hash = B256::from(topics[2]);
    let received_dest = u64::from_be_bytes(topics[3].as_slice()[24..].try_into()?);

    tracing::info!(
        hash = %received_hash,
        dest = received_dest,
        "parsed Tempo event"
    );

    assert_eq!(received_hash, message_hash);
    assert_eq!(received_dest, dest_chain_id);

    tracing::info!("Tempo event subscription test passed!");
    Ok(())
}

#[tokio::test]
async fn test_tempo_polling_fallback() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("bridge_e2e=debug")
        .try_init()
        .ok();

    // Start Tempo node
    let (http_url, _ws_url, _tasks) = start_tempo_node().await?;

    // Deploy mock bridge (use Tempo deployer with funded wallet)
    let bridge_address = deploy_message_bridge_tempo(&http_url).await?;

    // Use HTTP provider (polling mode)
    let provider = ProviderBuilder::new().connect_http(http_url.parse()?);

    let start_block = provider.get_block_number().await?;

    // Send a message with funded wallet
    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;

    let tx_provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(wallet))
        .connect_http(http_url.parse()?);

    let message_hash = B256::repeat_byte(0x77);

    let call = sendCall {
        messageHash: message_hash,
        destinationChainId: 1u64,
    };

    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(bridge_address)
        .input(alloy::sol_types::SolCall::abi_encode(&call).into());

    let pending = tx_provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;
    tracing::info!(tx_hash = %receipt.transaction_hash, "sent message on Tempo");

    // Wait for block to be mined
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Poll for logs
    let end_block = provider.get_block_number().await?;

    let filter = Filter::new()
        .address(bridge_address)
        .event_signature(MessageSent::SIGNATURE_HASH)
        .from_block(start_block)
        .to_block(end_block);

    let logs = provider.get_logs(&filter).await?;
    tracing::info!(count = logs.len(), "fetched logs from Tempo");

    assert!(!logs.is_empty(), "expected at least one log");

    let log = &logs[0];
    let received_hash = B256::from(log.topics()[2]);
    assert_eq!(received_hash, message_hash);

    tracing::info!("Tempo polling test passed!");
    Ok(())
}

/// Generate DKG keys for testing (5 shares, threshold 3).
/// Returns (sharing, shares, group_public_key_eip2537)
fn generate_test_dkg_keys() -> (
    commonware_cryptography::bls12381::primitives::sharing::Sharing<
        commonware_cryptography::bls12381::primitives::variant::MinSig,
    >,
    Vec<commonware_cryptography::bls12381::primitives::group::Share>,
    [u8; 256], // G2 public key in EIP-2537 format
) {
    use commonware_cryptography::bls12381::primitives::variant::MinSig;

    let mut rng = StdRng::seed_from_u64(42);
    let n = NZU32!(5);

    let (sharing, shares) = dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Mode::default(), n);

    // Get group public key (G2) and convert to EIP-2537 format
    let group_public = sharing.public();
    let compressed = group_public.encode();
    let compressed_array: [u8; G2_COMPRESSED_LEN] = compressed.as_ref().try_into().unwrap();
    let eip2537_pubkey = g2_to_eip2537(&compressed_array).unwrap();

    (sharing, shares, eip2537_pubkey)
}

/// Deploy MessageBridge with a specific G2 public key (for Anvil).
async fn deploy_bridge_with_pubkey_anvil(
    rpc_url: &str,
    public_key: &[u8; 256],
) -> eyre::Result<Address> {
    use alloy::{
        network::TransactionBuilder, providers::ProviderBuilder, signers::local::PrivateKeySigner,
    };

    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let owner = signer.address();

    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .connect_http(rpc_url.parse()?);

    let bytecode = hex::decode(MESSAGE_BRIDGE_BYTECODE.trim())?;
    let constructor_args = encode_message_bridge_constructor(owner, 1, public_key);
    let deploy_code: Vec<u8> = bytecode.into_iter().chain(constructor_args).collect();

    let tx =
        alloy::rpc::types::TransactionRequest::default().with_deploy_code(Bytes::from(deploy_code));

    let pending = provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;

    let address = receipt
        .contract_address
        .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;

    tracing::info!(%address, "deployed MessageBridge with G2 pubkey on Anvil");
    Ok(address)
}

/// Deploy MessageBridge with a specific G2 public key (for Tempo).
async fn deploy_bridge_with_pubkey_tempo(
    rpc_url: &str,
    public_key: &[u8; 256],
) -> eyre::Result<Address> {
    use alloy::{network::TransactionBuilder, providers::ProviderBuilder};

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let owner = wallet.address();

    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(wallet))
        .connect_http(rpc_url.parse()?);

    let bytecode = hex::decode(MESSAGE_BRIDGE_BYTECODE.trim())?;
    let constructor_args = encode_message_bridge_constructor(owner, 1, public_key);
    let deploy_code: Vec<u8> = bytecode.into_iter().chain(constructor_args).collect();

    let tx =
        alloy::rpc::types::TransactionRequest::default().with_deploy_code(Bytes::from(deploy_code));

    let pending = provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;

    let address = receipt
        .contract_address
        .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;

    tracing::info!(%address, "deployed MessageBridge with G2 pubkey on Tempo");
    Ok(address)
}

/// Full end-to-end test: Ethereum → Tempo cross-chain message flow.
///
/// This test:
/// 1. Generates real DKG keys (5 shares, threshold 3)
/// 2. Deploys MessageBridge on both Anvil (Ethereum) and Tempo with the same G2 public key
/// 3. Sends a message from Ethereum (calls `send()`)
/// 4. Signs the attestation with 3 signers
/// 5. Aggregates the threshold signature
/// 6. Submits to Tempo (calls `write()`)
/// 7. Verifies the message was received
#[tokio::test]
async fn test_full_bridge_flow_ethereum_to_tempo() -> eyre::Result<()> {
    use alloy::sol_types::SolCall;
    use tempo_native_bridge::eip2537::g1_to_eip2537;

    tracing_subscriber::fmt()
        .with_env_filter("bridge_e2e=debug,tempo_native_bridge=debug")
        .try_init()
        .ok();

    // ========================================
    // Step 1: Generate DKG keys
    // ========================================
    let (sharing, shares, group_pubkey) = generate_test_dkg_keys();
    let threshold = sharing.required::<N3f1>();
    tracing::info!(
        threshold,
        n = shares.len(),
        pubkey_len = group_pubkey.len(),
        "generated DKG keys"
    );

    // ========================================
    // Step 2: Start nodes and deploy contracts
    // ========================================
    let anvil = AnvilInstance::start().await?;
    let (tempo_http, _tempo_ws, _tasks) = start_tempo_node().await?;

    // Get chain IDs
    let anvil_provider = ProviderBuilder::new().connect_http(anvil.rpc_url.parse()?);
    let tempo_provider = ProviderBuilder::new().connect_http(tempo_http.parse()?);
    let ethereum_chain_id = anvil_provider.get_chain_id().await?;
    let tempo_chain_id = tempo_provider.get_chain_id().await?;
    tracing::info!(ethereum_chain_id, tempo_chain_id, "chain IDs");

    // Deploy MessageBridge on both chains with same public key
    let eth_bridge = deploy_bridge_with_pubkey_anvil(&anvil.rpc_url, &group_pubkey).await?;
    let tempo_bridge = deploy_bridge_with_pubkey_tempo(&tempo_http, &group_pubkey).await?;

    // ========================================
    // Step 3: Send message from Ethereum
    // ========================================
    let signer: alloy::signers::local::PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let sender = signer.address();

    let eth_provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .connect_http(anvil.rpc_url.parse()?);

    let message_hash = B256::repeat_byte(0xAB);

    let send_call = sendCall {
        messageHash: message_hash,
        destinationChainId: tempo_chain_id,
    };

    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(eth_bridge)
        .input(send_call.abi_encode().into());

    let pending = eth_provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;
    tracing::info!(
        tx_hash = %receipt.transaction_hash,
        sender = %sender,
        message_hash = %message_hash,
        "sent message from Ethereum"
    );

    // ========================================
    // Step 4: Create Message and sign with threshold signers
    // ========================================
    let message = Message::new(sender, message_hash, ethereum_chain_id, tempo_chain_id);
    let attestation_hash = message.attestation_hash();
    tracing::info!(attestation_hash = %attestation_hash, "computed attestation hash");

    // Create aggregator
    let mut aggregator = Aggregator::new(sharing.clone(), 1);

    // Sign with threshold number of signers
    let mut aggregated_result = None;
    for (i, share) in shares.iter().take(threshold as usize).enumerate() {
        let signer = BLSSigner::new(share.clone());
        let partial = signer.sign_partial(attestation_hash)?;
        tracing::debug!(index = partial.index, "signer {} produced partial", i);

        if let Some(result) = aggregator.add_partial(attestation_hash, partial, &message) {
            aggregated_result = Some(result);
        }
    }

    let (agg_sig, _) = aggregated_result.expect("threshold should be reached");
    tracing::info!(
        epoch = agg_sig.epoch,
        sig_len = agg_sig.signature.len(),
        "threshold signature recovered"
    );

    // ========================================
    // Step 5: Convert signature and submit to Tempo
    // ========================================
    // Convert G1 signature to EIP-2537 format (128 bytes)
    let eip2537_sig = g1_to_eip2537(&agg_sig.signature)?;
    tracing::info!(sig_len = eip2537_sig.len(), "converted to EIP-2537 format");

    let tempo_wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let tempo_tx_provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(tempo_wallet))
        .connect_http(tempo_http.parse()?);

    let write_call = writeCall {
        sender,
        messageHash: message_hash,
        originChainId: ethereum_chain_id,
        signature: Bytes::from(eip2537_sig.to_vec()),
    };

    let write_tx = alloy::rpc::types::TransactionRequest::default()
        .to(tempo_bridge)
        .input(write_call.abi_encode().into());

    let write_pending = tempo_tx_provider.send_transaction(write_tx).await?;
    let write_receipt = write_pending.get_receipt().await?;

    assert!(write_receipt.status(), "write transaction should succeed");

    tracing::info!(
        tx_hash = %write_receipt.transaction_hash,
        block = ?write_receipt.block_number,
        "submitted attestation to Tempo"
    );

    // ========================================
    // Step 6: Verify message was received
    // ========================================
    // Check MessageReceived event
    let logs = write_receipt.inner.logs();
    assert!(
        !logs.is_empty(),
        "should have emitted MessageReceived event"
    );

    let event_topic = logs[0].topics()[0];
    assert_eq!(
        event_topic,
        MessageReceived::SIGNATURE_HASH,
        "should be MessageReceived event"
    );

    // Call receivedAt to verify timestamp is set
    let received_at_call = receivedAtCall {
        originChainId: ethereum_chain_id,
        sender,
        messageHash: message_hash,
    };

    let call_result = tempo_provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(tempo_bridge)
                .input(received_at_call.abi_encode().into()),
        )
        .await?;

    // Decode the uint256 result
    let timestamp = alloy_primitives::U256::from_be_slice(&call_result);
    assert!(
        timestamp > alloy_primitives::U256::ZERO,
        "receivedAt should be non-zero"
    );

    tracing::info!(
        timestamp = %timestamp,
        "message successfully received on Tempo"
    );

    tracing::info!("🎉 Full bridge flow test passed: Ethereum → Tempo");
    Ok(())
}

// ============================================================================
// TokenBridge E2E Test - Full USDC Lock/Mint/Burn/Unlock Flow
// ============================================================================

// TokenBridge contract interface
sol! {
    #[derive(Debug)]
    event TokensBridged(
        bytes32 indexed messageHash,
        bytes32 indexed assetId,
        uint256 indexed nonce,
        address sender,
        address recipient,
        uint256 amount,
        uint64 destinationChainId
    );

    #[derive(Debug)]
    event TokensClaimed(
        bytes32 indexed messageHash,
        bytes32 indexed assetId,
        address indexed recipient,
        uint256 amount,
        uint64 originChainId
    );

    #[derive(Debug)]
    function bridgeTokens(
        bytes32 assetId,
        address recipient,
        uint256 amount,
        uint64 destinationChainId
    ) external returns (bytes32 messageHash, uint256 transferNonce);

    #[derive(Debug)]
    function claimTokens(
        bytes32 assetId,
        address recipient,
        uint256 amount,
        uint256 transferNonce,
        uint64 originChainId
    ) external;

    #[derive(Debug)]
    function registerAsset(
        bytes32 assetId,
        uint64 homeChainId,
        address homeToken,
        address localToken,
        bool isHomeChain
    ) external;

    #[derive(Debug)]
    function computeAssetId(uint64 homeChainId, address homeToken) external pure returns (bytes32);
}

// ERC20/TIP20 interface for testing
sol! {
    #[derive(Debug)]
    function mint(address to, uint256 amount) external;

    #[derive(Debug)]
    function approve(address spender, uint256 amount) external returns (bool);

    #[derive(Debug)]
    function balanceOf(address account) external view returns (uint256);

    #[derive(Debug)]
    function burn(uint256 amount) external;

    #[derive(Debug)]
    function transfer(address to, uint256 amount) external returns (bool);
}

// TIP20 Factory interface
sol! {
    #[derive(Debug)]
    event TokenCreated(address indexed token, string name, string symbol, string currency, address quoteToken, address admin, bytes32 salt);

    #[derive(Debug)]
    function createToken(
        string memory name,
        string memory symbol,
        string memory currency,
        address quoteToken,
        address admin,
        bytes32 salt
    ) external returns (address);
}

// RolesAuth interface for granting roles
sol! {
    #[derive(Debug)]
    function grantRole(bytes32 role, address account) external;

    #[derive(Debug)]
    function hasRole(address account, bytes32 role) external view returns (bool);
}

/// Encode MockERC20 constructor arguments: (string name, string symbol, uint8 decimals)
fn encode_mock_erc20_constructor(name: &str, symbol: &str, decimals: u8) -> Vec<u8> {
    // ABI encode: (string, string, uint8)
    // Strings: offset, offset, uint8, then string data
    let mut encoded = Vec::new();

    // Calculate offsets:
    // - First string offset: 96 (3 * 32 bytes for the 3 parameters)
    // - Second string offset: 96 + 32 + padded_name_len
    let name_bytes = name.as_bytes();
    let symbol_bytes = symbol.as_bytes();
    let name_padded_len = ((name_bytes.len() + 31) / 32) * 32;
    let symbol_padded_len = ((symbol_bytes.len() + 31) / 32) * 32;

    let name_offset: u64 = 96; // 3 * 32
    let symbol_offset: u64 = name_offset + 32 + name_padded_len as u64;

    // Offset for name string (32 bytes)
    encoded.extend_from_slice(&[0u8; 24]);
    encoded.extend_from_slice(&name_offset.to_be_bytes());

    // Offset for symbol string (32 bytes)
    encoded.extend_from_slice(&[0u8; 24]);
    encoded.extend_from_slice(&symbol_offset.to_be_bytes());

    // decimals (uint8, 32 bytes)
    encoded.extend_from_slice(&[0u8; 31]);
    encoded.push(decimals);

    // Name string: length + data
    encoded.extend_from_slice(&[0u8; 24]);
    encoded.extend_from_slice(&(name_bytes.len() as u64).to_be_bytes());
    encoded.extend_from_slice(name_bytes);
    encoded.extend_from_slice(&vec![0u8; name_padded_len - name_bytes.len()]);

    // Symbol string: length + data
    encoded.extend_from_slice(&[0u8; 24]);
    encoded.extend_from_slice(&(symbol_bytes.len() as u64).to_be_bytes());
    encoded.extend_from_slice(symbol_bytes);
    encoded.extend_from_slice(&vec![0u8; symbol_padded_len - symbol_bytes.len()]);

    encoded
}

/// Deploy MockERC20 on Anvil and mint tokens to a user.
async fn deploy_mock_erc20_anvil(
    rpc_url: &str,
    name: &str,
    symbol: &str,
    decimals: u8,
) -> eyre::Result<Address> {
    use alloy::{network::TransactionBuilder, signers::local::PrivateKeySigner};

    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();

    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .connect_http(rpc_url.parse()?);

    let bytecode = hex::decode(MOCK_ERC20_BYTECODE.trim())?;
    let constructor_args = encode_mock_erc20_constructor(name, symbol, decimals);
    let deploy_code: Vec<u8> = bytecode.into_iter().chain(constructor_args).collect();

    let tx =
        alloy::rpc::types::TransactionRequest::default().with_deploy_code(Bytes::from(deploy_code));

    let pending = provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;

    let address = receipt
        .contract_address
        .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;

    tracing::info!(%address, name, symbol, decimals, "deployed MockERC20 on Anvil");
    Ok(address)
}

/// Create a TIP-20 token on Tempo via the factory and grant ISSUER_ROLE to an address.
async fn create_tip20_tempo(
    rpc_url: &str,
    name: &str,
    symbol: &str,
    issuer: Address,
) -> eyre::Result<Address> {
    use alloy::sol_types::SolCall;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let admin = wallet.address();

    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(wallet))
        .connect_http(rpc_url.parse()?);

    // Create token via factory
    let salt = B256::random();
    let create_call = createTokenCall {
        name: name.to_string(),
        symbol: symbol.to_string(),
        currency: "USD".to_string(),
        quoteToken: PATH_USD_ADDRESS,
        admin,
        salt,
    };

    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(TIP20_FACTORY_ADDRESS)
        .gas_limit(5_000_000)
        .input(create_call.abi_encode().into());

    let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
    assert!(receipt.status(), "createToken failed");

    // Parse TokenCreated event to get token address
    let logs = receipt.inner.logs();
    // Find the TokenCreated event (should be the second log, first is usually Transfer)
    let token_created_log = logs
        .iter()
        .find(|log| !log.topics().is_empty() && log.topics()[0] == TokenCreated::SIGNATURE_HASH)
        .ok_or_else(|| eyre::eyre!("TokenCreated event not found"))?;

    // The token address is the first indexed parameter (topics[1])
    let token_address = Address::from_slice(&token_created_log.topics()[1].as_slice()[12..]);
    tracing::info!(%token_address, name, symbol, "created TIP-20 token on Tempo");

    // Grant ISSUER_ROLE to the issuer (TokenBridge)
    let grant_call = grantRoleCall {
        role: *ISSUER_ROLE,
        account: issuer,
    };

    let grant_tx = alloy::rpc::types::TransactionRequest::default()
        .to(token_address)
        .gas_limit(1_000_000)
        .input(grant_call.abi_encode().into());

    let grant_receipt = provider
        .send_transaction(grant_tx)
        .await?
        .get_receipt()
        .await?;
    assert!(grant_receipt.status(), "grantRole failed");
    tracing::info!(%issuer, role = ?*ISSUER_ROLE, "granted ISSUER_ROLE to TokenBridge");

    // Verify the role was granted
    let has_role_call = hasRoleCall {
        account: issuer,
        role: *ISSUER_ROLE,
    };
    let result = provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(token_address)
                .input(has_role_call.abi_encode().into()),
        )
        .await
        .map_err(|e| eyre::eyre!("hasRole call failed: {e}"))?;

    let has_role = result.len() >= 32 && result[31] == 1;
    if !has_role {
        return Err(eyre::eyre!("ISSUER_ROLE was not granted to {issuer}"));
    }
    tracing::info!(%issuer, has_role, "verified ISSUER_ROLE");

    Ok(token_address)
}

/// Encode TokenBridge constructor arguments: (address owner, address messageBridge)
fn encode_token_bridge_constructor(owner: Address, message_bridge: Address) -> Vec<u8> {
    let mut encoded = Vec::new();
    // owner (address, 32 bytes)
    encoded.extend_from_slice(&[0u8; 12]);
    encoded.extend_from_slice(owner.as_slice());
    // messageBridge (address, 32 bytes)
    encoded.extend_from_slice(&[0u8; 12]);
    encoded.extend_from_slice(message_bridge.as_slice());
    encoded
}

/// Deploy TokenBridge contract on Anvil.
async fn deploy_token_bridge_anvil(
    rpc_url: &str,
    message_bridge: Address,
) -> eyre::Result<Address> {
    use alloy::{network::TransactionBuilder, signers::local::PrivateKeySigner};

    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let owner = signer.address();

    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .connect_http(rpc_url.parse()?);

    let bytecode = hex::decode(TOKEN_BRIDGE_BYTECODE.trim())?;
    let constructor_args = encode_token_bridge_constructor(owner, message_bridge);
    let deploy_code: Vec<u8> = bytecode.into_iter().chain(constructor_args).collect();

    let tx =
        alloy::rpc::types::TransactionRequest::default().with_deploy_code(Bytes::from(deploy_code));

    let pending = provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;

    let address = receipt
        .contract_address
        .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;

    tracing::info!(%address, %message_bridge, "deployed TokenBridge on Anvil");
    Ok(address)
}

/// Deploy TokenBridge contract on Tempo.
async fn deploy_token_bridge_tempo(
    rpc_url: &str,
    message_bridge: Address,
) -> eyre::Result<Address> {
    use alloy::network::TransactionBuilder;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let owner = wallet.address();

    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(wallet))
        .connect_http(rpc_url.parse()?);

    let bytecode = hex::decode(TOKEN_BRIDGE_BYTECODE.trim())?;
    let constructor_args = encode_token_bridge_constructor(owner, message_bridge);
    let deploy_code: Vec<u8> = bytecode.into_iter().chain(constructor_args).collect();

    let tx =
        alloy::rpc::types::TransactionRequest::default().with_deploy_code(Bytes::from(deploy_code));

    let pending = provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;

    let address = receipt
        .contract_address
        .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;

    tracing::info!(%address, %message_bridge, "deployed TokenBridge on Tempo");
    Ok(address)
}

/// Full TokenBridge E2E test: USDC Lock/Mint (Eth→Tempo) and Burn/Unlock (Tempo→Eth).
///
/// This test deploys REAL tokens and performs ACTUAL transfers:
/// 1. Generates real DKG keys (5 shares, threshold 4)
/// 2. Deploys MessageBridge + TokenBridge on both Anvil (Ethereum) and Tempo
/// 3. Deploys MockERC20 (USDC) on Ethereum, creates TIP-20 (USDC.t) on Tempo
/// 4. Phase 1: Lock USDC on Ethereum → sign attestation → claim/mint USDC.t on Tempo
/// 5. Phase 2: Burn USDC.t on Tempo → sign attestation → claim/unlock USDC on Ethereum
#[tokio::test]
async fn test_token_bridge_full_flow_lock_mint_burn_unlock() -> eyre::Result<()> {
    use alloy::sol_types::SolCall;
    use tempo_native_bridge::eip2537::g1_to_eip2537;

    tracing_subscriber::fmt()
        .with_env_filter("bridge_e2e=debug,tempo_native_bridge=debug")
        .try_init()
        .ok();

    // ========================================
    // Step 1: Generate DKG keys
    // ========================================
    let (sharing, shares, group_pubkey) = generate_test_dkg_keys();
    let threshold = sharing.required::<N3f1>();
    tracing::info!(threshold, n = shares.len(), "generated DKG keys");

    // ========================================
    // Step 2: Start nodes
    // ========================================
    let anvil = AnvilInstance::start().await?;
    let (tempo_http, _tempo_ws, _tasks) = start_tempo_node().await?;

    // Get chain IDs
    let anvil_provider = ProviderBuilder::new().connect_http(anvil.rpc_url.parse()?);
    let tempo_provider = ProviderBuilder::new().connect_http(tempo_http.parse()?);
    let ethereum_chain_id = anvil_provider.get_chain_id().await?;
    let tempo_chain_id = tempo_provider.get_chain_id().await?;
    tracing::info!(ethereum_chain_id, tempo_chain_id, "chain IDs");

    // ========================================
    // Step 3: Deploy bridge contracts
    // ========================================
    let eth_msg_bridge = deploy_bridge_with_pubkey_anvil(&anvil.rpc_url, &group_pubkey).await?;
    let tempo_msg_bridge = deploy_bridge_with_pubkey_tempo(&tempo_http, &group_pubkey).await?;

    let eth_token_bridge = deploy_token_bridge_anvil(&anvil.rpc_url, eth_msg_bridge).await?;
    let tempo_token_bridge = deploy_token_bridge_tempo(&tempo_http, tempo_msg_bridge).await?;

    // ========================================
    // Step 4: Deploy REAL tokens
    // ========================================
    // Deploy MockERC20 (USDC) on Ethereum
    let eth_usdc = deploy_mock_erc20_anvil(&anvil.rpc_url, "USD Coin", "USDC", 6).await?;

    // Create TIP-20 (USDC.t) on Tempo with ISSUER_ROLE granted to TokenBridge
    let tempo_usdc =
        create_tip20_tempo(&tempo_http, "Tempo USDC", "USDC.t", tempo_token_bridge).await?;

    // ========================================
    // Step 5: Setup providers with signers
    // ========================================
    let eth_signer: alloy::signers::local::PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let user = eth_signer.address();

    let eth_provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(eth_signer))
        .connect_http(anvil.rpc_url.parse()?);

    let tempo_wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let tempo_user = tempo_wallet.address();
    let tempo_provider_with_wallet = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(tempo_wallet))
        .connect_http(tempo_http.parse()?);

    // ========================================
    // Step 6: Compute asset ID and register assets
    // ========================================
    let asset_id = {
        use alloy::primitives::keccak256;
        let mut data = Vec::with_capacity(28);
        data.extend_from_slice(&ethereum_chain_id.to_be_bytes());
        data.extend_from_slice(eth_usdc.as_slice());
        keccak256(&data)
    };
    tracing::info!(%asset_id, eth_usdc = %eth_usdc, tempo_usdc = %tempo_usdc, "computed asset ID");

    // Register on Ethereum (home chain - lock/unlock)
    let register_eth = registerAssetCall {
        assetId: asset_id,
        homeChainId: ethereum_chain_id,
        homeToken: eth_usdc,
        localToken: eth_usdc,
        isHomeChain: true,
    };
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(eth_token_bridge)
        .input(register_eth.abi_encode().into());
    let receipt = eth_provider
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "register asset on Ethereum failed");
    tracing::info!("registered USDC on Ethereum TokenBridge (home chain)");

    // Register on Tempo (remote chain - mint/burn)
    let register_tempo = registerAssetCall {
        assetId: asset_id,
        homeChainId: ethereum_chain_id,
        homeToken: eth_usdc,
        localToken: tempo_usdc,
        isHomeChain: false,
    };
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(tempo_token_bridge)
        .input(register_tempo.abi_encode().into());
    let receipt = tempo_provider_with_wallet
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "register asset on Tempo failed");
    tracing::info!("registered USDC on Tempo TokenBridge (remote chain)");

    // ========================================
    // Step 7: Mint USDC to user and approve TokenBridge
    // ========================================
    let bridge_amount = U256::from(1_000_000u64); // 1 USDC (6 decimals)

    // Mint USDC to user
    let mint_call = mintCall {
        to: user,
        amount: bridge_amount,
    };
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(eth_usdc)
        .input(mint_call.abi_encode().into());
    let receipt = eth_provider
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "mint USDC failed");

    // Approve TokenBridge to spend user's USDC
    let approve_call = approveCall {
        spender: eth_token_bridge,
        amount: bridge_amount,
    };
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(eth_usdc)
        .input(approve_call.abi_encode().into());
    let receipt = eth_provider
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "approve failed");

    // Verify user balance before bridging
    let balance_call = balanceOfCall { account: user };
    let result = anvil_provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(eth_usdc)
                .input(balance_call.abi_encode().into()),
        )
        .await?;
    let user_balance_before = U256::from_be_slice(&result);
    assert_eq!(
        user_balance_before, bridge_amount,
        "user should have 1 USDC"
    );
    tracing::info!(%user_balance_before, "user USDC balance before bridging");

    // ========================================
    // PHASE 1: Lock USDC on Ethereum → Mint USDC.t on Tempo
    // ========================================
    tracing::info!("=== PHASE 1: Ethereum → Tempo (Lock → Mint) ===");

    // Step 8: Call bridgeTokens on Ethereum
    let bridge_call = bridgeTokensCall {
        assetId: asset_id,
        recipient: tempo_user,
        amount: bridge_amount,
        destinationChainId: tempo_chain_id,
    };
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(eth_token_bridge)
        .gas_limit(500_000)
        .input(bridge_call.abi_encode().into());
    let bridge_receipt = eth_provider
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(bridge_receipt.status(), "bridgeTokens failed");

    // Parse TokensBridged event to get messageHash and nonce
    let bridge_logs = bridge_receipt.inner.logs();
    let bridge_event = bridge_logs
        .iter()
        .find(|log| !log.topics().is_empty() && log.topics()[0] == TokensBridged::SIGNATURE_HASH)
        .ok_or_else(|| eyre::eyre!("TokensBridged event not found"))?;
    let message_hash = bridge_event.topics()[1];
    let transfer_nonce = U256::from_be_slice(bridge_event.topics()[3].as_slice());
    tracing::info!(%message_hash, %transfer_nonce, "bridgeTokens emitted TokensBridged");

    // Verify USDC is locked in TokenBridge
    let bridge_balance_call = balanceOfCall {
        account: eth_token_bridge,
    };
    let result = anvil_provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(eth_usdc)
                .input(bridge_balance_call.abi_encode().into()),
        )
        .await?;
    let bridge_balance = U256::from_be_slice(&result);
    assert_eq!(
        bridge_balance, bridge_amount,
        "TokenBridge should hold locked USDC"
    );
    tracing::info!(%bridge_balance, "USDC locked in Ethereum TokenBridge");

    // Verify user balance is now 0
    let user_balance_call = balanceOfCall { account: user };
    let result = anvil_provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(eth_usdc)
                .input(user_balance_call.abi_encode().into()),
        )
        .await?;
    let user_balance_after = U256::from_be_slice(&result);
    assert_eq!(
        user_balance_after,
        U256::ZERO,
        "user should have 0 USDC after bridging"
    );

    // Step 9: Sign attestation with threshold signers
    let message = Message::new(
        eth_token_bridge,
        message_hash,
        ethereum_chain_id,
        tempo_chain_id,
    );
    let attestation_hash = message.attestation_hash();
    tracing::info!(%attestation_hash, "signing attestation for lock");

    let mut aggregator = Aggregator::new(sharing.clone(), 1);
    let mut aggregated_result = None;
    for share in shares.iter().take(threshold as usize) {
        let signer = BLSSigner::new(share.clone());
        let partial = signer.sign_partial(attestation_hash)?;
        if let Some(result) = aggregator.add_partial(attestation_hash, partial, &message) {
            aggregated_result = Some(result);
        }
    }
    let (agg_sig, _) = aggregated_result.expect("threshold should be reached");
    let eip2537_sig = g1_to_eip2537(&agg_sig.signature)?;
    tracing::info!("threshold signature aggregated");

    // Step 10: Submit attestation to Tempo MessageBridge
    let write_call = writeCall {
        sender: eth_token_bridge,
        messageHash: message_hash,
        originChainId: ethereum_chain_id,
        signature: Bytes::from(eip2537_sig.to_vec()),
    };
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(tempo_msg_bridge)
        .input(write_call.abi_encode().into());
    let write_receipt = tempo_provider_with_wallet
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(write_receipt.status(), "write attestation failed");
    tracing::info!("attestation submitted to Tempo MessageBridge");

    // Step 11: Claim tokens on Tempo (mints USDC.t)
    let claim_call = claimTokensCall {
        assetId: asset_id,
        recipient: tempo_user,
        amount: bridge_amount,
        transferNonce: transfer_nonce,
        originChainId: ethereum_chain_id,
    };
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(tempo_token_bridge)
        .gas_limit(5_000_000)
        .input(claim_call.abi_encode().into());
    let claim_receipt = tempo_provider_with_wallet
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(claim_receipt.status(), "claimTokens failed");
    tracing::info!("tokens claimed on Tempo - USDC.t minted");

    // Verify tempo_user received USDC.t
    let tempo_balance_call = balanceOfCall {
        account: tempo_user,
    };
    let result = tempo_provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(tempo_usdc)
                .input(tempo_balance_call.abi_encode().into()),
        )
        .await?;
    let tempo_user_balance = U256::from_be_slice(&result);
    assert_eq!(
        tempo_user_balance, bridge_amount,
        "tempo user should have USDC.t"
    );
    tracing::info!(%tempo_user_balance, "✓ USDC.t minted to tempo user");

    // ========================================
    // PHASE 2: Burn USDC.t on Tempo → Unlock USDC on Ethereum
    // ========================================
    tracing::info!("=== PHASE 2: Tempo → Ethereum (Burn → Unlock) ===");

    // Step 12: Approve TokenBridge to transfer USDC.t
    let approve_tempo_call = approveCall {
        spender: tempo_token_bridge,
        amount: bridge_amount,
    };
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(tempo_usdc)
        .gas_limit(1_000_000)
        .input(approve_tempo_call.abi_encode().into());
    let receipt = tempo_provider_with_wallet
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "approve USDC.t failed");

    // Step 13: Call bridgeTokens on Tempo (burns USDC.t)
    let bridge_back_call = bridgeTokensCall {
        assetId: asset_id,
        recipient: user, // Send back to original Ethereum user
        amount: bridge_amount,
        destinationChainId: ethereum_chain_id,
    };
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(tempo_token_bridge)
        .gas_limit(5_000_000)
        .input(bridge_back_call.abi_encode().into());
    let bridge_back_receipt = tempo_provider_with_wallet
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(bridge_back_receipt.status(), "bridgeTokens on Tempo failed");

    // Parse TokensBridged event
    let bridge_back_logs = bridge_back_receipt.inner.logs();
    let bridge_back_event = bridge_back_logs
        .iter()
        .find(|log| !log.topics().is_empty() && log.topics()[0] == TokensBridged::SIGNATURE_HASH)
        .ok_or_else(|| eyre::eyre!("TokensBridged event not found on Tempo"))?;
    let burn_message_hash = bridge_back_event.topics()[1];
    let burn_nonce = U256::from_be_slice(bridge_back_event.topics()[3].as_slice());
    tracing::info!(%burn_message_hash, %burn_nonce, "USDC.t burned, TokensBridged emitted");

    // Verify USDC.t was burned (user balance should be 0)
    let result = tempo_provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(tempo_usdc)
                .input(tempo_balance_call.abi_encode().into()),
        )
        .await?;
    let tempo_user_balance_after = U256::from_be_slice(&result);
    assert_eq!(
        tempo_user_balance_after,
        U256::ZERO,
        "USDC.t should be burned"
    );
    tracing::info!("✓ USDC.t burned from tempo user");

    // Step 14: Sign attestation for burn
    let burn_message = Message::new(
        tempo_token_bridge,
        burn_message_hash,
        tempo_chain_id,
        ethereum_chain_id,
    );
    let burn_attestation_hash = burn_message.attestation_hash();

    let mut aggregator2 = Aggregator::new(sharing.clone(), 1);
    let mut aggregated_result2 = None;
    for share in shares.iter().take(threshold as usize) {
        let signer = BLSSigner::new(share.clone());
        let partial = signer.sign_partial(burn_attestation_hash)?;
        if let Some(result) = aggregator2.add_partial(burn_attestation_hash, partial, &burn_message)
        {
            aggregated_result2 = Some(result);
        }
    }
    let (agg_sig2, _) = aggregated_result2.expect("threshold should be reached for burn");
    let eip2537_sig2 = g1_to_eip2537(&agg_sig2.signature)?;
    tracing::info!("threshold signature aggregated for burn");

    // Step 15: Submit attestation to Ethereum MessageBridge
    let write_call2 = writeCall {
        sender: tempo_token_bridge,
        messageHash: burn_message_hash,
        originChainId: tempo_chain_id,
        signature: Bytes::from(eip2537_sig2.to_vec()),
    };
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(eth_msg_bridge)
        .input(write_call2.abi_encode().into());
    let write_receipt2 = eth_provider
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(write_receipt2.status(), "write burn attestation failed");
    tracing::info!("burn attestation submitted to Ethereum MessageBridge");

    // Step 16: Claim tokens on Ethereum (unlocks USDC)
    let claim_back_call = claimTokensCall {
        assetId: asset_id,
        recipient: user,
        amount: bridge_amount,
        transferNonce: burn_nonce,
        originChainId: tempo_chain_id,
    };
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(eth_token_bridge)
        .gas_limit(500_000)
        .input(claim_back_call.abi_encode().into());
    let claim_back_receipt = eth_provider
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(
        claim_back_receipt.status(),
        "claimTokens on Ethereum failed"
    );
    tracing::info!("tokens claimed on Ethereum - USDC unlocked");

    // Verify user received USDC back
    let result = anvil_provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(eth_usdc)
                .input(user_balance_call.abi_encode().into()),
        )
        .await?;
    let user_final_balance = U256::from_be_slice(&result);
    assert_eq!(
        user_final_balance, bridge_amount,
        "user should have USDC back"
    );
    tracing::info!(%user_final_balance, "✓ USDC unlocked to user");

    // Verify TokenBridge escrow is now empty
    let result = anvil_provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(eth_usdc)
                .input(bridge_balance_call.abi_encode().into()),
        )
        .await?;
    let bridge_final_balance = U256::from_be_slice(&result);
    assert_eq!(
        bridge_final_balance,
        U256::ZERO,
        "TokenBridge escrow should be empty"
    );

    tracing::info!("🎉 TokenBridge full flow test passed!");
    tracing::info!("  ✓ Ethereum → Tempo: 1 USDC locked, 1 USDC.t minted");
    tracing::info!("  ✓ Tempo → Ethereum: 1 USDC.t burned, 1 USDC unlocked");

    Ok(())
}
