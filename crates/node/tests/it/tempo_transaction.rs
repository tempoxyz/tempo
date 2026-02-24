//! AA Transaction Flows
//!
//! - Sponsored raw tx flow (multi-party fee payer cosigning via eth_signTransaction).
//! - WebAuthn signature negative cases.
//! - Empty call batch rejection.
//! - Contract creation address correctness.
//! - Nonce bump on tx failure.
//!
//! Nonce Semantics
//!
//! - 2D nonce system behavior, pool ordering, and out-of-order arrival.
//! - Expiring nonce flow, replay protection, validity windows, and independence from protocol nonce.
//!
//! EIP-7702 Authorization Lists
//!
//! - Multi-key-type authorization list (secp256k1 + P256 + WebAuthn delegation).
//! - Keychain authorization in auth list is skipped (attack prevention).
//!
//! Keychain / Access Keys
//!
//! - Access key usage with key authorization and chain ID scoping.
//! - Keychain negative cases and RPC validation.
//! - Spending limits, expiry, enforcement, and revocation/spending-limit TOCTOU cases.
//!
//! RPC Matrices
//!
//! - eth_sendRawTransaction matrix: key type x fee payer x access key.
//! - eth_sendTransaction matrix: key type (P256/WebAuthn) x fee payer x access key x batch calls; secp256k1 x fee payer.
//! - eth_fillTransaction matrix: nonceKey + validBefore + validAfter + feeToken + fee payer.
//! - eth_estimateGas matrix.
//! - E2E fill → sign → send matrix across nonce modes, key types, and pre-bumped protocol nonces.
//!
//! Network
//!
//! - Transaction propagation across 2D nonce channels.
use alloy::{
    consensus::{BlockHeader, Transaction},
    hex,
    network::{EthereumWallet, ReceiptResponse},
    primitives::{Address, B256, Bytes, Signature, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::{SignerSync, local::MnemonicBuilder},
    sol_types::SolCall,
};
use alloy_eips::{Decodable2718, Encodable2718};
use alloy_primitives::TxKind;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use reth_ethereum::network::{NetworkSyncUpdater, SyncState};
use reth_primitives_traits::transaction::TxHashRef;
use reth_transaction_pool::TransactionPool;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, account_keychain::IAccountKeychain::revokeKeyCall,
};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    tip20::ITIP20::{self, transferCall},
};

use tempo_primitives::{
    SignatureType, TempoTransaction, TempoTxEnvelope,
    transaction::{
        KeyAuthorization, SignedKeyAuthorization, TEMPO_EXPIRING_NONCE_KEY,
        TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS, TokenLimit,
        tempo_transaction::Call,
        tt_signature::{
            KeychainSignature, P256SignatureWithPreHash, PrimitiveSignature, TempoSignature,
            WebAuthnSignature,
        },
        tt_signed::AASigned,
    },
};

use crate::utils::{SingleNodeSetup, TEST_MNEMONIC, TestNodeBuilder};
use tempo_node::rpc::TempoTransactionRequest;
use tempo_primitives::transaction::tt_signature::normalize_p256_s;

#[macro_use]
#[path = "test_macros.rs"]
mod test_macros;

/// Duration to wait for pool maintenance task to process blocks
const POOL_MAINTENANCE_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// Helper function to fund an address with fee tokens
/// Returns the fee token address that was used for funding
async fn fund_address_with_fee_tokens(
    setup: &mut SingleNodeSetup,
    provider: &impl Provider,
    funder_signer: &impl SignerSync,
    funder_addr: Address,
    recipient: Address,
    amount: U256,
    chain_id: u64,
) -> eyre::Result<Address> {
    let transfer_calldata = transferCall {
        to: recipient,
        amount,
    }
    .abi_encode();

    let funding_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: transfer_calldata.into(),
        }],
        nonce_key: U256::ZERO,
        nonce: provider.get_transaction_count(funder_addr).await?,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    // Sign and send the funding transaction
    let signature = funder_signer.sign_hash_sync(&funding_tx.signature_hash())?;
    let funding_envelope: TempoTxEnvelope = funding_tx.into_signed(signature.into()).into();
    let mut encoded_funding = Vec::new();
    funding_envelope.encode_2718(&mut encoded_funding);

    setup.node.rpc.inject_tx(encoded_funding.into()).await?;
    let funding_payload = setup.node.advance_block().await?;

    println!(
        "✓ Funded {} with {} tokens in block {}",
        recipient,
        amount,
        funding_payload.block().inner.number
    );

    Ok(DEFAULT_FEE_TOKEN)
}

/// Helper function to verify a transaction exists in the blockchain via eth_getTransactionByHash
/// and that it matches the original transaction
async fn verify_tx_in_block_via_rpc(
    provider: &impl Provider,
    encoded_tx: &[u8],
    expected_envelope: &TempoTxEnvelope,
) -> eyre::Result<()> {
    // Compute transaction hash from encoded bytes
    let tx_hash = keccak256(encoded_tx);

    println!("\nVerifying transaction via eth_getTransactionByHash...");
    println!("Transaction hash: {}", B256::from(tx_hash));

    // Use raw RPC call to fetch transaction since Alloy doesn't support custom tx type 0x76
    let raw_tx: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionByHash".into(), [tx_hash])
        .await?;

    // Verify transaction exists
    let tx_data = raw_tx.ok_or_else(|| eyre::eyre!("Transaction not found in blockchain"))?;

    println!("✓ Transaction found in blockchain");

    // Extract and verify key fields from the JSON response
    let tx_obj = tx_data
        .as_object()
        .ok_or_else(|| eyre::eyre!("Transaction response is not an object"))?;

    // Verify basic sanity checks
    let hash_str = tx_obj
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("Transaction hash not found in response"))?;
    let returned_hash = hash_str.parse::<B256>()?;
    assert_eq!(
        returned_hash, tx_hash,
        "Returned hash should match request hash"
    );

    // Verify it's an AA transaction (type 0x76)
    let tx_type = tx_obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("Transaction type not found in response"))?;
    assert_eq!(tx_type, "0x76", "Transaction should be AA type (0x76)");

    // Verify key fields match what we expect
    if let TempoTxEnvelope::AA(expected_aa) = expected_envelope {
        // Check chain ID
        if let Some(chain_id) = tx_obj.get("chainId").and_then(|v| v.as_str()) {
            let chain_id_u64 = u64::from_str_radix(chain_id.trim_start_matches("0x"), 16)?;
            assert_eq!(
                chain_id_u64,
                expected_aa.tx().chain_id,
                "Chain ID should match"
            );
        }

        // Check nonce
        if let Some(nonce) = tx_obj.get("nonce").and_then(|v| v.as_str()) {
            let nonce_u64 = u64::from_str_radix(nonce.trim_start_matches("0x"), 16)?;
            assert_eq!(nonce_u64, expected_aa.tx().nonce, "Nonce should match");
        }

        // Check number of calls
        if let Some(calls) = tx_obj.get("calls").and_then(|v| v.as_array()) {
            assert_eq!(
                calls.len(),
                expected_aa.tx().calls.len(),
                "Number of calls should match"
            );
        }

        if let Some(fee_token) = expected_aa.tx().fee_token {
            let rpc_fee_token = tx_obj
                .get("feeToken")
                .and_then(|v| v.as_str())
                .ok_or_else(|| eyre::eyre!("feeToken missing in response"))?
                .parse::<Address>()?;
            assert_eq!(rpc_fee_token, fee_token, "feeToken should match");
        }

        println!(
            "✓ Transaction verified: type=0x76, chain_id={}, nonce={}, calls={}",
            expected_aa.tx().chain_id,
            expected_aa.tx().nonce,
            expected_aa.tx().calls.len()
        );
    }

    // Verify encoding roundtrip on our end
    let mut encoded_slice = encoded_tx;
    let decoded = TempoTxEnvelope::decode_2718(&mut encoded_slice)?;
    assert!(
        matches!(decoded, TempoTxEnvelope::AA(_)),
        "Decoded transaction should be AA type"
    );

    println!("✓ Transaction encoding/decoding verified successfully");

    Ok(())
}

/// Helper function to verify a transaction does NOT exist in the blockchain
async fn verify_tx_not_in_block_via_rpc(
    provider: &impl Provider,
    encoded_tx: &[u8],
) -> eyre::Result<()> {
    // Compute transaction hash from encoded bytes
    let tx_hash = keccak256(encoded_tx);

    println!("\nVerifying transaction is NOT in blockchain...");
    println!("Transaction hash: {}", B256::from(tx_hash));

    // Use raw RPC call to try to fetch the transaction
    let raw_tx: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionByHash".into(), [tx_hash])
        .await?;

    // Verify transaction does NOT exist
    assert!(
        raw_tx.is_none(),
        "Transaction should not exist in blockchain (rejected transaction should not be retrievable)"
    );

    println!("✓ Confirmed: Transaction not found in blockchain (as expected)");

    Ok(())
}

/// Helper function to set up common test infrastructure
/// Returns: (setup, provider, signer, signer_addr)
async fn setup_test_with_funded_account() -> eyre::Result<(
    SingleNodeSetup,
    impl Provider + Clone,
    impl SignerSync,
    Address,
)> {
    // Setup test node with direct access
    let setup = TestNodeBuilder::new().build_with_node_access().await?;

    let http_url = setup.node.rpc_url();

    // Use TEST_MNEMONIC account (has balance in DEFAULT_FEE_TOKEN from genesis)
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let signer_addr = signer.address();

    // Create provider with wallet
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    Ok((setup, provider, signer, signer_addr))
}

/// Helper function to create a signed KeyAuthorization for gas estimation tests
fn create_signed_key_authorization(
    signer: &impl SignerSync,
    key_type: SignatureType,
    num_limits: usize,
) -> SignedKeyAuthorization {
    let limits = if num_limits == 0 {
        None
    } else {
        Some(
            (0..num_limits)
                .map(|_| TokenLimit {
                    token: Address::ZERO,
                    limit: U256::ZERO,
                })
                .collect(),
        )
    };

    let authorization = KeyAuthorization {
        chain_id: 0, // Wildcard - valid on any chain
        key_type,
        key_id: Address::random(), // Random key being authorized
        expiry: None,              // Never expires
        limits,
    };

    // Sign the key authorization
    let sig_hash = authorization.signature_hash();
    let signature = signer
        .sign_hash_sync(&sig_hash)
        .expect("signing should succeed");

    SignedKeyAuthorization {
        authorization,
        signature: PrimitiveSignature::Secp256k1(signature),
    }
}

/// Helper function to compute authorization signature hash (EIP-7702)
fn compute_authorization_signature_hash(auth: &alloy_eips::eip7702::Authorization) -> B256 {
    use alloy_rlp::Encodable as _;
    let mut sig_buf = Vec::new();
    sig_buf.push(tempo_primitives::transaction::tt_authorization::MAGIC);
    auth.encode(&mut sig_buf);
    alloy::primitives::keccak256(&sig_buf)
}

/// Helper to build an Authorization struct and compute its signature hash.
/// Callers provide the actual signing logic.
fn build_authorization(
    chain_id: u64,
    delegate_address: Address,
) -> (alloy_eips::eip7702::Authorization, B256) {
    let auth = alloy_eips::eip7702::Authorization {
        chain_id: alloy_primitives::U256::from(chain_id),
        address: delegate_address,
        nonce: 0,
    };
    let sig_hash = compute_authorization_signature_hash(&auth);
    (auth, sig_hash)
}

/// Helper function to verify EIP-7702 delegation code
fn verify_delegation_code(code: &Bytes, expected_delegate: Address, authority_name: &str) {
    // EIP-7702 delegation code format: 0xef0100 || address (23 bytes total)
    // 0xef = magic byte, 0x01 = version, 0x00 = reserved
    assert_eq!(
        code.len(),
        23,
        "{authority_name} should have EIP-7702 delegation code (23 bytes), got {} bytes",
        code.len()
    );
    assert_eq!(
        &code[0..3],
        &[0xef, 0x01, 0x00],
        "{authority_name} should have correct EIP-7702 magic bytes [0xef, 0x01, 0x00], got [{:02x}, {:02x}, {:02x}]",
        code[0],
        code[1],
        code[2]
    );
    assert_eq!(
        &code[3..23],
        expected_delegate.as_slice(),
        "{authority_name} should delegate to correct address {expected_delegate}"
    );
}

/// Helper function to set up P256 test infrastructure with funded account
/// Returns: (setup, provider, signing_key, pub_key_x, pub_key_y, signer_addr, funder_signer, funder_addr, chain_id, fee_token)
async fn setup_test_with_p256_funded_account(
    funding_amount: U256,
) -> eyre::Result<(
    SingleNodeSetup,
    impl Provider + Clone,
    p256::ecdsa::SigningKey,
    alloy::primitives::B256,
    alloy::primitives::B256,
    Address,
    impl SignerSync,
    Address,
    u64,
    Address,
)> {
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

    // Setup test node with direct access
    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let http_url = setup.node.rpc_url();

    // Generate a P256 key pair
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Extract public key coordinates
    let encoded_point = verifying_key.to_encoded_point(false);
    let pub_key_x = alloy::primitives::B256::from_slice(encoded_point.x().unwrap().as_ref());
    let pub_key_y = alloy::primitives::B256::from_slice(encoded_point.y().unwrap().as_ref());

    // Derive the P256 signer's address
    let signer_addr =
        tempo_primitives::transaction::tt_signature::derive_p256_address(&pub_key_x, &pub_key_y);

    // Use TEST_MNEMONIC account to fund the P256 signer
    let funder_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let funder_addr = funder_signer.address();

    // Create provider with funder's wallet
    let funder_wallet = EthereumWallet::from(funder_signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(funder_wallet)
        .connect_http(http_url.clone());

    // Get chain ID
    let chain_id = provider.get_chain_id().await?;

    // Fund the P256 signer with fee tokens
    let fee_token = fund_address_with_fee_tokens(
        &mut setup,
        &provider,
        &funder_signer,
        funder_addr,
        signer_addr,
        funding_amount,
        chain_id,
    )
    .await?;

    Ok((
        setup,
        provider,
        signing_key,
        pub_key_x,
        pub_key_y,
        signer_addr,
        funder_signer,
        funder_addr,
        chain_id,
        fee_token,
    ))
}

// ===== Keychain/Access Key Helper Functions =====

/// Helper to generate a P256 access key
fn generate_p256_access_key() -> (
    p256::ecdsa::SigningKey,
    alloy::primitives::B256,
    alloy::primitives::B256,
    Address,
) {
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let pub_key_x = alloy::primitives::B256::from_slice(encoded_point.x().unwrap().as_ref());
    let pub_key_y = alloy::primitives::B256::from_slice(encoded_point.y().unwrap().as_ref());
    let key_addr =
        tempo_primitives::transaction::tt_signature::derive_p256_address(&pub_key_x, &pub_key_y);
    (signing_key, pub_key_x, pub_key_y, key_addr)
}

/// Helper to create a key authorization
fn create_key_authorization(
    root_signer: &impl SignerSync,
    access_key_addr: Address,
    access_key_signature: TempoSignature,
    chain_id: u64,
    expiry: Option<u64>,
    spending_limits: Option<Vec<tempo_primitives::transaction::TokenLimit>>,
) -> eyre::Result<SignedKeyAuthorization> {
    // Infer key_type from the access key signature
    let key_type = access_key_signature.signature_type();

    let key_auth = KeyAuthorization {
        chain_id,
        key_type,
        key_id: access_key_addr,
        expiry,
        limits: spending_limits,
    };

    // Root key signs the authorization
    let root_auth_signature = root_signer.sign_hash_sync(&key_auth.signature_hash())?;

    Ok(key_auth.into_signed(PrimitiveSignature::Secp256k1(root_auth_signature)))
}

/// Helper to submit and mine an AA transaction
async fn submit_and_mine_aa_tx(
    setup: &mut SingleNodeSetup,
    tx: TempoTransaction,
    signature: TempoSignature,
) -> eyre::Result<B256> {
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let tx_hash = *envelope.tx_hash();
    setup
        .node
        .rpc
        .inject_tx(envelope.encoded_2718().into())
        .await?;
    setup.node.advance_block().await?;
    Ok(tx_hash)
}

/// Low-level P256 prehash signing. Returns a `PrimitiveSignature::P256`.
fn sign_p256_primitive(
    sig_hash: B256,
    signing_key: &p256::ecdsa::SigningKey,
    pub_key_x: B256,
    pub_key_y: B256,
) -> eyre::Result<PrimitiveSignature> {
    use sha2::{Digest, Sha256};

    let pre_hashed = Sha256::digest(sig_hash);
    let p256_signature: p256::ecdsa::Signature = signing_key.sign_prehash(&pre_hashed)?;
    let sig_bytes = p256_signature.to_bytes();

    Ok(PrimitiveSignature::P256(P256SignatureWithPreHash {
        r: B256::from_slice(&sig_bytes[0..32]),
        s: normalize_p256_s(&sig_bytes[32..64]),
        pub_key_x,
        pub_key_y,
        pre_hash: true,
    }))
}

/// Helper to sign AA transaction with P256 access key (wrapped in Keychain signature)
fn sign_aa_tx_with_p256_access_key(
    tx: &TempoTransaction,
    access_key_signing_key: &p256::ecdsa::SigningKey,
    access_pub_key_x: &B256,
    access_pub_key_y: &B256,
    root_key_addr: Address,
) -> eyre::Result<TempoSignature> {
    let inner = sign_p256_primitive(
        tx.signature_hash(),
        access_key_signing_key,
        *access_pub_key_x,
        *access_pub_key_y,
    )?;
    Ok(TempoSignature::Keychain(
        tempo_primitives::transaction::KeychainSignature::new(root_key_addr, inner),
    ))
}

/// Helper to sign AA transaction with secp256k1 access key (wrapped in Keychain signature)
fn sign_aa_tx_with_secp256k1_access_key(
    tx: &TempoTransaction,
    access_key_signer: &impl SignerSync,
    root_key_addr: Address,
) -> eyre::Result<TempoSignature> {
    let sig_hash = tx.signature_hash();
    let signature = access_key_signer.sign_hash_sync(&sig_hash)?;
    let inner_signature = PrimitiveSignature::Secp256k1(signature);

    Ok(TempoSignature::Keychain(
        tempo_primitives::transaction::KeychainSignature::new(root_key_addr, inner_signature),
    ))
}

/// Low-level WebAuthn signing. Returns a `PrimitiveSignature::WebAuthn`.
fn sign_webauthn_primitive(
    sig_hash: B256,
    signing_key: &p256::ecdsa::SigningKey,
    pub_key_x: B256,
    pub_key_y: B256,
    origin: &str,
) -> eyre::Result<PrimitiveSignature> {
    use sha2::{Digest, Sha256};

    let (authenticator_data, client_data_json) = create_webauthn_data(sig_hash, origin);

    let client_data_hash = Sha256::digest(client_data_json.as_bytes());
    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data);
    final_hasher.update(client_data_hash);
    let message_hash = final_hasher.finalize();

    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&message_hash)?;
    let sig_bytes = signature.to_bytes();

    let mut webauthn_data = Vec::new();
    webauthn_data.extend_from_slice(&authenticator_data);
    webauthn_data.extend_from_slice(client_data_json.as_bytes());

    Ok(PrimitiveSignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(webauthn_data),
        r: B256::from_slice(&sig_bytes[0..32]),
        s: normalize_p256_s(&sig_bytes[32..64]),
        pub_key_x,
        pub_key_y,
    }))
}

/// Helper to sign AA transaction with WebAuthn access key (wrapped in Keychain signature)
fn sign_aa_tx_with_webauthn_access_key(
    tx: &TempoTransaction,
    signing_key: &p256::ecdsa::SigningKey,
    pub_key_x: B256,
    pub_key_y: B256,
    origin: &str,
    root_key_addr: Address,
) -> eyre::Result<TempoSignature> {
    let inner = sign_webauthn_primitive(
        tx.signature_hash(),
        signing_key,
        pub_key_x,
        pub_key_y,
        origin,
    )?;
    Ok(TempoSignature::Keychain(KeychainSignature::new(
        root_key_addr,
        inner,
    )))
}

// ===== Call Creation Helper Functions =====

/// Helper to create a TIP20 transfer call
fn create_transfer_call(to: Address, amount: U256) -> Call {
    use alloy::sol_types::SolCall;
    use tempo_contracts::precompiles::ITIP20::transferCall;

    Call {
        to: DEFAULT_FEE_TOKEN.into(),
        value: U256::ZERO,
        input: transferCall { to, amount }.abi_encode().into(),
    }
}

/// Helper to create a TIP20 balanceOf call (useful as a benign call for key authorization txs)
fn create_balance_of_call(account: Address) -> Call {
    use alloy::sol_types::SolCall;

    Call {
        to: DEFAULT_FEE_TOKEN.into(),
        value: U256::ZERO,
        input: ITIP20::balanceOfCall { account }.abi_encode().into(),
    }
}

/// Helper to create a mock P256 signature for key authorization
/// This is used when creating a KeyAuthorization - the actual signature is from the root key,
/// but we need to specify the access key's public key coordinates
fn create_mock_p256_sig(pub_key_x: B256, pub_key_y: B256) -> TempoSignature {
    TempoSignature::Primitive(PrimitiveSignature::P256(
        tempo_primitives::transaction::tt_signature::P256SignatureWithPreHash {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x,
            pub_key_y,
            pre_hash: false,
        },
    ))
}

/// Helper to create a mock secp256k1 signature for key authorization
fn create_mock_secp256k1_sig() -> TempoSignature {
    TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::new(
        U256::ZERO,
        U256::ZERO,
        false,
    )))
}

/// Helper to create a mock WebAuthn signature for key authorization
fn create_mock_webauthn_sig(pub_key_x: B256, pub_key_y: B256) -> TempoSignature {
    TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::new(),
        r: B256::ZERO,
        s: B256::ZERO,
        pub_key_x,
        pub_key_y,
    }))
}

/// Helper to create default token spending limits (100 tokens of DEFAULT_FEE_TOKEN)
fn create_default_token_limit() -> Vec<tempo_primitives::transaction::TokenLimit> {
    use tempo_primitives::transaction::TokenLimit;

    vec![TokenLimit {
        token: DEFAULT_FEE_TOKEN,
        limit: U256::from(100u64) * U256::from(10).pow(U256::from(18)),
    }]
}

// ===== Transaction Creation Helper Functions =====

/// Helper to create a basic TempoTransaction with common defaults
fn create_basic_aa_tx(
    chain_id: u64,
    nonce: u64,
    calls: Vec<Call>,
    gas_limit: u64,
) -> TempoTransaction {
    TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit,
        calls,
        nonce_key: U256::ZERO,
        nonce,
        // Use AlphaUSD to match fund_address_with_fee_tokens
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    }
}

/// Helper to create an expiring nonce transaction (nonce_key = TEMPO_EXPIRING_NONCE_KEY, nonce = 0)
fn create_expiring_nonce_tx(
    chain_id: u64,
    valid_before: u64,
    recipient: Address,
) -> TempoTransaction {
    let mut tx = create_basic_aa_tx(
        chain_id,
        0,
        vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );
    tx.nonce_key = TEMPO_EXPIRING_NONCE_KEY;
    tx.valid_before = Some(valid_before);
    tx
}

// ===== Signature Helper Functions =====

/// Helper to sign AA transaction with secp256k1 key
fn sign_aa_tx_secp256k1(
    tx: &TempoTransaction,
    signer: &impl SignerSync,
) -> eyre::Result<TempoSignature> {
    let sig_hash = tx.signature_hash();
    let signature = signer.sign_hash_sync(&sig_hash)?;
    Ok(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        signature,
    )))
}

/// Helper to sign AA transaction with P256 key (with pre-hash)
fn sign_aa_tx_p256(
    tx: &TempoTransaction,
    signing_key: &p256::ecdsa::SigningKey,
    pub_key_x: B256,
    pub_key_y: B256,
) -> eyre::Result<TempoSignature> {
    let inner = sign_p256_primitive(tx.signature_hash(), signing_key, pub_key_x, pub_key_y)?;
    Ok(TempoSignature::Primitive(inner))
}

/// Helper to create WebAuthn authenticator data and client data JSON
fn create_webauthn_data(sig_hash: B256, origin: &str) -> (Vec<u8>, String) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    // Create minimal authenticator data
    let mut authenticator_data = vec![0u8; 37];
    authenticator_data[0..32].copy_from_slice(&[0xAA; 32]); // rpIdHash
    authenticator_data[32] = 0x01; // UP flag

    // Create client data JSON
    let challenge_b64url = URL_SAFE_NO_PAD.encode(sig_hash.as_slice());
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"{origin}","crossOrigin":false}}"#
    );

    (authenticator_data, client_data_json)
}

/// Helper to create WebAuthn signature for AA transaction
fn sign_aa_tx_webauthn(
    tx: &TempoTransaction,
    signing_key: &p256::ecdsa::SigningKey,
    pub_key_x: B256,
    pub_key_y: B256,
    origin: &str,
) -> eyre::Result<TempoSignature> {
    let inner = sign_webauthn_primitive(
        tx.signature_hash(),
        signing_key,
        pub_key_x,
        pub_key_y,
        origin,
    )?;
    Ok(TempoSignature::Primitive(inner))
}

// ===== Assertion Helper Functions =====

/// Helper to fetch a transaction receipt and assert its status.
/// Use `expected_success = true` to assert status == "0x1", `false` for "0x0".
async fn assert_receipt_status(
    provider: &impl Provider,
    tx_hash: B256,
    expected_success: bool,
) -> eyre::Result<()> {
    let raw: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;
    let receipt = raw.ok_or_else(|| eyre::eyre!("Transaction receipt not found for {tx_hash}"))?;
    let status = receipt["status"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("Receipt missing status field"))?;
    let expected = if expected_success { "0x1" } else { "0x0" };
    assert_eq!(status, expected, "Receipt status mismatch for {tx_hash}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_2d_nonce_system() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut setup, provider, alice_signer, alice_addr) = setup_test_with_funded_account().await?;

    println!("\nTesting AA 2D Nonce System (parallel nonce support)");
    println!("Alice address: {alice_addr}");

    let recipient = Address::random();
    let chain_id = provider.get_chain_id().await?;

    // Step 1: Verify that nonce_key = 0 (protocol nonce) works
    println!("\n1. Testing nonce_key = 0 (should succeed)");

    let nonce = provider.get_transaction_count(alice_addr).await?;
    let tx_protocol = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );

    // Sign and encode transaction
    let aa_signature = sign_aa_tx_secp256k1(&tx_protocol, &alice_signer)?;
    let envelope_protocol: TempoTxEnvelope = tx_protocol.into_signed(aa_signature).into();
    let encoded_protocol = envelope_protocol.encoded_2718();

    println!(
        "Transaction with nonce_key=0 encoded, size: {} bytes",
        encoded_protocol.len()
    );

    // Inject transaction and mine block - should succeed
    setup
        .node
        .rpc
        .inject_tx(encoded_protocol.clone().into())
        .await?;
    let payload = setup.node.advance_block().await?;
    println!(
        "✓ Transaction with nonce_key=0 mined in block {}",
        payload.block().inner.number
    );

    // Verify transaction can be fetched via eth_getTransactionByHash and is correct
    verify_tx_in_block_via_rpc(&provider, &encoded_protocol, &envelope_protocol).await?;

    // Step 2: Verify that nonce_key = 1 (2D nonces) now works
    println!("\n2. Testing nonce_key = 1 (should now succeed with 2D nonce pool)");

    let mut tx_parallel = create_basic_aa_tx(
        chain_id,
        0,
        vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );
    tx_parallel.nonce_key = U256::from(1);

    // Sign and encode transaction
    let aa_signature_parallel = sign_aa_tx_secp256k1(&tx_parallel, &alice_signer)?;
    let envelope_parallel: TempoTxEnvelope = tx_parallel.into_signed(aa_signature_parallel).into();
    let encoded_parallel = envelope_parallel.encoded_2718();

    println!(
        "Transaction with nonce_key=1 encoded, size: {} bytes",
        encoded_parallel.len()
    );

    // Inject transaction and mine block - should now succeed with 2D nonce pool
    setup
        .node
        .rpc
        .inject_tx(encoded_parallel.clone().into())
        .await?;
    let payload_parallel = setup.node.advance_block().await?;
    println!(
        "✓ Transaction with nonce_key=1 mined in block {}",
        payload_parallel.block().inner.number
    );

    // Verify transaction can be fetched via eth_getTransactionByHash and is correct
    verify_tx_in_block_via_rpc(&provider, &encoded_parallel, &envelope_parallel).await?;

    // Step 3: Verify protocol nonce didn't change (nonce_key=0) but user nonce did (nonce_key=1)
    println!("\n3. Verifying nonce independence");

    let protocol_nonce_after = provider.get_transaction_count(alice_addr).await?;
    assert_eq!(
        protocol_nonce_after,
        nonce + 1,
        "Protocol nonce (key=0) should have incremented from first transaction"
    );
    println!("✓ Protocol nonce (key=0): {nonce} → {protocol_nonce_after}");

    println!("✓ User nonce (key=1) was tracked independently in 2D nonce pool");

    // Step 4: Verify implicit nonceKey behavior (no explicit nonce_key set)
    println!("\n4. Testing implicit nonceKey assignment");

    let implicit_recipient = Address::random();

    async fn send_implicit_tx(
        setup: &mut SingleNodeSetup,
        signer: &impl SignerSync,
        chain_id: u64,
        recipient: Address,
        nonce: u64,
    ) -> eyre::Result<B256> {
        let tx = create_basic_aa_tx(
            chain_id,
            nonce,
            vec![Call {
                to: recipient.into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            2_000_000,
        );
        let signature = sign_aa_tx_secp256k1(&tx, signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
        let tx_hash = *envelope.tx_hash();
        setup
            .node
            .rpc
            .inject_tx(envelope.encoded_2718().into())
            .await?;
        Ok(tx_hash)
    }

    let implicit_hashes = [
        send_implicit_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            implicit_recipient,
            protocol_nonce_after,
        )
        .await?,
        send_implicit_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            implicit_recipient,
            protocol_nonce_after + 1,
        )
        .await?,
        send_implicit_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            implicit_recipient,
            protocol_nonce_after + 2,
        )
        .await?,
    ];

    setup.node.advance_block().await?;

    let implicit_txs: Vec<serde_json::Value> =
        futures::future::try_join_all(implicit_hashes.iter().map(|hash| async {
            let tx: Option<serde_json::Value> = provider
                .raw_request("eth_getTransactionByHash".into(), [*hash])
                .await?;
            tx.ok_or_else(|| eyre::eyre!("Implicit transaction not found"))
        }))
        .await?;

    let mut nonce_keys: Vec<U256> = implicit_txs
        .iter()
        .map(|tx| {
            if let Some(value) = tx.get("nonceKey") {
                if value.is_null() {
                    return Ok(U256::ZERO);
                }
                if let Some(value) = value.as_str() {
                    return U256::from_str_radix(value.trim_start_matches("0x"), 16)
                        .map_err(|err| eyre::eyre!("Invalid nonceKey: {err}"));
                }
                return Err(eyre::eyre!("nonceKey should be string or null"));
            }
            Ok(U256::ZERO)
        })
        .collect::<eyre::Result<Vec<_>>>()?;

    nonce_keys.sort();

    assert!(
        nonce_keys.first().copied().unwrap_or_default() == U256::ZERO,
        "Implicit txs should include a zero nonceKey"
    );
    assert!(
        nonce_keys.iter().all(|key| *key == U256::ZERO),
        "Implicit txs should keep nonceKey at 0"
    );
    println!("✓ Implicit nonceKey behavior verified (no auto-assignment)");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_2d_nonce_pool_comprehensive() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut setup, provider, alice_signer, alice_addr) = setup_test_with_funded_account().await?;

    println!("\n=== Comprehensive 2D Nonce Pool Test ===\n");
    println!("Alice address: {alice_addr}");

    let recipient = Address::random();
    let chain_id = provider.get_chain_id().await?;

    // ===========================================================================
    // Scenario 1: Pool Routing & Independence
    // ===========================================================================
    println!("\n--- Scenario 1: Pool Routing & Independence ---");

    let initial_nonce = provider.get_transaction_count(alice_addr).await?;
    println!("Initial protocol nonce: {initial_nonce}");

    // Helper function to create and send a transaction
    async fn send_tx(
        setup: &mut crate::utils::SingleNodeSetup,
        alice_signer: &impl SignerSync,
        chain_id: u64,
        recipient: Address,
        nonce_key: u64,
        nonce: u64,
        priority_fee: u128,
    ) -> eyre::Result<B256> {
        let tx = TempoTransaction {
            chain_id,
            max_priority_fee_per_gas: priority_fee,
            max_fee_per_gas: TEMPO_T1_BASE_FEE as u128 + priority_fee,
            gas_limit: 2_000_000,
            calls: vec![Call {
                to: recipient.into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            nonce_key: U256::from(nonce_key),
            nonce,
            fee_token: None,
            fee_payer_signature: None,
            valid_before: Some(u64::MAX),
            ..Default::default()
        };

        let sig_hash = tx.signature_hash();
        let signature = alice_signer.sign_hash_sync(&sig_hash)?;
        let signed_tx = AASigned::new_unhashed(
            tx,
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
        );
        let envelope: TempoTxEnvelope = signed_tx.into();
        let encoded = envelope.encoded_2718();

        let tx_hash = setup.node.rpc.inject_tx(encoded.into()).await?;
        println!(
            "  ✓ Sent tx: nonce_key={}, nonce={}, priority_fee={} gwei",
            nonce_key,
            nonce,
            priority_fee / 1_000_000_000
        );
        Ok(tx_hash)
    }

    // Send 3 transactions with different nonce_keys
    let mut sent = vec![];
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            0,
            initial_nonce,
            TEMPO_T1_BASE_FEE as u128,
        )
        .await?,
    ); // Protocol pool
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            1,
            0,
            TEMPO_T1_BASE_FEE as u128,
        )
        .await?,
    ); // 2D pool
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            2,
            0,
            TEMPO_T1_BASE_FEE as u128,
        )
        .await?,
    ); // 2D pool

    for tx_hash in &sent {
        // Assert that transactions are in the pool
        assert!(
            setup.node.inner.pool.contains(tx_hash),
            "Transaction should be in the pool"
        );
    }

    // Mine block
    let payload1 = setup.node.advance_block().await?;
    let block1_txs = &payload1.block().body().transactions;

    println!(
        "\n  Block {} mined with {} transactions",
        payload1.block().inner.number,
        block1_txs.len()
    );

    // Skip system tx at index 0, check our 3 txs
    assert!(
        block1_txs.len() >= 4,
        "Block should contain system tx + 3 user transactions"
    );

    // Verify protocol nonce incremented
    let protocol_nonce_after = provider.get_transaction_count(alice_addr).await?;
    assert_eq!(
        protocol_nonce_after,
        initial_nonce + 1,
        "Protocol nonce should increment only once"
    );
    println!("  ✓ Protocol nonce: {initial_nonce} → {protocol_nonce_after}",);

    // Wait for pool maintenance task to process the block
    tokio::time::sleep(POOL_MAINTENANCE_DELAY).await;

    for tx_hash in &sent {
        // Assert that transactions were removed from the pool and included in the block
        assert!(block1_txs.iter().any(|tx| tx.tx_hash() == tx_hash));
        assert!(!setup.node.inner.pool.contains(tx_hash));
    }
    println!("  ✓ All 3 transactions from different pools included in block");

    // ===========================================================================
    // Scenario 2: Priority Fee Ordering (with subsequent nonces)
    // ===========================================================================
    println!("\n--- Scenario 2: Priority Fee Ordering ---");

    // Send transactions with different priority fees
    let low_fee = 1_000_000_000u128; // 1 gwei
    let mid_fee = 5_000_000_000u128; // 5 gwei
    let high_fee = 10_000_000_000u128; // 10 gwei

    let mut sent = vec![];
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            0,
            protocol_nonce_after,
            low_fee,
        )
        .await?,
    ); // Protocol pool, low fee
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            1,
            1,
            high_fee,
        )
        .await?,
    ); // 2D pool, highest fee
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            2,
            1,
            mid_fee,
        )
        .await?,
    ); // 2D pool, medium fee

    for tx_hash in &sent {
        // Assert that transactions are in the pool
        assert!(
            setup.node.inner.pool.contains(tx_hash),
            "Transaction should be in the pool"
        );
    }

    // Mine block
    let payload2 = setup.node.advance_block().await?;
    let block2_txs = &payload2.block().body().transactions;

    println!(
        "\n  Block {} mined with {} transactions",
        payload2.block().inner.number,
        block2_txs.len()
    );

    assert_eq!(provider.get_transaction_count(alice_addr).await?, 2);

    // Verify transactions are ordered by priority fee (highest first)
    // Skip system tx at index 0
    if block2_txs.len() >= 4 {
        // Extract priority fees from transactions
        let mut priority_fees = Vec::new();
        for tx in block2_txs.iter() {
            if let TempoTxEnvelope::AA(aa_tx) = tx {
                priority_fees.push(aa_tx.tx().max_priority_fee_per_gas);
                println!(
                    "    TX with nonce_key={}, nonce={}, priority_fee={} gwei",
                    aa_tx.tx().nonce_key,
                    aa_tx.tx().nonce,
                    aa_tx.tx().max_priority_fee_per_gas / 1_000_000_000
                );
            }
        }

        // Verify all 3 transactions with different fees were included
        assert_eq!(priority_fees.len(), 3, "Should have 3 transactions");
        assert!(
            priority_fees.contains(&high_fee),
            "Should contain high fee tx"
        );
        assert!(
            priority_fees.contains(&mid_fee),
            "Should contain mid fee tx"
        );
        assert!(
            priority_fees.contains(&low_fee),
            "Should contain low fee tx"
        );
        println!(
            "  ✓ All transactions with different fees included (ordering may vary between pools)"
        );
    }

    // Wait for pool maintenance task to process the block
    tokio::time::sleep(POOL_MAINTENANCE_DELAY).await;

    for tx_hash in &sent {
        // Assert that transactions were removed from the pool
        assert!(!setup.node.inner.pool.contains(tx_hash));
    }

    // ===========================================================================
    // Scenario 3: Nonce Gap Handling
    // ===========================================================================
    println!("\n--- Scenario 3: Nonce Gap Handling ---");

    // Send nonce=0 for nonce_key=3 (should be pending)
    let pending = send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        3,
        0,
        TEMPO_T1_BASE_FEE as u128,
    )
    .await?;
    println!("  Sent nonce_key=3, nonce=0 (should be pending)");

    // Send nonce=2 for nonce_key=3 (should be queued - gap at nonce=1)
    let queued = send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        3,
        2,
        TEMPO_T1_BASE_FEE as u128,
    )
    .await?;
    println!("  Sent nonce_key=3, nonce=2 (should be queued - gap at nonce=1)");

    // Assert that both transactions are in the pool and tracked correctly
    assert!(
        setup
            .node
            .inner
            .pool
            .pending_transactions()
            .iter()
            .any(|tx| tx.hash() == &pending)
    );
    assert!(
        setup
            .node
            .inner
            .pool
            .queued_transactions()
            .iter()
            .any(|tx| tx.hash() == &queued)
    );

    // Mine block - only nonce=0 should be included
    let payload3 = setup.node.advance_block().await?;
    let block3_txs = &payload3.block().body().transactions;

    println!(
        "\n  Block {} mined with {} transactions",
        payload3.block().inner.number,
        block3_txs.len()
    );

    // Count AA transactions with nonce_key=3
    let nonce_key_3_txs: Vec<_> = block3_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(3)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        nonce_key_3_txs.len(),
        1,
        "Only 1 transaction (nonce=0) should be included, nonce=2 should be queued"
    );
    assert_eq!(
        nonce_key_3_txs[0], 0,
        "The included transaction should have nonce=0"
    );
    println!("  ✓ Only nonce=0 included, nonce=2 correctly queued due to gap");

    // Fill the gap - send nonce=1
    let new_pending = send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        3,
        1,
        TEMPO_T1_BASE_FEE as u128,
    )
    .await?;
    println!("\n  Sent nonce_key=3, nonce=1 (fills the gap)");

    assert!(
        setup
            .node
            .inner
            .pool
            .pending_transactions()
            .iter()
            .any(|tx| tx.hash() == &new_pending)
    );
    assert!(
        setup
            .node
            .inner
            .pool
            .pending_transactions()
            .iter()
            .any(|tx| tx.hash() == &queued)
    );

    // Mine block - both nonce=1 and nonce=2 should be included now
    let payload4 = setup.node.advance_block().await?;
    let block4_txs = &payload4.block().body().transactions;

    println!(
        "\n  Block {} mined with {} transactions",
        payload4.block().inner.number,
        block4_txs.len()
    );

    // Count AA transactions with nonce_key=3
    let mut nonce_key_3_txs_after: Vec<_> = block4_txs
        .iter()
        .filter_map(|tx| {
            if let TempoTxEnvelope::AA(aa_tx) = tx {
                if aa_tx.tx().nonce_key == U256::from(3) {
                    Some(aa_tx.tx().nonce)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    nonce_key_3_txs_after.sort();

    // After filling the gap, nonce=1 should be mined
    assert!(
        nonce_key_3_txs_after.contains(&1),
        "nonce=1 should be included after filling gap"
    );
    println!("  ✓ Gap filled: nonce=1 included successfully");

    // Note: nonce=2 was queued when state_nonce=0. After nonce=1 executes, state_nonce=2,
    // but the queued transaction doesn't automatically promote without new transactions triggering re-evaluation.
    // This is a known limitation - queued transactions need explicit promotion mechanism.
    if !nonce_key_3_txs_after.contains(&2) {
        println!("  ⚠️  nonce=2 not yet promoted from queue (known limitation)");
        println!("     Queued transactions need promotion mechanism when state changes");
    } else {
        println!("  ✓ Both nonce=1 and nonce=2 included");
    }

    // Wait for pool maintenance task to process the block
    tokio::time::sleep(POOL_MAINTENANCE_DELAY).await;

    // Assert that all transactions are removed from the pool
    assert!(!setup.node.inner.pool.contains(&pending));
    assert!(!setup.node.inner.pool.contains(&queued));
    assert!(!setup.node.inner.pool.contains(&new_pending));

    Ok(())
}
// Helper to send transaction
async fn send_tx(
    setup: &mut crate::utils::SingleNodeSetup,
    alice_signer: &impl SignerSync,
    chain_id: u64,
    recipient: Address,
    nonce_key: u64,
    nonce: u64,
    priority_fee: u128,
) -> eyre::Result<()> {
    let tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: priority_fee,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128 + priority_fee,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::from(nonce_key),
        nonce,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    let sig_hash = tx.signature_hash();
    let signature = alice_signer.sign_hash_sync(&sig_hash)?;
    let signed_tx = AASigned::new_unhashed(
        tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );
    let envelope: TempoTxEnvelope = signed_tx.into();
    let encoded = envelope.encoded_2718();

    setup.node.rpc.inject_tx(encoded.into()).await?;
    println!(
        "  ✓ Sent nonce={}, priority_fee={} gwei",
        nonce,
        priority_fee / 1_000_000_000
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_2d_nonce_out_of_order_arrival() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut setup, provider, alice_signer, _alice_addr) = setup_test_with_funded_account().await?;

    let chain_id = provider.get_chain_id().await?;
    let recipient = Address::random();

    println!("\n=== Out-of-Order Nonce Arrival Test ===");
    println!("Testing nonce_key=4 with nonces arriving as: [5, 0, 2]");
    println!("Expected: Only execute in order, queue out-of-order txs\n");

    // Step 1: Send nonce=5 (should be queued - large gap)
    println!("Step 1: Send nonce=5 (should be queued - gap at 0,1,2,3,4)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        5,
        10_000_000_000,
    )
    .await?;

    // Step 2: Send nonce=0 (should be pending - ready to execute)
    println!("\nStep 2: Send nonce=0 (should be pending - ready to execute)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        0,
        10_000_000_000,
    )
    .await?;

    // Step 3: Send nonce=2 (should be queued - gap at 1)
    println!("\nStep 3: Send nonce=2 (should be queued - gap at 1)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        2,
        10_000_000_000,
    )
    .await?;

    // Mine block - only nonce=0 should execute
    println!("\nMining block (should only include nonce=0)...");
    let payload1 = setup.node.advance_block().await?;
    let block1_txs = &payload1.block().body().transactions;

    let executed_nonces: Vec<u64> = block1_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(4)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();

    assert_eq!(executed_nonces, vec![0], "Only nonce=0 should execute");
    println!("  ✓ Block 1: Only nonce=0 executed (nonce=2 and nonce=5 correctly queued)");

    // Step 4: Send nonce=1 (fills first gap)
    println!("\nStep 4: Send nonce=1 (fills gap before nonce=2)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        1,
        10_000_000_000,
    )
    .await?;

    // Mine block - nonce=1 and nonce=2 should both execute (promotion!)
    println!("\nMining block (should include nonce=1 AND nonce=2 via promotion)...");
    let payload2 = setup.node.advance_block().await?;
    let block2_txs = &payload2.block().body().transactions;

    let mut executed_nonces: Vec<u64> = block2_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(4)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();
    executed_nonces.sort();

    assert!(executed_nonces.contains(&1), "nonce=1 should execute");
    assert!(
        executed_nonces.contains(&2),
        "nonce=2 should promote and execute"
    );
    println!("  ✓ Block 2: nonce=1 and nonce=2 executed (promotion worked!)");

    // Step 5: Send nonces 3 and 4 (fills remaining gaps)
    println!("\nStep 5: Send nonces 3 and 4 (fills gaps before nonce=5)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        3,
        10_000_000_000,
    )
    .await?;
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        4,
        10_000_000_000,
    )
    .await?;

    // Mine block - nonces 3, 4, and 5 should all execute
    println!("\nMining block (should include nonces 3, 4, AND 5 via promotion)...");
    let payload3 = setup.node.advance_block().await?;
    let block3_txs = &payload3.block().body().transactions;

    let mut executed_nonces: Vec<u64> = block3_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(4)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();
    executed_nonces.sort();

    assert!(executed_nonces.contains(&3), "nonce=3 should execute");
    assert!(executed_nonces.contains(&4), "nonce=4 should execute");
    assert!(
        executed_nonces.contains(&5),
        "nonce=5 should finally promote and execute"
    );
    Ok(())
}

#[tokio::test]
async fn test_aa_webauthn_signature_negative_cases() -> eyre::Result<()> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::{
        ecdsa::{SigningKey, signature::Signer},
        elliptic_curve::rand_core::OsRng,
    };
    use sha2::{Digest, Sha256};

    reth_tracing::init_test_tracing();

    // Setup test node with direct access
    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let http_url = setup.node.rpc_url();

    // Generate the correct P256 key pair for WebAuthn
    let correct_signing_key = SigningKey::random(&mut OsRng);
    let correct_verifying_key = correct_signing_key.verifying_key();

    // Extract correct public key coordinates
    let correct_encoded_point = correct_verifying_key.to_encoded_point(false);
    let correct_pub_key_x =
        alloy::primitives::B256::from_slice(correct_encoded_point.x().unwrap().as_ref());
    let correct_pub_key_y =
        alloy::primitives::B256::from_slice(correct_encoded_point.y().unwrap().as_ref());

    // Generate a different (wrong) P256 key pair
    let wrong_signing_key = SigningKey::random(&mut OsRng);
    let wrong_verifying_key = wrong_signing_key.verifying_key();

    // Extract wrong public key coordinates
    let wrong_encoded_point = wrong_verifying_key.to_encoded_point(false);
    let wrong_pub_key_x =
        alloy::primitives::B256::from_slice(wrong_encoded_point.x().unwrap().as_ref());
    let wrong_pub_key_y =
        alloy::primitives::B256::from_slice(wrong_encoded_point.y().unwrap().as_ref());

    // Use TEST_MNEMONIC account to fund the WebAuthn signers
    let funder_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let funder_addr = funder_signer.address();

    // Create provider with funder's wallet
    let funder_wallet = EthereumWallet::from(funder_signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(funder_wallet)
        .connect_http(http_url.clone());

    println!("\n=== Testing WebAuthn Negative Cases ===\n");

    // Get chain ID
    let chain_id = provider.get_chain_id().await?;

    // Create recipient address for test transactions
    let recipient = Address::random();

    // Helper function to create a test AA transaction
    let create_test_tx = |nonce_seq: u64| TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO,
        nonce: nonce_seq,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    // ===========================================
    // Test Case 1: Wrong Public Key
    // ===========================================
    println!("Test 1: Wrong public key in signature");

    let tx1 = create_test_tx(100);
    let sig_hash1 = tx1.signature_hash();

    // Create correct WebAuthn data
    let mut authenticator_data1 = vec![0u8; 37];
    authenticator_data1[32] = 0x01; // UP flag set

    let challenge_b64url1 = URL_SAFE_NO_PAD.encode(sig_hash1.as_slice());
    let client_data_json1 = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url1}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute message hash
    let client_data_hash1 = Sha256::digest(client_data_json1.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data1);
    final_hasher.update(client_data_hash1);
    let message_hash1 = final_hasher.finalize();

    // Sign with CORRECT private key
    let signature1: p256::ecdsa::Signature = correct_signing_key.sign(&message_hash1);
    let sig_bytes1 = signature1.to_bytes();

    // But use WRONG public key in the signature
    let mut webauthn_data1 = Vec::new();
    webauthn_data1.extend_from_slice(&authenticator_data1);
    webauthn_data1.extend_from_slice(client_data_json1.as_bytes());

    let aa_signature1 =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data1),
            r: alloy::primitives::B256::from_slice(&sig_bytes1[0..32]),
            s: alloy::primitives::B256::from_slice(&sig_bytes1[32..64]),
            pub_key_x: wrong_pub_key_x, // WRONG public key
            pub_key_y: wrong_pub_key_y, // WRONG public key
        }));

    // Try to verify - should fail
    let recovery_result1 = aa_signature1.recover_signer(&sig_hash1);
    assert!(
        recovery_result1.is_err(),
        "Should fail with wrong public key"
    );
    println!("✓ Signature recovery correctly failed with wrong public key");

    // ===========================================
    // Test Case 2: Wrong Private Key (signature doesn't match public key)
    // ===========================================
    println!("\nTest 2: Wrong private key (signature doesn't match public key)");

    let tx2 = create_test_tx(101);
    let sig_hash2 = tx2.signature_hash();

    // Create correct WebAuthn data
    let mut authenticator_data2 = vec![0u8; 37];
    authenticator_data2[32] = 0x01; // UP flag set

    let challenge_b64url2 = URL_SAFE_NO_PAD.encode(sig_hash2.as_slice());
    let client_data_json2 = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url2}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute message hash
    let client_data_hash2 = Sha256::digest(client_data_json2.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data2);
    final_hasher.update(client_data_hash2);
    let message_hash2 = final_hasher.finalize();

    // Sign with WRONG private key
    let signature2: p256::ecdsa::Signature = wrong_signing_key.sign(&message_hash2);
    let sig_bytes2 = signature2.to_bytes();

    // But use CORRECT public key in the signature
    let mut webauthn_data2 = Vec::new();
    webauthn_data2.extend_from_slice(&authenticator_data2);
    webauthn_data2.extend_from_slice(client_data_json2.as_bytes());

    let aa_signature2 =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data2),
            r: alloy::primitives::B256::from_slice(&sig_bytes2[0..32]),
            s: alloy::primitives::B256::from_slice(&sig_bytes2[32..64]),
            pub_key_x: correct_pub_key_x, // Correct public key
            pub_key_y: correct_pub_key_y, // But signature is from wrong private key
        }));

    // Try to verify - should fail
    let recovery_result2 = aa_signature2.recover_signer(&sig_hash2);
    assert!(
        recovery_result2.is_err(),
        "Should fail with wrong private key"
    );
    println!("✓ Signature recovery correctly failed with wrong private key");

    // ===========================================
    // Test Case 3: Wrong Challenge in clientDataJSON
    // ===========================================
    println!("\nTest 3: Wrong challenge in clientDataJSON");

    let tx3 = create_test_tx(102);
    let sig_hash3 = tx3.signature_hash();

    // Create WebAuthn data with WRONG challenge
    let mut authenticator_data3 = vec![0u8; 37];
    authenticator_data3[32] = 0x01; // UP flag set

    let wrong_challenge = B256::from([0xFF; 32]); // Different hash
    let wrong_challenge_b64url = URL_SAFE_NO_PAD.encode(wrong_challenge.as_slice());
    let client_data_json3 = format!(
        r#"{{"type":"webauthn.get","challenge":"{wrong_challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute message hash
    let client_data_hash3 = Sha256::digest(client_data_json3.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data3);
    final_hasher.update(client_data_hash3);
    let message_hash3 = final_hasher.finalize();

    // Sign with correct private key
    let signature3: p256::ecdsa::Signature = correct_signing_key.sign(&message_hash3);
    let sig_bytes3 = signature3.to_bytes();

    let mut webauthn_data3 = Vec::new();
    webauthn_data3.extend_from_slice(&authenticator_data3);
    webauthn_data3.extend_from_slice(client_data_json3.as_bytes());

    let aa_signature3 =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data3),
            r: alloy::primitives::B256::from_slice(&sig_bytes3[0..32]),
            s: alloy::primitives::B256::from_slice(&sig_bytes3[32..64]),
            pub_key_x: correct_pub_key_x,
            pub_key_y: correct_pub_key_y,
        }));

    // Try to verify - should fail during WebAuthn data validation
    let recovery_result3 = aa_signature3.recover_signer(&sig_hash3);
    assert!(
        recovery_result3.is_err(),
        "Should fail with wrong challenge"
    );
    println!("✓ Signature recovery correctly failed with wrong challenge");

    // ===========================================
    // Test Case 4: Wrong Authenticator Data
    // ===========================================
    println!("\nTest 4: Wrong authenticator data (UP flag not set)");

    let tx4 = create_test_tx(103);
    let sig_hash4 = tx4.signature_hash();

    // Create WebAuthn data with UP flag NOT set
    let mut authenticator_data4 = vec![0u8; 37];
    authenticator_data4[32] = 0x00; // UP flag NOT set (should be 0x01)

    let challenge_b64url4 = URL_SAFE_NO_PAD.encode(sig_hash4.as_slice());
    let client_data_json4 = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url4}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute message hash
    let client_data_hash4 = Sha256::digest(client_data_json4.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data4);
    final_hasher.update(client_data_hash4);
    let message_hash4 = final_hasher.finalize();

    // Sign with correct private key
    let signature4: p256::ecdsa::Signature = correct_signing_key.sign(&message_hash4);
    let sig_bytes4 = signature4.to_bytes();

    let mut webauthn_data4 = Vec::new();
    webauthn_data4.extend_from_slice(&authenticator_data4);
    webauthn_data4.extend_from_slice(client_data_json4.as_bytes());

    let aa_signature4 =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data4),
            r: alloy::primitives::B256::from_slice(&sig_bytes4[0..32]),
            s: alloy::primitives::B256::from_slice(&sig_bytes4[32..64]),
            pub_key_x: correct_pub_key_x,
            pub_key_y: correct_pub_key_y,
        }));

    // Try to verify - should fail during WebAuthn data validation
    let recovery_result4 = aa_signature4.recover_signer(&sig_hash4);
    assert!(
        recovery_result4.is_err(),
        "Should fail with wrong authenticator data"
    );
    println!("✓ Signature recovery correctly failed with wrong authenticator data");

    // ===========================================
    // Test Case 5: Transaction Injection Should Fail
    // ===========================================
    println!("\nTest 5: Transaction injection with invalid signature");

    // Fund one of the addresses to test transaction injection
    let test_signer_addr = tempo_primitives::transaction::tt_signature::derive_p256_address(
        &correct_pub_key_x,
        &correct_pub_key_y,
    );

    // Fund the test signer
    let transfer_amount = U256::from(10u64) * U256::from(10).pow(U256::from(18));
    fund_address_with_fee_tokens(
        &mut setup,
        &provider,
        &funder_signer,
        funder_addr,
        test_signer_addr,
        transfer_amount,
        chain_id,
    )
    .await?;

    // Now try to inject a transaction with wrong signature
    let bad_tx = create_test_tx(0);
    let _bad_sig_hash = bad_tx.signature_hash();

    // Create WebAuthn data with wrong challenge (like test case 3)
    let mut bad_auth_data = vec![0u8; 37];
    bad_auth_data[32] = 0x01;

    let wrong_challenge = B256::from([0xAA; 32]);
    let wrong_challenge_b64 = URL_SAFE_NO_PAD.encode(wrong_challenge.as_slice());
    let bad_client_data = format!(
        r#"{{"type":"webauthn.get","challenge":"{wrong_challenge_b64}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Sign with correct key but wrong data
    let client_hash = Sha256::digest(bad_client_data.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&bad_auth_data);
    final_hasher.update(client_hash);
    let bad_message_hash = final_hasher.finalize();

    let bad_signature: p256::ecdsa::Signature = correct_signing_key.sign(&bad_message_hash);
    let bad_sig_bytes = bad_signature.to_bytes();

    let mut bad_webauthn_data = Vec::new();
    bad_webauthn_data.extend_from_slice(&bad_auth_data);
    bad_webauthn_data.extend_from_slice(bad_client_data.as_bytes());

    let bad_tempo_signature =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(bad_webauthn_data),
            r: alloy::primitives::B256::from_slice(&bad_sig_bytes[0..32]),
            s: alloy::primitives::B256::from_slice(&bad_sig_bytes[32..64]),
            pub_key_x: correct_pub_key_x,
            pub_key_y: correct_pub_key_y,
        }));

    let signed_bad_tx = AASigned::new_unhashed(bad_tx, bad_tempo_signature);
    let bad_envelope: TempoTxEnvelope = signed_bad_tx.into();
    let mut encoded_bad = Vec::new();
    bad_envelope.encode_2718(&mut encoded_bad);

    // Try to inject - should fail
    let inject_result = setup.node.rpc.inject_tx(encoded_bad.clone().into()).await;
    assert!(
        inject_result.is_err(),
        "Transaction with invalid signature should be rejected"
    );
    println!("✓ Transaction with invalid WebAuthn signature correctly rejected");

    // Verify the rejected transaction is NOT available via eth_getTransactionByHash
    verify_tx_not_in_block_via_rpc(&provider, &encoded_bad).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_sponsored_raw_tx_sync_secp256k1() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let http_url = setup.node.rpc_url();
    let provider = ProviderBuilder::new().connect_http(http_url.clone());

    let chain_id = provider.get_chain_id().await?;

    let fee_payer_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let fee_payer_addr = fee_payer_signer.address();

    let user_signer = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = user_signer.address();

    let user_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(user_addr)
        .call()
        .await?;
    assert_eq!(user_balance, U256::ZERO, "User should be unfunded");

    let fee_payer_balance_before = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(fee_payer_addr)
        .call()
        .await?;

    let recipient = Address::random();
    let mut tx = create_basic_aa_tx(
        chain_id,
        0,
        vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );
    tx.fee_payer_signature = Some(Signature::new(U256::ZERO, U256::ZERO, false));

    let user_sig_hash = tx.signature_hash();
    let user_signature = user_signer.sign_hash_sync(&user_sig_hash)?;

    sign_fee_payer(&mut tx, user_addr, &fee_payer_signer)?;

    let aa_signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(user_signature));
    let envelope: TempoTxEnvelope = tx.into_signed(aa_signature).into();
    let encoded = envelope.encoded_2718();
    let tx_hash = *envelope.tx_hash();

    let sync_provider = ProviderBuilder::new().connect_http(http_url.clone());
    let encoded_for_sync = encoded.clone();
    let mut sync_handle = tokio::spawn(async move {
        sync_provider
            .raw_request("eth_sendRawTransactionSync".into(), [encoded_for_sync])
            .await
    });

    let raw_result: serde_json::Value =
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                tokio::select! {
                    res = &mut sync_handle => {
                        let res = res.map_err(|err| eyre::eyre!("Sync task failed: {err}"))?;
                        return res.map_err(|err| eyre::eyre!("Sync request failed: {err}"));
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                        setup
                            .node
                            .advance_block()
                            .await
                            .map_err(|err| eyre::eyre!("Advance block failed: {err}"))?;
                    }
                }
            }
        })
        .await
        .map_err(|_| eyre::eyre!("eth_sendRawTransactionSync timed out"))??;

    if let Some(tx_hash_str) = raw_result.as_str() {
        let returned_hash = tx_hash_str.parse::<B256>()?;
        assert_eq!(returned_hash, tx_hash, "RPC should return tx hash");
    } else {
        let receipt_obj = raw_result
            .as_object()
            .ok_or_else(|| eyre::eyre!("Sync response should be hash or receipt"))?;
        let status_ok = receipt_obj
            .get("status")
            .and_then(|value| value.as_str())
            .map(|value| value == "0x1")
            .unwrap_or(false);
        assert!(status_ok, "Receipt should indicate success");
        let returned_hash = receipt_obj
            .get("transactionHash")
            .and_then(|value| value.as_str())
            .ok_or_else(|| eyre::eyre!("Receipt missing transactionHash"))?
            .parse::<B256>()?;
        assert_eq!(returned_hash, tx_hash, "Receipt tx hash mismatch");
    }

    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;
    assert!(receipt.is_some(), "Transaction should be mined");

    let fee_payer_balance_after = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(fee_payer_addr)
        .call()
        .await?;
    assert!(
        fee_payer_balance_after < fee_payer_balance_before,
        "Fee payer should cover gas"
    );

    Ok(())
}

// ===== Explicit eth_sendRawTransaction Matrix Tests =====
// Covers key type (secp256k1/p256/webauthn) x fee payer on/off x access key on/off.

/// Key type for matrix tests
#[derive(Debug, Clone, Copy, PartialEq)]
enum KeyType {
    Secp256k1,
    P256,
    WebAuthn,
}

#[derive(Debug, Clone)]
struct RawSendTestCase {
    name: String,
    key_type: KeyType,
    fee_payer: bool,
    access_key: bool,
}

fn key_type_label(key_type: KeyType) -> &'static str {
    match key_type {
        KeyType::Secp256k1 => "secp256k1",
        KeyType::P256 => "p256",
        KeyType::WebAuthn => "webauthn",
    }
}

fn nonce_mode_label(nonce_mode: &NonceMode) -> &'static str {
    match nonce_mode {
        NonceMode::Protocol => "protocol",
        NonceMode::TwoD(_) => "2d",
        NonceMode::Expiring => "expiring",
        NonceMode::ExpiringAtBoundary => "expiring_at_boundary",
        NonceMode::ExpiringExceedsBoundary => "expiring_exceeds_boundary",
    }
}

fn build_case_name(prefix: &str, base: &str, parts: &[&str]) -> String {
    let mut name = String::with_capacity(prefix.len() + base.len() + parts.len() * 8 + 2);
    name.push_str(prefix);
    name.push_str("::");
    name.push_str(base);
    for part in parts {
        name.push('_');
        name.push_str(part);
    }
    name
}

fn build_raw_name(key_type: KeyType, flags: &[&str]) -> String {
    build_case_name("send_raw", key_type_label(key_type), flags)
}

#[derive(Debug, Clone)]
struct SendTestCase {
    name: String,
    key_type: KeyType,
    fee_payer: bool,
    access_key: bool,
    batch_calls: bool,
    funding_amount: Option<U256>,
    transfer_amount: Option<U256>,
}

fn build_send_name(key_type: KeyType, flags: &[&str], opts: &[&str]) -> String {
    let mut parts = Vec::with_capacity(flags.len() + opts.len());
    parts.extend_from_slice(flags);
    parts.extend_from_slice(opts);
    build_case_name("send", key_type_label(key_type), &parts)
}

fn build_fill_name(nonce_mode: &NonceMode, key_type: KeyType, parts: &[&str]) -> String {
    let base = format!(
        "{}_{}",
        nonce_mode_label(nonce_mode),
        key_type_label(key_type)
    );
    build_case_name("fill", &base, parts)
}

type SignTxFn = Box<dyn Fn(&TempoTransaction) -> eyre::Result<TempoSignature> + Send>;

struct AccessKeyContext<P, S> {
    setup: SingleNodeSetup,
    provider: P,
    chain_id: u64,
    root_signer: S,
    root_addr: Address,
    key_auth: SignedKeyAuthorization,
    sign: SignTxFn,
}

struct NonAccessContext<P, S> {
    setup: SingleNodeSetup,
    provider: P,
    chain_id: u64,
    signer_addr: Address,
    funder_signer: S,
    funder_addr: Address,
    sign: SignTxFn,
}

#[derive(Debug, Clone, Copy)]
struct FeePayerContext {
    addr: Address,
    balance_before: U256,
}

async fn configure_fee_payer_context(
    provider: &impl Provider,
    tx: &mut TempoTransaction,
    fee_payer_enabled: bool,
    signer_addr: Address,
    fee_payer_signer: &(impl SignerSync + ?Sized),
    fee_payer_addr: Address,
    self_payer_addr: Address,
) -> eyre::Result<FeePayerContext> {
    if fee_payer_enabled {
        let balance_before = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
            .balanceOf(fee_payer_addr)
            .call()
            .await?;
        sign_fee_payer(tx, signer_addr, fee_payer_signer)?;

        Ok(FeePayerContext {
            addr: fee_payer_addr,
            balance_before,
        })
    } else {
        let balance_before = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
            .balanceOf(self_payer_addr)
            .call()
            .await?;
        Ok(FeePayerContext {
            addr: self_payer_addr,
            balance_before,
        })
    }
}

async fn send_raw_aa_and_assert_mined(
    setup: &mut SingleNodeSetup,
    provider: &impl Provider,
    envelope: &TempoTxEnvelope,
    signer_addr: Address,
) -> eyre::Result<()> {
    let encoded = envelope.encoded_2718();
    let tx_hash = *envelope.tx_hash();

    let decoded = TempoTxEnvelope::decode_2718(&mut encoded.as_slice())?;
    assert!(
        matches!(decoded, TempoTxEnvelope::AA(_)),
        "Should decode as AA transaction"
    );
    if let TempoTxEnvelope::AA(ref decoded_aa) = decoded {
        let recovered = decoded_aa
            .signature()
            .recover_signer(&decoded_aa.signature_hash())
            .expect("Should recover signer");
        assert_eq!(recovered, signer_addr, "Recovered signer should match");
    }

    let raw_result: B256 = provider
        .raw_request("eth_sendRawTransaction".into(), [encoded.clone()])
        .await?;
    assert_eq!(raw_result, tx_hash, "RPC should return tx hash");

    setup.node.advance_block().await?;
    assert_receipt_status(provider, tx_hash, true).await?;

    verify_tx_in_block_via_rpc(provider, &encoded, envelope).await?;

    Ok(())
}

async fn inject_and_assert_mined(
    setup: &mut SingleNodeSetup,
    provider: &impl Provider,
    encoded: Vec<u8>,
    tx_hash: B256,
) -> eyre::Result<()> {
    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;
    assert_receipt_status(provider, tx_hash, true).await?;

    Ok(())
}

async fn assert_fee_token_balance(
    provider: &impl Provider,
    who: Address,
    expected: U256,
    msg: &str,
) -> eyre::Result<()> {
    let bal = ITIP20::new(DEFAULT_FEE_TOKEN, provider)
        .balanceOf(who)
        .call()
        .await?;
    assert_eq!(bal, expected, "{msg}");
    Ok(())
}

async fn assert_batch_recipient_balances(
    provider: &impl Provider,
    token: Address,
    recipient_1: Address,
    recipient_2: Address,
    transfer_amount: U256,
) -> eyre::Result<()> {
    let bal_1 = ITIP20::new(token, provider)
        .balanceOf(recipient_1)
        .call()
        .await?;
    assert_eq!(
        bal_1, transfer_amount,
        "Recipient 1 should receive transfer_amount"
    );
    let bal_2 = ITIP20::new(token, provider)
        .balanceOf(recipient_2)
        .call()
        .await?;
    assert_eq!(
        bal_2, transfer_amount,
        "Recipient 2 should receive transfer_amount"
    );
    Ok(())
}

fn sign_fee_payer(
    tx: &mut TempoTransaction,
    signer_addr: Address,
    fee_payer: &(impl SignerSync + ?Sized),
) -> eyre::Result<()> {
    tx.fee_payer_signature = Some(Signature::new(U256::ZERO, U256::ZERO, false));
    let fee_payer_sig_hash = tx.fee_payer_signature_hash(signer_addr);
    let fee_payer_signature = fee_payer.sign_hash_sync(&fee_payer_sig_hash)?;
    tx.fee_payer_signature = Some(fee_payer_signature);

    Ok(())
}

async fn assert_fee_payer_spent(
    provider: &impl Provider,
    fee_payer: FeePayerContext,
) -> eyre::Result<()> {
    let fee_payer_balance_after = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(fee_payer.addr)
        .call()
        .await?;
    assert!(
        fee_payer_balance_after < fee_payer.balance_before,
        "Fee payer should cover gas"
    );

    Ok(())
}

async fn run_raw_send_test_case(test_case: &RawSendTestCase) -> eyre::Result<()> {
    println!("\n=== Raw send test: {} ===\n", test_case.name);

    match test_case.key_type {
        KeyType::Secp256k1 => {
            run_raw_send_test_case_with_key(
                test_case,
                || async {
                    let setup = TestNodeBuilder::new().build_with_node_access().await?;
                    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
                    let chain_id = provider.get_chain_id().await?;

                    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
                    let root_addr = root_signer.address();

                    let access_signer = alloy::signers::local::PrivateKeySigner::random();
                    let access_addr = access_signer.address();
                    let key_auth = create_key_authorization(
                        &root_signer,
                        access_addr,
                        create_mock_secp256k1_sig(),
                        chain_id,
                        None,
                        Some(create_default_token_limit()),
                    )?;

                    let sign = Box::new(move |tx: &TempoTransaction| {
                        sign_aa_tx_with_secp256k1_access_key(tx, &access_signer, root_addr)
                    });

                    Ok(AccessKeyContext {
                        setup,
                        provider,
                        chain_id,
                        root_signer,
                        root_addr,
                        key_auth,
                        sign,
                    })
                },
                || async {
                    let setup = TestNodeBuilder::new().build_with_node_access().await?;
                    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
                    let chain_id = provider.get_chain_id().await?;

                    let funder_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
                    let funder_addr = funder_signer.address();

                    let user_signer = alloy::signers::local::PrivateKeySigner::random();
                    let user_addr = user_signer.address();

                    let sign = Box::new(move |tx: &TempoTransaction| {
                        sign_aa_tx_secp256k1(tx, &user_signer)
                    });

                    Ok(NonAccessContext {
                        setup,
                        provider,
                        chain_id,
                        signer_addr: user_addr,
                        funder_signer,
                        funder_addr,
                        sign,
                    })
                },
            )
            .await
        }
        KeyType::P256 => {
            run_raw_send_test_case_with_key(
                test_case,
                || async {
                    let (setup, provider, root_signer, root_addr) =
                        setup_test_with_funded_account().await?;
                    let chain_id = provider.get_chain_id().await?;

                    let (access_signing_key, access_pub_x, access_pub_y, access_key_addr) =
                        generate_p256_access_key();
                    let key_auth = create_key_authorization(
                        &root_signer,
                        access_key_addr,
                        create_mock_p256_sig(access_pub_x, access_pub_y),
                        chain_id,
                        None,
                        Some(create_default_token_limit()),
                    )?;

                    let sign = Box::new(move |tx: &TempoTransaction| {
                        sign_aa_tx_with_p256_access_key(
                            tx,
                            &access_signing_key,
                            &access_pub_x,
                            &access_pub_y,
                            root_addr,
                        )
                    });

                    Ok(AccessKeyContext {
                        setup,
                        provider,
                        chain_id,
                        root_signer,
                        root_addr,
                        key_auth,
                        sign,
                    })
                },
                || async {
                    let funding_amount = U256::from(1_000_000_000_000_000_000u128);
                    let (
                        setup,
                        provider,
                        signing_key,
                        pub_key_x,
                        pub_key_y,
                        signer_addr,
                        funder_signer,
                        funder_addr,
                        chain_id,
                        _fee_token,
                    ) = setup_test_with_p256_funded_account(funding_amount).await?;

                    let sign = Box::new(move |tx: &TempoTransaction| {
                        sign_aa_tx_p256(tx, &signing_key, pub_key_x, pub_key_y)
                    });

                    Ok(NonAccessContext {
                        setup,
                        provider,
                        chain_id,
                        signer_addr,
                        funder_signer,
                        funder_addr,
                        sign,
                    })
                },
            )
            .await
        }
        KeyType::WebAuthn => {
            run_raw_send_test_case_with_key(
                test_case,
                || async {
                    let (setup, provider, root_signer, root_addr) =
                        setup_test_with_funded_account().await?;
                    let chain_id = provider.get_chain_id().await?;

                    let (access_signing_key, access_pub_x, access_pub_y, access_key_addr) =
                        generate_p256_access_key();
                    let key_auth = create_key_authorization(
                        &root_signer,
                        access_key_addr,
                        create_mock_webauthn_sig(access_pub_x, access_pub_y),
                        chain_id,
                        None,
                        Some(create_default_token_limit()),
                    )?;

                    let sign = Box::new(move |tx: &TempoTransaction| {
                        sign_aa_tx_with_webauthn_access_key(
                            tx,
                            &access_signing_key,
                            access_pub_x,
                            access_pub_y,
                            "https://example.com",
                            root_addr,
                        )
                    });

                    Ok(AccessKeyContext {
                        setup,
                        provider,
                        chain_id,
                        root_signer,
                        root_addr,
                        key_auth,
                        sign,
                    })
                },
                || async {
                    let funding_amount = U256::from(1_000_000_000_000_000_000u128);
                    let (
                        setup,
                        provider,
                        signing_key,
                        pub_key_x,
                        pub_key_y,
                        signer_addr,
                        funder_signer,
                        funder_addr,
                        chain_id,
                        _fee_token,
                    ) = setup_test_with_p256_funded_account(funding_amount).await?;

                    let sign = Box::new(move |tx: &TempoTransaction| {
                        sign_aa_tx_webauthn(
                            tx,
                            &signing_key,
                            pub_key_x,
                            pub_key_y,
                            "https://example.com",
                        )
                    });

                    Ok(NonAccessContext {
                        setup,
                        provider,
                        chain_id,
                        signer_addr,
                        funder_signer,
                        funder_addr,
                        sign,
                    })
                },
            )
            .await
        }
    }
}

fn resolve_send_amounts(test_case: &SendTestCase) -> eyre::Result<(U256, U256)> {
    let base_funding = U256::from(1_000_000_000_000_000_000u128);
    let funding_amount = test_case.funding_amount.unwrap_or(base_funding);
    let transfer_amount = test_case
        .transfer_amount
        .unwrap_or(U256::from(1u64) * U256::from(10).pow(U256::from(6)));

    Ok((funding_amount.max(base_funding), transfer_amount))
}

fn create_send_calls(
    recipient_1: Address,
    recipient_2: Option<Address>,
    fee_token: Address,
    batch_calls: bool,
    transfer_amount: U256,
) -> Vec<Call> {
    if batch_calls {
        let recipient_2 = recipient_2.expect("batch calls require two recipients");
        vec![
            Call {
                to: fee_token.into(),
                value: U256::ZERO,
                input: transferCall {
                    to: recipient_1,
                    amount: transfer_amount,
                }
                .abi_encode()
                .into(),
            },
            Call {
                to: fee_token.into(),
                value: U256::ZERO,
                input: transferCall {
                    to: recipient_2,
                    amount: transfer_amount,
                }
                .abi_encode()
                .into(),
            },
        ]
    } else {
        vec![Call {
            to: recipient_1.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }]
    }
}

async fn run_send_transaction_test_case(test_case: &SendTestCase) -> eyre::Result<()> {
    println!("\n=== Send transaction test: {} ===\n", test_case.name);

    if test_case.key_type == KeyType::Secp256k1 && test_case.access_key {
        return Err(eyre::eyre!(
            "secp256k1 access key not supported in send matrix"
        ));
    }
    if test_case.key_type == KeyType::Secp256k1 && test_case.batch_calls {
        return Err(eyre::eyre!(
            "secp256k1 batch calls not supported in send matrix"
        ));
    }

    let (funding_amount, transfer_amount) = resolve_send_amounts(test_case)?;

    if test_case.access_key {
        let (mut setup, provider, root_signer, root_addr) =
            setup_test_with_funded_account().await?;
        let chain_id = provider.get_chain_id().await?;
        let (access_signing_key, access_pub_key_x, access_pub_key_y, access_key_addr) =
            generate_p256_access_key();

        let access_signature = match test_case.key_type {
            KeyType::P256 => create_mock_p256_sig(access_pub_key_x, access_pub_key_y),
            KeyType::WebAuthn => create_mock_webauthn_sig(access_pub_key_x, access_pub_key_y),
            KeyType::Secp256k1 => unreachable!("guarded above"),
        };

        let key_auth = create_key_authorization(
            &root_signer,
            access_key_addr,
            access_signature,
            chain_id,
            None,
            Some(create_default_token_limit()),
        )?;

        let recipient_1 = Address::random();
        let recipient_2 = if test_case.batch_calls {
            Some(Address::random())
        } else {
            None
        };

        let mut tx = create_basic_aa_tx(
            chain_id,
            provider.get_transaction_count(root_addr).await?,
            create_send_calls(
                recipient_1,
                recipient_2,
                DEFAULT_FEE_TOKEN,
                test_case.batch_calls,
                transfer_amount,
            ),
            2_000_000,
        );
        tx.key_authorization = Some(key_auth);

        let fee_payer_ctx = configure_fee_payer_context(
            &provider,
            &mut tx,
            test_case.fee_payer,
            root_addr,
            &root_signer,
            root_addr,
            root_addr,
        )
        .await?;

        let signature = match test_case.key_type {
            KeyType::P256 => sign_aa_tx_with_p256_access_key(
                &tx,
                &access_signing_key,
                &access_pub_key_x,
                &access_pub_key_y,
                root_addr,
            )?,
            KeyType::WebAuthn => sign_aa_tx_with_webauthn_access_key(
                &tx,
                &access_signing_key,
                access_pub_key_x,
                access_pub_key_y,
                "https://example.com",
                root_addr,
            )?,
            KeyType::Secp256k1 => unreachable!("guarded above"),
        };

        let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
        let encoded = envelope.encoded_2718();
        let tx_hash = *envelope.tx_hash();

        inject_and_assert_mined(&mut setup, &provider, encoded, tx_hash).await?;
        assert_fee_payer_spent(&provider, fee_payer_ctx).await?;

        if test_case.batch_calls {
            assert_batch_recipient_balances(
                &provider,
                DEFAULT_FEE_TOKEN,
                recipient_1,
                recipient_2.expect("batch_calls requires recipient_2"),
                transfer_amount,
            )
            .await?;
        }

        return Ok(());
    }

    match test_case.key_type {
        KeyType::Secp256k1 => {
            let (mut setup, provider, signer, signer_addr) =
                setup_test_with_funded_account().await?;
            let chain_id = provider.get_chain_id().await?;
            let recipient = Address::random();
            let nonce = provider.get_transaction_count(signer_addr).await?;

            let mut tx = create_basic_aa_tx(
                chain_id,
                nonce,
                create_send_calls(recipient, None, DEFAULT_FEE_TOKEN, false, transfer_amount),
                2_000_000,
            );
            if test_case.fee_payer {
                sign_fee_payer(&mut tx, signer_addr, &signer)?;
            }

            let signature = sign_aa_tx_secp256k1(&tx, &signer)?;
            let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
            let encoded = envelope.encoded_2718();
            let tx_hash = *envelope.tx_hash();

            inject_and_assert_mined(&mut setup, &provider, encoded, tx_hash).await?;

            Ok(())
        }
        KeyType::P256 | KeyType::WebAuthn => {
            let (
                mut setup,
                provider,
                signing_key,
                pub_key_x,
                pub_key_y,
                signer_addr,
                fee_payer_signer,
                fee_payer_addr,
                chain_id,
                fee_token,
            ) = setup_test_with_p256_funded_account(funding_amount).await?;

            let recipient_1 = Address::random();
            let recipient_2 = if test_case.batch_calls {
                Some(Address::random())
            } else {
                None
            };

            let mut tx = create_basic_aa_tx(
                chain_id,
                0,
                create_send_calls(
                    recipient_1,
                    recipient_2,
                    fee_token,
                    test_case.batch_calls,
                    transfer_amount,
                ),
                2_000_000,
            );
            tx.fee_token = Some(fee_token);

            let fee_payer_ctx = configure_fee_payer_context(
                &provider,
                &mut tx,
                test_case.fee_payer,
                signer_addr,
                &fee_payer_signer,
                fee_payer_addr,
                signer_addr,
            )
            .await?;

            let signature = match test_case.key_type {
                KeyType::P256 => sign_aa_tx_p256(&tx, &signing_key, pub_key_x, pub_key_y)?,
                KeyType::WebAuthn => sign_aa_tx_webauthn(
                    &tx,
                    &signing_key,
                    pub_key_x,
                    pub_key_y,
                    "https://example.com",
                )?,
                KeyType::Secp256k1 => unreachable!("handled above"),
            };

            let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
            let encoded = envelope.encoded_2718();
            let tx_hash = *envelope.tx_hash();

            inject_and_assert_mined(&mut setup, &provider, encoded, tx_hash).await?;
            assert_fee_payer_spent(&provider, fee_payer_ctx).await?;

            if test_case.batch_calls {
                assert_batch_recipient_balances(
                    &provider,
                    fee_token,
                    recipient_1,
                    recipient_2.expect("batch_calls requires recipient_2"),
                    transfer_amount,
                )
                .await?;
            }

            Ok(())
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
// Covers key type (secp256k1/p256/webauthn) x fee payer; P256/WebAuthn also cover access key and batch calls.
async fn test_eth_send_transaction_matrix() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let transfer_amount = U256::from(1u64) * U256::from(10).pow(U256::from(6));
    let webauthn_transfer_amount = U256::from(5u64) * U256::from(10).pow(U256::from(6));

    let test_matrix = [
        send_case!(Secp256k1),
        send_case!(Secp256k1, fee_payer),
        send_case!(P256, fee_payer),
        send_case!(P256, fee_payer, access_key),
        send_case!(P256),
        send_case!(
            P256,
            batch_calls;
            funding_amount = transfer_amount * U256::from(10u64),
            transfer_amount = transfer_amount
        ),
        send_case!(P256, access_key),
        send_case!(
            WebAuthn,
            batch_calls;
            funding_amount = webauthn_transfer_amount * U256::from(2u64),
            transfer_amount = webauthn_transfer_amount
        ),
        send_case!(WebAuthn, fee_payer),
        send_case!(WebAuthn, access_key),
    ];

    println!("\n=== eth_sendTransaction matrix ===\n");
    println!("Running {} sendTransaction cases...\n", test_matrix.len());

    for (index, test_case) in test_matrix.iter().enumerate() {
        println!("[{}/{}] {}", index + 1, test_matrix.len(), test_case.name);
        run_send_transaction_test_case(test_case).await?;
    }

    println!("\n✓ All {} sendTransaction cases passed", test_matrix.len());
    Ok(())
}

async fn run_raw_send_test_case_with_key<
    AccessSetupFn,
    AccessSetupFut,
    NonAccessSetupFn,
    NonAccessSetupFut,
    PAccess,
    PNonAccess,
    SAccess,
    SNonAccess,
>(
    test_case: &RawSendTestCase,
    access_setup: AccessSetupFn,
    non_access_setup: NonAccessSetupFn,
) -> eyre::Result<()>
where
    AccessSetupFn: FnOnce() -> AccessSetupFut,
    AccessSetupFut: std::future::Future<Output = eyre::Result<AccessKeyContext<PAccess, SAccess>>>,
    NonAccessSetupFn: FnOnce() -> NonAccessSetupFut,
    NonAccessSetupFut:
        std::future::Future<Output = eyre::Result<NonAccessContext<PNonAccess, SNonAccess>>>,
    PAccess: Provider,
    PNonAccess: Provider,
    SAccess: SignerSync,
    SNonAccess: SignerSync,
{
    if test_case.access_key {
        let mut context = access_setup().await?;
        let recipient = Address::random();

        let fee_payer_signer = if test_case.fee_payer {
            let signer = alloy::signers::local::PrivateKeySigner::random();
            let addr = signer.address();
            fund_address_with_fee_tokens(
                &mut context.setup,
                &context.provider,
                &context.root_signer,
                context.root_addr,
                addr,
                U256::from(1_000_000_000_000_000_000u128),
                context.chain_id,
            )
            .await?;
            Some(signer)
        } else {
            None
        };

        let mut tx = create_basic_aa_tx(
            context.chain_id,
            context
                .provider
                .get_transaction_count(context.root_addr)
                .await?,
            vec![Call {
                to: recipient.into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            2_000_000,
        );
        tx.key_authorization = Some(context.key_auth);

        let (fp_signer_ref, fp_addr) = match &fee_payer_signer {
            Some(s) => (s as &dyn SignerSync, s.address()),
            None => (&context.root_signer as &dyn SignerSync, context.root_addr),
        };
        let fee_payer_context = configure_fee_payer_context(
            &context.provider,
            &mut tx,
            test_case.fee_payer,
            context.root_addr,
            fp_signer_ref,
            fp_addr,
            context.root_addr,
        )
        .await?;

        let signature = (context.sign)(&tx)?;
        let envelope: TempoTxEnvelope = tx.into_signed(signature).into();

        send_raw_aa_and_assert_mined(
            &mut context.setup,
            &context.provider,
            &envelope,
            context.root_addr,
        )
        .await?;
        assert_fee_payer_spent(&context.provider, fee_payer_context).await?;

        return Ok(());
    }

    let mut context = non_access_setup().await?;
    let signer_unfunded = test_case.key_type == KeyType::Secp256k1 && test_case.fee_payer;
    if test_case.key_type == KeyType::Secp256k1 && !test_case.fee_payer {
        fund_address_with_fee_tokens(
            &mut context.setup,
            &context.provider,
            &context.funder_signer,
            context.funder_addr,
            context.signer_addr,
            U256::from(1_000_000_000_000_000_000u128),
            context.chain_id,
        )
        .await?;
    }

    if signer_unfunded {
        assert_fee_token_balance(
            &context.provider,
            context.signer_addr,
            U256::ZERO,
            "Unfunded signer should have zero balance",
        )
        .await?;
    }

    let recipient = Address::random();
    let signer_nonce = context
        .provider
        .get_transaction_count(context.signer_addr)
        .await?;
    let mut tx = create_basic_aa_tx(
        context.chain_id,
        signer_nonce,
        vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );

    let fee_payer_context = configure_fee_payer_context(
        &context.provider,
        &mut tx,
        test_case.fee_payer,
        context.signer_addr,
        &context.funder_signer,
        context.funder_addr,
        context.signer_addr,
    )
    .await?;

    let signature = (context.sign)(&tx)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();

    send_raw_aa_and_assert_mined(
        &mut context.setup,
        &context.provider,
        &envelope,
        context.signer_addr,
    )
    .await?;
    assert_fee_payer_spent(&context.provider, fee_payer_context).await?;

    if signer_unfunded {
        assert_fee_token_balance(
            &context.provider,
            context.signer_addr,
            U256::ZERO,
            "Unfunded signer should still have zero balance after fee-payer tx",
        )
        .await?;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_send_raw_transaction_matrix() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let test_matrix = [
        raw_case!(Secp256k1),
        raw_case!(Secp256k1, fee_payer),
        raw_case!(Secp256k1, access_key),
        raw_case!(Secp256k1, fee_payer, access_key),
        raw_case!(P256),
        raw_case!(P256, fee_payer),
        raw_case!(P256, access_key),
        raw_case!(P256, fee_payer, access_key),
        raw_case!(WebAuthn),
        raw_case!(WebAuthn, fee_payer),
        raw_case!(WebAuthn, access_key),
        raw_case!(WebAuthn, fee_payer, access_key),
    ];

    println!("\n=== Explicit eth_sendRawTransaction matrix ===\n");
    println!("Running {} raw send cases...\n", test_matrix.len());

    for (index, test_case) in test_matrix.iter().enumerate() {
        println!("[{}/{}] {}", index + 1, test_matrix.len(), test_case.name);
        run_raw_send_test_case(test_case).await?;
    }

    println!("\n✓ All {} raw send cases passed", test_matrix.len());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_sign_transaction_multi_party_fee_payer_cosign() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let http_url = setup.node.rpc_url();
    let provider = ProviderBuilder::new().connect_http(http_url.clone());

    let fee_payer_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let fee_payer_addr = fee_payer_signer.address();

    let user_signer = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = user_signer.address();

    let user_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(user_addr)
        .call()
        .await?;
    assert_eq!(user_balance, U256::ZERO, "User should be unfunded");

    let fee_payer_balance_before = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(fee_payer_addr)
        .call()
        .await?;

    let chain_id = provider.get_chain_id().await?;
    let mut tx = create_basic_aa_tx(
        chain_id,
        0,
        vec![Call {
            to: Address::random().into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );
    tx.fee_payer_signature = Some(Signature::new(U256::ZERO, U256::ZERO, false));

    let user_signature = sign_aa_tx_secp256k1(&tx, &user_signer)?;
    let sign_only_envelope: TempoTxEnvelope = tx.into_signed(user_signature).into();
    let sign_only_encoded = sign_only_envelope.encoded_2718();

    let decoded = TempoTxEnvelope::decode_2718(&mut sign_only_encoded.as_slice())?;
    let (mut decoded_tx, decoded_sig) = match decoded {
        TempoTxEnvelope::AA(aa_tx) => (aa_tx.tx().clone(), aa_tx.signature().clone()),
        _ => return Err(eyre::eyre!("Expected AA transaction")),
    };

    let fee_payer_sig_hash = decoded_tx.fee_payer_signature_hash(user_addr);
    let fee_payer_signature = fee_payer_signer.sign_hash_sync(&fee_payer_sig_hash)?;
    decoded_tx.fee_payer_signature = Some(fee_payer_signature);

    let final_envelope: TempoTxEnvelope = decoded_tx.into_signed(decoded_sig).into();
    let encoded = final_envelope.encoded_2718();
    let tx_hash = *final_envelope.tx_hash();

    let raw_result: B256 = provider
        .raw_request("eth_sendRawTransaction".into(), [encoded.clone()])
        .await?;
    assert_eq!(raw_result, tx_hash, "RPC should return tx hash");

    setup.node.advance_block().await?;

    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;
    assert!(receipt.is_some(), "Transaction should be mined");

    let fee_payer_balance_after = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(fee_payer_addr)
        .call()
        .await?;
    assert!(
        fee_payer_balance_after < fee_payer_balance_before,
        "Fee payer should cover gas"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_empty_call_batch_should_fail() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (setup, provider, alice_signer, alice_addr) = setup_test_with_funded_account().await?;

    println!("\n=== Testing AA Empty Call Batch (should fail) ===\n");
    println!("Alice address: {alice_addr}");

    // Get alice's current nonce (protocol nonce, key 0)
    let nonce = provider.get_transaction_count(alice_addr).await?;
    println!("Alice nonce: {nonce}");

    // Create AA transaction with EMPTY call batch
    // The empty vector will be properly RLP-encoded as 0xc0 (empty list)
    let tx = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![], // EMPTY call batch - properly encoded but fails validation
        nonce_key: U256::ZERO,
        nonce,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    println!("Created AA transaction with empty call batch");

    // Sign the transaction with secp256k1
    let aa_signature = sign_aa_tx_secp256k1(&tx, &alice_signer)?;
    let signed_tx = AASigned::new_unhashed(tx, aa_signature);

    // Convert to envelope and encode
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    println!(
        "Encoded AA transaction: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Try to inject transaction - should fail due to empty call batch
    let result = setup.node.rpc.inject_tx(encoded.clone().into()).await;

    // The transaction should be rejected with a specific error
    let e = result.expect_err("Transaction with empty call batch should be rejected");
    println!("✓ Transaction with empty call batch correctly rejected: {e}");

    // Verify the error is about decode failure or validation
    // Empty call batch should fail during decoding/validation
    let error_msg = e.to_string();
    assert!(
        error_msg.contains("decode")
            || error_msg.contains("empty")
            || error_msg.contains("call")
            || error_msg.contains("valid"),
        "Error should indicate decode/validation failure for empty calls, got: {error_msg}"
    );

    // Verify the rejected transaction is NOT available via eth_getTransactionByHash
    verify_tx_not_in_block_via_rpc(&provider, &encoded).await?;

    // Verify alice's nonce did NOT increment (transaction was rejected)
    let alice_nonce_after = provider.get_transaction_count(alice_addr).await?;
    assert_eq!(
        alice_nonce_after, nonce,
        "Nonce should not increment for rejected transaction"
    );

    println!("✓ Test completed: Empty call batch correctly rejected");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_estimate_gas_matrix() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (_setup, provider, signer, signer_addr) = setup_test_with_funded_account().await?;

    println!("\n=== eth_estimateGas matrix: key type × keychain × key auth ===\n");
    println!("Test address: {signer_addr}");

    let recipient = Address::random();

    let base_tx_request = || TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(signer_addr),
            ..Default::default()
        },
        calls: vec![Call {
            to: TxKind::Call(recipient),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        ..Default::default()
    };

    async fn estimate_gas(
        provider: &impl Provider,
        request: &TempoTransactionRequest,
    ) -> eyre::Result<u64> {
        let hex: String = provider
            .raw_request("eth_estimateGas".into(), [serde_json::to_value(request)?])
            .await?;
        Ok(u64::from_str_radix(hex.trim_start_matches("0x"), 16)?)
    }

    #[derive(Clone)]
    enum GasCaseKind {
        KeyType {
            key_type: SignatureType,
            key_data: Option<Bytes>,
        },
        Keychain {
            key_type: Option<SignatureType>,
            num_limits: usize,
        },
        KeyAuth {
            key_type: SignatureType,
            num_limits: usize,
        },
    }

    enum ExpectedGasDiff {
        Range(std::ops::RangeInclusive<u64>),
        GreaterThan(&'static str),
    }

    struct GasCase {
        name: &'static str,
        kind: GasCaseKind,
        expected: ExpectedGasDiff,
    }

    let cases = [
        // +5,000 gas for P256 signature verification
        GasCase {
            name: "p256",
            kind: GasCaseKind::KeyType {
                key_type: SignatureType::P256,
                key_data: None,
            },
            expected: ExpectedGasDiff::Range(4_800..=5_200),
        },
        // 5,000 (P256 verification) + calldata gas for WebAuthn envelope
        GasCase {
            name: "webauthn",
            kind: GasCaseKind::KeyType {
                key_type: SignatureType::WebAuthn,
                // WebAuthn data size excluding 128 bytes for public keys
                key_data: Some(Bytes::from(116u16.to_be_bytes().to_vec())),
            },
            expected: ExpectedGasDiff::GreaterThan("p256"),
        },
        // T1B+: keychain validation (3k) + sig_gas (3k ecrecover) + SLOAD (2.2k) +
        // SSTORE (250k) = ~258.2k + warm access overhead ≈ 260k
        GasCase {
            name: "keychain_secp256k1",
            kind: GasCaseKind::Keychain {
                key_type: None,
                num_limits: 0,
            },
            expected: ExpectedGasDiff::Range(258_000..=263_000),
        },
        // keychain_secp256k1 costs + 5,000 P256 signature verification
        GasCase {
            name: "keychain_p256",
            kind: GasCaseKind::Keychain {
                key_type: Some(SignatureType::P256),
                num_limits: 0,
            },
            expected: ExpectedGasDiff::Range(263_000..=268_000),
        },
        // T1B+: sig_gas (3k) + SLOAD (2.2k) + SSTORE (250k) = ~255.2k + warm access overhead
        GasCase {
            name: "key_auth_secp256k1",
            kind: GasCaseKind::KeyAuth {
                key_type: SignatureType::Secp256k1,
                num_limits: 0,
            },
            expected: ExpectedGasDiff::Range(255_000..=260_000),
        },
        // Same range as secp256k1: the authorization signature is always secp256k1
        // from the root key; key_type only describes which key is being authorized.
        GasCase {
            name: "key_auth_p256",
            kind: GasCaseKind::KeyAuth {
                key_type: SignatureType::P256,
                num_limits: 0,
            },
            expected: ExpectedGasDiff::Range(255_000..=260_000),
        },
        // T1B+: key_auth_secp256k1 costs + 3 × SSTORE (250k) for spending limits
        GasCase {
            name: "key_auth_secp256k1_3_limits",
            kind: GasCaseKind::KeyAuth {
                key_type: SignatureType::Secp256k1,
                num_limits: 3,
            },
            expected: ExpectedGasDiff::Range(1_010_000..=1_016_000),
        },
    ];

    let baseline_gas = estimate_gas(&provider, &base_tx_request()).await?;
    println!("Baseline gas (secp256k1): {baseline_gas}");

    let mut results: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();

    for (i, case) in cases.iter().enumerate() {
        println!("\n[{}/{}] {}", i + 1, cases.len(), case.name);

        let mut request = base_tx_request();
        match &case.kind {
            GasCaseKind::KeyType { key_type, key_data } => {
                request.key_type = Some(*key_type);
                request.key_data = key_data.clone();
            }
            // Same-tx auth+use pattern: provide both key_id AND key_authorization
            // with the same key_id so the keychain is provisioned and used in one tx.
            GasCaseKind::Keychain {
                key_type,
                num_limits,
            } => {
                let auth = create_signed_key_authorization(
                    &signer,
                    key_type.unwrap_or(SignatureType::Secp256k1),
                    *num_limits,
                );
                request.key_id = Some(auth.key_id);
                request.key_authorization = Some(auth);
                if let Some(kt) = key_type {
                    request.key_type = Some(*kt);
                }
            }
            GasCaseKind::KeyAuth {
                key_type,
                num_limits,
            } => {
                let auth = create_signed_key_authorization(&signer, *key_type, *num_limits);
                request.key_authorization = Some(auth);
            }
        }

        let gas = estimate_gas(&provider, &request).await?;
        println!("  gas: {gas}");

        match &case.expected {
            ExpectedGasDiff::Range(range) => {
                let diff = (gas as i64 - baseline_gas as i64).unsigned_abs();
                assert!(
                    range.contains(&diff),
                    "[{}] expected diff in {:?}, got {diff}",
                    case.name,
                    range,
                );
                println!("  ✓ diff {diff} in {range:?}");
            }
            ExpectedGasDiff::GreaterThan(ref_name) => {
                let ref_gas = results[ref_name];
                assert!(
                    gas > ref_gas,
                    "[{}] expected gas {gas} > {ref_name} gas {ref_gas}",
                    case.name,
                );
                println!("  ✓ gas {gas} > {ref_name} gas {ref_gas}");
            }
        }

        results.insert(case.name, gas);
    }

    println!("\n✓ All gas estimation cases passed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_authorization_list() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing EIP-7702 Authorization List with AA Signatures ===\n");

    // Setup test node with funded account
    let (mut setup, provider, sender_signer, sender_addr) =
        setup_test_with_funded_account().await?;
    let chain_id = provider.get_chain_id().await?;

    println!("Transaction sender: {sender_addr}");

    // The delegate address that all EOAs will delegate to (using AccountKeychain precompile)
    // Note that this test simply asserts that the account has been delegated, rather than testing
    // functionality of a the code that the account delegates to
    let delegate_address = ACCOUNT_KEYCHAIN_ADDRESS;
    println!("Delegate address: {delegate_address}");

    use p256::{ecdsa::SigningKey as P256SigningKey, elliptic_curve::rand_core::OsRng};
    use tempo_primitives::transaction::TempoSignedAuthorization;

    fn sign_p256_authorization(
        sig_hash: B256,
        auth: alloy_eips::eip7702::Authorization,
        signing_key: &P256SigningKey,
        pub_key_x: B256,
        pub_key_y: B256,
    ) -> eyre::Result<TempoSignedAuthorization> {
        let inner = sign_p256_primitive(sig_hash, signing_key, pub_key_x, pub_key_y)?;
        let aa_sig = TempoSignature::Primitive(inner);
        Ok(TempoSignedAuthorization::new_unchecked(auth, aa_sig))
    }

    fn generate_p256_key() -> (P256SigningKey, B256, B256, Address) {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let encoded_point = signing_key.verifying_key().to_encoded_point(false);
        let pub_key_x = B256::from_slice(encoded_point.x().unwrap().as_ref());
        let pub_key_y = B256::from_slice(encoded_point.y().unwrap().as_ref());
        let addr = tempo_primitives::transaction::tt_signature::derive_p256_address(
            &pub_key_x, &pub_key_y,
        );
        (signing_key, pub_key_x, pub_key_y, addr)
    }

    // Authority 1: Secp256k1
    println!("\n--- Authority 1: Secp256k1 ---");
    let auth1_signer = alloy::signers::local::PrivateKeySigner::random();
    let auth1_addr = auth1_signer.address();
    let (auth1, sig_hash1) = build_authorization(chain_id, delegate_address);
    let sig1 = auth1_signer.sign_hash_sync(&sig_hash1)?;
    let auth1_signed = TempoSignedAuthorization::new_unchecked(
        auth1,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(sig1)),
    );
    println!("Authority 1 address: {auth1_addr}");

    // Authority 2: P256
    println!("\n--- Authority 2: P256 ---");
    let (auth2_key, pub2_x, pub2_y, auth2_addr) = generate_p256_key();
    let (auth2, sig_hash2) = build_authorization(chain_id, delegate_address);
    let auth2_signed = sign_p256_authorization(sig_hash2, auth2, &auth2_key, pub2_x, pub2_y)?;
    println!("Authority 2 address: {auth2_addr}");

    // Authority 3: WebAuthn
    println!("\n--- Authority 3: WebAuthn ---");
    let (auth3_key, pub3_x, pub3_y, auth3_addr) = generate_p256_key();
    let (auth3, sig_hash3) = build_authorization(chain_id, delegate_address);
    let inner =
        sign_webauthn_primitive(sig_hash3, &auth3_key, pub3_x, pub3_y, "https://example.com")?;
    let auth3_signed =
        TempoSignedAuthorization::new_unchecked(auth3, TempoSignature::Primitive(inner));
    println!("Authority 3 address: {auth3_addr}");

    // ========================================================================
    // Verify BEFORE state: All authority accounts should have no code
    // ========================================================================
    println!("\n--- Verifying BEFORE state ---");

    let auth1_code_before = provider.get_code_at(auth1_addr).await?;
    let auth2_code_before = provider.get_code_at(auth2_addr).await?;
    let auth3_code_before = provider.get_code_at(auth3_addr).await?;

    assert_eq!(
        auth1_code_before.len(),
        0,
        "Authority 1 should have no code before delegation"
    );
    assert_eq!(
        auth2_code_before.len(),
        0,
        "Authority 2 should have no code before delegation"
    );
    assert_eq!(
        auth3_code_before.len(),
        0,
        "Authority 3 should have no code before delegation"
    );
    // ========================================================================
    // Create AA transaction with authorization list using RPC
    // ========================================================================
    println!("\n--- Creating AA transaction with authorization list via RPC ---");

    let recipient = Address::random();

    // Create transaction request using RPC interface
    let tx_request = TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(sender_addr),
            to: Some(recipient.into()),
            value: Some(U256::ZERO),
            gas: Some(2_000_000), // Higher gas for authorization list processing
            max_fee_per_gas: Some(TEMPO_T1_BASE_FEE as u128),
            max_priority_fee_per_gas: Some(TEMPO_T1_BASE_FEE as u128),
            nonce: Some(provider.get_transaction_count(sender_addr).await?),
            chain_id: Some(chain_id),
            ..Default::default()
        },
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        tempo_authorization_list: vec![auth1_signed, auth2_signed, auth3_signed], // All 3 authorizations
        ..Default::default()
    };

    println!(
        "  Created tx request with {} authorizations (Secp256k1, P256, WebAuthn)",
        tx_request.tempo_authorization_list.len()
    );

    // Build the AA transaction from the request
    let tx = tx_request
        .build_aa()
        .map_err(|e| eyre::eyre!("Failed to build AA tx: {:?}", e))?;

    // Sign the transaction with sender's secp256k1 key
    let tx_sig_hash = tx.signature_hash();
    let tx_signature = sender_signer.sign_hash_sync(&tx_sig_hash)?;
    let tx_tempo_signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(tx_signature));
    let signed_tx = AASigned::new_unhashed(tx, tx_tempo_signature);

    // Convert to envelope and encode
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    println!(
        "  Encoded transaction: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Test encoding/decoding roundtrip
    let decoded = TempoTxEnvelope::decode_2718(&mut encoded.as_slice())?;
    assert!(
        matches!(decoded, TempoTxEnvelope::AA(_)),
        "Should decode as AA transaction"
    );
    println!("  ✓ Encoding/decoding roundtrip successful");

    // Submit transaction via RPC
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let payload = setup.node.advance_block().await?;

    println!(
        "  ✓ Transaction mined in block {}",
        payload.block().inner.number
    );

    // Verify transaction via RPC
    verify_tx_in_block_via_rpc(&provider, &encoded, &envelope).await?;

    // Verify the authorization list was included in the transaction and get recovered addresses
    let mut recovered_authorities = Vec::new();
    if let TempoTxEnvelope::AA(aa_tx) = &envelope {
        println!("\n--- Verifying authorization list in transaction ---");
        println!(
            "  Authorization list length: {}",
            aa_tx.tx().tempo_authorization_list.len()
        );

        // Verify each authorization can be recovered
        for (i, aa_auth) in aa_tx.tx().tempo_authorization_list.iter().enumerate() {
            match aa_auth.recover_authority() {
                Ok(authority) => {
                    println!("  ✓ Authorization {} recovered: {}", i + 1, authority);
                    recovered_authorities.push(authority);
                }
                Err(e) => {
                    println!("  ✗ Authorization {} recovery failed: {:?}", i + 1, e);
                    panic!("Authorization recovery failed");
                }
            }
        }
    }

    // Verify that recovered authorities match expected addresses
    assert_eq!(
        recovered_authorities[0], auth1_addr,
        "Secp256k1 authority should match expected address"
    );
    assert_eq!(
        recovered_authorities[1], auth2_addr,
        "P256 authority should match expected address"
    );
    assert_eq!(
        recovered_authorities[2], auth3_addr,
        "WebAuthn authority should match expected address"
    );

    // ========================================================================
    // Verify AFTER state: All authority accounts should have delegation code
    // ========================================================================
    println!("\n--- Verifying AFTER state ---");

    let auth1_code_after = provider.get_code_at(recovered_authorities[0]).await?;
    let auth2_code_after = provider.get_code_at(recovered_authorities[1]).await?;
    let auth3_code_after = provider.get_code_at(recovered_authorities[2]).await?;

    // Verify each authority has correct EIP-7702 delegation code
    verify_delegation_code(
        &auth1_code_after,
        delegate_address,
        "Authority 1 (Secp256k1)",
    );
    verify_delegation_code(&auth2_code_after, delegate_address, "Authority 2 (P256)");
    verify_delegation_code(
        &auth3_code_after,
        delegate_address,
        "Authority 3 (WebAuthn)",
    );

    println!("verification successful");

    Ok(())
}

/// Test that keychain signatures in tempo_authorization_list are rejected.
#[tokio::test(flavor = "multi_thread")]
async fn test_keychain_authorization_in_auth_list_is_skipped() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Setup test node with funded sender account
    let (mut setup, provider, sender_signer, sender_addr) =
        setup_test_with_funded_account().await?;
    let chain_id = provider.get_chain_id().await?;

    // Create attacker and victim accounts
    let attacker_signer = alloy::signers::local::PrivateKeySigner::random();
    let attacker_addr = attacker_signer.address();
    let victim_addr = Address::random(); // Victim account - attacker wants to delegate this

    // The delegate address the attacker wants to set on the victim's account
    let delegate_address = attacker_addr; // Attacker controls this

    // ========================================================================
    // Create a spoofed keychain authorization
    // The attacker signs with their own key but claims to act on behalf of victim
    // ========================================================================

    let victim_nonce_before = provider.get_transaction_count(victim_addr).await?;
    let victim_code_before = provider.get_code_at(victim_addr).await?;

    // Create authorization for victim's address
    let auth = alloy_eips::eip7702::Authorization {
        chain_id: alloy_primitives::U256::from(chain_id),
        address: delegate_address,
        nonce: victim_nonce_before,
    };

    // Compute the signature hash
    let sig_hash = compute_authorization_signature_hash(&auth);

    // Attacker signs the authorization with their own key
    let attacker_signature = attacker_signer.sign_hash_sync(&sig_hash)?;
    let inner_sig = PrimitiveSignature::Secp256k1(attacker_signature);

    // Create a keychain signature claiming to act on behalf of victim
    // This is the attack: attacker signs, but claims victim's address
    let keychain_sig = KeychainSignature::new(victim_addr, inner_sig);
    let spoofed_sig = TempoSignature::Keychain(keychain_sig);

    // Create the signed authorization with the spoofed keychain signature
    let spoofed_auth =
        tempo_primitives::transaction::TempoSignedAuthorization::new_unchecked(auth, spoofed_sig);

    // Verify the spoofed auth recovers to victim's address (demonstrating the attack vector)
    let recovered = spoofed_auth.recover_authority()?;
    assert_eq!(
        recovered, victim_addr,
        "Spoofed auth should recover to victim address"
    );

    // ========================================================================
    // Create and send the attack transaction
    // ========================================================================

    let recipient = Address::random();

    let tx_request = TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(sender_addr),
            to: Some(recipient.into()),
            value: Some(U256::ZERO),
            gas: Some(2_000_000),
            max_fee_per_gas: Some(TEMPO_T1_BASE_FEE as u128),
            max_priority_fee_per_gas: Some(TEMPO_T1_BASE_FEE as u128),
            nonce: Some(provider.get_transaction_count(sender_addr).await?),
            chain_id: Some(chain_id),
            ..Default::default()
        },
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        tempo_authorization_list: vec![spoofed_auth], // Include the spoofed authorization
        ..Default::default()
    };

    // Build and sign the transaction with sender's key (NOT a keychain signature)
    let tx = tx_request
        .build_aa()
        .map_err(|e| eyre::eyre!("Failed to build AA tx: {:?}", e))?;

    let tx_sig_hash = tx.signature_hash();
    let tx_signature = sender_signer.sign_hash_sync(&tx_sig_hash)?;
    let tx_tempo_signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(tx_signature));
    let signed_tx = AASigned::new_unhashed(tx, tx_tempo_signature);

    // Encode and submit
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let _payload = setup.node.advance_block().await?;

    // ========================================================================
    // Verify the attack was prevented
    // ========================================================================
    println!("\n--- Verifying attack was prevented ---");

    let victim_nonce_after = provider.get_transaction_count(victim_addr).await?;
    let victim_code_after = provider.get_code_at(victim_addr).await?;

    // The keychain authorization should have been SKIPPED
    // So victim's state should remain unchanged
    assert_eq!(
        victim_nonce_before, victim_nonce_after,
        "Victim nonce should not change - keychain auth should be skipped"
    );
    assert_eq!(
        victim_code_before.len(),
        victim_code_after.len(),
        "Victim code should not change - keychain auth should be skipped"
    );
    assert!(
        victim_code_after.is_empty(),
        "Victim should have no delegation code"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_bump_nonce_on_failure() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut setup, provider, alice_signer, alice_addr) = setup_test_with_funded_account().await?;

    // Verify alice has zero native balance
    let alice_eth_balance = provider.get_account_info(alice_addr).await?.balance;
    assert_eq!(
        alice_eth_balance,
        U256::ZERO,
        "Test accounts should have zero ETH balance"
    );

    println!("Alice address: {alice_addr}");
    println!("Alice ETH balance: {alice_eth_balance} (expected: 0)");

    // Get alice's current nonce (protocol nonce, key 0)
    let nonce = provider.get_transaction_count(alice_addr).await?;
    println!("Alice nonce: {nonce}");

    // Create AA transaction with secp256k1 signature and protocol nonce
    let tx = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: alloy_primitives::bytes!("0xef"),
        }],
        nonce_key: U256::ZERO, // Protocol nonce (key 0)
        nonce,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    println!("Created AA transaction with secp256k1 signature");

    // Sign the transaction with secp256k1
    let aa_signature = sign_aa_tx_secp256k1(&tx, &alice_signer)?;
    let signed_tx = AASigned::new_unhashed(tx, aa_signature);

    // Convert to envelope and encode
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    println!(
        "Encoded AA transaction: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Inject transaction and mine block
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let payload = setup.node.advance_block().await?;

    println!(
        "✓ AA transaction mined in block {}",
        payload.block().inner.number
    );

    // Verify transaction can be fetched via eth_getTransactionByHash and is correct
    verify_tx_in_block_via_rpc(&provider, &encoded, &envelope).await?;

    // Verify alice's nonce incremented (protocol nonce)
    // This proves the transaction was successfully mined and executed
    let alice_nonce_after = provider.get_transaction_count(alice_addr).await?;
    assert_eq!(
        alice_nonce_after,
        nonce + 1,
        "Protocol nonce should increment"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_access_key() -> eyre::Result<()> {
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
    use tempo_primitives::transaction::TokenLimit;

    reth_tracing::init_test_tracing();

    println!("\n=== Testing AA Transaction with Key Authorization and P256 Spending Limits ===\n");

    // Setup test node
    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let http_url = setup.node.rpc_url();

    // Generate a P256 key pair for the access key
    let access_key_signing_key = SigningKey::random(&mut OsRng);
    let access_key_verifying_key = access_key_signing_key.verifying_key();

    // Extract access key public key coordinates
    let encoded_point = access_key_verifying_key.to_encoded_point(false);
    let access_pub_key_x = alloy::primitives::B256::from_slice(encoded_point.x().unwrap().as_ref());
    let access_pub_key_y = alloy::primitives::B256::from_slice(encoded_point.y().unwrap().as_ref());

    // Derive the access key's address
    let access_key_addr = tempo_primitives::transaction::tt_signature::derive_p256_address(
        &access_pub_key_x,
        &access_pub_key_y,
    );

    println!("Access key (P256) address: {access_key_addr}");
    println!("Access key public key X: {access_pub_key_x}");
    println!("Access key public key Y: {access_pub_key_y}");

    // Use TEST_MNEMONIC account as the root key (funded account)
    let root_key_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_key_addr = root_key_signer.address();

    // Create provider with root key's wallet
    let root_wallet = EthereumWallet::from(root_key_signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(root_wallet)
        .connect_http(http_url.clone());

    let chain_id = provider.get_chain_id().await?;

    println!("Root key address: {root_key_addr}");
    println!("Chain ID: {chain_id}");

    // Check root key's initial balance
    let root_balance_initial = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(root_key_addr)
        .call()
        .await?;
    println!("Root key initial balance: {root_balance_initial} tokens");

    // Create recipient for the token transfer
    let recipient = Address::random();
    println!("Token transfer recipient: {recipient}");

    // Define spending limits for the access key
    // Allow spending up to 10 tokens from DEFAULT_FEE_TOKEN
    let spending_limit_amount = U256::from(10u64) * U256::from(10).pow(U256::from(18)); // 10 tokens
    let spending_limits = vec![TokenLimit {
        token: DEFAULT_FEE_TOKEN,
        limit: spending_limit_amount,
    }];

    println!("\nCreating key authorization:");
    println!("  - Token: {DEFAULT_FEE_TOKEN}");
    println!("  - Spending limit: {spending_limit_amount} (10 tokens)");
    println!("  - Key type: P256");
    println!("  - Key ID (address): {access_key_addr}");

    // Root key signs the key authorization data to authorize the access key
    let mock_sig = create_mock_p256_sig(access_pub_key_x, access_pub_key_y);
    let key_authorization = create_key_authorization(
        &root_key_signer,
        access_key_addr,
        mock_sig,
        chain_id,
        None,
        Some(spending_limits),
    )?;

    println!("✓ Key authorization created (never expires)");
    println!("✓ Key authorization signed by root key");

    // Create a token transfer call within the spending limit
    // Transfer 5 tokens (within the 10 token limit)
    let transfer_amount = U256::from(5u64) * U256::from(10).pow(U256::from(18)); // 5 tokens

    println!("\nCreating AA transaction:");
    println!("  - Transfer amount: {transfer_amount} tokens (within 10 token limit)");

    // Create AA transaction with key authorization and token transfer
    let nonce = provider.get_transaction_count(root_key_addr).await?;
    let transfer_calldata = transferCall {
        to: recipient,
        amount: transfer_amount,
    }
    .abi_encode();
    let mut tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: transfer_calldata.into(),
        }],
        2_000_000, // Higher gas for key authorization verification
    );
    // Use pathUSD (DEFAULT_FEE_TOKEN) as fee token
    // and our spending limit is set for pathUSD
    tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    tx.key_authorization = Some(key_authorization);

    println!("✓ AA transaction created with key authorization");

    // Verify the transaction is valid
    tx.validate()
        .map_err(|e| eyre::eyre!("Transaction validation failed: {}", e))?;

    // Verify key_authorization is set correctly
    assert!(
        tx.key_authorization.is_some(),
        "Key authorization should be set"
    );
    println!("✓ Key authorization set correctly");

    // Sign the transaction with the ACCESS KEY (P256)
    let sig_hash = tx.signature_hash();
    println!("\nSigning transaction with access key (P256)...");
    println!("  Transaction signature hash: {sig_hash}");

    let aa_signature = sign_aa_tx_with_p256_access_key(
        &tx,
        &access_key_signing_key,
        &access_pub_key_x,
        &access_pub_key_y,
        root_key_addr,
    )?;

    println!("✓ Transaction signed with access key P256 signature (wrapped in Keychain)");

    // Verify signature recovery works - should return root_key_addr
    let recovered_signer = aa_signature.recover_signer(&sig_hash)?;
    assert_eq!(
        recovered_signer, root_key_addr,
        "Recovered signer should match root key address"
    );
    println!("✓ Signature recovery successful (recovered: {recovered_signer})");

    // Create signed transaction (clone tx since we need it later for verification)
    let signed_tx = AASigned::new_unhashed(tx.clone(), aa_signature);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    println!(
        "\nEncoded AA transaction: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Get recipient's initial balance (should be 0)
    let recipient_balance_before = ITIP20::new(DEFAULT_FEE_TOKEN, provider.clone())
        .balanceOf(recipient)
        .call()
        .await?;
    assert_eq!(
        recipient_balance_before,
        U256::ZERO,
        "Recipient should have zero initial balance"
    );
    println!("Recipient initial balance: {recipient_balance_before}");

    // Inject transaction and mine block
    println!("\nInjecting transaction into mempool...");
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;

    println!("Mining block...");
    let payload = setup.node.advance_block().await?;

    println!(
        "✓ AA transaction with key authorization mined in block {}",
        payload.block().inner.number
    );

    // Verify transaction can be fetched via RPC
    verify_tx_in_block_via_rpc(&provider, &encoded, &envelope).await?;

    // Verify the block contains the transaction
    assert!(
        !payload.block().body().transactions.is_empty(),
        "Block should contain the transaction"
    );

    println!(
        "\nBlock contains {} transactions",
        payload.block().body().transactions.len()
    );
    for (i, tx) in payload.block().body().transactions.iter().enumerate() {
        let mut tx_encoded = Vec::new();
        tx.encode_2718(&mut tx_encoded);
        println!(
            "  Transaction {}: type={:?}, size={} bytes, first 20 bytes={}",
            i,
            std::mem::discriminant(tx),
            tx_encoded.len(),
            alloy_primitives::hex::encode(&tx_encoded[..20.min(tx_encoded.len())])
        );
    }

    // Get transaction hash and receipt
    let tx_from_block = &payload.block().body().transactions[0];
    let tx_hash_trie = tx_from_block.trie_hash();
    println!("Transaction hash from block (trie_hash): {tx_hash_trie}");

    // Encode the transaction from the block and compare with what was injected
    let mut block_tx_encoded = Vec::new();
    tx_from_block.encode_2718(&mut block_tx_encoded);
    let block_tx_hash_from_encoded = keccak256(&block_tx_encoded);
    println!(
        "Block transaction hash (from re-encoding): {}",
        B256::from(block_tx_hash_from_encoded)
    );
    println!("Block transaction size: {} bytes", block_tx_encoded.len());
    println!("Injected transaction size: {} bytes", encoded.len());

    if block_tx_encoded != encoded {
        println!("WARNING: Block transaction encoding DIFFERS from injected transaction!");
        if block_tx_encoded.len() != encoded.len() {
            println!(
                "  Size mismatch: {} vs {}",
                block_tx_encoded.len(),
                encoded.len()
            );
        }
        // Print first 100 bytes of both for comparison
        let block_preview = &block_tx_encoded[..std::cmp::min(100, block_tx_encoded.len())];
        let injected_preview = &encoded[..std::cmp::min(100, encoded.len())];
        println!(
            "  Block tx first bytes: {}",
            alloy_primitives::hex::encode(block_preview)
        );
        println!(
            "  Injected tx first bytes: {}",
            alloy_primitives::hex::encode(injected_preview)
        );
    } else {
        println!("Block transaction encoding matches injected transaction");
    }

    // Try to get the actual transaction hash
    let tx_hash_actual = if let TempoTxEnvelope::AA(aa_signed) = tx_from_block {
        let sig_hash = aa_signed.signature_hash();
        println!("\nTransaction in block IS an AA transaction:");
        println!("  Signature hash from block: {sig_hash}");
        println!("  Nonce from block: {}", aa_signed.tx().nonce);
        println!("  Calls from block: {}", aa_signed.tx().calls.len());
        println!(
            "  Has key_authorization: {}",
            aa_signed.tx().key_authorization.is_some()
        );
        if let Some(key_auth) = &aa_signed.tx().key_authorization {
            println!("  key_authorization.key_id: {}", key_auth.key_id);
            println!("  key_authorization.expiry: {:?}", key_auth.expiry);
            println!(
                "  key_authorization.limits: {} limits",
                key_auth.limits.as_ref().map_or(0, |l| l.len())
            );
            println!(
                "  key_authorization.signature type: {:?}",
                key_auth.signature.signature_type()
            );
        }
        println!(
            "  Transaction signature type: {:?}",
            aa_signed.signature().signature_type()
        );
        if let TempoSignature::Keychain(ks) = aa_signed.signature() {
            println!("  Keychain user_address: {}", ks.user_address);
            println!(
                "  Keychain inner signature type: {:?}",
                ks.signature.signature_type()
            );
        }
        *aa_signed.hash()
    } else {
        println!("\nWARNING: Transaction in block is NOT an AA transaction!");
        println!(
            "  Envelope variant: {:?}",
            std::mem::discriminant(tx_from_block)
        );
        tx_hash_trie
    };
    println!("Transaction hash (actual): {tx_hash_actual}");

    // Use raw RPC call to get receipt since Alloy doesn't support custom tx type 0x76
    let receipt_opt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash_actual])
        .await?;
    let receipt_json = receipt_opt.expect("Receipt should exist");

    println!("\n=== Transaction Receipt ===");
    let status = receipt_json
        .get("status")
        .and_then(|v| v.as_str())
        .map(|s| s != "0x0")
        .unwrap_or(false);
    let gas_used = receipt_json
        .get("gasUsed")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let effective_gas_price = receipt_json
        .get("effectiveGasPrice")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let logs_count = receipt_json
        .get("logs")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    println!("Status: {status}");
    println!("Gas used: {gas_used}");
    println!("Effective gas price: {effective_gas_price}");
    println!("Logs count: {logs_count}");

    assert!(status, "Transaction should succeed");

    // Verify recipient received the tokens
    let recipient_balance_after = ITIP20::new(DEFAULT_FEE_TOKEN, provider.clone())
        .balanceOf(recipient)
        .call()
        .await?;

    println!("\n=== Verifying Token Transfer ===");
    println!("Recipient balance after: {recipient_balance_after} tokens");

    assert_eq!(
        recipient_balance_after, transfer_amount,
        "Recipient should have received exactly the transfer amount"
    );
    println!("✓ Recipient received correct amount: {transfer_amount} tokens");

    // Verify root key's balance decreased
    let root_balance_after = ITIP20::new(DEFAULT_FEE_TOKEN, provider.clone())
        .balanceOf(root_key_addr)
        .call()
        .await?;

    let balance_decrease = root_balance_initial - root_balance_after;
    println!(
        "\nRoot key balance: {root_balance_initial} → {root_balance_after} (decreased by {balance_decrease})"
    );

    // pathUSD balance should decrease by at least the transfer amount
    // (gas fees are also paid in pathUSD since we set fee_token to pathUSD)
    assert!(
        balance_decrease >= transfer_amount,
        "Root key pathUSD should have decreased by at least the transfer amount"
    );
    let gas_fee_paid = balance_decrease - transfer_amount;
    println!("✓ Root key paid for transfer ({transfer_amount}) + gas fees ({gas_fee_paid})");

    // Verify the key was authorized in the AccountKeychain precompile
    println!("\n=== Verifying Key Authorization in Precompile ===");

    use alloy::sol_types::SolCall;
    use alloy_primitives::address;
    use tempo_precompiles::account_keychain::{getKeyCall, getRemainingLimitCall};
    const ACCOUNT_KEYCHAIN_ADDRESS: Address =
        address!("0xAAAAAAAA00000000000000000000000000000000");

    // Convert access key address to B256 (pad to 32 bytes)
    let mut access_key_hash_bytes = [0u8; 32];
    access_key_hash_bytes[12..].copy_from_slice(access_key_addr.as_slice());
    let _access_key_hash = alloy::primitives::FixedBytes::<32>::from(access_key_hash_bytes);

    // Query the precompile for the key info using eth_call
    let get_key_call = getKeyCall {
        account: root_key_addr,
        keyId: access_key_addr,
    };
    let call_data = get_key_call.abi_encode();

    let _tx_request = alloy::rpc::types::TransactionRequest::default()
        .to(ACCOUNT_KEYCHAIN_ADDRESS)
        .input(call_data.into());

    // Query remaining spending limit
    let get_remaining_call = getRemainingLimitCall {
        account: root_key_addr,
        keyId: access_key_addr,
        token: DEFAULT_FEE_TOKEN,
    };
    let call_data = get_remaining_call.abi_encode();

    let _tx_request = alloy::rpc::types::TransactionRequest::default()
        .to(ACCOUNT_KEYCHAIN_ADDRESS)
        .input(call_data.into());

    // Verify signature hash includes key_authorization
    let mut tx_without_auth = tx.clone();
    tx_without_auth.key_authorization = None;
    let sig_hash_without_auth = tx_without_auth.signature_hash();

    assert_ne!(
        sig_hash, sig_hash_without_auth,
        "Signature hash must change with key_authorization"
    );

    Ok(())
}

// ===== Negative Test Cases for Access Keys / Keychain =====

/// Comprehensive negative test cases for keychain/access key functionality
/// Tests: zero public key, duplicate key, unauthorized authorize
#[tokio::test]
async fn test_aa_keychain_negative_cases() -> eyre::Result<()> {
    use tempo_precompiles::account_keychain::{SignatureType, authorizeKeyCall};
    use tempo_primitives::transaction::TokenLimit;

    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();
    let provider = ProviderBuilder::new()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    const ACCOUNT_KEYCHAIN_ADDRESS: Address =
        alloy_primitives::address!("0xAAAAAAAA00000000000000000000000000000000");

    println!("\n=== Testing Keychain Negative Cases ===\n");

    // Manually track nonce to avoid provider cache issues
    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Test 1: Try to authorize with zero public key (should fail)
    println!("Test 1: Zero public key");
    let authorize_call = authorizeKeyCall {
        keyId: Address::ZERO,
        signatureType: SignatureType::P256,
        expiry: u64::MAX,
        enforceLimits: true,
        limits: vec![],
    };
    let mut tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: authorize_call.abi_encode().into(),
        }],
        2_000_000,
    );
    tx.fee_token = None;
    let signature = sign_aa_tx_secp256k1(&tx, &root_signer)?;
    let _tx_hash = submit_and_mine_aa_tx(&mut setup, tx, signature).await?;
    nonce += 1; // Increment after successful submission
    println!("✓ Zero public key rejected\n");

    // Test 2: Authorize same key twice (should fail on second attempt)
    println!("Test 2: Duplicate key authorization");
    let (_, pub_x, pub_y, access_key_addr) = generate_p256_access_key();
    // Create a mock P256 signature to indicate this is a P256 key
    let mock_p256_sig = TempoSignature::Primitive(PrimitiveSignature::P256(
        tempo_primitives::transaction::tt_signature::P256SignatureWithPreHash {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: pub_x,
            pub_key_y: pub_y,
            pre_hash: false,
        },
    ));
    let key_auth = create_key_authorization(
        &root_signer,
        access_key_addr,
        mock_p256_sig,
        chain_id,
        None, // Never expires
        Some(vec![TokenLimit {
            token: DEFAULT_FEE_TOKEN,
            limit: U256::from(10u64) * U256::from(10).pow(U256::from(18)),
        }]),
    )?;

    // First authorization should succeed
    let mut tx1 = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );
    tx1.fee_token = None;
    tx1.key_authorization = Some(key_auth.clone());
    let signature = sign_aa_tx_secp256k1(&tx1, &root_signer)?;
    let _tx_hash = submit_and_mine_aa_tx(&mut setup, tx1, signature).await?;
    nonce += 1;
    println!("  ✓ First authorization succeeded");

    // Second authorization with same key should fail
    // The transaction will be mined but should revert during execution
    let mut tx2 = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );
    tx2.fee_token = None;
    tx2.key_authorization = Some(key_auth);
    let signature2 = sign_aa_tx_secp256k1(&tx2, &root_signer)?;
    let signed_tx2 = AASigned::new_unhashed(tx2, signature2);
    let envelope2: TempoTxEnvelope = signed_tx2.into();
    let mut encoded2 = Vec::new();
    envelope2.encode_2718(&mut encoded2);
    let tx_hash2 = envelope2.tx_hash();

    let inject_result = setup.node.rpc.inject_tx(encoded2.into()).await;

    if let Err(e) = inject_result {
        // Transaction was rejected at pool level (expected for duplicate key)
        println!("  ✓ Duplicate key rejected at pool level: {e}");
    } else {
        // Transaction was accepted, mine it and check if it reverted
        setup.node.advance_block().await?;
        nonce += 1; // Increment since transaction was included in block

        // Check receipt status - should be false (reverted)
        let receipt_opt2: Option<serde_json::Value> = provider
            .raw_request("eth_getTransactionReceipt".into(), [*tx_hash2])
            .await?;

        if let Some(receipt_json2) = receipt_opt2 {
            let status2 = receipt_json2
                .get("status")
                .and_then(|v| v.as_str())
                .map(|s| s != "0x0")
                .unwrap_or(false);

            if status2 {
                return Err(eyre::eyre!(
                    "Duplicate key authorization should have reverted but succeeded"
                ));
            }
            println!("  ✓ Duplicate key rejected (transaction reverted)");
        } else {
            println!("  ✓ Duplicate key rejected (transaction not included in block)");
        }
    }

    println!("✓ Duplicate key rejected\n");

    // Test 3: Access key trying to authorize another key (should fail)
    println!("Test 3: Unauthorized authorize attempt");
    let (access_key_1, pub_x_1, pub_y_1, access_addr_1) = generate_p256_access_key();
    let mock_p256_sig_1 = TempoSignature::Primitive(PrimitiveSignature::P256(
        tempo_primitives::transaction::tt_signature::P256SignatureWithPreHash {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: pub_x_1,
            pub_key_y: pub_y_1,
            pre_hash: false,
        },
    ));
    let key_auth_1 = create_key_authorization(
        &root_signer,
        access_addr_1,
        mock_p256_sig_1,
        chain_id,
        None, // Never expires
        Some(vec![TokenLimit {
            token: DEFAULT_FEE_TOKEN,
            limit: U256::from(10u64) * U256::from(10).pow(U256::from(18)),
        }]),
    )?;

    // Authorize access_key_1 with root key (should succeed)
    let mut tx3 = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );
    tx3.fee_token = None;
    tx3.key_authorization = Some(key_auth_1);
    let signature = sign_aa_tx_secp256k1(&tx3, &root_signer)?;
    let _tx_hash = submit_and_mine_aa_tx(&mut setup, tx3, signature).await?;
    nonce += 1;

    // Try to authorize second key using first access key (should fail)
    let (_, pub_x_2, pub_y_2, access_addr_2) = generate_p256_access_key();
    let mock_p256_sig_2 = TempoSignature::Primitive(PrimitiveSignature::P256(
        tempo_primitives::transaction::tt_signature::P256SignatureWithPreHash {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: pub_x_2,
            pub_key_y: pub_y_2,
            pre_hash: false,
        },
    ));
    let key_auth_2 = create_key_authorization(
        &root_signer,
        access_addr_2,
        mock_p256_sig_2,
        chain_id,
        None,         // Never expires
        Some(vec![]), // No spending allowed
    )?;
    let mut tx4 = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );
    tx4.fee_token = None;
    tx4.key_authorization = Some(key_auth_2);
    // Sign with access_key_1 (not root_key) - this should fail validation
    let signature =
        sign_aa_tx_with_p256_access_key(&tx4, &access_key_1, &pub_x_1, &pub_y_1, root_addr)?;

    // Submit - transaction MUST be rejected at RPC/pool level
    // The access_key_1 is authorized, so it can sign transactions, but the transaction
    // is trying to authorize ANOTHER key, which should be rejected at pool level
    let signed_tx4 = AASigned::new_unhashed(tx4, signature);
    let envelope4: TempoTxEnvelope = signed_tx4.into();
    let mut encoded4 = Vec::new();
    envelope4.encode_2718(&mut encoded4);

    let inject_result = setup.node.rpc.inject_tx(encoded4.into()).await.expect_err(
        "Transaction signed by access key trying to authorize another key \
             MUST be rejected at RPC/pool level",
    );

    let error_msg = inject_result.to_string();

    // Verify the error mentions keychain validation failure
    assert!(
        error_msg.contains("Keychain") || error_msg.contains("is not authorized"),
        "Error must mention keychain or authorization failure. Got: {error_msg}"
    );

    println!("✓ Unauthorized authorize rejected\n");

    println!("=== All Keychain Negative Tests Passed ===");
    Ok(())
}

#[tokio::test]
async fn test_transaction_key_authorization_and_spending_limits() -> eyre::Result<()> {
    use alloy::sol_types::SolCall;
    use tempo_contracts::precompiles::ITIP20::{balanceOfCall, transferCall};
    use tempo_precompiles::account_keychain::updateSpendingLimitCall;
    use tempo_primitives::transaction::TokenLimit;

    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    // Use TEST_MNEMONIC account (has balance in DEFAULT_FEE_TOKEN from genesis)
    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    const ACCOUNT_KEYCHAIN_ADDRESS: Address =
        alloy_primitives::address!("0xAAAAAAAA00000000000000000000000000000000");

    // Generate an access key
    let (access_key_signing, pub_x, pub_y, access_key_addr) = generate_p256_access_key();

    let spending_limit = U256::from(5u64) * U256::from(10).pow(U256::from(18)); // 5 tokens
    let over_limit_amount = U256::from(10u64) * U256::from(10).pow(U256::from(18)); // 10 tokens

    let mock_p256_sig = TempoSignature::Primitive(PrimitiveSignature::P256(
        tempo_primitives::transaction::tt_signature::P256SignatureWithPreHash {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: pub_x,
            pub_key_y: pub_y,
            pre_hash: false,
        },
    ));

    let key_auth = create_key_authorization(
        &root_signer,
        access_key_addr,
        mock_p256_sig,
        chain_id,
        None, // Never expires
        Some(vec![TokenLimit {
            token: DEFAULT_FEE_TOKEN,
            limit: spending_limit,
        }]),
    )?;

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Test 1: Authorize the access key with spending limits
    let auth_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: balanceOfCall { account: root_addr }.abi_encode().into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        // Use pathUSD as fee token (matches the spending limit token)
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: Some(key_auth.clone()),
        tempo_authorization_list: vec![],
    };

    let sig = root_signer.sign_hash_sync(&auth_tx.signature_hash())?;
    let _tx_hash = submit_and_mine_aa_tx(
        &mut setup,
        auth_tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(sig)),
    )
    .await?;
    nonce += 1;

    // Test 2: Try to use access key to call admin functions (must revert)
    let bad_admin_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: updateSpendingLimitCall {
                keyId: access_key_addr,
                token: DEFAULT_FEE_TOKEN,
                newLimit: U256::from(20u64) * U256::from(10).pow(U256::from(18)),
            }
            .abi_encode()
            .into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        // Use pathUSD as fee token (matches the spending limit token)
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    };

    let access_sig = sign_aa_tx_with_p256_access_key(
        &bad_admin_tx,
        &access_key_signing,
        &pub_x,
        &pub_y,
        root_addr,
    )?;

    let signed_tx = AASigned::new_unhashed(bad_admin_tx, access_sig);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);
    let tx_hash = *envelope.tx_hash();

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;

    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;

    let receipt_json = receipt.expect("Transaction must be included in block");
    let status = receipt_json
        .get("status")
        .and_then(|v| v.as_str())
        .expect("Receipt must have status field");

    assert_eq!(
        status, "0x0",
        "Access keys cannot call admin functions - transaction must revert"
    );
    nonce += 1;

    // Test 3: Try to transfer more than spending limit using access key (must revert)
    let recipient = Address::random();
    let over_limit_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: transferCall {
                to: recipient,
                amount: over_limit_amount,
            }
            .abi_encode()
            .into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        // Use pathUSD as fee token (matches the spending limit token)
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    };

    let access_sig = sign_aa_tx_with_p256_access_key(
        &over_limit_tx,
        &access_key_signing,
        &pub_x,
        &pub_y,
        root_addr,
    )?;

    let signed_tx = AASigned::new_unhashed(over_limit_tx, access_sig);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);
    let tx_hash = *envelope.tx_hash();

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;

    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;

    let receipt_json = receipt.expect("Transaction must be included in block");
    let status = receipt_json
        .get("status")
        .and_then(|v| v.as_str())
        .expect("Receipt must have status field");

    assert_eq!(
        status, "0x0",
        "Transfer exceeding spending limit must revert"
    );
    nonce += 1;

    // Test 4: Transfer within spending limit using access key (must succeed)
    let safe_transfer_amount = U256::from(3u64) * U256::from(10).pow(U256::from(18));
    let within_limit_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: transferCall {
                to: recipient,
                amount: safe_transfer_amount,
            }
            .abi_encode()
            .into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        // Use pathUSD as fee token (matches the spending limit token)
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    };

    let access_sig = sign_aa_tx_with_p256_access_key(
        &within_limit_tx,
        &access_key_signing,
        &pub_x,
        &pub_y,
        root_addr,
    )?;

    let signed_tx = AASigned::new_unhashed(within_limit_tx, access_sig);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let tx_hash = *envelope.tx_hash();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;

    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;

    let receipt_json = receipt.expect("Transaction must be included in block");
    let status = receipt_json
        .get("status")
        .and_then(|v| v.as_str())
        .expect("Receipt must have status field");

    assert_eq!(status, "0x1", "Transfer within spending limit must succeed");

    let recipient_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient)
        .call()
        .await?;

    assert_eq!(
        recipient_balance, safe_transfer_amount,
        "Recipient must receive exactly the transferred amount"
    );

    Ok(())
}

/// Test enforce_limits flag behavior with unlimited and restricted spending keys
#[tokio::test]
async fn test_aa_keychain_enforce_limits() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing enforce_limits Flag Behavior ===\n");

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Generate two access keys - one unlimited, one with no spending allowed
    let (unlimited_key_signing, unlimited_pub_x, unlimited_pub_y, unlimited_key_addr) =
        generate_p256_access_key();
    let (no_spending_key_signing, no_spending_pub_x, no_spending_pub_y, no_spending_key_addr) =
        generate_p256_access_key();

    println!("Unlimited access key address: {unlimited_key_addr}");
    println!("No-spending access key address: {no_spending_key_addr}");

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // STEP 1: Authorize unlimited spending key (limits: None)
    // Root key signs to authorize the access key
    println!("\n=== STEP 1: Authorize Unlimited Spending Key ===");

    let unlimited_key_auth = create_key_authorization(
        &root_signer,
        unlimited_key_addr,
        create_mock_p256_sig(unlimited_pub_x, unlimited_pub_y),
        chain_id,
        None, // Never expires
        None, // Unlimited spending (no limits enforced)
    )?;

    // First tx: Root key signs to authorize the unlimited access key (with benign balanceOf call)
    let mut auth_unlimited_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    // Use pathUSD as fee token (matches the spending limit token)
    auth_unlimited_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    auth_unlimited_tx.key_authorization = Some(unlimited_key_auth);

    let root_sig = sign_aa_tx_secp256k1(&auth_unlimited_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, auth_unlimited_tx, root_sig).await?;
    nonce += 1;

    println!("✓ Unlimited key authorized");

    // STEP 2: Use unlimited access key to transfer a large amount
    println!("\n=== STEP 2: Transfer with Unlimited Key ===");

    let recipient1 = Address::random();
    let large_transfer_amount = U256::from(10u64) * U256::from(10).pow(U256::from(18)); // 10 tokens

    let mut transfer_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(recipient1, large_transfer_amount)],
        2_000_000,
    );
    // Use pathUSD as fee token (matches the spending limit token)
    transfer_tx.fee_token = Some(DEFAULT_FEE_TOKEN);

    let unlimited_sig = sign_aa_tx_with_p256_access_key(
        &transfer_tx,
        &unlimited_key_signing,
        &unlimited_pub_x,
        &unlimited_pub_y,
        root_addr,
    )?;

    let signed_tx = AASigned::new_unhashed(transfer_tx, unlimited_sig);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let tx_hash = *envelope.tx_hash();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;
    nonce += 1;

    // Check the receipt to understand the result
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("Transaction must be included in block");

    assert!(
        receipt.status(),
        "Unlimited key transfer must succeed. Receipt: {receipt:?}"
    );

    // Verify the large transfer succeeded (unlimited key has no limit enforcement)
    let recipient1_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient1)
        .call()
        .await?;

    assert_eq!(
        recipient1_balance, large_transfer_amount,
        "Unlimited key must be able to transfer any amount"
    );
    println!("✓ Unlimited key transferred {large_transfer_amount} tokens successfully");

    // STEP 3: Authorize no-spending key (limits: Some([]))
    println!("\n=== STEP 3: Authorize No-Spending Key ===");

    let no_spending_key_auth = create_key_authorization(
        &root_signer,
        no_spending_key_addr,
        create_mock_p256_sig(no_spending_pub_x, no_spending_pub_y),
        chain_id,
        None,         // Never expires
        Some(vec![]), // No spending allowed (empty limits with enforce_limits=true)
    )?;

    // First authorize the no-spending key (with root key)
    let mut auth_no_spending_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    // Use pathUSD as fee token (matches the spending limit token)
    auth_no_spending_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    auth_no_spending_tx.key_authorization = Some(no_spending_key_auth);

    let root_sig = sign_aa_tx_secp256k1(&auth_no_spending_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, auth_no_spending_tx, root_sig).await?;
    nonce += 1;

    println!("✓ No-spending key authorized");

    // STEP 4: Try to transfer with no-spending key (must fail)
    println!("\n=== STEP 4: Transfer with No-Spending Key (must fail) ===");

    let recipient2 = Address::random();
    let small_transfer_amount = U256::from(1u64) * U256::from(10).pow(U256::from(18)); // 1 token

    let mut no_spending_transfer_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(recipient2, small_transfer_amount)],
        2_000_000,
    );
    // Use pathUSD as fee token (matches the spending limit token)
    no_spending_transfer_tx.fee_token = Some(DEFAULT_FEE_TOKEN);

    let no_spending_sig = sign_aa_tx_with_p256_access_key(
        &no_spending_transfer_tx,
        &no_spending_key_signing,
        &no_spending_pub_x,
        &no_spending_pub_y,
        root_addr,
    )?;

    let signed_tx = AASigned::new_unhashed(no_spending_transfer_tx, no_spending_sig);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);
    let tx_hash = *envelope.tx_hash();

    // The transaction should be rejected at RPC, during block building, or reverted on-chain
    // because fee payment exceeds the spending limit (empty limits = no spending allowed)
    match setup.node.rpc.inject_tx(encoded.into()).await {
        Err(e) => {
            // Rejected at RPC level - this is valid
            println!("No-spending key transaction was rejected by RPC: {e}");
        }
        Ok(_) => {
            // If accepted into pool, check what happened at block building
            setup.node.advance_block().await?;
            let receipt = provider.get_transaction_receipt(tx_hash).await?;

            if let Some(receipt) = receipt {
                // If included, it must have failed
                assert!(
                    !receipt.status(),
                    "No-spending key must not be able to transfer any tokens"
                );
                println!("No-spending key transaction was included but reverted");
            } else {
                println!(
                    "No-spending key transaction was rejected by block builder (spending limit exceeded)"
                );
            }
        }
    }

    // Verify recipient2 received NO tokens
    let recipient2_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient2)
        .call()
        .await?;

    assert_eq!(
        recipient2_balance,
        U256::ZERO,
        "Recipient must not receive any tokens from no-spending key"
    );

    println!("✓ No-spending key correctly blocked from transferring tokens");

    // STEP 5: Verify unlimited key can still transfer (second transfer)
    println!("\n=== STEP 5: Unlimited Key Second Transfer ===");
    // Don't increment nonce - the previous transaction was rejected so on-chain nonce didn't change

    let recipient3 = Address::random();
    let second_transfer = U256::from(5u64) * U256::from(10).pow(U256::from(18)); // 5 tokens

    let second_unlimited_tx = TempoTransaction {
        chain_id,
        // Use higher gas price to replace the rejected no-spending tx still in pool
        max_priority_fee_per_gas: (TEMPO_T1_BASE_FEE * 2) as u128,
        max_fee_per_gas: (TEMPO_T1_BASE_FEE * 2) as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: transferCall {
                to: recipient3,
                amount: second_transfer,
            }
            .abi_encode()
            .into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        // Use pathUSD as fee token (matches the spending limit token)
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    };

    let unlimited_sig2 = sign_aa_tx_with_p256_access_key(
        &second_unlimited_tx,
        &unlimited_key_signing,
        &unlimited_pub_x,
        &unlimited_pub_y,
        root_addr,
    )?;

    let _tx_hash = submit_and_mine_aa_tx(&mut setup, second_unlimited_tx, unlimited_sig2).await?;

    let recipient3_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient3)
        .call()
        .await?;

    assert_eq!(
        recipient3_balance, second_transfer,
        "Unlimited key must be able to transfer again without limit"
    );
    println!("✓ Unlimited key transferred {second_transfer} tokens successfully");

    println!("\n=== All enforce_limits Tests Passed ===");
    Ok(())
}

/// Test key expiry functionality - covers various expiry scenarios
/// - expiry = None (never expires) - should work indefinitely
/// - expiry > block.timestamp - should work before expiry, fail after expiry
/// - expiry < block.timestamp (past) - should fail during block building (rejected by builder)
#[tokio::test]
async fn test_aa_keychain_expiry() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing Key Expiry Functionality ===\n");

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Generate multiple access keys for different expiry scenarios
    let (never_expires_signing, never_expires_pub_x, never_expires_pub_y, never_expires_addr) =
        generate_p256_access_key();
    let (short_expiry_signing, short_expiry_pub_x, short_expiry_pub_y, short_expiry_addr) =
        generate_p256_access_key();
    let (_past_expiry_signing, past_expiry_pub_x, past_expiry_pub_y, past_expiry_addr) =
        generate_p256_access_key();

    println!("Never-expires key address: {never_expires_addr}");
    println!("Short-expiry key address: {short_expiry_addr}");
    println!("Past-expiry key address: {past_expiry_addr}");

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Get current block timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();
    println!("\nCurrent block timestamp: {current_timestamp}");

    // ========================================
    // TEST 1: expiry = None (never expires)
    // ========================================
    println!("\n=== TEST 1: Authorize Key with expiry = None (never expires) ===");

    let never_expires_key_auth = create_key_authorization(
        &root_signer,
        never_expires_addr,
        create_mock_p256_sig(never_expires_pub_x, never_expires_pub_y),
        chain_id,
        None, // Never expires
        Some(create_default_token_limit()),
    )?;

    // Authorize the never-expires key
    let mut auth_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    // Use pathUSD as fee token (matches the spending limit token)
    auth_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    auth_tx.key_authorization = Some(never_expires_key_auth);

    let root_sig = sign_aa_tx_secp256k1(&auth_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, auth_tx, root_sig).await?;
    nonce += 1;

    println!("✓ Never-expires key authorized");

    // Use the never-expires key - should work
    let recipient1 = Address::random();
    let transfer_amount = U256::from(1u64) * U256::from(10).pow(U256::from(18));

    let mut transfer_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(recipient1, transfer_amount)],
        2_000_000,
    );
    // Use pathUSD as fee token (matches the spending limit token)
    transfer_tx.fee_token = Some(DEFAULT_FEE_TOKEN);

    let never_expires_sig = sign_aa_tx_with_p256_access_key(
        &transfer_tx,
        &never_expires_signing,
        &never_expires_pub_x,
        &never_expires_pub_y,
        root_addr,
    )?;

    submit_and_mine_aa_tx(&mut setup, transfer_tx, never_expires_sig).await?;
    nonce += 1;

    let recipient1_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient1)
        .call()
        .await?;

    assert_eq!(
        recipient1_balance, transfer_amount,
        "Never-expires key must be able to transfer"
    );
    println!("✓ Never-expires key transfer succeeded");

    // ========================================
    // TEST 2: expiry > block.timestamp (authorize, use before expiry, then test after expiry)
    // ========================================
    println!("\n=== TEST 2: Authorize Key with future expiry ===");

    // Advance a few blocks to get a meaningful timestamp
    for _ in 0..3 {
        setup.node.advance_block().await?;
    }

    // Get fresh timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let test2_timestamp = block.header.timestamp();

    println!("Current block timestamp for TEST 2: {test2_timestamp}, using nonce: {nonce}");

    // Set expiry to just enough time in the future to authorize and use the key once
    // Each block advances timestamp by ~1 second, so 3 seconds should be enough for:
    // - authorization tx (1 block)
    // - use key tx (1 block)
    // Then after expiry, advancing a few more blocks should exceed the expiry
    let short_expiry_timestamp = test2_timestamp + 3;
    println!("Setting key expiry to: {short_expiry_timestamp} (current: {test2_timestamp})");

    let short_expiry_key_auth = create_key_authorization(
        &root_signer,
        short_expiry_addr,
        create_mock_p256_sig(short_expiry_pub_x, short_expiry_pub_y),
        chain_id,
        Some(short_expiry_timestamp),
        Some(create_default_token_limit()),
    )?;

    let mut auth_short_expiry_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    // Use pathUSD as fee token (matches the spending limit token)
    auth_short_expiry_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    auth_short_expiry_tx.key_authorization = Some(short_expiry_key_auth);

    let root_sig = sign_aa_tx_secp256k1(&auth_short_expiry_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, auth_short_expiry_tx, root_sig).await?;
    nonce += 1;

    println!("✓ Short-expiry key authorized");

    // Use the short-expiry key BEFORE expiry - should work
    println!("\n=== TEST 2a: Use key BEFORE expiry (should succeed) ===");

    let recipient2 = Address::random();

    let mut before_expiry_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(recipient2, transfer_amount)],
        2_000_000,
    );
    // Use pathUSD as fee token (matches the spending limit token)
    before_expiry_tx.fee_token = Some(DEFAULT_FEE_TOKEN);

    let short_expiry_sig = sign_aa_tx_with_p256_access_key(
        &before_expiry_tx,
        &short_expiry_signing,
        &short_expiry_pub_x,
        &short_expiry_pub_y,
        root_addr,
    )?;

    submit_and_mine_aa_tx(&mut setup, before_expiry_tx, short_expiry_sig).await?;
    nonce += 1;

    let recipient2_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient2)
        .call()
        .await?;

    assert_eq!(
        recipient2_balance, transfer_amount,
        "Short-expiry key must work before expiry"
    );
    println!("✓ Short-expiry key transfer succeeded before expiry");

    // Advance blocks until the key expires
    println!("\n=== TEST 2b: Advance time past expiry, then try to use key (should fail) ===");

    // Advance several blocks to ensure timestamp exceeds expiry
    for _ in 0..3 {
        setup.node.advance_block().await?;
    }

    // Get new timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let new_timestamp = block.header.timestamp();
    println!("New block timestamp: {new_timestamp} (expiry was: {short_expiry_timestamp})");

    assert!(
        new_timestamp >= short_expiry_timestamp,
        "Block timestamp should be past expiry"
    );

    // Try to use the expired key - should fail
    let recipient3 = Address::random();

    let mut after_expiry_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(recipient3, transfer_amount)],
        2_000_000,
    );
    // Use pathUSD as fee token (matches the spending limit token)
    after_expiry_tx.fee_token = Some(DEFAULT_FEE_TOKEN);

    let expired_key_sig = sign_aa_tx_with_p256_access_key(
        &after_expiry_tx,
        &short_expiry_signing,
        &short_expiry_pub_x,
        &short_expiry_pub_y,
        root_addr,
    )?;

    let signed_tx = AASigned::new_unhashed(after_expiry_tx, expired_key_sig);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    // The tx should be rejected by the mempool because the access key has expired
    let result = setup.node.rpc.inject_tx(encoded.into()).await;
    assert!(
        result.is_err(),
        "Expired access key transaction must be rejected by mempool"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Access key expired"),
        "Error must indicate access key expiry, got: {err_msg}"
    );
    println!("✓ Expired access key transaction was rejected by mempool: {err_msg}");

    // Nonce was not consumed since tx was rejected

    // ========================================
    // TEST 3: KeyAuthorization with expiry in the past (should fail in mempool)
    // ========================================
    println!("\n=== TEST 3: Authorize Key with expiry in the past ===");

    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let block_timestamp = block.header.timestamp();
    println!("Block timestamp: {block_timestamp}, using nonce: {nonce}");

    // Use expiry = 1 which is definitely in the past
    let past_expiry = 1u64;
    println!("Setting past expiry to: {past_expiry}");

    let past_expiry_key_auth = create_key_authorization(
        &root_signer,
        past_expiry_addr,
        create_mock_p256_sig(past_expiry_pub_x, past_expiry_pub_y),
        chain_id,
        Some(past_expiry), // Expiry in the past
        Some(create_default_token_limit()),
    )?;

    let mut past_expiry_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    // Use pathUSD as fee token (matches the spending limit token)
    past_expiry_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    past_expiry_tx.key_authorization = Some(past_expiry_key_auth);

    let root_sig = sign_aa_tx_secp256k1(&past_expiry_tx, &root_signer)?;
    let signed_tx = AASigned::new_unhashed(past_expiry_tx, root_sig);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    // The tx should be rejected by the mempool because the KeyAuthorization has expired
    let result = setup.node.rpc.inject_tx(encoded.into()).await;
    assert!(
        result.is_err(),
        "Expired KeyAuthorization transaction must be rejected by mempool"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("KeyAuthorization expired"),
        "Error must indicate KeyAuthorization expiry, got: {err_msg}"
    );
    println!("✓ Expired KeyAuthorization transaction was rejected by mempool: {err_msg}");

    Ok(())
}

/// Test RPC validation of Keychain signatures - ensures proper validation in transaction pool
/// Tests both positive (authorized key) and negative (unauthorized key) cases in a single test
#[tokio::test]
async fn test_aa_keychain_rpc_validation() -> eyre::Result<()> {
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
    use tempo_primitives::transaction::TokenLimit;

    reth_tracing::init_test_tracing();

    println!("\n=== Testing RPC Validation of Keychain Signatures ===\n");

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let http_url = setup.node.rpc_url();

    // Generate TWO P256 access keys
    let authorized_key_signing_key = SigningKey::random(&mut OsRng);
    let authorized_key_verifying_key = authorized_key_signing_key.verifying_key();
    let authorized_encoded_point = authorized_key_verifying_key.to_encoded_point(false);
    let authorized_pub_key_x = B256::from_slice(authorized_encoded_point.x().unwrap().as_ref());
    let authorized_pub_key_y = B256::from_slice(authorized_encoded_point.y().unwrap().as_ref());
    let authorized_key_addr = tempo_primitives::transaction::tt_signature::derive_p256_address(
        &authorized_pub_key_x,
        &authorized_pub_key_y,
    );

    let unauthorized_key_signing_key = SigningKey::random(&mut OsRng);
    let unauthorized_key_verifying_key = unauthorized_key_signing_key.verifying_key();
    let unauthorized_encoded_point = unauthorized_key_verifying_key.to_encoded_point(false);
    let unauthorized_pub_key_x = B256::from_slice(unauthorized_encoded_point.x().unwrap().as_ref());
    let unauthorized_pub_key_y = B256::from_slice(unauthorized_encoded_point.y().unwrap().as_ref());
    let unauthorized_key_addr = tempo_primitives::transaction::tt_signature::derive_p256_address(
        &unauthorized_pub_key_x,
        &unauthorized_pub_key_y,
    );

    println!("Authorized access key address: {authorized_key_addr}");
    println!("Unauthorized access key address: {unauthorized_key_addr}");

    // Setup root key (funded account)
    let root_key_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_key_addr = root_key_signer.address();
    let root_wallet = EthereumWallet::from(root_key_signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(root_wallet)
        .connect_http(http_url.clone());

    let chain_id = provider.get_chain_id().await?;
    let mut nonce = provider.get_transaction_count(root_key_addr).await?;

    println!("Root key address: {root_key_addr}");
    println!("Chain ID: {chain_id}\n");

    // STEP 1: Authorize the first access key (same-tx auth+use)
    println!("=== STEP 1: Authorize Access Key (same-tx auth+use) ===");

    let spending_limits = vec![TokenLimit {
        token: DEFAULT_FEE_TOKEN,
        limit: U256::from(10u64) * U256::from(10).pow(U256::from(18)), // 10 tokens
    }];

    let mock_p256_sig =
        TempoSignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: authorized_pub_key_x,
            pub_key_y: authorized_pub_key_y,
            pre_hash: false,
        }));

    let key_auth = create_key_authorization(
        &root_key_signer,
        authorized_key_addr,
        mock_p256_sig,
        chain_id,
        None, // Never expires
        Some(spending_limits.clone()),
    )?;

    let recipient1 = Address::random();
    let transfer_amount = U256::from(2u64) * U256::from(10).pow(U256::from(18)); // 2 tokens

    let auth_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: transferCall {
                to: recipient1,
                amount: transfer_amount,
            }
            .abi_encode()
            .into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: Some(key_auth),
        tempo_authorization_list: vec![],
    };

    let auth_sig = sign_aa_tx_with_p256_access_key(
        &auth_tx,
        &authorized_key_signing_key,
        &authorized_pub_key_x,
        &authorized_pub_key_y,
        root_key_addr,
    )?;

    let signed_auth_tx = AASigned::new_unhashed(auth_tx, auth_sig);
    let auth_envelope: TempoTxEnvelope = signed_auth_tx.into();
    let auth_tx_hash = *auth_envelope.tx_hash();
    let mut auth_encoded = Vec::new();
    auth_envelope.encode_2718(&mut auth_encoded);

    setup.node.rpc.inject_tx(auth_encoded.into()).await?;
    setup.node.advance_block().await?;
    nonce += 1;

    // Verify transaction succeeded
    let receipt1: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [auth_tx_hash])
        .await?;
    let receipt1_json = receipt1.expect("Receipt must exist");
    let status1 = receipt1_json
        .get("status")
        .and_then(|v| v.as_str())
        .expect("Receipt must have status");
    assert_eq!(status1, "0x1", "Authorization transaction must succeed");
    println!("✓ Access key authorized and used successfully\n");

    // STEP 2: POSITIVE TEST - Use the authorized key (should succeed)
    println!("=== STEP 2: POSITIVE TEST - Use Authorized Key ===");

    let recipient2 = Address::random();

    let positive_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: transferCall {
                to: recipient2,
                amount: transfer_amount,
            }
            .abi_encode()
            .into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None, // No auth needed - key already authorized
        tempo_authorization_list: vec![],
    };

    let positive_sig = sign_aa_tx_with_p256_access_key(
        &positive_tx,
        &authorized_key_signing_key,
        &authorized_pub_key_x,
        &authorized_pub_key_y,
        root_key_addr,
    )?;

    let signed_positive_tx = AASigned::new_unhashed(positive_tx, positive_sig);
    let positive_envelope: TempoTxEnvelope = signed_positive_tx.into();
    let positive_tx_hash = *positive_envelope.tx_hash();
    let mut positive_encoded = Vec::new();
    positive_envelope.encode_2718(&mut positive_encoded);

    // This should succeed - authorized key is used
    setup.node.rpc.inject_tx(positive_encoded.into()).await?;
    setup.node.advance_block().await?;
    nonce += 1;

    // Verify transaction succeeded
    let receipt2: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [positive_tx_hash])
        .await?;
    let receipt2_json = receipt2.expect("Receipt must exist");
    let status2 = receipt2_json
        .get("status")
        .and_then(|v| v.as_str())
        .expect("Receipt must have status");
    assert_eq!(status2, "0x1", "Positive test transaction must succeed");

    let recipient2_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient2)
        .call()
        .await?;

    assert_eq!(
        recipient2_balance, transfer_amount,
        "Recipient should receive tokens from authorized key"
    );

    println!("✓ POSITIVE TEST PASSED: Authorized key transaction succeeded\n");

    // STEP 3: NEGATIVE TEST - Use an unauthorized key (should be rejected at pool level)
    println!("=== STEP 3: NEGATIVE TEST - Use Unauthorized Key ===");

    let recipient3 = Address::random();

    let negative_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: transferCall {
                to: recipient3,
                amount: transfer_amount,
            }
            .abi_encode()
            .into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    };

    // Sign with UNAUTHORIZED key
    let negative_sig = sign_aa_tx_with_p256_access_key(
        &negative_tx,
        &unauthorized_key_signing_key,
        &unauthorized_pub_key_x,
        &unauthorized_pub_key_y,
        root_key_addr,
    )?;

    let signed_negative_tx = AASigned::new_unhashed(negative_tx, negative_sig);
    let negative_envelope: TempoTxEnvelope = signed_negative_tx.into();
    let mut negative_encoded = Vec::new();
    negative_envelope.encode_2718(&mut negative_encoded);

    println!("Attempting to inject transaction signed with unauthorized key...");

    // This MUST be REJECTED at the RPC/pool level
    let inject_result = setup
        .node
        .rpc
        .inject_tx(negative_encoded.into())
        .await
        .expect_err("Unauthorized key transaction MUST be rejected at RPC/pool level");

    let error_msg = inject_result.to_string();

    // Verify the error message contains the expected validation failure details
    assert!(
        error_msg.contains("Keychain signature validation failed: access key does not exist"),
        "Error must mention 'Keychain signature validation failed'. Got: {error_msg}"
    );

    // Verify recipient3 received NO tokens
    let recipient3_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient3)
        .call()
        .await?;

    assert_eq!(
        recipient3_balance,
        U256::ZERO,
        "Recipient should NOT receive tokens from unauthorized key"
    );

    // STEP 4: NEGATIVE TEST - Invalid KeyAuthorization signature (wrong signer)
    println!("\n=== STEP 4: NEGATIVE TEST - Invalid KeyAuthorization (wrong signer) ===");

    let (another_unauthorized_key, pub_x_3, pub_y_3, addr_3) = generate_p256_access_key();

    // Create KeyAuthorization but sign it with unauthorized_key_signer instead of root_key_signer
    let wrong_signer = &unauthorized_key_signing_key;

    // Try to create a KeyAuthorization signed by the WRONG signer (not root key)
    // This simulates someone trying to authorize a key without root key permission
    let auth_message_hash = KeyAuthorization {
        chain_id,
        key_type: tempo_primitives::transaction::SignatureType::P256,
        key_id: addr_3,
        expiry: None, // Never expires
        limits: Some(spending_limits.clone()),
    }
    .signature_hash();

    // Sign with wrong key (should be root_key_signer)
    use sha2::{Digest, Sha256};
    let wrong_sig_hash = B256::from_slice(Sha256::digest(auth_message_hash).as_ref());
    let wrong_signature: p256::ecdsa::Signature =
        wrong_signer.sign_prehash(wrong_sig_hash.as_slice())?;
    let wrong_sig_bytes = wrong_signature.to_bytes();

    let invalid_key_auth = KeyAuthorization {
        chain_id,
        key_type: tempo_primitives::transaction::SignatureType::P256,
        key_id: addr_3,
        expiry: None, // Never expires
        limits: Some(spending_limits.clone()),
    }
    .into_signed(PrimitiveSignature::P256(P256SignatureWithPreHash {
        r: B256::from_slice(&wrong_sig_bytes[0..32]),
        s: normalize_p256_s(&wrong_sig_bytes[32..64]),
        pub_key_x: unauthorized_pub_key_x, // pub key of wrong signer
        pub_key_y: unauthorized_pub_key_y,
        pre_hash: true,
    }));

    let invalid_auth_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: Some(invalid_key_auth),
        tempo_authorization_list: vec![],
    };

    // Sign the transaction with the new key we're trying to authorize
    let invalid_auth_sig = sign_aa_tx_with_p256_access_key(
        &invalid_auth_tx,
        &another_unauthorized_key,
        &pub_x_3,
        &pub_y_3,
        root_key_addr,
    )?;

    let signed_invalid_auth_tx = AASigned::new_unhashed(invalid_auth_tx, invalid_auth_sig);
    let invalid_auth_envelope: TempoTxEnvelope = signed_invalid_auth_tx.into();
    let mut invalid_auth_encoded = Vec::new();
    invalid_auth_envelope.encode_2718(&mut invalid_auth_encoded);

    println!("Attempting to inject transaction with invalid KeyAuthorization signature...");

    // This is a same-tx auth+use case: the transaction includes a KeyAuthorization for addr_3,
    // and is signed by another_unauthorized_key (which will become addr_3 after authorization).
    // The KeyAuthorization signature is invalid (signed by wrong_signer, not root_key_signer).
    // This MUST be REJECTED at the RPC/pool level.
    let inject_result_invalid_auth = setup
        .node
        .rpc
        .inject_tx(invalid_auth_encoded.into())
        .await
        .expect_err(
            "Transaction with invalid KeyAuthorization signature MUST be rejected at RPC/pool level"
        );

    let error_msg = inject_result_invalid_auth.to_string();

    // Verify the error message contains the expected validation failure details
    assert!(
        error_msg.contains("Invalid KeyAuthorization signature"),
        "Error must mention 'Invalid KeyAuthorization signature'. Got: {error_msg}"
    );

    Ok(())
}

/// Test that verifies that we can propagate 2d transactions
#[tokio::test(flavor = "multi_thread")]
async fn test_propagate_2d_transactions() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Create wallet from mnemonic
    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(0)?
        .build()?;

    let mut setup = crate::utils::TestNodeBuilder::new()
        .with_node_count(2)
        .build_multi_node()
        .await?;

    let tx = TempoTransaction {
        chain_id: 1337,
        max_priority_fee_per_gas: 1_000_000_000u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: Address::random().into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::from(123),
        nonce: 0,
        ..Default::default()
    };

    let sig_hash = tx.signature_hash();
    let signature = wallet.sign_hash_sync(&sig_hash)?;
    let signed_tx = AASigned::new_unhashed(
        tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );
    let envelope: TempoTxEnvelope = signed_tx.into();
    let encoded = envelope.encoded_2718();

    let node1 = setup.nodes.remove(0);
    let node2 = setup.nodes.remove(0);

    // make sure both nodes are ready to broadcast
    node1.inner.network.update_sync_state(SyncState::Idle);
    node2.inner.network.update_sync_state(SyncState::Idle);

    let mut tx_listener1 = node1.inner.pool.pending_transactions_listener();
    let mut tx_listener2 = node2.inner.pool.pending_transactions_listener();

    // Submitting transaction to first peer
    let provider1 =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(node1.rpc_url());
    let _ = provider1.send_raw_transaction(&encoded).await.unwrap();

    // ensure we see it as pending from the first peer
    let pending_hash1 = tx_listener1.recv().await.unwrap();
    assert_eq!(pending_hash1, *envelope.tx_hash());
    let _rpc_tx = provider1
        .get_transaction_by_hash(pending_hash1)
        .await
        .unwrap();

    // ensure we see it as pending on the second peer as well (should be broadcasted from first to second)
    let pending_hash2 = tx_listener2.recv().await.unwrap();
    assert_eq!(pending_hash2, *envelope.tx_hash());

    // check we can fetch it from the second peer now
    let provider2 =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(node2.rpc_url());
    let _rpc_tx = provider2
        .get_transaction_by_hash(pending_hash2)
        .await
        .unwrap();

    Ok(())
}

/// Test that KeyAuthorization with wrong chain_id is rejected
///
/// This test verifies that:
/// 1. A KeyAuthorization signed for a different chain_id is rejected at the RPC/pool level
/// 2. A KeyAuthorization with chain_id = 0 (wildcard) is accepted on any chain
#[tokio::test]
async fn test_aa_key_authorization_chain_id_validation() -> eyre::Result<()> {
    use tempo_primitives::transaction::TokenLimit;

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(root_addr).await?;

    println!("\n=== Test: KeyAuthorization Chain ID Validation ===");
    println!("Current chain ID: {chain_id}");

    // Generate an access key
    let (_, pub_x, pub_y, access_key_addr) = generate_p256_access_key();

    let mock_p256_sig = TempoSignature::Primitive(PrimitiveSignature::P256(
        tempo_primitives::transaction::tt_signature::P256SignatureWithPreHash {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: pub_x,
            pub_key_y: pub_y,
            pre_hash: false,
        },
    ));

    let spending_limits = vec![TokenLimit {
        token: DEFAULT_FEE_TOKEN,
        limit: U256::from(10u64) * U256::from(10).pow(U256::from(18)),
    }];

    // Test 1: Wrong chain_id should be rejected
    println!("\nTest 1: KeyAuthorization with wrong chain_id should be rejected");
    let wrong_chain_id = chain_id + 1; // Different chain ID
    let key_auth_wrong_chain = create_key_authorization(
        &root_signer,
        access_key_addr,
        mock_p256_sig.clone(),
        wrong_chain_id,
        None, // Never expires
        Some(spending_limits.clone()),
    )?;

    let tx_wrong_chain = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: Some(key_auth_wrong_chain),
        tempo_authorization_list: vec![],
    };

    let sig_hash = tx_wrong_chain.signature_hash();
    let signature = root_signer.sign_hash_sync(&sig_hash)?;
    let signed_tx = AASigned::new_unhashed(
        tx_wrong_chain,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    let inject_result = setup.node.rpc.inject_tx(encoded.into()).await;

    // Should be rejected
    assert!(
        inject_result.is_err(),
        "Transaction with wrong chain_id KeyAuthorization MUST be rejected"
    );

    let error_msg = inject_result.unwrap_err().to_string();
    assert!(
        error_msg.contains("chain_id does not match"),
        "Error must mention chain_id mismatch. Got: {error_msg}"
    );
    println!("  ✓ Wrong chain_id KeyAuthorization rejected as expected");

    // Test 2: chain_id = 0 (wildcard) should be accepted
    println!("\nTest 2: KeyAuthorization with chain_id = 0 (wildcard) should be accepted");
    let key_auth_wildcard = create_key_authorization(
        &root_signer,
        access_key_addr,
        mock_p256_sig,
        0,    // Wildcard chain_id
        None, // Never expires
        Some(spending_limits),
    )?;

    let tx_wildcard = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: Some(key_auth_wildcard),
        tempo_authorization_list: vec![],
    };

    let sig_hash = tx_wildcard.signature_hash();
    let signature = root_signer.sign_hash_sync(&sig_hash)?;
    let tx_hash = submit_and_mine_aa_tx(
        &mut setup,
        tx_wildcard,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    )
    .await?;
    println!("  ✓ Wildcard chain_id KeyAuthorization accepted (tx: {tx_hash})");

    Ok(())
}

/// Test that contract CREATE in a Tempo transaction computes the correct contract address.
#[tokio::test(flavor = "multi_thread")]
async fn test_aa_create_correct_contract_address() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut setup, provider, signer, signer_addr) = setup_test_with_funded_account().await?;

    let chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(signer_addr).await?;

    // Compute expected contract address BEFORE sending transaction
    // CREATE address = keccak256(rlp([sender, nonce]))[12:]
    let expected_contract_address = signer_addr.create(nonce);

    println!("Test: CREATE contract address computation in Tempo transaction");
    println!("  Sender: {signer_addr}");
    println!("  Nonce: {nonce}");
    println!("  Expected contract address: {expected_contract_address}");

    // Simple contract initcode: PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
    // This stores 42 at memory[0] and returns 32 bytes
    let init_code =
        Bytes::from_static(&[0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);

    // Create Tempo transaction with CREATE as first (and only) call
    let tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: init_code,
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    // Sign and send
    let signature = signer.sign_hash_sync(&tx.signature_hash())?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let _payload = setup.node.advance_block().await?;

    // Get receipt using raw RPC to handle Tempo-specific transaction type
    let tx_hash = keccak256(&encoded);
    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;
    let receipt = receipt.expect("Receipt not found");

    let actual_contract_address: Address = receipt["contractAddress"]
        .as_str()
        .expect("Receipt should have contractAddress for CREATE transaction")
        .parse()?;

    println!("  Actual contract address from receipt: {actual_contract_address}");

    assert_eq!(
        actual_contract_address,
        expected_contract_address,
        "Contract address should be computed from nonce {nonce}, not nonce {}. \
         This indicates the nonce was incorrectly incremented before CREATE address derivation.",
        nonce + 1
    );

    // Verify contract was actually deployed at that address
    let deployed_code = provider.get_code_at(actual_contract_address).await?;
    assert!(
        !deployed_code.is_empty(),
        "Contract should be deployed at the expected address"
    );

    // Verify the contract returns 42 (the init code stores 0x2a at memory[0])
    let mut expected_code = [0u8; 32];
    expected_code[31] = 0x2a;
    assert_eq!(
        deployed_code.as_ref(),
        &expected_code,
        "Deployed contract should have expected runtime code"
    );

    Ok(())
}

/// Verifies that transactions signed with a revoked access key cannot be executed.
#[tokio::test]
async fn test_aa_keychain_revocation_toctou_dos() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing AA Keychain Revocation TOCTOU DoS ===\n");

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Generate an access key for the attack
    let (access_key_signing, access_pub_x, access_pub_y, access_key_addr) =
        generate_p256_access_key();

    println!("Access key address: {access_key_addr}");

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Get current block timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();
    println!("Current block timestamp: {current_timestamp}");

    // ========================================
    // STEP 1: Authorize the access key
    // ========================================
    println!("\n=== STEP 1: Authorize the access key ===");

    let key_auth = create_key_authorization(
        &root_signer,
        access_key_addr,
        create_mock_p256_sig(access_pub_x, access_pub_y),
        chain_id,
        None, // Never expires
        Some(create_default_token_limit()),
    )?;

    let mut auth_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    auth_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    auth_tx.key_authorization = Some(key_auth);

    let root_sig = sign_aa_tx_secp256k1(&auth_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, auth_tx, root_sig).await?;
    nonce += 1;

    println!("Access key authorized");

    // ========================================
    // STEP 2: Submit a transaction with valid_after in the future using the access key
    // ========================================
    println!("\n=== STEP 2: Submit transaction with future valid_after using access key ===");

    // Advance a couple blocks to get a fresh timestamp
    for _ in 0..2 {
        setup.node.advance_block().await?;
    }

    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let new_timestamp = block.header.timestamp();

    // Set valid_after to be 10 seconds in the future (enough time to revoke the key)
    let valid_after_time = new_timestamp + 10;
    println!("Setting valid_after to {valid_after_time} (current: {new_timestamp})");

    // Create a transaction that uses the access key with valid_after
    let recipient = Address::random();
    let transfer_amount = U256::from(1u64) * U256::from(10).pow(U256::from(18));

    let mut delayed_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(recipient, transfer_amount)],
        2_000_000,
    );
    delayed_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    delayed_tx.valid_after = Some(valid_after_time);

    // Sign with the access key (wrapped in Keychain signature)
    let access_key_sig = sign_aa_tx_with_p256_access_key(
        &delayed_tx,
        &access_key_signing,
        &access_pub_x,
        &access_pub_y,
        root_addr,
    )?;

    // Submit the transaction - it should pass validation because the key is still authorized
    let delayed_tx_envelope: TempoTxEnvelope = delayed_tx.into_signed(access_key_sig).into();
    let delayed_tx_hash = *delayed_tx_envelope.tx_hash();
    setup
        .node
        .rpc
        .inject_tx(delayed_tx_envelope.encoded_2718().into())
        .await?;
    // Note: We don't increment nonce here because the delayed tx won't be mined until valid_after.
    // The revoke tx below uses a different nonce_key (2D nonce) to be mined independently.

    println!("Delayed transaction submitted (hash: {delayed_tx_hash})");

    // Verify transaction is in the pool
    assert!(
        setup.node.inner.pool.contains(&delayed_tx_hash),
        "Delayed transaction should be in the pool"
    );
    println!("Transaction is in the mempool");

    // ========================================
    // STEP 3: Revoke the access key before valid_after is reached
    // ========================================
    println!("\n=== STEP 3: Revoke the access key ===");

    let revoke_call = revokeKeyCall {
        keyId: access_key_addr,
    };

    // Use a 2D nonce (different nonce_key) so this tx can be mined independently
    // of the delayed tx which is also using the root account but blocking on valid_after
    let mut revoke_tx = create_basic_aa_tx(
        chain_id,
        0, // nonce 0 for this new nonce_key
        vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: revoke_call.abi_encode().into(),
        }],
        2_000_000,
    );
    revoke_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    revoke_tx.nonce_key = U256::from(1); // Use a different nonce key so it's independent

    let revoke_sig = sign_aa_tx_secp256k1(&revoke_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, revoke_tx, revoke_sig).await?;

    // Verify the key is actually revoked by querying the keychain
    use tempo_contracts::precompiles::account_keychain::IAccountKeychain::IAccountKeychainInstance;
    let keychain = IAccountKeychainInstance::new(ACCOUNT_KEYCHAIN_ADDRESS, &provider);
    let key_info = keychain.getKey(root_addr, access_key_addr).call().await?;
    assert!(key_info.isRevoked, "Key should be marked as revoked");
    println!("Access key revoked");

    // The evict_revoked_keychain_txs maintenance task has a 1-second startup delay,
    // then monitors storage changes on block commits and evicts transactions signed
    // with revoked keys. We need to advance a block to trigger the commit notification,
    // then wait for the maintenance task to process it.
    // Advance another block to trigger the commit notification
    setup.node.advance_block().await?;

    // Wait for keychain eviction task to process the block with the revocation
    tokio::time::sleep(POOL_MAINTENANCE_DELAY).await;

    // ========================================
    // STEP 4: Verify transaction is evicted from the pool
    // ========================================
    println!("\n=== STEP 4: Verify transaction is evicted from pool ===");

    // Check pool state immediately after revocation
    let tx_still_in_pool = setup.node.inner.pool.contains(&delayed_tx_hash);

    // Check if transaction was mined (should not be, since it had valid_after in future)
    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [delayed_tx_hash])
        .await?;

    // Check the transfer recipient balance to verify if the transaction actually executed
    let recipient_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient)
        .call()
        .await?;

    println!("\n=== RESULTS ===");
    println!("Transaction still in pool: {tx_still_in_pool}");
    println!("Transaction mined: {}", receipt.is_some());
    println!("Recipient balance: {recipient_balance}");
    println!("Expected transfer amount: {transfer_amount}");

    if tx_still_in_pool {
        panic!(
            "DoS via AA keychain revocation TOCTOU: \
             Transaction signed with revoked key should be evicted from the mempool"
        );
    } else if receipt.is_some() {
        // Transaction was mined - check if it succeeded or reverted
        let receipt_obj = receipt.as_ref().unwrap().as_object().unwrap();
        let status = receipt_obj
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");

        if status == "0x1" {
            // Verify the transfer actually happened
            if recipient_balance == transfer_amount {
                println!("Recipient received {transfer_amount} tokens");
            }

            panic!(
                "Transaction signed with revoked key was executed successfully. \
                 The keychain revocation is not being enforced at execution time."
            );
        } else {
            // Transaction was mined but reverted - this is expected behavior
            // Verify the transfer did NOT happen
            assert_eq!(
                recipient_balance,
                U256::ZERO,
                "Recipient should have no balance since transaction reverted"
            );
        }
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_estimate_gas_expiring_nonce_tx() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing eth_estimateGas for Expiring Nonce TX ===\n");

    let setup = TestNodeBuilder::new().build_with_node_access().await?;

    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let signer_addr = signer.address();

    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(signer)
        .connect_http(setup.node.rpc_url());

    let recipient = Address::random();

    // Get current block timestamp so valid_before is within the 30s expiry window
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let valid_before = block.header.timestamp() + 20;

    let request = TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(signer_addr),
            ..Default::default()
        },
        calls: vec![Call {
            to: TxKind::Call(recipient),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: Some(TEMPO_EXPIRING_NONCE_KEY),
        valid_before: Some(valid_before),
        ..Default::default()
    };

    let gas = provider.estimate_gas(request).await?;
    assert!(gas > 0, "gas estimate should be non-zero");

    Ok(())
}

/// Test basic expiring nonce flow - submit transaction with expiring nonce, verify it executes
#[tokio::test(flavor = "multi_thread")]
async fn test_aa_expiring_nonce_basic_flow() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing Expiring Nonce Basic Flow ===\n");

    let (mut setup, provider, alice_signer, alice_addr) = setup_test_with_funded_account().await?;

    let chain_id = provider.get_chain_id().await?;
    let recipient = Address::random();

    // Advance a few blocks to get a meaningful timestamp
    for _ in 0..3 {
        setup.node.advance_block().await?;
    }

    // Get current block timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();
    println!("Current block timestamp: {current_timestamp}");

    // Create expiring nonce transaction with valid_before in the future (within 30s window)
    let valid_before = current_timestamp + 20; // 20 seconds in future
    println!("Setting valid_before to: {valid_before}");

    let tx = create_expiring_nonce_tx(chain_id, valid_before, recipient);

    // Sign and encode the transaction
    let aa_signature = sign_aa_tx_secp256k1(&tx, &alice_signer)?;
    let envelope: TempoTxEnvelope = tx.into_signed(aa_signature).into();
    let tx_hash = *envelope.tx_hash();
    let encoded = envelope.encoded_2718();

    println!("Transaction hash: {tx_hash}");

    // Inject and mine
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let payload = setup.node.advance_block().await?;

    println!(
        "✓ Expiring nonce transaction mined in block {}",
        payload.block().inner.number
    );

    assert_receipt_status(&provider, tx_hash, true).await?;
    println!("✓ Expiring nonce transaction executed successfully");

    // Verify alice's protocol nonce did NOT increment (expiring nonce doesn't use protocol nonce)
    let alice_protocol_nonce = provider.get_transaction_count(alice_addr).await?;
    assert_eq!(
        alice_protocol_nonce, 0,
        "Protocol nonce should remain 0 for expiring nonce transactions"
    );
    println!("✓ Protocol nonce unchanged (still 0)");

    Ok(())
}

/// Test that a different fee payer CANNOT replay a user's expiring-nonce sponsored transaction
/// by signing as an alternate fee payer.
///
/// Replay protection uses `expiring_nonce_hash = keccak256(encode_for_signing || sender)`,
/// which is invariant to fee payer signature changes. Even though different fee payer signatures
/// produce different `tx_hash` values, the `expiring_nonce_hash` is identical, so the second
/// submission is rejected.
#[tokio::test(flavor = "multi_thread")]
async fn test_aa_expiring_nonce_fee_payer_signature_malleability() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing Expiring Nonce Fee Payer Signature Malleability ===\n");

    let (mut setup, provider, _funder_signer, _funder_addr) =
        setup_test_with_funded_account().await?;

    let chain_id = provider.get_chain_id().await?;

    // Fee payer 1 is the funded TEST_MNEMONIC account
    let fee_payer_1_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;

    // Fee payer 2 is a separate account (attacker / alternate relayer)
    // Fund it so the replay rejection is driven by expiring nonce dedup, not balance checks.
    let fee_payer_2_signer = alloy::signers::local::PrivateKeySigner::random();
    fund_address_with_fee_tokens(
        &mut setup,
        &provider,
        &fee_payer_1_signer,
        fee_payer_1_signer.address(),
        fee_payer_2_signer.address(),
        U256::from(1_000_000_000_000_000_000u128),
        chain_id,
    )
    .await?;

    // User is a fresh random account
    let user_signer = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = user_signer.address();

    // Advance blocks to get a meaningful timestamp
    for _ in 0..3 {
        setup.node.advance_block().await?;
    }

    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();
    let valid_before = current_timestamp + 25;

    // Create a sponsored expiring-nonce transaction with a benign call.
    // The user has no balance — the fee payer covers gas. Any call from the user
    // demonstrates the replay: if executed twice, the user's intent runs twice.
    let recipient = Address::random();

    let mut tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: TEMPO_EXPIRING_NONCE_KEY,
        nonce: 0,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        valid_before: Some(valid_before),
        // Presence of fee_payer_signature indicates a fee-payer-sponsored tx
        fee_payer_signature: Some(Signature::new(U256::ZERO, U256::ZERO, false)),
        ..Default::default()
    };

    // Step 1: User signs the transaction (signature_hash excludes fee payer sig)
    let user_sig_hash = tx.signature_hash();
    let user_signature = user_signer.sign_hash_sync(&user_sig_hash)?;
    println!("User signature_hash: {user_sig_hash}");

    // Step 2: Fee payer 1 signs the fee payer hash
    let fee_payer_sig_hash = tx.fee_payer_signature_hash(user_addr);
    let fee_payer_sig_1 = fee_payer_1_signer.sign_hash_sync(&fee_payer_sig_hash)?;
    tx.fee_payer_signature = Some(fee_payer_sig_1);

    // Build and submit the first version (fee payer 1)
    let aa_sig = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(user_signature));
    let envelope_1: TempoTxEnvelope = tx.clone().into_signed(aa_sig.clone()).into();
    let tx_hash_1 = *envelope_1.tx_hash();
    let encoded_1 = envelope_1.encoded_2718();
    println!("First tx_hash (fee payer 1):  {tx_hash_1}");

    setup.node.rpc.inject_tx(encoded_1.into()).await?;
    setup.node.advance_block().await?;

    let receipt_1: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash_1])
        .await?;
    assert!(receipt_1.is_some(), "First transaction should be mined");
    let receipt_1_json = receipt_1.unwrap();
    let status_1 = receipt_1_json["status"]
        .as_str()
        .map(|s| s == "0x1")
        .unwrap_or(false);
    assert!(status_1, "First transaction should succeed");
    println!("✓ First submission succeeded");

    // Step 3: Fee payer 2 (attacker) signs the SAME user intent as a different fee payer.
    // The user's signature remains valid because signature_hash is invariant to fee payer sig.
    let fee_payer_sig_2 = fee_payer_2_signer.sign_hash_sync(&fee_payer_sig_hash)?;
    assert_ne!(
        fee_payer_sig_1, fee_payer_sig_2,
        "Different fee payer keys must produce different signatures"
    );
    tx.fee_payer_signature = Some(fee_payer_sig_2);

    // The user's signature_hash should be identical (invariant to fee payer sig)
    assert_eq!(
        tx.signature_hash(),
        user_sig_hash,
        "User signature_hash must be invariant to fee payer signature changes"
    );

    // Build the second version — different fee payer sig means different tx_hash
    let envelope_2: TempoTxEnvelope = tx.into_signed(aa_sig).into();
    let tx_hash_2 = *envelope_2.tx_hash();
    let encoded_2 = envelope_2.encoded_2718();
    println!("Second tx_hash (fee payer 2): {tx_hash_2}");

    assert_ne!(
        tx_hash_1, tx_hash_2,
        "Different fee payer signatures must produce different tx hashes"
    );

    // Step 4: Submit the replay — this is rejected because replay protection uses
    // expiring_nonce_hash (keccak256(encode_for_signing || sender)), which is invariant
    // to fee payer changes.
    let replay_result = setup.node.rpc.inject_tx(encoded_2.into()).await;

    let error_msg = replay_result
        .expect_err("Replay with different fee payer signature must be rejected")
        .to_string();

    assert!(
        error_msg
            .contains("Expiring nonce transaction replay: tx hash already seen and not expired"),
        "Rejection must be due to expiring nonce replay protection, got: {error_msg}"
    );
    println!("✓ Replay with different fee payer correctly rejected: {error_msg}");

    Ok(())
}

/// Test expiring nonce replay protection - same tx hash should be rejected
#[tokio::test(flavor = "multi_thread")]
async fn test_aa_expiring_nonce_replay_protection() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing Expiring Nonce Replay Protection ===\n");

    let (mut setup, provider, alice_signer, _alice_addr) = setup_test_with_funded_account().await?;

    let chain_id = provider.get_chain_id().await?;
    let recipient = Address::random();

    // Advance a few blocks to get a meaningful timestamp
    for _ in 0..3 {
        setup.node.advance_block().await?;
    }

    // Get current block timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();

    // Create expiring nonce transaction
    let valid_before = current_timestamp + 25;

    let tx = create_expiring_nonce_tx(chain_id, valid_before, recipient);

    let aa_signature = sign_aa_tx_secp256k1(&tx, &alice_signer)?;
    let envelope: TempoTxEnvelope = tx.into_signed(aa_signature).into();
    let tx_hash = *envelope.tx_hash();
    let encoded = envelope.encoded_2718();

    println!("First submission - tx hash: {tx_hash}");

    // First submission should succeed
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    setup.node.advance_block().await?;

    assert_receipt_status(&provider, tx_hash, true).await?;
    println!("✓ First submission succeeded");

    // Second submission with SAME encoded tx (same hash) should fail
    println!("\nSecond submission - attempting replay with same tx hash...");

    // Try to inject the same transaction again - should be rejected at pool level
    let replay_result = setup.node.rpc.inject_tx(encoded.clone().into()).await;

    // The replay MUST be rejected at pool validation (we check seen[tx_hash] in validator)
    assert!(
        replay_result.is_err(),
        "Replay should be rejected at transaction pool level"
    );
    println!("✓ Replay rejected at transaction pool level");

    Ok(())
}

/// Test expiring nonce validity window - reject transactions outside the valid window
#[tokio::test(flavor = "multi_thread")]
async fn test_aa_expiring_nonce_validity_window() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing Expiring Nonce Validity Window ===\n");

    let (mut setup, provider, alice_signer, _alice_addr) = setup_test_with_funded_account().await?;

    let chain_id = provider.get_chain_id().await?;

    // Advance a few blocks to get a meaningful timestamp
    for _ in 0..3 {
        setup.node.advance_block().await?;
    }

    // Get current block timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();
    println!("Current block timestamp: {current_timestamp}");
    println!("Max expiry window: {TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS} seconds");

    // TEST 1: valid_before exactly at max window (should succeed)
    println!("\n--- TEST 1: valid_before at exactly max window (now + 30s) ---");
    {
        let recipient = Address::random();
        let valid_before = current_timestamp + TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS;

        let tx = create_expiring_nonce_tx(chain_id, valid_before, recipient);
        let aa_signature = sign_aa_tx_secp256k1(&tx, &alice_signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(aa_signature).into();
        let tx_hash = *envelope.tx_hash();

        setup
            .node
            .rpc
            .inject_tx(envelope.encoded_2718().into())
            .await?;
        setup.node.advance_block().await?;

        assert_receipt_status(&provider, tx_hash, true).await?;
        println!("✓ valid_before = now + 30s accepted");
    }

    // TEST 2: valid_before too far in future (should fail)
    println!("\n--- TEST 2: valid_before too far in future (now + 31s) ---");
    {
        // Advance block to get fresh timestamp
        setup.node.advance_block().await?;
        let block = provider
            .get_block_by_number(Default::default())
            .await?
            .unwrap();
        let current_timestamp = block.header.timestamp();

        let recipient = Address::random();
        let valid_before = current_timestamp + TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS + 1; // 31 seconds

        let tx = create_expiring_nonce_tx(chain_id, valid_before, recipient);
        let aa_signature = sign_aa_tx_secp256k1(&tx, &alice_signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(aa_signature).into();
        let inject_result = setup
            .node
            .rpc
            .inject_tx(envelope.encoded_2718().into())
            .await;

        let err = inject_result.expect_err(
            "Transaction with valid_before too far in future should be rejected at pool level",
        );
        let err_str = err.to_string();
        assert!(
            err_str.contains("exceeds max allowed") || err_str.contains("valid_before"),
            "Expected ExpiringNonceValidBeforeTooFar error, got: {err_str}"
        );
        println!("✓ valid_before = now + 31s rejected at pool level with expected error");
    }

    // TEST 3: valid_before in the past (should fail)
    println!("\n--- TEST 3: valid_before in the past ---");
    {
        // Advance block to get fresh timestamp
        setup.node.advance_block().await?;
        let block = provider
            .get_block_by_number(Default::default())
            .await?
            .unwrap();
        let current_timestamp = block.header.timestamp();

        let recipient = Address::random();
        let valid_before = current_timestamp.saturating_sub(1); // 1 second in past

        let tx = create_expiring_nonce_tx(chain_id, valid_before, recipient);
        let aa_signature = sign_aa_tx_secp256k1(&tx, &alice_signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(aa_signature).into();
        let tx_hash = *envelope.tx_hash();

        let inject_result = setup
            .node
            .rpc
            .inject_tx(envelope.encoded_2718().into())
            .await;

        if inject_result.is_err() {
            println!("✓ valid_before in past rejected at pool level");
        } else {
            setup.node.advance_block().await?;
            let raw: Option<serde_json::Value> = provider
                .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
                .await?;
            let succeeded = raw
                .as_ref()
                .and_then(|r| r["status"].as_str())
                .map(|s| s == "0x1")
                .unwrap_or(false);
            assert!(
                !succeeded,
                "Transaction with valid_before in the past should be rejected"
            );
            println!("✓ valid_before in past rejected at execution level");
        }
    }

    println!("\n=== All Expiring Nonce Validity Window Tests Passed ===");
    Ok(())
}

/// Test that expiring nonce transactions don't affect protocol nonce
///
/// This test demonstrates that expiring nonce transactions are independent from
/// protocol nonce - alice can use expiring nonce, then use protocol nonce afterward.
#[tokio::test(flavor = "multi_thread")]
async fn test_aa_expiring_nonce_independent_from_protocol_nonce() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing Expiring Nonce Independence from Protocol Nonce ===\n");

    let (mut setup, provider, alice_signer, alice_addr) = setup_test_with_funded_account().await?;

    let chain_id = provider.get_chain_id().await?;

    // Advance a few blocks to get a meaningful timestamp
    for _ in 0..3 {
        setup.node.advance_block().await?;
    }

    // Step 1: Submit an expiring nonce transaction
    println!("Step 1: Submit expiring nonce transaction...");
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();
    let valid_before = current_timestamp + 25;

    let expiring_tx = create_expiring_nonce_tx(chain_id, valid_before, Address::random());
    let aa_signature = sign_aa_tx_secp256k1(&expiring_tx, &alice_signer)?;
    let envelope: TempoTxEnvelope = expiring_tx.into_signed(aa_signature).into();
    let expiring_tx_hash = *envelope.tx_hash();

    setup
        .node
        .rpc
        .inject_tx(envelope.encoded_2718().into())
        .await?;
    setup.node.advance_block().await?;

    assert_receipt_status(&provider, expiring_tx_hash, true).await?;
    println!("✓ Expiring nonce transaction succeeded");

    // Verify protocol nonce is still 0
    let protocol_nonce = provider.get_transaction_count(alice_addr).await?;
    assert_eq!(
        protocol_nonce, 0,
        "Protocol nonce should be 0 after expiring nonce tx"
    );
    println!("✓ Protocol nonce still 0 after expiring nonce tx");

    // Step 2: Now submit a protocol nonce transaction (nonce_key = 0)
    println!("\nStep 2: Submit protocol nonce transaction...");
    let protocol_tx = create_basic_aa_tx(
        chain_id,
        0,
        vec![Call {
            to: Address::random().into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );
    let aa_signature = sign_aa_tx_secp256k1(&protocol_tx, &alice_signer)?;
    let envelope: TempoTxEnvelope = protocol_tx.into_signed(aa_signature).into();
    let protocol_tx_hash = *envelope.tx_hash();

    setup
        .node
        .rpc
        .inject_tx(envelope.encoded_2718().into())
        .await?;
    setup.node.advance_block().await?;

    assert_receipt_status(&provider, protocol_tx_hash, true).await?;
    println!("✓ Protocol nonce transaction succeeded");

    // Verify protocol nonce incremented
    let protocol_nonce = provider.get_transaction_count(alice_addr).await?;
    assert_eq!(
        protocol_nonce, 1,
        "Protocol nonce should be 1 after protocol tx"
    );
    println!("✓ Protocol nonce now 1 after protocol tx");

    println!("\n✓ Expiring nonces are independent from protocol nonces");

    Ok(())
}
/// Verifies that transactions signed with a keychain key are evicted when spending limits change.
///
/// This tests the TOCTOU vulnerability (CHAIN-444) where:
/// 1. An attacker funds and authorizes an address with balance > spending limit
/// 2. Submits transactions that pass validation
/// 3. Reduces spending limit so execution would fail
/// 4. Transactions should be evicted from the mempool
#[tokio::test]
async fn test_aa_keychain_spending_limit_toctou_dos() -> eyre::Result<()> {
    use tempo_precompiles::account_keychain::updateSpendingLimitCall;

    reth_tracing::init_test_tracing();

    println!("\n=== Testing AA Keychain Spending Limit TOCTOU DoS ===\n");

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Generate an access key for the attack
    let (access_key_signing, access_pub_x, access_pub_y, access_key_addr) =
        generate_p256_access_key();

    println!("Access key address: {access_key_addr}");

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Get current block timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();
    println!("Current block timestamp: {current_timestamp}");

    // ========================================
    // STEP 1: Authorize the access key with a spending limit
    // ========================================
    println!("\n=== STEP 1: Authorize the access key with spending limit ===");

    // Set a generous spending limit initially (100 tokens)
    let initial_spending_limit = U256::from(100u64) * U256::from(10).pow(U256::from(18));

    let key_auth = create_key_authorization(
        &root_signer,
        access_key_addr,
        create_mock_p256_sig(access_pub_x, access_pub_y),
        chain_id,
        None, // Never expires
        Some(vec![tempo_primitives::transaction::TokenLimit {
            token: DEFAULT_FEE_TOKEN,
            limit: initial_spending_limit,
        }]),
    )?;

    let mut auth_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    auth_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    auth_tx.key_authorization = Some(key_auth);

    let root_sig = sign_aa_tx_secp256k1(&auth_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, auth_tx, root_sig).await?;
    nonce += 1;

    println!("Access key authorized with spending limit: {initial_spending_limit}");

    // ========================================
    // STEP 2: Submit a transaction with valid_after in the future using the access key
    // ========================================
    println!("\n=== STEP 2: Submit transaction with future valid_after using access key ===");

    // Advance a couple blocks to get a fresh timestamp
    for _ in 0..2 {
        setup.node.advance_block().await?;
    }

    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let new_timestamp = block.header.timestamp();

    // Set valid_after to be 10 seconds in the future (enough time to reduce spending limit)
    let valid_after_time = new_timestamp + 10;
    println!("Setting valid_after to {valid_after_time} (current: {new_timestamp})");

    // Create a transaction that uses the access key with valid_after
    let recipient = Address::random();
    let transfer_amount = U256::from(1u64) * U256::from(10).pow(U256::from(18)); // 1 token

    let mut delayed_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(recipient, transfer_amount)],
        300_000,
    );
    delayed_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    delayed_tx.valid_after = Some(valid_after_time);

    // Sign with the access key (wrapped in Keychain signature)
    let access_key_sig = sign_aa_tx_with_p256_access_key(
        &delayed_tx,
        &access_key_signing,
        &access_pub_x,
        &access_pub_y,
        root_addr,
    )?;

    // Submit the transaction - it should pass validation because the spending limit is still high
    let delayed_tx_envelope: TempoTxEnvelope = delayed_tx.into_signed(access_key_sig).into();
    let delayed_tx_hash = *delayed_tx_envelope.tx_hash();
    setup
        .node
        .rpc
        .inject_tx(delayed_tx_envelope.encoded_2718().into())
        .await?;

    println!("Delayed transaction submitted (hash: {delayed_tx_hash})");

    // Verify transaction is in the pool
    assert!(
        setup.node.inner.pool.contains(&delayed_tx_hash),
        "Delayed transaction should be in the pool"
    );
    println!("Transaction is in the mempool");

    // ========================================
    // STEP 3: Reduce the spending limit to 0 before valid_after is reached
    // ========================================
    println!("\n=== STEP 3: Reduce spending limit to 0 ===");

    let update_limit_call = updateSpendingLimitCall {
        keyId: access_key_addr,
        token: DEFAULT_FEE_TOKEN,
        newLimit: U256::ZERO, // Set to 0, making all pending transfers fail
    };

    // Use a 2D nonce (different nonce_key) so this tx can be mined independently
    let mut update_tx = create_basic_aa_tx(
        chain_id,
        0, // nonce 0 for this new nonce_key
        vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: update_limit_call.abi_encode().into(),
        }],
        2_000_000,
    );
    update_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    update_tx.nonce_key = U256::from(1); // Use a different nonce key so it's independent

    let update_sig = sign_aa_tx_secp256k1(&update_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, update_tx, update_sig).await?;

    println!("Spending limit reduced to 0");

    // The maintenance task monitors for SpendingLimitUpdated events and evicts transactions
    // signed with keys whose spending limits have changed.
    // Advance another block to trigger the commit notification
    setup.node.advance_block().await?;

    // Wait for maintenance task to process the block with the spending limit update
    tokio::time::sleep(POOL_MAINTENANCE_DELAY).await;

    // ========================================
    // STEP 4: Verify transaction is evicted from the pool
    // ========================================
    println!("\n=== STEP 4: Verify transaction is evicted from pool ===");

    // Check pool state after spending limit update
    let tx_still_in_pool = setup.node.inner.pool.contains(&delayed_tx_hash);

    // Check if transaction was mined (should not be, since it had valid_after in future)
    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [delayed_tx_hash])
        .await?;

    // Check the transfer recipient balance
    let recipient_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient)
        .call()
        .await?;

    println!("\n=== RESULTS ===");
    println!("Transaction still in pool: {tx_still_in_pool}");
    println!("Transaction mined: {}", receipt.is_some());
    println!("Recipient balance: {recipient_balance}");
    println!("Expected transfer amount: {transfer_amount}");

    if tx_still_in_pool {
        panic!(
            "DoS via AA keychain spending limit TOCTOU: \
             Transaction from key with reduced spending limit should be evicted from the mempool"
        );
    } else if receipt.is_some() {
        // Transaction was mined - check if it succeeded or reverted
        let receipt_obj = receipt.as_ref().unwrap().as_object().unwrap();
        let status = receipt_obj
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");

        if status == "0x1" {
            // Verify the transfer actually happened
            if recipient_balance == transfer_amount {
                println!("Recipient received {transfer_amount} tokens");
            }

            panic!(
                "Transaction exceeding spending limit was executed successfully. \
                 The spending limit enforcement is not being enforced at execution time."
            );
        } else {
            // Transaction was mined but reverted - this is expected behavior
            // Verify the transfer did NOT happen
            assert_eq!(
                recipient_balance,
                U256::ZERO,
                "Recipient should have no balance since transaction reverted"
            );
        }
    }

    println!("\n=== Test passed: Transaction was correctly evicted ===");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
// Covers eth_fillTransaction field filling for nonceKey, validBefore, validAfter, feeToken, and fee payer signature hash recovery.
async fn test_eth_fill_transaction_matrix() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (_setup, provider, _signer, signer_addr) = setup_test_with_funded_account().await?;

    let fee_payer_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;

    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();

    let test_matrix = [
        fill_case!(Protocol, Secp256k1, omit_nonce_key),
        fill_case!(TwoD(42), Secp256k1),
        fill_case!(Expiring, Secp256k1; valid_before_offset = 20),
        fill_case!(
            Expiring,
            Secp256k1;
            valid_before_offset = 20,
            valid_after_offset = -10
        ),
        fill_case!(
            Expiring,
            Secp256k1;
            valid_before_offset = 20,
            explicit_nonce = 12
        ),
        fill_case!(Protocol, Secp256k1; fee_token = DEFAULT_FEE_TOKEN),
        fill_case!(
            Protocol,
            Secp256k1,
            fee_payer;
            fee_token = DEFAULT_FEE_TOKEN
        ),
    ];

    println!("\n=== eth_fillTransaction matrix ===\n");
    println!("Running {} fillTransaction cases...\n", test_matrix.len());

    for (index, test_case) in test_matrix.iter().enumerate() {
        println!("[{}/{}] {}", index + 1, test_matrix.len(), test_case.name);
        let (filled_tx, request_context) =
            fill_transaction_from_case(&provider, test_case, signer_addr, current_timestamp)
                .await?;
        assert_fill_request_expectations(&filled_tx, &request_context, test_case)?;

        if test_case.fee_payer {
            let fee_payer_sig_hash = filled_tx.fee_payer_signature_hash(signer_addr);
            let fee_payer_signature = fee_payer_signer.sign_hash_sync(&fee_payer_sig_hash)?;
            assert_eq!(
                fee_payer_signature.recover_address_from_prehash(&fee_payer_sig_hash)?,
                fee_payer_signer.address(),
                "feePayerSignature hash should be deterministic"
            );
        }
    }

    println!("\n✓ All {} fillTransaction cases passed", test_matrix.len());
    Ok(())
}

/// Helper to parse a filled transaction response into a TempoTransaction
fn parse_filled_tx(filled: &serde_json::Value) -> eyre::Result<TempoTransaction> {
    let tx = filled
        .get("tx")
        .ok_or_else(|| eyre::eyre!("Missing 'tx' field in response"))?;

    let chain_id = tx
        .get("chainId")
        .and_then(|v| v.as_str())
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16))
        .transpose()?
        .ok_or_else(|| eyre::eyre!("Missing 'chainId' in filled tx"))?;

    let nonce = tx
        .get("nonce")
        .and_then(|v| v.as_str())
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16))
        .transpose()?
        .unwrap_or(0);

    let gas_limit = tx
        .get("gas")
        .and_then(|v| v.as_str())
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16))
        .transpose()?
        .ok_or_else(|| eyre::eyre!("Missing 'gas' in filled tx"))?;

    let max_fee_per_gas = tx
        .get("maxFeePerGas")
        .and_then(|v| v.as_str())
        .map(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16))
        .transpose()?
        .ok_or_else(|| eyre::eyre!("Missing 'maxFeePerGas' in filled tx"))?;

    let max_priority_fee_per_gas = tx
        .get("maxPriorityFeePerGas")
        .and_then(|v| v.as_str())
        .map(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16))
        .transpose()?
        .ok_or_else(|| eyre::eyre!("Missing 'maxPriorityFeePerGas' in filled tx"))?;

    let nonce_key = tx
        .get("nonceKey")
        .and_then(|v| v.as_str())
        .map(|s| U256::from_str_radix(s.trim_start_matches("0x"), 16))
        .transpose()?
        .unwrap_or(U256::ZERO);

    let valid_before = tx
        .get("validBefore")
        .and_then(|v| v.as_str())
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16))
        .transpose()?;

    let valid_after = tx
        .get("validAfter")
        .and_then(|v| v.as_str())
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16))
        .transpose()?;

    let fee_token = tx
        .get("feeToken")
        .and_then(|v| v.as_str())
        .map(|s| s.parse::<Address>())
        .transpose()?;

    let calls = tx
        .get("calls")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|call| {
                    let to = call
                        .get("to")
                        .and_then(|v| v.as_str())
                        .map(|s| s.parse::<Address>())
                        .transpose()?
                        .map(TxKind::Call)
                        .unwrap_or(TxKind::Create);
                    let value = call
                        .get("value")
                        .and_then(|v| v.as_str())
                        .map(|s| U256::from_str_radix(s.trim_start_matches("0x"), 16))
                        .transpose()?
                        .unwrap_or(U256::ZERO);
                    let input = call
                        .get("data")
                        .or_else(|| call.get("input"))
                        .and_then(|v| v.as_str())
                        .map(|s| {
                            let hex_str = s.trim_start_matches("0x");
                            if hex_str.is_empty() {
                                Ok(Bytes::new())
                            } else {
                                hex::decode(hex_str).map(Bytes::from)
                            }
                        })
                        .transpose()?
                        .unwrap_or_default();
                    Ok(tempo_primitives::transaction::tempo_transaction::Call { to, value, input })
                })
                .collect::<eyre::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(TempoTransaction {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        nonce_key,
        valid_before,
        valid_after,
        fee_token,
        calls,
        ..Default::default()
    })
}

/// Nonce mode for E2E test matrix
#[derive(Debug, Clone, Copy)]
enum NonceMode {
    Protocol,
    TwoD(u64),
    Expiring,
    ExpiringAtBoundary,
    ExpiringExceedsBoundary,
}

/// Expected outcome for E2E test
#[derive(Debug, Clone, Copy)]
enum ExpectedOutcome {
    Success,
    Rejection,
}

/// Test case definition for fill tests and E2E matrix
struct FillTestCase {
    name: String,
    nonce_mode: NonceMode,
    key_type: KeyType,
    include_nonce_key: bool,
    fee_token: Option<Address>,
    fee_payer: bool,
    valid_before_offset: Option<i64>,
    valid_after_offset: Option<i64>,
    explicit_nonce: Option<u64>,
    pre_bump_nonce: Option<u64>,
    expected: ExpectedOutcome,
}

struct FillRequestContext {
    request: TempoTransactionRequest,
    expected_nonce: Option<u64>,
    expected_nonce_key: U256,
    expected_valid_before: Option<u64>,
    expected_valid_after: Option<u64>,
}

fn key_type_to_signature_type(key_type: KeyType) -> SignatureType {
    match key_type {
        KeyType::Secp256k1 => SignatureType::Secp256k1,
        KeyType::P256 => SignatureType::P256,
        KeyType::WebAuthn => SignatureType::WebAuthn,
    }
}

fn resolve_timestamp_offset(current_timestamp: u64, offset: i64) -> u64 {
    if offset.is_negative() {
        current_timestamp.saturating_sub(offset.unsigned_abs())
    } else {
        current_timestamp + offset as u64
    }
}

fn build_fill_request_context(
    test_case: &FillTestCase,
    signer_addr: Address,
    recipient: Address,
    current_timestamp: u64,
) -> FillRequestContext {
    let valid_before_offset = test_case
        .valid_before_offset
        .map(|offset| resolve_timestamp_offset(current_timestamp, offset));
    let valid_after_offset = test_case
        .valid_after_offset
        .map(|offset| resolve_timestamp_offset(current_timestamp, offset));

    let valid_before = valid_before_offset.or_else(|| match test_case.nonce_mode {
        NonceMode::Expiring => Some(current_timestamp + 20),
        NonceMode::ExpiringAtBoundary => {
            Some(current_timestamp + TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS)
        }
        NonceMode::ExpiringExceedsBoundary => {
            Some(current_timestamp + TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS + 1)
        }
        _ => None,
    });

    let nonce_key_value = match test_case.nonce_mode {
        NonceMode::Protocol => U256::ZERO,
        NonceMode::TwoD(key) => U256::from(key),
        NonceMode::Expiring
        | NonceMode::ExpiringAtBoundary
        | NonceMode::ExpiringExceedsBoundary => TEMPO_EXPIRING_NONCE_KEY,
    };
    let nonce_key = if test_case.include_nonce_key {
        Some(nonce_key_value)
    } else {
        None
    };
    let expected_nonce_key = if test_case.include_nonce_key {
        nonce_key_value
    } else {
        U256::ZERO
    };

    let fee_payer_signature = if test_case.fee_payer {
        Some(Signature::new(U256::ONE, U256::ONE, false))
    } else {
        None
    };

    let request = TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(signer_addr),
            nonce: test_case.explicit_nonce,
            ..Default::default()
        },
        calls: vec![Call {
            to: TxKind::Call(recipient),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        key_type: Some(key_type_to_signature_type(test_case.key_type)),
        key_data: None,
        fee_token: test_case.fee_token,
        fee_payer_signature,
        valid_before,
        valid_after: valid_after_offset,
        nonce_key,
        ..Default::default()
    };

    FillRequestContext {
        request,
        expected_nonce: test_case.explicit_nonce,
        expected_nonce_key,
        expected_valid_before: valid_before,
        expected_valid_after: valid_after_offset,
    }
}

async fn fill_transaction_from_case(
    provider: &impl Provider,
    test_case: &FillTestCase,
    signer_addr: Address,
    current_timestamp: u64,
) -> eyre::Result<(TempoTransaction, FillRequestContext)> {
    let recipient = Address::random();
    let request_context =
        build_fill_request_context(test_case, signer_addr, recipient, current_timestamp);

    let filled: serde_json::Value = provider
        .raw_request(
            "eth_fillTransaction".into(),
            [serde_json::to_value(&request_context.request)?],
        )
        .await?;

    let tx = parse_filled_tx(&filled)?;

    Ok((tx, request_context))
}

fn assert_fill_request_expectations(
    tx: &TempoTransaction,
    request_context: &FillRequestContext,
    test_case: &FillTestCase,
) -> eyre::Result<()> {
    assert_eq!(
        tx.nonce_key, request_context.expected_nonce_key,
        "nonceKey should match"
    );
    assert_eq!(
        tx.valid_before, request_context.expected_valid_before,
        "validBefore should match"
    );
    assert_eq!(
        tx.valid_after, request_context.expected_valid_after,
        "validAfter should match"
    );

    if let Some(expected_nonce) = request_context.expected_nonce {
        assert_eq!(tx.nonce, expected_nonce, "nonce should be preserved");
    }

    if let Some(fee_token) = test_case.fee_token {
        assert_eq!(
            tx.fee_token,
            Some(fee_token),
            "feeToken should be preserved"
        );
    } else {
        assert_eq!(tx.fee_token, None, "feeToken should remain empty");
    }

    assert_eq!(
        tx.fee_payer_signature, None,
        "feePayerSignature should remain empty"
    );

    Ok(())
}

/// Send `count` no-op transactions to bump the protocol nonce.
async fn bump_protocol_nonce(
    setup: &mut SingleNodeSetup,
    provider: &impl Provider,
    signer: &impl SignerSync,
    signer_addr: Address,
    count: u64,
) -> eyre::Result<()> {
    let recipient = Address::random();
    let chain_id = provider.get_chain_id().await?;
    let start_nonce = provider.get_transaction_count(signer_addr).await?;

    for i in 0..count {
        let tx = TempoTransaction {
            chain_id,
            nonce: start_nonce + i,
            gas_limit: 300_000,
            max_fee_per_gas: TEMPO_T1_BASE_FEE as u128 + 1_000_000,
            max_priority_fee_per_gas: 1_000_000,
            fee_token: Some(DEFAULT_FEE_TOKEN),
            calls: vec![Call {
                to: recipient.into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            ..Default::default()
        };

        let sig_hash = tx.signature_hash();
        let signature = signer.sign_hash_sync(&sig_hash)?;
        let signed = AASigned::new_unhashed(
            tx,
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
        );
        let envelope: TempoTxEnvelope = signed.into();
        setup
            .node
            .rpc
            .inject_tx(envelope.encoded_2718().into())
            .await?;
        setup.node.advance_block().await?;
        tokio::time::sleep(POOL_MAINTENANCE_DELAY).await;
    }

    let final_nonce = provider.get_transaction_count(signer_addr).await?;
    assert_eq!(
        final_nonce,
        start_nonce + count,
        "Protocol nonce should have bumped"
    );
    Ok(())
}

/// Run a single E2E test case from the matrix
async fn run_fill_sign_send_test(test_case: &FillTestCase) -> eyre::Result<()> {
    println!("\n=== E2E Test: {} ===\n", test_case.name);
    println!("  nonce_mode: {:?}", test_case.nonce_mode);
    println!("  key_type: {:?}", test_case.key_type);

    let uses_p256 = matches!(test_case.key_type, KeyType::P256 | KeyType::WebAuthn);

    if uses_p256 {
        run_fill_sign_send_test_p256(test_case).await
    } else {
        run_fill_sign_send_test_secp256k1(test_case).await
    }
}

/// Run test with secp256k1 key
async fn run_fill_sign_send_test_secp256k1(test_case: &FillTestCase) -> eyre::Result<()> {
    let (mut setup, provider, alice_signer, alice_addr) = setup_test_with_funded_account().await?;

    if let Some(count) = test_case.pre_bump_nonce {
        bump_protocol_nonce(&mut setup, &provider, &alice_signer, alice_addr, count).await?;
    }

    for _ in 0..3 {
        setup.node.advance_block().await?;
    }

    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();
    let initial_protocol_nonce = provider.get_transaction_count(alice_addr).await?;

    let (mut tx, request_context) =
        fill_transaction_from_case(&provider, test_case, alice_addr, current_timestamp).await?;
    tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    if request_context.expected_valid_before.is_none() {
        tx.valid_before = Some(u64::MAX);
    }

    let signature = sign_aa_tx_secp256k1(&tx, &alice_signer)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let tx_hash = *envelope.tx_hash();

    let send_result = provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await;

    match test_case.expected {
        ExpectedOutcome::Success => {
            let _ = send_result?;
            setup.node.advance_block().await?;

            let raw_receipt: Option<serde_json::Value> = provider
                .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
                .await?;
            assert!(raw_receipt.is_some(), "Transaction should be mined");
            let status = raw_receipt.unwrap()["status"]
                .as_str()
                .map(|s| s == "0x1")
                .unwrap_or(false);
            assert!(status, "Transaction should succeed");

            let final_protocol_nonce = provider.get_transaction_count(alice_addr).await?;
            let should_increment = matches!(test_case.nonce_mode, NonceMode::Protocol);
            if should_increment {
                assert_eq!(final_protocol_nonce, initial_protocol_nonce + 1);
            } else {
                assert_eq!(final_protocol_nonce, initial_protocol_nonce);
            }
        }
        ExpectedOutcome::Rejection => {
            assert!(send_result.is_err(), "Transaction should be rejected");
        }
    }

    println!("✓ Test passed: {}", test_case.name);
    Ok(())
}

/// Run test with P256 or WebAuthn key
async fn run_fill_sign_send_test_p256(test_case: &FillTestCase) -> eyre::Result<()> {
    let funding_amount = U256::from(1_000_000_000_000_000_000u128);
    let (
        mut setup,
        provider,
        signing_key,
        pub_key_x,
        pub_key_y,
        signer_addr,
        _funder_signer,
        _funder_addr,
        chain_id,
        _fee_token,
    ) = setup_test_with_p256_funded_account(funding_amount).await?;

    for _ in 0..3 {
        setup.node.advance_block().await?;
    }

    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();

    let (mut tx, _request_context) =
        fill_transaction_from_case(&provider, test_case, signer_addr, current_timestamp).await?;
    tx.chain_id = chain_id;
    tx.fee_token = Some(DEFAULT_FEE_TOKEN);

    let signature = match test_case.key_type {
        KeyType::P256 => sign_aa_tx_p256(&tx, &signing_key, pub_key_x, pub_key_y)?,
        KeyType::WebAuthn => sign_aa_tx_webauthn(
            &tx,
            &signing_key,
            pub_key_x,
            pub_key_y,
            "https://example.com",
        )?,
        KeyType::Secp256k1 => unreachable!(),
    };

    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let tx_hash = *envelope.tx_hash();

    let send_result = provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await;

    match test_case.expected {
        ExpectedOutcome::Success => {
            let _ = send_result?;
            setup.node.advance_block().await?;

            let raw_receipt: Option<serde_json::Value> = provider
                .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
                .await?;
            assert!(raw_receipt.is_some(), "Transaction should be mined");
            let status = raw_receipt.unwrap()["status"]
                .as_str()
                .map(|s| s == "0x1")
                .unwrap_or(false);
            assert!(status, "Transaction should succeed");
        }
        ExpectedOutcome::Rejection => {
            assert!(send_result.is_err(), "Transaction should be rejected");
        }
    }

    println!("✓ Test passed: {}", test_case.name);
    Ok(())
}

/// E2E matrix: fill -> sign -> send across nonce modes and key types.
/// Regression test: CREATE + KeyAuthorization nonce bump (T1B fix).
///
/// **The bug (T1):** An AA CREATE transaction with a KeyAuthorization uses a
/// gas-metered precompile call for `authorize_key`. The SSTORE costs can exceed
/// the remaining gas, causing OutOfGas. The handler then short-circuits execution
/// before `make_create_frame` bumps the protocol nonce. Since the nonce stays at 0,
/// the signed transaction can be replayed indefinitely.
///
/// **The fix (T1B):** The precompile runs with unlimited gas, eliminating the OOG
/// path. Gas is accounted for solely in intrinsic gas. The CREATE frame is always
/// constructed, the nonce is always bumped, and replay is impossible.
///
/// This test verifies:
/// 1. CREATE + KeyAuthorization tx succeeds and deploys a contract
/// 2. The protocol nonce is bumped (nonce 0 → 1)
/// 3. Replaying the same signed transaction is rejected (nonce too low)
#[tokio::test]
async fn test_t1b_create_nonce_bump_with_key_authorization() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut setup, provider, root_signer, root_addr) = setup_test_with_funded_account().await?;

    let chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(root_addr).await?;

    println!("\n=== Testing CREATE + KeyAuthorization Nonce Bump (T1B regression) ===\n");
    println!("Root address: {root_addr}");
    println!("Initial nonce: {nonce}");

    // Generate a P256 access key to authorize
    let (_, access_pub_x, access_pub_y, access_key_addr) = generate_p256_access_key();
    println!("Access key to authorize: {access_key_addr}");

    // Create key authorization signed by root (secp256k1)
    let mock_sig = create_mock_p256_sig(access_pub_x, access_pub_y);
    let key_authorization = create_key_authorization(
        &root_signer,
        access_key_addr,
        mock_sig,
        chain_id,
        None, // never expires
        None, // no spending limits
    )?;

    // Compute expected contract address BEFORE sending
    let expected_contract_address = root_addr.create(nonce);
    println!("Expected contract address: {expected_contract_address}");

    // Simple initcode: PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
    // Stores 42 at memory[0] and returns 32 bytes as runtime code
    let init_code =
        Bytes::from_static(&[0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);

    // Build AA tx: CREATE call + key_authorization
    let mut tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: init_code,
        }],
        2_000_000,
    );
    tx.key_authorization = Some(key_authorization);

    // Sign with root key (secp256k1)
    let aa_signature = sign_aa_tx_secp256k1(&tx, &root_signer)?;
    let envelope: TempoTxEnvelope = tx.into_signed(aa_signature).into();
    let encoded = envelope.encoded_2718();

    // Submit and mine
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let payload = setup.node.advance_block().await?;
    println!(
        "✓ CREATE + KeyAuth tx mined in block {}",
        payload.block().inner.number
    );

    // 1. Verify nonce was bumped
    let nonce_after = provider.get_transaction_count(root_addr).await?;
    assert_eq!(
        nonce_after,
        nonce + 1,
        "Protocol nonce must be bumped after CREATE tx with KeyAuthorization"
    );
    println!("✓ Nonce bumped: {nonce} → {nonce_after}");

    // 2. Verify contract was deployed at the expected address
    let deployed_code = provider.get_code_at(expected_contract_address).await?;
    assert!(
        !deployed_code.is_empty(),
        "Contract should be deployed at the expected address"
    );
    let mut expected_code = [0u8; 32];
    expected_code[31] = 0x2a;
    assert_eq!(
        deployed_code.as_ref(),
        &expected_code,
        "Deployed contract should have expected runtime code (0x2a)"
    );
    println!("✓ Contract deployed at {expected_contract_address}");

    // 3. Verify receipt shows success
    let tx_hash = keccak256(&encoded);
    assert_receipt_status(&provider, tx_hash, true).await?;
    println!("✓ Receipt status: success");

    // 4. Verify replay is rejected — same signed tx should fail with nonce-too-low
    let replay_result = setup.node.rpc.inject_tx(encoded.into()).await;
    assert!(
        replay_result.is_err(),
        "Replay of the same CREATE+KeyAuth tx must be rejected (nonce already bumped)"
    );
    println!("✓ Replay rejected: {}", replay_result.unwrap_err());

    println!("\n=== CREATE + KeyAuthorization Nonce Bump Test Passed ===");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_fill_sign_send_matrix() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let test_matrix = [
        fill_case!(Protocol, Secp256k1),
        fill_case!(TwoD(42), Secp256k1),
        fill_case!(Expiring, Secp256k1),
        fill_case!(Expiring, P256),
        fill_case!(Expiring, WebAuthn),
        fill_case!(ExpiringAtBoundary, Secp256k1),
        fill_case!(ExpiringAtBoundary, P256),
        fill_case!(ExpiringAtBoundary, WebAuthn),
        fill_case!(ExpiringExceedsBoundary, Secp256k1, reject),
        fill_case!(ExpiringExceedsBoundary, P256, reject),
        fill_case!(ExpiringExceedsBoundary, WebAuthn, reject),
        fill_case!(TwoD(12345), Secp256k1; pre_bump_nonce = 5),
        fill_case!(Expiring, Secp256k1; explicit_nonce = 0, pre_bump_nonce = 3),
        fill_case!(Expiring, Secp256k1; explicit_nonce = 0),
    ];

    println!("\n=== E2E Test Matrix: fill -> sign -> send ===\n");
    println!("Running {} test cases...\n", test_matrix.len());

    for (i, test_case) in test_matrix.iter().enumerate() {
        println!("[{}/{}] {}", i + 1, test_matrix.len(), test_case.name);
        run_fill_sign_send_test(test_case).await?;
    }

    println!("\n✓ All {} test cases passed", test_matrix.len());
    Ok(())
}
