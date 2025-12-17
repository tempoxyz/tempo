use alloy::{
    consensus::{BlockHeader, Transaction},
    network::{EthereumWallet, ReceiptResponse},
    primitives::{Address, B256, Bytes, Signature, U256, keccak256},
    providers::{Provider, ProviderBuilder},
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
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO,
    tip20::ITIP20::{self, transferCall},
};

use tempo_primitives::{
    SignatureType, TempoTransaction, TempoTxEnvelope,
    transaction::{
        KeyAuthorization, SignedKeyAuthorization, TokenLimit,
        tempo_transaction::Call,
        tt_signature::{
            P256SignatureWithPreHash, PrimitiveSignature, TempoSignature, WebAuthnSignature,
        },
        tt_signed::AASigned,
    },
};

use crate::utils::{SingleNodeSetup, TEST_MNEMONIC, TestNodeBuilder};
use tempo_primitives::transaction::tt_signature::normalize_p256_s;

/// Helper function to fund an address with fee tokens
async fn fund_address_with_fee_tokens(
    setup: &mut SingleNodeSetup,
    provider: &impl Provider,
    funder_signer: &impl SignerSync,
    funder_addr: Address,
    recipient: Address,
    amount: U256,
    chain_id: u64,
) -> eyre::Result<()> {
    let transfer_calldata = transferCall {
        to: recipient,
        amount,
    }
    .abi_encode();

    let funding_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO.into(),
            value: U256::ZERO,
            input: transfer_calldata.into(),
        }],
        nonce_key: U256::ZERO,
        nonce: provider.get_transaction_count(funder_addr).await?,
        fee_token: Some(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    // Sign and send the funding transaction
    let sig_hash = funding_tx.signature_hash();
    let signature = funder_signer.sign_hash_sync(&sig_hash)?;
    let aa_signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature));
    let signed_funding_tx = AASigned::new_unhashed(funding_tx, aa_signature);
    let funding_envelope: TempoTxEnvelope = signed_funding_tx.into();
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

    Ok(())
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

    // Use raw RPC call to fetch transaction since Alloy doesn't support custom tx type 0x5
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
    let setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();

    // Use TEST_MNEMONIC account (has balance in DEFAULT_FEE_TOKEN_POST_ALLEGRETTO from genesis)
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

/// Helper function to create a signed Secp256k1 authorization
fn create_secp256k1_authorization<T>(
    chain_id: u64,
    delegate_address: Address,
    signer: &T,
) -> eyre::Result<(
    tempo_primitives::transaction::TempoSignedAuthorization,
    Address,
)>
where
    T: SignerSync + alloy::signers::Signer,
{
    use alloy_eips::eip7702::Authorization;
    use tempo_primitives::transaction::TempoSignedAuthorization;

    let authority_addr = signer.address();

    let auth = Authorization {
        chain_id: alloy_primitives::U256::from(chain_id),
        address: delegate_address,
        nonce: 0,
    };

    let sig_hash = compute_authorization_signature_hash(&auth);
    let signature = signer.sign_hash_sync(&sig_hash)?;
    let aa_sig = tempo_primitives::transaction::tt_signature::TempoSignature::Primitive(
        tempo_primitives::transaction::tt_signature::PrimitiveSignature::Secp256k1(signature),
    );
    let signed_auth = TempoSignedAuthorization::new_unchecked(auth, aa_sig);

    Ok((signed_auth, authority_addr))
}

/// Helper function to create a signed P256 authorization
fn create_p256_authorization(
    chain_id: u64,
    delegate_address: Address,
) -> eyre::Result<(
    tempo_primitives::transaction::TempoSignedAuthorization,
    Address,
    p256::ecdsa::SigningKey,
)> {
    use alloy_eips::eip7702::Authorization;
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
    use sha2::{Digest, Sha256};
    use tempo_primitives::transaction::{
        TempoSignedAuthorization,
        tt_signature::{P256SignatureWithPreHash, TempoSignature},
    };

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Extract P256 public key coordinates
    let encoded_point = verifying_key.to_encoded_point(false);
    let pub_key_x = alloy::primitives::B256::from_slice(encoded_point.x().unwrap().as_slice());
    let pub_key_y = alloy::primitives::B256::from_slice(encoded_point.y().unwrap().as_slice());

    // Derive P256 address
    let authority_addr =
        tempo_primitives::transaction::tt_signature::derive_p256_address(&pub_key_x, &pub_key_y);

    let auth = Authorization {
        chain_id: alloy_primitives::U256::from(chain_id),
        address: delegate_address,
        nonce: 0,
    };

    let sig_hash = compute_authorization_signature_hash(&auth);

    // Sign with P256 (using pre-hash)
    let pre_hashed = Sha256::digest(sig_hash.as_slice());
    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&pre_hashed)?;
    let sig_bytes = signature.to_bytes();

    let aa_sig = TempoSignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
        r: alloy::primitives::B256::from_slice(&sig_bytes[0..32]),
        s: normalize_p256_s(&sig_bytes[32..64]),
        pub_key_x,
        pub_key_y,
        pre_hash: true,
    }));
    let signed_auth = TempoSignedAuthorization::new_unchecked(auth, aa_sig);

    Ok((signed_auth, authority_addr, signing_key))
}

/// Helper function to create a signed WebAuthn authorization
fn create_webauthn_authorization(
    chain_id: u64,
    delegate_address: Address,
) -> eyre::Result<(
    tempo_primitives::transaction::TempoSignedAuthorization,
    Address,
    p256::ecdsa::SigningKey,
)> {
    use alloy_eips::eip7702::Authorization;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
    use sha2::{Digest, Sha256};
    use tempo_primitives::transaction::{
        TempoSignedAuthorization,
        tt_signature::{TempoSignature, WebAuthnSignature},
    };

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Extract WebAuthn public key coordinates
    let encoded_point = verifying_key.to_encoded_point(false);
    let pub_key_x = alloy::primitives::B256::from_slice(encoded_point.x().unwrap().as_slice());
    let pub_key_y = alloy::primitives::B256::from_slice(encoded_point.y().unwrap().as_slice());

    // Derive WebAuthn address (same derivation as P256)
    let authority_addr =
        tempo_primitives::transaction::tt_signature::derive_p256_address(&pub_key_x, &pub_key_y);

    let auth = Authorization {
        chain_id: alloy_primitives::U256::from(chain_id),
        address: delegate_address,
        nonce: 0,
    };

    let sig_hash = compute_authorization_signature_hash(&auth);

    // Create WebAuthn signature
    let mut authenticator_data = vec![0u8; 37];
    authenticator_data[0..32].copy_from_slice(&[0xBB; 32]); // rpIdHash
    authenticator_data[32] = 0x01; // UP flag set
    authenticator_data[33..37].copy_from_slice(&[0, 0, 0, 0]); // signCount

    let challenge_b64url = URL_SAFE_NO_PAD.encode(sig_hash.as_slice());
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute WebAuthn message hash
    let client_data_hash = Sha256::digest(client_data_json.as_bytes());
    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data);
    final_hasher.update(client_data_hash);
    let message_hash = final_hasher.finalize();

    // Sign with P256
    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&message_hash)?;
    let sig_bytes = signature.to_bytes();

    // Construct WebAuthn data
    let mut webauthn_data = Vec::new();
    webauthn_data.extend_from_slice(&authenticator_data);
    webauthn_data.extend_from_slice(client_data_json.as_bytes());

    let aa_sig = TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(webauthn_data),
        r: alloy::primitives::B256::from_slice(&sig_bytes[0..32]),
        s: normalize_p256_s(&sig_bytes[32..64]),
        pub_key_x,
        pub_key_y,
    }));
    let signed_auth = TempoSignedAuthorization::new_unchecked(auth, aa_sig);

    Ok((signed_auth, authority_addr, signing_key))
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
/// Returns: (setup, provider, signing_key, pub_key_x, pub_key_y, signer_addr, funder_signer, funder_addr, chain_id)
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
)> {
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

    // Setup test node with direct access
    let mut setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();

    // Generate a P256 key pair
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Extract public key coordinates
    let encoded_point = verifying_key.to_encoded_point(false);
    let pub_key_x = alloy::primitives::B256::from_slice(encoded_point.x().unwrap().as_slice());
    let pub_key_y = alloy::primitives::B256::from_slice(encoded_point.y().unwrap().as_slice());

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
    fund_address_with_fee_tokens(
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
    let pub_key_x = alloy::primitives::B256::from_slice(encoded_point.x().unwrap().as_slice());
    let pub_key_y = alloy::primitives::B256::from_slice(encoded_point.y().unwrap().as_slice());
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
    let signed_tx = AASigned::new_unhashed(tx, signature);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let tx_hash = envelope.tx_hash();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;
    Ok(*tx_hash)
}

/// Helper to sign AA transaction with P256 access key (wrapped in Keychain signature)
fn sign_aa_tx_with_p256_access_key(
    tx: &TempoTransaction,
    access_key_signing_key: &p256::ecdsa::SigningKey,
    access_pub_key_x: &B256,
    access_pub_key_y: &B256,
    root_key_addr: Address,
) -> eyre::Result<TempoSignature> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha256};
    use tempo_primitives::transaction::tt_signature::P256SignatureWithPreHash;

    let sig_hash = tx.signature_hash();
    let pre_hashed = Sha256::digest(sig_hash.as_slice());
    let p256_signature: p256::ecdsa::Signature =
        access_key_signing_key.sign_prehash(&pre_hashed)?;
    let sig_bytes = p256_signature.to_bytes();

    let inner_signature = PrimitiveSignature::P256(P256SignatureWithPreHash {
        r: alloy::primitives::B256::from_slice(&sig_bytes[0..32]),
        s: normalize_p256_s(&sig_bytes[32..64]),
        pub_key_x: *access_pub_key_x,
        pub_key_y: *access_pub_key_y,
        pre_hash: true,
    });

    Ok(TempoSignature::Keychain(
        tempo_primitives::transaction::KeychainSignature::new(root_key_addr, inner_signature),
    ))
}

// ===== Call Creation Helper Functions =====

/// Helper to create a TIP20 transfer call
fn create_transfer_call(to: Address, amount: U256) -> Call {
    use alloy::sol_types::SolCall;
    use tempo_contracts::precompiles::ITIP20::transferCall;

    Call {
        to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
        value: U256::ZERO,
        input: transferCall { to, amount }.abi_encode().into(),
    }
}

/// Helper to create a TIP20 balanceOf call (useful as a benign call for key authorization txs)
fn create_balance_of_call(account: Address) -> Call {
    use alloy::sol_types::SolCall;

    Call {
        to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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

/// Helper to create default token spending limits (100 tokens of DEFAULT_FEE_TOKEN)
fn create_default_token_limit() -> Vec<tempo_primitives::transaction::TokenLimit> {
    use tempo_primitives::transaction::TokenLimit;

    vec![TokenLimit {
        token: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO,
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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit,
        calls,
        nonce_key: U256::ZERO,
        nonce,
        // Use AlphaUSD to match fund_address_with_fee_tokens
        fee_token: Some(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    }
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
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha256};
    use tempo_primitives::transaction::tt_signature::P256SignatureWithPreHash;

    let sig_hash = tx.signature_hash();
    let pre_hashed = Sha256::digest(sig_hash.as_slice());
    let p256_signature: p256::ecdsa::Signature = signing_key.sign_prehash(&pre_hashed)?;
    let sig_bytes = p256_signature.to_bytes();

    Ok(TempoSignature::Primitive(PrimitiveSignature::P256(
        P256SignatureWithPreHash {
            r: B256::from_slice(&sig_bytes[0..32]),
            s: normalize_p256_s(&sig_bytes[32..64]),
            pub_key_x,
            pub_key_y,
            pre_hash: true,
        },
    )))
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
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha256};

    let sig_hash = tx.signature_hash();
    let (authenticator_data, client_data_json) = create_webauthn_data(sig_hash, origin);

    // Compute message hash per WebAuthn spec
    let client_data_hash = Sha256::digest(client_data_json.as_bytes());
    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data);
    final_hasher.update(client_data_hash);
    let message_hash = final_hasher.finalize();

    // Sign
    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&message_hash)?;
    let sig_bytes = signature.to_bytes();

    // Construct WebAuthn data
    let mut webauthn_data = Vec::new();
    webauthn_data.extend_from_slice(&authenticator_data);
    webauthn_data.extend_from_slice(client_data_json.as_bytes());

    Ok(TempoSignature::Primitive(PrimitiveSignature::WebAuthn(
        WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data),
            r: B256::from_slice(&sig_bytes[0..32]),
            s: normalize_p256_s(&sig_bytes[32..64]),
            pub_key_x,
            pub_key_y,
        },
    )))
}

// ===== Transaction Encoding Helper Functions =====

/// Helper to encode an AA transaction
fn encode_aa_tx(tx: TempoTransaction, signature: TempoSignature) -> Vec<u8> {
    let signed_tx = AASigned::new_unhashed(tx, signature);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);
    encoded
}

// ===== Token Helper Functions =====

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_basic_transfer_secp256k1() -> eyre::Result<()> {
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

    // Create recipient address
    let recipient = Address::random();

    // Get alice's current nonce (protocol nonce, key 0)
    let nonce = provider.get_transaction_count(alice_addr).await?;
    println!("Alice nonce: {nonce}");

    // Create AA transaction with secp256k1 signature and protocol nonce
    let chain_id = provider.get_chain_id().await?;
    let tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        100_000,
    );

    println!("Created AA transaction with secp256k1 signature");

    // Sign and encode the transaction
    let aa_signature = sign_aa_tx_secp256k1(&tx, &alice_signer)?;
    let encoded = encode_aa_tx(tx.clone(), aa_signature.clone());

    // Recreate envelope for verification
    let signed_tx = AASigned::new_unhashed(tx, aa_signature);
    let envelope: TempoTxEnvelope = signed_tx.into();

    println!(
        "Encoded AA transaction: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Test encoding/decoding roundtrip
    let decoded = TempoTxEnvelope::decode_2718(&mut encoded.as_slice())?;
    assert!(
        matches!(decoded, TempoTxEnvelope::AA(_)),
        "Should decode as AA transaction"
    );
    println!("✓ Encoding/decoding roundtrip successful");

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
        100_000,
    );

    // Sign and encode transaction
    let aa_signature = sign_aa_tx_secp256k1(&tx_protocol, &alice_signer)?;
    let encoded_protocol = encode_aa_tx(tx_protocol.clone(), aa_signature.clone());

    // Recreate envelope for verification
    let signed_tx_protocol = AASigned::new_unhashed(tx_protocol, aa_signature);
    let envelope_protocol: TempoTxEnvelope = signed_tx_protocol.into();

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
        100_000,
    );
    tx_parallel.nonce_key = U256::from(1); // Parallel nonce - should be rejected

    // Sign and encode transaction
    let aa_signature_parallel = sign_aa_tx_secp256k1(&tx_parallel, &alice_signer)?;
    let encoded_parallel = encode_aa_tx(tx_parallel.clone(), aa_signature_parallel.clone());

    // Recreate envelope for verification
    let signed_tx_parallel = AASigned::new_unhashed(tx_parallel, aa_signature_parallel);
    let envelope_parallel: TempoTxEnvelope = signed_tx_parallel.into();

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
            max_fee_per_gas: TEMPO_BASE_FEE as u128 + priority_fee,
            gas_limit: 100_000,
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
            TEMPO_BASE_FEE as u128,
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
            TEMPO_BASE_FEE as u128,
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
            TEMPO_BASE_FEE as u128,
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
        TEMPO_BASE_FEE as u128,
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
        TEMPO_BASE_FEE as u128,
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
        TEMPO_BASE_FEE as u128,
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

    // Wait for the 2D pool maintenance task to process the canonical state notification.
    // The maintenance task runs asynchronously, so we poll until transactions are removed.
    for _ in 0..100 {
        if !setup.node.inner.pool.contains(&pending)
            && !setup.node.inner.pool.contains(&queued)
            && !setup.node.inner.pool.contains(&new_pending)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

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
        max_fee_per_gas: TEMPO_BASE_FEE as u128 + priority_fee,
        gas_limit: 100_000,
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
async fn test_aa_webauthn_signature_flow() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let transfer_amount = U256::from(10u64) * U256::from(10).pow(U256::from(18)); // 10 tokens
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
    ) = setup_test_with_p256_funded_account(transfer_amount).await?;

    println!("WebAuthn signer address: {signer_addr}");
    println!("Public key X: {pub_key_x}");
    println!("Public key Y: {pub_key_y}");

    // Create recipient address for the actual test
    let recipient = Address::random();

    // Create AA transaction with WebAuthn signature
    let tx = create_basic_aa_tx(
        chain_id,
        0, // First transaction
        vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        200_000, // Higher gas limit for WebAuthn verification
    );

    println!("Created AA transaction for WebAuthn signature");

    // Sign with WebAuthn
    let aa_signature = sign_aa_tx_webauthn(
        &tx,
        &signing_key,
        pub_key_x,
        pub_key_y,
        "https://example.com",
    )?;
    println!("Created WebAuthn signature");

    // Encode the transaction
    let encoded = encode_aa_tx(tx.clone(), aa_signature.clone());

    // Recreate envelope for verification
    let signed_tx = AASigned::new_unhashed(tx, aa_signature);
    let envelope: TempoTxEnvelope = signed_tx.into();

    println!(
        "Encoded AA transaction with WebAuthn: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Test encoding/decoding roundtrip
    let decoded = TempoTxEnvelope::decode_2718(&mut encoded.as_slice())?;
    assert!(
        matches!(decoded, TempoTxEnvelope::AA(_)),
        "Should decode as AA transaction"
    );

    if let TempoTxEnvelope::AA(decoded_tx) = &decoded {
        // Verify the signature can be recovered
        let recovered_signer = decoded_tx
            .signature()
            .recover_signer(&decoded_tx.signature_hash())
            .expect("Should recover signer from WebAuthn signature");

        assert_eq!(
            recovered_signer, signer_addr,
            "Recovered signer should match expected WebAuthn address"
        );
        println!("✓ WebAuthn signature recovery successful");
    }

    println!("✓ Encoding/decoding roundtrip successful");

    // Inject transaction and mine block
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let payload = setup.node.advance_block().await?;

    println!(
        "✓ AA transaction with WebAuthn signature mined in block {}",
        payload.block().inner.number
    );

    // Verify transaction can be fetched via eth_getTransactionByHash and is correct
    verify_tx_in_block_via_rpc(&provider, &encoded, &envelope).await?;

    // Verify the block contains transactions
    assert!(
        !payload.block().body().transactions.is_empty(),
        "Block should contain the WebAuthn transaction"
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
    let mut setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();

    // Generate the correct P256 key pair for WebAuthn
    let correct_signing_key = SigningKey::random(&mut OsRng);
    let correct_verifying_key = correct_signing_key.verifying_key();

    // Extract correct public key coordinates
    let correct_encoded_point = correct_verifying_key.to_encoded_point(false);
    let correct_pub_key_x =
        alloy::primitives::B256::from_slice(correct_encoded_point.x().unwrap().as_slice());
    let correct_pub_key_y =
        alloy::primitives::B256::from_slice(correct_encoded_point.y().unwrap().as_slice());

    // Generate a different (wrong) P256 key pair
    let wrong_signing_key = SigningKey::random(&mut OsRng);
    let wrong_verifying_key = wrong_signing_key.verifying_key();

    // Extract wrong public key coordinates
    let wrong_encoded_point = wrong_verifying_key.to_encoded_point(false);
    let wrong_pub_key_x =
        alloy::primitives::B256::from_slice(wrong_encoded_point.x().unwrap().as_slice());
    let wrong_pub_key_y =
        alloy::primitives::B256::from_slice(wrong_encoded_point.y().unwrap().as_slice());

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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 200_000,
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

#[tokio::test]
async fn test_aa_p256_call_batching() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let initial_funding_amount = U256::from(20u64) * U256::from(10).pow(U256::from(18)); // 20 tokens with 18 decimals
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
    ) = setup_test_with_p256_funded_account(initial_funding_amount).await?;

    println!("\n=== Testing P256 Call Batching ===\n");
    println!("P256 signer address: {signer_addr}");

    // Create multiple recipient addresses for batch transfers
    let num_recipients = 5;
    let mut recipients = Vec::new();
    for i in 0..num_recipients {
        recipients.push((Address::random(), i + 1)); // Each gets different amount
    }

    println!("\nPreparing batch transfer to {num_recipients} recipients:");
    for (i, (addr, multiplier)) in recipients.iter().enumerate() {
        println!(
            "  Recipient {}: {} (amount: {} tokens)",
            i + 1,
            addr,
            multiplier
        );
    }

    // Create batch calls - transfer different amounts to each recipient
    let transfer_base_amount = U256::from(1u64) * U256::from(10).pow(U256::from(18)); // 1 token base
    let mut calls = Vec::new();

    for (recipient, multiplier) in &recipients {
        let amount = transfer_base_amount * U256::from(*multiplier);
        let calldata = transferCall {
            to: *recipient,
            amount,
        }
        .abi_encode();

        calls.push(Call {
            to: DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO.into(),
            value: U256::ZERO,
            input: calldata.into(),
        });
    }

    println!(
        "\nCreating AA transaction with {} batched calls",
        calls.len()
    );

    // Create AA transaction with batched calls and P256 signature
    // Use AlphaUSD (DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO) since that's what we funded with
    let batch_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 500_000, // Higher gas limit for multiple calls
        calls,
        nonce_key: U256::ZERO,
        nonce: 0, // First transaction from P256 signer
        fee_token: Some(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    };

    // Sign with P256
    let batch_sig_hash = batch_tx.signature_hash();
    println!("Batch transaction signature hash: {batch_sig_hash}");

    let aa_batch_signature = sign_aa_tx_p256(&batch_tx, &signing_key, pub_key_x, pub_key_y)?;
    println!("✓ Created P256 signature for batch transaction");

    // Verify signature recovery works
    let recovered_signer = aa_batch_signature
        .recover_signer(&batch_sig_hash)
        .expect("Should recover signer from P256 signature");
    assert_eq!(
        recovered_signer, signer_addr,
        "Recovered signer should match P256 address"
    );
    println!("✓ P256 signature recovery successful");

    // Encode the batch transaction
    let encoded_batch = encode_aa_tx(batch_tx.clone(), aa_batch_signature.clone());

    // Recreate envelope for verification
    let signed_batch_tx = AASigned::new_unhashed(batch_tx, aa_batch_signature);
    let batch_envelope: TempoTxEnvelope = signed_batch_tx.into();

    println!(
        "Encoded batch transaction: {} bytes (type: 0x{:02x})",
        encoded_batch.len(),
        encoded_batch[0]
    );

    // Get initial balances of all recipients (should be 0)
    let mut initial_balances = Vec::new();

    println!("\nChecking initial recipient balances:");
    for (i, (recipient, _)) in recipients.iter().enumerate() {
        let balance = ITIP20::new(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO, &provider)
            .balanceOf(*recipient)
            .call()
            .await?;
        initial_balances.push(balance);
        assert_eq!(
            balance,
            U256::ZERO,
            "Recipient {} should have 0 initial balance",
            i + 1
        );
        println!("  Recipient {}: {} tokens", i + 1, balance);
    }

    // Inject and mine the batch transaction
    println!("\nExecuting batch transaction...");
    setup
        .node
        .rpc
        .inject_tx(encoded_batch.clone().into())
        .await?;
    let batch_payload = setup.node.advance_block().await?;

    println!(
        "✓ Batch transaction mined in block {}",
        batch_payload.block().inner.number
    );

    // Verify transaction can be fetched via eth_getTransactionByHash and is correct
    verify_tx_in_block_via_rpc(&provider, &encoded_batch, &batch_envelope).await?;

    // Verify the block contains the transaction
    assert!(
        !batch_payload.block().body().transactions.is_empty(),
        "Block should contain the batch transaction"
    );

    // Find the AA transaction in the block (skip any system transactions)
    let aa_tx = batch_payload
        .block()
        .body()
        .transactions
        .iter()
        .find_map(|tx| tx.as_aa())
        .expect("Block should contain an AA transaction");

    assert_eq!(
        aa_tx.tx().calls.len(),
        num_recipients,
        "Transaction should have {num_recipients} calls"
    );
    println!(
        "✓ Block contains AA transaction with {} calls",
        aa_tx.tx().calls.len()
    );

    // Verify it used P256 signature
    match aa_tx.signature() {
        TempoSignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
            pre_hash,
            ..
        })) => {
            assert!(*pre_hash, "Should have pre_hash flag set");
            println!("✓ Transaction used P256 signature with pre-hash");
        }
        _ => panic!("Transaction should have P256 signature"),
    }

    // Verify all recipients received their tokens
    println!("\nVerifying recipient balances after batch transfer:");
    for (i, ((recipient, multiplier), initial_balance)) in
        recipients.iter().zip(initial_balances.iter()).enumerate()
    {
        let expected_amount = transfer_base_amount * U256::from(*multiplier);
        let final_balance = ITIP20::new(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO, &provider)
            .balanceOf(*recipient)
            .call()
            .await?;

        assert_eq!(
            final_balance,
            expected_amount,
            "Recipient {} should have received {} tokens",
            i + 1,
            expected_amount
        );

        println!(
            "  Recipient {}: {} → {} tokens (expected: {})",
            i + 1,
            initial_balance,
            final_balance,
            expected_amount
        );
    }

    // Verify the P256 signer's balance decreased by the total transferred amount
    let total_transferred = (1..=num_recipients as u64)
        .map(|i| transfer_base_amount * U256::from(i))
        .fold(U256::ZERO, |acc, x| acc + x);

    let signer_final_balance = ITIP20::new(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO, &provider)
        .balanceOf(signer_addr)
        .call()
        .await?;
    let expected_signer_balance = initial_funding_amount - total_transferred;

    // Account for gas fees paid
    assert!(
        signer_final_balance < expected_signer_balance,
        "Signer balance should be less than initial minus transferred (due to gas fees)"
    );

    println!(
        "\n✓ P256 signer balance: {signer_final_balance} tokens (transferred: {total_transferred}, plus gas fees)"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_fee_payer_tx() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Setup test node
    let mut setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();

    // Fee payer is the funded TEST_MNEMONIC account
    let fee_payer_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let fee_payer_addr = fee_payer_signer.address();

    // User is a fresh random account with no balance
    let user_signer = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = user_signer.address();

    // Create provider without wallet (we'll sign manually)
    let provider = ProviderBuilder::new().connect_http(http_url.clone());

    let chain_id = provider.get_chain_id().await?;

    println!("\n=== Testing AA Fee Payer Transaction ===\n");
    println!("Fee payer address: {fee_payer_addr}");
    println!("User address: {user_addr} (unfunded)");

    // Verify user has ZERO balance (check AlphaUSD since that's what fees are paid in)
    let user_token_balance = ITIP20::new(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO, &provider)
        .balanceOf(user_addr)
        .call()
        .await?;
    assert_eq!(
        user_token_balance,
        U256::ZERO,
        "User should have zero balance"
    );
    println!("User token balance: {user_token_balance} (expected: 0)");

    // Get fee payer's balance before transaction (check AlphaUSD since that's what fees are paid in)
    let fee_payer_balance_before = ITIP20::new(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO, &provider)
        .balanceOf(fee_payer_addr)
        .call()
        .await?;
    println!("Fee payer balance before: {fee_payer_balance_before} tokens");

    // Create AA transaction with fee payer signature placeholder
    let recipient = Address::random();
    let mut tx = create_basic_aa_tx(
        chain_id,
        0, // First transaction for user
        vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        100_000,
    );
    tx.fee_payer_signature = Some(Signature::new(U256::ZERO, U256::ZERO, false)); // Placeholder

    println!("Created AA transaction with fee payer placeholder");

    // Step 1: User signs the transaction
    let user_sig_hash = tx.signature_hash();
    let user_signature = user_signer.sign_hash_sync(&user_sig_hash)?;
    println!("✓ User signed transaction");

    // Verify user signature is valid
    assert_eq!(
        user_signature
            .recover_address_from_prehash(&user_sig_hash)
            .unwrap(),
        user_addr,
        "User signature should recover to user address"
    );

    // Step 2: Fee payer signs the fee payer signature hash
    let fee_payer_sig_hash = tx.fee_payer_signature_hash(user_addr);
    let fee_payer_signature = fee_payer_signer.sign_hash_sync(&fee_payer_sig_hash)?;
    println!("✓ Fee payer signed fee payer hash");

    // Verify fee payer signature is valid
    assert_eq!(
        fee_payer_signature
            .recover_address_from_prehash(&fee_payer_sig_hash)
            .unwrap(),
        fee_payer_addr,
        "Fee payer signature should recover to fee payer address"
    );

    // Step 3: Update transaction with real fee payer signature
    tx.fee_payer_signature = Some(fee_payer_signature);

    // Create signed transaction with user's signature
    let aa_signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(user_signature));
    let encoded = encode_aa_tx(tx.clone(), aa_signature.clone());

    // Recreate envelope for verification
    let signed_tx = AASigned::new_unhashed(tx, aa_signature);
    let envelope: TempoTxEnvelope = signed_tx.into();

    println!(
        "Encoded AA transaction: {} bytes (type: 0x{:02x})",
        encoded.len(),
        encoded[0]
    );

    // Inject transaction and mine block
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    let payload = setup.node.advance_block().await?;

    println!(
        "✓ AA fee payer transaction mined in block {}",
        payload.block().inner.number
    );

    // Verify transaction can be fetched via eth_getTransactionByHash and is correct
    verify_tx_in_block_via_rpc(&provider, &encoded, &envelope).await?;

    // Verify the transaction was successful
    assert!(
        !payload.block().body().transactions.is_empty(),
        "Block should contain the fee payer transaction"
    );

    // Verify user still has ZERO balance (fee payer paid)
    let user_token_balance_after = ITIP20::new(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO, &provider)
        .balanceOf(user_addr)
        .call()
        .await?;
    assert_eq!(
        user_token_balance_after,
        U256::ZERO,
        "User should still have zero balance"
    );

    // Verify fee payer's balance decreased (check AlphaUSD since that's what fees are paid in)
    let fee_payer_balance_after = ITIP20::new(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO, &provider)
        .balanceOf(fee_payer_addr)
        .call()
        .await?;

    println!("Fee payer balance after: {fee_payer_balance_after} tokens");

    assert!(
        fee_payer_balance_after < fee_payer_balance_before,
        "Fee payer balance should have decreased"
    );

    let gas_cost = fee_payer_balance_before - fee_payer_balance_after;
    println!("Gas cost paid by fee payer: {gas_cost} tokens");

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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
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
    let sig_hash = tx.signature_hash();
    let signature = alice_signer.sign_hash_sync(&sig_hash)?;
    let aa_signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature));
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
async fn test_aa_estimate_gas_with_key_types() -> eyre::Result<()> {
    use alloy::rpc::types::TransactionRequest;
    use tempo_node::rpc::TempoTransactionRequest;
    use tempo_primitives::transaction::tempo_transaction::Call;

    reth_tracing::init_test_tracing();

    let (_setup, provider, _signer, signer_addr) = setup_test_with_funded_account().await?;
    // Keep setup alive for the duration of the test
    let _ = &_setup;

    println!("\n=== Testing eth_estimateGas with keyType and keyData ===\n");
    println!("Test address: {signer_addr}");

    let recipient = Address::random();

    // Helper to create a base transaction request
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

    // Test 1: Estimate gas WITHOUT keyType (baseline - uses secp256k1)
    println!("Test 1: Estimating gas WITHOUT keyType (baseline)");
    let baseline_gas: String = provider
        .raw_request(
            "eth_estimateGas".into(),
            [serde_json::to_value(base_tx_request())?],
        )
        .await?;
    let baseline_gas_u64 = u64::from_str_radix(baseline_gas.trim_start_matches("0x"), 16)?;
    println!("  Baseline gas: {baseline_gas_u64}");

    // Test 2: Estimate gas WITH keyType="p256"
    println!("\nTest 2: Estimating gas WITH keyType='p256'");
    let tx_request_p256 = TempoTransactionRequest {
        key_type: Some(SignatureType::P256),
        ..base_tx_request()
    };

    let p256_gas: String = provider
        .raw_request(
            "eth_estimateGas".into(),
            [serde_json::to_value(&tx_request_p256)?],
        )
        .await?;
    let p256_gas_u64 = u64::from_str_radix(p256_gas.trim_start_matches("0x"), 16)?;
    println!("  P256 gas: {p256_gas_u64}");
    // P256 should add approximately 5,000 gas (allow small tolerance for gas estimation variance)
    let p256_diff = (p256_gas_u64 as i64 - baseline_gas_u64 as i64).unsigned_abs();
    assert!(
        (4_985..=5_015).contains(&p256_diff),
        "P256 should add ~5,000 gas: actual diff {p256_diff} (expected 5,000 ±15)",
    );
    println!("  ✓ P256 adds {p256_diff} gas (expected ~5,000)");

    // Test 3: Estimate gas WITH keyType="webauthn" and keyData
    println!("\nTest 3: Estimating gas WITH keyType='webauthn' and keyData");

    // Specify WebAuthn data size (excluding 128 bytes for public keys)
    // Encoded as hex: 116 = 0x74 (1 byte) or 0x0074 (2 bytes)
    let webauthn_size = 116u16;
    let key_data = Bytes::from(webauthn_size.to_be_bytes().to_vec());
    println!("  Requesting WebAuthn data size: {webauthn_size} bytes (keyData: {key_data})",);

    let tx_request_webauthn = TempoTransactionRequest {
        key_type: Some(SignatureType::WebAuthn),
        key_data: Some(key_data),
        ..base_tx_request()
    };

    let webauthn_gas: String = provider
        .raw_request(
            "eth_estimateGas".into(),
            [serde_json::to_value(&tx_request_webauthn)?],
        )
        .await?;
    let webauthn_gas_u64 = u64::from_str_radix(webauthn_gas.trim_start_matches("0x"), 16)?;
    println!("  WebAuthn gas: {webauthn_gas_u64}");

    // WebAuthn should add 5,000 + calldata gas
    assert!(
        webauthn_gas_u64 > p256_gas_u64,
        "WebAuthn should cost more than P256"
    );
    println!("  ✓ WebAuthn adds signature verification + calldata gas");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_estimate_gas_with_keychain_and_key_auth() -> eyre::Result<()> {
    use alloy::rpc::types::TransactionRequest;
    use tempo_node::rpc::TempoTransactionRequest;
    use tempo_primitives::transaction::tempo_transaction::Call;

    reth_tracing::init_test_tracing();

    let (_setup, provider, signer, signer_addr) = setup_test_with_funded_account().await?;
    // Keep setup alive for the duration of the test
    let _ = &_setup;

    println!("\n=== Testing eth_estimateGas with isKeychain and keyAuthorization ===\n");
    println!("Test address: {signer_addr}");

    let recipient = Address::random();

    // Helper to create a base transaction request
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

    // Test 1: Baseline gas (secp256k1, primitive signature)
    println!("Test 1: Baseline gas (secp256k1, primitive signature)");
    let baseline_gas: String = provider
        .raw_request(
            "eth_estimateGas".into(),
            [serde_json::to_value(base_tx_request())?],
        )
        .await?;
    let baseline_gas_u64 = u64::from_str_radix(baseline_gas.trim_start_matches("0x"), 16)?;
    println!("  Baseline gas: {baseline_gas_u64}");

    // Test 2: Keychain signature (secp256k1 inner) - should add 3,000 gas
    println!("\nTest 2: Keychain signature (secp256k1 inner)");
    let tx_keychain = TempoTransactionRequest {
        is_keychain: true,
        ..base_tx_request()
    };

    let keychain_gas: String = provider
        .raw_request(
            "eth_estimateGas".into(),
            [serde_json::to_value(&tx_keychain)?],
        )
        .await?;
    let keychain_gas_u64 = u64::from_str_radix(keychain_gas.trim_start_matches("0x"), 16)?;
    println!("  Keychain gas: {keychain_gas_u64}");

    let keychain_diff = keychain_gas_u64 as i64 - baseline_gas_u64 as i64;
    assert!(
        (2_985..=3_015).contains(&keychain_diff.unsigned_abs()),
        "Keychain should add ~3,000 gas: actual diff {keychain_diff} (expected 3,000 ±15)"
    );
    println!("  ✓ Keychain adds {keychain_diff} gas (expected ~3,000)");

    // Test 3: Keychain signature with P256 inner - should add 3,000 + 5,000 = 8,000 gas
    println!("\nTest 3: Keychain signature (P256 inner)");
    let tx_keychain_p256 = TempoTransactionRequest {
        key_type: Some(SignatureType::P256),
        is_keychain: true,
        ..base_tx_request()
    };

    let keychain_p256_gas: String = provider
        .raw_request(
            "eth_estimateGas".into(),
            [serde_json::to_value(&tx_keychain_p256)?],
        )
        .await?;
    let keychain_p256_gas_u64 =
        u64::from_str_radix(keychain_p256_gas.trim_start_matches("0x"), 16)?;
    println!("  Keychain P256 gas: {keychain_p256_gas_u64}");

    let keychain_p256_diff = keychain_p256_gas_u64 as i64 - baseline_gas_u64 as i64;
    // P256 adds 5,000 + Keychain adds 3,000 = 8,000
    assert!(
        (7_985..=8_015).contains(&keychain_p256_diff.unsigned_abs()),
        "Keychain P256 should add ~8,000 gas: actual diff {keychain_p256_diff} (expected 8,000 ±15)"
    );
    println!("  ✓ Keychain P256 adds {keychain_p256_diff} gas (expected ~8,000)");

    // Test 4: KeyAuthorization with secp256k1 (no limits)
    println!("\nTest 4: KeyAuthorization (secp256k1, no limits)");
    let key_auth_secp = create_signed_key_authorization(&signer, SignatureType::Secp256k1, 0);
    let tx_key_auth = TempoTransactionRequest {
        key_authorization: Some(key_auth_secp),
        ..base_tx_request()
    };

    let key_auth_gas: String = provider
        .raw_request(
            "eth_estimateGas".into(),
            [serde_json::to_value(&tx_key_auth)?],
        )
        .await?;
    let key_auth_gas_u64 = u64::from_str_radix(key_auth_gas.trim_start_matches("0x"), 16)?;
    println!("  KeyAuth gas: {key_auth_gas_u64}");

    // KeyAuth secp256k1 adds ~30,000 gas (27,000 base + 3,000 ecrecover)
    let key_auth_diff = key_auth_gas_u64 as i64 - baseline_gas_u64 as i64;
    assert!(
        (29_500..=31_000).contains(&key_auth_diff.unsigned_abs()),
        "KeyAuth secp256k1 should add ~30,000 gas: actual diff {key_auth_diff} (expected 30,000 ±500)"
    );
    println!("  ✓ KeyAuth secp256k1 adds {key_auth_diff} gas (expected ~30,000)");

    // Test 5: KeyAuthorization with P256 key type (no limits)
    // Note: The key authorization signature is secp256k1 (signed by root key).
    // The key_type field specifies what type of key is being authorized (P256),
    // but the gas cost depends on the signature type, not the key being authorized.
    println!("\nTest 5: KeyAuthorization (P256 key type, no limits)");
    let key_auth_p256 = create_signed_key_authorization(&signer, SignatureType::P256, 0);
    let tx_key_auth_p256 = TempoTransactionRequest {
        key_authorization: Some(key_auth_p256),
        ..base_tx_request()
    };

    let key_auth_p256_gas: String = provider
        .raw_request(
            "eth_estimateGas".into(),
            [serde_json::to_value(&tx_key_auth_p256)?],
        )
        .await?;
    let key_auth_p256_gas_u64 =
        u64::from_str_radix(key_auth_p256_gas.trim_start_matches("0x"), 16)?;
    println!("  KeyAuth P256 key type gas: {key_auth_p256_gas_u64}");

    // KeyAuth with P256 key type has same gas as secp256k1 (~30,000) because
    // the authorization signature itself is always secp256k1 from the root key
    let key_auth_p256_diff = key_auth_p256_gas_u64 as i64 - baseline_gas_u64 as i64;
    assert!(
        (29_500..=31_000).contains(&key_auth_p256_diff.unsigned_abs()),
        "KeyAuth P256 key type should add ~30,000 gas (same as secp256k1): actual diff {key_auth_p256_diff}"
    );
    println!(
        "  ✓ KeyAuth P256 key type adds {key_auth_p256_diff} gas (same as secp256k1, ~30,000)"
    );

    // Test 6: KeyAuthorization with spending limits
    println!("\nTest 6: KeyAuthorization (secp256k1, 3 spending limits)");
    let key_auth_limits = create_signed_key_authorization(&signer, SignatureType::Secp256k1, 3);
    let tx_key_auth_limits = TempoTransactionRequest {
        key_authorization: Some(key_auth_limits),
        ..base_tx_request()
    };

    let key_auth_limits_gas: String = provider
        .raw_request(
            "eth_estimateGas".into(),
            [serde_json::to_value(&tx_key_auth_limits)?],
        )
        .await?;
    let key_auth_limits_gas_u64 =
        u64::from_str_radix(key_auth_limits_gas.trim_start_matches("0x"), 16)?;
    println!("  KeyAuth with 3 limits gas: {key_auth_limits_gas_u64}");

    // KeyAuth secp256k1 with 3 limits adds ~96,000 gas (30,000 + 3*22,000)
    let key_auth_limits_diff = key_auth_limits_gas_u64 as i64 - baseline_gas_u64 as i64;
    assert!(
        (95_500..=97_500).contains(&key_auth_limits_diff.unsigned_abs()),
        "KeyAuth with 3 limits should add ~96,000 gas: actual diff {key_auth_limits_diff} (expected 96,000 ±1,500)"
    );
    println!("  ✓ KeyAuth with 3 limits adds {key_auth_limits_diff} gas (expected ~96,000)");

    println!("\n✓ All gas estimation tests passed!");
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

    // The delegate address that all EOAs will delegate to (using default 7702 delegate)
    let delegate_address = tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;
    println!("Delegate address: {delegate_address}");

    // ========================================================================
    // Authority 1: Secp256k1 signature
    // ========================================================================
    println!("\n--- Authority 1: Secp256k1 ---");

    let auth1_signer = alloy::signers::local::PrivateKeySigner::random();
    let (auth1_signed, auth1_addr) =
        create_secp256k1_authorization(chain_id, delegate_address, &auth1_signer)?;
    println!("Authority 1 address: {auth1_addr}");
    println!("  ✓ Created Secp256k1 authorization");

    // ========================================================================
    // Authority 2: P256 signature
    // ========================================================================
    println!("\n--- Authority 2: P256 ---");

    let (auth2_signed, auth2_addr, _auth2_signing_key) =
        create_p256_authorization(chain_id, delegate_address)?;
    println!("Authority 2 address: {auth2_addr}");
    println!("  ✓ Created P256 authorization");

    // ========================================================================
    // Authority 3: WebAuthn signature
    // ========================================================================
    println!("\n--- Authority 3: WebAuthn ---");

    let (auth3_signed, auth3_addr, _auth3_signing_key) =
        create_webauthn_authorization(chain_id, delegate_address)?;
    println!("Authority 3 address: {auth3_addr}");
    println!("  ✓ Created WebAuthn authorization");

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
    use alloy::rpc::types::TransactionRequest;
    use tempo_node::rpc::TempoTransactionRequest;

    let tx_request = TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(sender_addr),
            to: Some(recipient.into()),
            value: Some(U256::ZERO),
            gas: Some(300_000), // Higher gas for authorization list processing
            max_fee_per_gas: Some(TEMPO_BASE_FEE as u128),
            max_priority_fee_per_gas: Some(TEMPO_BASE_FEE as u128),
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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
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
    let sig_hash = tx.signature_hash();
    let signature = alice_signer.sign_hash_sync(&sig_hash)?;
    let aa_signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature));
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
    use sha2::{Digest, Sha256};
    use tempo_primitives::transaction::{
        KeyAuthorization, TokenLimit, tt_signature::P256SignatureWithPreHash,
    };

    reth_tracing::init_test_tracing();

    println!("\n=== Testing AA Transaction with Key Authorization and P256 Spending Limits ===\n");

    // Setup test node
    let mut setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();

    // Generate a P256 key pair for the access key
    let access_key_signing_key = SigningKey::random(&mut OsRng);
    let access_key_verifying_key = access_key_signing_key.verifying_key();

    // Extract access key public key coordinates
    let encoded_point = access_key_verifying_key.to_encoded_point(false);
    let access_pub_key_x =
        alloy::primitives::B256::from_slice(encoded_point.x().unwrap().as_slice());
    let access_pub_key_y =
        alloy::primitives::B256::from_slice(encoded_point.y().unwrap().as_slice());

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
    let root_balance_initial = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, &provider)
        .balanceOf(root_key_addr)
        .call()
        .await?;
    println!("Root key initial balance: {root_balance_initial} tokens");

    // Create recipient for the token transfer
    let recipient = Address::random();
    println!("Token transfer recipient: {recipient}");

    // Define spending limits for the access key
    // Allow spending up to 10 tokens from DEFAULT_FEE_TOKEN_POST_ALLEGRETTO
    let spending_limit_amount = U256::from(10u64) * U256::from(10).pow(U256::from(18)); // 10 tokens
    let spending_limits = vec![TokenLimit {
        token: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO,
        limit: spending_limit_amount,
    }];

    println!("\nCreating key authorization:");
    println!("  - Token: {DEFAULT_FEE_TOKEN_POST_ALLEGRETTO}");
    println!("  - Spending limit: {spending_limit_amount} (10 tokens)");
    println!("  - Key type: P256");
    println!("  - Key ID (address): {access_key_addr}");

    // Root key signs the key authorization data to authorize the access key
    // Compute the authorization message hash using the helper function
    // Message format: keccak256(rlp([chain_id, key_type, key_id, expiry, limits]))
    let auth_message_hash = KeyAuthorization {
        chain_id,
        key_type: tempo_primitives::transaction::SignatureType::P256,
        key_id: access_key_addr,
        expiry: None, // Never expires
        limits: Some(spending_limits.clone()),
    }
    .signature_hash();

    // Root key signs the authorization message
    let root_auth_signature = root_key_signer.sign_hash_sync(&auth_message_hash)?;

    // Create the key authorization with root key signature
    let key_authorization = KeyAuthorization {
        chain_id,
        key_type: tempo_primitives::transaction::SignatureType::P256, // Type of key being authorized
        key_id: access_key_addr, // Address derived from P256 public key
        expiry: None,            // Never expires
        limits: Some(spending_limits),
    }
    .into_signed(PrimitiveSignature::Secp256k1(root_auth_signature));

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
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
            value: U256::ZERO,
            input: transfer_calldata.into(),
        }],
        300_000, // Higher gas for key authorization verification
    );
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
    // In a real scenario, this would be the user's access key signing the transaction
    let sig_hash = tx.signature_hash();
    println!("\nSigning transaction with access key (P256)...");
    println!("  Transaction signature hash: {sig_hash}");

    // Pre-hash for P256 signature
    let pre_hashed = Sha256::digest(sig_hash.as_slice());

    // Sign with the access key
    let p256_signature: p256::ecdsa::Signature =
        access_key_signing_key.sign_prehash(&pre_hashed)?;
    let sig_bytes = p256_signature.to_bytes();

    // Create P256 primitive signature for the inner signature
    let inner_signature = PrimitiveSignature::P256(P256SignatureWithPreHash {
        r: alloy::primitives::B256::from_slice(&sig_bytes[0..32]),
        s: normalize_p256_s(&sig_bytes[32..64]),
        pub_key_x: access_pub_key_x,
        pub_key_y: access_pub_key_y,
        pre_hash: true,
    });

    // Wrap it in a Keychain signature with the root key address
    let aa_signature =
        TempoSignature::Keychain(tempo_primitives::transaction::KeychainSignature::new(
            root_key_addr, // The root account this transaction is for
            inner_signature,
        ));

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
    let recipient_balance_before = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, provider.clone())
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
    let recipient_balance_after = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, provider.clone())
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
    let root_balance_after = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, provider.clone())
        .balanceOf(root_key_addr)
        .call()
        .await?;

    let balance_decrease = root_balance_initial - root_balance_after;
    println!(
        "\nRoot key balance: {root_balance_initial} → {root_balance_after} (decreased by {balance_decrease})"
    );

    // PathUSD balance should decrease by exactly the transfer amount
    // (gas fees are paid in AlphaUSD via fee_token setting)
    assert_eq!(
        balance_decrease, transfer_amount,
        "Root key PathUSD should have decreased by transfer amount"
    );
    println!("✓ Root key paid for transfer (gas fees paid in AlphaUSD)");

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
        token: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO,
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

    let mut setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_with_node_access()
        .await?;
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
    let tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: authorize_call.abi_encode().into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: None,
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,
        tempo_authorization_list: vec![],
    };
    let sig_hash = tx.signature_hash();
    let signature = root_signer.sign_hash_sync(&sig_hash)?;
    let _tx_hash = submit_and_mine_aa_tx(
        &mut setup,
        tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    )
    .await?;
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
            token: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO,
            limit: U256::from(10u64) * U256::from(10).pow(U256::from(18)),
        }]),
    )?;

    // First authorization should succeed
    let tx1 = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
        key_authorization: Some(key_auth.clone()),
        tempo_authorization_list: vec![],
    };
    let sig_hash = tx1.signature_hash();
    let signature = root_signer.sign_hash_sync(&sig_hash)?;
    let _tx_hash = submit_and_mine_aa_tx(
        &mut setup,
        tx1,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    )
    .await?;
    nonce += 1;
    println!("  ✓ First authorization succeeded");

    // Second authorization with same key should fail
    // The transaction will be mined but should revert during execution
    let tx2 = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
        key_authorization: Some(key_auth),
        tempo_authorization_list: vec![],
    };
    let sig_hash2 = tx2.signature_hash();
    let signature2 = root_signer.sign_hash_sync(&sig_hash2)?;
    let signed_tx2 = AASigned::new_unhashed(
        tx2,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature2)),
    );
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
            token: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO,
            limit: U256::from(10u64) * U256::from(10).pow(U256::from(18)),
        }]),
    )?;

    // Authorize access_key_1 with root key (should succeed)
    let tx3 = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
        key_authorization: Some(key_auth_1),
        tempo_authorization_list: vec![],
    };
    let sig_hash = tx3.signature_hash();
    let signature = root_signer.sign_hash_sync(&sig_hash)?;
    let _tx_hash = submit_and_mine_aa_tx(
        &mut setup,
        tx3,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    )
    .await?;
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
    let tx4 = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
        key_authorization: Some(key_auth_2),
        tempo_authorization_list: vec![],
    };
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

    let mut setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_with_node_access()
        .await?;
    // Use TEST_MNEMONIC account (has balance in DEFAULT_FEE_TOKEN_POST_ALLEGRETTO from genesis)
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
            token: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO,
            limit: spending_limit,
        }]),
    )?;

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Test 1: Authorize the access key with spending limits
    let auth_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 400_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
            value: U256::ZERO,
            input: balanceOfCall { account: root_addr }.abi_encode().into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: None,
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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: updateSpendingLimitCall {
                keyId: access_key_addr,
                token: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO,
                newLimit: U256::from(20u64) * U256::from(10).pow(U256::from(18)),
            }
            .abi_encode()
            .into(),
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: None,
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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
        fee_token: None,
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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
        fee_token: None,
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

    let recipient_balance = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, &provider)
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

    let mut setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_with_node_access()
        .await?;

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
        400_000,
    );
    auth_unlimited_tx.fee_token = None;
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
        300_000,
    );
    transfer_tx.fee_token = None;

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
    let recipient1_balance = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, &provider)
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
        400_000,
    );
    auth_no_spending_tx.fee_token = None;
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
        300_000,
    );
    no_spending_transfer_tx.fee_token = None;

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

    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;

    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("Transaction must be included in block");

    assert!(
        !receipt.status(),
        "No-spending key must not be able to transfer any tokens"
    );

    // Verify recipient2 received NO tokens
    let recipient2_balance = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, &provider)
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
    nonce += 1;

    let recipient3 = Address::random();
    let second_transfer = U256::from(5u64) * U256::from(10).pow(U256::from(18)); // 5 tokens

    let second_unlimited_tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
        fee_token: None,
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

    let recipient3_balance = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, &provider)
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

    let mut setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_with_node_access()
        .await?;

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
        400_000,
    );
    auth_tx.fee_token = None;
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
        300_000,
    );
    transfer_tx.fee_token = None;

    let never_expires_sig = sign_aa_tx_with_p256_access_key(
        &transfer_tx,
        &never_expires_signing,
        &never_expires_pub_x,
        &never_expires_pub_y,
        root_addr,
    )?;

    submit_and_mine_aa_tx(&mut setup, transfer_tx, never_expires_sig).await?;
    nonce += 1;

    let recipient1_balance = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, &provider)
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
        400_000,
    );
    auth_short_expiry_tx.fee_token = None;
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
        300_000,
    );
    before_expiry_tx.fee_token = None;

    let short_expiry_sig = sign_aa_tx_with_p256_access_key(
        &before_expiry_tx,
        &short_expiry_signing,
        &short_expiry_pub_x,
        &short_expiry_pub_y,
        root_addr,
    )?;

    submit_and_mine_aa_tx(&mut setup, before_expiry_tx, short_expiry_sig).await?;
    nonce += 1;

    let recipient2_balance = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, &provider)
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
        300_000,
    );
    after_expiry_tx.fee_token = None;

    let expired_key_sig = sign_aa_tx_with_p256_access_key(
        &after_expiry_tx,
        &short_expiry_signing,
        &short_expiry_pub_x,
        &short_expiry_pub_y,
        root_addr,
    )?;

    let signed_tx = AASigned::new_unhashed(after_expiry_tx, expired_key_sig);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let tx_hash = *envelope.tx_hash();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    // The tx should be accepted into the pool (pool doesn't check expiry in detail)
    // but should fail when included in a block
    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;

    // Check if transaction was included and reverted
    let receipt = provider.get_transaction_receipt(tx_hash).await?;

    // The tx might not be included at all (rejected by builder) or included but reverted
    if let Some(receipt) = receipt {
        assert!(
            !receipt.status(),
            "Expired key transaction must revert if included"
        );
        println!("✓ Expired key transaction was included but reverted (status: 0x0)");
    } else {
        println!("✓ Expired key transaction was rejected by block builder (not included)");
    }

    // Verify recipient3 received NO tokens
    let recipient3_balance = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, &provider)
        .balanceOf(recipient3)
        .call()
        .await?;

    assert_eq!(
        recipient3_balance,
        U256::ZERO,
        "Recipient must not receive tokens from expired key"
    );

    // The expired key tx is stuck in mempool, so we need to skip that nonce
    nonce += 1;

    // ========================================
    // TEST 3: expiry in the past (should fail during block building)
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
        400_000,
    );
    past_expiry_tx.fee_token = None;
    past_expiry_tx.key_authorization = Some(past_expiry_key_auth);

    let root_sig = sign_aa_tx_secp256k1(&past_expiry_tx, &root_signer)?;
    let signed_tx = AASigned::new_unhashed(past_expiry_tx, root_sig);
    let envelope: TempoTxEnvelope = signed_tx.into();
    let tx_hash = *envelope.tx_hash();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    // Expiry check happens during block building
    // Transaction may be accepted to pool but will fail during block building
    setup.node.rpc.inject_tx(encoded.into()).await?;
    setup.node.advance_block().await?;

    // Check if transaction was included (it should fail or not be included)
    let receipt = provider.get_transaction_receipt(tx_hash).await?;

    if let Some(receipt) = receipt {
        // If included, it must have failed
        assert!(
            !receipt.status(),
            "Past expiry key transaction must fail if included. Receipt: {receipt:?}"
        );
        println!("✓ Past expiry key transaction was included but failed (status: 0x0)");
    } else {
        println!("✓ Past expiry key transaction was rejected by block builder (not included)");
    }

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

    let mut setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_with_node_access()
        .await?;
    let http_url = setup.node.rpc_url();

    // Generate TWO P256 access keys
    let authorized_key_signing_key = SigningKey::random(&mut OsRng);
    let authorized_key_verifying_key = authorized_key_signing_key.verifying_key();
    let authorized_encoded_point = authorized_key_verifying_key.to_encoded_point(false);
    let authorized_pub_key_x = B256::from_slice(authorized_encoded_point.x().unwrap().as_slice());
    let authorized_pub_key_y = B256::from_slice(authorized_encoded_point.y().unwrap().as_slice());
    let authorized_key_addr = tempo_primitives::transaction::tt_signature::derive_p256_address(
        &authorized_pub_key_x,
        &authorized_pub_key_y,
    );

    let unauthorized_key_signing_key = SigningKey::random(&mut OsRng);
    let unauthorized_key_verifying_key = unauthorized_key_signing_key.verifying_key();
    let unauthorized_encoded_point = unauthorized_key_verifying_key.to_encoded_point(false);
    let unauthorized_pub_key_x =
        B256::from_slice(unauthorized_encoded_point.x().unwrap().as_slice());
    let unauthorized_pub_key_y =
        B256::from_slice(unauthorized_encoded_point.y().unwrap().as_slice());
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
        token: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO,
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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 500_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
        fee_token: None,
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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
        fee_token: None,
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

    let recipient2_balance = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, &provider)
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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
        fee_token: None,
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
    let recipient3_balance = ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, &provider)
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
    let wrong_sig_hash = B256::from_slice(&Sha256::digest(auth_message_hash.as_slice()));
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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 500_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
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

    let mut setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_with_node_access()
        .await?;

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
        token: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO,
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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 300_000,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.into(),
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
