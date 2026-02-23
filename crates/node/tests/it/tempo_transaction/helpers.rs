use crate::utils::{SingleNodeSetup, TEST_MNEMONIC, TestNodeBuilder};
use alloy::{
    consensus::BlockHeader,
    hex,
    primitives::{Address, B256, Bytes, Signature, U256, keccak256},
    providers::Provider,
    rpc::types::TransactionRequest,
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
    sol_types::SolCall,
};
use alloy_eips::Encodable2718;
use alloy_primitives::TxKind;
use reth_primitives_traits::transaction::TxHashRef;
use reth_transaction_pool::TransactionPool;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;
use tempo_node::rpc::TempoTransactionRequest;
use tempo_precompiles::tip20::ITIP20::{self, transferCall};
use tempo_primitives::{
    SignatureType, TempoTransaction, TempoTxEnvelope,
    transaction::{
        KeyAuthorization, SignedKeyAuthorization, TEMPO_EXPIRING_NONCE_KEY,
        TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS, TokenLimit,
        tempo_transaction::Call,
        tt_signature::{
            KeychainSignature, P256SignatureWithPreHash, PrimitiveSignature, TempoSignature,
            WebAuthnSignature, normalize_p256_s,
        },
    },
};

use super::types::*;

/// Polls until the pool no longer contains the given tx hash, or returns error after timeout.
pub(super) async fn wait_until_pool_not_contains(
    pool: &impl TransactionPool,
    tx_hash: &alloy::primitives::B256,
    label: &str,
) -> eyre::Result<()> {
    let timeout = std::time::Duration::from_secs(10);
    let interval = std::time::Duration::from_millis(10);
    let start = std::time::Instant::now();
    while pool.contains(tx_hash) {
        if start.elapsed() > timeout {
            eyre::bail!("Timed out waiting for tx {tx_hash} to leave pool ({label})");
        }
        tokio::time::sleep(interval).await;
    }
    Ok(())
}

/// Fixed funding amount: 500 tokens (6 decimals).
/// Deterministic to ensure test reproducibility.
pub(crate) fn rand_funding_amount() -> U256 {
    U256::from(500_000_000u64)
}

/// Fixed sub-amount: max / 4. Panics if max < 4.
/// Deterministic to ensure test reproducibility.
pub(crate) fn rand_sub_amount(max: U256) -> U256 {
    max / U256::from(4)
}

// ---------------------------------------------------------------------------
// Localnet — TestEnv implementation for single-node local tests
// ---------------------------------------------------------------------------

pub(crate) struct Localnet {
    pub setup: SingleNodeSetup,
    pub provider: alloy::providers::RootProvider,
    pub chain_id: u64,
    pub funder_signer: alloy::signers::local::LocalSigner<alloy::signers::k256::ecdsa::SigningKey>,
    pub funder_addr: Address,
}

impl Localnet {
    pub(crate) async fn new() -> eyre::Result<Self> {
        reth_tracing::init_test_tracing();
        let setup = TestNodeBuilder::new().build_with_node_access().await?;
        let provider = alloy::providers::RootProvider::new_http(setup.node.rpc_url());
        let chain_id = provider.get_chain_id().await?;
        let funder_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
        let funder_addr = funder_signer.address();
        Ok(Self {
            setup,
            provider,
            chain_id,
            funder_signer,
            funder_addr,
        })
    }
}

impl super::types::TestEnv for Localnet {
    type P = alloy::providers::RootProvider;

    fn provider(&self) -> &Self::P {
        &self.provider
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    async fn fund_account(&mut self, addr: Address) -> eyre::Result<U256> {
        let amount = rand_funding_amount();
        fund_address_with(
            &mut self.setup,
            &self.provider,
            &self.funder_signer,
            self.funder_addr,
            addr,
            amount,
            DEFAULT_FEE_TOKEN,
            self.chain_id,
        )
        .await?;
        Ok(amount)
    }

    async fn submit_tx(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value> {
        self.setup.node.rpc.inject_tx(encoded.into()).await?;
        self.setup.node.advance_block().await?;

        let raw: Option<serde_json::Value> = self
            .provider
            .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
            .await?;
        let receipt =
            raw.ok_or_else(|| eyre::eyre!("Transaction receipt not found for {tx_hash}"))?;
        let status = receipt["status"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("Receipt missing status field"))?;
        assert_eq!(status, "0x1", "Receipt status mismatch for {tx_hash}");
        Ok(receipt)
    }

    async fn submit_tx_excluded_by_builder(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<()> {
        self.setup.node.rpc.inject_tx(encoded.into()).await?;
        assert!(
            self.setup.node.inner.pool.contains(&tx_hash),
            "Tx should be in pool after injection"
        );

        // Advance several blocks — tx should never be included by the builder.
        for _ in 0..5 {
            self.setup.node.advance_block().await?;

            let raw: Option<serde_json::Value> = self
                .provider
                .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
                .await?;
            if let Some(receipt) = raw {
                let status = receipt["status"].as_str().unwrap_or("?");
                panic!(
                    "Transaction {tx_hash} was mined (status={status}), \
                     expected exclusion by builder"
                );
            }
        }
        Ok(())
    }

    async fn bump_protocol_nonce(
        &mut self,
        signer: &PrivateKeySigner,
        signer_addr: Address,
        count: u64,
    ) -> eyre::Result<()> {
        let recipient = Address::random();
        let start_nonce = self.provider.get_transaction_count(signer_addr).await?;

        for i in 0..count {
            let tx = create_basic_aa_tx(
                self.chain_id,
                start_nonce + i,
                vec![Call {
                    to: recipient.into(),
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
                300_000,
            );

            let signature = sign_aa_tx_secp256k1(&tx, signer)?;
            let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
            let tx_hash = *envelope.tx_hash();
            self.setup
                .node
                .rpc
                .inject_tx(envelope.encoded_2718().into())
                .await?;
            self.setup.node.advance_block().await?;
            wait_until_pool_not_contains(
                &self.setup.node.inner.pool,
                &tx_hash,
                "bump_protocol_nonce",
            )
            .await?;
        }

        let final_nonce = self.provider.get_transaction_count(signer_addr).await?;
        assert_eq!(
            final_nonce,
            start_nonce + count,
            "Protocol nonce should have bumped"
        );
        Ok(())
    }

    async fn current_block_timestamp(&mut self) -> eyre::Result<u64> {
        for _ in 0..3 {
            self.setup.node.advance_block().await?;
        }
        let block = self
            .provider
            .get_block_by_number(Default::default())
            .await?
            .ok_or_else(|| eyre::eyre!("latest block missing"))?;
        Ok(block.header.timestamp())
    }

    async fn submit_tx_unchecked(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value> {
        self.setup.node.rpc.inject_tx(encoded.into()).await?;

        // Try multiple blocks — the tx may not be pending in the first block
        // if pool maintenance hasn't processed the previous block yet.
        for _ in 0..3 {
            self.setup.node.advance_block().await?;

            let raw: Option<serde_json::Value> = self
                .provider
                .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
                .await?;
            if let Some(receipt) = raw {
                return Ok(receipt);
            }
        }
        Err(eyre::eyre!(
            "Transaction receipt not found for {tx_hash} after 3 blocks"
        ))
    }

    async fn submit_tx_sync(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value> {
        let sync_provider: alloy::providers::RootProvider =
            alloy::providers::RootProvider::new_http(self.setup.node.rpc_url());
        let encoded_for_sync = encoded;
        let mut sync_handle = tokio::spawn(async move {
            sync_provider
                .raw_request::<_, serde_json::Value>(
                    "eth_sendRawTransactionSync".into(),
                    [encoded_for_sync],
                )
                .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                tokio::select! {
                    res = &mut sync_handle => {
                        let res = res.map_err(|err| eyre::eyre!("Sync task failed: {err}"))?;
                        let _raw_result = res.map_err(|err| eyre::eyre!("Sync request failed: {err}"))?;
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                        self.setup
                            .node
                            .advance_block()
                            .await
                            .map_err(|err| eyre::eyre!("Advance block failed: {err}"))?;
                    }
                }
            }
            // Poll for receipt after sync completes (may not be immediately queryable)
            for _ in 0..10 {
                let raw: Option<serde_json::Value> = self
                    .provider
                    .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
                    .await?;
                if let Some(receipt) = raw {
                    let status = receipt["status"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("Receipt missing status field for {tx_hash}"))?;
                    assert_eq!(status, "0x1", "Receipt status mismatch for {tx_hash}");
                    return Ok(receipt);
                }
                self.setup.node.advance_block().await
                    .map_err(|err| eyre::eyre!("Advance block failed: {err}"))?;
            }
            Err(eyre::eyre!("Transaction receipt not found for {tx_hash} after sync"))
        })
        .await
        .map_err(|_| eyre::eyre!("eth_sendRawTransactionSync timed out"))?
    }
}

/// Helper function to fund an address with tokens
#[allow(clippy::too_many_arguments)]
pub(super) async fn fund_address_with(
    setup: &mut SingleNodeSetup,
    provider: &impl Provider,
    funder_signer: &impl SignerSync,
    funder_addr: Address,
    recipient: Address,
    amount: U256,
    fee_token: Address,
    chain_id: u64,
) -> eyre::Result<()> {
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
            to: fee_token.into(),
            value: U256::ZERO,
            input: transfer_calldata.into(),
        }],
        nonce_key: U256::ZERO,
        nonce: provider.get_transaction_count(funder_addr).await?,
        fee_token: Some(fee_token),
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    // Sign and send the funding transaction
    let signature = funder_signer.sign_hash_sync(&funding_tx.signature_hash())?;
    let funding_envelope: TempoTxEnvelope = funding_tx.into_signed(signature.into()).into();
    let mut encoded_funding = Vec::new();
    funding_envelope.encode_2718(&mut encoded_funding);

    let expected_hash = *funding_envelope.tx_hash();
    let funding_hash = setup.node.rpc.inject_tx(encoded_funding.into()).await?;
    assert_eq!(
        funding_hash, expected_hash,
        "inject_tx hash should match envelope hash"
    );
    let funding_payload = setup.node.advance_block().await?;

    let raw: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [funding_hash])
        .await?;
    let receipt =
        raw.ok_or_else(|| eyre::eyre!("Funding tx receipt not found for {funding_hash}"))?;
    let status = receipt["status"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("Funding receipt missing status field"))?;
    eyre::ensure!(
        status == "0x1",
        "Funding tx reverted (status {status}) for {recipient} — funder may be out of tokens"
    );

    println!(
        "✓ Funded {} with {} tokens in block {}",
        recipient,
        amount,
        funding_payload.block().inner.number
    );

    Ok(())
}

/// Helper function to verify a transaction does NOT exist in the blockchain
pub(super) async fn verify_tx_not_in_block_via_rpc(
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

pub(crate) async fn estimate_gas(
    provider: &impl Provider,
    request: &TempoTransactionRequest,
) -> eyre::Result<u64> {
    let hex: String = provider
        .raw_request("eth_estimateGas".into(), [serde_json::to_value(request)?])
        .await?;
    Ok(u64::from_str_radix(hex.trim_start_matches("0x"), 16)?)
}

/// Helper function to create a signed KeyAuthorization for gas estimation tests
pub(crate) fn create_signed_key_authorization(
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
pub(super) fn compute_authorization_signature_hash(
    auth: &alloy_eips::eip7702::Authorization,
) -> B256 {
    use alloy_rlp::Encodable as _;
    let mut sig_buf = Vec::new();
    sig_buf.push(tempo_primitives::transaction::tt_authorization::MAGIC);
    auth.encode(&mut sig_buf);
    alloy::primitives::keccak256(&sig_buf)
}

/// Helper to build an Authorization struct and compute its signature hash.
/// Callers provide the actual signing logic.
pub(super) fn build_authorization(
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
pub(super) fn verify_delegation_code(
    code: &Bytes,
    expected_delegate: Address,
    authority_name: &str,
) {
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

// ===== Keychain/Access Key Helper Functions =====

/// Helper to generate a P256 access key
pub(crate) fn generate_p256_access_key() -> (
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
pub(crate) fn create_key_authorization(
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
pub(super) async fn submit_and_mine_aa_tx(
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
pub(super) fn sign_p256_primitive(
    sig_hash: B256,
    signing_key: &p256::ecdsa::SigningKey,
    pub_key_x: B256,
    pub_key_y: B256,
) -> eyre::Result<PrimitiveSignature> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
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
pub(crate) fn sign_aa_tx_with_p256_access_key(
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
pub(crate) fn sign_aa_tx_with_secp256k1_access_key(
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
pub(super) fn sign_webauthn_primitive(
    sig_hash: B256,
    signing_key: &p256::ecdsa::SigningKey,
    pub_key_x: B256,
    pub_key_y: B256,
    origin: &str,
) -> eyre::Result<PrimitiveSignature> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
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
pub(crate) fn sign_aa_tx_with_webauthn_access_key(
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

/// Helper to create a TIP20 transfer call for a given token
pub(super) fn create_transfer_call(token: Address, to: Address, amount: U256) -> Call {
    Call {
        to: token.into(),
        value: U256::ZERO,
        input: transferCall { to, amount }.abi_encode().into(),
    }
}

/// Helper to create a TIP20 balanceOf call (useful as a benign call for key authorization txs)
pub(super) fn create_balance_of_call(account: Address) -> Call {
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
pub(crate) fn create_mock_p256_sig(pub_key_x: B256, pub_key_y: B256) -> TempoSignature {
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
pub(crate) fn create_mock_secp256k1_sig() -> TempoSignature {
    TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::new(
        U256::ZERO,
        U256::ZERO,
        false,
    )))
}

/// Helper to create a mock WebAuthn signature for key authorization
pub(crate) fn create_mock_webauthn_sig(pub_key_x: B256, pub_key_y: B256) -> TempoSignature {
    TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::new(),
        r: B256::ZERO,
        s: B256::ZERO,
        pub_key_x,
        pub_key_y,
    }))
}

/// Helper to create default token spending limits derived from the funded amount.
pub(crate) fn create_default_token_limit(
    funded: U256,
) -> Vec<tempo_primitives::transaction::TokenLimit> {
    use tempo_primitives::transaction::TokenLimit;

    vec![TokenLimit {
        token: DEFAULT_FEE_TOKEN,
        limit: funded / U256::from(2),
    }]
}

// ===== Transaction Creation Helper Functions =====

/// Helper to create a basic TempoTransaction with common defaults
pub(crate) fn create_basic_aa_tx(
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
        // Use AlphaUSD to match fund_address_with
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
pub(super) fn create_expiring_nonce_tx(
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
pub(crate) fn sign_aa_tx_secp256k1(
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
pub(crate) fn sign_aa_tx_p256(
    tx: &TempoTransaction,
    signing_key: &p256::ecdsa::SigningKey,
    pub_key_x: B256,
    pub_key_y: B256,
) -> eyre::Result<TempoSignature> {
    let inner = sign_p256_primitive(tx.signature_hash(), signing_key, pub_key_x, pub_key_y)?;
    Ok(TempoSignature::Primitive(inner))
}

/// Helper to create WebAuthn authenticator data and client data JSON
pub(super) fn create_webauthn_data(sig_hash: B256, origin: &str) -> (Vec<u8>, String) {
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
pub(crate) fn sign_aa_tx_webauthn(
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
pub(super) async fn assert_receipt_status(
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

pub(crate) async fn configure_fee_payer_context(
    provider: &impl Provider,
    tx: &mut TempoTransaction,
    fee_payer_enabled: bool,
    signer_addr: Address,
    fee_payer_signer: &PrivateKeySigner,
) -> eyre::Result<Option<FeePayerContext>> {
    if !fee_payer_enabled {
        return Ok(None);
    }

    let fee_payer_addr = fee_payer_signer.address();
    let token = tx.fee_token.unwrap_or(DEFAULT_FEE_TOKEN);
    let balance_before = ITIP20::new(token, provider)
        .balanceOf(fee_payer_addr)
        .call()
        .await?;
    sign_fee_payer(tx, signer_addr, fee_payer_signer)?;

    Ok(Some(FeePayerContext {
        addr: fee_payer_addr,
        token,
        balance_before,
    }))
}

pub(crate) async fn assert_token_balance(
    provider: &impl Provider,
    token: Address,
    who: Address,
    expected: U256,
    msg: &str,
) -> eyre::Result<()> {
    let bal = ITIP20::new(token, provider).balanceOf(who).call().await?;
    assert_eq!(bal, expected, "{msg}");
    Ok(())
}

pub(crate) async fn assert_batch_recipient_balances(
    provider: &impl Provider,
    token: Address,
    recipient_1: Address,
    recipient_2: Address,
    transfer_amount: U256,
) -> eyre::Result<()> {
    assert_token_balance(
        provider,
        token,
        recipient_1,
        transfer_amount,
        "Recipient 1 should receive transfer_amount",
    )
    .await?;
    assert_token_balance(
        provider,
        token,
        recipient_2,
        transfer_amount,
        "Recipient 2 should receive transfer_amount",
    )
    .await?;
    Ok(())
}

pub(crate) fn sign_fee_payer(
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

pub(crate) async fn assert_fee_payer_spent(
    provider: &impl Provider,
    fee_payer: FeePayerContext,
    receipt: &serde_json::Value,
) -> eyre::Result<()> {
    use tempo_primitives::transaction::calc_gas_balance_spending;

    let gas_used = parse_hex_u64(receipt, "gasUsed")?
        .ok_or_else(|| eyre::eyre!("Receipt missing 'gasUsed'"))?;
    let effective_gas_price = parse_hex_u128(receipt, "effectiveGasPrice")?
        .ok_or_else(|| eyre::eyre!("Receipt missing 'effectiveGasPrice'"))?;

    let expected_cost = calc_gas_balance_spending(gas_used, effective_gas_price);

    let balance_after = ITIP20::new(fee_payer.token, provider)
        .balanceOf(fee_payer.addr)
        .call()
        .await?;
    let actual_spent = fee_payer
        .balance_before
        .checked_sub(balance_after)
        .ok_or_else(|| {
            eyre::eyre!(
                "Fee payer balance increased unexpectedly (before={}, after={})",
                fee_payer.balance_before,
                balance_after,
            )
        })?;

    assert_eq!(
        actual_spent, expected_cost,
        "Fee payer balance change should equal ceil(gasUsed * effectiveGasPrice / 10^12) \
         (balance_before={}, balance_after={}, gasUsed={gas_used}, effectiveGasPrice={effective_gas_price})",
        fee_payer.balance_before, balance_after,
    );

    Ok(())
}

/// Resolve transfer amount for send tests, deriving from the funded balance.
pub(crate) fn resolve_send_amounts(test_case: &SendTestCase, funded: U256) -> U256 {
    test_case
        .transfer_amount
        .unwrap_or_else(|| rand_sub_amount(funded))
}

pub(crate) fn create_send_calls(
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
            to: fee_token.into(),
            value: U256::ZERO,
            input: transferCall {
                to: recipient_1,
                amount: transfer_amount,
            }
            .abi_encode()
            .into(),
        }]
    }
}

fn parse_hex_u64(json: &serde_json::Value, field: &str) -> eyre::Result<Option<u64>> {
    json.get(field)
        .and_then(|v| v.as_str())
        .map(|s| {
            let s = s.trim_start_matches("0x");
            let s = if s.is_empty() { "0" } else { s };
            u64::from_str_radix(s, 16).map_err(|e| eyre::eyre!("Failed to parse '{field}': {e}"))
        })
        .transpose()
}

fn parse_hex_u128(json: &serde_json::Value, field: &str) -> eyre::Result<Option<u128>> {
    json.get(field)
        .and_then(|v| v.as_str())
        .map(|s| {
            let s = s.trim_start_matches("0x");
            let s = if s.is_empty() { "0" } else { s };
            u128::from_str_radix(s, 16).map_err(|e| eyre::eyre!("Failed to parse '{field}': {e}"))
        })
        .transpose()
}

fn parse_hex_u256(json: &serde_json::Value, field: &str) -> eyre::Result<Option<U256>> {
    json.get(field)
        .and_then(|v| v.as_str())
        .map(|s| {
            let s = s.trim_start_matches("0x");
            let s = if s.is_empty() { "0" } else { s };
            U256::from_str_radix(s, 16).map_err(|e| eyre::eyre!("Failed to parse '{field}': {e}"))
        })
        .transpose()
}

fn require_hex_u64(json: &serde_json::Value, field: &str) -> eyre::Result<u64> {
    parse_hex_u64(json, field)?.ok_or_else(|| eyre::eyre!("Missing '{field}' in filled tx"))
}

fn require_hex_u128(json: &serde_json::Value, field: &str) -> eyre::Result<u128> {
    parse_hex_u128(json, field)?.ok_or_else(|| eyre::eyre!("Missing '{field}' in filled tx"))
}

pub(crate) fn parse_filled_tx(filled: &serde_json::Value) -> eyre::Result<TempoTransaction> {
    let tx = filled
        .get("tx")
        .ok_or_else(|| eyre::eyre!("Missing 'tx' field in response"))?;

    let chain_id = require_hex_u64(tx, "chainId")?;
    let nonce = parse_hex_u64(tx, "nonce")?.unwrap_or(0);
    let gas_limit = require_hex_u64(tx, "gas")?;
    let max_fee_per_gas = require_hex_u128(tx, "maxFeePerGas")?;
    let max_priority_fee_per_gas = require_hex_u128(tx, "maxPriorityFeePerGas")?;
    let nonce_key = parse_hex_u256(tx, "nonceKey")?.unwrap_or(U256::ZERO);
    let valid_before = parse_hex_u64(tx, "validBefore")?;
    let valid_after = parse_hex_u64(tx, "validAfter")?;

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

pub(crate) fn resolve_timestamp_offset(current_timestamp: u64, offset: i64) -> u64 {
    if offset.is_negative() {
        current_timestamp.saturating_sub(offset.unsigned_abs())
    } else {
        current_timestamp.saturating_add(offset as u64)
    }
}

pub(crate) fn build_fill_request_context(
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
            Some(current_timestamp + TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS + 3600)
        }
        NonceMode::ExpiringInPast => Some(current_timestamp.saturating_sub(1)),
        _ => None,
    });

    let nonce_key_value = match test_case.nonce_mode {
        NonceMode::Protocol => U256::ZERO,
        NonceMode::TwoD(key) => U256::from(key),
        NonceMode::Expiring
        | NonceMode::ExpiringAtBoundary
        | NonceMode::ExpiringExceedsBoundary
        | NonceMode::ExpiringInPast => TEMPO_EXPIRING_NONCE_KEY,
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

pub(crate) async fn fill_transaction_from_case(
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

pub(crate) fn assert_fill_request_expectations(
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
