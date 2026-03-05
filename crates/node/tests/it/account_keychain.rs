//! Integration tests for AccountKeychain precompile.
//!
//! ## Coverage
//!
//! ### TEMPO-KEY21: Spending limit tx_origin enforcement
//!
//! Spending limits are only consumed when `msg_sender == tx_origin`. When a contract
//! calls TIP-20 `transfer()` on behalf of itself (not the signing EOA), the EOA's
//! spending limit must NOT be reduced.
//!
//! This cannot be tested in Foundry invariant tests because `transaction_key` uses
//! transient storage (TSTORE/TLOAD). A real signed transaction must be submitted to a
//! running node so that the EVM sets `tx.origin` correctly.

use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::SignerSync,
    signers::local::MnemonicBuilder,
    sol_types::SolCall,
};
use alloy_primitives::TxKind;
use alloy_eips::Encodable2718;
use reth_ethereum::primitives::transaction::TxHashRef;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    account_keychain::getRemainingLimitCall,
    tip20::ITIP20::transferCall,
};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{
        KeyAuthorization, SignedKeyAuthorization, TokenLimit,
        tempo_transaction::Call,
        tt_signature::{P256SignatureWithPreHash, PrimitiveSignature, TempoSignature},
    },
};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::{Digest, Sha256};

use crate::utils::{SingleNodeSetup, TEST_MNEMONIC, TestNodeBuilder};
use tempo_primitives::transaction::tt_signature::normalize_p256_s;

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

fn sign_p256_primitive(
    sig_hash: alloy::primitives::B256,
    signing_key: &p256::ecdsa::SigningKey,
    pub_key_x: alloy::primitives::B256,
    pub_key_y: alloy::primitives::B256,
) -> eyre::Result<PrimitiveSignature> {
    let pre_hashed = Sha256::digest(sig_hash);
    let p256_sig: p256::ecdsa::Signature = signing_key.sign_prehash(&pre_hashed)?;
    let sig_bytes = p256_sig.to_bytes();
    Ok(PrimitiveSignature::P256(P256SignatureWithPreHash {
        r: alloy::primitives::B256::from_slice(&sig_bytes[0..32]),
        s: normalize_p256_s(&sig_bytes[32..64]),
        pub_key_x,
        pub_key_y,
        pre_hash: true,
    }))
}

fn sign_aa_with_p256_access_key(
    tx: &TempoTransaction,
    access_signing_key: &p256::ecdsa::SigningKey,
    access_pub_x: alloy::primitives::B256,
    access_pub_y: alloy::primitives::B256,
    root_addr: Address,
) -> eyre::Result<TempoSignature> {
    let inner =
        sign_p256_primitive(tx.signature_hash(), access_signing_key, access_pub_x, access_pub_y)?;
    Ok(TempoSignature::Keychain(
        tempo_primitives::transaction::KeychainSignature::new(root_addr, inner),
    ))
}

fn create_key_authorization_p256(
    root_signer: &impl SignerSync,
    access_key_addr: Address,
    pub_key_x: alloy::primitives::B256,
    pub_key_y: alloy::primitives::B256,
    chain_id: u64,
    spending_limits: Vec<TokenLimit>,
) -> eyre::Result<SignedKeyAuthorization> {
    let auth = KeyAuthorization {
        chain_id,
        key_type: tempo_primitives::SignatureType::P256,
        key_id: access_key_addr,
        expiry: None,
        limits: Some(spending_limits),
    };
    let sig_hash = auth.signature_hash();
    let signature = root_signer.sign_hash_sync(&sig_hash)?;
    Ok(auth.into_signed(PrimitiveSignature::Secp256k1(signature)))
}

fn basic_tx(chain_id: u64, nonce: u64, calls: Vec<Call>) -> TempoTransaction {
    TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls,
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        valid_before: Some(u64::MAX),
        ..Default::default()
    }
}

async fn submit_and_mine(
    setup: &mut SingleNodeSetup,
    tx: TempoTransaction,
    sig: TempoSignature,
) -> eyre::Result<alloy::primitives::B256> {
    let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
    let hash = *envelope.tx_hash();
    setup.node.rpc.inject_tx(envelope.encoded_2718().into()).await?;
    setup.node.advance_block().await?;
    Ok(hash)
}

async fn get_remaining_limit(
    provider: &impl Provider,
    account: Address,
    key_id: Address,
    token: Address,
) -> eyre::Result<U256> {
    use alloy::rpc::types::TransactionRequest;
    let call_data = getRemainingLimitCall { account, keyId: key_id, token }.abi_encode();
    let req =
        TransactionRequest::default().to(ACCOUNT_KEYCHAIN_ADDRESS).input(call_data.into());
    let result = provider.call(req).await?;
    Ok(U256::from_be_slice(&result))
}

async fn get_token_balance(provider: &impl Provider, account: Address) -> eyre::Result<U256> {
    use alloy::rpc::types::TransactionRequest;
    use tempo_precompiles::tip20::ITIP20::balanceOfCall;
    let call_data = balanceOfCall { account }.abi_encode();
    let req = TransactionRequest::default().to(DEFAULT_FEE_TOKEN).input(call_data.into());
    let result = provider.call(req).await?;
    Ok(U256::from_be_slice(&result))
}

/// TEMPO-KEY21: Spending limits are only consumed when `msg_sender == tx_origin`.
///
/// Scenario:
///   1. Root key authorizes an access key with a 100-token spending limit.
///   2. A "forwarder" contract is deployed and funded with 50 tokens of its own.
///      When called, it executes `DEFAULT_FEE_TOKEN.transfer(recipient, amount)` using
///      its own balance. For this TIP-20 call: msg_sender = forwarder_addr != tx_origin.
///   3. The access key sends a batched transaction:
///      (a) Calls the forwarder (contract executes its own transfer internally).
///      (b) Directly transfers 10 tokens from the EOA.
///   4. Assertions:
///      - Forwarder balance -> 0  (its own transfer succeeded).
///      - recipient_via_contract balance -> 50.
///      - recipient_direct balance -> 10.
///      - EOA spending limit -> 90 (decreased by 10 only, NOT by 60).
#[tokio::test]
async fn test_key21_spending_limit_not_consumed_by_contract_call() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== TEMPO-KEY21: Spending limit tx_origin enforcement ===\n");

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let (access_signing_key, access_pub_x, access_pub_y, access_key_addr) =
        generate_p256_access_key();

    println!("Root address:       {root_addr}");
    println!("Access key address: {access_key_addr}");

    let mut nonce = provider.get_transaction_count(root_addr).await?;
    let one_token = U256::from(10u64).pow(U256::from(18u64));

    // Step 1: Authorize access key with 100-token spending limit.
    println!("\n[1] Authorizing access key with 100-token spending limit...");

    let spending_limit = U256::from(100u64) * one_token;

    let key_auth = create_key_authorization_p256(
        &root_signer,
        access_key_addr,
        access_pub_x,
        access_pub_y,
        chain_id,
        vec![TokenLimit { token: DEFAULT_FEE_TOKEN, limit: spending_limit }],
    )?;

    let mut auth_tx = basic_tx(
        chain_id,
        nonce,
        vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: tempo_precompiles::tip20::ITIP20::balanceOfCall { account: root_addr }
                .abi_encode()
                .into(),
        }],
    );
    auth_tx.key_authorization = Some(key_auth);

    let auth_sig = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        root_signer.sign_hash_sync(&auth_tx.signature_hash())?,
    ));
    submit_and_mine(&mut setup, auth_tx, auth_sig).await?;
    nonce += 1;

    let limit_initial =
        get_remaining_limit(&provider, root_addr, access_key_addr, DEFAULT_FEE_TOKEN).await?;
    assert_eq!(limit_initial, spending_limit, "Initial spending limit must be 100 tokens");
    println!("✓ Spending limit confirmed: {limit_initial}");

    // Step 2: Deploy forwarder contract.
    //
    // Runtime bytecode reads (recipient, amount) from calldata[0:64] and calls
    // DEFAULT_FEE_TOKEN.transfer(recipient, amount) spending the CONTRACT's own tokens.
    // When this executes: msg_sender = forwarder_addr != tx_origin (root_addr).
    println!("\n[2] Deploying forwarder contract...");

    let token_bytes: [u8; 20] = DEFAULT_FEE_TOKEN.into();

    let mut runtime: Vec<u8> = Vec::new();
    // Store selector transfer(address,uint256) = 0xa9059cbb at mem[0..32]
    runtime.extend_from_slice(&[0x63, 0xa9, 0x05, 0x9c, 0xbb]); // PUSH4
    runtime.extend_from_slice(&[0x60, 0xe0]);                    // PUSH1 0xe0
    runtime.push(0x1b);                                           // SHL
    runtime.extend_from_slice(&[0x60, 0x00]);                    // PUSH1 0x00
    runtime.push(0x52);                                           // MSTORE
    // recipient = calldata[0:32] -> mem[4:36]
    runtime.extend_from_slice(&[0x60, 0x00]); runtime.push(0x35);
    runtime.extend_from_slice(&[0x60, 0x04]); runtime.push(0x52);
    // amount = calldata[32:64] -> mem[36:68]
    runtime.extend_from_slice(&[0x60, 0x20]); runtime.push(0x35);
    runtime.extend_from_slice(&[0x60, 0x24]); runtime.push(0x52);
    // CALL(gas, token, 0, argsOffset=0, argsSize=68, retOffset=128, retSize=32)
    runtime.extend_from_slice(&[0x60, 0x20]); // retSize
    runtime.extend_from_slice(&[0x60, 0x80]); // retOffset
    runtime.extend_from_slice(&[0x60, 0x44]); // argsSize=68
    runtime.extend_from_slice(&[0x60, 0x00]); // argsOffset
    runtime.extend_from_slice(&[0x60, 0x00]); // value
    runtime.push(0x73); runtime.extend_from_slice(&token_bytes); // PUSH20 <token>
    runtime.push(0x5a); // GAS
    runtime.push(0xf1); // CALL
    runtime.push(0x50); // POP
    runtime.push(0x00); // STOP

    let runtime_len = runtime.len() as u8;

    // 11-byte initcode header: copies runtime to mem then returns it
    let mut initcode: Vec<u8> = Vec::new();
    initcode.extend_from_slice(&[0x60, runtime_len]);
    initcode.push(0x80);
    initcode.extend_from_slice(&[0x60, 0x0b]);
    initcode.extend_from_slice(&[0x60, 0x00]);
    initcode.push(0x39);
    initcode.extend_from_slice(&[0x60, 0x00]);
    initcode.push(0xf3);
    initcode.extend_from_slice(&runtime);

    let forwarder_addr = root_addr.create(nonce);

    let deploy_tx = basic_tx(
        chain_id,
        nonce,
        vec![Call { to: TxKind::Create, value: U256::ZERO, input: Bytes::from(initcode) }],
    );
    let deploy_sig = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        root_signer.sign_hash_sync(&deploy_tx.signature_hash())?,
    ));
    let deploy_hash = submit_and_mine(&mut setup, deploy_tx, deploy_sig).await?;
    nonce += 1;

    let deployed_code = provider.get_code_at(forwarder_addr).await?;
    assert!(
        !deployed_code.is_empty(),
        "Forwarder must be deployed at {forwarder_addr} (tx: {deploy_hash})"
    );
    println!("✓ Forwarder deployed at {forwarder_addr} ({} runtime bytes)", deployed_code.len());

    // Step 3: Fund forwarder with 50 tokens.
    println!("\n[3] Funding forwarder with 50 tokens...");

    let forwarder_amount = U256::from(50u64) * one_token;

    let fund_tx = basic_tx(
        chain_id,
        nonce,
        vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: transferCall { to: forwarder_addr, amount: forwarder_amount }
                .abi_encode()
                .into(),
        }],
    );
    let fund_sig = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        root_signer.sign_hash_sync(&fund_tx.signature_hash())?,
    ));
    submit_and_mine(&mut setup, fund_tx, fund_sig).await?;
    nonce += 1;

    let forwarder_bal = get_token_balance(&provider, forwarder_addr).await?;
    assert_eq!(forwarder_bal, forwarder_amount, "Forwarder must hold 50 tokens");
    println!("✓ Forwarder balance: {forwarder_bal}");

    // Step 4: Access key sends batched transaction.
    println!("\n[4] Sending batched transaction via access key...");

    let recipient_via_contract = Address::random();
    let recipient_direct = Address::random();
    let direct_amount = U256::from(10u64) * one_token;

    // Calldata for forwarder: abi.encode(recipient_via_contract, forwarder_amount)
    let mut forwarder_calldata = [0u8; 64];
    forwarder_calldata[12..32].copy_from_slice(recipient_via_contract.as_slice());
    let amount_bytes: [u8; 32] = forwarder_amount.to_be_bytes();
    forwarder_calldata[32..64].copy_from_slice(&amount_bytes);

    let batched_tx = basic_tx(
        chain_id,
        nonce,
        vec![
            // (a) Contract-mediated transfer -- must NOT consume EOA spending limit
            Call {
                to: forwarder_addr.into(),
                value: U256::ZERO,
                input: Bytes::from(forwarder_calldata.to_vec()),
            },
            // (b) Direct EOA transfer -- MUST consume 10 tokens of spending limit
            Call {
                to: DEFAULT_FEE_TOKEN.into(),
                value: U256::ZERO,
                input: transferCall { to: recipient_direct, amount: direct_amount }
                    .abi_encode()
                    .into(),
            },
        ],
    );

    let access_sig = sign_aa_with_p256_access_key(
        &batched_tx,
        &access_signing_key,
        access_pub_x,
        access_pub_y,
        root_addr,
    )?;
    let batched_hash = submit_and_mine(&mut setup, batched_tx, access_sig).await?;

    let raw_receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [batched_hash])
        .await?;
    let receipt = raw_receipt.expect("Batched transaction must be mined");
    let status = receipt["status"].as_str().map(|s| s == "0x1").unwrap_or(false);
    assert!(status, "Batched transaction must succeed (status 0x1)");
    println!("✓ Batched transaction mined: {batched_hash}");

    // Step 5: Verify outcomes.
    println!("\n[5] Verifying outcomes...");

    let forwarder_bal_after = get_token_balance(&provider, forwarder_addr).await?;
    assert_eq!(forwarder_bal_after, U256::ZERO, "Forwarder should have 0 tokens after transfer");
    println!("✓ Forwarder balance after: {forwarder_bal_after}");

    let bal_via_contract = get_token_balance(&provider, recipient_via_contract).await?;
    assert_eq!(
        bal_via_contract, forwarder_amount,
        "recipient_via_contract should have received 50 tokens from forwarder"
    );
    println!("✓ recipient_via_contract balance: {bal_via_contract}");

    let bal_direct = get_token_balance(&provider, recipient_direct).await?;
    assert_eq!(bal_direct, direct_amount, "recipient_direct should have received 10 tokens");
    println!("✓ recipient_direct balance: {bal_direct}");

    // KEY21 core assertion: limit decreased by 10 only, not 60.
    let limit_after =
        get_remaining_limit(&provider, root_addr, access_key_addr, DEFAULT_FEE_TOKEN).await?;
    let expected_limit = spending_limit - direct_amount; // 100 - 10 = 90

    assert_eq!(
        limit_after,
        expected_limit,
        "TEMPO-KEY21 VIOLATION: spending limit should be {} (100 - 10 = 90 tokens) \
         but got {}. The forwarder's internal transfer must NOT consume the EOA's \
         spending limit because msg_sender (forwarder) != tx_origin (root_addr).",
        expected_limit,
        limit_after,
    );
    println!(
        "OK TEMPO-KEY21: limit={limit_after} \
         (started={spending_limit}, direct_transfer=-{direct_amount}, contract_transfer=-0)"
    );
    println!("\n=== TEMPO-KEY21 PASSED ===");

    Ok(())
}
