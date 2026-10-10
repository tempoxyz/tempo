//! End-to-end tests for the redacted zone RPC server.
//!
//! These tests launch a zone node with a redacted RPC server and verify:
//! - Authentication enforcement (missing/invalid tokens, wrong chain ID)
//! - Public method access
//! - Balance & state privacy (users only see their own data)
//! - Block redaction (activity-derived header fields zeroed, transactions cleared)
//! - Method tier enforcement (restricted/disabled/unknown methods)

use crate::utils::{
    DEFAULT_TIMEOUT, TIP20_TX_GAS, l1_dev_signer, now_secs, start_zone_with_redacted_rpc,
    start_zone_with_redacted_rpc_l1, start_zone_with_redacted_rpc_l1_with_encryption,
};
use alloy::{
    primitives::{Address, B256, TxKind, U256, address, hex},
    signers::local::PrivateKeySigner,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_provider::{ProviderBuilder, bindings::IMulticall3};
use alloy_signer::SignerSync;
use alloy_sol_types::{SolCall, SolError};
use futures::{SinkExt, StreamExt};
use p256::ecdsa::SigningKey as P256SigningKey;
use rand::thread_rng;
use serde_json::{Value, json};
use std::{collections::HashSet, time::Duration};
use tempo_chainspec::spec::{TEMPO_T0_BASE_FEE, TEMPO_T1_BASE_FEE};
use tempo_contracts::precompiles::{
    IAccountKeychain, INonce, IStorageCredits, ITIP20 as ContractTip20, ITIP403Registry,
    TIP403_REGISTRY_ADDRESS,
    account_keychain::IAccountKeychain::SignatureType as KeyInfoSignatureType,
};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS, STORAGE_CREDITS_ADDRESS,
    tip20::ITIP20 as PrecompileTip20, tip403_registry::ALLOW_ALL_POLICY_ID,
};
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{Call, TempoTransaction},
};
use tempo_zone_contracts::{
    IZoneInbox, TEMPO_STATE_ADDRESS, TempoState, Unauthorized, ZONE_INBOX_ADDRESS,
    ZONE_TOKEN_ADDRESS,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};

fn corrupt_token_hex(token: &str) -> String {
    let mut bytes = hex::decode(token).expect("token hex should decode");
    let idx = usize::from(bytes.len() > 1);
    bytes[idx] ^= 0x01;
    hex::encode(bytes)
}

fn address_topic(address: Address) -> String {
    address.into_word().to_string()
}

fn signed_sponsored_raw_transaction(
    signer: &PrivateKeySigner,
    fee_payer: &PrivateKeySigner,
    chain_id: u64,
) -> eyre::Result<String> {
    let mut transaction = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: u128::from(TEMPO_T0_BASE_FEE),
        max_fee_per_gas: u128::from(TEMPO_T0_BASE_FEE),
        gas_limit: 500_000,
        calls: vec![Call {
            to: TxKind::Call(signer.address()),
            value: U256::ZERO,
            input: Default::default(),
        }],
        fee_token: Some(PATH_USD_ADDRESS),
        ..Default::default()
    };

    let fee_payer_hash = transaction.fee_payer_signature_hash(signer.address());
    transaction.fee_payer_signature = Some(fee_payer.sign_hash_sync(&fee_payer_hash)?);

    let signature = signer.sign_hash_sync(&transaction.signature_hash())?;
    let envelope: TempoTxEnvelope = transaction.into_signed(signature.into()).into();

    Ok(hex::encode_prefixed(envelope.encoded_2718()))
}

fn assert_filter_not_found_error(response: &serde_json::Value) {
    let error = response
        .get("error")
        .unwrap_or_else(|| panic!("expected filter-not-found error, got {response}"));
    assert_eq!(
        error["code"].as_i64().unwrap(),
        -32602,
        "filter-not-found should surface as invalid params",
    );
    assert_eq!(
        error["message"].as_str().unwrap(),
        "filter not found",
        "filter-not-found message should be stable",
    );
}

fn assert_redacted_block(block: &Value) {
    assert!(!block.is_null(), "block should not be null");
    assert!(
        block["transactions"]
            .as_array()
            .is_some_and(|transactions| transactions.is_empty()),
        "block transactions should be empty (redacted)"
    );

    let zero_root = B256::ZERO.to_string();
    assert_eq!(block["transactionsRoot"], zero_root);
    assert_eq!(block["receiptsRoot"], zero_root);
    assert_eq!(block["stateRoot"], zero_root);
    assert_eq!(block["extraData"], "0x");

    if let Some(withdrawals_root) = block.get("withdrawalsRoot") {
        assert!(
            withdrawals_root.is_null() || withdrawals_root == zero_root.as_str(),
            "block withdrawalsRoot should be null or zero"
        );
    }
    if let Some(bloom) = block.get("logsBloom").and_then(Value::as_str) {
        let bloom_trimmed = bloom.strip_prefix("0x").unwrap_or(bloom);
        assert!(
            bloom_trimmed.chars().all(|c| c == '0'),
            "block logsBloom should be all zeros"
        );
    }
    assert_eq!(block["gasUsed"], "0x0");
    if let Some(size) = block.get("size") {
        assert_eq!(size.as_str(), Some("0x0"));
    }
    if let Some(blob_gas_used) = block.get("blobGasUsed") {
        assert_eq!(blob_gas_used.as_str(), Some("0x0"));
    }
    if let Some(excess_blob_gas) = block.get("excessBlobGas") {
        assert_eq!(excess_blob_gas.as_str(), Some("0x0"));
    }
    if let Some(withdrawals) = block.get("withdrawals") {
        assert!(
            withdrawals
                .as_array()
                .is_some_and(|withdrawals| withdrawals.is_empty()),
            "block withdrawals should be empty when present"
        );
    }
}

type RedactedRpcWs =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn redacted_rpc_ws_url(http_url: &url::Url) -> eyre::Result<url::Url> {
    let mut ws_url = http_url.clone();
    let target_scheme = if ws_url.scheme() == "https" {
        "wss"
    } else {
        "ws"
    };
    ws_url
        .set_scheme(target_scheme)
        .map_err(|_| eyre::eyre!("failed to derive websocket URL"))?;
    Ok(ws_url)
}

fn jsonrpc_with_params(method: &str, params: Value, id: u64) -> String {
    json!({"jsonrpc":"2.0","method":method,"params":params,"id":id}).to_string()
}

async fn connect_redacted_rpc_ws(url: &url::Url, auth_token: &str) -> eyre::Result<RedactedRpcWs> {
    let ws_url = redacted_rpc_ws_url(url)?;
    let mut req = ws_url.as_str().into_client_request()?;
    req.headers_mut().insert(
        "x-authorization-token",
        auth_token
            .parse()
            .expect("auth token header should be valid"),
    );
    let (ws, _) = connect_async(req).await?;
    Ok(ws)
}

async fn ws_next_json(ws: &mut RedactedRpcWs) -> eyre::Result<Value> {
    let Some(msg) = tokio::time::timeout(DEFAULT_TIMEOUT, ws.next())
        .await
        .map_err(|_| eyre::eyre!("timed out waiting for websocket message"))?
    else {
        eyre::bail!("websocket closed unexpectedly");
    };

    match msg? {
        Message::Text(text) => Ok(serde_json::from_str(&text)?),
        other => {
            eyre::bail!("expected text websocket message, got {other:?}");
        }
    }
}

async fn ws_subscribe(ws: &mut RedactedRpcWs, params: Value) -> eyre::Result<String> {
    ws.send(Message::Text(
        jsonrpc_with_params("eth_subscribe", params, 1).into(),
    ))
    .await?;
    let response = ws_next_json(ws).await?;
    Ok(response["result"]
        .as_str()
        .expect("subscription response should include an id")
        .to_owned())
}

async fn ws_collect_messages_until_quiet(
    ws: &mut RedactedRpcWs,
    duration: Duration,
) -> eyre::Result<Vec<Value>> {
    let mut messages = Vec::new();

    loop {
        match tokio::time::timeout(duration, ws.next()).await {
            Err(_) => return Ok(messages),
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => return Ok(messages),
            Ok(Some(Ok(Message::Text(text)))) => messages.push(serde_json::from_str(&text)?),
            Ok(Some(Ok(other))) => {
                eyre::bail!("unexpected websocket frame: {other:?}");
            }
            Ok(Some(Err(err))) => return Err(err.into()),
        }
    }
}

/// Auth enforcement: missing header → 401, garbage token → 401/403, wrong chain ID → 403.
#[tokio::test(flavor = "multi_thread")]
async fn test_auth_rejection() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc().await?;

    // No auth header → 401
    let (status, _) = ctx
        .call_no_auth("eth_blockNumber", serde_json::json!([]))
        .await?;
    assert_eq!(status.as_u16(), 401, "missing auth should return 401");

    // Garbage token → 401 or 403
    let (status, _) = ctx
        .call_raw("eth_blockNumber", serde_json::json!([]), "deadbeef")
        .await?;
    assert!(
        status.as_u16() == 401 || status.as_u16() == 403,
        "invalid auth should return 401 or 403, got {status}"
    );

    // Valid signature but wrong chain ID → 403
    let bad_token = ctx.build_bad_token(&ctx.sequencer_signer, 1, ctx.config.chain_id + 1);
    let (status, _) = ctx
        .call_raw("eth_blockNumber", serde_json::json!([]), &bad_token)
        .await?;
    assert_eq!(status.as_u16(), 403, "wrong chain ID should return 403");

    Ok(())
}

/// Pool admission requires the transaction sender to hold an enabled zone token.
#[tokio::test(flavor = "multi_thread")]
async fn test_send_raw_transaction_requires_enabled_token_balance() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut ctx = start_zone_with_redacted_rpc().await?;
    let user_signer = PrivateKeySigner::random();
    let fee_payer = PrivateKeySigner::random();
    ctx.inject_deposit(
        PATH_USD_ADDRESS,
        fee_payer.address(),
        fee_payer.address(),
        1_000_000,
    )
    .await?;
    let raw = signed_sponsored_raw_transaction(&user_signer, &fee_payer, ctx.config.chain_id)?;

    for method in ["eth_sendRawTransaction", "eth_sendRawTransactionSync"] {
        let response = ctx.call_as_user(method, json!([raw]), &user_signer).await?;
        assert_eq!(
            response["error"]["code"].as_i64(),
            Some(-32603),
            "{method} should reject a sender without enabled-token balance: {response}",
        );
        assert_eq!(
            response["error"]["message"].as_str(),
            Some("sender must hold a nonzero balance of an enabled zone token"),
            "{method} should explain why the transaction was rejected: {response}",
        );
    }

    ctx.inject_deposit(
        PATH_USD_ADDRESS,
        user_signer.address(),
        user_signer.address(),
        1_000_000,
    )
    .await?;

    let response = ctx
        .call_as_user("eth_sendRawTransaction", json!([raw]), &user_signer)
        .await?;
    assert!(
        response["result"].as_str().is_some(),
        "funded sender transaction should be accepted: {response}",
    );

    Ok(())
}

/// Real P256 and WebAuthn auth tokens are accepted by the redacted RPC.
#[tokio::test(flavor = "multi_thread")]
async fn test_non_secp_auth_tokens() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc().await?;
    let p256_signer = P256SigningKey::random(&mut thread_rng());
    let webauthn_signer = P256SigningKey::random(&mut thread_rng());

    for token in [
        ctx.p256_token(&p256_signer),
        ctx.webauthn_token(&webauthn_signer),
    ] {
        let resp = ctx
            .call("eth_blockNumber", serde_json::json!([]), &token)
            .await?;
        assert!(
            resp.get("error").is_none(),
            "auth token should succeed: {resp}"
        );
        assert!(
            resp["result"].as_str().is_some(),
            "expected block number result"
        );
    }

    Ok(())
}

/// Invalid P256 signatures and WebAuthn challenge mismatches are rejected.
#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_non_secp_auth_tokens_are_rejected() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc().await?;
    let p256_signer = P256SigningKey::random(&mut thread_rng());
    let webauthn_signer = P256SigningKey::random(&mut thread_rng());

    let bad_p256 = corrupt_token_hex(&ctx.p256_token(&p256_signer));
    let (status, _) = ctx
        .call_raw("eth_blockNumber", serde_json::json!([]), &bad_p256)
        .await?;
    assert_eq!(status.as_u16(), 403, "invalid P256 token should return 403");

    let bad_webauthn = ctx.webauthn_token_with_challenge(&webauthn_signer, B256::repeat_byte(0x77));
    let (status, _) = ctx
        .call_raw("eth_blockNumber", serde_json::json!([]), &bad_webauthn)
        .await?;
    assert_eq!(
        status.as_u16(),
        403,
        "WebAuthn token with wrong challenge should return 403",
    );

    Ok(())
}

/// Authorized P256 keychain tokens authenticate as the root account in both V1 and V2 encodings.
#[tokio::test(flavor = "multi_thread")]
async fn test_keychain_auth_tokens_v1_and_v2() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut ctx = start_zone_with_redacted_rpc().await?;
    let root_signer = PrivateKeySigner::random();
    let access_signer = P256SigningKey::random(&mut thread_rng());

    ctx.inject_deposit(
        PATH_USD_ADDRESS,
        address!("0x0000000000000000000000000000000000001111"),
        root_signer.address(),
        1_000_000,
    )
    .await?;

    let (_, key_id) = ctx.keychain_p256_token(root_signer.address(), &access_signer, 0x04);
    ctx.authorize_keychain_key(
        &root_signer,
        key_id,
        KeyInfoSignatureType::P256,
        now_secs() + 300,
    )
    .await?;

    for version in [0x03, 0x04] {
        let (token, _) = ctx.keychain_p256_token(root_signer.address(), &access_signer, version);
        let resp = ctx
            .call(
                "eth_call",
                serde_json::json!([
                    {
                        "from": format!("{:#x}", root_signer.address()),
                        "to": format!("{:#x}", root_signer.address()),
                        "input": "0x"
                    },
                    "latest"
                ]),
                &token,
            )
            .await?;
        assert_eq!(
            resp["result"].as_str().unwrap(),
            "0x",
            "keychain auth should allow calls from the root account",
        );
    }

    Ok(())
}

/// Keychain auth rejects missing, revoked, and signature-type-mismatched keys.
#[tokio::test(flavor = "multi_thread")]
async fn test_keychain_auth_rejection_cases() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut ctx = start_zone_with_redacted_rpc().await?;

    let missing_root = PrivateKeySigner::random();
    let missing_access = P256SigningKey::random(&mut thread_rng());
    let (missing_token, _) = ctx.keychain_p256_token(missing_root.address(), &missing_access, 0x04);
    let (status, _) = ctx
        .call_raw("eth_blockNumber", serde_json::json!([]), &missing_token)
        .await?;
    assert_eq!(
        status.as_u16(),
        403,
        "missing keychain auth should return 403"
    );

    let revoked_root = PrivateKeySigner::random();
    let revoked_access = P256SigningKey::random(&mut thread_rng());
    ctx.inject_deposit(
        PATH_USD_ADDRESS,
        address!("0x0000000000000000000000000000000000002222"),
        revoked_root.address(),
        1_000_000,
    )
    .await?;
    let (revoked_token, revoked_key_id) =
        ctx.keychain_p256_token(revoked_root.address(), &revoked_access, 0x04);
    ctx.authorize_keychain_key(
        &revoked_root,
        revoked_key_id,
        KeyInfoSignatureType::P256,
        now_secs() + 300,
    )
    .await?;
    ctx.revoke_keychain_key(&revoked_root, revoked_key_id)
        .await?;
    let (status, _) = ctx
        .call_raw("eth_blockNumber", serde_json::json!([]), &revoked_token)
        .await?;
    assert_eq!(status.as_u16(), 403, "revoked key should return 403");

    let mismatch_root = PrivateKeySigner::random();
    let mismatch_access = P256SigningKey::random(&mut thread_rng());
    ctx.inject_deposit(
        PATH_USD_ADDRESS,
        address!("0x0000000000000000000000000000000000004444"),
        mismatch_root.address(),
        1_000_000,
    )
    .await?;
    let (mismatch_token, mismatch_key_id) =
        ctx.keychain_p256_token(mismatch_root.address(), &mismatch_access, 0x04);
    ctx.authorize_keychain_key(
        &mismatch_root,
        mismatch_key_id,
        KeyInfoSignatureType::Secp256k1,
        now_secs() + 300,
    )
    .await?;
    let (status, _) = ctx
        .call_raw("eth_blockNumber", serde_json::json!([]), &mismatch_token)
        .await?;
    assert_eq!(
        status.as_u16(),
        403,
        "signature-type mismatch should return 403",
    );

    Ok(())
}

/// Public methods work for both sequencer and users without leaking private fee activity.
#[tokio::test(flavor = "multi_thread")]
async fn test_public_methods() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc().await?;
    let user_signer = PrivateKeySigner::random();

    for method in ["eth_blockNumber", "eth_chainId"] {
        let seq_resp = ctx.call_as_sequencer(method, serde_json::json!([])).await?;
        assert!(
            seq_resp.get("result").is_some() && seq_resp.get("error").is_none(),
            "sequencer should succeed for {method}"
        );

        let user_resp = ctx
            .call_as_user(method, serde_json::json!([]), &user_signer)
            .await?;
        assert!(
            user_resp.get("result").is_some() && user_resp.get("error").is_none(),
            "user should succeed for {method}"
        );
    }

    for (method, expected) in [
        ("eth_gasPrice", U256::from(TEMPO_T1_BASE_FEE)),
        ("eth_maxPriorityFeePerGas", U256::ZERO),
    ] {
        for response in [
            ctx.call_as_sequencer(method, json!([])).await?,
            ctx.call_as_user(method, json!([]), &user_signer).await?,
        ] {
            assert_eq!(response["result"], json!(format!("{expected:#x}")));
        }
    }

    Ok(())
}

/// Filter ownership is scoped to the creating account, and uninstall removes follow-up access.
#[tokio::test(flavor = "multi_thread")]
async fn test_filter_ownership_and_uninstall_cleanup() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut ctx = start_zone_with_redacted_rpc().await?;
    let owner_signer = PrivateKeySigner::random();
    let other_signer = PrivateKeySigner::random();

    let create_resp = ctx
        .call_as_user("eth_newBlockFilter", serde_json::json!([]), &owner_signer)
        .await?;
    assert!(
        create_resp.get("error").is_none(),
        "owner should be able to create a block filter: {create_resp}"
    );
    let filter_id = create_resp["result"].clone();

    ctx.inject_empty_block().await?;

    let owner_changes = ctx
        .call_as_user(
            "eth_getFilterChanges",
            serde_json::json!([filter_id.clone()]),
            &owner_signer,
        )
        .await?;
    assert!(
        owner_changes.get("error").is_none(),
        "owner should be able to read filter changes: {owner_changes}"
    );
    assert!(
        owner_changes["result"]
            .as_array()
            .is_some_and(|changes| !changes.is_empty()),
        "owner should observe at least one new block hash"
    );

    let other_changes = ctx
        .call_as_user(
            "eth_getFilterChanges",
            serde_json::json!([filter_id.clone()]),
            &other_signer,
        )
        .await?;
    assert_filter_not_found_error(&other_changes);

    let uninstall_resp = ctx
        .call_as_user(
            "eth_uninstallFilter",
            serde_json::json!([filter_id.clone()]),
            &owner_signer,
        )
        .await?;
    assert!(
        uninstall_resp["result"].as_bool().unwrap(),
        "owner uninstall should succeed",
    );

    let after_uninstall = ctx
        .call_as_user(
            "eth_getFilterChanges",
            serde_json::json!([filter_id]),
            &owner_signer,
        )
        .await?;
    assert_filter_not_found_error(&after_uninstall);

    Ok(())
}

/// Balance & state privacy: users see `0x0` for other addresses (balance and nonce),
/// can see their own, and sequencer has full access.
#[tokio::test(flavor = "multi_thread")]
async fn test_balance_privacy() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut ctx = start_zone_with_redacted_rpc().await?;

    let depositor = address!("0x0000000000000000000000000000000000001111");
    let recipient = address!("0x0000000000000000000000000000000000005678");
    let deposit_amount: u128 = 1_000_000;

    ctx.inject_deposit(PATH_USD_ADDRESS, depositor, recipient, deposit_amount)
        .await?;

    let user_signer = PrivateKeySigner::random();

    // User querying another address's balance → 0x0
    let resp = ctx.get_balance_as_user(recipient, &user_signer).await?;
    assert_eq!(
        resp["result"].as_str().unwrap(),
        "0x0",
        "non-owner should see 0x0 balance for other addresses"
    );

    // User querying another address's tx count → 0x0
    let resp = ctx.get_tx_count_as_user(recipient, &user_signer).await?;
    assert_eq!(
        resp["result"].as_str().unwrap(),
        "0x0",
        "non-owner should see 0x0 for other address's tx count"
    );

    // User querying own balance → works (no error)
    let resp = ctx
        .get_balance_as_user(user_signer.address(), &user_signer)
        .await?;
    assert!(
        resp.get("result").is_some() && resp.get("error").is_none(),
        "user should be able to query own balance"
    );

    // Sequencer querying any address → full access
    let resp = ctx.get_balance_as_sequencer(recipient).await?;
    assert!(
        resp.get("result").is_some() && resp.get("error").is_none(),
        "sequencer should be able to query any address's balance"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip403_zero_caller_is_operator_only() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc().await?;
    let user = PrivateKeySigner::random();
    let call = ITIP403Registry::isAuthorizedCall {
        policyId: ALLOW_ALL_POLICY_ID,
        user: user.address(),
    };
    let data = hex::encode_prefixed(call.abi_encode());
    let operator_provider = ctx.zone.provider();
    let operator_registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, &operator_provider);

    // The trusted operator RPC admits the zero caller and executes the TIP-403 read.
    let zero_caller = operator_registry
        .isAuthorized(ALLOW_ALL_POLICY_ID, user.address())
        .from(Address::ZERO)
        .call()
        .await?;
    assert!(zero_caller);

    // The operator RPC still rejects ordinary callers at the precompile boundary.
    let nonzero_caller = operator_registry
        .isAuthorized(ALLOW_ALL_POLICY_ID, user.address())
        .from(user.address())
        .call()
        .await;
    assert!(nonzero_caller.is_err());

    // The redacted RPC rejects an explicit zero caller because it does not match the authenticated
    // user.
    let response = ctx
        .call_as_user(
            "eth_call",
            json!([{
                "from": Address::ZERO,
                "to": TIP403_REGISTRY_ADDRESS,
                "data": &data,
            }, "latest"]),
            &user,
        )
        .await?;
    assert_eq!(response["error"]["code"], -32004);

    // The redacted RPC fills an omitted `from` with the authenticated nonzero user, which TIP-403
    // rejects at the precompile boundary.
    let response = ctx
        .call_as_user(
            "eth_call",
            json!([{
                "to": TIP403_REGISTRY_ADDRESS,
                "data": &data,
            }, "latest"]),
            &user,
        )
        .await?;
    assert_eq!(response["error"]["code"], -32603);
    assert_eq!(response["error"]["message"], "execution reverted");
    Ok(())
}

/// `eth_call` against the zone TIP-20 enforces read privacy for `balanceOf` and `allowance`
/// without a sequencer bypass.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_eth_call_privacy() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut ctx = start_zone_with_redacted_rpc().await?;

    let owner_signer = l1_dev_signer();
    let owner = owner_signer.address();
    let spender_signer = PrivateKeySigner::random();
    let spender = spender_signer.address();
    let outsider_signer = PrivateKeySigner::random();

    let deposit_amount: u128 = 1_000_000;
    let allowance_amount: u128 = 333_333;

    ctx.inject_deposit(PATH_USD_ADDRESS, owner, owner, deposit_amount)
        .await?;

    let owner_provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(ctx.zone.http_url().clone());
    let approve_pending = ContractTip20::new(PATH_USD_ADDRESS, &owner_provider)
        .approve(spender, U256::from(allowance_amount))
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .gas(TIP20_TX_GAS)
        .send()
        .await?;
    ctx.fixture.inject_empty_block(ctx.zone.deposit_queue());
    let approve_receipt = approve_pending.get_receipt().await?;
    assert!(approve_receipt.status(), "approve should succeed");
    let balance_call = PrecompileTip20::balanceOfCall { account: owner };
    let balance_data = hex::encode_prefixed(balance_call.abi_encode());
    let allowance_call = PrecompileTip20::allowanceCall { owner, spender };
    let allowance_data = hex::encode_prefixed(allowance_call.abi_encode());

    let outsider_balance = ctx
        .call_as_user(
            "eth_call",
            serde_json::json!([
                {
                    "to": format!("{PATH_USD_ADDRESS:#x}"),
                    "data": balance_data,
                },
                "latest"
            ]),
            &outsider_signer,
        )
        .await?;
    assert!(
        outsider_balance.get("error").is_some(),
        "non-owner balanceOf(other) should revert"
    );

    let outsider_allowance = ctx
        .call_as_user(
            "eth_call",
            serde_json::json!([
                {
                    "to": format!("{PATH_USD_ADDRESS:#x}"),
                    "data": allowance_data,
                },
                "latest"
            ]),
            &outsider_signer,
        )
        .await?;
    assert!(
        outsider_allowance.get("error").is_some(),
        "unrelated caller allowance(owner, spender) should revert"
    );

    let sequencer_balance = ctx
        .call_as_sequencer(
            "eth_call",
            serde_json::json!([
                {
                    "from": format!("{:#x}", ctx.sequencer_signer.address()),
                    "to": format!("{PATH_USD_ADDRESS:#x}"),
                    "data": hex::encode_prefixed(balance_call.abi_encode()),
                },
                "latest"
            ]),
        )
        .await?;
    assert!(
        sequencer_balance.get("error").is_some(),
        "sequencer balanceOf(other) should revert"
    );

    let sequencer_allowance = ctx
        .call_as_sequencer(
            "eth_call",
            serde_json::json!([
                {
                    "from": format!("{:#x}", ctx.sequencer_signer.address()),
                    "to": format!("{PATH_USD_ADDRESS:#x}"),
                    "data": hex::encode_prefixed(allowance_call.abi_encode()),
                },
                "latest"
            ]),
        )
        .await?;
    assert!(
        sequencer_allowance.get("error").is_some(),
        "sequencer allowance(owner, spender) should revert"
    );

    Ok(())
}

/// TIP-20 permit nonce reads are owner-scoped at the precompile boundary, including calls forwarded
/// through Multicall3.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_nonce_eth_call_privacy() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc_l1().await?;
    let owner_signer = PrivateKeySigner::random();
    let owner = owner_signer.address();
    let outsider_signer = PrivateKeySigner::random();
    let nonce_call = PrecompileTip20::noncesCall { owner };
    let calldata = nonce_call.abi_encode();

    let outsider = ctx
        .call_as_user(
            "eth_call",
            json!([{
                "to": format!("{PATH_USD_ADDRESS:#x}"),
                "data": hex::encode_prefixed(&calldata),
            }, "latest"]),
            &outsider_signer,
        )
        .await?;
    let outsider_error = outsider["error"]["message"].as_str().unwrap_or_default();
    assert!(
        outsider_error.contains(&hex::encode_prefixed(Unauthorized::SELECTOR)),
        "non-owner nonces(owner) should revert with Unauthorized(): {outsider}"
    );

    let owner_response = ctx
        .call_as_user(
            "eth_call",
            json!([{
                "to": format!("{PATH_USD_ADDRESS:#x}"),
                "data": hex::encode_prefixed(&calldata),
            }, "latest"]),
            &owner_signer,
        )
        .await?;
    let owner_bytes = hex::decode(
        owner_response["result"]
            .as_str()
            .expect("owner nonce read should return hex")
            .trim_start_matches("0x"),
    )?;
    assert_eq!(
        PrecompileTip20::noncesCall::abi_decode_returns(&owner_bytes)?,
        U256::ZERO
    );

    let multicall = IMulticall3::aggregateCall {
        calls: vec![IMulticall3::Call {
            target: PATH_USD_ADDRESS,
            callData: calldata.into(),
        }],
    };
    let forwarded = ctx
        .call_as_user(
            "eth_call",
            json!([{
                "to": format!("{:#x}", alloy_provider::MULTICALL3_ADDRESS),
                "data": hex::encode_prefixed(multicall.abi_encode()),
            }, "latest"]),
            &outsider_signer,
        )
        .await?;
    assert!(
        forwarded.get("result").is_none() && forwarded.get("error").is_some(),
        "Multicall3 must not expose another owner's TIP-20 nonce: {forwarded}"
    );

    Ok(())
}

/// `eth_call` against ZoneInbox refund balances is scoped to the authenticated
/// owner, preventing arbitrary `refunds(token, owner)` reads.
#[tokio::test(flavor = "multi_thread")]
async fn test_zone_inbox_refunds_eth_call_privacy() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc_l1().await?;

    let owner_signer = PrivateKeySigner::random();
    let owner = owner_signer.address();
    let outsider_signer = PrivateKeySigner::random();

    let refunds_call = IZoneInbox::refundsCall {
        token: ZONE_TOKEN_ADDRESS,
        owner,
    };
    let refunds_data = hex::encode_prefixed(refunds_call.abi_encode());

    let outsider_refunds = ctx
        .call_as_user(
            "eth_call",
            json!([
                {
                    "to": format!("{ZONE_INBOX_ADDRESS:#x}"),
                    "data": refunds_data,
                },
                "latest"
            ]),
            &outsider_signer,
        )
        .await?;
    let outsider_error = outsider_refunds["error"]["message"]
        .as_str()
        .expect("non-owner refund read should return an RPC error message");
    let unauthorized_selector = hex::encode_prefixed(Unauthorized::SELECTOR);
    assert!(
        outsider_error.contains("Unauthorized") && outsider_error.contains(&unauthorized_selector),
        "the ZoneInbox getter must reject a direct non-owner refund read with Unauthorized(): {outsider_refunds}"
    );

    let owner_refunds = ctx
        .call_as_user(
            "eth_call",
            json!([
                {
                    "to": format!("{ZONE_INBOX_ADDRESS:#x}"),
                    "data": hex::encode_prefixed(refunds_call.abi_encode()),
                },
                "latest"
            ]),
            &owner_signer,
        )
        .await?;
    let owner_refunds_bytes = hex::decode(
        owner_refunds["result"]
            .as_str()
            .expect("own refunds call should return hex")
            .trim_start_matches("0x"),
    )?;
    assert_eq!(
        IZoneInbox::refundsCall::abi_decode_returns(&owner_refunds_bytes)?,
        0,
        "own refunds(token, owner) read should retain normal eth_call behavior"
    );

    let multicall = IMulticall3::aggregateCall {
        calls: vec![IMulticall3::Call {
            target: ZONE_INBOX_ADDRESS,
            callData: refunds_call.abi_encode().into(),
        }],
    };
    let forwarded_refunds = ctx
        .call_as_user(
            "eth_call",
            json!([
                {
                    "to": format!("{:#x}", alloy_provider::MULTICALL3_ADDRESS),
                    "data": hex::encode_prefixed(multicall.abi_encode()),
                },
                "latest"
            ]),
            &outsider_signer,
        )
        .await?;
    assert!(
        forwarded_refunds.get("result").is_none() && forwarded_refunds.get("error").is_some(),
        "Multicall3 must not expose another owner's refund balance: {forwarded_refunds}"
    );

    Ok(())
}

/// Account-indexed native getters enforce privacy inside the EVM so direct and helper-forwarded
/// calls cannot read another account's NonceManager, AccountKeychain, or StorageCredits state.
#[tokio::test(flavor = "multi_thread")]
async fn test_native_account_getter_eth_call_privacy() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc_l1().await?;
    let owner_signer = PrivateKeySigner::random();
    let owner = owner_signer.address();
    let outsider_signer = PrivateKeySigner::random();
    let key_id = Address::repeat_byte(0x55);

    let calls = [
        (
            NONCE_PRECOMPILE_ADDRESS,
            INonce::getNonceCall {
                account: owner,
                nonceKey: U256::ONE,
            }
            .abi_encode(),
            "NonceManager.getNonce",
        ),
        (
            ACCOUNT_KEYCHAIN_ADDRESS,
            IAccountKeychain::getKeyCall {
                account: owner,
                keyId: key_id,
            }
            .abi_encode(),
            "AccountKeychain.getKey",
        ),
        (
            STORAGE_CREDITS_ADDRESS,
            IStorageCredits::balanceOfCall { account: owner }.abi_encode(),
            "StorageCredits.balanceOf",
        ),
    ];

    for (target, calldata, label) in calls {
        let direct = ctx
            .call_as_user(
                "eth_call",
                json!([
                    {
                        "to": format!("{target:#x}"),
                        "data": hex::encode_prefixed(&calldata),
                    },
                    "latest"
                ]),
                &outsider_signer,
            )
            .await?;
        let direct_error = direct["error"]["message"].as_str().unwrap_or_default();
        assert!(
            direct_error.contains(&hex::encode_prefixed(Unauthorized::SELECTOR)),
            "outsider direct {label} should revert with Unauthorized(): {direct}"
        );

        let own = ctx
            .call_as_user(
                "eth_call",
                json!([
                    {
                        "to": format!("{target:#x}"),
                        "data": hex::encode_prefixed(&calldata),
                    },
                    "latest"
                ]),
                &owner_signer,
            )
            .await?;
        assert!(
            own["result"].as_str().is_some(),
            "owner direct {label} should retain normal eth_call behavior: {own}"
        );

        let multicall = IMulticall3::aggregateCall {
            calls: vec![IMulticall3::Call {
                target,
                callData: calldata.into(),
            }],
        };
        let forwarded = ctx
            .call_as_user(
                "eth_call",
                json!([
                    {
                        "to": format!("{:#x}", alloy_provider::MULTICALL3_ADDRESS),
                        "data": hex::encode_prefixed(multicall.abi_encode()),
                    },
                    "latest"
                ]),
                &outsider_signer,
            )
            .await?;
        assert!(
            forwarded.get("result").is_none() && forwarded.get("error").is_some(),
            "Multicall3 must not expose another account through {label}: {forwarded}"
        );
    }

    Ok(())
}

/// Simulation methods reject contract creation and override extensions.
#[tokio::test(flavor = "multi_thread")]
async fn test_simulation_validation_rejects_create_and_overrides() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc().await?;
    let user_signer = PrivateKeySigner::random();
    let simulation_target = format!("{:#x}", Address::repeat_byte(0x11));

    for method in ["eth_call", "eth_estimateGas"] {
        let create_resp = ctx
            .call_as_user(
                method,
                json!([
                    {
                        "data": "0x60006000f3",
                    },
                    "latest"
                ]),
                &user_signer,
            )
            .await?;
        assert_eq!(
            create_resp["error"]["code"].as_i64().unwrap(),
            -32602,
            "{method} should reject create-style requests",
        );
        assert_eq!(
            create_resp["error"]["message"].as_str().unwrap(),
            "contract creation not supported on zones",
        );

        let user_override_resp = ctx
            .call_as_user(
                method,
                json!([
                    {
                        "to": simulation_target.clone(),
                        "data": "0x"
                    },
                    "latest",
                    {}
                ]),
                &user_signer,
            )
            .await?;
        assert_eq!(
            user_override_resp["error"]["code"].as_i64().unwrap(),
            -32602,
            "{method} should reject user state overrides",
        );
        assert_eq!(
            user_override_resp["error"]["message"].as_str().unwrap(),
            "state overrides not allowed",
        );
    }

    let fill_resp = ctx
        .call_as_user(
            "eth_fillTransaction",
            json!([
                {
                    "gas": "0x5208",
                }
            ]),
            &user_signer,
        )
        .await?;
    assert_eq!(fill_resp["error"]["code"].as_i64().unwrap(), -32602);
    assert_eq!(
        fill_resp["error"]["message"].as_str().unwrap(),
        "contract creation not supported on zones",
    );

    Ok(())
}

/// Block access control: full=true is rejected for all callers;
/// full=false returns redacted blocks without activity-derived commitments.
#[tokio::test(flavor = "multi_thread")]
async fn test_block_access_control() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut ctx = start_zone_with_redacted_rpc().await?;
    ctx.inject_empty_block().await?;

    let user_signer = PrivateKeySigner::random();

    // full=true → rejected with -32005
    let resp = ctx
        .call_as_user(
            "eth_getBlockByNumber",
            serde_json::json!(["latest", true]),
            &user_signer,
        )
        .await?;
    let error = resp.get("error").expect("full=true should be rejected");
    assert_eq!(
        error["code"].as_i64().unwrap(),
        -32005,
        "full=true should return -32005"
    );

    // full=false → redacted block (empty txs, zeroed logsBloom)
    let resp = ctx
        .call_as_user(
            "eth_getBlockByNumber",
            serde_json::json!(["latest", false]),
            &user_signer,
        )
        .await?;
    let block = resp.get("result").expect("should have result");
    assert_redacted_block(block);

    let block_hash = block["hash"].as_str().expect("block should have hash");
    let resp = ctx
        .call_as_user(
            "eth_getBlockByHash",
            serde_json::json!([block_hash, false]),
            &user_signer,
        )
        .await?;
    assert_redacted_block(resp.get("result").expect("should have result"));

    Ok(())
}

/// Methods outside the redacted RPC allowlist are indistinguishable from unknown methods.
#[tokio::test(flavor = "multi_thread")]
async fn test_unexposed_methods_are_not_found() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc().await?;
    let user_signer = PrivateKeySigner::random();

    for method in [
        "eth_getCode",
        "eth_getStorageAt",
        "eth_getBlockReceipts",
        "debug_traceTransaction",
        "txpool_content",
        "eth_subscribe",
        "eth_newPendingTransactionFilter",
        "eth_mining",
        "eth_hashrate",
        "eth_someNonexistentMethod",
    ] {
        let resp = ctx
            .call_as_user(method, serde_json::json!([]), &user_signer)
            .await?;
        let error = resp
            .get("error")
            .unwrap_or_else(|| panic!("{method} should return error"));
        assert_eq!(
            error["code"].as_i64().unwrap(),
            -32601,
            "{method} should return -32601"
        );
    }

    Ok(())
}

/// WebSocket log subscriptions are sender-scoped: callers only see logs
/// from their own transactions.
#[tokio::test(flavor = "multi_thread")]
async fn test_ws_logs_subscription_is_sender_scoped() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut ctx = start_zone_with_redacted_rpc().await?;
    let owner_signer = l1_dev_signer();
    let outsider_signer = PrivateKeySigner::random();
    let spender = PrivateKeySigner::random().address();

    ctx.inject_deposit(
        PATH_USD_ADDRESS,
        owner_signer.address(),
        owner_signer.address(),
        1_000_000,
    )
    .await?;
    ctx.inject_deposit(
        PATH_USD_ADDRESS,
        outsider_signer.address(),
        outsider_signer.address(),
        1_000_000,
    )
    .await?;

    let owner_token = ctx.user_token(&owner_signer);
    let mut owner_ws = connect_redacted_rpc_ws(&ctx.redacted_rpc_url, &owner_token).await?;

    owner_ws
        .send(Message::Text(
            jsonrpc_with_params(
                "eth_subscribe",
                json!(["logs", {"address": format!("{PATH_USD_ADDRESS:#x}")}]),
                1,
            )
            .into(),
        ))
        .await?;
    let broad_subscription = ws_next_json(&mut owner_ws).await?;
    assert_eq!(broad_subscription["id"], 1);
    assert_eq!(
        broad_subscription["error"]["code"].as_i64().unwrap(),
        -32602,
        "broad private log subscriptions should be rejected"
    );

    let owner_subscription = ws_subscribe(
        &mut owner_ws,
        json!([
            "logs",
            {
                "address": format!("{PATH_USD_ADDRESS:#x}"),
                "topics": [null, address_topic(owner_signer.address())],
            }
        ]),
    )
    .await?;

    let owner_provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(ctx.zone.http_url().clone());
    let outsider_provider = ProviderBuilder::new()
        .wallet(outsider_signer.clone())
        .connect_http(ctx.zone.http_url().clone());

    let owner_pending = ContractTip20::new(PATH_USD_ADDRESS, &owner_provider)
        .approve(spender, U256::from(111u64))
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .gas(TIP20_TX_GAS)
        .send()
        .await?;
    let outsider_pending = ContractTip20::new(PATH_USD_ADDRESS, &outsider_provider)
        .approve(spender, U256::from(222u64))
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .gas(TIP20_TX_GAS)
        .send()
        .await?;

    let owner_hash = *owner_pending.tx_hash();

    ctx.fixture.inject_empty_block(ctx.zone.deposit_queue());

    let owner_receipt = owner_pending.get_receipt().await?;
    let outsider_receipt = outsider_pending.get_receipt().await?;
    assert!(owner_receipt.status(), "owner approve should succeed");
    assert!(outsider_receipt.status(), "outsider approve should succeed");

    let mut owner_notifications = vec![ws_next_json(&mut owner_ws).await?];
    owner_notifications
        .extend(ws_collect_messages_until_quiet(&mut owner_ws, Duration::from_millis(500)).await?);
    let owner_hashes = owner_notifications
        .into_iter()
        .map(|notification| {
            assert_eq!(
                notification["params"]["subscription"].as_str().unwrap(),
                owner_subscription
            );
            notification["params"]["result"]["transactionHash"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<HashSet<_>>();
    assert_eq!(owner_hashes, HashSet::from([owner_hash.to_string()]));

    Ok(())
}

/// Pending transaction subscriptions are disabled because they expose mempool activity.
#[tokio::test(flavor = "multi_thread")]
async fn test_ws_pending_transaction_subscriptions_are_disabled() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc().await?;
    let user_signer = PrivateKeySigner::random();
    let user_token = ctx.user_token(&user_signer);
    let mut user_ws = connect_redacted_rpc_ws(&ctx.redacted_rpc_url, &user_token).await?;

    for (id, params) in [
        (1, json!(["newPendingTransactions"])),
        (2, json!(["newPendingTransactions", true])),
        (3, json!(["newPendingTransactions", {}])),
    ] {
        user_ws
            .send(Message::Text(
                jsonrpc_with_params("eth_subscribe", params, id).into(),
            ))
            .await?;
        let response = ws_next_json(&mut user_ws).await?;
        assert_eq!(response["id"], id);
        assert_eq!(
            response["error"]["code"].as_i64().unwrap(),
            -32006,
            "newPendingTransactions should be disabled"
        );
    }

    Ok(())
}

/// Zone-specific metadata methods return the authenticated account/token expiry
/// and the configured zone metadata.
#[tokio::test(flavor = "multi_thread")]
async fn test_zone_metadata_methods() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc_l1().await?;
    let user_signer = PrivateKeySigner::random();

    let auth_info = ctx
        .call_as_user(
            "zone_getAuthorizationTokenInfo",
            serde_json::json!([]),
            &user_signer,
        )
        .await?;
    assert_eq!(
        auth_info["result"]["account"].as_str().unwrap(),
        format!("{:#x}", user_signer.address()),
    );
    assert!(
        auth_info["result"]["expiresAt"].as_str().is_some(),
        "expiresAt should be a quantity string",
    );

    let zone_info = ctx
        .call_as_user("zone_getZoneInfo", serde_json::json!([]), &user_signer)
        .await?;
    assert_eq!(
        zone_info["result"]["zoneId"].as_str().unwrap(),
        format!("0x{:x}", ctx.config.zone_id),
    );
    assert_eq!(zone_info["result"]["isAccessEnforced"], true);
    assert_eq!(zone_info["result"]["isGatewayOpen"], false);
    assert_eq!(
        zone_info["result"]["zoneTokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|token| token.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["0x20c0000000000000000000000000000000000000"],
    );
    assert_eq!(
        zone_info["result"]["chainId"].as_str().unwrap(),
        format!("0x{:x}", ctx.config.chain_id),
    );
    let tempo_block_number = TempoState::new(TEMPO_STATE_ADDRESS, ctx.zone.provider())
        .tempoBlockNumber()
        .call()
        .await?;
    assert_eq!(
        zone_info["result"]["tempoBlockNumber"],
        format!("0x{tempo_block_number:x}"),
    );

    Ok(())
}

/// `zone_getZoneInfo` returns every token currently enabled on the portal.
#[tokio::test(flavor = "multi_thread")]
async fn test_zone_get_zone_info_returns_all_enabled_tokens() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc_l1().await?;
    let user_signer = PrivateKeySigner::random();
    let alpha_salt = B256::with_last_byte(0x44);
    let alpha_token = ctx
        .l1()
        .create_tip20("AlphaUSD", "aUSD", alpha_salt)
        .await?;

    ctx.l1()
        .enable_token_on_portal(ctx.portal_address(), alpha_token)
        .await?;

    let zone_info = ctx
        .call_as_user("zone_getZoneInfo", serde_json::json!([]), &user_signer)
        .await?;
    let zone_tokens = zone_info["result"]["zoneTokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|token| token.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();

    assert_eq!(
        zone_tokens,
        vec![
            format!("{PATH_USD_ADDRESS:#x}"),
            format!("{alpha_token:#x}")
        ],
    );

    Ok(())
}

fn encryption_public_key(secret_key: &k256::SecretKey) -> (String, u8) {
    let (x, y_parity) =
        zone_precompiles::ecies::compressed_x_and_parity(secret_key.public_key().as_affine());
    (x.to_string(), y_parity)
}

/// The method returns the latest key on Tempo L1 without waiting for the Zone
/// to process the key rotation.
#[tokio::test(flavor = "multi_thread")]
async fn test_zone_get_encryption_key_reads_latest_l1_key() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let ctx = start_zone_with_redacted_rpc_l1_with_encryption().await?;
    let portal_address = ctx.portal_address();
    let caller = ctx.l1().user_signer();

    let second_key = k256::SecretKey::from_slice(&[0x42; 32])?;
    ctx.l1()
        .set_sequencer_encryption_key(portal_address, &second_key)
        .await?;

    let (second_x, second_prefix) = encryption_public_key(&second_key);
    let second = ctx
        .call_as_user("zone_getEncryptionKey", serde_json::json!([]), &caller)
        .await?;
    assert!(
        second.get("error").is_none(),
        "unexpected response: {second}"
    );
    assert_eq!(
        second["result"],
        serde_json::json!({
            "x": second_x,
            "yParity": second_prefix,
            "keyIndex": "0x1",
        })
    );

    Ok(())
}
