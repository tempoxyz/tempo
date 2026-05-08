use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};
use alloy::{
    consensus::{Signed, TxLegacy, transaction::SignerRecoverable},
    hex,
    primitives::{Address, B256, Bytes, Signature, U256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::MnemonicBuilder},
};
use alloy_eips::{Decodable2718, Encodable2718};
use core::num::NonZeroU64;
use reth_node_core::args::PruningArgs;
use reth_primitives_traits::transaction::TxHashRef as _;
use serde_json::json;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;
use tempo_node::rpc::expiring_nonce_status::{ExpiringNonceStatus, ExpiringNonceStatusResponse};
use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, nonce::NonceManager};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{TEMPO_EXPIRING_NONCE_KEY, tempo_transaction::Call},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_get_expiring_nonce_status() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;
    setup.node.payload.timestamp = 0;
    let current_timestamp = setup.node.payload.timestamp;

    let (included, included_hash) =
        signed_expiring_nonce_tx(&signer, chain_id, current_timestamp + 30)?;
    assert_eq!(
        get_expiring_nonce_status(&provider, &included).await?,
        ExpiringNonceStatus::Pending,
    );

    setup.node.rpc.inject_tx(included.clone().into()).await?;
    setup.node.advance_block().await?;
    assert_receipt_status(&provider, included_hash, true).await?;

    let (expired, _) = signed_expiring_nonce_tx(&signer, chain_id, current_timestamp + 29)?;
    let (expired_at_boundary, _) =
        signed_expiring_nonce_tx(&signer, chain_id, current_timestamp + 30)?;
    advance_until_finalized_after(&mut setup, &provider, current_timestamp + 30).await?;

    assert_eq!(
        get_expiring_nonce_status(&provider, &included).await?,
        ExpiringNonceStatus::Included,
    );
    assert_eq!(
        get_expiring_nonce_status(&provider, &expired).await?,
        ExpiringNonceStatus::Expired,
    );
    assert_eq!(
        get_expiring_nonce_status(&provider, &expired_at_boundary).await?,
        ExpiringNonceStatus::Expired,
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_expiring_nonce_status_unavailable_after_pruned_replay_state() -> eyre::Result<()>
{
    reth_tracing::init_test_tracing();

    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let chain_id = 1337;
    let valid_before = 5;
    let (target, _) = signed_expiring_nonce_tx(&signer, chain_id, valid_before)?;
    let target_expiring_nonce_hash = expiring_nonce_hash(&target)?;

    // Seed the target as already seen at genesis so that later classification
    // depends on historical pre-expiry replay state, not an unchanged zero slot.
    let mut setup = TestNodeBuilder::new()
        .with_genesis(genesis_with_seen_expiring_nonce(
            target_expiring_nonce_hash,
            valid_before,
        )?)
        .with_pruning(PruningArgs {
            block_interval: Some(1),
            storage_history_before: Some(20),
            account_history_before: Some(20),
            minimum_distance: Some(0),
            ..Default::default()
        })
        .build_with_node_access()
        .await?;
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(signer.clone())
        .connect_http(setup.node.rpc_url());
    setup.node.payload.timestamp = 0;

    advance_until_finalized_after(&mut setup, &provider, valid_before).await?;

    // The seeded ring pointer starts at zero, so this real expiring-nonce tx
    // evicts the target hash and clears its latest replay-state entry.
    let clearer_valid_before = setup.node.payload.timestamp + 30;
    let (clearer, clearer_hash) =
        signed_expiring_nonce_tx(&signer, chain_id, clearer_valid_before)?;
    setup.node.rpc.inject_tx(clearer.into()).await?;
    setup.node.advance_block().await?;
    assert_receipt_status(&provider, clearer_hash, true).await?;

    assert_eq!(
        get_expiring_nonce_status(&provider, &target).await?,
        ExpiringNonceStatus::Included,
    );

    for _ in 0..40 {
        setup.node.advance_block().await?;
    }

    // After storage-history pruning, the node can no longer reconstruct the
    // target's nonzero pre-expiry replay state, so classification is unavailable.
    assert_eq!(
        get_expiring_nonce_status(&provider, &target).await?,
        ExpiringNonceStatus::Unavailable,
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_expiring_nonce_status_rejects_non_expiring_transaction() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(signer.clone())
        .connect_http(setup.http_url);
    let chain_id = provider.get_chain_id().await?;

    let mut tx = expiring_nonce_tx(chain_id, 1);
    tx.nonce_key = U256::from(1);
    tx.valid_before = None;
    let signature = signer.sign_hash_sync(&tx.signature_hash())?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();
    let encoded = envelope.encoded_2718();

    let err = provider
        .raw_request::<_, ExpiringNonceStatusResponse>(
            "tempo_getExpiringNonceStatus".into(),
            (json!({ "signedTransaction": format!("0x{}", hex::encode(encoded)) }),),
        )
        .await
        .expect_err("non-expiring transaction should be rejected");

    assert!(
        err.to_string()
            .contains("not an expiring-nonce transaction")
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_expiring_nonce_status_rejects_malformed_signed_transaction() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(setup.http_url);

    let err = provider
        .raw_request::<_, ExpiringNonceStatusResponse>(
            "tempo_getExpiringNonceStatus".into(),
            (json!({ "signedTransaction": "0xdeadbeef" }),),
        )
        .await
        .expect_err("malformed transaction bytes should be rejected");

    assert!(err.to_string().contains("invalid signed transaction"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_expiring_nonce_status_rejects_legacy_transaction() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(setup.http_url);
    let legacy = TempoTxEnvelope::Legacy(Signed::new_unhashed(
        TxLegacy {
            chain_id: None,
            nonce: 0,
            gas_price: 0,
            gas_limit: 21_000,
            to: Address::random().into(),
            value: U256::ZERO,
            input: Bytes::new(),
        },
        Signature::test_signature(),
    ));
    let encoded = legacy.encoded_2718();

    let err = provider
        .raw_request::<_, ExpiringNonceStatusResponse>(
            "tempo_getExpiringNonceStatus".into(),
            (json!({ "signedTransaction": format!("0x{}", hex::encode(encoded)) }),),
        )
        .await
        .expect_err("legacy transaction should be rejected");

    assert!(
        err.to_string()
            .contains("transaction is not a Tempo transaction")
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_expiring_nonce_status_rejects_missing_valid_before() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(signer.clone())
        .connect_http(setup.http_url);
    let chain_id = provider.get_chain_id().await?;

    let mut tx = expiring_nonce_tx(chain_id, 1);
    tx.valid_before = None;
    let signature = signer.sign_hash_sync(&tx.signature_hash())?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();
    let encoded = envelope.encoded_2718();

    let err = provider
        .raw_request::<_, ExpiringNonceStatusResponse>(
            "tempo_getExpiringNonceStatus".into(),
            (json!({ "signedTransaction": format!("0x{}", hex::encode(encoded)) }),),
        )
        .await
        .expect_err("missing validBefore should be rejected");

    assert!(err.to_string().contains("missing validBefore"));

    Ok(())
}

fn signed_expiring_nonce_tx(
    signer: &impl SignerSync,
    chain_id: u64,
    valid_before: u64,
) -> eyre::Result<(Vec<u8>, B256)> {
    let tx = expiring_nonce_tx(chain_id, valid_before);
    let signature = signer.sign_hash_sync(&tx.signature_hash())?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();
    Ok((envelope.encoded_2718(), *envelope.tx_hash()))
}

fn expiring_nonce_tx(chain_id: u64, valid_before: u64) -> TempoTransaction {
    TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: Address::random().into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: TEMPO_EXPIRING_NONCE_KEY,
        nonce: 0,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_before: Some(NonZeroU64::new(valid_before).expect("valid_before must be non-zero")),
        ..Default::default()
    }
}

fn expiring_nonce_hash(signed_transaction: &[u8]) -> eyre::Result<B256> {
    let mut encoded = signed_transaction;
    let envelope = TempoTxEnvelope::decode_2718(&mut encoded)?;
    let aa_tx = envelope
        .as_aa()
        .ok_or_else(|| eyre::eyre!("expected Tempo transaction"))?;
    let sender = envelope.recover_signer()?;
    Ok(aa_tx.expiring_nonce_hash(sender))
}

fn genesis_with_seen_expiring_nonce(
    expiring_nonce_hash: B256,
    valid_before: u64,
) -> eyre::Result<String> {
    let mut genesis: serde_json::Value =
        serde_json::from_str(include_str!("../assets/test-genesis.json"))?;
    let storage = &mut genesis["alloc"][format!("{NONCE_PRECOMPILE_ADDRESS:#x}")]["storage"];
    if storage.is_null() {
        *storage = serde_json::json!({});
    }

    let nonce_manager = NonceManager::new();
    storage[storage_key(nonce_manager.expiring_nonce_seen[expiring_nonce_hash].slot())] =
        serde_json::Value::String(storage_value(U256::from(valid_before)));
    storage[storage_key(nonce_manager.expiring_nonce_ring[0].slot())] =
        serde_json::Value::String(format!("{expiring_nonce_hash:#x}"));

    Ok(serde_json::to_string(&genesis)?)
}

fn storage_key(slot: U256) -> String {
    storage_value(slot)
}

fn storage_value(value: U256) -> String {
    format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
}

async fn get_expiring_nonce_status(
    provider: &impl Provider<TempoNetwork>,
    signed_transaction: &[u8],
) -> eyre::Result<ExpiringNonceStatus> {
    let response: ExpiringNonceStatusResponse = provider
        .raw_request(
            "tempo_getExpiringNonceStatus".into(),
            (json!({ "signedTransaction": format!("0x{}", hex::encode(signed_transaction)) }),),
        )
        .await?;

    Ok(response.status)
}

async fn assert_receipt_status(
    provider: &impl Provider<TempoNetwork>,
    tx_hash: B256,
    expected_success: bool,
) -> eyre::Result<()> {
    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;
    let receipt = receipt.ok_or_else(|| eyre::eyre!("missing receipt for {tx_hash}"))?;
    let expected = if expected_success { "0x1" } else { "0x0" };
    assert_eq!(receipt["status"], expected);
    Ok(())
}

async fn advance_until_finalized_after(
    setup: &mut crate::utils::SingleNodeSetup,
    provider: &impl Provider<TempoNetwork>,
    timestamp: u64,
) -> eyre::Result<()> {
    for _ in 0..60 {
        setup.node.advance_block().await?;

        let finalized: Option<serde_json::Value> = provider
            .raw_request("eth_getBlockByNumber".into(), ("finalized", false))
            .await?;
        let Some(finalized) = finalized else {
            continue;
        };
        let Some(finalized_timestamp) = finalized["timestamp"].as_str() else {
            continue;
        };
        let finalized_timestamp =
            u64::from_str_radix(finalized_timestamp.trim_start_matches("0x"), 16)?;
        if finalized_timestamp >= timestamp {
            return Ok(());
        }
    }

    eyre::bail!("finalized block did not reach timestamp {timestamp}")
}
