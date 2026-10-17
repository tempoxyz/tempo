//! End-to-end coverage for the Zone base-fee transition.

use alloy::{
    consensus::BlockHeader as _,
    network::ReceiptResponse as _,
    primitives::{Address, TxKind, U256},
    providers::Provider as _,
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_rpc_types_eth::{BlockNumberOrTag, FeeHistory};
use alloy_signer::SignerSync as _;
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_chainspec::{
    hardfork::TempoHardfork,
    spec::{
        TEMPO_T0_BASE_FEE, TEMPO_T1_BASE_FEE, TEMPO_T7_BASE_FEE_CAP, tempo_t7_next_block_base_fee,
    },
};
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{
        AASigned, Call, PrimitiveSignature, TempoSignature, TempoTransaction,
        calc_gas_balance_spending,
    },
};
use zone_chainspec::test_utils::set_tempo_fork;
use zone_node::rpc::auth::AuthContext;
use zone_precompiles::ZONE_FEE_MANAGER_ADDRESS;

use crate::utils::{
    DEFAULT_TIMEOUT, ZoneTestNode, start_local_zone_with_fixture_and_withdrawal_batch_interval,
};

const ZONE_ID: u32 = 1;
const FEE_BALANCE: u128 = 1_000_000;
const PRIORITY_FEE: u128 = 1_000_000_000;

async fn redacted_rpc(
    zone: &ZoneTestNode,
) -> eyre::Result<std::sync::Arc<dyn zone_node::rpc::ZoneRpcApi>> {
    zone.rpc_api(zone_node::rpc::RedactedRpcConfig {
        listen_addr: ([127, 0, 0, 1], 0).into(),
        zone_id: ZONE_ID,
        chain_id: zone.provider().get_chain_id().await?,
        max_auth_token_validity: zone_node::rpc::auth::DEFAULT_MAX_AUTH_TOKEN_VALIDITY,
        max_response_size: 160 * 1024 * 1024,
        zone_portal: Address::ZERO,
    })
    .await
}

fn sponsored_transaction(
    sender: &PrivateKeySigner,
    fee_payer: &PrivateKeySigner,
    chain_id: u64,
) -> eyre::Result<TempoTxEnvelope> {
    let mut transaction = TempoTransaction {
        chain_id,
        max_fee_per_gas: u128::from(TEMPO_T7_BASE_FEE_CAP),
        max_priority_fee_per_gas: PRIORITY_FEE,
        gas_limit: 500_000,
        calls: vec![Call {
            to: TxKind::Call(sender.address()),
            value: U256::ZERO,
            input: Default::default(),
        }],
        fee_token: Some(PATH_USD_ADDRESS),
        ..Default::default()
    };

    let fee_payer_hash = transaction.fee_payer_signature_hash(sender.address());
    transaction.fee_payer_signature = Some(fee_payer.sign_hash_sync(&fee_payer_hash)?);
    let sender_signature = sender.sign_hash_sync(&transaction.signature_hash())?;
    let signed = AASigned::new_unhashed(
        transaction,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(sender_signature)),
    );
    Ok(signed.into())
}

fn t14_genesis() -> eyre::Result<alloy::genesis::Genesis> {
    let mut genesis = zone_node::genesis::genesis_template()?;
    set_tempo_fork(&mut genesis, TempoHardfork::T14, 1);
    Ok(genesis)
}

#[tokio::test(flavor = "multi_thread")]
async fn t13_keeps_legacy_fees_without_t14() -> eyre::Result<()> {
    let mut genesis = zone_node::genesis::genesis_template()?;
    set_tempo_fork(&mut genesis, TempoHardfork::T13, 0);
    let (zone, mut fixture) =
        start_local_zone_with_fixture_and_withdrawal_batch_interval(ZONE_ID, 2, 2, genesis).await?;
    fixture.inject_empty_block(zone.deposit_queue());
    zone.wait_for_block_number(1, DEFAULT_TIMEOUT).await?;
    let block = zone
        .provider()
        .get_block_by_number(1.into())
        .await?
        .expect("first Zone block");
    assert_eq!(block.header.base_fee_per_gas(), Some(0));

    let rpc = redacted_rpc(&zone).await?;
    let gas_price = rpc
        .gas_price()
        .await
        .map_err(|err| eyre::eyre!(err.to_string()))?;
    assert_eq!(
        serde_json::from_str::<U256>(gas_price.get())?,
        U256::from(TEMPO_T1_BASE_FEE)
    );
    let history = rpc
        .fee_history(1, BlockNumberOrTag::Number(1), Some(Vec::new()))
        .await
        .map_err(|err| eyre::eyre!(err.to_string()))?;
    let history: FeeHistory = serde_json::from_str(history.get())?;
    assert_eq!(
        history.base_fee_per_gas,
        vec![u128::from(TEMPO_T0_BASE_FEE); 2]
    );
    assert_eq!(history.gas_used_ratio, vec![0.0]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t14_activates_dynamic_base_fee() -> eyre::Result<()> {
    let (zone, mut fixture) =
        start_local_zone_with_fixture_and_withdrawal_batch_interval(ZONE_ID, 2, 2, t14_genesis()?)
            .await?;

    let genesis = zone
        .provider()
        .get_block_by_number(0.into())
        .await?
        .expect("Zone genesis block");
    fixture.inject_empty_block(zone.deposit_queue());
    zone.wait_for_block_number(1, DEFAULT_TIMEOUT).await?;
    let first = zone
        .provider()
        .get_block_by_number(1.into())
        .await?
        .expect("first Zone block");
    assert_eq!(
        first.header.base_fee_per_gas(),
        Some(tempo_t7_next_block_base_fee(
            genesis.header.base_fee_per_gas().expect("genesis base fee"),
            genesis.header.gas_used(),
        )),
        "the T14 activation block must adjust from its parent"
    );
    let rpc = redacted_rpc(&zone).await?;
    let gas_price = rpc
        .gas_price()
        .await
        .map_err(|err| eyre::eyre!(err.to_string()))?;
    assert_eq!(
        serde_json::from_str::<U256>(gas_price.get())?,
        U256::from(tempo_t7_next_block_base_fee(
            first
                .header
                .base_fee_per_gas()
                .expect("first block base fee"),
            first.header.gas_used(),
        )),
        "eth_gasPrice must quote the next block's base fee"
    );
    let fee_history = rpc
        .fee_history(1, BlockNumberOrTag::Number(0), Some(Vec::new()))
        .await
        .map_err(|err| eyre::eyre!(err.to_string()))?;
    let fee_history: FeeHistory = serde_json::from_str(fee_history.get())?;
    assert_eq!(
        fee_history.base_fee_per_gas,
        vec![
            u128::from(genesis.header.base_fee_per_gas().expect("genesis base fee")),
            u128::from(
                first
                    .header
                    .base_fee_per_gas()
                    .expect("first block base fee")
            ),
        ],
        "fee history must use the canonical T14 successor fee at the fork boundary"
    );

    fixture.inject_empty_block(zone.deposit_queue());
    zone.wait_for_block_number(2, DEFAULT_TIMEOUT).await?;
    let second = zone
        .provider()
        .get_block_by_number(2.into())
        .await?
        .expect("second Zone block");
    assert_eq!(
        second.header.base_fee_per_gas(),
        Some(tempo_t7_next_block_base_fee(
            first
                .header
                .base_fee_per_gas()
                .expect("first block base fee"),
            first.header.gas_used(),
        )),
        "post-activation blocks must adjust from their parent's fee and gas usage"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sponsored_transaction_settles_nonzero_base_fee() -> eyre::Result<()> {
    let (zone, mut fixture) =
        start_local_zone_with_fixture_and_withdrawal_batch_interval(ZONE_ID, 2, 2, t14_genesis()?)
            .await?;
    let sender = PrivateKeySigner::random();
    let fee_payer = PrivateKeySigner::random();
    let deposits = [sender.address(), fee_payer.address()]
        .map(|account| fixture.make_deposit(PATH_USD_ADDRESS, account, account, FEE_BALANCE));
    fixture.inject_deposits(zone.deposit_queue(), deposits.into());
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        fee_payer.address(),
        U256::from(FEE_BALANCE),
        DEFAULT_TIMEOUT,
    )
    .await?;

    let provider = zone.provider();
    let beneficiary = provider
        .get_block_by_number(1.into())
        .await?
        .expect("deposit block")
        .header
        .beneficiary();
    let sender_before = zone.balance_of(PATH_USD_ADDRESS, sender.address()).await?;
    let fee_payer_before = zone
        .balance_of(PATH_USD_ADDRESS, fee_payer.address())
        .await?;
    let beneficiary_before = zone.balance_of(PATH_USD_ADDRESS, beneficiary).await?;
    let escrow_before = zone
        .balance_of(PATH_USD_ADDRESS, ZONE_FEE_MANAGER_ADDRESS)
        .await?;

    let transaction = sponsored_transaction(&sender, &fee_payer, provider.get_chain_id().await?)?;
    let pending = provider
        .send_raw_transaction(&transaction.encoded_2718())
        .await?;
    fixture.inject_empty_block(zone.deposit_queue());
    let receipt = pending.get_receipt().await?;
    assert!(receipt.status(), "sponsored transaction must succeed");
    assert!(
        receipt.effective_gas_price > 0,
        "T14 transaction must pay a nonzero base fee"
    );
    let block = provider
        .get_block_by_number(
            receipt
                .block_number()
                .expect("mined transaction block number")
                .into(),
        )
        .await?
        .expect("mined transaction block");
    let base_fee = block.header.base_fee_per_gas().expect("block base fee");
    assert!(
        receipt.effective_gas_price > u128::from(base_fee),
        "transaction must include a priority fee"
    );
    let rpc = redacted_rpc(&zone).await?;
    let gas_price = rpc
        .gas_price()
        .await
        .map_err(|err| eyre::eyre!(err.to_string()))?;
    assert_eq!(
        serde_json::from_str::<U256>(gas_price.get())?,
        U256::from(tempo_t7_next_block_base_fee(
            base_fee,
            block.header.gas_used()
        )),
        "eth_gasPrice must quote the next block's base fee without the sampled priority fee"
    );

    let filled = rpc
        .fill_transaction(
            TempoTransactionRequest {
                inner: TransactionRequest {
                    from: Some(sender.address()),
                    to: Some(TxKind::Call(sender.address())),
                    gas: Some(21_000),
                    ..Default::default()
                },
                ..Default::default()
            },
            AuthContext {
                caller: sender.address(),
                expires_at: u64::MAX,
                keychain_key_id: None,
            },
        )
        .await
        .map_err(|err| eyre::eyre!(err.to_string()))?;
    let filled: serde_json::Value = serde_json::from_str(filled.get())?;
    assert_eq!(
        filled["tx"]["maxPriorityFeePerGas"], "0x0",
        "eth_fillTransaction must default the priority fee to zero"
    );

    let actual_fee = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price);
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, sender.address()).await?,
        sender_before,
        "the sponsored sender must not pay the execution fee"
    );
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, fee_payer.address())
            .await?,
        fee_payer_before - actual_fee,
        "the fee payer must pay exactly the receipt fee"
    );
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, beneficiary).await?,
        beneficiary_before + actual_fee,
        "the producing sequencer must receive the execution fee"
    );
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, ZONE_FEE_MANAGER_ADDRESS)
            .await?,
        escrow_before,
        "unused maximum-fee escrow must be refunded"
    );

    Ok(())
}
