use alloy::{
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::MnemonicBuilder},
    sol_types::SolCall,
};
use alloy_eips::Encodable2718;
use tempo_contracts::precompiles::{ITIP20, ITIPFeeAMM};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::amm::PoolKey,
};
use tempo_primitives::{TempoTransaction, TempoTxEnvelope, transaction::tempo_transaction::Call};

use crate::utils::setup_test_token;

/// Test that AMM liquidity validation correctly rejects transactions with insufficient liquidity.
///
/// This test verifies that when a pool exists between payment_token and validator_token,
/// transactions can use that payment token as long as there's sufficient liquidity.
/// When liquidity is drained, transactions should be rejected.
#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_insufficient_fee_amm_liquidity() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = crate::utils::TestNodeBuilder::new()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let sender_address = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet.clone())
        .connect_http(http_url);

    // Setup payment token
    let payment_token = setup_test_token(provider.clone(), sender_address).await?;
    let payment_token_addr = *payment_token.address();

    let validator_token_addr = DEFAULT_FEE_TOKEN;
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let validator_token = ITIP20::new(validator_token_addr, provider.clone());

    let liquidity_amount = U256::from(10_000_000);

    println!("Setting up FeeAMM pool with initial liquidity...");

    // Mint tokens for liquidity
    validator_token
        .mint(sender_address, liquidity_amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    payment_token
        .mint(sender_address, liquidity_amount * U256::from(2))
        .send()
        .await?
        .get_receipt()
        .await?;

    // Create pool with liquidity
    fee_amm
        .mint(
            payment_token_addr,
            validator_token_addr,
            liquidity_amount,
            sender_address,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    println!("FeeAMM pool created with liquidity.");

    // First, verify transactions work WITH liquidity
    println!("Testing transaction with sufficient liquidity (should succeed)...");

    let tx = TempoTransaction {
        fee_token: Some(payment_token_addr),
        calls: vec![Call {
            to: payment_token_addr.into(),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: sender_address,
                amount: U256::from(1),
            }
            .abi_encode()
            .into(),
        }],
        chain_id: provider.get_chain_id().await?,
        max_fee_per_gas: provider.get_gas_price().await?,
        max_priority_fee_per_gas: provider.get_gas_price().await?,
        nonce: provider.get_transaction_count(sender_address).await?,
        gas_limit: 1_000_000,
        ..Default::default()
    };
    let signature = wallet.sign_hash_sync(&tx.signature_hash()).unwrap();
    let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();

    provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .watch()
        .await?;

    println!("Transaction with liquidity succeeded as expected.");

    // Now drain the pool
    println!("Draining pool liquidity...");

    let pool_key = PoolKey::new(payment_token_addr, validator_token_addr);
    let pool_id = pool_key.get_id();

    let lp_balance = fee_amm
        .liquidityBalances(pool_id, sender_address)
        .call()
        .await?;

    // Use explicit nonce to avoid stale nonce issues
    let burn_nonce = provider.get_transaction_count(sender_address).await?;
    fee_amm
        .burn(
            payment_token_addr,
            validator_token_addr,
            lp_balance,
            sender_address,
        )
        .nonce(burn_nonce)
        .send()
        .await?
        .get_receipt()
        .await?;

    let pool = fee_amm.pools(pool_id).call().await?;
    println!(
        "Pool drained. Reserves - user_token: {}, validator_token: {}",
        pool.reserveUserToken, pool.reserveValidatorToken
    );

    // Now try again - should fail due to insufficient liquidity
    println!("Testing transaction with insufficient liquidity (should fail)...");

    // Use high gas to ensure the amount_out exceeds remaining reserves
    let tx = TempoTransaction {
        fee_token: Some(payment_token_addr),
        calls: vec![Call {
            to: payment_token_addr.into(),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: sender_address,
                amount: U256::from(1),
            }
            .abi_encode()
            .into(),
        }],
        chain_id: provider.get_chain_id().await?,
        max_fee_per_gas: 1_000_000_000_000u128, // Very high gas price
        max_priority_fee_per_gas: 1_000_000_000_000u128,
        nonce: provider.get_transaction_count(sender_address).await?,
        gas_limit: 1_000_000, // High gas limit
        ..Default::default()
    };
    let signature = wallet.sign_hash_sync(&tx.signature_hash()).unwrap();
    let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();

    let result = provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await;

    match result {
        Ok(_) => {
            panic!("Transaction should have been rejected due to insufficient AMM liquidity");
        }
        Err(err) => {
            let err_str = err.to_string();
            assert!(
                err_str.contains("Insufficient liquidity"),
                "Expected 'Insufficient liquidity' error, got: {err}"
            );
            println!("Transaction correctly rejected: {err}");
        }
    }

    println!("Test completed: AMM liquidity validation verified");

    Ok(())
}
