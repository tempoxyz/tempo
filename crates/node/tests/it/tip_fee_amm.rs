use alloy::{
    network::ReceiptResponse,
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, coins_bip39::English},
};
use alloy_rpc_types_eth::TransactionRequest;
use std::env;
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{IFeeManager, ITIP20, tip_fee_amm::PoolKey, types::ITIPFeeAMM},
};

use crate::utils::{setup_test_node, setup_test_token};

#[tokio::test(flavor = "multi_thread")]
async fn test_mint_liquidity() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let amount = U256::from(rand::random::<u128>());
    let token_0 = setup_test_token(provider.clone(), caller).await?;
    token_0
        .mint(caller, amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    let token_1 = setup_test_token(provider.clone(), caller).await?;
    token_1
        .mint(caller, amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    fee_amm
        .createPool(*token_0.address(), *token_1.address())
        .send()
        .await?
        .get_receipt()
        .await?;

    // Approve fee manager to spend tokens
    token_0
        .approve(TIP_FEE_MANAGER_ADDRESS, U256::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;

    token_1
        .approve(TIP_FEE_MANAGER_ADDRESS, U256::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;

    let pool_key = PoolKey::new(*token_0.address(), *token_1.address());
    let pool_id = fee_amm.getPoolId(pool_key.clone().into()).call().await?;

    // Check initial state
    let total_supply = fee_amm.totalSupply(pool_id).call().await?;
    let lp_balance = fee_amm.liquidityBalances(pool_id, caller).call().await?;
    let pool = fee_amm.pools(pool_id).call().await?;

    let user_token0_balance = token_0.balanceOf(caller).call().await?;
    assert_eq!(user_token0_balance, amount);
    let user_token1_balance = token_1.balanceOf(caller).call().await?;
    assert_eq!(user_token1_balance, amount);
    let fee_manager_token0_balance = token_0.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(fee_manager_token0_balance, U256::ZERO);
    let fee_manager_token1_balance = token_1.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(fee_manager_token1_balance, U256::ZERO);

    assert_eq!(total_supply, U256::ZERO);
    assert_eq!(lp_balance, U256::ZERO);
    assert_eq!(pool.reserve0, 0);
    assert_eq!(pool.reserve1, 0);

    // Mint liquidity
    let mint_receipt = fee_amm
        .mint(pool_key.into(), amount, amount, caller)
        .send()
        .await?
        .get_receipt()
        .await?;

    assert!(mint_receipt.status(), "Mint transaction should succeed");

    // Assert state changes
    let total_supply = fee_amm.totalSupply(pool_id).call().await?;
    assert!(total_supply > U256::ZERO);
    assert!(total_supply > lp_balance); // Should be LP balance + MIN_LIQUIDITY

    let lp_balance = fee_amm.liquidityBalances(pool_id, caller).call().await?;
    assert!(lp_balance > U256::ZERO);
    assert_eq!(lp_balance, total_supply - U256::from(1000u64)); // MIN_LIQUIDITY = 1000

    let pool = fee_amm.pools(pool_id).call().await?;
    assert_eq!(pool.reserve0, amount.to::<u128>());
    assert_eq!(pool.reserve1, amount.to::<u128>());

    let final_token0_balance = token_0.balanceOf(caller).call().await?;
    assert_eq!(final_token0_balance, user_token0_balance - amount);
    let final_token1_balance = token_1.balanceOf(caller).call().await?;
    assert_eq!(final_token1_balance, user_token1_balance - amount);

    let final_fee_manager_token0_balance =
        token_0.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(
        final_fee_manager_token0_balance,
        fee_manager_token0_balance + amount
    );
    let final_fee_manager_token1_balance =
        token_1.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(
        final_fee_manager_token1_balance,
        fee_manager_token1_balance + amount
    );

    Ok(())
}
