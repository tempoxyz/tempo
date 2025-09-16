use alloy::{
    primitives::U256,
    providers::ProviderBuilder,
    signers::local::{MnemonicBuilder, coins_bip39::English},
    sol_types::SolEvent,
};
use alloy_primitives::Address;
use std::env;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{
        tip_fee_manager::amm::{MIN_LIQUIDITY, PoolKey, sqrt},
        types::{IFeeManager, ITIP20, ITIPFeeAMM},
    },
};

use crate::utils::{setup_test_node, setup_test_token};

#[tokio::test(flavor = "multi_thread")]
async fn test_create_pool() -> eyre::Result<()> {
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
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Setup test tokens and fee AMM
    let token_0 = Address::random();
    let token_1 = Address::random();
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Create pool
    let create_pool_receipt = fee_amm
        .createPool(token_0, token_1)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(create_pool_receipt.status());

    // Assert pool exists
    let pool_key = PoolKey::new(token_0, token_1);
    let pool_id = pool_key.get_id();
    assert!(fee_amm.poolExists(pool_id).call().await?);

    // Assert pool initial state
    let pool = fee_amm.pools(pool_id).call().await?;
    assert_eq!(pool.reserveUserToken, 0);
    assert_eq!(pool.reserveValidatorToken, 0);
    assert_eq!(pool.pendingFeeSwapIn, 0);

    let total_supply = fee_amm.totalSupply(pool_id).call().await?;
    assert_eq!(total_supply, U256::ZERO);

    // Assert PoolCreated event was emitted
    let pool_created_event = create_pool_receipt
        .logs()
        .iter()
        .filter_map(|log| ITIPFeeAMM::PoolCreated::decode_log(&log.inner).ok())
        .next()
        .expect("PoolCreated event should be emitted");

    // Assert event values match the pool key
    assert_eq!(pool_created_event.userToken, pool_key.user_token);
    assert_eq!(pool_created_event.validatorToken, pool_key.validator_token);

    Ok(())
}

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

    // Setup test token and fee AMM
    let token_0 = setup_test_token(provider.clone(), caller).await?;
    let token_1 = setup_test_token(provider.clone(), caller).await?;
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Mint, approve and create pool
    let mut pending = vec![];
    pending.push(token_0.mint(caller, amount).send().await?);
    pending.push(token_1.mint(caller, amount).send().await?);
    pending.push(
        token_0
            .approve(TIP_FEE_MANAGER_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    pending.push(
        token_1
            .approve(TIP_FEE_MANAGER_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    pending.push(
        fee_amm
            .createPool(*token_0.address(), *token_1.address())
            .send()
            .await?,
    );

    for tx in pending {
        let receipt = tx.get_receipt().await?;
        assert!(receipt.status());
    }

    // Assert initial state
    let pool_key = PoolKey::new(*token_0.address(), *token_1.address());
    let pool_id = pool_key.get_id();
    assert!(fee_amm.poolExists(pool_id).call().await?);

    let user_token0_balance = token_0.balanceOf(caller).call().await?;
    assert_eq!(user_token0_balance, amount);

    let user_token1_balance = token_1.balanceOf(caller).call().await?;
    assert_eq!(user_token1_balance, amount);

    let fee_manager_token0_balance = token_0.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(fee_manager_token0_balance, U256::ZERO);

    let fee_manager_token1_balance = token_1.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(fee_manager_token1_balance, U256::ZERO);

    let total_supply = fee_amm.totalSupply(pool_id).call().await?;
    assert_eq!(total_supply, U256::ZERO);

    let lp_balance = fee_amm.liquidityBalances(pool_id, caller).call().await?;
    assert_eq!(lp_balance, U256::ZERO);

    let pool = fee_amm.pools(pool_id).call().await?;
    assert_eq!(pool.reserveUserToken, 0);
    assert_eq!(pool.reserveValidatorToken, 0);
    assert_eq!(pool.pendingFeeSwapIn, 0);

    // Mint liquidity
    let mint_receipt = fee_amm
        .mint(
            pool_key.user_token,
            pool_key.validator_token,
            amount,
            amount,
            caller,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(mint_receipt.status());

    // Assert state changes
    let total_supply = fee_amm.totalSupply(pool_id).call().await?;
    let lp_balance = fee_amm.liquidityBalances(pool_id, caller).call().await?;

    let expected_liquidity = sqrt(amount * amount) - MIN_LIQUIDITY;
    assert_eq!(lp_balance, expected_liquidity);
    let expected_total_supply = expected_liquidity + MIN_LIQUIDITY;
    assert_eq!(total_supply, expected_total_supply);

    let pool = fee_amm.pools(pool_id).call().await?;
    assert_eq!(pool.reserveUserToken, amount.to::<u128>());
    assert_eq!(pool.reserveValidatorToken, amount.to::<u128>());

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

#[tokio::test(flavor = "multi_thread")]
async fn test_burn_liquidity() -> eyre::Result<()> {
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

    // Setup test token and fee AMM
    let token_0 = setup_test_token(provider.clone(), caller).await?;
    let token_1 = setup_test_token(provider.clone(), caller).await?;
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Mint, approve and create pool
    let mut pending = vec![];
    pending.push(token_0.mint(caller, amount).send().await?);
    pending.push(token_1.mint(caller, amount).send().await?);
    pending.push(
        token_0
            .approve(TIP_FEE_MANAGER_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    pending.push(
        token_1
            .approve(TIP_FEE_MANAGER_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    pending.push(
        fee_amm
            .createPool(*token_0.address(), *token_1.address())
            .send()
            .await?,
    );

    for tx in pending {
        let receipt = tx.get_receipt().await?;
        assert!(receipt.status());
    }

    let pool_key = PoolKey::new(*token_0.address(), *token_1.address());
    let pool_id = pool_key.get_id();

    // Mint liquidity first
    let mint_receipt = fee_amm
        .mint(
            pool_key.user_token,
            pool_key.validator_token,
            amount,
            amount,
            caller,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(mint_receipt.status());

    // Get state before burn
    let total_supply_before_burn = fee_amm.totalSupply(pool_id).call().await?;
    let lp_balance_before_burn = fee_amm.liquidityBalances(pool_id, caller).call().await?;
    let pool_before_burn = fee_amm.pools(pool_id).call().await?;
    let user_token0_balance_before_burn = token_0.balanceOf(caller).call().await?;
    let user_token1_balance_before_burn = token_1.balanceOf(caller).call().await?;
    let fee_manager_token0_balance_before_burn =
        token_0.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    let fee_manager_token1_balance_before_burn =
        token_1.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;

    // Burn half of the liquidity
    let burn_amount = lp_balance_before_burn / U256::from(2);
    let burn_receipt = fee_amm
        .burn(
            pool_key.user_token,
            pool_key.validator_token,
            burn_amount,
            caller,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(burn_receipt.status());

    // Calculate expected amounts returned
    let expected_amount0 =
        (burn_amount * U256::from(pool_before_burn.reserveUserToken)) / total_supply_before_burn;
    let expected_amount1 = (burn_amount * U256::from(pool_before_burn.reserveValidatorToken))
        / total_supply_before_burn;

    // Assert state changes
    let total_supply_after_burn = fee_amm.totalSupply(pool_id).call().await?;
    assert_eq!(
        total_supply_after_burn,
        total_supply_before_burn - burn_amount
    );

    let lp_balance_after_burn = fee_amm.liquidityBalances(pool_id, caller).call().await?;
    assert_eq!(lp_balance_after_burn, lp_balance_before_burn - burn_amount);

    let pool_after_burn = fee_amm.pools(pool_id).call().await?;
    assert_eq!(
        pool_after_burn.reserveUserToken,
        pool_before_burn.reserveUserToken - expected_amount0.to::<u128>()
    );
    assert_eq!(
        pool_after_burn.reserveValidatorToken,
        pool_before_burn.reserveValidatorToken - expected_amount1.to::<u128>()
    );

    let user_token0_balance_after_burn = token_0.balanceOf(caller).call().await?;
    assert_eq!(
        user_token0_balance_after_burn,
        user_token0_balance_before_burn + expected_amount0
    );

    let user_token1_balance_after_burn = token_1.balanceOf(caller).call().await?;
    assert_eq!(
        user_token1_balance_after_burn,
        user_token1_balance_before_burn + expected_amount1
    );

    let fee_manager_token0_balance_after_burn =
        token_0.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(
        fee_manager_token0_balance_after_burn,
        fee_manager_token0_balance_before_burn - expected_amount0
    );

    let fee_manager_token1_balance_after_burn =
        token_1.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(
        fee_manager_token1_balance_after_burn,
        fee_manager_token1_balance_before_burn - expected_amount1
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_transact_different_fee_tokens() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = setup_test_node(source).await?;

    // Setup user and validator wallets
    let user_wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .index(1)?
        .build()?;
    let user_address = user_wallet.address();
    let user_provider = ProviderBuilder::new()
        .wallet(user_wallet)
        .connect_http(http_url.clone());

    let validator_wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .index(2)?
        .build()?;
    let validator_address = validator_wallet.address();
    let validator_provider = ProviderBuilder::new()
        .wallet(validator_wallet)
        .connect_http(http_url.clone());

    // Create different tokens for user and validator
    let user_token = setup_test_token(user_provider.clone(), user_address).await?;
    let validator_token = setup_test_token(validator_provider.clone(), validator_address).await?;

    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, user_provider.clone());

    // Mint initial balances
    let mint_amount = U256::from(u128::MAX);
    let mut pending = vec![];
    pending.push(user_token.mint(user_address, mint_amount).send().await?);
    pending.push(
        validator_token
            .mint(validator_address, mint_amount)
            .send()
            .await?,
    );
    for tx in pending {
        let receipt = tx.get_receipt().await?;
        assert!(receipt.status());
    }
    // Set different tokens for user and validator
    let set_user_token_receipt = fee_manager
        .setUserToken(*user_token.address())
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(set_user_token_receipt.status());
    let token = fee_manager.userTokens(user_address).call().await?;
    assert_eq!(token, *user_token.address());

    // Create fee manager with validator provider and set token
    let set_validator_token_receipt =
        IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, validator_provider.clone())
            .setValidatorToken(*validator_token.address())
            .send()
            .await?
            .get_receipt()
            .await?;
    assert!(set_validator_token_receipt.status());
    let token = fee_manager
        .validatorTokens(validator_address)
        .call()
        .await?;
    assert_eq!(token, *validator_token.address());

    // Create new pool for fee tokens
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, user_provider.clone());
    let create_pool_receipt = fee_amm
        .createPool(*user_token.address(), *validator_token.address())
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(create_pool_receipt.status());

    // Verify pool was created
    let pool_key = PoolKey::new(*user_token.address(), *validator_token.address());
    let pool_id = pool_key.get_id();
    assert!(fee_amm.poolExists(pool_id).call().await?);

    // // Approve tokens for the fee manager
    // let liquidity_amount = U256::from(10u128.pow(20)); // 100 tokens
    // let mut approvals = vec![];
    //
    // // User approves user tokens
    // approvals.push(
    //     user_token
    //         .approve(TIP_FEE_MANAGER_ADDRESS, U256::MAX)
    //         .send()
    //         .await?,
    // );
    // // Validator approves validator tokens
    // approvals.push(
    //     validator_token
    //         .approve(TIP_FEE_MANAGER_ADDRESS, U256::MAX)
    //         .send()
    //         .await?,
    // );
    //
    // for tx in approvals {
    //     let receipt = tx.get_receipt().await?;
    //     assert!(receipt.status());
    // }
    //
    // // Add liquidity to the pool (user provides both tokens for simplicity)
    // let mint_receipt = user_amm
    //     .mint(
    //         *user_token.address(),
    //         *validator_token.address(),
    //         liquidity_amount,
    //         liquidity_amount,
    //         user_address,
    //     )
    //     .send()
    //     .await?
    //     .get_receipt()
    //     .await?;
    // assert!(mint_receipt.status());
    //
    // // Verify liquidity was added
    // let pool = user_amm.pools(pool_id).call().await?;
    // assert_eq!(pool.reserveUserToken, liquidity_amount.to::<u128>());
    // assert_eq!(pool.reserveValidatorToken, liquidity_amount.to::<u128>());
    //
    // let total_supply = user_amm.totalSupply(pool_id).call().await?;
    // let expected_liquidity = sqrt(liquidity_amount * liquidity_amount) - MIN_LIQUIDITY;
    // assert_eq!(total_supply, expected_liquidity + MIN_LIQUIDITY);
    //
    // let lp_balance = user_amm
    //     .liquidityBalances(pool_id, user_address)
    //     .call()
    //     .await?;
    // assert_eq!(lp_balance, expected_liquidity);
    //
    // // Test fee token balance retrieval for user
    // let user_balance_result = user_fee_manager
    //     .getFeeTokenBalance(user_address, validator_address)
    //     .call()
    //     .await?;
    // assert_eq!(user_balance_result._0, *user_token.address());
    // assert!(user_balance_result._1 > U256::ZERO);
    //
    // // Test fee token balance retrieval for validator (should use validator token)
    // let validator_balance_result = validator_fee_manager
    //     .getFeeTokenBalance(validator_address, validator_address)
    //     .call()
    //     .await?;
    // assert_eq!(validator_balance_result._0, *validator_token.address());
    // assert!(validator_balance_result._1 > U256::ZERO);
    //
    // // Test payment functionality by performing a fee swap
    // let swap_amount = U256::from(10u128.pow(18)); // 1 token
    //
    // // First transfer some user tokens to validator for the swap
    // let transfer_receipt = user_token
    //     .transfer(validator_address, swap_amount * U256::from(2))
    //     .send()
    //     .await?
    //     .get_receipt()
    //     .await?;
    // assert!(transfer_receipt.status());
    //
    // // Validator approves tokens for swap
    // let validator_user_token = ITIP20::new(*user_token.address(), validator_provider.clone());
    // let approve_receipt = validator_user_token
    //     .approve(TIP_FEE_MANAGER_ADDRESS, U256::MAX)
    //     .send()
    //     .await?
    //     .get_receipt()
    //     .await?;
    // assert!(approve_receipt.status());
    //
    // // Perform a fee swap from user token to validator token
    // let fee_swap_receipt = validator_amm
    //     .feeSwap(
    //         *user_token.address(),
    //         *validator_token.address(),
    //         swap_amount,
    //         validator_address,
    //     )
    //     .send()
    //     .await?
    //     .get_receipt()
    //     .await?;
    // assert!(fee_swap_receipt.status());
    //
    // // Verify pool reserves changed after swap
    // let pool_after_swap = user_amm.pools(pool_id).call().await?;
    // assert!(pool_after_swap.reserveUserToken > pool.reserveUserToken);
    // assert!(pool_after_swap.reserveValidatorToken < pool.reserveValidatorToken);
    //
    // // Test rebalance swap in the opposite direction
    // let rebalance_amount = U256::from(5 * 10u128.pow(17)); // 0.5 tokens
    //
    // let rebalance_receipt = validator_amm
    //     .rebalanceSwap(
    //         *validator_token.address(),
    //         *user_token.address(),
    //         rebalance_amount,
    //         validator_address,
    //     )
    //     .send()
    //     .await?
    //     .get_receipt()
    //     .await?;
    // assert!(rebalance_receipt.status());
    //
    // // Verify pool is more balanced after rebalance
    // let pool_after_rebalance = user_amm.pools(pool_id).call().await?;
    // let reserve_diff_before = pool_after_swap
    //     .reserveUserToken
    //     .abs_diff(pool_after_swap.reserveValidatorToken);
    // let reserve_diff_after = pool_after_rebalance
    //     .reserveUserToken
    //     .abs_diff(pool_after_rebalance.reserveValidatorToken);
    // assert!(
    //     reserve_diff_after < reserve_diff_before,
    //     "Pool should be more balanced after rebalance"
    // );
    //
    Ok(())
}
