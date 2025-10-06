use crate::utils::{await_receipts, setup_test_node, setup_test_token};
use alloy::{
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use alloy_eips::BlockId;
use alloy_primitives::{Address, uint};
use std::env;
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, TIP_FEE_MANAGER_ADDRESS,
    contracts::{
        ITIP20::ITIP20Instance,
        tip_fee_manager::amm::{MIN_LIQUIDITY, PoolKey},
        types::{
            IFeeManager, ITIP20,
            ITIPFeeAMM::{self},
        },
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn test_mint_liquidity() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
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
    await_receipts(&mut pending).await?;

    // Assert initial state
    let pool_key = PoolKey::new(*token_0.address(), *token_1.address());
    let pool_id = pool_key.get_id();
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

    let expected_liquidity = (amount * amount) / uint!(2_U256) - MIN_LIQUIDITY;
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

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let amount = U256::from(u64::MAX);

    // Setup test token and fee AMM
    let token_0 = setup_test_token(provider.clone(), caller).await?;
    let token_1 = setup_test_token(provider.clone(), caller).await?;
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Mint tokens to caller
    let mut pending = vec![];
    pending.push(token_0.mint(caller, amount).send().await?);
    pending.push(token_1.mint(caller, amount).send().await?);
    await_receipts(&mut pending).await?;

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
    let user_wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let user_address = user_wallet.address();

    let provider = ProviderBuilder::new()
        .wallet(user_wallet)
        .connect_http(http_url.clone());

    let block = provider
        .get_block(BlockId::latest())
        .await?
        .expect("Could not get block");
    let validator_address = block.header.beneficiary;
    assert!(!validator_address.is_zero());

    // Create different tokens for user and validator
    let user_token = setup_test_token(provider.clone(), user_address).await?;
    // Use default fee token for validator
    let validator_token = ITIP20Instance::new(DEFAULT_FEE_TOKEN, provider.clone());
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Mint initial balances
    // Note that the user already has a preallocated balance of the predeployed fee token
    let mint_amount = U256::from(u128::MAX);
    let mut pending = vec![];
    pending.push(user_token.mint(user_address, mint_amount).send().await?);
    await_receipts(&mut pending).await?;

    // Create new pool for fee tokens
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let pool_key = PoolKey::new(*user_token.address(), *validator_token.address());
    let pool_id = pool_key.get_id();

    // User provides both tokens for liquidity, with minimum balance
    let liquidity = U256::from(u16::MAX) + uint!(1_000_000_000_U256);
    pending.push(
        fee_amm
            .mint(
                *user_token.address(),
                *validator_token.address(),
                liquidity,
                liquidity,
                user_address,
            )
            .send()
            .await?,
    );
    await_receipts(&mut pending).await?;

    // Verify liquidity was added
    let pool = fee_amm.pools(pool_id).call().await?;
    assert_eq!(pool.reserveUserToken, liquidity.to::<u128>());
    assert_eq!(pool.reserveValidatorToken, liquidity.to::<u128>());

    // Check total supply and individual LP balances
    let total_supply = fee_amm.totalSupply(pool_id).call().await?;
    let expected_initial_liquidity = (liquidity * liquidity) / U256::from(2) - MIN_LIQUIDITY;
    assert_eq!(total_supply, expected_initial_liquidity + MIN_LIQUIDITY);

    let user_lp_balance = fee_amm
        .liquidityBalances(pool_id, user_address)
        .call()
        .await?;
    assert_eq!(user_lp_balance, expected_initial_liquidity);

    // Set different tokens for user and validator, validator is already set to predeployed fee
    // token
    pending.push(
        fee_manager
            .setUserToken(*user_token.address())
            .send()
            .await?,
    );
    await_receipts(&mut pending).await?;

    // Verify tokens are set correctly
    let user_fee_token = fee_manager.userTokens(user_address).call().await?;
    let val_fee_token = fee_manager
        .validatorTokens(validator_address)
        .call()
        .await?;
    assert_ne!(user_fee_token, val_fee_token);

    // Get initial validator token balance
    let _initial_validator_balance = validator_token.balanceOf(validator_address).call().await?;
    let initial_user_balance = user_token.balanceOf(user_address).call().await?;

    // Cache pool balances before
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let pool_before = fee_amm
        .getPool(user_fee_token, val_fee_token)
        .call()
        .await?;

    // Transfer using predeployed TIP20
    let transfer_token = ITIP20::new(DEFAULT_FEE_TOKEN, provider.clone());

    let transfer_receipt = transfer_token
        .transfer(Address::random(), U256::ZERO)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(transfer_receipt.status());

    // Assert that gas token in was swapped to the validator token
    let user_balance = user_token.balanceOf(user_address).call().await?;
    assert!(user_balance < initial_user_balance);

    let _validator_balance = validator_token.balanceOf(validator_address).call().await?;
    // TODO: uncomment when we can set suggested fee recipient in debug config to non zero value
    // NOTE: currently, we set the suggested_fee_recipient as address(0) when running the node
    // in debug mode. Related, TIP20 transfers do not update the `to` address balance if it is
    // address(0). Due to this, the validator balance does not currently increment in this test
    // assert!(validator_balance > initial_validator_balance);

    let pool_after = fee_amm
        .getPool(user_fee_token, val_fee_token)
        .call()
        .await?;
    assert!(pool_before.reserveUserToken < pool_after.reserveUserToken);
    assert!(pool_before.reserveValidatorToken > pool_after.reserveValidatorToken);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_first_liquidity_provider() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let alice = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Setup test tokens and fee AMM
    let user_token = setup_test_token(provider.clone(), alice).await?;
    let validator_token = setup_test_token(provider.clone(), alice).await?;
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Define amounts (100000 * 1e18)
    let amount0 = uint!(100000_000000000000000000_U256);
    let amount1 = uint!(100000_000000000000000000_U256);

    // Mint tokens to alice
    let mut pending = vec![];
    pending.push(user_token.mint(alice, amount0).send().await?);
    pending.push(validator_token.mint(alice, amount1).send().await?);
    await_receipts(&mut pending).await?;

    // Get pool info
    let pool_key = PoolKey::new(*user_token.address(), *validator_token.address());
    let pool_id = pool_key.get_id();

    // Verify pool doesn't exist yet
    let pool = fee_amm.pools(pool_id).call().await?;
    assert_eq!(pool.reserveUserToken, 0);
    assert_eq!(pool.reserveValidatorToken, 0);

    // Add liquidity which creates the pool
    let mint_receipt = fee_amm
        .mint(
            pool_key.user_token,
            pool_key.validator_token,
            amount0,
            amount1,
            alice,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(mint_receipt.status());

    // Calculate expected liquidity: (amount0 * amount1) / 2 - MIN_LIQUIDITY
    let expected_liquidity = (amount0 * amount1) / uint!(2_U256) - MIN_LIQUIDITY;

    // Check liquidity minted
    let lp_balance = fee_amm.liquidityBalances(pool_id, alice).call().await?;
    assert_eq!(lp_balance, expected_liquidity);

    // Check total supply
    let total_supply = fee_amm.totalSupply(pool_id).call().await?;
    assert_eq!(total_supply, expected_liquidity + MIN_LIQUIDITY);

    // Check reserves updated
    let pool = fee_amm.pools(pool_id).call().await?;
    assert_eq!(pool.reserveUserToken, amount0.to::<u128>());
    assert_eq!(pool.reserveValidatorToken, amount1.to::<u128>());

    // Verify tokens were transferred to fee manager
    let fee_manager_balance0 = user_token.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(fee_manager_balance0, amount0);

    let fee_manager_balance1 = validator_token
        .balanceOf(TIP_FEE_MANAGER_ADDRESS)
        .call()
        .await?;
    assert_eq!(fee_manager_balance1, amount1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_burn_liquidity_partial() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let alice = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Setup test tokens and fee AMM
    let user_token = setup_test_token(provider.clone(), alice).await?;
    let validator_token = setup_test_token(provider.clone(), alice).await?;
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Define amounts (100000 * 1e18)
    let amount0 = uint!(100000_000000000000000000_U256);
    let amount1 = uint!(100000_000000000000000000_U256);

    // Mint tokens to alice
    let mut pending = vec![];
    pending.push(user_token.mint(alice, amount0).send().await?);
    pending.push(validator_token.mint(alice, amount1).send().await?);
    await_receipts(&mut pending).await?;

    // Get pool info
    let pool_key = PoolKey::new(*user_token.address(), *validator_token.address());
    let pool_id = pool_key.get_id();

    // Add liquidity
    let mint_receipt = fee_amm
        .mint(
            pool_key.user_token,
            pool_key.validator_token,
            amount0,
            amount1,
            alice,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(mint_receipt.status());

    // Get liquidity balance
    let liquidity = fee_amm.liquidityBalances(pool_id, alice).call().await?;

    // Record balances before burn
    let user_balance0_before = user_token.balanceOf(alice).call().await?;
    let user_balance1_before = validator_token.balanceOf(alice).call().await?;

    // Burn half of the liquidity
    let burn_amount = liquidity / U256::from(2);

    // Get pool state before burn
    let pool_before = fee_amm.pools(pool_id).call().await?;
    let total_supply_before = fee_amm.totalSupply(pool_id).call().await?;

    // Burn partial liquidity
    let burn_receipt = fee_amm
        .burn(
            pool_key.user_token,
            pool_key.validator_token,
            burn_amount,
            alice,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(burn_receipt.status());

    // Calculate expected amounts returned
    let expected_amount0 =
        (burn_amount * U256::from(pool_before.reserveUserToken)) / total_supply_before;
    let expected_amount1 =
        (burn_amount * U256::from(pool_before.reserveValidatorToken)) / total_supply_before;

    // Verify we got tokens back
    let user_balance0_after = user_token.balanceOf(alice).call().await?;
    let user_balance1_after = validator_token.balanceOf(alice).call().await?;

    assert_eq!(
        user_balance0_after,
        user_balance0_before + expected_amount0,
        "Should receive exact expected userToken amount"
    );
    assert_eq!(
        user_balance1_after,
        user_balance1_before + expected_amount1,
        "Should receive exact expected validatorToken amount"
    );

    // Verify LP balance reduced
    let lp_balance_after = fee_amm.liquidityBalances(pool_id, alice).call().await?;
    assert_eq!(lp_balance_after, liquidity - burn_amount);

    // Verify reserves updated correctly
    let pool_after = fee_amm.pools(pool_id).call().await?;
    assert_eq!(
        pool_after.reserveUserToken,
        pool_before.reserveUserToken - expected_amount0.to::<u128>()
    );
    assert_eq!(
        pool_after.reserveValidatorToken,
        pool_before.reserveValidatorToken - expected_amount1.to::<u128>()
    );

    Ok(())
}
