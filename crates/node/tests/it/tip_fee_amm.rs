use crate::{
    tempo_transaction::helpers::{
        create_basic_aa_tx, sign_aa_tx_with_secp256k1_access_key, sign_fee_payer,
    },
    utils::{ForkSchedule, TestNodeBuilder, setup_test_token},
};
use alloy::{
    network::ReceiptResponse,
    primitives::{B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::{SolCall, SolEvent},
};
use alloy_eips::{BlockId, Encodable2718};
use alloy_primitives::{Address, uint};
use reth_e2e_test_utils::{
    receipt::{PendingTransactionExt, await_successful_receipts},
    wallet::test_signer,
};
use tempo_alloy::TempoNetwork;
use tempo_chainspec::{hardfork::TempoHardfork, spec::TEMPO_T1_BASE_FEE};
use tempo_contracts::precompiles::{
    IAccountKeychain, IFeeManager, IRolesAuth,
    ITIP20::{self, ITIP20Instance},
    ITIP20Factory, ITIPFeeAMM,
};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, DEFAULT_FEE_TOKEN, PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    TIP20_FACTORY_ADDRESS,
    tip_fee_manager::amm::{MIN_LIQUIDITY, PoolKey, compute_amount_out},
    tip20::ISSUER_ROLE,
};
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{Call, KeyAuthorization, PrimitiveSignature, calc_gas_balance_spending},
};
use test_case::test_case;

async fn setup_test_token_with_quote<P>(
    provider: P,
    caller: Address,
    quote_token: Address,
) -> eyre::Result<ITIP20Instance<impl Clone + Provider>>
where
    P: Provider + Clone,
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let receipt = factory
        .createToken_0(
            "Test".to_string(),
            "TEST".to_string(),
            "USD".to_string(),
            quote_token,
            caller,
            B256::random(),
        )
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    let event = ITIP20Factory::TokenCreated::decode_log(&receipt.logs()[1].inner).unwrap();
    let token = ITIP20::new(event.token, provider.clone());

    IRolesAuth::new(*token.address(), provider)
        .grantRole(ISSUER_ROLE, caller)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    Ok(token)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mint_liquidity() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = test_signer(0);
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let amount = U256::from(rand_09::random::<u128>());

    // Setup test token and fee AMM
    let token_0 = setup_test_token(provider.clone(), caller).await?;
    let token_1 = setup_test_token(provider.clone(), caller).await?;
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Mint, approve and create pool
    let mut pending = vec![];
    pending.push(token_0.mint(caller, amount).send().await?);
    pending.push(token_1.mint(caller, amount).send().await?);
    await_successful_receipts(pending).await?;

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
    fee_amm
        .mint(
            pool_key.user_token,
            pool_key.validator_token,
            amount,
            caller,
        )
        .send()
        .await?
        .successful_receipt()
        .await?;

    // Assert state changes
    let total_supply = fee_amm.totalSupply(pool_id).call().await?;
    let lp_balance = fee_amm.liquidityBalances(pool_id, caller).call().await?;

    // With mint, liquidity = (amount / 2) - MIN_LIQUIDITY (for first mint)
    // Only validator tokens are transferred, creating a one-sided pool
    let half_amount = amount / U256::from(2);
    let expected_liquidity = half_amount - MIN_LIQUIDITY;
    assert_eq!(lp_balance, expected_liquidity);
    let expected_total_supply = half_amount;
    assert_eq!(total_supply, expected_total_supply);

    // Only validator reserve is updated (user reserve stays 0)
    let pool = fee_amm.pools(pool_id).call().await?;
    assert_eq!(pool.reserveUserToken, 0);
    assert_eq!(pool.reserveValidatorToken, amount.to::<u128>());

    // User token balance unchanged (not transferred)
    let final_token0_balance = token_0.balanceOf(caller).call().await?;
    assert_eq!(final_token0_balance, user_token0_balance);
    // Validator token balance decreased
    let final_token1_balance = token_1.balanceOf(caller).call().await?;
    assert_eq!(final_token1_balance, user_token1_balance - amount);

    // User token not transferred to fee manager
    let final_fee_manager_token0_balance =
        token_0.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(final_fee_manager_token0_balance, fee_manager_token0_balance);
    // Validator token transferred to fee manager
    let final_fee_manager_token1_balance =
        token_1.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(
        final_fee_manager_token1_balance,
        fee_manager_token1_balance + amount
    );

    Ok(())
}

/// Test burning liquidity from a FeeAMM pool.
#[tokio::test(flavor = "multi_thread")]
async fn test_burn_liquidity() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = test_signer(0);
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
    await_successful_receipts(pending).await?;

    let pool_key = PoolKey::new(*token_0.address(), *token_1.address());
    let pool_id = pool_key.get_id();

    // Mint liquidity using balanced `mint`
    fee_amm
        .mint(
            pool_key.user_token,
            pool_key.validator_token,
            amount,
            caller,
        )
        .send()
        .await?
        .successful_receipt()
        .await?;

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

    // TODO: fix
    fee_amm
        .burn(
            pool_key.user_token,
            pool_key.validator_token,
            burn_amount,
            caller,
        )
        .send()
        .await?
        .successful_receipt()
        .await?;

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

    // Setup tokens for fee payment
    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    // Setup user and validator wallets
    let user_wallet = test_signer(1);
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
    let validator_token = ITIP20Instance::new(PATH_USD_ADDRESS, provider.clone());
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Mint initial balances
    // Note that the user already has a preallocated balance of the predeployed fee token
    let mint_amount = U256::from(u128::MAX);
    let mut pending = vec![];
    pending.push(user_token.mint(user_address, mint_amount).send().await?);
    await_successful_receipts(pending.drain(..)).await?;

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
                user_address,
            )
            .send()
            .await?,
    );
    await_successful_receipts(pending.drain(..)).await?;

    // Verify liquidity was added
    let pool = fee_amm.pools(pool_id).call().await?;
    assert_eq!(pool.reserveUserToken, 0);
    assert_eq!(pool.reserveValidatorToken, liquidity.to::<u128>());

    // Check total supply and individual LP balances
    let total_supply = fee_amm.totalSupply(pool_id).call().await?;
    let expected_initial_liquidity = liquidity / U256::from(2) - MIN_LIQUIDITY;
    assert_eq!(total_supply, expected_initial_liquidity + MIN_LIQUIDITY);

    let user_lp_balance = fee_amm
        .liquidityBalances(pool_id, user_address)
        .call()
        .await?;
    assert_eq!(user_lp_balance, expected_initial_liquidity);

    // Cache pool balances before setting tokens (to avoid any fee swaps affecting the baseline)
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let pool_before = fee_amm
        .getPool(*user_token.address(), *validator_token.address())
        .call()
        .await?;

    // Set different tokens for user and validator, validator is already set to predeployed fee
    // token
    pending.push(
        fee_manager
            .setUserToken(*user_token.address())
            .send()
            .await?,
    );
    await_successful_receipts(pending).await?;

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

    // Transfer using predeployed TIP20
    let transfer_token = ITIP20::new(DEFAULT_FEE_TOKEN, provider.clone());

    transfer_token
        .transfer(Address::random(), U256::ONE)
        .send()
        .await?
        .successful_receipt()
        .await?;

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

#[test_case(false ; "no_direct_pool")]
#[test_case(true ; "insufficient_direct_pool")]
#[tokio::test(flavor = "multi_thread")]
async fn test_transact_two_hop_fee_route(direct_pool_exists: bool) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let user_wallet = test_signer(1);
    let user_address = user_wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(user_wallet)
        .connect_http(http_url);

    let validator_address = provider
        .get_block(BlockId::latest())
        .await?
        .expect("Could not get block")
        .header
        .beneficiary;

    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let validator_token = ITIP20Instance::new(PATH_USD_ADDRESS, provider.clone());

    let hop_token = setup_test_token(provider.clone(), user_address).await?;
    let user_token =
        setup_test_token_with_quote(provider.clone(), user_address, *hop_token.address()).await?;

    let liquidity = uint!(1_000_000_000_000_000_000_U256);
    let mut pending = vec![];
    pending.push(user_token.mint(user_address, liquidity).send().await?);
    pending.push(hop_token.mint(user_address, liquidity).send().await?);
    await_successful_receipts(pending).await?;

    fee_amm
        .mint(
            *user_token.address(),
            *hop_token.address(),
            liquidity,
            user_address,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    fee_amm
        .mint(
            *hop_token.address(),
            *validator_token.address(),
            liquidity,
            user_address,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    if direct_pool_exists {
        // Present but far below any real tx fee, forcing the T5 two-hop fallback.
        fee_amm
            .mint(
                *user_token.address(),
                *validator_token.address(),
                U256::from(3_000),
                user_address,
            )
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    fee_manager
        .setUserToken(*user_token.address())
        .send()
        .await?
        .get_receipt()
        .await?;

    let direct_before = fee_amm
        .getPool(*user_token.address(), *validator_token.address())
        .call()
        .await?;
    let first_hop_before = fee_amm
        .getPool(*user_token.address(), *hop_token.address())
        .call()
        .await?;
    let second_hop_before = fee_amm
        .getPool(*hop_token.address(), *validator_token.address())
        .call()
        .await?;
    let collected_before = fee_manager
        .collectedFees(validator_address, *validator_token.address())
        .call()
        .await?;

    let transfer_token = ITIP20::new(DEFAULT_FEE_TOKEN, provider.clone());
    let receipt = transfer_token
        .transfer(Address::random(), U256::ONE)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .successful_receipt()
        .await?;

    let actual_spending = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price);
    let out1 = compute_amount_out(actual_spending)?;
    let out2 = compute_amount_out(out1)?;

    let collected_after = fee_manager
        .collectedFees(validator_address, *validator_token.address())
        .call()
        .await?;
    assert_eq!(collected_after - collected_before, out2);

    let direct_after = fee_amm
        .getPool(*user_token.address(), *validator_token.address())
        .call()
        .await?;
    assert_eq!(
        direct_after.reserveUserToken,
        direct_before.reserveUserToken
    );
    assert_eq!(
        direct_after.reserveValidatorToken,
        direct_before.reserveValidatorToken
    );

    let first_hop_after = fee_amm
        .getPool(*user_token.address(), *hop_token.address())
        .call()
        .await?;
    assert_eq!(
        first_hop_after.reserveUserToken,
        first_hop_before.reserveUserToken + actual_spending.to::<u128>()
    );
    assert_eq!(
        first_hop_after.reserveValidatorToken,
        first_hop_before.reserveValidatorToken - out1.to::<u128>()
    );

    let second_hop_after = fee_amm
        .getPool(*hop_token.address(), *validator_token.address())
        .call()
        .await?;
    assert_eq!(
        second_hop_after.reserveUserToken,
        second_hop_before.reserveUserToken + out1.to::<u128>()
    );
    assert_eq!(
        second_hop_after.reserveValidatorToken,
        second_hop_before.reserveValidatorToken - out2.to::<u128>()
    );

    Ok(())
}

/// Test the first liquidity provider creating a new pool.
#[tokio::test(flavor = "multi_thread")]
async fn test_first_liquidity_provider() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .with_genesis(include_str!("../assets/test-genesis.json").to_string())
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = test_signer(0);
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
    await_successful_receipts(pending).await?;

    // Get pool info
    let pool_key = PoolKey::new(*user_token.address(), *validator_token.address());
    let pool_id = pool_key.get_id();

    // Verify pool doesn't exist yet
    let pool = fee_amm.pools(pool_id).call().await?;
    assert_eq!(pool.reserveUserToken, 0);
    assert_eq!(pool.reserveValidatorToken, 0);

    // Mint single-sided liquidity (with validator tokens)
    fee_amm
        .mint(
            pool_key.user_token,
            pool_key.validator_token,
            amount0,
            alice,
        )
        .send()
        .await?
        .successful_receipt()
        .await?;

    // Single-sided mint with validator token: liquidity = (amountValidatorToken / 2) - MIN_LIQUIDITY
    let half_amount = amount0 / U256::from(2);
    let expected_liquidity = half_amount - MIN_LIQUIDITY;

    // Check liquidity minted
    let lp_balance = fee_amm.liquidityBalances(pool_id, alice).call().await?;
    assert_eq!(lp_balance, expected_liquidity);

    // Check total supply
    let total_supply = fee_amm.totalSupply(pool_id).call().await?;
    assert_eq!(total_supply, expected_liquidity + MIN_LIQUIDITY);

    // Check reserves updated - only validator token is added (single-sided mint)
    let pool = fee_amm.pools(pool_id).call().await?;
    assert_eq!(pool.reserveUserToken, 0);
    assert_eq!(pool.reserveValidatorToken, amount0.to::<u128>());

    // Verify only validator tokens were transferred to fee manager (single-sided)
    let fee_manager_balance0 = user_token.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(fee_manager_balance0, U256::ZERO);

    let fee_manager_balance1 = validator_token
        .balanceOf(TIP_FEE_MANAGER_ADDRESS)
        .call()
        .await?;
    assert_eq!(fee_manager_balance1, amount0);

    Ok(())
}

/// Test partial burn of liquidity from a FeeAMM pool.
#[tokio::test(flavor = "multi_thread")]
async fn test_burn_liquidity_partial() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = test_signer(0);
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
    await_successful_receipts(pending).await?;

    // Get pool info
    let pool_key = PoolKey::new(*user_token.address(), *validator_token.address());
    let pool_id = pool_key.get_id();

    // Add liquidity using balanced `mint`
    fee_amm
        .mint(
            pool_key.user_token,
            pool_key.validator_token,
            amount0,
            alice,
        )
        .send()
        .await?
        .successful_receipt()
        .await?;

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
    fee_amm
        .burn(
            pool_key.user_token,
            pool_key.validator_token,
            burn_amount,
            alice,
        )
        .send()
        .await?
        .successful_receipt()
        .await?;

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

#[tokio::test(flavor = "multi_thread")]
async fn test_cant_burn_required_liquidity() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = test_signer(0);
    let alice = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Setup test tokens and fee AMM
    let user_token = setup_test_token(provider.clone(), alice).await?;
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Define amounts (100000 * 1e18)
    let amount0 = uint!(100000_000000000000000000_U256);

    // Mint tokens to alice
    let mut pending = vec![];
    pending.push(user_token.mint(alice, amount0).send().await?);
    await_successful_receipts(pending).await?;

    // Get pool info
    let pool_key = PoolKey::new(*user_token.address(), PATH_USD_ADDRESS);
    let pool_id = pool_key.get_id();

    // Add liquidity
    fee_amm
        .mint(
            pool_key.user_token,
            pool_key.validator_token,
            uint!(100000000_U256),
            alice,
        )
        .send()
        .await?
        .successful_receipt()
        .await?;

    // Get liquidity balance
    let liquidity = fee_amm.liquidityBalances(pool_id, alice).call().await?;

    IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone())
        .setUserToken(*user_token.address())
        .send()
        .await?
        .get_receipt()
        .await?
        .status();

    // Burn entire liquidity
    let burn_receipt = fee_amm
        .burn(
            pool_key.user_token,
            pool_key.validator_token,
            liquidity,
            alice,
        )
        .max_fee_per_gas(TEMPO_T1_BASE_FEE as u128 * 100)
        .max_priority_fee_per_gas(TEMPO_T1_BASE_FEE as u128 * 99)
        .gas(1000000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(!burn_receipt.status());

    Ok(())
}

/// A sponsored access key must not redirect its root's custodied LP assets with zero limits.
#[test_case(false; "zero_limits")]
#[test_case(true; "second_token_limit_rollback")]
#[tokio::test(flavor = "multi_thread")]
async fn test_sponsored_access_key_cannot_redirect_fee_amm_burn(
    first_token_allowed: bool,
) -> eyre::Result<()> {
    let setup = TestNodeBuilder::new()
        .with_schedule(ForkSchedule::DevnetAt(TempoHardfork::T14))
        .build_http_only()
        .await?;
    let root = test_signer(0);
    let account = root.address();
    let sponsor = test_signer(1);
    let key = PrivateKeySigner::random();
    let attacker = Address::random();
    let tempo_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(setup.http_url.clone());
    let provider = ProviderBuilder::new()
        .wallet(root.clone())
        .connect_http(setup.http_url);
    let amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, &provider);
    let token = setup_test_token(provider.clone(), account).await?;
    let user_token = *token.address();
    let amount = U256::from(1_000_000_000_000_000_000u128);
    token
        .mint(account, amount)
        .send()
        .await?
        .successful_receipt()
        .await?;
    amm.mint(user_token, PATH_USD_ADDRESS, amount, account)
        .send()
        .await?
        .successful_receipt()
        .await?;
    let pool = PoolKey::new(user_token, PATH_USD_ADDRESS).get_id();
    let liquidity = amm.liquidityBalances(pool, account).call().await?;
    assert!(liquidity > U256::ZERO);
    let chain_id = provider.get_chain_id().await?;
    // Paying one transaction in the user token seeds both sides of this pool.
    let mut seed_tx = create_basic_aa_tx(
        chain_id,
        provider.get_transaction_count(account).await?,
        vec![Call {
            to: user_token.into(),
            value: U256::ZERO,
            input: ITIP20::balanceOfCall { account }.abi_encode().into(),
        }],
        5_000_000,
    );
    seed_tx.fee_token = Some(user_token);
    let signature = root.sign_hash_sync(&seed_tx.signature_hash())?;
    let envelope: TempoTxEnvelope = seed_tx.into_signed(signature.into()).into();
    assert!(
        tempo_provider
            .send_raw_transaction(&envelope.encoded_2718())
            .await?
            .get_receipt()
            .await?
            .status()
    );
    let pool_before = amm.pools(pool).call().await?;
    assert!(
        liquidity * U256::from(pool_before.reserveUserToken) / amm.totalSupply(pool).call().await?
            > U256::ZERO
    );
    let authorization = KeyAuthorization::unrestricted(
        chain_id,
        tempo_primitives::SignatureType::Secp256k1,
        key.address(),
    );
    let authorization = if first_token_allowed {
        authorization.with_limits(vec![tempo_primitives::transaction::TokenLimit {
            token: user_token,
            limit: amount,
            period: 0,
        }])
    } else {
        authorization.with_no_spending()
    };
    let signature = root.sign_hash_sync(&authorization.signature_hash())?;
    let mut auth_tx = create_basic_aa_tx(
        chain_id,
        provider.get_transaction_count(account).await?,
        vec![Call {
            to: user_token.into(),
            value: U256::ZERO,
            input: ITIP20::balanceOfCall { account }.abi_encode().into(),
        }],
        5_000_000,
    );
    auth_tx.key_authorization =
        Some(authorization.into_signed(PrimitiveSignature::Secp256k1(signature)));
    let signature = root.sign_hash_sync(&auth_tx.signature_hash())?;
    let envelope: TempoTxEnvelope = auth_tx.into_signed(signature.into()).into();
    assert!(
        tempo_provider
            .send_raw_transaction(&envelope.encoded_2718())
            .await?
            .get_receipt()
            .await?
            .status()
    );
    let mut burn_tx = create_basic_aa_tx(
        chain_id,
        provider.get_transaction_count(account).await?,
        vec![Call {
            to: TIP_FEE_MANAGER_ADDRESS.into(),
            value: U256::ZERO,
            input: ITIPFeeAMM::burnCall {
                userToken: user_token,
                validatorToken: PATH_USD_ADDRESS,
                liquidity,
                to: attacker,
            }
            .abi_encode()
            .into(),
        }],
        5_000_000,
    );
    sign_fee_payer(&mut burn_tx, account, &sponsor)?;
    let signature = sign_aa_tx_with_secp256k1_access_key(&burn_tx, &key, account)?;
    let envelope: TempoTxEnvelope = burn_tx.into_signed(signature).into();
    let receipt = tempo_provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .get_receipt()
        .await?;
    assert!(!receipt.status());
    assert_eq!(
        amm.liquidityBalances(pool, account).call().await?,
        liquidity
    );
    let pool_after = amm.pools(pool).call().await?;
    assert_eq!(pool_after.reserveUserToken, pool_before.reserveUserToken);
    assert_eq!(
        pool_after.reserveValidatorToken,
        pool_before.reserveValidatorToken
    );
    assert_eq!(
        IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, &provider)
            .getRemainingLimitWithPeriod(account, key.address(), user_token)
            .call()
            .await?
            .remaining,
        if first_token_allowed {
            amount
        } else {
            U256::ZERO
        }
    );
    assert_eq!(token.balanceOf(attacker).call().await?, U256::ZERO);
    assert_eq!(
        ITIP20::new(PATH_USD_ADDRESS, &provider)
            .balanceOf(attacker)
            .call()
            .await?,
        U256::ZERO
    );
    assert_eq!(
        IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, &provider)
            .getRemainingLimitWithPeriod(account, key.address(), PATH_USD_ADDRESS)
            .call()
            .await?
            .remaining,
        U256::ZERO
    );
    Ok(())
}
