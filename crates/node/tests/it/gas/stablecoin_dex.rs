use std::collections::BTreeMap;

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    sol_types::SolEvent,
};
use reth_e2e_test_utils::wallet::test_signer;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    IRolesAuth, IStablecoinDEX,
    ITIP20::{self, ITIP20Instance},
    ITIP20Factory,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS, STABLECOIN_DEX_ADDRESS, TIP20_FACTORY_ADDRESS,
    error::TempoPrecompileError,
    stablecoin_dex::{MAX_TICK, MIN_ORDER_AMOUNT, MIN_TICK, RoundingDirection, base_to_quote},
    tip20::ISSUER_ROLE,
};
use test_case::test_case;

use crate::utils::{TestNodeBuilder, make_genesis_at};

#[derive(Debug, serde::Serialize)]
struct DexGasOutcome {
    gas: u64,
    status: bool,
}

fn under_overflow_revert() -> Bytes {
    TempoPrecompileError::under_overflow()
        .into_precompile_result(0, 0)
        .unwrap()
        .bytes
}

async fn approve<P: Provider + Clone>(
    provider: P,
    token: Address,
    spender: Address,
) -> eyre::Result<()> {
    let receipt = ITIP20::new(token, provider)
        .approve(spender, U256::MAX)
        .send_sync()
        .await?;
    assert!(receipt.status(), "approve failed");
    Ok(())
}

async fn setup_test_token<P>(
    provider: P,
    caller: Address,
    name: &str,
    symbol: &str,
    quote_token: Address,
    salt: u8,
) -> eyre::Result<ITIP20Instance<impl Clone + Provider>>
where
    P: Provider + Clone,
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let receipt = factory
        .createToken_0(
            name.to_string(),
            symbol.to_string(),
            "USD".to_string(),
            quote_token,
            caller,
            B256::with_last_byte(salt),
        )
        .gas(5_000_000)
        .send_sync()
        .await?;
    assert!(receipt.status(), "token creation failed");

    let event = receipt
        .logs()
        .iter()
        .find_map(|log| ITIP20Factory::TokenCreated::decode_log(&log.inner).ok())
        .ok_or_else(|| eyre::eyre!("TokenCreated event not found"))?;
    let token = ITIP20::new(event.token, provider.clone());

    let roles = IRolesAuth::new(*token.address(), provider);
    let receipt = roles
        .grantRole(ISSUER_ROLE, caller)
        .gas(1_000_000)
        .send_sync()
        .await?;
    assert!(receipt.status(), "grant issuer role failed");

    Ok(token)
}

#[test_case(TempoHardfork::T12 ; "t12_without_aggregate_liquidity")]
#[tokio::test(flavor = "multi_thread")]
async fn test_stablecoin_dex_revert_gas_snapshots(hardfork: TempoHardfork) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .with_genesis(make_genesis_at(hardfork))
        .with_instant_mining()
        .build_http_only()
        .await?;
    let signers = (0..=6).map(test_signer).collect::<Vec<_>>();
    let providers = signers
        .iter()
        .map(|signer| {
            ProviderBuilder::new()
                .wallet(signer.clone())
                .connect_http(setup.http_url.clone())
        })
        .collect::<Vec<_>>();
    let admin_provider = providers[0].clone();
    let admin = signers[0].address();
    let exchange =
        |index: usize| IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, providers[index].clone());
    let mut gas = BTreeMap::new();

    // A running-input overflow must occur after the second order is settled.
    let ask_base = setup_test_token(
        admin_provider.clone(),
        admin,
        "Overflow Ask",
        "OASK",
        PATH_USD_ADDRESS,
        0x63,
    )
    .await?;
    let first = u128::MAX / 2;
    let second = u128::MAX - first;
    for (index, amount) in [(1, first), (2, second)] {
        let receipt = ask_base
            .mint(signers[index].address(), U256::from(amount))
            .send_sync()
            .await?;
        assert!(receipt.status(), "overflow ask mint failed");
    }
    approve(
        providers[1].clone(),
        *ask_base.address(),
        STABLECOIN_DEX_ADDRESS,
    )
    .await?;
    approve(
        providers[2].clone(),
        *ask_base.address(),
        STABLECOIN_DEX_ADDRESS,
    )
    .await?;
    for (index, amount) in [(1, first), (2, second)] {
        let receipt = exchange(index)
            .place(*ask_base.address(), amount, false, MAX_TICK)
            .gas(5_000_000)
            .send_sync()
            .await?;
        assert!(receipt.status(), "overflow ask setup failed");
    }
    let err = exchange(3)
        .swapExactAmountOut(PATH_USD_ADDRESS, *ask_base.address(), u128::MAX, u128::MAX)
        .call()
        .await
        .expect_err("overflow swap call unexpectedly succeeded");
    assert_eq!(err.as_revert_data(), Some(under_overflow_revert()));

    let receipt = exchange(3)
        .swapExactAmountOut(PATH_USD_ADDRESS, *ask_base.address(), u128::MAX, u128::MAX)
        .gas(10_000_000)
        .send_sync()
        .await?;
    assert!(!receipt.status(), "overflow swap unexpectedly succeeded");
    gas.insert(
        "swap_exact_out_accumulation_overflow",
        DexGasOutcome {
            gas: receipt.gas_used,
            status: receipt.status(),
        },
    );

    // A placement aggregate overflow must occur after linking the previous tail.
    let bid_quote = setup_test_token(
        admin_provider.clone(),
        admin,
        "Overflow Quote",
        "OQUOTE",
        PATH_USD_ADDRESS,
        0x64,
    )
    .await?;
    let bid_base = setup_test_token(
        admin_provider,
        admin,
        "Overflow Bid",
        "OBID",
        *bid_quote.address(),
        0x65,
    )
    .await?;
    let escrow = [
        base_to_quote(first, MIN_TICK, RoundingDirection::Up).unwrap(),
        base_to_quote(second, MIN_TICK, RoundingDirection::Up).unwrap(),
        base_to_quote(MIN_ORDER_AMOUNT, MIN_TICK, RoundingDirection::Up).unwrap(),
    ];
    for (index, amount) in escrow.into_iter().enumerate() {
        let user = index + 4;
        let receipt = bid_quote
            .mint(signers[user].address(), U256::from(amount))
            .send_sync()
            .await?;
        assert!(receipt.status(), "overflow quote mint failed");
        approve(
            providers[user].clone(),
            *bid_quote.address(),
            STABLECOIN_DEX_ADDRESS,
        )
        .await?;
    }
    for (index, amount) in [(4, first), (5, second)] {
        let receipt = exchange(index)
            .place(*bid_base.address(), amount, true, MIN_TICK)
            .gas(5_000_000)
            .send_sync()
            .await?;
        assert!(receipt.status(), "overflow bid setup failed");
    }
    let receipt = exchange(6)
        .place(*bid_base.address(), MIN_ORDER_AMOUNT, true, MIN_TICK)
        .gas(5_000_000)
        .send_sync()
        .await?;
    gas.insert(
        "place_aggregate_overflow",
        DexGasOutcome {
            gas: receipt.gas_used,
            status: receipt.status(),
        },
    );

    let snapshot_name = format!(
        "stablecoin_dex_revert_gas_snapshot_{}",
        hardfork.name().to_lowercase()
    );
    insta::assert_yaml_snapshot!(snapshot_name, gas);
    Ok(())
}
