use std::collections::BTreeMap;

use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, PrivateKeySigner},
    sol_types::SolEvent,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    IRolesAuth, IStablecoinDEX, IStorageCredits,
    ITIP20::{self, ITIP20Instance},
    ITIP20Factory,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS, STABLECOIN_DEX_ADDRESS, STORAGE_CREDITS_ADDRESS, TIP20_FACTORY_ADDRESS,
    stablecoin_dex::MIN_ORDER_AMOUNT, tip20::ISSUER_ROLE,
};
use test_case::test_case;

use crate::utils::{TEST_MNEMONIC, TestNodeBuilder, await_receipts, make_genesis_at};

const USER_COUNT: usize = 14;

#[derive(Debug, serde::Serialize)]
struct DexGasRow {
    gas: u64,
    storage_credits: String,
    pooled_storage_credits: String,
}

fn signer(index: u32) -> eyre::Result<PrivateKeySigner> {
    Ok(MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(index)?
        .build()?)
}

async fn approve<P: Provider + Clone>(
    provider: P,
    token: Address,
    spender: Address,
) -> eyre::Result<()> {
    let receipt = ITIP20::new(token, provider)
        .approve(spender, U256::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "approve failed");
    Ok(())
}

async fn setup_deterministic_test_token<P>(
    provider: P,
    caller: Address,
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
            PATH_USD_ADDRESS,
            caller,
            B256::with_last_byte(0x62),
        )
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
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
        .grantRole(*ISSUER_ROLE, caller)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "grant issuer role failed");

    Ok(token)
}

#[test_case(TempoHardfork::T6 ; "t6_without_tip1060")]
#[test_case(TempoHardfork::T7 ; "t7_with_tip1060")]
#[tokio::test(flavor = "multi_thread")]
async fn test_stablecoin_dex_order_gas_snapshots(hardfork: TempoHardfork) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .with_genesis(make_genesis_at(hardfork))
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let signers = (0..=USER_COUNT as u32)
        .map(signer)
        .collect::<eyre::Result<Vec<_>>>()?;
    let providers = signers
        .iter()
        .map(|signer| {
            ProviderBuilder::new()
                .wallet(signer.clone())
                .connect_http(http_url.clone())
        })
        .collect::<Vec<_>>();

    let admin_provider = providers[0].clone();
    let admin = signers[0].address();

    let base = setup_deterministic_test_token(admin_provider.clone(), admin).await?;
    let quote = ITIP20Instance::new(PATH_USD_ADDRESS, admin_provider.clone());
    let base_addr = *base.address();
    let quote_addr = *quote.address();

    let mint_amount = U256::from(MIN_ORDER_AMOUNT * 1_000);
    let mut pending = vec![];
    for account in signers.iter().skip(1).map(|signer| signer.address()) {
        pending.push(base.mint(account, mint_amount).send().await?);
        pending.push(quote.mint(account, mint_amount).send().await?);
    }
    await_receipts(&mut pending).await?;

    for provider in providers.iter().skip(1) {
        approve(provider.clone(), base_addr, STABLECOIN_DEX_ADDRESS).await?;
        approve(provider.clone(), quote_addr, STABLECOIN_DEX_ADDRESS).await?;
    }

    let exchange =
        |index: usize| IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, providers[index].clone());
    let tip1060_credits =
        |index: usize| IStorageCredits::new(STORAGE_CREDITS_ADDRESS, providers[index].clone());
    let mut gas = BTreeMap::new();

    macro_rules! credits {
        ($index:expr) => {{
            if hardfork.is_t7() {
                exchange($index)
                    .storageCredits(signers[$index].address())
                    .call()
                    .await?
            } else {
                0
            }
        }};
    }

    macro_rules! pooled_credits {
        () => {{
            if hardfork.is_t7() {
                tip1060_credits(0)
                    .balanceOf(STABLECOIN_DEX_ADDRESS)
                    .call()
                    .await?
            } else {
                0
            }
        }};
    }

    macro_rules! record_tx {
        ($name:literal, $call:expr, $message:literal) => {{
            let pooled_before = pooled_credits!();
            let receipt = $call.send().await?.get_receipt().await?;
            assert!(receipt.status(), $message);
            let pooled_after = pooled_credits!();
            gas.insert(
                $name,
                DexGasRow {
                    gas: receipt.gas_used,
                    storage_credits: "n/a".to_string(),
                    pooled_storage_credits: format!(
                        "DEX TIP-1060: {pooled_before} -> {pooled_after}"
                    ),
                },
            );
            receipt
        }};
    }

    macro_rules! record_tx_with_credits {
        ($name:literal, $credit_user:expr, $call:expr, $message:literal) => {{
            let before = credits!($credit_user);
            let pooled_before = pooled_credits!();
            let receipt = $call.send().await?.get_receipt().await?;
            assert!(receipt.status(), $message);
            let after = credits!($credit_user);
            let pooled_after = pooled_credits!();
            gas.insert(
                $name,
                DexGasRow {
                    gas: receipt.gas_used,
                    storage_credits: format!("user{}: {before} -> {after}", $credit_user),
                    pooled_storage_credits: format!(
                        "DEX TIP-1060: {pooled_before} -> {pooled_after}"
                    ),
                },
            );
            receipt
        }};
    }

    macro_rules! record_tx_with_cross_user_credits {
        ($name:literal, $credit_user:expr, $owner:expr, $call:expr, $message:literal) => {{
            let before = credits!($credit_user);
            let owner_before = credits!($owner);
            let pooled_before = pooled_credits!();
            let receipt = $call.send().await?.get_receipt().await?;
            assert!(receipt.status(), $message);
            let after = credits!($credit_user);
            let owner_after = credits!($owner);
            let pooled_after = pooled_credits!();
            gas.insert(
                $name,
                DexGasRow {
                    gas: receipt.gas_used,
                    storage_credits: format!(
                        "user{}: {before} -> {after}; user{}: {owner_before} -> {owner_after}",
                        $credit_user, $owner
                    ),
                    pooled_storage_credits: format!(
                        "DEX TIP-1060: {pooled_before} -> {pooled_after}"
                    ),
                },
            );
            receipt
        }};
    }

    macro_rules! send_tx {
        ($call:expr, $message:literal) => {{
            let receipt = $call.send().await?.get_receipt().await?;
            assert!(receipt.status(), $message);
            receipt
        }};
    }

    let amount = MIN_ORDER_AMOUNT * 4;
    let fill = MIN_ORDER_AMOUNT;

    record_tx!(
        "create_pair",
        exchange(0).createPair(base_addr),
        "createPair failed"
    );

    let cancel_order = exchange(1).nextOrderId().call().await?;
    record_tx_with_credits!(
        "place_bid_wallet",
        1,
        exchange(1).place(base_addr, amount, true, 0),
        "place bid failed"
    );
    record_tx_with_credits!(
        "cancel_bid_earn_credits",
        1,
        exchange(1).cancel(cancel_order),
        "cancel bid failed"
    );
    record_tx_with_credits!(
        "place_bid_reuse_cancel_credits",
        1,
        exchange(1).place(base_addr, fill, true, -60),
        "place bid reusing cancel credits failed"
    );

    let cross_user_cancel_order = exchange(6).nextOrderId().call().await?;
    send_tx!(
        exchange(6).place(base_addr, fill, true, -10),
        "setup cross-user cancel credit bid failed"
    );
    send_tx!(
        exchange(6).cancel(cross_user_cancel_order),
        "setup cross-user cancel credits failed"
    );
    record_tx_with_cross_user_credits!(
        "place_bid_cross_user_after_cancel_credits",
        7,
        6,
        exchange(7).place(base_addr, fill, true, -70),
        "place bid after another user cancelled failed"
    );

    record_tx_with_credits!(
        "place_ask_wallet",
        2,
        exchange(2).place(base_addr, amount, false, 100),
        "place ask failed"
    );
    record_tx_with_credits!(
        "swap_exact_in_partial_ask_no_credits",
        2,
        exchange(8).swapExactAmountIn(quote_addr, base_addr, fill, 0),
        "partial ask exact-in swap failed"
    );
    let quote_balance = exchange(2)
        .balanceOf(signers[2].address(), quote_addr)
        .call()
        .await?;
    assert!(quote_balance > 0, "expected quote internal balance");
    record_tx_with_credits!(
        "withdraw_internal_balance",
        2,
        exchange(2).withdraw(quote_addr, quote_balance),
        "withdraw quote balance failed"
    );

    send_tx!(
        exchange(3).place(base_addr, fill, false, 90),
        "setup full ask exact-in failed"
    );
    let quote_for_full_ask = exchange(8)
        .quoteSwapExactAmountOut(quote_addr, base_addr, fill)
        .call()
        .await?;
    record_tx_with_credits!(
        "swap_exact_in_full_ask_earn_credits",
        3,
        exchange(8).swapExactAmountIn(quote_addr, base_addr, quote_for_full_ask, 0),
        "full ask exact-in swap failed"
    );
    record_tx_with_credits!(
        "place_bid_reuse_swap_credits",
        3,
        exchange(3).place(base_addr, fill, true, -40),
        "place bid reusing swap credits failed"
    );

    send_tx!(
        exchange(4).place(base_addr, fill, false, 80),
        "setup full ask exact-out failed"
    );
    record_tx_with_credits!(
        "swap_exact_out_full_ask_earn_credits",
        4,
        exchange(8).swapExactAmountOut(quote_addr, base_addr, fill, u128::MAX),
        "full ask exact-out swap failed"
    );
    record_tx_with_cross_user_credits!(
        "place_bid_cross_user_after_fill_credits",
        7,
        4,
        exchange(7).place(base_addr, fill, true, -80),
        "place bid after another user's order filled failed"
    );

    record_tx_with_credits!(
        "place_flip_bid_wallet",
        5,
        exchange(5).placeFlip(base_addr, fill, true, 20, 30),
        "place flip bid failed"
    );
    record_tx_with_credits!(
        "swap_exact_in_full_flip_bid",
        5,
        exchange(8).swapExactAmountIn(base_addr, quote_addr, fill, 0),
        "full flip bid exact-in swap failed"
    );

    send_tx!(
        exchange(9).place(base_addr, fill, true, -90),
        "setup predecessor bid for tail cancel failed"
    );
    let tail_cancel_order = exchange(10).nextOrderId().call().await?;
    send_tx!(
        exchange(10).place(base_addr, fill, true, -90),
        "setup tail bid cancel failed"
    );
    record_tx_with_cross_user_credits!(
        "cancel_tail_bid_credits_predecessor_next",
        10,
        9,
        exchange(10).cancel(tail_cancel_order),
        "tail bid cancel failed"
    );
    record_tx_with_credits!(
        "place_bid_reuse_predecessor_next_credit",
        9,
        exchange(9).place(base_addr, fill, true, -100),
        "place bid reusing predecessor next credit failed"
    );

    send_tx!(
        exchange(13).place(base_addr, fill, true, 120),
        "setup head bid for successor-prev fill failed"
    );
    send_tx!(
        exchange(14).place(base_addr, fill, true, 120),
        "setup successor bid for successor-prev fill failed"
    );
    record_tx_with_cross_user_credits!(
        "swap_exact_in_full_head_bid_tracks_successor_prev",
        13,
        14,
        exchange(8).swapExactAmountIn(base_addr, quote_addr, fill, 0),
        "full head bid exact-in swap failed"
    );

    let head_cancel_order = exchange(11).nextOrderId().call().await?;
    send_tx!(
        exchange(11).place(base_addr, fill, true, 110),
        "setup head bid for successor-prev cancel failed"
    );
    send_tx!(
        exchange(12).place(base_addr, fill, true, 110),
        "setup successor bid for successor-prev cancel failed"
    );
    record_tx_with_cross_user_credits!(
        "cancel_head_bid_tracks_successor_prev",
        11,
        12,
        exchange(11).cancel(head_cancel_order),
        "head bid cancel failed"
    );

    eprintln!(
        "\nStablecoinDEX {} lifecycle gas snapshot:",
        hardfork.name()
    );
    for (name, row) in &gas {
        eprintln!(
            "{name}: {} ({}, {})",
            row.gas, row.storage_credits, row.pooled_storage_credits
        );
    }

    let snapshot_name = format!(
        "stablecoin_dex_lifecycle_gas_snapshot_{}",
        hardfork.name().to_lowercase()
    );
    insta::assert_yaml_snapshot!(snapshot_name, gas);

    Ok(())
}
