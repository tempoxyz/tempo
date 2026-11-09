use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    sol_types::SolEvent,
};
use reth_e2e_test_utils::wallet::test_signer;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::{IReservations, ITIP20, RESERVATIONS_ADDRESS, TIP20Error};

use crate::utils::{TestNodeBuilder, setup_test_token};

/// A card authorization held, captured above the hold and partly refunded through transactions.
#[tokio::test(flavor = "multi_thread")]
async fn test_hold_capture_refund() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let owner_wallet = test_signer(0);
    let payee_wallet = test_signer(1);
    let (owner, payee) = (owner_wallet.address(), payee_wallet.address());
    let owner_provider = ProviderBuilder::new()
        .wallet(owner_wallet)
        .connect_http(setup.http_url.clone());
    let payee_provider = ProviderBuilder::new()
        .wallet(payee_wallet)
        .connect_http(setup.http_url.clone());

    let token = setup_test_token(owner_provider.clone(), owner).await?;
    let token_address = *token.address();
    token
        .mint(owner, U256::from(1_000))
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let reservations = IReservations::new(RESERVATIONS_ADDRESS, owner_provider.clone());
    let id = B256::random();
    let now = owner_provider
        .get_block_by_number(Default::default())
        .await?
        .expect("latest block exists")
        .header
        .timestamp;
    let receipt = reservations
        .hold(token_address, id, 600, now + 3_600, payee)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(3_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    assert_eq!(
        reservations.reserved(owner, token_address).call().await?,
        600
    );
    assert_eq!(
        reservations.available(owner, token_address).call().await?,
        400
    );
    assert_eq!(token.balanceOf(owner).call().await?, U256::from(1_000));

    let Err(err) = token
        .transfer(Address::random(), U256::from(401))
        .call()
        .await
    else {
        panic!("a transfer above the available balance must revert");
    };
    assert_eq!(
        err.as_decoded_interface_error::<TIP20Error>(),
        Some(TIP20Error::insufficient_balance(
            U256::from(400),
            U256::from(401),
            token_address
        ))
    );

    let receipt = reservations
        .capture(id, 650)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(3_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    let captured = receipt
        .logs()
        .iter()
        .find_map(|log| IReservations::HoldCaptured::decode_log(&log.inner).ok())
        .expect("capture emits HoldCaptured");
    assert_eq!((captured.amount, captured.debt), (650, 0));
    assert_eq!(token.balanceOf(payee).call().await?, U256::from(650));
    assert_eq!(token.balanceOf(owner).call().await?, U256::from(350));
    assert_eq!(reservations.reserved(owner, token_address).call().await?, 0);

    let receipt = IReservations::new(RESERVATIONS_ADDRESS, payee_provider)
        .refund(owner, id, 100)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    assert_eq!(token.balanceOf(owner).call().await?, U256::from(450));
    let totals = reservations.captured(owner, id).call().await?;
    assert_eq!((totals.captured, totals.refunded), (650, 100));
    let transfers: Vec<_> = receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP20::Transfer::decode_log(&log.inner).ok())
        .map(|log| (log.from, log.to, log.amount))
        .collect();
    assert!(transfers.contains(&(payee, owner, U256::from(100))));

    Ok(())
}
