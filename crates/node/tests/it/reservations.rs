use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    sol_types::SolEvent,
};
use reth_e2e_test_utils::wallet::test_signer;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::{
    IReservationCore::{self, HoldRequest},
    ITIP20, RESERVATIONS_ADDRESS, ReservationsError, TIP20Error,
};

use crate::utils::{TestNodeBuilder, setup_test_token};

/// Holds placed by the owner and by an approved holder, captured above the hold within the
/// tolerance fixed at placement, captured in parts by the payee naming the placer, refunded, and
/// a charge within the holder's budget, all through transactions.
#[tokio::test(flavor = "multi_thread")]
async fn test_hold_capture_refund() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let owner_wallet = test_signer(0);
    let payee_wallet = test_signer(1);
    let holder_wallet = test_signer(2);
    let (owner, payee, holder) = (
        owner_wallet.address(),
        payee_wallet.address(),
        holder_wallet.address(),
    );
    let owner_provider = ProviderBuilder::new()
        .wallet(owner_wallet)
        .connect_http(setup.http_url.clone());
    let payee_provider = ProviderBuilder::new()
        .wallet(payee_wallet)
        .connect_http(setup.http_url.clone());
    let holder_provider = ProviderBuilder::new()
        .wallet(holder_wallet)
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

    let reservations = IReservationCore::new(RESERVATIONS_ADDRESS, owner_provider.clone());
    let now = owner_provider
        .get_block_by_number(Default::default())
        .await?
        .expect("latest block exists")
        .header
        .timestamp;
    let request = |id: B256, amount: u128| HoldRequest {
        token: token_address,
        id,
        amount,
        expiresAt: now + 3_600,
        payee,
    };

    let id = B256::random();
    let receipt = reservations
        .hold(request(id, 600))
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

    // Without a tolerance, a capture above the hold is refused; the tolerance is fixed when a hold
    // is placed.
    let Err(err) = reservations
        .capture(owner, owner, id, 650, true)
        .call()
        .await
    else {
        panic!("a capture above the hold must revert without a tolerance");
    };
    assert_eq!(
        err.as_decoded_interface_error::<ReservationsError>(),
        Some(ReservationsError::capture_limit_exceeded())
    );
    let receipt = reservations
        .release(owner, owner, id)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    let receipt = reservations
        .setCaptureTolerance(payee, token_address, 1_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    // The id is free again once its hold settled.
    let receipt = reservations
        .hold(request(id, 600))
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(3_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    assert_eq!(
        reservations
            .getHold(owner, owner, id)
            .call()
            .await?
            .captureLimit,
        660
    );

    let receipt = reservations
        .capture(owner, owner, id, 650, true)
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
        .find_map(|log| IReservationCore::HoldCaptured::decode_log(&log.inner).ok())
        .expect("capture emits HoldCaptured");
    assert_eq!((captured.amount, captured.isFinal), (650, true));
    assert_eq!(token.balanceOf(payee).call().await?, U256::from(650));
    assert_eq!(token.balanceOf(owner).call().await?, U256::from(350));
    assert_eq!(reservations.reserved(owner, token_address).call().await?, 0);

    let payee_reservations = IReservationCore::new(RESERVATIONS_ADDRESS, payee_provider);
    let receipt = payee_reservations
        .refund(owner, token_address, owner, id, 100)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    assert_eq!(token.balanceOf(owner).call().await?, U256::from(450));
    // A settled hold leaves no record.
    let record = reservations.getHold(owner, owner, id).call().await?;
    assert_eq!((record.kind, record.held), (0, 0));
    let transfers: Vec<_> = receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP20::Transfer::decode_log(&log.inner).ok())
        .map(|log| (log.from, log.to, log.amount))
        .collect();
    assert!(transfers.contains(&(payee, owner, U256::from(100))));

    // An approved holder places a hold; the payee captures it in parts.
    let receipt = reservations
        .approveHolder(holder, token_address, 300, 0)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    let holder_reservations = IReservationCore::new(RESERVATIONS_ADDRESS, holder_provider);
    let second = B256::random();
    let receipt = holder_reservations
        .holdFrom(owner, request(second, 200))
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(3_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    let budget = reservations
        .budget(owner, holder, token_address)
        .call()
        .await?;
    assert_eq!((budget.limit, budget.outstanding), (300, 200));

    for (amount, is_final) in [(120, false), (50, true)] {
        let receipt = payee_reservations
            .capture(owner, holder, second, amount, is_final)
            .gas_price(TEMPO_T1_BASE_FEE as u128)
            .gas(3_000_000)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
    }
    assert_eq!(token.balanceOf(payee).call().await?, U256::from(720));
    assert_eq!(token.balanceOf(owner).call().await?, U256::from(280));
    assert_eq!(reservations.reserved(owner, token_address).call().await?, 0);
    // Captures stay spent; the rest of the hold returned to the budget.
    let budget = reservations
        .budget(owner, holder, token_address)
        .call()
        .await?;
    assert_eq!((budget.spent, budget.outstanding), (170, 0));

    // The holder charges without a hold, within its budget.
    let receipt = holder_reservations
        .charge(owner, token_address, B256::random(), 80, payee)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(3_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    let charged = receipt
        .logs()
        .iter()
        .find_map(|log| IReservationCore::Charged::decode_log(&log.inner).ok())
        .expect("charge emits Charged");
    assert_eq!((charged.amount, charged.payee), (80, payee));
    assert_eq!(token.balanceOf(owner).call().await?, U256::from(200));
    let Err(err) = holder_reservations
        .charge(owner, token_address, B256::random(), 51, payee)
        .call()
        .await
    else {
        panic!("a charge past the budget must revert");
    };
    assert_eq!(
        err.as_decoded_interface_error::<ReservationsError>(),
        Some(ReservationsError::budget_exceeded())
    );

    Ok(())
}
