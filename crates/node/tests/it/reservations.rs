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
/// owner's tolerance, captured in parts by the payee, refunded, and a charge, all through
/// transactions.
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
        standIn: false,
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

    // Without a tolerance, a capture above the hold is refused.
    let Err(err) = reservations.capture(owner, id, 650, true).call().await else {
        panic!("a capture above the hold must revert without a tolerance");
    };
    assert_eq!(
        err.as_decoded_interface_error::<ReservationsError>(),
        Some(ReservationsError::tolerance_exceeded())
    );
    let receipt = reservations
        .setCaptureTolerance(payee, token_address, 1_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());

    let receipt = reservations
        .capture(owner, id, 650, true)
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
    assert_eq!((captured.amount, captured.debt), (650, 0));
    assert_eq!(token.balanceOf(payee).call().await?, U256::from(650));
    assert_eq!(token.balanceOf(owner).call().await?, U256::from(350));
    assert_eq!(reservations.reserved(owner, token_address).call().await?, 0);

    let payee_reservations = IReservationCore::new(RESERVATIONS_ADDRESS, payee_provider);
    let receipt = payee_reservations
        .refund(owner, id, 100)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    assert_eq!(token.balanceOf(owner).call().await?, U256::from(450));
    let record = reservations.getHold(owner, id).call().await?;
    assert_eq!(
        (record.captured, record.refunded, record.settled),
        (650, 100, true)
    );
    let transfers: Vec<_> = receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP20::Transfer::decode_log(&log.inner).ok())
        .map(|log| (log.from, log.to, log.amount))
        .collect();
    assert!(transfers.contains(&(payee, owner, U256::from(100))));

    // An approved holder places a hold; the payee captures it in parts.
    let receipt = reservations
        .approveHolder(holder, token_address, 300)
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
    let allowance = reservations
        .allowance(owner, holder, token_address)
        .call()
        .await?;
    assert_eq!((allowance.allowance, allowance.outstanding), (300, 200));

    for (amount, is_final) in [(120, false), (50, true)] {
        let receipt = payee_reservations
            .capture(owner, second, amount, is_final)
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
    let allowance = reservations
        .allowance(owner, holder, token_address)
        .call()
        .await?;
    assert_eq!(allowance.outstanding, 0);

    // The holder charges without a hold, within its allowance.
    let receipt = holder_reservations
        .charge(owner, token_address, B256::random(), 80, payee, false)
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
    assert_eq!((charged.amount, charged.debt), (80, 0));
    assert_eq!(token.balanceOf(owner).call().await?, U256::from(200));

    Ok(())
}
