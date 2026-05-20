use std::future::Future;

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionReceipt,
    signers::local::{MnemonicBuilder, PrivateKeySigner},
    sol_types::{SolEvent, SolValue},
    transports::http::reqwest::Url,
};
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use eyre::OptionExt as _;
use futures::future::join_all;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_precompiles::{
    PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS, TIP1028_GUARD_ADDRESS,
    tip20::{IRolesAuth, ISSUER_ROLE, ITIP20},
    tip20_factory::ITIP20Factory,
    tip403_registry::{ALLOW_ALL_POLICY_ID, ITIP403Registry, REJECT_ALL_POLICY_ID},
    tip1028_guard::{
        BLOCKED_PROOF_VERSION,
        ITIP1028Guard::{self, ITIP1028GuardErrors as TIP1028GuardError},
        InboundKind, RECOVERY_RECEIVER,
    },
};

use crate::{Setup, execution_runtime::TEST_MNEMONIC, setup_validators};

const GAS: u64 = 5_000_000;
const GAS_PRICE: u128 = TEMPO_T1_BASE_FEE as u128;

struct BlockedTransfer {
    token: Address,
    receiver: Address,
    proof: Bytes,
}

#[test_traced]
fn test_blocked_transfer_claim_no_recovery() {
    run_tip1028_test(1028, |http_url| async move {
        let amount = U256::from(250);
        let blocked = create_blocked_transfer(
            http_url.clone(),
            10,
            11,
            RECOVERY_RECEIVER,
            B256::from([0x01; 32]),
            amount,
        )
        .await?;

        let other_wallet = wallet(12)?;
        let other = other_wallet.address();
        let other_provider = ProviderBuilder::new()
            .wallet(other_wallet)
            .connect_http(http_url.clone());
        let other_tip1028 = ITIP1028Guard::new(TIP1028_GUARD_ADDRESS, other_provider);
        let Err(result) = other_tip1028
            .claim(other, blocked.proof.clone())
            .call()
            .await
        else {
            panic!("expected recovery claim without recovery address to fail");
        };
        assert_eq!(
            result.as_decoded_interface_error::<TIP1028GuardError>(),
            Some(TIP1028GuardError::unauthorized_claimer())
        );
        assert_eq!(
            token_view(http_url.clone(), blocked.token)
                .balanceOf(TIP1028_GUARD_ADDRESS)
                .call()
                .await?,
            amount
        );

        let receiver_wallet = wallet(11)?;
        let receiver_provider = ProviderBuilder::new()
            .wallet(receiver_wallet)
            .connect_http(http_url.clone());
        let receiver_tip1028 = ITIP1028Guard::new(TIP1028_GUARD_ADDRESS, receiver_provider);
        let claim = receiver_tip1028
            .claim(blocked.receiver, blocked.proof.clone())
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(claim.status(), "claim receipt: {claim:#?}");

        let token = token_view(http_url, blocked.token);
        assert_eq!(token.balanceOf(blocked.receiver).call().await?, amount);
        assert_eq!(
            token.balanceOf(TIP1028_GUARD_ADDRESS).call().await?,
            U256::ZERO
        );

        Ok(())
    });
}

#[test_traced]
fn test_tip1028_claim_with_recovery() {
    run_tip1028_test(1029, |http_url| async move {
        let amount = U256::from(400);
        let recovery = wallet(22)?.address();
        let destination = wallet(23)?.address();
        let blocked = create_blocked_transfer(
            http_url.clone(),
            20,
            21,
            recovery,
            B256::from([0x02; 32]),
            amount,
        )
        .await?;

        let recovery_provider = ProviderBuilder::new()
            .wallet(wallet(22)?)
            .connect_http(http_url.clone());
        let recovery_tip1028 = ITIP1028Guard::new(TIP1028_GUARD_ADDRESS, recovery_provider);
        let claim = recovery_tip1028
            .claim(destination, blocked.proof)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(claim.status(), "claim receipt: {claim:#?}");

        let token = token_view(http_url, blocked.token);
        assert_eq!(token.balanceOf(blocked.receiver).call().await?, U256::ZERO);
        assert_eq!(token.balanceOf(destination).call().await?, amount);
        assert_eq!(
            token.balanceOf(TIP1028_GUARD_ADDRESS).call().await?,
            U256::ZERO
        );

        Ok(())
    });
}

fn run_tip1028_test<F, Fut>(seed: u64, test: F)
where
    F: FnOnce(Url) -> Fut + Send + 'static,
    Fut: Future<Output = eyre::Result<()>> + Send + 'static,
{
    let _ = tempo_eyre::install();

    Runner::from(Config::default().with_seed(seed)).start(|mut context| async move {
        let setup = Setup::new()
            .how_many_signers(1)
            .epoch_length(100)
            .seed(seed);
        let (mut nodes, execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        let http_url = nodes[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();

        execution_runtime
            .run_async(test(http_url))
            .await
            .unwrap()
            .unwrap();
    });
}

async fn create_blocked_transfer(
    http_url: Url,
    sender_index: u32,
    receiver_index: u32,
    recovery: Address,
    salt: B256,
    amount: U256,
) -> eyre::Result<BlockedTransfer> {
    let admin_wallet = wallet(0)?;
    let admin = admin_wallet.address();
    let admin_provider = ProviderBuilder::new()
        .wallet(admin_wallet)
        .connect_http(http_url.clone());
    let token = create_token(admin_provider.clone(), admin, salt).await?;

    let receiver_wallet = wallet(receiver_index)?;
    let receiver = receiver_wallet.address();
    let receiver_provider = ProviderBuilder::new()
        .wallet(receiver_wallet)
        .connect_http(http_url.clone());
    let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, receiver_provider);
    registry
        .setReceivePolicy(REJECT_ALL_POLICY_ID, ALLOW_ALL_POLICY_ID, recovery)
        .gas(GAS)
        .gas_price(GAS_PRICE)
        .send()
        .await?
        .get_receipt()
        .await?;

    let sender_wallet = wallet(sender_index)?;
    let sender = sender_wallet.address();
    let token_admin = ITIP20::new(token, admin_provider);
    token_admin
        .mint(sender, amount)
        .gas(GAS)
        .gas_price(GAS_PRICE)
        .send()
        .await?
        .get_receipt()
        .await?;

    let sender_provider = ProviderBuilder::new()
        .wallet(sender_wallet)
        .connect_http(http_url.clone());
    let sender_token = ITIP20::new(token, sender_provider);
    let transfer = sender_token
        .transfer(receiver, amount)
        .gas(GAS)
        .gas_price(GAS_PRICE)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(transfer.status());

    let blocked = transfer_blocked(&transfer)?;
    assert_eq!(blocked.token, token);
    assert_eq!(blocked.from, sender);
    assert_eq!(blocked.receiver, receiver);
    assert_eq!(blocked.recipient, receiver);
    assert_eq!(blocked.recoveryAuthority, recovery);
    assert_eq!(blocked.amount, amount);
    assert_eq!(
        blocked.blockedReason,
        ITIP403Registry::BlockedReason::RECEIVE_POLICY as u8
    );

    let proof: Bytes = ITIP1028Guard::ClaimProofV1 {
        version: BLOCKED_PROOF_VERSION,
        token,
        recoveryAuthority: recovery,
        originator: blocked.from,
        recipient: blocked.recipient,
        blockedAt: blocked.blockedAt,
        blockedNonce: blocked.blockedNonce,
        blockedReason: blocked.blockedReason,
        kind: InboundKind::TRANSFER,
        memo: blocked.memo,
    }
    .abi_encode()
    .into();

    let tip1028 = ITIP1028Guard::new(
        TIP1028_GUARD_ADDRESS,
        ProviderBuilder::new().connect_http(http_url.clone()),
    );
    assert_eq!(
        tip1028.balanceOf(proof.clone()).call().await?,
        amount,
        "blocked event: {blocked:#?}"
    );

    let token_view = token_view(http_url.clone(), token);
    assert_eq!(token_view.balanceOf(sender).call().await?, U256::ZERO);
    assert_eq!(token_view.balanceOf(receiver).call().await?, U256::ZERO);
    assert_eq!(
        token_view.balanceOf(TIP1028_GUARD_ADDRESS).call().await?,
        amount
    );

    let blocked = BlockedTransfer {
        token,
        receiver,
        proof,
    };

    Ok(blocked)
}

async fn create_token<P>(provider: P, admin: Address, salt: B256) -> eyre::Result<Address>
where
    P: Provider + Clone,
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let receipt = factory
        .createToken_0(
            "Token".to_string(),
            "TKN".to_string(),
            "USD".to_string(),
            PATH_USD_ADDRESS,
            admin,
            salt,
        )
        .gas(GAS)
        .gas_price(GAS_PRICE)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());

    let created = receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP20Factory::TokenCreated::decode_log(&log.inner).ok())
        .next()
        .ok_or_eyre("TokenCreated event missing")?;
    let token = created.token;

    let roles = IRolesAuth::new(token, provider);
    let grant = roles
        .grantRole(*ISSUER_ROLE, admin)
        .gas(GAS)
        .gas_price(GAS_PRICE)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(grant.status());

    Ok(token)
}

fn token_view(http_url: Url, token: Address) -> ITIP20::ITIP20Instance<impl Clone + Provider> {
    ITIP20::new(token, ProviderBuilder::new().connect_http(http_url))
}

fn transfer_blocked(receipt: &TransactionReceipt) -> eyre::Result<ITIP1028Guard::TransferBlocked> {
    receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP1028Guard::TransferBlocked::decode_log(&log.inner).ok())
        .map(|event| event.data)
        .next()
        .ok_or_eyre("TransferBlocked event missing")
}

fn wallet(index: u32) -> eyre::Result<PrivateKeySigner> {
    Ok(MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(index)?
        .build()?)
}
