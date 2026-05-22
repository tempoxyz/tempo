use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol_types::{SolEvent, SolValue},
};
use alloy_rpc_types_eth::TransactionReceipt;
use eyre::OptionExt;
use tempo_contracts::precompiles::{
    IReceivePolicyGuard, IRolesAuth, ITIP20, ITIP20Factory, ITIP403Registry,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS, RECEIVE_POLICY_GUARD_ADDRESS, TIP20_FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS,
    receive_policy_guard::{BLOCKED_RECEIPT_VERSION, InboundKind, RECOVERY_ORIGINATOR},
    tip20::ISSUER_ROLE,
    tip403_registry::{ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID},
};

use super::helpers::{GAS_LIMIT, GasSnapshot, print_gas_snapshot, test_signer};
use crate::utils::TestNodeBuilder;

struct BlockedTransfer {
    receiver: Address,
    receipt: Bytes,
    gas_used: u64,
}

async fn create_token<P>(provider: P, admin: Address, salt: B256) -> eyre::Result<Address>
where
    P: Provider + Clone,
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let receipt = factory
        .createToken_0(
            "TIP1028 Gas".to_string(),
            "T1028".to_string(),
            "USD".to_string(),
            PATH_USD_ADDRESS,
            admin,
            salt,
        )
        .gas(GAS_LIMIT)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "createToken failed");

    let created = receipt
        .logs()
        .iter()
        .find_map(|log| ITIP20Factory::TokenCreated::decode_log(&log.inner).ok())
        .ok_or_eyre("TokenCreated event missing")?;
    let token = created.token;

    let roles = IRolesAuth::new(token, provider);
    let grant = roles
        .grantRole(*ISSUER_ROLE, admin)
        .gas(GAS_LIMIT)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(grant.status(), "grantRole failed");

    Ok(token)
}

async fn set_receive_policy<P: Provider + Clone>(
    registry: &ITIP403Registry::ITIP403RegistryInstance<P>,
    sender_policy_id: u64,
    token_filter_id: u64,
    recovery: Address,
) -> eyre::Result<u64> {
    let receipt = registry
        .setReceivePolicy(sender_policy_id, token_filter_id, recovery)
        .gas(GAS_LIMIT)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "setReceivePolicy failed");

    Ok(receipt.gas_used)
}

async fn create_blocked_transfer<P: Provider + Clone>(
    token: &ITIP20::ITIP20Instance<P>,
    receiver: Address,
    expected_recovery_authority: Address,
    amount: U256,
) -> eyre::Result<BlockedTransfer> {
    let receipt = token
        .transfer(receiver, amount)
        .gas(GAS_LIMIT)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "blocked transfer failed");

    let blocked = transfer_blocked(&receipt)?;
    assert_eq!(blocked.token, *token.address());
    assert_eq!(blocked.receiver, receiver);
    assert_eq!(blocked.recipient, receiver);
    assert_eq!(blocked.recoveryAuthority, expected_recovery_authority);
    assert_eq!(blocked.amount, amount);
    assert_eq!(blocked.receiptVersion, BLOCKED_RECEIPT_VERSION);
    assert_eq!(
        blocked.blockedReason,
        ITIP403Registry::BlockedReason::RECEIVE_POLICY as u8
    );

    let receipt_bytes: Bytes = IReceivePolicyGuard::ClaimReceiptV1 {
        version: 1,
        token: *token.address(),
        recoveryAuthority: expected_recovery_authority,
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

    Ok(BlockedTransfer {
        receiver,
        receipt: receipt_bytes,
        gas_used: receipt.gas_used,
    })
}

async fn create_allowed_transfer<P: Provider + Clone>(
    token: &ITIP20::ITIP20Instance<P>,
    receiver: Address,
    amount: U256,
) -> eyre::Result<u64> {
    let receipt = token
        .transfer(receiver, amount)
        .gas(GAS_LIMIT)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "allowed transfer failed");
    assert!(
        transfer_blocked(&receipt).is_err(),
        "allowed transfer should not emit TransferBlocked"
    );

    Ok(receipt.gas_used)
}

async fn claim_blocked<P: Provider + Clone>(
    guard: &IReceivePolicyGuard::IReceivePolicyGuardInstance<P>,
    to: Address,
    blocked: &BlockedTransfer,
) -> eyre::Result<u64> {
    let receipt = guard
        .claim(to, blocked.receipt.clone())
        .gas(GAS_LIMIT)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "claim failed");

    Ok(receipt.gas_used)
}

fn transfer_blocked(
    receipt: &TransactionReceipt,
) -> eyre::Result<IReceivePolicyGuard::TransferBlocked> {
    receipt
        .logs()
        .iter()
        .find_map(|log| IReceivePolicyGuard::TransferBlocked::decode_log(&log.inner).ok())
        .map(|event| event.data)
        .ok_or_eyre("TransferBlocked event missing")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_receive_policy_guard_gas_snapshots() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let [
        admin,
        originator,
        originator_recovery_receiver,
        receiver_recovery_receiver,
        third_party_recovery_receiver,
        recovery,
        destination,
        allowed_third_party_receiver,
    ] = (0..8)
        .map(test_signer)
        .collect::<eyre::Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| eyre::eyre!("expected 8 test signers"))?;

    let provider = |signer: &PrivateKeySigner| {
        ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone())
    };
    let admin_provider = provider(&admin);
    let originator_provider = provider(&originator);

    let token = create_token(
        admin_provider.clone(),
        admin.address(),
        B256::with_last_byte(0x28),
    )
    .await?;
    let admin_token = ITIP20::new(token, admin_provider);
    let mint = admin_token
        .mint(originator.address(), U256::from(30_000))
        .gas(GAS_LIMIT)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(mint.status(), "mint failed");

    let mut gas = GasSnapshot::new();

    for (name, signer, sender_policy_id, recovery_authority) in [
        (
            "set_receive_policy_originator_recovery",
            &originator_recovery_receiver,
            REJECT_ALL_POLICY_ID,
            RECOVERY_ORIGINATOR,
        ),
        (
            "set_receive_policy_receiver_recovery",
            &receiver_recovery_receiver,
            REJECT_ALL_POLICY_ID,
            receiver_recovery_receiver.address(),
        ),
        (
            "set_receive_policy_third_party_recovery",
            &third_party_recovery_receiver,
            REJECT_ALL_POLICY_ID,
            recovery.address(),
        ),
        (
            "set_receive_policy_allowed_third_party_recovery",
            &allowed_third_party_receiver,
            ALLOW_ALL_POLICY_ID,
            recovery.address(),
        ),
    ] {
        gas.record(
            name,
            set_receive_policy(
                &ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider(signer)),
                sender_policy_id,
                ALLOW_ALL_POLICY_ID,
                recovery_authority,
            )
            .await?,
        );
    }

    let originator_token = ITIP20::new(token, originator_provider.clone());
    let originator_blocked = create_blocked_transfer(
        &originator_token,
        originator_recovery_receiver.address(),
        originator.address(),
        U256::from(1_000),
    )
    .await?;
    gas.record(
        "transfer_blocked_originator_recovery",
        originator_blocked.gas_used,
    );

    let receiver_blocked = create_blocked_transfer(
        &originator_token,
        receiver_recovery_receiver.address(),
        receiver_recovery_receiver.address(),
        U256::from(2_000),
    )
    .await?;
    gas.record(
        "transfer_blocked_receiver_recovery",
        receiver_blocked.gas_used,
    );

    let third_party_blocked = create_blocked_transfer(
        &originator_token,
        third_party_recovery_receiver.address(),
        recovery.address(),
        U256::from(3_000),
    )
    .await?;
    gas.record(
        "transfer_blocked_third_party_recovery",
        third_party_blocked.gas_used,
    );
    gas.record(
        "transfer_allowed_third_party_receive_policy",
        create_allowed_transfer(
            &originator_token,
            allowed_third_party_receiver.address(),
            U256::from(4_000),
        )
        .await?,
    );

    let originator_guard =
        IReceivePolicyGuard::new(RECEIVE_POLICY_GUARD_ADDRESS, originator_provider);
    let receiver_guard = IReceivePolicyGuard::new(
        RECEIVE_POLICY_GUARD_ADDRESS,
        provider(&receiver_recovery_receiver),
    );
    let recovery_guard =
        IReceivePolicyGuard::new(RECEIVE_POLICY_GUARD_ADDRESS, provider(&recovery));

    gas.record(
        "claim_originator_recovery_to_destination",
        claim_blocked(
            &originator_guard,
            destination.address(),
            &originator_blocked,
        )
        .await?,
    );
    gas.record(
        "claim_receiver_recovery_to_receiver",
        claim_blocked(
            &receiver_guard,
            receiver_blocked.receiver,
            &receiver_blocked,
        )
        .await?,
    );
    gas.record(
        "claim_third_party_recovery_to_destination",
        claim_blocked(&recovery_guard, destination.address(), &third_party_blocked).await?,
    );

    print_gas_snapshot("ReceivePolicyGuard gas snapshot", &gas);

    insta::assert_yaml_snapshot!(gas);

    Ok(())
}
