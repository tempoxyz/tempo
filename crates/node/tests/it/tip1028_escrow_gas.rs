use std::collections::BTreeMap;

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, PrivateKeySigner},
    sol_types::{SolEvent, SolValue},
};
use alloy_rpc_types_eth::TransactionReceipt;
use eyre::OptionExt;
use tempo_contracts::precompiles::{
    IRolesAuth, ITIP20, ITIP20Factory, ITIP403Registry, ITIP1028Escrow,
};
use tempo_precompiles::{
    ESCROW_ADDRESS, PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS,
    tip20::ISSUER_ROLE,
    tip403_registry::{ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID},
    tip1028_escrow::{
        BLOCKED_RECEIPT_VERSION, InboundKind, RECOVERY_ORIGINATOR, RECOVERY_RECEIVER,
    },
};

use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};

const GAS: u64 = 5_000_000;

struct BlockedTransfer {
    token: Address,
    receiver: Address,
    recovery: Address,
    receipt: Bytes,
    gas_used: u64,
}

fn wallet(index: u32) -> eyre::Result<PrivateKeySigner> {
    Ok(MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(index)?
        .build()?)
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
        .gas(GAS)
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
        .gas(GAS)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(grant.status(), "grantRole failed");

    Ok(token)
}

async fn set_receive_policy<P: Provider + Clone>(
    registry: &ITIP403Registry::ITIP403RegistryInstance<P>,
    recovery: Address,
) -> eyre::Result<u64> {
    let receipt = registry
        .setReceivePolicy(REJECT_ALL_POLICY_ID, ALLOW_ALL_POLICY_ID, recovery)
        .gas(GAS)
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
    recovery: Address,
    amount: U256,
) -> eyre::Result<BlockedTransfer> {
    let receipt = token
        .transfer(receiver, amount)
        .gas(GAS)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "blocked transfer failed");

    let blocked = transfer_blocked(&receipt)?;
    assert_eq!(blocked.token, *token.address());
    assert_eq!(blocked.receiver, receiver);
    assert_eq!(blocked.recipient, receiver);
    assert_eq!(blocked.recoveryAuthority, recovery);
    assert_eq!(blocked.amount, amount);
    assert_eq!(blocked.receiptVersion, BLOCKED_RECEIPT_VERSION);
    assert_eq!(
        blocked.blockedReason,
        ITIP403Registry::BlockedReason::RECEIVE_POLICY as u8
    );

    let receipt_bytes: Bytes = ITIP1028Escrow::ClaimReceiptV1 {
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
        token: *token.address(),
        receiver,
        recovery,
        receipt: receipt_bytes,
        gas_used: receipt.gas_used,
    })
}

async fn claim_blocked<P: Provider + Clone>(
    escrow: &ITIP1028Escrow::ITIP1028EscrowInstance<P>,
    to: Address,
    blocked: &BlockedTransfer,
) -> eyre::Result<u64> {
    let receipt = escrow
        .claim(
            blocked.token,
            blocked.recovery,
            BLOCKED_RECEIPT_VERSION,
            blocked.receipt.clone(),
            to,
        )
        .gas(GAS)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "claim failed");

    Ok(receipt.gas_used)
}

fn transfer_blocked(receipt: &TransactionReceipt) -> eyre::Result<ITIP1028Escrow::TransferBlocked> {
    receipt
        .logs()
        .iter()
        .find_map(|log| ITIP1028Escrow::TransferBlocked::decode_log(&log.inner).ok())
        .map(|event| event.data)
        .ok_or_eyre("TransferBlocked event missing")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1028_escrow_gas_snapshots() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let admin = wallet(0)?;
    let originator = wallet(1)?;
    let originator_recovery_receiver = wallet(2)?;
    let receiver_recovery_receiver = wallet(3)?;
    let third_party_recovery_receiver = wallet(4)?;
    let recovery = wallet(5)?;
    let destination = wallet(6)?;

    let admin_provider = ProviderBuilder::new()
        .wallet(admin.clone())
        .connect_http(http_url.clone());
    let originator_provider = ProviderBuilder::new()
        .wallet(originator.clone())
        .connect_http(http_url.clone());

    let token = create_token(
        admin_provider.clone(),
        admin.address(),
        B256::with_last_byte(0x28),
    )
    .await?;
    let admin_token = ITIP20::new(token, admin_provider);
    let mint = admin_token
        .mint(originator.address(), U256::from(30_000))
        .gas(GAS)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(mint.status(), "mint failed");

    let mut gas = BTreeMap::new();

    let originator_recovery_provider = ProviderBuilder::new()
        .wallet(originator_recovery_receiver.clone())
        .connect_http(http_url.clone());
    let receiver_recovery_provider = ProviderBuilder::new()
        .wallet(receiver_recovery_receiver.clone())
        .connect_http(http_url.clone());
    let third_party_recovery_provider = ProviderBuilder::new()
        .wallet(third_party_recovery_receiver.clone())
        .connect_http(http_url.clone());

    gas.insert(
        "set_receive_policy_originator_recovery",
        set_receive_policy(
            &ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, originator_recovery_provider),
            RECOVERY_ORIGINATOR,
        )
        .await?,
    );
    gas.insert(
        "set_receive_policy_receiver_recovery",
        set_receive_policy(
            &ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, receiver_recovery_provider.clone()),
            RECOVERY_RECEIVER,
        )
        .await?,
    );
    gas.insert(
        "set_receive_policy_third_party_recovery",
        set_receive_policy(
            &ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, third_party_recovery_provider),
            recovery.address(),
        )
        .await?,
    );

    let originator_token = ITIP20::new(token, originator_provider.clone());
    let originator_blocked = create_blocked_transfer(
        &originator_token,
        originator_recovery_receiver.address(),
        RECOVERY_ORIGINATOR,
        U256::from(1_000),
    )
    .await?;
    gas.insert(
        "transfer_blocked_originator_recovery",
        originator_blocked.gas_used,
    );

    let receiver_blocked = create_blocked_transfer(
        &originator_token,
        receiver_recovery_receiver.address(),
        RECOVERY_RECEIVER,
        U256::from(2_000),
    )
    .await?;
    gas.insert(
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
    gas.insert(
        "transfer_blocked_third_party_recovery",
        third_party_blocked.gas_used,
    );

    let originator_escrow = ITIP1028Escrow::new(ESCROW_ADDRESS, originator_provider);
    let receiver_escrow = ITIP1028Escrow::new(ESCROW_ADDRESS, receiver_recovery_provider);
    let recovery_escrow = ITIP1028Escrow::new(
        ESCROW_ADDRESS,
        ProviderBuilder::new()
            .wallet(recovery.clone())
            .connect_http(http_url),
    );

    gas.insert(
        "claim_originator_recovery_to_destination",
        claim_blocked(
            &originator_escrow,
            destination.address(),
            &originator_blocked,
        )
        .await?,
    );
    gas.insert(
        "claim_receiver_recovery_to_receiver",
        claim_blocked(
            &receiver_escrow,
            receiver_blocked.receiver,
            &receiver_blocked,
        )
        .await?,
    );
    gas.insert(
        "claim_third_party_recovery_to_destination",
        claim_blocked(
            &recovery_escrow,
            destination.address(),
            &third_party_blocked,
        )
        .await?,
    );

    eprintln!("\nTIP1028Escrow gas snapshot:");
    for (name, gas_used) in &gas {
        eprintln!("{name}: {gas_used}");
    }

    insta::assert_yaml_snapshot!(gas);

    Ok(())
}
