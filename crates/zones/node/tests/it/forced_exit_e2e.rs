//! Native L1 -> shared Zone execution -> quorum settlement -> ordinary L1 delivery.
use crate::utils::{L1TestNode, ZoneAccount, ZoneTestNode, poll_until, spawn_sequencer};
use alloy::{primitives::U256, providers::Provider, sol_types::SolEvent};
use alloy_signer::SignerSync;
use std::time::Duration;
use tempo_contracts::zones::{ForcedExitAuthorization, ZonePortal};
use tempo_precompiles::PATH_USD_ADDRESS;
use zone_precompiles::ecies;

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_forced_exit_settles_and_pays_without_an_l2_transaction() -> eyre::Result<()> {
    forced_exit_flow(false).await
}

#[tokio::test(flavor = "multi_thread")]
async fn forced_exit_uses_ordinary_delivery_failure_and_private_bounceback() -> eyre::Result<()> {
    forced_exit_flow(true).await
}

async fn forced_exit_flow(bounce: bool) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let timeout = Duration::from_secs(90);
    let l1 = L1TestNode::start().await?;
    let factory = l1.native_zone_factory().await?;
    let portal_address = l1.create_zone(factory).await?;
    let portal_admin = ZonePortal::new(portal_address, l1.admin_provider());
    assert_eq!(portal_admin.forcedExitVersion().call().await?, 0);
    let activation = portal_admin
        .activateForcedExits()
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(activation.status());
    assert_eq!(portal_admin.forcedExitVersion().call().await?, 1);
    // Empty/rejected entries settle through the existing empty-batch cadence.
    let zone = ZoneTestNode::start_from_l1_with_forced_exits(
        l1.http_url(),
        l1.ws_url(),
        portal_address,
        10,
    )
    .await?;
    let mut account = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    l1.fund_user(account.address(), 50_000_000).await?;
    account.deposit(5_000_000, timeout, &zone).await?;
    let amount = zone.balance_of(PATH_USD_ADDRESS, account.address()).await?;
    assert!(!amount.is_zero());
    let user = l1.user_signer();
    let auth = ForcedExitAuthorization {
        account: account.address(),
        zoneChainId: U256::from(zone.provider().get_chain_id().await?),
        token: PATH_USD_ADDRESS,
        recipient: l1.admin_address(),
        nonce: U256::from(999),
        admitBefore: u64::MAX,
    };
    let digest = exithatch::authorization_digest(
        &auth,
        U256::from(l1.provider().get_chain_id().await?),
        portal_address,
    );
    let signature = user.sign_hash_sync(&digest)?;
    let plaintext = exithatch::encode_payload(&auth, &signature.as_bytes());
    let key = k256::SecretKey::from(l1.dev_signer().credential());
    let (x, parity) = ecies::compressed_x_and_parity(key.public_key().as_affine());
    let encrypted = ecies::encrypt_payload(
        &x,
        parity,
        &plaintext,
        ecies::EncryptionContext {
            portal: portal_address,
            sender: account.address(),
            key_index: U256::ZERO,
        },
        &mut k256::elliptic_curve::rand_core::OsRng,
        Some("forced-exit-v1"),
    )
    .unwrap();
    let portal = ZonePortal::new(portal_address, account.l1_provider());
    let recipient_before = l1.balance_of(PATH_USD_ADDRESS, l1.admin_address()).await?;
    let tx_count = zone
        .provider()
        .get_transaction_count(account.address())
        .await?;
    let receipt = portal
        .requestForcedExit(PATH_USD_ADDRESS, U256::ZERO, encrypted.clone())
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    zone.wait_for_balance(PATH_USD_ADDRESS, account.address(), U256::ZERO, timeout)
        .await?;
    assert_eq!(
        zone.provider()
            .get_transaction_count(account.address())
            .await?,
        tx_count
    );
    // Start settlement after execution to exercise reconstruction from persisted receipts.
    let replay = portal
        .requestForcedExit(PATH_USD_ADDRESS, U256::ZERO, encrypted.clone())
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(replay.status());
    let mut corrupted = encrypted;
    corrupted.tag[0] ^= 1;
    let invalid = portal
        .requestForcedExit(PATH_USD_ADDRESS, U256::ZERO, corrupted)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(invalid.status());
    let empty_auth = ForcedExitAuthorization {
        nonce: U256::from(1000),
        ..auth.clone()
    };
    let empty_digest = exithatch::authorization_digest(
        &empty_auth,
        U256::from(l1.provider().get_chain_id().await?),
        portal_address,
    );
    let empty_signature = user.sign_hash_sync(&empty_digest)?;
    let empty_payload = exithatch::encode_payload(&empty_auth, &empty_signature.as_bytes());
    let encrypted = ecies::encrypt_payload(
        &x,
        parity,
        &empty_payload,
        ecies::EncryptionContext {
            portal: portal_address,
            sender: account.address(),
            key_index: U256::ZERO,
        },
        &mut k256::elliptic_curve::rand_core::OsRng,
        Some("forced-exit-v1"),
    )
    .unwrap();
    let empty = portal
        .requestForcedExit(PATH_USD_ADDRESS, U256::ZERO, encrypted)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(empty.status());
    zone.wait_for_l2_tempo_finalized(empty.block_number.unwrap(), timeout)
        .await?;
    if bounce {
        let revoked = l1
            .set_allowed_account_on_portal(portal_address, auth.recipient, false)
            .await?;
        zone.wait_for_l2_tempo_finalized(revoked, timeout).await?;
    }
    let last_request = empty
        .inner
        .logs()
        .iter()
        .find_map(|log| ZonePortal::ForcedExitRequested::decode_log(&log.inner).ok())
        .expect("admission event");
    let _sequencer = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    poll_until(
        timeout,
        Duration::from_millis(250),
        "forced exit settlement",
        || async {
            Ok(
                (portal.lastProcessedDepositNumber().call().await? >= last_request.depositNumber)
                    .then_some(()),
            )
        },
    )
    .await?;
    if bounce {
        zone.wait_for_balance(PATH_USD_ADDRESS, account.address(), amount, timeout)
            .await?;
        l1.assert_withdrawals_processed_in_order(
            portal_address,
            &[(auth.recipient, PATH_USD_ADDRESS, amount.to::<u128>(), false)],
        )
        .await?;
    } else {
        l1.wait_for_balance(
            PATH_USD_ADDRESS,
            l1.admin_address(),
            recipient_before + amount + U256::from(4 * exithatch::FORCED_EXIT_COMPENSATION),
            timeout,
        )
        .await?;
    }
    // Exactly one ordinary withdrawal was delivered despite replay, invalid and empty requests.
    let delivered = portal
        .WithdrawalProcessed_filter()
        .from_block(0)
        .query()
        .await?;
    assert_eq!(delivered.len(), 1);
    assert_eq!(
        delivered[0].0.senderTag,
        tempo_contracts::zones::Withdrawal::sender_tag(
            auth.account,
            exithatch::private_request_hash(&auth, &signature.as_bytes()),
            1,
        ),
    );
    Ok(())
}
