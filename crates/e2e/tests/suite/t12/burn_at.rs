//! TIP-1006 through signed RPC transactions, consensus, and committed execution state.

use std::{future::Future, time::Duration};

use alloy::{
    eips::Encodable2718,
    network::ReceiptResponse,
    primitives::{Address, B256, TxKind, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Log,
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::{SolCall, SolEvent},
    transports::http::reqwest::Url,
};
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;
use tempo_alloy::{
    TempoNetwork,
    contracts::{MULTICALL3_ADDRESS, Multicall3},
    rpc::TempoTransactionReceipt,
};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, PATH_USD_ADDRESS, RECEIVE_POLICY_GUARD_ADDRESS,
    STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS,
    account_keychain::IAccountKeychain,
    tip20::{BURN_AT_ROLE, BURN_BLOCKED_ROLE, IRolesAuth, ITIP20, PAUSE_ROLE, UNPAUSE_ROLE},
    tip403_registry::{ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID},
};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{Call, KeychainSignature, PrimitiveSignature, TempoSignature},
};

use super::super::blocked_transfers::{create_token, wallet};
use crate::{Setup, setup_validators};

const GAS: u64 = 5_000_000;
const GAS_PRICE: u128 = TEMPO_T1_BASE_FEE as u128;

#[test_traced]
fn burn_at_is_unavailable_before_t12() {
    run_burn_at_test(1006, u64::MAX, |url| async move {
        let signer = wallet(0)?;
        let admin = signer.address();
        let provider = ProviderBuilder::new().wallet(signer).connect_http(url);
        let address = create_token(provider.clone(), admin, B256::ZERO).await?;
        let token = ITIP20::new(address, &provider);
        let roles = IRolesAuth::new(address, &provider);
        let receipt = roles
            .grantRole(BURN_AT_ROLE, admin)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
        let receipt = token
            .mint(admin, U256::from(10))
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());

        assert!(token.BURN_AT_ROLE().call().await.is_err());
        let receipt = token
            .burnAt(admin, U256::ONE)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(!receipt.status());
        assert_no_burn_events(receipt.logs(), address);
        assert_eq!(token.balanceOf(admin).call().await?, U256::from(10));
        assert_eq!(token.totalSupply().call().await?, U256::from(10));
        Ok(())
    });
}

#[test_traced]
fn burn_at_permissions_policy_and_protected_balances() {
    run_burn_at_test(1007, 0, |url| async move {
        let signer = wallet(0)?;
        let admin = signer.address();
        let holder = wallet(1)?.address();
        let provider = ProviderBuilder::new().wallet(signer).connect_http(url);
        let address = create_token(provider.clone(), admin, B256::ZERO).await?;
        let token = ITIP20::new(address, &provider);
        let roles = IRolesAuth::new(address, &provider);
        let receipt = token
            .mint(holder, U256::from(100))
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
        assert_eq!(
            token.BURN_AT_ROLE().call().await?,
            keccak256("BURN_AT_ROLE")
        );

        // ISSUER_ROLE and BURN_BLOCKED_ROLE do not authorize burnAt.
        let receipt = token
            .burnAt(holder, U256::ONE)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(!receipt.status());
        assert_no_burn_events(receipt.logs(), address);
        let receipt = roles
            .grantRole(BURN_BLOCKED_ROLE, admin)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
        let receipt = token
            .burnAt(holder, U256::ONE)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(!receipt.status());
        assert_no_burn_events(receipt.logs(), address);
        for role in [BURN_AT_ROLE, PAUSE_ROLE, UNPAUSE_ROLE] {
            let receipt = roles
                .grantRole(role, admin)
                .gas(GAS)
                .gas_price(GAS_PRICE)
                .send()
                .await?
                .get_receipt()
                .await?;
            assert!(receipt.status());
        }

        let mut remaining = U256::from(100);
        for policy in [ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID] {
            let receipt = token
                .changeTransferPolicyId(policy)
                .gas(GAS)
                .gas_price(GAS_PRICE)
                .send()
                .await?
                .get_receipt()
                .await?;
            assert!(receipt.status());
            let receipt = token
                .burnAt(holder, U256::from(20))
                .gas(GAS)
                .gas_price(GAS_PRICE)
                .send()
                .await?
                .get_receipt()
                .await?;
            assert!(receipt.status());
            assert_burn_events(receipt.logs(), address, admin, holder, U256::from(20));
            remaining -= U256::from(20);
            assert_eq!(token.balanceOf(holder).call().await?, remaining);
            assert_eq!(token.totalSupply().call().await?, remaining);
        }
        let zero = token
            .burnAt(holder, U256::ZERO)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(zero.status());
        assert_burn_events(zero.logs(), address, admin, holder, U256::ZERO);
        let receipt = token
            .burnAt(holder, remaining + U256::ONE)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(!receipt.status());
        assert_no_burn_events(receipt.logs(), address);

        let receipt = token
            .pause()
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
        let receipt = token
            .burnAt(holder, U256::ONE)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(!receipt.status());
        assert_no_burn_events(receipt.logs(), address);
        let receipt = token
            .unpause()
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());

        // Zero-amount calls isolate the protected-address check from insufficient balance.
        for from in [
            address,
            TIP_FEE_MANAGER_ADDRESS,
            STABLECOIN_DEX_ADDRESS,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            RECEIVE_POLICY_GUARD_ADDRESS,
            address!("5AD0000000000000000000000000000000000000"),
            address!("5AD000000000000000000000ffffffffffffffff"),
        ] {
            let receipt = token
                .burnAt(from, U256::ZERO)
                .gas(GAS)
                .gas_price(GAS_PRICE)
                .send()
                .await?
                .get_receipt()
                .await?;
            assert!(!receipt.status());
            assert_no_burn_events(receipt.logs(), address);
            let receipt = token
                .burnBlocked(from, U256::ZERO)
                .gas(GAS)
                .gas_price(GAS_PRICE)
                .send()
                .await?
                .get_receipt()
                .await?;
            assert!(!receipt.status());
            assert_no_burn_events(receipt.logs(), address);
        }
        let receipt = roles
            .revokeRole(BURN_AT_ROLE, admin)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
        let receipt = token
            .burnAt(holder, U256::ONE)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(!receipt.status());
        assert_no_burn_events(receipt.logs(), address);
        assert_eq!(token.balanceOf(holder).call().await?, remaining);
        assert_eq!(token.totalSupply().call().await?, remaining);
        Ok(())
    });
}

#[test_traced]
fn burn_at_bridge_enforces_access_key_limits_and_rolls_back() {
    run_burn_at_test(1008, 0, |url| async move {
        let signer = wallet(0)?;
        let holder = signer.address();
        let aa_provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(url.clone());
        let provider = ProviderBuilder::new().wallet(signer).connect_http(url);
        let address = create_token(provider.clone(), holder, B256::ZERO).await?;
        let token = ITIP20::new(address, &provider);
        let roles = IRolesAuth::new(address, &provider);
        let keychain = IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, &provider);
        let receipt = token
            .mint(holder, U256::from(40))
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());

        // Multicall3 is deployed in the test genesis and acts as the bridge calling burnAt.
        assert!(!provider.get_code_at(MULTICALL3_ADDRESS).await?.is_empty());
        let receipt = roles
            .grantRole(BURN_AT_ROLE, MULTICALL3_ADDRESS)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
        let key = PrivateKeySigner::random();
        let receipt = keychain
            .authorizeKey_1(
                key.address(),
                IAccountKeychain::SignatureType::Secp256k1,
                IAccountKeychain::KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![
                        IAccountKeychain::TokenLimit {
                            token: address,
                            amount: U256::from(100),
                            period: 0,
                        },
                        IAccountKeychain::TokenLimit {
                            token: PATH_USD_ADDRESS,
                            amount: U256::from(u128::MAX),
                            period: 0,
                        },
                    ],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            )
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());

        let burn = |amount| Multicall3::Call3 {
            target: address,
            allowFailure: false,
            callData: token.burnAt(holder, U256::from(amount)).calldata().clone(),
        };

        // A failed burn must restore the spending limit deducted before the balance check.
        let receipt = send_access_key_calls(&aa_provider, holder, &key, vec![burn(50)]).await?;
        assert!(!receipt.status());
        assert_no_burn_events(receipt.logs(), address);
        assert_burn_state(&provider, address, holder, key.address(), 40, 100).await?;

        let receipt = send_access_key_calls(&aa_provider, holder, &key, vec![burn(20)]).await?;
        assert!(receipt.status());
        assert_burn_events(
            receipt.logs(),
            address,
            MULTICALL3_ADDRESS,
            holder,
            U256::from(20),
        );
        assert_access_key_spend(receipt.logs(), address, holder, key.address(), 20, 80);
        assert_burn_state(&provider, address, holder, key.address(), 20, 80).await?;

        // The first burn succeeds, then a mandatory second call fails and reverts the whole batch.
        let receipt =
            send_access_key_calls(&aa_provider, holder, &key, vec![burn(10), burn(50)]).await?;
        assert!(!receipt.status());
        assert_no_burn_events(receipt.logs(), address);
        assert_burn_state(&provider, address, holder, key.address(), 20, 80).await?;

        // Fund above the requested burn so only the access-key limit can reject it.
        // Raw access-key transactions also advance the holder's nonce.
        let receipt = token
            .mint(holder, U256::from(100))
            .nonce(provider.get_transaction_count(holder).await?)
            .gas(GAS)
            .gas_price(GAS_PRICE)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
        let receipt = send_access_key_calls(&aa_provider, holder, &key, vec![burn(81)]).await?;
        assert!(!receipt.status());
        assert_no_burn_events(receipt.logs(), address);
        assert_burn_state(&provider, address, holder, key.address(), 120, 80).await?;

        let receipt = send_access_key_calls(&aa_provider, holder, &key, vec![burn(0)]).await?;
        assert!(receipt.status());
        assert_burn_events(
            receipt.logs(),
            address,
            MULTICALL3_ADDRESS,
            holder,
            U256::ZERO,
        );
        assert_access_key_spend(receipt.logs(), address, holder, key.address(), 0, 80);
        assert_burn_state(&provider, address, holder, key.address(), 120, 80).await?;
        Ok(())
    });
}

async fn send_access_key_calls(
    provider: &impl Provider<TempoNetwork>,
    holder: Address,
    key: &PrivateKeySigner,
    calls: Vec<Multicall3::Call3>,
) -> eyre::Result<TempoTransactionReceipt> {
    let tx = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        gas_limit: GAS,
        max_fee_per_gas: GAS_PRICE,
        fee_token: Some(PATH_USD_ADDRESS),
        nonce: provider.get_transaction_count(holder).await?,
        calls: vec![Call {
            to: TxKind::Call(MULTICALL3_ADDRESS),
            value: U256::ZERO,
            input: Multicall3::aggregate3Call { calls }.abi_encode().into(),
        }],
        ..Default::default()
    };
    let signature = key.sign_hash_sync(&KeychainSignature::signing_hash(
        tx.signature_hash(),
        holder,
    ))?;
    let envelope: TempoTxEnvelope = tx
        .into_signed(TempoSignature::Keychain(KeychainSignature::new(
            holder,
            PrimitiveSignature::Secp256k1(signature),
        )))
        .into();
    Ok(provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .get_receipt()
        .await?)
}

async fn assert_burn_state(
    provider: &impl Provider,
    address: Address,
    holder: Address,
    key: Address,
    balance: u64,
    limit: u64,
) -> eyre::Result<()> {
    let token = ITIP20::new(address, provider);
    let keychain = IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, provider);
    assert_eq!(token.balanceOf(holder).call().await?, U256::from(balance));
    assert_eq!(token.totalSupply().call().await?, U256::from(balance));
    assert_eq!(
        keychain
            .getRemainingLimitWithPeriod(holder, key, address)
            .call()
            .await?
            .remaining,
        U256::from(limit)
    );
    Ok(())
}

fn assert_no_burn_events(logs: &[Log], token: Address) {
    assert!(logs.iter().all(|log| log.address() != token));
    assert!(
        logs.iter()
            .filter_map(|log| IAccountKeychain::AccessKeySpend::decode_log(&log.inner).ok())
            .all(|event| event.token != token)
    );
}

fn assert_access_key_spend(
    logs: &[Log],
    token: Address,
    holder: Address,
    key: Address,
    amount: u64,
    remaining: u64,
) {
    let spends: Vec<_> = logs
        .iter()
        .filter(|log| log.address() == ACCOUNT_KEYCHAIN_ADDRESS)
        .filter_map(|log| IAccountKeychain::AccessKeySpend::decode_log(&log.inner).ok())
        .filter(|event| event.token == token)
        .collect();
    assert_eq!(spends.len(), 1);
    assert_eq!(spends[0].account, holder);
    assert_eq!(spends[0].publicKey, key);
    assert_eq!(spends[0].amount, U256::from(amount));
    assert_eq!(spends[0].remainingLimit, U256::from(remaining));
}

fn run_burn_at_test<F, Fut>(seed: u64, t12_time: u64, test: F)
where
    F: FnOnce(Url) -> Fut + Send + 'static,
    Fut: Future<Output = eyre::Result<()>> + Send + 'static,
{
    let _ = tempo_eyre::install();
    Runner::from(Config::default().with_seed(seed)).start(|mut context| async move {
        let setup = Setup::new(crate::VERIFICATION_MODE)
            .how_many_signers(1)
            .epoch_length(100)
            .seed(seed)
            .t12_time(t12_time);
        let (mut nodes, execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;
        let url = nodes[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();
        execution_runtime
            .run_async(async move {
                tokio::time::timeout(Duration::from_secs(90), test(url)).await??;
                eyre::Ok(())
            })
            .await
            .unwrap()
            .unwrap();
    });
}

fn assert_burn_events(logs: &[Log], token: Address, burner: Address, from: Address, amount: U256) {
    let logs: Vec<_> = logs.iter().filter(|log| log.address() == token).collect();
    assert_eq!(logs.len(), 2);
    let transfer = ITIP20::Transfer::decode_log(&logs[0].inner).unwrap();
    assert_eq!(
        (transfer.from, transfer.to, transfer.amount),
        (from, Address::ZERO, amount)
    );
    let burn = ITIP20::BurnAt::decode_log(&logs[1].inner).unwrap();
    assert_eq!(
        (burn.burner, burn.from, burn.amount),
        (burner, from, amount)
    );
    assert_eq!(
        logs[1].topics(),
        &[
            keccak256("BurnAt(address,address,uint256)"),
            burner.into_word(),
            from.into_word(),
            B256::from(amount.to_be_bytes::<32>())
        ]
    );
    assert!(logs[1].inner.data.data.is_empty());
}
