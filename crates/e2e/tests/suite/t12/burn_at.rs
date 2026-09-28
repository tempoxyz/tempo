//! TIP-1006 through signed RPC transactions, consensus, and committed execution state.

use std::{future::Future, time::Duration};

use alloy::{
    eips::Encodable2718,
    network::ReceiptResponse,
    primitives::{Address, B256, Bytes, TxKind, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Log, TransactionReceipt, TransactionRequest},
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
use tempo_alloy::TempoNetwork;
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
        send_call(
            &provider,
            address,
            IRolesAuth::grantRoleCall {
                role: BURN_AT_ROLE,
                account: admin,
            },
            true,
        )
        .await?;
        send_call(
            &provider,
            address,
            ITIP20::mintCall {
                to: admin,
                amount: U256::from(10),
            },
            true,
        )
        .await?;

        assert!(token.BURN_AT_ROLE().call().await.is_err());
        send_call(
            &provider,
            address,
            ITIP20::burnAtCall {
                from: admin,
                amount: U256::ONE,
            },
            false,
        )
        .await?;
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
        send_call(
            &provider,
            address,
            ITIP20::mintCall {
                to: holder,
                amount: U256::from(100),
            },
            true,
        )
        .await?;
        assert_eq!(
            token.BURN_AT_ROLE().call().await?,
            keccak256("BURN_AT_ROLE")
        );

        // ISSUER_ROLE and BURN_BLOCKED_ROLE do not authorize burnAt.
        send_call(
            &provider,
            address,
            ITIP20::burnAtCall {
                from: holder,
                amount: U256::ONE,
            },
            false,
        )
        .await?;
        send_call(
            &provider,
            address,
            IRolesAuth::grantRoleCall {
                role: BURN_BLOCKED_ROLE,
                account: admin,
            },
            true,
        )
        .await?;
        send_call(
            &provider,
            address,
            ITIP20::burnAtCall {
                from: holder,
                amount: U256::ONE,
            },
            false,
        )
        .await?;
        for role in [BURN_AT_ROLE, PAUSE_ROLE, UNPAUSE_ROLE] {
            send_call(
                &provider,
                address,
                IRolesAuth::grantRoleCall {
                    role,
                    account: admin,
                },
                true,
            )
            .await?;
        }

        let mut remaining = U256::from(100);
        for policy in [ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID] {
            send_call(
                &provider,
                address,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy,
                },
                true,
            )
            .await?;
            let receipt = send_call(
                &provider,
                address,
                ITIP20::burnAtCall {
                    from: holder,
                    amount: U256::from(20),
                },
                true,
            )
            .await?;
            assert_burn_events(receipt.logs(), address, admin, holder, U256::from(20));
            remaining -= U256::from(20);
            assert_eq!(token.balanceOf(holder).call().await?, remaining);
            assert_eq!(token.totalSupply().call().await?, remaining);
        }
        let zero = send_call(
            &provider,
            address,
            ITIP20::burnAtCall {
                from: holder,
                amount: U256::ZERO,
            },
            true,
        )
        .await?;
        assert_burn_events(zero.logs(), address, admin, holder, U256::ZERO);
        send_call(
            &provider,
            address,
            ITIP20::burnAtCall {
                from: holder,
                amount: remaining + U256::ONE,
            },
            false,
        )
        .await?;

        send_call(&provider, address, ITIP20::pauseCall {}, true).await?;
        send_call(
            &provider,
            address,
            ITIP20::burnAtCall {
                from: holder,
                amount: U256::ONE,
            },
            false,
        )
        .await?;
        send_call(&provider, address, ITIP20::unpauseCall {}, true).await?;

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
            send_call(
                &provider,
                address,
                ITIP20::burnAtCall {
                    from,
                    amount: U256::ZERO,
                },
                false,
            )
            .await?;
            send_call(
                &provider,
                address,
                ITIP20::burnBlockedCall {
                    from,
                    amount: U256::ZERO,
                },
                false,
            )
            .await?;
        }
        send_call(
            &provider,
            address,
            IRolesAuth::revokeRoleCall {
                role: BURN_AT_ROLE,
                account: admin,
            },
            true,
        )
        .await?;
        send_call(
            &provider,
            address,
            ITIP20::burnAtCall {
                from: holder,
                amount: U256::ONE,
            },
            false,
        )
        .await?;
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
        send_call(
            &provider,
            address,
            ITIP20::mintCall {
                to: holder,
                amount: U256::from(40),
            },
            true,
        )
        .await?;
        let bridge = deploy_bridge(&provider, address, false).await?;
        let reverting_bridge = deploy_bridge(&provider, address, true).await?;
        for account in [bridge, reverting_bridge] {
            send_call(
                &provider,
                address,
                IRolesAuth::grantRoleCall {
                    role: BURN_AT_ROLE,
                    account,
                },
                true,
            )
            .await?;
        }

        let key = PrivateKeySigner::random();
        send_call(
            &provider,
            ACCOUNT_KEYCHAIN_ADDRESS,
            IAccountKeychain::authorizeKey_1Call {
                keyId: key.address(),
                signatureType: IAccountKeychain::SignatureType::Secp256k1,
                config: IAccountKeychain::KeyRestrictions {
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
            },
            true,
        )
        .await?;
        let keychain = IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, &provider);
        let chain_id = provider.get_chain_id().await?;

        for (target, amount, refill, succeeds, balance, limit) in [
            (bridge, 50, 0, false, 40, 100), // Sufficient limit, insufficient balance: deduction rolls back.
            (bridge, 20, 0, true, 20, 80),
            (reverting_bridge, 10, 0, false, 20, 80), // Enclosing revert restores a successful child burn.
            (bridge, 81, 100, false, 120, 80), // Sufficient balance, insufficient access-key limit.
            (bridge, 0, 0, true, 120, 80),
        ] {
            if refill > 0 {
                // Raw access-key transactions also advance the root account's nonce.
                let receipt = token
                    .mint(holder, U256::from(refill))
                    .nonce(provider.get_transaction_count(holder).await?)
                    .gas(GAS)
                    .gas_price(GAS_PRICE)
                    .send()
                    .await?
                    .get_receipt()
                    .await?;
                assert!(receipt.status());
            }
            let amount = U256::from(amount);
            let tx = TempoTransaction {
                chain_id,
                gas_limit: GAS,
                max_fee_per_gas: GAS_PRICE,
                fee_token: Some(PATH_USD_ADDRESS),
                nonce: provider.get_transaction_count(holder).await?,
                calls: vec![Call {
                    to: TxKind::Call(target),
                    value: U256::ZERO,
                    input: ITIP20::burnAtCall {
                        from: holder,
                        amount,
                    }
                    .abi_encode()
                    .into(),
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
            let receipt = aa_provider
                .send_raw_transaction(&envelope.encoded_2718())
                .await?
                .get_receipt()
                .await?;
            assert_eq!(receipt.status(), succeeds, "burn {amount}: {receipt:#?}");
            if succeeds {
                assert_burn_events(receipt.logs(), address, target, holder, amount);
            } else {
                assert!(receipt.logs().iter().all(|log| log.address() != address));
            }
            let spends: Vec<_> = receipt
                .logs()
                .iter()
                .filter(|log| log.address() == ACCOUNT_KEYCHAIN_ADDRESS)
                .filter_map(|log| IAccountKeychain::AccessKeySpend::decode_log(&log.inner).ok())
                .filter(|event| event.token == address)
                .collect();
            assert_eq!(spends.len(), usize::from(succeeds));
            if let Some(spend) = spends.first() {
                assert_eq!(spend.amount, amount);
                assert_eq!(spend.remainingLimit, U256::from(limit));
            }
            assert_eq!(token.balanceOf(holder).call().await?, U256::from(balance));
            assert_eq!(token.totalSupply().call().await?, U256::from(balance));
            assert_eq!(
                keychain
                    .getRemainingLimitWithPeriod(holder, key.address(), address)
                    .call()
                    .await?
                    .remaining,
                U256::from(limit)
            );
        }
        Ok(())
    });
}

fn run_burn_at_test<F, Fut>(seed: u64, t12_time: u64, test: F)
where
    F: FnOnce(Url) -> Fut + Send + 'static,
    Fut: Future<Output = eyre::Result<()>> + Send + 'static,
{
    let _ = tempo_eyre::install();
    Runner::from(Config::default().with_seed(seed)).start(|mut context| async move {
        let setup = Setup::new()
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

async fn send_call<P: Provider, C: SolCall>(
    provider: &P,
    to: Address,
    call: C,
    succeeds: bool,
) -> eyre::Result<TransactionReceipt> {
    let receipt = provider
        .send_transaction(TransactionRequest {
            to: Some(TxKind::Call(to)),
            input: call.abi_encode().into(),
            gas: Some(GAS),
            gas_price: Some(GAS_PRICE),
            ..Default::default()
        })
        .await?
        .get_receipt()
        .await?;
    assert_eq!(receipt.status(), succeeds, "{}: {receipt:#?}", C::SIGNATURE);
    if !succeeds {
        assert!(receipt.logs().iter().all(|log| log.address() != to));
    }
    Ok(receipt)
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

async fn deploy_bridge(
    provider: &impl Provider,
    token: Address,
    revert_after_burn: bool,
) -> eyre::Result<Address> {
    // Forward calldata via CALL and bubble failures. Optionally revert after a successful burn.
    let mut runtime = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x5f, 0x73];
    runtime.extend_from_slice(token.as_slice());
    runtime.extend_from_slice(&[0x5a, 0xf1, 0x3d, 0x5f, 0x5f, 0x3e]);
    let success = u8::try_from(runtime.len() + 6)?;
    runtime.extend_from_slice(&[0x60, success, 0x57, 0x3d, 0x5f, 0xfd, 0x5b, 0x3d, 0x5f]);
    runtime.push(if revert_after_burn { 0xfd } else { 0xf3 });
    let len = u8::try_from(runtime.len())?;
    let mut init = vec![0x60, len, 0x60, 12, 0x60, 0, 0x39, 0x60, len, 0x60, 0, 0xf3];
    init.extend_from_slice(&runtime);
    let receipt = provider
        .send_transaction(TransactionRequest {
            to: Some(TxKind::Create),
            input: Bytes::from(init).into(),
            gas: Some(GAS),
            gas_price: Some(GAS_PRICE),
            ..Default::default()
        })
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    let address = receipt.contract_address.expect("bridge deployment address");
    assert_eq!(provider.get_code_at(address).await?.as_ref(), runtime);
    Ok(address)
}
