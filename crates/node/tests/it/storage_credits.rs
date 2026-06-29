use crate::utils::{TEST_MNEMONIC, TestNodeBuilder, setup_test_token};
use alloy::{
    network::ReceiptResponse,
    primitives::{Address, B256, Bytes, U256, aliases::U96},
    providers::{Provider, ProviderBuilder},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
    sol_types::{SolCall, SolEvent},
};
use alloy_eips::{BlockId, Encodable2718};
use alloy_rpc_types_eth::{TransactionReceipt, TransactionRequest};
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, IFeeManager, IReceivePolicyGuard, IStorageCredits, ITIP20,
    ITIP20ChannelReserve, ITIP403Registry, ITIPFeeAMM,
    account_keychain::IAccountKeychain::{
        IAccountKeychainInstance, KeyRestrictions, SignatureType, TokenLimit, revokeKeyCall,
    },
    authorizeKeyCall,
};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, PATH_USD_ADDRESS, RECEIVE_POLICY_GUARD_ADDRESS,
    STORAGE_CREDITS_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS,
    TIP403_REGISTRY_ADDRESS,
    tip403_registry::{ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID},
};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{
        calc_gas_balance_spending,
        tempo_transaction::Call,
        tt_signature::{KeychainSignature, PrimitiveSignature, TempoSignature},
    },
};

async fn wait_for_latest_beneficiary<P: Provider>(
    provider: &P,
    expected: Address,
) -> eyre::Result<()> {
    for _ in 0..30 {
        let beneficiary = provider
            .get_block(BlockId::latest())
            .await?
            .ok_or_else(|| eyre::eyre!("latest block missing"))?
            .header
            .beneficiary;
        if beneficiary == expected {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let beneficiary = provider
        .get_block(BlockId::latest())
        .await?
        .ok_or_else(|| eyre::eyre!("latest block missing"))?
        .header
        .beneficiary;
    eyre::bail!("latest beneficiary {beneficiary:?} did not become {expected:?}")
}

fn transfer_blocked(
    receipt: &TransactionReceipt,
) -> eyre::Result<IReceivePolicyGuard::TransferBlocked> {
    receipt
        .logs()
        .iter()
        .find_map(|log| IReceivePolicyGuard::TransferBlocked::decode_log(&log.inner).ok())
        .map(|event| event.data)
        .ok_or_else(|| eyre::eyre!("TransferBlocked event missing"))
}

async fn send_tempo_tx<P: Provider>(
    provider: &P,
    signer: &PrivateKeySigner,
    tx: TempoTransaction,
) -> eyre::Result<TempoTransactionReceipt> {
    let sig = signer.sign_hash_sync(&tx.signature_hash())?;
    let envelope: TempoTxEnvelope = tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            sig,
        )))
        .into();
    let tx_hash = provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .watch()
        .await?;

    provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await
        .map_err(Into::into)
}

/// Regression for the TIP-1060 fee-collection path reported in PR review.
///
/// This exercises the full node/RPC path rather than seeding mocked EVM state:
/// - authorize an access key with a fee-token limit equal to the tx max fee,
/// - submit a failing keychain AA transaction so fee precharge clears the limit slot,
/// - let post-execution reimbursement restore the unused limit,
/// - assert the keychain did not retain a storage credit from fee bookkeeping.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_keychain_fee_refund_does_not_retain_storage_credit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let root = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root.address();
    let provider = ProviderBuilder::new()
        .wallet(root.clone())
        .connect_http(setup.http_url);
    let access_key = PrivateKeySigner::random();

    let gas_limit = 500_000u64;
    let gas_price = 1_000_000_000_000u128;
    let max_fee = U256::from(gas_limit);

    let authorize = authorizeKeyCall {
        keyId: access_key.address(),
        signatureType: SignatureType::Secp256k1,
        config: KeyRestrictions {
            expiry: u64::MAX,
            enforceLimits: true,
            limits: vec![TokenLimit {
                token: DEFAULT_FEE_TOKEN,
                amount: max_fee,
                period: 0,
            }],
            allowAnyCalls: true,
            allowedCalls: vec![],
        },
    };
    let authorize_hash = provider
        .send_transaction(
            TransactionRequest::default()
                .to(ACCOUNT_KEYCHAIN_ADDRESS)
                .input(authorize.abi_encode().into())
                .gas_limit(2_000_000),
        )
        .await?
        .watch()
        .await?;
    let authorize_receipt = provider
        .raw_request::<_, TempoTransactionReceipt>(
            "eth_getTransactionReceipt".into(),
            (authorize_hash,),
        )
        .await?;
    assert!(
        authorize_receipt.status(),
        "access-key authorization must succeed"
    );

    let keychain = IAccountKeychainInstance::new(ACCOUNT_KEYCHAIN_ADDRESS, &provider);
    let credits = IStorageCredits::new(STORAGE_CREDITS_ADDRESS, &provider);

    let remaining_before = keychain
        .getRemainingLimitWithPeriod(root_addr, access_key.address(), DEFAULT_FEE_TOKEN)
        .call()
        .await?
        .remaining;
    let credit_before = credits.balanceOf(ACCOUNT_KEYCHAIN_ADDRESS).call().await?;
    assert_eq!(remaining_before, max_fee);

    let tx = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        nonce: provider.get_transaction_count(root_addr).await?,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit,
        calls: vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: revokeKeyCall {
                keyId: Address::repeat_byte(0xee),
            }
            .abi_encode()
            .into(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        ..Default::default()
    };

    let keychain_hash = KeychainSignature::signing_hash(tx.signature_hash(), root_addr);
    let access_signature = access_key.sign_hash_sync(&keychain_hash)?;
    let envelope: TempoTxEnvelope = tx
        .into_signed(TempoSignature::Keychain(KeychainSignature::new(
            root_addr,
            PrimitiveSignature::Secp256k1(access_signature),
        )))
        .into();

    let tx_hash = provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await?;
    assert!(
        !receipt.status(),
        "the access-key AA transaction must commit the user-call failure path"
    );

    let remaining_after = keychain
        .getRemainingLimitWithPeriod(root_addr, access_key.address(), DEFAULT_FEE_TOKEN)
        .call()
        .await?
        .remaining;
    let credit_after = credits.balanceOf(ACCOUNT_KEYCHAIN_ADDRESS).call().await?;

    assert!(
        !remaining_after.is_zero() && remaining_after < max_fee,
        "post-tx fee refund must restore the keychain spending-limit slot"
    );
    assert_eq!(
        credit_after, credit_before,
        "fee precharge/reimbursement bookkeeping must not change keychain storage credits"
    );

    Ok(())
}

/// Regression: #6206's non-creditable slot set must also protect the FeeManager's AMM custody
/// balance. A fee paid in custom token `T` recreates `TIP20(T).balances[TIP_FEE_MANAGER_ADDRESS]`
/// with TIP-1060 disabled; a later public `rebalanceSwap` must not clear that same slot under
/// normal accounting and leave a stale credit.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_rebalance_swap_does_not_mint_stale_fee_manager_custody_credit()
-> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let root = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root.address();
    let root_provider = ProviderBuilder::new()
        .wallet(root.clone())
        .connect_http(setup.http_url.clone());

    let attacker = PrivateKeySigner::random();
    let attacker_addr = attacker.address();
    let attacker_provider = ProviderBuilder::new()
        .wallet(attacker.clone())
        .connect_http(setup.http_url);

    let fee_token = setup_test_token(root_provider.clone(), root_addr).await?;
    let fee_token_addr = *fee_token.address();
    let validator_token = ITIP20::new(PATH_USD_ADDRESS, root_provider.clone());
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, root_provider.clone());
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, root_provider.clone());
    let credits = IStorageCredits::new(STORAGE_CREDITS_ADDRESS, &root_provider);

    let liquidity = U256::from(1_000_000_000_000_000_000u128);
    assert!(
        fee_token
            .mint(root_addr, liquidity)
            .send()
            .await?
            .get_receipt()
            .await?
            .status()
    );

    // Seed the rebalance recipient's `T` balance so the FeeManager -> attacker transfer does not
    // create a new token balance slot that could consume the credit minted by clearing custody.
    assert!(
        fee_token
            .mint(attacker_addr, U256::ONE)
            .send()
            .await?
            .get_receipt()
            .await?
            .status()
    );

    // The attacker pays the rebalance tx fees and validator-token input in PATH_USD, not `T`.
    assert!(
        validator_token
            .transfer(attacker_addr, liquidity)
            .send()
            .await?
            .get_receipt()
            .await?
            .status()
    );

    assert!(
        fee_amm
            .mint(fee_token_addr, PATH_USD_ADDRESS, liquidity, root_addr)
            .send()
            .await?
            .get_receipt()
            .await?
            .status()
    );
    assert!(
        fee_manager
            .setUserToken(fee_token_addr)
            .send()
            .await?
            .get_receipt()
            .await?
            .status()
    );

    let custody_before_fee = fee_token.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    let pool_before_fee = fee_amm
        .getPool(fee_token_addr, PATH_USD_ADDRESS)
        .call()
        .await?;
    assert_eq!(
        U256::from(pool_before_fee.reserveUserToken),
        custody_before_fee,
        "any setup-time custom-token fees should already be reflected in AMM custody"
    );
    let credit_before = credits.balanceOf(fee_token_addr).call().await?;

    let gas_limit = 500_000u64;
    let gas_price = 1_000_000_000_000u128;
    let fee_tx = TempoTransaction {
        chain_id: root_provider.get_chain_id().await?,
        nonce: root_provider.get_transaction_count(root_addr).await?,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit,
        calls: vec![Call {
            to: STORAGE_CREDITS_ADDRESS.into(),
            value: U256::ZERO,
            input: IStorageCredits::balanceOfCall {
                account: fee_token_addr,
            }
            .abi_encode()
            .into(),
        }],
        fee_token: Some(fee_token_addr),
        ..Default::default()
    };
    let sig = root.sign_hash_sync(&fee_tx.signature_hash())?;
    let envelope: TempoTxEnvelope = fee_tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            sig,
        )))
        .into();
    let fee_tx_hash = root_provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let fee_tx_receipt = root_provider
        .raw_request::<_, TempoTransactionReceipt>(
            "eth_getTransactionReceipt".into(),
            (fee_tx_hash,),
        )
        .await?;
    assert!(fee_tx_receipt.status());

    let custody_balance = fee_token.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert!(custody_balance > custody_before_fee);
    let pool_after_fee = fee_amm
        .getPool(fee_token_addr, PATH_USD_ADDRESS)
        .call()
        .await?;
    assert_eq!(
        U256::from(pool_after_fee.reserveUserToken),
        custody_balance,
        "post-tx fee swap should leave FeeManager custody matching the AMM user-token reserve"
    );
    assert_eq!(
        credits.balanceOf(fee_token_addr).call().await?,
        credit_before,
        "disabled fee collection should not itself mint token storage credits"
    );

    let attacker_fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, attacker_provider.clone());
    let rebalance_receipt = attacker_fee_amm
        .rebalanceSwap(
            fee_token_addr,
            PATH_USD_ADDRESS,
            custody_balance,
            attacker_addr,
        )
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(rebalance_receipt.status());

    assert_eq!(
        fee_token.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?,
        U256::ZERO,
        "rebalanceSwap should drain the FeeManager's custom-token custody balance"
    );
    let credit_after_rebalance = credits.balanceOf(fee_token_addr).call().await?;
    assert_eq!(
        credit_after_rebalance, credit_before,
        "rebalanceSwap must not mint a storage credit for clearing FeeManager custody that fee collection can recreate with accounting disabled"
    );

    let recreate_tx = TempoTransaction {
        chain_id: root_provider.get_chain_id().await?,
        nonce: root_provider.get_transaction_count(root_addr).await?,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit,
        calls: vec![Call {
            to: STORAGE_CREDITS_ADDRESS.into(),
            value: U256::ZERO,
            input: IStorageCredits::balanceOfCall {
                account: fee_token_addr,
            }
            .abi_encode()
            .into(),
        }],
        fee_token: Some(fee_token_addr),
        ..Default::default()
    };
    let sig = root.sign_hash_sync(&recreate_tx.signature_hash())?;
    let envelope: TempoTxEnvelope = recreate_tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            sig,
        )))
        .into();
    let recreate_hash = root_provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let recreate_receipt = root_provider
        .raw_request::<_, TempoTransactionReceipt>(
            "eth_getTransactionReceipt".into(),
            (recreate_hash,),
        )
        .await?;
    assert!(recreate_receipt.status());
    assert!(
        fee_token.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await? > U256::ZERO,
        "later disabled fee collection should recreate FeeManager custody"
    );
    assert_eq!(
        credits.balanceOf(fee_token_addr).call().await?,
        credit_before,
        "disabled fee collection recreates custody without consuming the stale credit"
    );

    let fresh_recipient = Address::repeat_byte(0xf7);
    assert!(
        fee_token
            .mint(fresh_recipient, U256::ONE)
            .nonce(root_provider.get_transaction_count(root_addr).await?)
            .send()
            .await?
            .get_receipt()
            .await?
            .status()
    );
    assert_eq!(
        credits.balanceOf(fee_token_addr).call().await?,
        credit_before,
        "a normal Refund-mode token storage creation must not get subsidized by FeeManager custody churn"
    );

    Ok(())
}

/// FeeManager distribution must not mint a reusable FeeManager credit for the collected-fee clear,
/// and its nested TIP-20 payout must still account for creating the validator's token balance.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_fee_manager_credit_from_distribute_fees_is_not_redeemable() -> eyre::Result<()>
{
    reth_tracing::init_test_tracing();

    let initial_validator = Address::repeat_byte(0x42);
    let dynamic_validator = std::sync::Arc::new(std::sync::Mutex::new(initial_validator));
    let setup = TestNodeBuilder::new()
        .with_dynamic_validator(dynamic_validator.clone())
        .build_http_only()
        .await?;

    let root = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root.address();
    let attacker = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let attacker_addr = attacker.address();
    let validator = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(2)?
        .build()?;
    let validator_addr = validator.address();
    let user = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(3)?
        .build()?;
    let user_addr = user.address();
    let credit_source = PrivateKeySigner::random();
    let credit_source_addr = credit_source.address();

    let provider = ProviderBuilder::new()
        .wallet(root.clone())
        .connect_http(setup.http_url.clone());
    let attacker_provider = ProviderBuilder::new()
        .wallet(attacker)
        .connect_http(setup.http_url.clone());
    let validator_provider = ProviderBuilder::new()
        .wallet(validator)
        .connect_http(setup.http_url.clone());
    let fee_token = setup_test_token(provider.clone(), root_addr).await?;
    let fee_token_addr = *fee_token.address();
    let root_fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let attacker_fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, attacker_provider);
    let validator_fee_manager =
        IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, validator_provider.clone());
    let validator_fee_token = ITIP20::new(fee_token_addr, validator_provider);
    let credits = IStorageCredits::new(STORAGE_CREDITS_ADDRESS, &provider);
    let credit_seed_amount = U256::from(1234u64);

    let path_usd = ITIP20::new(PATH_USD_ADDRESS, provider.clone());
    for recipient in [attacker_addr, validator_addr, user_addr, credit_source_addr] {
        let receipt = path_usd
            .transfer(recipient, U256::from(10_000_000_000u64))
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
    }

    for (recipient, amount) in [
        (root_addr, U256::from(10_000_000_000u64)),
        (user_addr, U256::from(10_000_000_000u64)),
        (credit_source_addr, credit_seed_amount),
    ] {
        let receipt = fee_token
            .mint(recipient, amount)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
    }
    let token_credit_before_seed = credits.balanceOf(fee_token_addr).call().await?;
    let seed_credit_receipt = send_tempo_tx(
        &provider,
        &credit_source,
        TempoTransaction {
            chain_id: provider.get_chain_id().await?,
            nonce: provider.get_transaction_count(credit_source_addr).await?,
            max_priority_fee_per_gas: 1_000_000_000_000u128,
            max_fee_per_gas: 1_000_000_000_000u128,
            gas_limit: 1_000_000,
            calls: vec![Call {
                to: fee_token_addr.into(),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: user_addr,
                    amount: credit_seed_amount,
                }
                .abi_encode()
                .into(),
            }],
            fee_token: Some(DEFAULT_FEE_TOKEN),
            ..Default::default()
        },
    )
    .await?;
    assert!(seed_credit_receipt.status());
    assert_eq!(
        credits.balanceOf(fee_token_addr).call().await?,
        token_credit_before_seed + 1,
        "setup must seed one reusable token storage credit"
    );

    let set_validator_receipt = validator_fee_manager
        .setValidatorToken(fee_token_addr)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(set_validator_receipt.status());

    *dynamic_validator.lock().unwrap() = validator_addr;
    wait_for_latest_beneficiary(&provider, validator_addr).await?;

    let gas_price = 1_000_000_000_000u128;
    let collect_fees_tx = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        nonce: provider.get_transaction_count(root_addr).await?,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit: 500_000,
        calls: vec![Call {
            to: Address::repeat_byte(0x55).into(),
            value: U256::ZERO,
            input: Default::default(),
        }],
        fee_token: Some(fee_token_addr),
        ..Default::default()
    };
    let collect_fees_signature = root.sign_hash_sync(&collect_fees_tx.signature_hash())?;
    let collect_fees_envelope: TempoTxEnvelope = collect_fees_tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            collect_fees_signature,
        )))
        .into();
    let collect_fees_hash = provider
        .send_raw_transaction(&collect_fees_envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let collect_fees_receipt = provider
        .raw_request::<_, TempoTransactionReceipt>(
            "eth_getTransactionReceipt".into(),
            (collect_fees_hash,),
        )
        .await?;
    assert!(collect_fees_receipt.status());
    assert!(
        !root_fee_manager
            .collectedFees(validator_addr, *fee_token.address())
            .call()
            .await?
            .is_zero(),
        "validator must have custom-token fees to distribute"
    );
    assert_eq!(
        fee_token.balanceOf(validator_addr).call().await?,
        U256::ZERO,
        "validator payout balance must start empty so distributeFees creates it"
    );

    *dynamic_validator.lock().unwrap() = initial_validator;
    wait_for_latest_beneficiary(&provider, initial_validator).await?;

    let token_credit_before_distribute = credits.balanceOf(fee_token_addr).call().await?;
    assert!(
        token_credit_before_distribute > 0,
        "direct payout regression requires a token credit to settle against"
    );
    let fee_manager_credit_before_distribute =
        credits.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    let distribute_receipt = attacker_fee_manager
        .distributeFees(validator_addr, fee_token_addr)
        .gas(2_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(distribute_receipt.status());
    assert_eq!(
        root_fee_manager
            .collectedFees(validator_addr, *fee_token.address())
            .call()
            .await?,
        U256::ZERO,
        "distributeFees must clear collectedFees[V][T]"
    );
    let fee_manager_credit_after_distribute =
        credits.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    let validator_payout = fee_token.balanceOf(validator_addr).call().await?;
    assert!(
        validator_payout > U256::ZERO,
        "distributeFees must pay the validator"
    );
    assert_eq!(
        credits.balanceOf(fee_token_addr).call().await?,
        token_credit_before_distribute - 1,
        "the FeeManager -> validator payout balance creation must consume a token storage credit"
    );
    let validator_drain_receipt = validator_fee_token
        .transfer(user_addr, validator_payout)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(validator_drain_receipt.status());
    assert_eq!(
        fee_token.balanceOf(validator_addr).call().await?,
        U256::ZERO,
        "validator must be able to clear the full distributed payout"
    );
    assert_eq!(
        credits.balanceOf(fee_token_addr).call().await?,
        token_credit_before_distribute,
        "clearing the distributed validator balance must restore only the credit consumed by payout creation"
    );

    *dynamic_validator.lock().unwrap() = validator_addr;
    wait_for_latest_beneficiary(&provider, validator_addr).await?;

    let user_nonce = provider.get_transaction_count(user_addr).await?;
    let recreate_collected_fees_tx = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        nonce: user_nonce,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit: 500_000,
        calls: vec![Call {
            to: Address::repeat_byte(0x56).into(),
            value: U256::ZERO,
            input: Default::default(),
        }],
        fee_token: Some(*fee_token.address()),
        ..Default::default()
    };
    let recreate_signature = user.sign_hash_sync(&recreate_collected_fees_tx.signature_hash())?;
    let recreate_envelope: TempoTxEnvelope = recreate_collected_fees_tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            recreate_signature,
        )))
        .into();
    let recreate_hash = provider
        .send_raw_transaction(&recreate_envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let recreate_receipt = provider
        .raw_request::<_, TempoTransactionReceipt>(
            "eth_getTransactionReceipt".into(),
            (recreate_hash,),
        )
        .await?;
    assert!(recreate_receipt.status());
    assert!(
        !root_fee_manager
            .collectedFees(validator_addr, *fee_token.address())
            .call()
            .await?
            .is_zero(),
        "post-tx fee collection must recreate collectedFees[V][T]"
    );
    let fee_manager_credit_after_recreate =
        credits.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(
        fee_manager_credit_after_recreate, fee_manager_credit_after_distribute,
        "disabled post-tx fee collection must not redeem the FeeManager credit"
    );

    assert_eq!(
        fee_manager_credit_before_distribute, fee_manager_credit_after_distribute,
        "distributeFees must not mint a FeeManager storage credit"
    );

    Ok(())
}

/// Regression: when a validator's receive policy blocks a FeeManager distribution, the nested
/// transfer creates both TIP20(T).balances[ReceivePolicyGuard] and
/// ReceivePolicyGuard.balances[receipt]. Those creations must be accounted even though
/// distributeFees disables storage-credit minting for FeeManager-owned clears.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_distribute_fees_receive_policy_guard_creations_are_accounted()
-> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let initial_validator = Address::repeat_byte(0x64);
    let dynamic_validator = std::sync::Arc::new(std::sync::Mutex::new(initial_validator));
    let setup = TestNodeBuilder::new()
        .with_dynamic_validator(dynamic_validator.clone())
        .build_http_only()
        .await?;

    let root = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root.address();
    let validator = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(4)?
        .build()?;
    let validator_addr = validator.address();
    let user = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(5)?
        .build()?;
    let user_addr = user.address();
    let dummy_receiver = PrivateKeySigner::random();
    let dummy_receiver_addr = dummy_receiver.address();
    let credit_source = PrivateKeySigner::random();
    let credit_source_addr = credit_source.address();

    let provider = ProviderBuilder::new()
        .wallet(root.clone())
        .connect_http(setup.http_url.clone());
    let validator_provider = ProviderBuilder::new()
        .wallet(validator)
        .connect_http(setup.http_url.clone());
    let dummy_provider = ProviderBuilder::new()
        .wallet(dummy_receiver)
        .connect_http(setup.http_url.clone());
    let fee_token = setup_test_token(provider.clone(), root_addr).await?;
    let fee_token_addr = *fee_token.address();
    let path_usd = ITIP20::new(PATH_USD_ADDRESS, &provider);
    let root_fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let validator_fee_manager =
        IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, validator_provider.clone());
    let validator_registry =
        ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, validator_provider.clone());
    let dummy_registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, dummy_provider.clone());
    let validator_guard =
        IReceivePolicyGuard::new(RECEIVE_POLICY_GUARD_ADDRESS, validator_provider.clone());
    let dummy_guard = IReceivePolicyGuard::new(RECEIVE_POLICY_GUARD_ADDRESS, dummy_provider);
    let root_guard = IReceivePolicyGuard::new(RECEIVE_POLICY_GUARD_ADDRESS, provider.clone());
    let credits = IStorageCredits::new(STORAGE_CREDITS_ADDRESS, &provider);

    for recipient in [
        validator_addr,
        user_addr,
        dummy_receiver_addr,
        credit_source_addr,
    ] {
        let receipt = path_usd
            .transfer(recipient, U256::from(10_000_000_000u64))
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
    }

    let root_mint_receipt = fee_token
        .mint(root_addr, U256::from(10_000_000_000u64))
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(root_mint_receipt.status());
    let user_mint_receipt = fee_token
        .mint(user_addr, U256::ONE)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(user_mint_receipt.status());
    let validator_seed_receipt = fee_token
        .mint(validator_addr, U256::ONE)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(validator_seed_receipt.status());

    let set_validator_receipt = validator_fee_manager
        .setValidatorToken(fee_token_addr)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(set_validator_receipt.status());
    let validator_policy_receipt = validator_registry
        .setReceivePolicy(REJECT_ALL_POLICY_ID, ALLOW_ALL_POLICY_ID, validator_addr)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(validator_policy_receipt.status());

    *dynamic_validator.lock().unwrap() = validator_addr;
    wait_for_latest_beneficiary(&provider, validator_addr).await?;

    let gas_price = 1_000_000_000_000u128;
    let collect_fees_tx = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        nonce: provider.get_transaction_count(root_addr).await?,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit: 500_000,
        calls: vec![Call {
            to: Address::repeat_byte(0x65).into(),
            value: U256::ZERO,
            input: Default::default(),
        }],
        fee_token: Some(fee_token_addr),
        ..Default::default()
    };
    let collect_fees_signature = root.sign_hash_sync(&collect_fees_tx.signature_hash())?;
    let collect_fees_envelope: TempoTxEnvelope = collect_fees_tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            collect_fees_signature,
        )))
        .into();
    let collect_fees_hash = provider
        .send_raw_transaction(&collect_fees_envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let collect_fees_receipt = provider
        .raw_request::<_, TempoTransactionReceipt>(
            "eth_getTransactionReceipt".into(),
            (collect_fees_hash,),
        )
        .await?;
    assert!(collect_fees_receipt.status());
    let payout_amount = root_fee_manager
        .collectedFees(validator_addr, fee_token_addr)
        .call()
        .await?;
    assert!(
        payout_amount > U256::ZERO,
        "validator must have custom-token fees to distribute"
    );

    *dynamic_validator.lock().unwrap() = initial_validator;
    wait_for_latest_beneficiary(&provider, initial_validator).await?;

    let credit_seed_amount = U256::from(4321u64);
    let source_mint_receipt = fee_token
        .mint(credit_source_addr, credit_seed_amount)
        .nonce(provider.get_transaction_count(root_addr).await?)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(source_mint_receipt.status());
    let token_credit_before_seed = credits.balanceOf(fee_token_addr).call().await?;
    let seed_token_credit_receipt = send_tempo_tx(
        &provider,
        &credit_source,
        TempoTransaction {
            chain_id: provider.get_chain_id().await?,
            nonce: provider.get_transaction_count(credit_source_addr).await?,
            max_priority_fee_per_gas: 1_000_000_000_000u128,
            max_fee_per_gas: 1_000_000_000_000u128,
            gas_limit: 1_000_000,
            calls: vec![Call {
                to: fee_token_addr.into(),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: user_addr,
                    amount: credit_seed_amount,
                }
                .abi_encode()
                .into(),
            }],
            fee_token: Some(DEFAULT_FEE_TOKEN),
            ..Default::default()
        },
    )
    .await?;
    assert!(seed_token_credit_receipt.status());
    assert_eq!(
        credits.balanceOf(fee_token_addr).call().await?,
        token_credit_before_seed + 1,
        "setup must seed one reusable fee-token storage credit"
    );

    let dummy_policy_receipt = dummy_registry
        .setReceivePolicy(
            REJECT_ALL_POLICY_ID,
            ALLOW_ALL_POLICY_ID,
            dummy_receiver_addr,
        )
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(dummy_policy_receipt.status());
    let blocked_seed_receipt = path_usd
        .transfer(dummy_receiver_addr, U256::ONE)
        .nonce(provider.get_transaction_count(root_addr).await?)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(blocked_seed_receipt.status());
    let blocked_seed = transfer_blocked(&blocked_seed_receipt)?;
    let claim_seed_receipt = dummy_guard
        .claim(dummy_receiver_addr, blocked_seed.receipt.clone())
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(claim_seed_receipt.status());
    assert_eq!(
        root_guard
            .balanceOf(blocked_seed.receipt.clone())
            .call()
            .await?,
        U256::ZERO,
        "setup claim must clear the seeded guard receipt"
    );

    let token_credit_before_distribute = credits.balanceOf(fee_token_addr).call().await?;
    let guard_credit_before_distribute = credits
        .balanceOf(RECEIVE_POLICY_GUARD_ADDRESS)
        .call()
        .await?;
    assert!(
        token_credit_before_distribute > 0,
        "receive-policy regression requires a token credit to settle against"
    );
    assert!(
        guard_credit_before_distribute > 0,
        "receive-policy regression requires a guard credit to settle against"
    );
    assert_eq!(
        fee_token
            .balanceOf(RECEIVE_POLICY_GUARD_ADDRESS)
            .call()
            .await?,
        U256::ZERO,
        "fee token guard custody must start empty before the blocked distribution"
    );

    let distribute_receipt = root_fee_manager
        .distributeFees(validator_addr, fee_token_addr)
        .nonce(provider.get_transaction_count(root_addr).await?)
        .gas(2_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(distribute_receipt.status());
    let blocked_distribution = transfer_blocked(&distribute_receipt)?;
    assert_eq!(blocked_distribution.token, fee_token_addr);
    assert_eq!(blocked_distribution.receiver, validator_addr);
    assert_eq!(blocked_distribution.amount, payout_amount);
    assert_eq!(
        root_fee_manager
            .collectedFees(validator_addr, fee_token_addr)
            .call()
            .await?,
        U256::ZERO,
        "distributeFees must clear collectedFees[V][T]"
    );
    assert_eq!(
        fee_token
            .balanceOf(RECEIVE_POLICY_GUARD_ADDRESS)
            .call()
            .await?,
        payout_amount,
        "blocked FeeManager payout must move fee-token custody to the guard"
    );
    assert_eq!(
        root_guard
            .balanceOf(blocked_distribution.receipt.clone())
            .call()
            .await?,
        payout_amount,
        "blocked FeeManager payout must create a guard receipt balance"
    );
    assert_eq!(
        credits.balanceOf(fee_token_addr).call().await?,
        token_credit_before_distribute - 1,
        "guard fee-token balance creation must consume a token storage credit"
    );
    assert_eq!(
        credits
            .balanceOf(RECEIVE_POLICY_GUARD_ADDRESS)
            .call()
            .await?,
        guard_credit_before_distribute - 1,
        "guard receipt creation must consume a ReceivePolicyGuard storage credit"
    );

    let claim_distribution_receipt = validator_guard
        .claim(validator_addr, blocked_distribution.receipt.clone())
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(claim_distribution_receipt.status());
    assert_eq!(
        fee_token
            .balanceOf(RECEIVE_POLICY_GUARD_ADDRESS)
            .call()
            .await?,
        U256::ZERO,
        "claiming the blocked payout must clear fee-token guard custody"
    );
    assert_eq!(
        root_guard
            .balanceOf(blocked_distribution.receipt.clone())
            .call()
            .await?,
        U256::ZERO,
        "claiming the blocked payout must clear the guard receipt"
    );
    assert_eq!(
        fee_token.balanceOf(validator_addr).call().await?,
        payout_amount + U256::ONE,
        "claim should release the blocked payout to the seeded validator balance"
    );
    assert_eq!(
        credits.balanceOf(fee_token_addr).call().await?,
        token_credit_before_distribute,
        "clearing guard fee-token custody must only restore the credit consumed by blocked payout creation"
    );
    assert_eq!(
        credits
            .balanceOf(RECEIVE_POLICY_GUARD_ADDRESS)
            .call()
            .await?,
        guard_credit_before_distribute,
        "clearing the guard receipt must only restore the credit consumed by blocked payout creation"
    );

    Ok(())
}

/// Successful access-key fee refunds must cancel a TIP-1060 credit minted by a same-tx user spend
/// if post-tx reimbursement recreates the keychain spending-limit slot.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_successful_keychain_spend_fee_refund_cancels_restored_limit_credit()
-> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let root = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root.address();
    let provider = ProviderBuilder::new()
        .wallet(root.clone())
        .connect_http(setup.http_url);
    let access_key = PrivateKeySigner::random();

    let gas_limit = 500_000u64;
    let gas_price = 1_000_000_000_000u128;
    let max_fee = calc_gas_balance_spending(gas_limit, gas_price);
    let transfer_amount = U256::from(1_234u64);
    let spending_limit = max_fee + transfer_amount;
    let recipient = Address::repeat_byte(0xcc);

    let authorize = authorizeKeyCall {
        keyId: access_key.address(),
        signatureType: SignatureType::Secp256k1,
        config: KeyRestrictions {
            expiry: u64::MAX,
            enforceLimits: true,
            limits: vec![TokenLimit {
                token: DEFAULT_FEE_TOKEN,
                amount: spending_limit,
                period: 0,
            }],
            allowAnyCalls: true,
            allowedCalls: vec![],
        },
    };
    let authorize_hash = provider
        .send_transaction(
            TransactionRequest::default()
                .to(ACCOUNT_KEYCHAIN_ADDRESS)
                .input(authorize.abi_encode().into())
                .gas_limit(2_000_000),
        )
        .await?
        .watch()
        .await?;
    let authorize_receipt = provider
        .raw_request::<_, TempoTransactionReceipt>(
            "eth_getTransactionReceipt".into(),
            (authorize_hash,),
        )
        .await?;
    assert!(authorize_receipt.status());

    let keychain = IAccountKeychainInstance::new(ACCOUNT_KEYCHAIN_ADDRESS, &provider);
    let credits = IStorageCredits::new(STORAGE_CREDITS_ADDRESS, &provider);

    let remaining_before = keychain
        .getRemainingLimitWithPeriod(root_addr, access_key.address(), DEFAULT_FEE_TOKEN)
        .call()
        .await?
        .remaining;
    let credit_before = credits.balanceOf(ACCOUNT_KEYCHAIN_ADDRESS).call().await?;
    assert_eq!(remaining_before, spending_limit);

    let tx = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        nonce: provider.get_transaction_count(root_addr).await?,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: recipient,
                amount: transfer_amount,
            }
            .abi_encode()
            .into(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        ..Default::default()
    };

    let keychain_hash = KeychainSignature::signing_hash(tx.signature_hash(), root_addr);
    let access_signature = access_key.sign_hash_sync(&keychain_hash)?;
    let envelope: TempoTxEnvelope = tx
        .into_signed(TempoSignature::Keychain(KeychainSignature::new(
            root_addr,
            PrimitiveSignature::Secp256k1(access_signature),
        )))
        .into();

    let tx_hash = provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await?;
    assert!(receipt.status());

    let remaining_after = keychain
        .getRemainingLimitWithPeriod(root_addr, access_key.address(), DEFAULT_FEE_TOKEN)
        .call()
        .await?
        .remaining;
    let credit_after = credits.balanceOf(ACCOUNT_KEYCHAIN_ADDRESS).call().await?;
    let fee_token = ITIP20::new(DEFAULT_FEE_TOKEN, &provider);

    assert!(remaining_after > U256::ZERO);
    assert_eq!(
        credit_after, credit_before,
        "post-tx fee refund recreates the keychain limit slot, so the same-tx clear credit must be canceled"
    );
    assert_eq!(
        fee_token.balanceOf(recipient).call().await?,
        transfer_amount
    );

    Ok(())
}

/// Successful fee-token refunds must cancel a TIP-1060 credit minted by a same-tx user spend if
/// post-tx reimbursement recreates the fee payer's TIP-20 balance slot.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_successful_fee_token_spend_fee_refund_cancels_restored_balance_credit()
-> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let root = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_provider = ProviderBuilder::new()
        .wallet(root.clone())
        .connect_http(setup.http_url.clone());

    let fee_payer = PrivateKeySigner::random();
    let fee_payer_addr = fee_payer.address();
    let fee_payer_provider = ProviderBuilder::new()
        .wallet(fee_payer.clone())
        .connect_http(setup.http_url);

    let gas_limit = 500_000u64;
    let gas_price = 1_000_000_000_000u128;
    let max_fee = calc_gas_balance_spending(gas_limit, gas_price);
    let transfer_amount = U256::from(1_234u64);
    let initial_fee_payer_balance = max_fee + transfer_amount;
    let recipient = Address::repeat_byte(0xdd);

    let fee_token = ITIP20::new(DEFAULT_FEE_TOKEN, root_provider.clone());
    let recipient_seed_receipt = fee_token
        .transfer(recipient, U256::ONE)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(recipient_seed_receipt.status());
    let fee_payer_seed_receipt = fee_token
        .transfer(fee_payer_addr, initial_fee_payer_balance)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(fee_payer_seed_receipt.status());
    assert_eq!(
        fee_token.balanceOf(fee_payer_addr).call().await?,
        initial_fee_payer_balance
    );

    let credits = IStorageCredits::new(STORAGE_CREDITS_ADDRESS, &root_provider);
    let credit_before = credits.balanceOf(DEFAULT_FEE_TOKEN).call().await?;

    let tx = TempoTransaction {
        chain_id: fee_payer_provider.get_chain_id().await?,
        nonce: fee_payer_provider
            .get_transaction_count(fee_payer_addr)
            .await?,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit,
        calls: vec![Call {
            to: DEFAULT_FEE_TOKEN.into(),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: recipient,
                amount: transfer_amount,
            }
            .abi_encode()
            .into(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        ..Default::default()
    };
    let sig = fee_payer.sign_hash_sync(&tx.signature_hash())?;
    let envelope: TempoTxEnvelope = tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            sig,
        )))
        .into();

    let tx_hash = fee_payer_provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let receipt = root_provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await?;
    assert!(receipt.status());
    assert_eq!(receipt.fee_token, Some(DEFAULT_FEE_TOKEN));

    let spent_fee = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price());
    let expected_refund = max_fee - spent_fee;
    assert!(expected_refund > U256::ZERO);

    assert_eq!(
        fee_token.balanceOf(fee_payer_addr).call().await?,
        expected_refund
    );
    assert_eq!(
        fee_token.balanceOf(recipient).call().await?,
        transfer_amount + U256::ONE
    );
    assert_eq!(
        credits.balanceOf(DEFAULT_FEE_TOKEN).call().await?,
        credit_before,
        "post-tx fee refund recreates the payer balance slot, so the same-tx clear credit must be canceled"
    );

    Ok(())
}

/// A normal TIP-20 precompile storage clear should mint a TIP-1060 credit for the token, and a
/// later storage creation by the same token should redeem that account-local credit in Refund mode.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_tip20_clear_mints_and_later_creation_redeems_credit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let root = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root.address();
    let provider = ProviderBuilder::new()
        .wallet(root.clone())
        .connect_http(setup.http_url);

    let token = setup_test_token(provider.clone(), root_addr).await?;
    let recipient = Address::repeat_byte(0xcc);
    let amount = U256::from(1234u64);

    // Seed recipient with non-zero balance so the transfer clears the sender's balance slot.
    // Does not create a new recipient balance slot that could consume the credit.
    let recipient_seed_receipt = token
        .mint(recipient, U256::ONE)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(recipient_seed_receipt.status());
    let sender_seed_receipt = token
        .mint(root_addr, amount)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(sender_seed_receipt.status());

    let credits = IStorageCredits::new(STORAGE_CREDITS_ADDRESS, &provider);
    let credit_before = credits.balanceOf(*token.address()).call().await?;

    let gas_price = 1_000_000_000_000u128;
    let tx = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        nonce: provider.get_transaction_count(root_addr).await?,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit: 500_000,
        calls: vec![Call {
            to: (*token.address()).into(),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: recipient,
                amount,
            }
            .abi_encode()
            .into(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        ..Default::default()
    };
    let sig = root.sign_hash_sync(&tx.signature_hash())?;
    let envelope: TempoTxEnvelope = tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            sig,
        )))
        .into();
    let hash = provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (hash,))
        .await?;
    assert!(receipt.status());

    assert_eq!(token.balanceOf(root_addr).call().await?, U256::ZERO);
    assert_eq!(token.balanceOf(recipient).call().await?, amount + U256::ONE);
    let credit_after_clear = credits.balanceOf(*token.address()).call().await?;
    assert_eq!(
        credit_after_clear,
        credit_before + 1,
        "clearing the sender TIP-20 precompile balance slot must persist one storage credit for the token"
    );
    assert_eq!(
        credits.modeOf(*token.address()).call().await?,
        IStorageCredits::Mode::Refund,
        "storage creation mode is transient and defaults to Refund in a fresh call"
    );
    assert_eq!(
        credits.budgetOf(*token.address()).call().await?,
        0,
        "Direct budget is transient and defaults to zero in a fresh call"
    );

    let fresh_recipient = Address::repeat_byte(0xdd);
    let mint_receipt = token
        .mint(fresh_recipient, U256::ONE)
        .nonce(provider.get_transaction_count(root_addr).await?)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(mint_receipt.status());

    assert_eq!(token.balanceOf(fresh_recipient).call().await?, U256::ONE);
    assert_eq!(
        credits.balanceOf(*token.address()).call().await?,
        credit_before,
        "a later Refund-mode balance-slot creation by the same token must redeem the minted credit"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1066_channel_storage_credits_are_payer_scoped() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let root = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let payer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let other_payer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(2)?
        .build()?;
    let payee = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(3)?
        .build()?;

    let provider = ProviderBuilder::new()
        .wallet(root)
        .connect_http(setup.http_url.clone());
    let payer_provider = ProviderBuilder::new()
        .wallet(payer.clone())
        .connect_http(setup.http_url.clone());
    let other_payer_provider = ProviderBuilder::new()
        .wallet(other_payer.clone())
        .connect_http(setup.http_url.clone());
    let payee_provider = ProviderBuilder::new()
        .wallet(payee.clone())
        .connect_http(setup.http_url);

    let path_usd = ITIP20::new(PATH_USD_ADDRESS, &provider);
    for funded in [payer.address(), other_payer.address()] {
        let receipt = path_usd
            .transfer(funded, U256::from(5_000_000u64))
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
    }

    let payer_reserve = ITIP20ChannelReserve::new(TIP20_CHANNEL_RESERVE_ADDRESS, &payer_provider);
    let other_payer_reserve =
        ITIP20ChannelReserve::new(TIP20_CHANNEL_RESERVE_ADDRESS, &other_payer_provider);
    let payee_reserve = ITIP20ChannelReserve::new(TIP20_CHANNEL_RESERVE_ADDRESS, &payee_provider);
    let storage_credits = IStorageCredits::new(STORAGE_CREDITS_ADDRESS, &provider);

    let open_receipt = payer_reserve
        .open(
            payee.address(),
            Address::ZERO,
            PATH_USD_ADDRESS,
            U96::from(1_000u64),
            B256::with_last_byte(1),
            Address::ZERO,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(open_receipt.status());

    let opened = open_receipt
        .logs()
        .iter()
        .find_map(|log| ITIP20ChannelReserve::ChannelOpened::decode_log(&log.inner).ok())
        .ok_or_else(|| eyre::eyre!("ChannelOpened event missing"))?;
    let descriptor = ITIP20ChannelReserve::ChannelDescriptor {
        payer: opened.payer,
        payee: opened.payee,
        operator: opened.operator,
        token: opened.token,
        salt: opened.salt,
        authorizedSigner: opened.authorizedSigner,
        expiringNonceHash: opened.expiringNonceHash,
    };

    let close_receipt = payee_reserve
        .close(descriptor, U96::ZERO, U96::ZERO, Bytes::new())
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(close_receipt.status());

    assert_eq!(
        payer_reserve.storageCredits(payer.address()).call().await?,
        1
    );
    assert_eq!(
        payer_reserve
            .storageCredits(other_payer.address())
            .call()
            .await?,
        0
    );
    assert_eq!(
        storage_credits
            .balanceOf(TIP20_CHANNEL_RESERVE_ADDRESS)
            .call()
            .await?,
        0,
        "the TIP-1060 token backing the first channel credit is held by the payer counter slot"
    );

    let other_open_receipt = other_payer_reserve
        .open(
            payee.address(),
            Address::ZERO,
            PATH_USD_ADDRESS,
            U96::from(1_000u64),
            B256::with_last_byte(2),
            Address::ZERO,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(other_open_receipt.status());
    assert_eq!(
        payer_reserve.storageCredits(payer.address()).call().await?,
        1,
        "a different payer must not consume the original payer's channel credit"
    );

    let payer_reopen_receipt = payer_reserve
        .open(
            payee.address(),
            Address::ZERO,
            PATH_USD_ADDRESS,
            U96::from(1_000u64),
            B256::with_last_byte(3),
            Address::ZERO,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(payer_reopen_receipt.status());
    assert_eq!(
        payer_reserve.storageCredits(payer.address()).call().await?,
        0,
        "the original payer's next open must consume exactly one channel credit"
    );
    assert_eq!(
        storage_credits
            .balanceOf(TIP20_CHANNEL_RESERVE_ADDRESS)
            .call()
            .await?,
        0,
        "consuming channel credits must not leave reusable TIP-1060 credits on the precompile"
    );

    Ok(())
}
