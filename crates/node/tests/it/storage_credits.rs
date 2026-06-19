use crate::utils::{TEST_MNEMONIC, TestNodeBuilder, setup_test_token};
use alloy::{
    network::ReceiptResponse,
    primitives::{Address, Signature, U256},
    providers::{Provider, ProviderBuilder},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
    sol_types::SolCall,
};
use alloy_eips::{BlockId, Encodable2718};
use alloy_rpc_types_eth::TransactionRequest;
use std::sync::{Arc, Mutex};
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, IFeeManager,
    IFeeManager::setUserTokenCall,
    IStorageCredits, ITIP20, ITIPFeeAMM,
    account_keychain::IAccountKeychain::{
        IAccountKeychainInstance, KeyRestrictions, SignatureType, TokenLimit, revokeKeyCall,
    },
    authorizeKeyCall,
};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, PATH_USD_ADDRESS, STORAGE_CREDITS_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    tip_fee_manager::amm::PoolKey,
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

/// A FeeManager collected-fee clear for a non-current beneficiary must not create a reusable
/// FeeManager storage credit that can later be redeemed by unrelated FeeManager state creation.
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
    let path_usd = ITIP20::new(PATH_USD_ADDRESS, &provider);
    let root_fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let attacker_fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, attacker_provider);
    let validator_fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, validator_provider);
    let credits = IStorageCredits::new(STORAGE_CREDITS_ADDRESS, &provider);

    for recipient in [attacker_addr, validator_addr, user_addr] {
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
        .mint(user_addr, U256::from(10_000_000_000u64))
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(user_mint_receipt.status());

    let set_validator_receipt = validator_fee_manager
        .setValidatorToken(*fee_token.address())
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
        fee_token: Some(*fee_token.address()),
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

    *dynamic_validator.lock().unwrap() = initial_validator;
    wait_for_latest_beneficiary(&provider, initial_validator).await?;

    let fee_manager_credit_before_distribute =
        credits.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    let distribute_receipt = attacker_fee_manager
        .distributeFees(validator_addr, *fee_token.address())
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

    *dynamic_validator.lock().unwrap() = validator_addr;
    wait_for_latest_beneficiary(&provider, validator_addr).await?;

    let mut user_nonce = provider.get_transaction_count(user_addr).await?;
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
    user_nonce += 1;
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

    let set_user_token_tx = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        nonce: user_nonce,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: TIP_FEE_MANAGER_ADDRESS.into(),
            value: U256::ZERO,
            input: setUserTokenCall {
                token: *fee_token.address(),
            }
            .abi_encode()
            .into(),
        }],
        fee_token: Some(*fee_token.address()),
        ..Default::default()
    };
    let set_user_token_signature = user.sign_hash_sync(&set_user_token_tx.signature_hash())?;
    let set_user_token_envelope: TempoTxEnvelope = set_user_token_tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            set_user_token_signature,
        )))
        .into();
    let set_user_token_hash = provider
        .send_raw_transaction(&set_user_token_envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let set_user_token_receipt = provider
        .raw_request::<_, TempoTransactionReceipt>(
            "eth_getTransactionReceipt".into(),
            (set_user_token_hash,),
        )
        .await?;
    assert!(set_user_token_receipt.status());
    assert_eq!(
        root_fee_manager.userTokens(user_addr).call().await?,
        *fee_token.address()
    );

    assert_eq!(
        credits.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?,
        fee_manager_credit_after_recreate,
        "unrelated FeeManager Refund-mode storage creation must not redeem a credit leaked by distributeFees"
    );
    assert_eq!(
        fee_manager_credit_before_distribute, fee_manager_credit_after_distribute,
        "distributeFees must not mint a FeeManager storage credit"
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

/// A periodic keychain limit that reaches zero should not clear storage, so a later fee-token
/// recreation cannot leave a stale AccountKeychain-owned TIP-1060 credit to redeem.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_cross_token_keychain_fee_recreation_does_not_redeem_stale_credit()
-> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let root = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root.address();
    let validator = Arc::new(Mutex::new(root_addr));
    let setup = TestNodeBuilder::new()
        .with_dynamic_validator(validator.clone())
        .build_http_only()
        .await?;
    let provider = ProviderBuilder::new()
        .wallet(root.clone())
        .connect_http(setup.http_url);

    let access_key = PrivateKeySigner::random();
    let token_b = setup_test_token(provider.clone(), root_addr).await?;
    let token_b_addr = *token_b.address();
    let recipient = Address::repeat_byte(0xbb);

    let gas_limit = 500_000u64;
    let gas_price = 1_000_000_000_000u128;
    let max_fee = calc_gas_balance_spending(gas_limit, gas_price);
    let token_b_spend = U256::from(1_000_000u64);

    let seed_root_receipt = token_b
        .mint(root_addr, token_b_spend + max_fee * U256::from(8))
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(seed_root_receipt.status());
    let seed_recipient_receipt = token_b
        .mint(recipient, U256::ONE)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(seed_recipient_receipt.status());

    let authorize = authorizeKeyCall {
        keyId: access_key.address(),
        signatureType: SignatureType::Secp256k1,
        config: KeyRestrictions {
            expiry: u64::MAX,
            enforceLimits: true,
            limits: vec![
                TokenLimit {
                    token: DEFAULT_FEE_TOKEN,
                    amount: max_fee,
                    period: 0,
                },
                TokenLimit {
                    token: token_b_addr,
                    amount: token_b_spend,
                    period: 1,
                },
            ],
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

    let credits = IStorageCredits::new(STORAGE_CREDITS_ADDRESS, &provider);
    let credit_before = credits.balanceOf(ACCOUNT_KEYCHAIN_ADDRESS).call().await?;

    // Tx1 pays fees in the default token and exhausts token B's keychain limit under enabled
    // execution accounting. The zero sentinel keeps the periodic limit slot allocated, so token B
    // must not mint an AccountKeychain-owned storage credit.
    let tx1 = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        nonce: provider.get_transaction_count(root_addr).await?,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit,
        calls: vec![Call {
            to: token_b_addr.into(),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: recipient,
                amount: token_b_spend,
            }
            .abi_encode()
            .into(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        ..Default::default()
    };
    let keychain_hash = KeychainSignature::signing_hash(tx1.signature_hash(), root_addr);
    let access_signature = access_key.sign_hash_sync(&keychain_hash)?;
    let envelope: TempoTxEnvelope = tx1
        .into_signed(TempoSignature::Keychain(KeychainSignature::new(
            root_addr,
            PrimitiveSignature::Secp256k1(access_signature),
        )))
        .into();
    let tx1_hash = provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let tx1_receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx1_hash,))
        .await?;
    assert!(tx1_receipt.status());

    let credit_after_clear = credits.balanceOf(ACCOUNT_KEYCHAIN_ADDRESS).call().await?;
    assert_eq!(
        credit_after_clear, credit_before,
        "exhausting token B's keychain spending-limit slot must not mint an AccountKeychain credit"
    );

    *validator.lock().unwrap() = Address::repeat_byte(0x77);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let set_validator_token_receipt = fee_manager
        .setValidatorToken(token_b_addr)
        .nonce(provider.get_transaction_count(root_addr).await?)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(set_validator_token_receipt.status());

    *validator.lock().unwrap() = root_addr;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Tx2 pays fees in token B after the periodic limit expires. Fee pre-collection runs with
    // TIP-1060 disabled and resets the same keychain limit slot without creating a stale credit.
    let tx2 = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        nonce: provider.get_transaction_count(root_addr).await?,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit,
        calls: vec![Call {
            to: STORAGE_CREDITS_ADDRESS.into(),
            value: U256::ZERO,
            input: IStorageCredits::balanceOfCall {
                account: ACCOUNT_KEYCHAIN_ADDRESS,
            }
            .abi_encode()
            .into(),
        }],
        fee_token: Some(token_b_addr),
        ..Default::default()
    };
    let keychain_hash = KeychainSignature::signing_hash(tx2.signature_hash(), root_addr);
    let access_signature = access_key.sign_hash_sync(&keychain_hash)?;
    let envelope: TempoTxEnvelope = tx2
        .into_signed(TempoSignature::Keychain(KeychainSignature::new(
            root_addr,
            PrimitiveSignature::Secp256k1(access_signature),
        )))
        .into();
    let tx2_hash = provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let tx2_receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx2_hash,))
        .await?;
    assert!(tx2_receipt.status());

    let credit_after_disabled_recreate = credits.balanceOf(ACCOUNT_KEYCHAIN_ADDRESS).call().await?;
    assert_eq!(
        credit_after_disabled_recreate, credit_after_clear,
        "disabled fee pre-collection must not create or burn AccountKeychain credits"
    );

    // Tx3 creates ordinary AccountKeychain storage in Refund mode. There should be no stale credit
    // for end-of-transaction settlement to consume.
    let redeem_key = PrivateKeySigner::random();
    let redeem = authorizeKeyCall {
        keyId: redeem_key.address(),
        signatureType: SignatureType::Secp256k1,
        config: KeyRestrictions {
            expiry: u64::MAX,
            enforceLimits: true,
            limits: vec![TokenLimit {
                token: DEFAULT_FEE_TOKEN,
                amount: U256::ONE,
                period: 0,
            }],
            allowAnyCalls: true,
            allowedCalls: vec![],
        },
    };
    let tx3 = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        nonce: provider.get_transaction_count(root_addr).await?,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: redeem.abi_encode().into(),
        }],
        fee_token: Some(token_b_addr),
        ..Default::default()
    };
    let sig = root.sign_hash_sync(&tx3.signature_hash())?;
    let envelope: TempoTxEnvelope = tx3
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            sig,
        )))
        .into();
    let tx3_hash = provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let tx3_receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx3_hash,))
        .await?;
    assert!(tx3_receipt.status());

    assert_eq!(
        credits.balanceOf(ACCOUNT_KEYCHAIN_ADDRESS).call().await?,
        credit_after_disabled_recreate,
        "a later AccountKeychain Refund-mode creation must not redeem a stale credit"
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

/// Regression: burning the caller's full AMM LP balance clears a FeeManager-owned
/// `liquidity_balances[pool][caller]` slot and mints a FeeManager storage credit. A later disabled
/// fee-collection write to a fresh `collected_fees[beneficiary][validator_token]` slot must consume
/// or cancel that credit before another FeeManager storage creation can redeem it.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_burn_lp_credit_not_redeemed_by_later_set_user_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let root = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root.address();
    let active_beneficiary = Arc::new(Mutex::new(root_addr));
    let setup = TestNodeBuilder::new()
        .with_dynamic_validator(active_beneficiary.clone())
        .build_http_only()
        .await?;
    let root_provider = ProviderBuilder::new()
        .wallet(root.clone())
        .connect_http(setup.http_url.clone());

    let redeemer = PrivateKeySigner::random();
    let redeemer_addr = redeemer.address();
    let redeemer_provider = ProviderBuilder::new()
        .wallet(redeemer.clone())
        .connect_http(setup.http_url);

    let user_token = setup_test_token(root_provider.clone(), root_addr).await?;
    let user_token_addr = *user_token.address();
    let default_fee_token = ITIP20::new(DEFAULT_FEE_TOKEN, root_provider.clone());
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, root_provider.clone());
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, root_provider.clone());
    let credits = IStorageCredits::new(STORAGE_CREDITS_ADDRESS, &root_provider);

    let liquidity = U256::from(1_000_000_000_000_000_000u128);
    assert!(
        user_token
            .mint(root_addr, liquidity)
            .send()
            .await?
            .get_receipt()
            .await?
            .status()
    );
    assert!(
        fee_amm
            .mint(user_token_addr, PATH_USD_ADDRESS, liquidity, root_addr)
            .send()
            .await?
            .get_receipt()
            .await?
            .status()
    );
    let pool_id = PoolKey::new(user_token_addr, PATH_USD_ADDRESS).get_id();
    let lp_balance = fee_amm.liquidityBalances(pool_id, root_addr).call().await?;
    assert!(lp_balance > U256::ZERO);

    let collected_root = fee_manager
        .collectedFees(root_addr, PATH_USD_ADDRESS)
        .call()
        .await?;
    assert!(
        collected_root > U256::ZERO,
        "setup transactions should make the root beneficiary collected-fees slot nonzero before burn"
    );

    let credit_before_burn = credits.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    let burn_receipt = fee_amm
        .burn(user_token_addr, PATH_USD_ADDRESS, lp_balance, root_addr)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(burn_receipt.status());
    assert_eq!(
        fee_amm.liquidityBalances(pool_id, root_addr).call().await?,
        U256::ZERO,
        "burning the full LP balance should clear the FeeManager liquidity balance slot"
    );
    let credit_after_burn = credits.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(
        credit_after_burn,
        credit_before_burn + 1,
        "clearing the FeeManager liquidity balance slot should mint one backed FeeManager credit"
    );

    let fresh_beneficiary = Address::repeat_byte(0x8b);
    *active_beneficiary.lock().unwrap() = fresh_beneficiary;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert_eq!(
        fee_manager
            .collectedFees(fresh_beneficiary, PATH_USD_ADDRESS)
            .call()
            .await?,
        U256::ZERO,
        "the next fee tx should create a fresh collected_fees slot"
    );

    let fee_tx_receipt = default_fee_token
        .transfer(Address::repeat_byte(0x9c), U256::ONE)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(fee_tx_receipt.status());
    assert!(
        fee_manager
            .collectedFees(fresh_beneficiary, PATH_USD_ADDRESS)
            .call()
            .await?
            > U256::ZERO,
        "disabled collect_fee_post_tx should create collected_fees for the fresh beneficiary"
    );
    let credit_after_collected_fees = credits.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;

    assert_ne!(
        fee_manager.userTokens(redeemer_addr).call().await?,
        user_token_addr,
        "the redeemer must not already have this user token set"
    );
    let gas_limit = 2_000_000u64;
    let gas_price = 1_000_000_000_000u128;
    let mut set_user_token_tx = TempoTransaction {
        chain_id: root_provider.get_chain_id().await?,
        nonce: redeemer_provider
            .get_transaction_count(redeemer_addr)
            .await?,
        max_priority_fee_per_gas: gas_price,
        max_fee_per_gas: gas_price,
        gas_limit,
        calls: vec![Call {
            to: TIP_FEE_MANAGER_ADDRESS.into(),
            value: U256::ZERO,
            input: IFeeManager::setUserTokenCall {
                token: user_token_addr,
            }
            .abi_encode()
            .into(),
        }],
        fee_payer_signature: Some(Signature::new(
            Default::default(),
            Default::default(),
            false,
        )),
        ..Default::default()
    };
    let sig_hash = set_user_token_tx.signature_hash();
    let redeemer_signature = redeemer.sign_hash_sync(&sig_hash)?;
    let fee_payer_signature =
        root.sign_hash_sync(&set_user_token_tx.fee_payer_signature_hash(redeemer_addr))?;
    set_user_token_tx.fee_payer_signature = Some(fee_payer_signature);
    let envelope: TempoTxEnvelope = set_user_token_tx
        .into_signed(redeemer_signature.into())
        .into();
    let set_user_token_hash = root_provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let set_user_token_receipt = root_provider
        .raw_request::<_, TempoTransactionReceipt>(
            "eth_getTransactionReceipt".into(),
            (set_user_token_hash,),
        )
        .await?;
    assert!(set_user_token_receipt.status());

    assert_eq!(
        credits.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?,
        credit_after_collected_fees,
        "setUserToken must not redeem a FeeManager credit made stale by disabled collected_fees creation"
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
