use crate::utils::{TEST_MNEMONIC, TestNodeBuilder, setup_test_token};
use alloy::{
    network::ReceiptResponse,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
    sol_types::SolCall,
};
use alloy_eips::{BlockId, Encodable2718};
use alloy_rpc_types_eth::TransactionRequest;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, IFeeManager,
    IFeeManager::setUserTokenCall,
    IStorageCredits, ITIP20,
    account_keychain::IAccountKeychain::{
        IAccountKeychainInstance, KeyRestrictions, SignatureType, TokenLimit, revokeKeyCall,
    },
    authorizeKeyCall,
};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, PATH_USD_ADDRESS, STORAGE_CREDITS_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{
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
