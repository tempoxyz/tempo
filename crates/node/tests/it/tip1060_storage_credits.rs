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
    DEFAULT_FEE_TOKEN, IFeeManager, ITIP20, ITIP1060StorageCredits,
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
    let credits = ITIP1060StorageCredits::new(STORAGE_CREDITS_ADDRESS, &provider);

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

/// Demonstrates that protecting only `FeeManager.collected_fees` is insufficient.
///
/// Fee collection can create `TIP20.balances[TIP_FEE_MANAGER_ADDRESS]` while
/// TIP-1060 accounting is disabled. A later public `distributeFees` call can
/// clear that TIP20-owned slot with TIP-1060 enabled, minting an unbacked
/// storage credit to the token owner. A subsequent public TIP20 transfer can
/// redeem that credit against a different `0 -> nonzero` balance slot.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_distribute_fees_mints_and_redeems_unbacked_tip20_credit() -> eyre::Result<()>
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
    let distributor = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let distributor_addr = distributor.address();
    let validator = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(2)?
        .build()?;
    let validator_addr = validator.address();
    let provider = ProviderBuilder::new()
        .wallet(root.clone())
        .connect_http(setup.http_url.clone());
    let distributor_provider = ProviderBuilder::new()
        .wallet(distributor)
        .connect_http(setup.http_url.clone());
    let validator_provider = ProviderBuilder::new()
        .wallet(validator)
        .connect_http(setup.http_url);

    let fee_token = setup_test_token(provider.clone(), root_addr).await?;
    let path_usd = ITIP20::new(PATH_USD_ADDRESS, &provider);
    let root_fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let validator_fee_manager =
        IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, validator_provider.clone());
    let distributor_fee_manager =
        IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, distributor_provider.clone());
    let distributor_fee_token = ITIP20::new(*fee_token.address(), distributor_provider.clone());
    let credits = ITIP1060StorageCredits::new(STORAGE_CREDITS_ADDRESS, &provider);

    fee_token
        .mint(root_addr, U256::from(10_000_000_000u64))
        .send()
        .await?
        .get_receipt()
        .await?;
    fee_token
        .mint(validator_addr, U256::from(10_000u64))
        .send()
        .await?
        .get_receipt()
        .await?;
    fee_token
        .mint(distributor_addr, U256::from(10_000u64))
        .send()
        .await?
        .get_receipt()
        .await?;
    path_usd
        .transfer(distributor_addr, U256::from(10_000_000_000u64))
        .send()
        .await?
        .get_receipt()
        .await?;
    path_usd
        .transfer(validator_addr, U256::from(10_000_000_000u64))
        .send()
        .await?
        .get_receipt()
        .await?;

    let set_validator_receipt = validator_fee_manager
        .setValidatorToken(*fee_token.address())
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(set_validator_receipt.status());

    *dynamic_validator.lock().unwrap() = validator_addr;
    wait_for_latest_beneficiary(&provider, validator_addr).await?;

    let collected_before = root_fee_manager
        .collectedFees(validator_addr, *fee_token.address())
        .call()
        .await?;
    let fee_manager_token_balance_before =
        fee_token.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;

    let gas_price = 1_000_000_000_000u128;
    let fee_collection_tx = TempoTransaction {
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
    let fee_collection_signature = root.sign_hash_sync(&fee_collection_tx.signature_hash())?;
    let fee_collection_envelope: TempoTxEnvelope = fee_collection_tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            fee_collection_signature,
        )))
        .into();
    let fee_collection_hash = provider
        .send_raw_transaction(&fee_collection_envelope.encoded_2718())
        .await?
        .watch()
        .await?;
    let fee_collection_receipt = provider
        .raw_request::<_, TempoTransactionReceipt>(
            "eth_getTransactionReceipt".into(),
            (fee_collection_hash,),
        )
        .await?;
    assert!(fee_collection_receipt.status());

    let collected_after_fee_collection = root_fee_manager
        .collectedFees(validator_addr, *fee_token.address())
        .call()
        .await?;
    let fee_manager_token_balance_after_fee_collection =
        fee_token.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert!(
        collected_after_fee_collection > collected_before,
        "fee collection must accumulate fees in the custom validator token"
    );
    assert!(
        fee_manager_token_balance_after_fee_collection > fee_manager_token_balance_before,
        "fee collection must create FeeManager custody balance in the custom token"
    );

    *dynamic_validator.lock().unwrap() = initial_validator;
    wait_for_latest_beneficiary(&provider, initial_validator).await?;

    let validator_token_balance_before_distribute =
        fee_token.balanceOf(validator_addr).call().await?;
    assert!(
        !validator_token_balance_before_distribute.is_zero(),
        "validator token balance must be nonzero so distributeFees cannot redeem in the same tx"
    );
    let token_credit_before = credits.balanceOf(*fee_token.address()).call().await?;
    let distribute_receipt = distributor_fee_manager
        .distributeFees(validator_addr, *fee_token.address())
        .gas(2_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(distribute_receipt.status());

    let fee_manager_token_balance_after_distribute =
        fee_token.balanceOf(TIP_FEE_MANAGER_ADDRESS).call().await?;
    assert_eq!(
        fee_manager_token_balance_after_distribute,
        U256::ZERO,
        "distributeFees must clear the custom-token FeeManager custody slot"
    );

    let token_credit_after_distribute = credits.balanceOf(*fee_token.address()).call().await?;
    assert_eq!(
        token_credit_after_distribute,
        token_credit_before + 1,
        "clearing the fee-collection-created TIP20 custody slot mints an unbacked token credit"
    );

    let fresh_recipient = Address::random();
    assert_eq!(
        fee_token.balanceOf(fresh_recipient).call().await?,
        U256::ZERO,
        "redemption target must start with an empty balance slot"
    );
    let redeem_receipt = distributor_fee_token
        .transfer(fresh_recipient, U256::from(1u64))
        .gas(2_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(redeem_receipt.status());
    assert_eq!(
        fee_token.balanceOf(fresh_recipient).call().await?,
        U256::from(1u64)
    );

    let token_credit_after_redeem = credits.balanceOf(*fee_token.address()).call().await?;
    assert_eq!(
        token_credit_after_redeem, token_credit_before,
        "a later TIP20 0 -> nonzero balance write redeems the unbacked token credit"
    );

    Ok(())
}
