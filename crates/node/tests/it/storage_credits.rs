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
use alloy_eips::Encodable2718;
use alloy_rpc_types_eth::TransactionRequest;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, IStorageCredits, ITIP20,
    account_keychain::IAccountKeychain::{
        IAccountKeychainInstance, KeyRestrictions, SignatureType, TokenLimit, revokeKeyCall,
    },
    authorizeKeyCall,
};
use tempo_precompiles::{ACCOUNT_KEYCHAIN_ADDRESS, STORAGE_CREDITS_ADDRESS};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{
        calc_gas_balance_spending,
        tempo_transaction::Call,
        tt_signature::{KeychainSignature, PrimitiveSignature, TempoSignature},
    },
};

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

/// Regression for successful access-key fee refund accounting.
///
/// This exercises the full node/RPC path rather than seeding mocked EVM state:
/// - authorize an access key with fee-token limit equal to max fee plus transfer amount,
/// - submit a successful keychain AA transaction that transfers that amount,
/// - fee precharge leaves exactly the transfer amount in the limit row,
/// - the TIP-20 transfer clears the row under normal TIP-1060 accounting,
/// - post-tx reimbursement recreates the row with TIP-1060 disabled,
/// - assert the cleared row does not retain a storage credit when the final row is live.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_successful_keychain_spend_fee_refund_recreates_limit_without_credit_retained()
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
    assert!(
        receipt.status(),
        "the access-key AA transaction must succeed so the user-call limit clear commits"
    );

    let remaining_after = keychain
        .getRemainingLimitWithPeriod(root_addr, access_key.address(), DEFAULT_FEE_TOKEN)
        .call()
        .await?
        .remaining;
    let credit_after = credits.balanceOf(ACCOUNT_KEYCHAIN_ADDRESS).call().await?;
    let fee_token = ITIP20::new(DEFAULT_FEE_TOKEN, &provider);

    assert!(
        remaining_after > U256::ZERO,
        "post-tx fee refund must restore the keychain spending-limit slot"
    );
    assert_eq!(
        credit_after, credit_before,
        "successful spend clears the keychain limit, but post-tx refund restoration leaves the final slot live so no storage credit may remain"
    );
    assert_eq!(
        fee_token.balanceOf(recipient).call().await?,
        transfer_amount
    );

    Ok(())
}

/// Regression for fee-token refund accounting when reimbursement recreates the payer balance slot.
///
/// The fee payer starts with exactly max fee plus transfer amount in DEFAULT_FEE_TOKEN. Fee
/// precharge leaves exactly the transfer amount, the successful user TIP-20 transfer clears the
/// payer's balance slot under normal accounting, and post-tx reimbursement recreates that slot with
/// TIP-1060 accounting disabled. The final live balance slot must not leave a retained storage
/// credit for the token.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_successful_fee_token_spend_fee_refund_recreates_balance_without_credit_retained()
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
    assert!(
        receipt.status(),
        "the primitive fee-token transaction must succeed so the user-call balance clear commits"
    );
    assert_eq!(receipt.fee_token, Some(DEFAULT_FEE_TOKEN));

    let spent_fee = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price());
    let expected_refund = max_fee - spent_fee;
    assert!(
        expected_refund > U256::ZERO,
        "gas limit must leave a non-zero fee refund to recreate the payer balance slot"
    );

    assert_eq!(
        fee_token.balanceOf(fee_payer_addr).call().await?,
        expected_refund,
        "post-tx fee refund must recreate the fee payer's DEFAULT_FEE_TOKEN balance slot"
    );
    assert_eq!(
        fee_token.balanceOf(recipient).call().await?,
        transfer_amount + U256::ONE
    );
    assert_eq!(
        credits.balanceOf(DEFAULT_FEE_TOKEN).call().await?,
        credit_before,
        "successful spend clears the fee payer balance, but post-tx refund restoration leaves the final slot live so no storage credit may remain"
    );

    Ok(())
}

/// A normal TIP-20 precompile storage clear should mint a persistent TIP-1060 credit for the token,
/// and a later storage creation by the same token should redeem that account-local credit.
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
