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
use alloy_eips::Encodable2718;
use alloy_rpc_types_eth::TransactionRequest;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, IStorageCredits, ITIP20, ITIP20ChannelReserve,
    account_keychain::IAccountKeychain::{
        IAccountKeychainInstance, KeyRestrictions, SignatureType, TokenLimit, revokeKeyCall,
    },
    authorizeKeyCall,
};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, PATH_USD_ADDRESS, STORAGE_CREDITS_ADDRESS,
    TIP20_CHANNEL_RESERVE_ADDRESS,
};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{
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
