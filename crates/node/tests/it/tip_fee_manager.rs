use crate::utils::{setup_test_node, setup_test_token};
use alloy::{
    consensus::SignableTransaction,
    providers::{Provider, ProviderBuilder, WalletProvider},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
};
use alloy_eips::{BlockId, Encodable2718};
use alloy_network::{AnyReceiptEnvelope, EthereumWallet, ReceiptResponse, TxSignerSync};
use alloy_primitives::{Address, Signature, U256};
use alloy_rpc_types_eth::TransactionRequest;
use std::env;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_contracts::precompiles::{
    IFeeManager, ITIP20,
    ITIPFeeAMM::{self},
};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    tip20::token_id_to_address,
};
use tempo_primitives::{TxFeeToken, transaction::calc_gas_balance_spending};

#[tokio::test(flavor = "multi_thread")]
async fn test_set_user_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let user_address = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let user_token = setup_test_token(provider.clone(), user_address).await?;
    let validator_token = ITIP20::new(PATH_USD_ADDRESS, &provider);
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    user_token
        .mint(user_address, U256::from(1e10))
        .send()
        .await?
        .watch()
        .await?;

    // Initial token should be predeployed token
    assert_eq!(
        fee_manager.userTokens(user_address).call().await?,
        token_id_to_address(1)
    );

    let validator = provider
        .get_block(BlockId::latest())
        .await?
        .unwrap()
        .header
        .beneficiary;

    let validator_balance_before = validator_token.balanceOf(validator).call().await?;

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    let receipt = fee_amm
        .mintWithValidatorToken(
            *user_token.address(),
            *validator_token.address(),
            U256::from(1e8),
            user_address,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());

    let expected_cost = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price);

    let validator_balance_after = validator_token.balanceOf(validator).call().await?;
    assert_eq!(
        validator_balance_after,
        validator_balance_before + expected_cost * U256::from(9970) / U256::from(10000)
    );

    let set_receipt = fee_manager
        .setUserToken(*user_token.address())
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(set_receipt.status());

    let current_token = fee_manager.userTokens(user_address).call().await?;
    assert_eq!(current_token, *user_token.address());

    assert!(validator_token.balanceOf(validator).call().await? > validator_balance_after);

    // send a dummy transaction
    let receipt = provider
        .send_transaction(TransactionRequest::default().to(Address::random()))
        .await?
        .get_receipt()
        .await?;

    // Assert transaction fee was paid in the newly configured token.
    assert!(receipt.logs().last().unwrap().address() == *user_token.address());

    // Ensure the validator was paid for it (or wasn't due to pre-moderato bug)
    let validator_balance_before = validator_token
        .balanceOf(validator)
        .block((receipt.block_number.unwrap() - 1).into())
        .call()
        .await?;
    let validator_balance_after = validator_token.balanceOf(validator).call().await?;

    assert!(validator_balance_after > validator_balance_before);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_set_validator_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let validator_address = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let validator_token = setup_test_token(provider.clone(), validator_address).await?;
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider);

    let initial_token = fee_manager
        .validatorTokens(validator_address)
        .call()
        .await?;
    // Initial token should be default fee token (PathUSD in Allegretto)
    assert_eq!(initial_token, DEFAULT_FEE_TOKEN_POST_ALLEGRETTO);

    let set_receipt = fee_manager
        .setValidatorToken(*validator_token.address())
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(set_receipt.status());

    let current_token = fee_manager
        .validatorTokens(validator_address)
        .call()
        .await?;
    assert_eq!(current_token, *validator_token.address());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_fee_token_tx() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = setup_test_node(source).await?;

    let signers = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .into_iter()
        .take(2)
        .collect::<Result<Vec<_>, _>>()?;

    let mut wallet = EthereumWallet::new(signers[0].clone());
    wallet.register_signer(signers[1].clone());

    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);
    let user_address = provider.default_signer_address();

    let user_token = setup_test_token(provider.clone(), user_address).await?;
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    let fees = provider.estimate_eip1559_fees().await?;

    let send_fee_token_tx = || async {
        let mut tx = TxFeeToken {
            chain_id: provider.get_chain_id().await?,
            nonce: provider.get_transaction_count(user_address).await?,
            fee_token: Some(*user_token.address()),
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            max_fee_per_gas: fees.max_fee_per_gas,
            gas_limit: 21000,
            to: Address::ZERO.into(),
            ..Default::default()
        };

        let signature = signers[0].sign_transaction_sync(&mut tx).unwrap();

        let tx = tx.into_signed(signature);

        provider.send_raw_transaction(&tx.encoded_2718()).await
    };

    let res = send_fee_token_tx().await;
    assert!(
        res.err()
            .is_some_and(|e| e.to_string().contains("insufficient funds"))
    );

    for signer in &signers {
        assert!(
            user_token
                .mint(signer.address(), U256::from(1e18))
                .send()
                .await?
                .get_receipt()
                .await?
                .status()
        );
    }

    // Mint liquidity
    assert!(
        fee_amm
            .mint(
                *user_token.address(),
                PATH_USD_ADDRESS,
                U256::from(1e18),
                U256::from(1e18),
                signers[1].address(),
            )
            .from(signers[1].address())
            .send()
            .await?
            .get_receipt()
            .await?
            .status()
    );

    let tx_hash = send_fee_token_tx().await?.watch().await?;
    let receipt = provider
        .client()
        .request::<_, AnyReceiptEnvelope>("eth_getTransactionReceipt", (tx_hash,))
        .await?;

    assert!(receipt.status());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_fee_payer_tx() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = setup_test_node(source).await?;

    let fee_payer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let user = PrivateKeySigner::random();

    let provider = ProviderBuilder::new().connect_http(http_url);
    let fees = provider.estimate_eip1559_fees().await?;

    let mut tx = TxFeeToken {
        chain_id: provider.get_chain_id().await?,
        nonce: provider.get_transaction_count(user.address()).await?,
        max_priority_fee_per_gas: fees.max_fee_per_gas,
        max_fee_per_gas: fees.max_fee_per_gas,
        gas_limit: 21000,
        to: Address::ZERO.into(),
        fee_payer_signature: Some(Signature::new(
            Default::default(),
            Default::default(),
            false,
        )),
        ..Default::default()
    };

    let signature = user.sign_transaction_sync(&mut tx).unwrap();
    assert!(
        signature
            .recover_address_from_prehash(&tx.signature_hash())
            .unwrap()
            == user.address()
    );
    let fee_payer_signature = fee_payer
        .sign_hash_sync(&tx.fee_payer_signature_hash(user.address()))
        .unwrap();

    tx.fee_payer_signature = Some(fee_payer_signature);
    let tx = tx.into_signed(signature);

    assert!(
        ITIP20::new(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, &provider)
            .balanceOf(user.address())
            .call()
            .await?
            .is_zero()
    );

    // Get fee_payer's actual fee token (may differ from DEFAULT_FEE_TOKEN_POST_ALLEGRETTO)
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &provider);
    let fee_payer_token = fee_manager.userTokens(fee_payer.address()).call().await?;

    let balance_before = ITIP20::new(fee_payer_token, provider.clone())
        .balanceOf(fee_payer.address())
        .call()
        .await?;

    let tx_hash = provider
        .send_raw_transaction(&tx.encoded_2718())
        .await?
        .watch()
        .await?;

    let receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await?;

    assert!(receipt.status());

    let balance_after = ITIP20::new(fee_payer_token, &provider)
        .balanceOf(fee_payer.address())
        .call()
        .await?;

    let cost = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price());
    assert_eq!(balance_after, balance_before - cost);

    Ok(())
}
