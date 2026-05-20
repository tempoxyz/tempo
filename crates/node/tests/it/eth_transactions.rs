use crate::utils::{TEST_MNEMONIC, TestNodeBuilder, setup_test_token};
use alloy::{
    consensus::Transaction,
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use alloy_network::TransactionResponse;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;

#[tokio::test(flavor = "multi_thread")]
async fn test_get_transaction_by_sender_and_nonce() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;

    let nonce_before = provider.get_transaction_count(caller).await?;

    let mint_amount = U256::from(1000000u64);
    let pending_tx = token
        .mint(caller, mint_amount)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?;

    let tx_hash = *pending_tx.tx_hash();
    let receipt = pending_tx.get_receipt().await?;
    assert!(receipt.status());

    let nonce_after = provider.get_transaction_count(caller).await?;
    assert_eq!(nonce_after, nonce_before + 1);

    let fetched_tx = provider
        .get_transaction_by_sender_nonce(caller, nonce_before)
        .await?;

    assert!(
        fetched_tx.is_some(),
        "Transaction should be found by sender and nonce"
    );

    let tx = fetched_tx.unwrap();
    assert_eq!(
        *tx.inner.tx_hash(),
        tx_hash,
        "Transaction hash should match"
    );
    assert_eq!(tx.from(), caller, "Transaction sender should match");
    assert_eq!(
        tx.inner.nonce(),
        nonce_before,
        "Transaction nonce should match"
    );

    Ok(())
}
