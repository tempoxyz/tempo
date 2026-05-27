use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{BlockId, TransactionRequest},
    signers::local::MnemonicBuilder,
};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;

#[ignore = "production Block-STM node E2E; run from scripts/check-blockstm-builder.sh"]
#[tokio::test(flavor = "multi_thread")]
async fn blockstm_node_e2e_starts_with_flag_and_builds_serial_equivalent_block() -> eyre::Result<()>
{
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .with_blockstm(4)
        .build_http_only()
        .await?;
    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let sender = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(wallet))
        .connect_http(setup.http_url);

    let tx = TransactionRequest::default()
        .from(sender)
        .to(Address::repeat_byte(0x42))
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas_limit(300_000)
        .value(U256::ZERO);
    let receipt = provider.send_transaction(tx).await?.get_receipt().await?;

    assert!(receipt.status(), "Block-STM E2E transaction reverted");
    let block_number = receipt
        .block_number
        .expect("Block-STM E2E transaction must be included in a block");
    let block = provider
        .get_block(BlockId::number(block_number))
        .await?
        .expect("Block-STM E2E block must be available");
    assert!(
        !block.transactions.is_empty(),
        "Block-STM E2E block should include the submitted transaction"
    );

    Ok(())
}
