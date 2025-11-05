use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use alloy_eips::BlockNumberOrTag;
use futures::{StreamExt, future::join_all, stream};
use std::env;
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_precompiles::tip20::{ITIP20, token_id_to_address};

#[tokio::test(flavor = "multi_thread")]
async fn test_base_fee() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(
            include_str!("../assets/base-fee-test.json").to_string(),
        )
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Get initial block to check base fee
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .expect("Could not get latest block");

    let base_fee = block
        .header
        .base_fee_per_gas
        .expect("Could not get basefee");
    assert_eq!(base_fee, TEMPO_BASE_FEE as u128 as u64);

    // Use the pre-deployed token from genesis (token 1)
    let token_addr = token_id_to_address(1);
    let token = ITIP20::new(token_addr, provider.clone());

    // Gas limit is set to 200k in test-genesis.json, send 500 txs to exceed limit over multiple
    // blocks
    let mut pending_txs = vec![];
    for _ in 0..500 {
        let pending_tx = token
            .transfer(Address::random(), U256::ONE)
            .gas_price(TEMPO_BASE_FEE as u128)
            .gas(30000)
            .send()
            .await?;
        pending_txs.push(pending_tx);
    }

    // Wait for all receipts, get block number of last receipt
    let receipts = join_all(pending_txs.into_iter().map(|tx| tx.get_receipt()))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    let final_block = receipts
        .iter()
        .filter_map(|r| r.block_number)
        .max()
        .unwrap();

    stream::iter(0..=final_block)
        .for_each(|block_num| {
            let provider = provider.clone();
            async move {
                let block = provider
                    .get_block_by_number(BlockNumberOrTag::Number(block_num))
                    .await
                    .unwrap()
                    .expect("Could not get block");

                let base_fee = block
                    .header
                    .base_fee_per_gas
                    .expect("Could not get basefee");
                assert_eq!(base_fee, TEMPO_BASE_FEE as u128 as u64);
            }
        })
        .await;

    // Check fee history and ensure fee stays at 0
    let fee_history = provider
        .get_fee_history(final_block, BlockNumberOrTag::Number(final_block), &[])
        .await?;

    for (base_fee, gas_used_ratio) in fee_history
        .base_fee_per_gas
        .iter()
        .zip(fee_history.gas_used_ratio)
    {
        assert_eq!(*base_fee, TEMPO_BASE_FEE as u128);
        println!("Gas used ratio: {gas_used_ratio}");
    }

    Ok(())
}
