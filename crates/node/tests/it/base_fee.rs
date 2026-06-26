use alloy::{
    network::ReceiptResponse,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use alloy_eips::BlockNumberOrTag;
use futures::{StreamExt, future::join_all, stream};
use std::{env, time::Duration};
use tempo_chainspec::constants::gas::{
    TEMPO_T1_BASE_FEE, TEMPO_T7_BASE_FEE_FLOOR, tempo_t7_next_block_base_fee,
};
use tempo_precompiles::{PATH_USD_ADDRESS, tip20::ITIP20};

#[tokio::test(flavor = "multi_thread")]
async fn test_base_fee() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
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
    assert_eq!(base_fee, TEMPO_T1_BASE_FEE);

    let token = ITIP20::new(PATH_USD_ADDRESS, provider.clone());

    // Gas limit is set to 200k in test-genesis.json, send 500 txs to exceed limit over multiple
    // blocks
    let mut pending_txs = vec![];
    for _ in 0..500 {
        let pending_tx = token
            .transfer(Address::random(), U256::ONE)
            .gas_price(TEMPO_T1_BASE_FEE as u128)
            .gas(1_000_000)
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

    let blocks = stream::iter(0..=final_block)
        .then(|block_num| {
            let provider = provider.clone();
            async move {
                provider
                    .get_block_by_number(BlockNumberOrTag::Number(block_num))
                    .await
                    .unwrap()
                    .expect("Could not get block")
            }
        })
        .collect::<Vec<_>>()
        .await;

    assert_eq!(
        blocks[0]
            .header
            .base_fee_per_gas
            .expect("Could not get basefee"),
        TEMPO_T1_BASE_FEE
    );

    for window in blocks.windows(2) {
        let parent = &window[0];
        let child = &window[1];
        let parent_base_fee = parent
            .header
            .base_fee_per_gas
            .expect("Could not get parent basefee");
        let child_base_fee = child
            .header
            .base_fee_per_gas
            .expect("Could not get child basefee");
        assert_eq!(
            child_base_fee,
            tempo_t7_next_block_base_fee(parent_base_fee, parent.header.gas_used)
        );
    }

    // Check fee history and ensure base fees match the chain blocks.
    let fee_history = provider
        .get_fee_history(final_block, BlockNumberOrTag::Number(final_block), &[])
        .await?;

    let mut expected_fee_history = blocks
        .iter()
        .skip(1)
        .map(|block| {
            block
                .header
                .base_fee_per_gas
                .expect("Could not get basefee") as u128
        })
        .collect::<Vec<_>>();
    let final_block = blocks.last().expect("at least genesis block");
    expected_fee_history.push(u128::from(tempo_t7_next_block_base_fee(
        final_block
            .header
            .base_fee_per_gas
            .expect("Could not get final block basefee"),
        final_block.header.gas_used,
    )));

    assert_eq!(
        fee_history.base_fee_per_gas.len(),
        expected_fee_history.len()
    );
    for ((base_fee, gas_used_ratio), expected_base_fee) in fee_history
        .base_fee_per_gas
        .iter()
        .zip(fee_history.gas_used_ratio)
        .zip(expected_fee_history)
    {
        assert_eq!(*base_fee, expected_base_fee);
        println!("Gas used ratio: {gas_used_ratio}");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_t7_floor_base_fee_transaction_succeeds_after_low_activity() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = crate::utils::TestNodeBuilder::new()
        .build_http_only()
        .await?;
    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);

    let mut floor_block = None;
    for _ in 0..128 {
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .expect("Could not get latest block");
        let base_fee = block
            .header
            .base_fee_per_gas
            .expect("Could not get basefee");
        if base_fee == TEMPO_T7_BASE_FEE_FLOOR {
            floor_block = Some(block);
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    let floor_block =
        floor_block.expect("base fee should decay to the T6 floor under low activity");
    assert_eq!(
        floor_block
            .header
            .base_fee_per_gas
            .expect("Could not get basefee"),
        TEMPO_T7_BASE_FEE_FLOOR
    );

    let token = ITIP20::new(PATH_USD_ADDRESS, provider.clone());
    let receipt = token
        .transfer(Address::random(), U256::ONE)
        .gas_price(TEMPO_T7_BASE_FEE_FLOOR as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    assert!(receipt.status(), "floor-priced transaction should succeed");
    assert_eq!(
        receipt.effective_gas_price(),
        u128::from(TEMPO_T7_BASE_FEE_FLOOR),
        "floor-priced transaction should be mined at the T6 floor base fee"
    );

    Ok(())
}
