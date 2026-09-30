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

/// Admission must retain floor-priced transactions through a temporary base-fee spike.
#[tokio::test(flavor = "multi_thread")]
async fn test_t7_floor_transaction_queued_through_base_fee_spike() -> eyre::Result<()> {
    use alloy::{
        consensus::{BlockHeader, SignableTransaction, TxEip1559, TxEnvelope},
        primitives::address,
        signers::SignerSync,
    };
    use alloy_eips::eip2718::Encodable2718;
    use alloy_network::TxSignerSync;
    use tempo_chainspec::constants::gas::TEMPO_T7_BASE_FEE_GAS_TARGET;
    use tempo_primitives::{
        TempoTxEnvelope,
        transaction::{Call, TempoTransaction},
    };

    // INVALID consumes the entire gas limit without spending time in a busy loop.
    let burner = address!("1234567890123456789012345678901234567890");
    let mut genesis: serde_json::Value =
        serde_json::from_str(include_str!("../assets/test-genesis.json"))?;
    genesis["baseFeePerGas"] = serde_json::json!(format!("{TEMPO_T7_BASE_FEE_FLOOR:#x}"));
    genesis["alloc"][format!("{burner:#x}")] = serde_json::json!({
        "balance": "0x0", "code": "0xfe", "nonce": "0x1"
    });
    let mut setup = crate::utils::TestNodeBuilder::new()
        .with_genesis(serde_json::to_string(&genesis)?)
        .build_with_node_access()
        .await?;
    let signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let mut burn_tx = TxEip1559 {
        chain_id,
        gas_limit: 25_000_000,
        to: burner.into(),
        max_fee_per_gas: u128::from(TEMPO_T1_BASE_FEE),
        ..Default::default()
    };
    let signature = signer.sign_transaction_sync(&mut burn_tx)?;
    let raw = TxEnvelope::Eip1559(burn_tx.into_signed(signature)).encoded_2718();
    let burn_hash = *provider.send_raw_transaction(&raw).await?.tx_hash();
    setup.node.advance_block().await?;
    let receipt = provider
        .get_transaction_receipt(burn_hash)
        .await?
        .expect("burner mined");
    assert!(!receipt.status());
    let busy = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .unwrap();
    assert!(busy.header.gas_used() > TEMPO_T7_BASE_FEE_GAS_TARGET);
    assert_eq!(
        busy.header.base_fee_per_gas(),
        Some(TEMPO_T7_BASE_FEE_FLOOR)
    );

    // The busy parent raises this block's fee. Submit only once that elevated fee is the tip.
    setup.node.advance_block().await?;
    let elevated = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .unwrap();
    assert!(elevated.header.base_fee_per_gas().unwrap() > TEMPO_T7_BASE_FEE_FLOOR);
    assert_eq!(elevated.header.gas_used(), 0);

    let mut floor_tx = TxEip1559 {
        chain_id,
        nonce: 1,
        gas_limit: 100_000,
        to: Address::ZERO.into(),
        max_fee_per_gas: u128::from(TEMPO_T7_BASE_FEE_FLOOR),
        ..Default::default()
    };
    let signature = signer.sign_transaction_sync(&mut floor_tx)?;
    let raw = TxEnvelope::Eip1559(floor_tx.into_signed(signature)).encoded_2718();
    let floor_hash = *provider.send_raw_transaction(&raw).await?.tx_hash();
    // Exercise the separate AA 2D-nonce pool alongside the protocol-nonce pool.
    let aa_tx = TempoTransaction {
        chain_id,
        nonce_key: U256::ONE,
        gas_limit: 1_000_000,
        max_fee_per_gas: u128::from(TEMPO_T7_BASE_FEE_FLOOR),
        fee_token: Some(PATH_USD_ADDRESS),
        calls: vec![Call {
            to: Address::ZERO.into(),
            value: U256::ZERO,
            input: Default::default(),
        }],
        ..Default::default()
    };
    let signature = signer.sign_hash_sync(&aa_tx.signature_hash())?;
    let aa_tx: TempoTxEnvelope = aa_tx.into_signed(signature.into()).into();
    let aa_hash = *provider
        .send_raw_transaction(&aa_tx.encoded_2718())
        .await?
        .tx_hash();
    let mut parent_fee = elevated.header.base_fee_per_gas().unwrap();
    let mut parent_gas = elevated.header.gas_used();
    for _ in 0..32 {
        let expected_fee = tempo_t7_next_block_base_fee(parent_fee, parent_gas);
        setup.node.advance_block().await?;
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .unwrap();
        assert_eq!(block.header.base_fee_per_gas(), Some(expected_fee));
        for hash in [floor_hash, aa_hash] {
            let receipt = provider.get_transaction_receipt(hash).await?;
            if expected_fee == TEMPO_T7_BASE_FEE_FLOOR {
                let receipt = receipt
                    .expect("queued transaction must be included in the first floor-priced block");
                assert!(receipt.status());
                assert_eq!(receipt.block_number, Some(block.header.number()));
                assert_eq!(
                    receipt.effective_gas_price(),
                    u128::from(TEMPO_T7_BASE_FEE_FLOOR)
                );
            } else {
                assert!(
                    receipt.is_none(),
                    "transaction must wait until it can pay the block base fee"
                );
            }
        }
        if expected_fee == TEMPO_T7_BASE_FEE_FLOOR {
            return Ok(());
        }
        assert_eq!(
            block.header.gas_used(),
            0,
            "mine empty blocks while the transaction waits"
        );
        parent_fee = expected_fee;
        parent_gas = block.header.gas_used();
    }
    panic!("base fee did not decay to the floor");
}
