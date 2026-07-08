//! TIP-1040 temporary storage precompile, exercised through the full node path:
//! real transactions, block building, state commit, and RPC reads.

use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};
use alloy::{
    network::ReceiptResponse,
    primitives::{B256, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::ITemporaryStorage;
use tempo_precompiles::{TEMPORARY_STORAGE_ADDRESS, temporary_storage::EPOCH_LENGTH};
use tempo_primitives::TemporaryStorageAccount;

#[tokio::test(flavor = "multi_thread")]
async fn test_temporary_storage_survives_block_commit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let sender = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);

    let temporary_storage = ITemporaryStorage::new(TEMPORARY_STORAGE_ADDRESS, &provider);
    let key = B256::repeat_byte(0x01);
    let value = B256::repeat_byte(0x02);

    // Store in block N.
    let receipt = temporary_storage
        .temporaryStore(key, value)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(500_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "temporaryStore tx should succeed");
    let store_block = receipt.block_number().expect("receipt has block number");

    // Overwrite the same slot to measure `intrinsic + existing-slot store (~7.1k)`
    // with identical calldata size, independent of the fee model.
    let value2 = B256::repeat_byte(0x03);
    let receipt = temporary_storage
        .temporaryStore(key, value2)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(500_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(
        receipt.status(),
        "overwrite temporaryStore tx should succeed"
    );
    let existing_store_gas = receipt.gas_used;

    // A store that runs out of gas inside the precompile must fail without leaving
    // partial state: `existing_store_gas + 10k` clears tx validation but is ~23k short
    // of a new-slot store (40k). This tx also lands in a block > N, so the reads below
    // are guaranteed to cross a block commit.
    let oog_key = B256::repeat_byte(0xEE);
    let receipt = temporary_storage
        .temporaryStore(oog_key, value)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(existing_store_gas + 10_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(!receipt.status(), "underfunded temporaryStore should fail");
    assert!(receipt.block_number().expect("receipt has block number") > store_block);

    // The stored value survives block commit; the failed store left nothing behind.
    let loaded = temporary_storage.temporaryLoad(key).call().await?;
    assert_eq!(loaded, value2);
    let loaded = temporary_storage.temporaryLoad(oog_key).call().await?;
    assert_eq!(loaded, B256::ZERO);

    // The boundary hook deployed the 0xEF marker to the precompile and the current
    // epoch's account, and the value sits in the epoch account's storage.
    let epoch_account = TemporaryStorageAccount::for_epoch(store_block / EPOCH_LENGTH).address();
    assert_eq!(
        provider
            .get_code_at(TEMPORARY_STORAGE_ADDRESS)
            .await?
            .as_ref(),
        [0xef]
    );
    assert_eq!(provider.get_code_at(epoch_account).await?.as_ref(), [0xef]);

    let slot = keccak256([sender.as_slice(), key.as_slice()].concat());
    let stored = provider
        .get_storage_at(epoch_account, U256::from_be_bytes(slot.0))
        .await?;
    assert_eq!(B256::from(stored), value2);

    Ok(())
}
