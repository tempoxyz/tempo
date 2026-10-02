use crate::utils::TestNodeBuilder;
use alloy::{
    eips::{
        eip7002::WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
        eip7251::CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
    },
    primitives::{B256, U256, keccak256},
    providers::{Provider, ProviderBuilder},
};
use alloy_trie::{Nibbles, TrieAccount, proof::verify_proof};
use std::time::Duration;

#[test_case::test_case(0, false; "sequential_sync_root")]
#[test_case::test_case(0, true; "sequential_shared_root")]
#[test_case::test_case(4, false; "parallel_sync_root")]
#[test_case::test_case(4, true; "parallel_shared_root")]
#[tokio::test(flavor = "multi_thread")]
async fn post_block_state_is_included_in_header_root(
    execution_threads: usize,
    share_sparse_trie: bool,
) -> eyre::Result<()> {
    let addresses = [
        WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
        CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
    ];
    let mut genesis: serde_json::Value =
        serde_json::from_str(include_str!("../assets/test-genesis.json"))?;
    for address in addresses {
        // Increment slot zero on every post-block system call and return no requests.
        genesis["alloc"][format!("{address:#x}")] = serde_json::json!({
            "balance": "0x0", "nonce": "0x1", "code": "0x60005460010160005500",
        });
    }
    let setup = TestNodeBuilder::new()
        .with_genesis(serde_json::to_string(&genesis)?)
        .with_execution_threads(execution_threads)
        .with_shared_sparse_trie(share_sparse_trie)
        .with_proof_window(64)
        .build_http_only()
        .await?;
    let provider = ProviderBuilder::new().connect_http(setup.http_url.clone());
    tokio::time::timeout(Duration::from_secs(10), async {
        while provider.get_block_number().await? < 3 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, eyre::Error>(())
    })
    .await??;
    let block = provider
        .get_block_by_number(3.into())
        .await?
        .expect("block 3 exists");
    for address in addresses {
        let proof = provider
            .get_proof(address, vec![B256::ZERO])
            .block_id(3.into())
            .await?;
        assert_eq!(proof.storage_proof[0].value, U256::from(3));
        let account = TrieAccount {
            nonce: proof.nonce,
            balance: proof.balance,
            storage_root: proof.storage_hash,
            code_hash: proof.code_hash,
        };
        // Check the persisted post-block storage against the root committed in
        // the block, not just against another invocation of the same builder.
        verify_proof(
            block.header.state_root,
            Nibbles::unpack(keccak256(address)),
            Some(alloy_rlp::encode(account)),
            &proof.account_proof,
        )?;
        verify_proof(
            proof.storage_hash,
            Nibbles::unpack(keccak256(B256::ZERO)),
            Some(alloy_rlp::encode(U256::from(3))),
            &proof.storage_proof[0].proof,
        )?;
    }
    Ok(())
}
