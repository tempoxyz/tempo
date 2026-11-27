use crate::utils::TestNodeBuilder;
use alloy::{
    hex,
    primitives::{Address, B256, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::EIP1186AccountProofResponse,
};
use futures::future::try_join_all;
use reth_trie_common::AccountProof;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Snapshots and verifies `eth_getMultiProof` per proof ending. Both tries hash keys to `1230..`,
/// `1231..` and `20..`; absent keys end at the root (`3..`), extension (`124..`) or leaf (`21..`).
#[tokio::test(flavor = "multi_thread")]
async fn multi_proof_snapshots() -> eyre::Result<()> {
    let address = |prefix| grind(prefix, |i| Address::from_word(i.into()));
    let slot = |prefix| grind(prefix, B256::from);
    let [account, leaf_account] = ["1230", "20"].map(address);
    let storage: BTreeMap<_, _> = ["1230", "1231", "20"]
        .map(|prefix| (slot(prefix), B256::with_last_byte(1)))
        .into();

    let mut genesis: Value = serde_json::from_str(include_str!("../assets/test-genesis.json"))?;
    genesis["alloc"] = serde_json::to_value(BTreeMap::from([
        (account, json!({ "balance": "0x1", "storage": storage })),
        (address("1231"), json!({ "balance": "0x2" })),
        (leaf_account, json!({ "balance": "0x3" })),
    ]))?;
    let setup = TestNodeBuilder::new()
        .with_genesis(genesis.to_string())
        .with_instant_mining()
        .build_http_only()
        .await?;
    let provider = ProviderBuilder::new().connect_http(setup.http_url);
    // Untyped so the snapshot holds the exact wire output.
    let multi_proof = async |targets: &[(Address, Vec<B256>)]| {
        provider
            .client()
            .request::<_, Vec<Value>>("eth_getMultiProof", (targets, "0x0"))
            .await
    };
    let (names, targets) = <(Vec<_>, Vec<_>)>::from_iter([
        ("account_present_below_extension", (account, vec![])),
        ("account_present_leaf", (leaf_account, vec![])),
        ("account_absent_at_branch", (address("3"), vec![])),
        ("account_absent_at_extension", (address("124"), vec![])),
        ("account_absent_at_leaf", (address("21"), vec![])),
        ("storage_present", (account, vec![slot("1230"), slot("20")])),
        ("storage_absent_at_branch", (account, vec![slot("3")])),
        ("storage_absent_at_extension", (account, vec![slot("124")])),
        ("storage_absent_at_leaf", (account, vec![slot("21")])),
        ("storage_absent_empty_trie", (leaf_account, vec![slot("3")])),
    ]);
    let (block, singles, combined) = tokio::try_join!(
        provider.get_block_by_number(0.into()),
        try_join_all(targets.chunks(1).map(&multi_proof)),
        multi_proof(&targets),
    )?;
    for (name, response) in names.into_iter().zip(&singles) {
        insta::assert_snapshot!(name, serde_json::to_string_pretty(response)?);
    }
    assert_eq!(combined, singles.concat());
    let state_root = block.expect("genesis block").header.state_root;
    for proof in &combined {
        AccountProof::from(EIP1186AccountProofResponse::deserialize(proof)?).verify(state_root)?;
    }
    Ok(())
}

/// Returns the first candidate whose keccak hash starts with the hex nibbles `prefix`.
fn grind<T: AsRef<[u8]>>(prefix: &str, candidate: impl Fn(U256) -> T) -> T {
    (0u64..)
        .map(|i| candidate(U256::from(i)))
        .find(|key| hex::encode(keccak256(key)).starts_with(prefix))
        .expect("prefix is reachable")
}
