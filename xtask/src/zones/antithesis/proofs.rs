//! Independently verify pathUSD proofs and compare finalized state across execution profiles.

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{DynProvider, Provider},
    rpc::types::{BlockId, BlockNumberOrTag, EIP1186AccountProofResponse, Header},
};
use alloy_trie::{Nibbles, TrieAccount, nodes::TrieNode, proof::verify_proof};
use antithesis_sdk::{assert_always, assert_sometimes};
use eyre::{Context as _, OptionExt as _, Result, ensure};
use serde_json::json;
use std::time::Duration;
use tempo_precompiles::{PATH_USD_ADDRESS, tip20::TIP20Token};
use tokio::time::{sleep, timeout};

use super::{Context, POLL, checks::SETTLE_TIMEOUT};

const PROOF_RPC_TIMEOUT: Duration = Duration::from_secs(5);

impl Context {
    /// Checks one finalized payment-token state across every execution profile. During faults,
    /// unavailable samples are skipped; `eventually` retries them within the recovery budget.
    pub(super) async fn check_proofs(&self, eventually: bool) -> Result<()> {
        ensure!(
            self.zones.len() == 4,
            "proof checks require four execution profiles"
        );
        ensure!(
            self.l1_validators.len() == 4,
            "proof checks require four L1 validators"
        );
        let accounts = self.ledger.accounts()?;
        ensure!(
            !accounts.is_empty(),
            "seed the payment workload before checking proofs"
        );
        let token = TIP20Token::from_address_unchecked(PATH_USD_ADDRESS);
        // Follow newly created accounts while bounding each proof to 64 storage slots.
        let mut slots = vec![B256::from(token.total_supply.slot())];
        slots.extend(
            accounts
                .iter()
                .rev()
                .take(63)
                .map(|account| B256::from(token.balances[account.address()].slot())),
        );
        let mut zone_nodes: Vec<_> = [
            "optimized",
            "sequential-fallback",
            "cache-disabled-comparison",
            "fast-fallback",
        ]
        .into_iter()
        .zip(&self.zones)
        .map(|(profile, provider)| NodeProgress {
            profile,
            provider,
            verified: false,
        })
        .collect();
        let mut l1_nodes: Vec<_> = [
            "certified-follower",
            "sequential-fallback",
            "optimized",
            "fast-fallback",
            "cache-disabled-comparison",
        ]
        .into_iter()
        .zip(std::iter::once(&self.l1).chain(&self.l1_validators))
        .map(|(profile, provider)| NodeProgress {
            profile,
            provider,
            verified: false,
        })
        .collect();
        // Both chains get the same recovery window; one unavailable chain cannot hide the other.
        futures::future::try_join(
            check_node_proofs("L1", &mut l1_nodes, &slots, eventually),
            check_node_proofs("Zone", &mut zone_nodes, &slots, eventually),
        )
        .await?;
        Ok(())
    }
}

/// Samples one chain independently; an incomplete sample is not an error during faults.
async fn check_node_proofs(
    chain: &str,
    nodes: &mut [NodeProgress<'_>],
    slots: &[B256],
    eventually: bool,
) -> Result<()> {
    let mut target: Option<Header> = None;
    let mut reference = None;
    let mut comparisons = 0;
    let mut compared_height = None;

    // Pin once and retain verified nodes across retries, even if they later go offline.
    let sample = async {
        loop {
            for node in nodes.iter_mut().filter(|node| !node.verified) {
                let finalized = match timeout(
                    PROOF_RPC_TIMEOUT,
                    node.provider
                        .get_block_by_number(BlockNumberOrTag::Finalized),
                )
                .await
                {
                    Ok(Ok(Some(block))) => block.header,
                    other => {
                        eprintln!(
                            "{chain} {}: finalized block unavailable: {other:?}",
                            node.profile
                        );
                        continue;
                    }
                };
                let pinned = target.get_or_insert_with(|| finalized.clone());
                if finalized.number < pinned.number {
                    continue;
                }
                let header = match timeout(
                    PROOF_RPC_TIMEOUT,
                    node.provider.get_block_by_number(pinned.number.into()),
                )
                .await
                {
                    Ok(Ok(Some(block))) => block.header,
                    _ => continue,
                };
                let same_header = header.hash == pinned.hash && header.inner == pinned.inner;
                assert_always!(
                    same_header,
                    "Independently finalized execution histories agree",
                    &json!({
                        "chain": chain, "profile": node.profile, "number": pinned.number,
                        "expected": pinned.hash, "actual": header.hash
                    })
                );
                ensure!(same_header, "independently finalized block hashes diverge");

                let proof = match timeout(
                    PROOF_RPC_TIMEOUT,
                    node.provider
                        .get_proof(PATH_USD_ADDRESS, slots.to_vec())
                        .block_id(BlockId::hash_canonical(pinned.hash)),
                )
                .await
                {
                    Ok(Ok(proof)) => proof,
                    other => {
                        eprintln!("{chain} {}: proof unavailable: {other:?}", node.profile);
                        continue;
                    }
                };
                // Discard a proof if its block stopped being canonical while it was fetched.
                match timeout(
                    PROOF_RPC_TIMEOUT,
                    node.provider.get_block_by_number(pinned.number.into()),
                )
                .await
                {
                    Ok(Ok(Some(block))) if block.header == header => {}
                    _ => continue,
                }
                let verified = verify_account_and_storage(&header, PATH_USD_ADDRESS, slots, &proof);
                assert_always!(
                    verified.is_ok(),
                    "Execution account and storage proofs verify independently",
                    &json!({
                        "chain": chain, "profile": node.profile, "address": PATH_USD_ADDRESS, "block_hash": header.hash,
                        "error": verified.as_ref().err().map(|error| format!("{error:#}"))
                    })
                );
                let verified = verified?;
                if let Some(reference) = &reference {
                    let agrees = reference == &verified;
                    assert_always!(
                        agrees,
                        "Proven execution account and storage fields agree at identical block hash",
                        &json!({
                            "chain": chain, "profile": node.profile, "block_hash": header.hash
                        })
                    );
                    ensure!(agrees, "proven fields diverge at identical block hash");
                    comparisons += 1;
                    compared_height = Some(pinned.number);
                } else {
                    reference = Some(verified);
                }
                node.verified = true;
            }
            if nodes.iter().all(|node| node.verified) {
                return Ok(true);
            }
            if !eventually {
                return Ok(false);
            }
            // Only unfinished state samples are retried, within the outer deadline.
            sleep(POLL).await;
        }
    };
    let result = timeout(SETTLE_TIMEOUT, sample).await;

    let result: Result<bool> = match result {
        Ok(result) => result,
        Err(error) if eventually => {
            assert_always!(
                false,
                "Eventually sampled finalized execution state is available",
                &json!({"chain": chain})
            );
            Err(eyre::Report::new(error).wrap_err("eventual availability deadline expired"))
        }
        Err(_) => Ok(false),
    };
    if eventually && result.as_ref().is_ok_and(|complete| *complete) {
        assert_always!(
            true,
            "Eventually sampled finalized execution state is available",
            &json!({"chain": chain})
        );
    }
    if chain == "L1" {
        assert_sometimes!(
            comparisons > 0,
            "L1 execution profiles compare independently proven state",
            &json!({"comparisons": comparisons})
        );
        assert_sometimes!(
            compared_height.is_some_and(|height| height > 0),
            "L1 proof comparisons reach finalized non-genesis state",
            &json!({"height": compared_height})
        );
    } else {
        assert_sometimes!(
            comparisons > 0,
            "Zone execution profiles compare independently proven state",
            &json!({"comparisons": comparisons})
        );
        assert_sometimes!(
            compared_height.is_some_and(|height| height > 0),
            "Zone proof comparisons reach finalized non-genesis state",
            &json!({"height": compared_height})
        );
    }
    println!(
        "{}",
        json!({"chain": chain, "coverage": result.as_ref().is_ok_and(|complete| *complete), "comparisons": comparisons})
    );
    result.map(|_| ())
}

/// Progress for one node at the command's pinned finalized block.
struct NodeProgress<'a> {
    profile: &'static str,
    provider: &'a DynProvider,
    verified: bool,
}

/// Only independently authenticated fields participate in the cross-profile comparison.
#[derive(Debug, PartialEq, Eq)]
struct VerifiedState {
    account: Option<TrieAccount>,
    storage: Vec<U256>,
}

fn verify_account_and_storage(
    header: &Header,
    address: Address,
    slots: &[B256],
    proof: &EIP1186AccountProofResponse,
) -> Result<VerifiedState> {
    ensure!(proof.address == address, "proof address mismatch");
    let key = Nibbles::unpack(keccak256(address));
    let account = if verify_proof(
        header.state_root,
        key,
        None,
        hashed_nodes(&proof.account_proof),
    )
    .is_ok()
    {
        None
    } else {
        let mut account = None;
        for node in &proof.account_proof {
            if let TrieNode::Leaf(leaf) =
                alloy_rlp::decode_exact::<TrieNode>(node).wrap_err("decode account proof node")?
                && verify_proof(
                    header.state_root,
                    key,
                    Some(leaf.value.clone()),
                    hashed_nodes(&proof.account_proof),
                )
                .is_ok()
            {
                account = Some(
                    alloy_rlp::decode_exact::<TrieAccount>(&leaf.value)
                        .wrap_err("decode Tempo account including extension")?,
                );
                break;
            }
        }
        Some(account.ok_or_eyre("no independently verified account leaf")?)
    };
    let fields = account.clone().unwrap_or_default();
    ensure!(
        fields.nonce == proof.nonce
            && fields.balance == proof.balance
            && (fields.code_hash == proof.code_hash
                || (account.is_none() && proof.code_hash.is_zero()))
            && (fields.storage_root == proof.storage_hash
                || (account.is_none() && proof.storage_hash.is_zero())),
        "RPC account fields do not match proven account"
    );
    ensure!(
        proof.storage_proof.len() == slots.len(),
        "storage proof count mismatch"
    );
    let mut storage = Vec::with_capacity(slots.len());
    for slot in slots {
        let mut matches = proof
            .storage_proof
            .iter()
            .filter(|entry| entry.key.as_b256() == *slot);
        let entry = matches
            .next()
            .ok_or_eyre("missing requested storage proof")?;
        ensure!(matches.next().is_none(), "duplicate storage proof");
        let expected = (!entry.value.is_zero()).then(|| alloy_rlp::encode(entry.value));
        verify_proof(
            fields.storage_root,
            Nibbles::unpack(keccak256(slot)),
            expected,
            hashed_nodes(&entry.proof),
        )
        .wrap_err("verify storage proof")?;
        storage.push(entry.value);
    }
    Ok(VerifiedState { account, storage })
}

// Inline descendants are already authenticated and traversed by alloy's verifier. Some RPCs
// redundantly append them, whereas the verifier expects only the root and hashed descendants.
fn hashed_nodes(proof: &[Bytes]) -> impl Iterator<Item = &Bytes> {
    proof
        .iter()
        .enumerate()
        .filter(|(index, node)| *index == 0 || node.len() >= 32)
        .map(|(_, node)| node)
}
