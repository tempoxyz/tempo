//! `check-proofs`: state proofs every node serves through `eth_getMultiProof` verify against
//! the block's state root, and nodes that hold the same block serve the same proof.
//!
//! A trie bug that computes a wrong root or a wrong proof node shows up here as a proof that does
//! not verify, or as two nodes on one block disagreeing, whichever part of the trie it touches:
//! present and absent accounts, present and absent storage slots, on the zone and on L1.

use alloy::{
    primitives::{Address, B256, U256, keccak256},
    providers::{DynProvider, Provider},
    rpc::types::{BlockId, BlockNumberOrTag, EIP1186AccountProofResponse},
};
use alloy_rlp::Decodable as _;
use alloy_trie::{
    EMPTY_ROOT_HASH, KECCAK_EMPTY, Nibbles, TrieAccount, nodes::TrieNode, proof::verify_proof,
};
use antithesis_sdk::{assert_always, assert_sometimes};
use serde_json::json;
use std::collections::BTreeMap;
use tempo_contracts::{
    precompiles::ITIP20,
    zones::{ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS},
};
use tempo_precompiles::PATH_USD_ADDRESS;

use super::{
    APPROVAL_SPENDERS, Context, Record, approval_spender, collide::collision_slot, is_rpc_error,
    random_below, random_spender, shuffled,
};

/// Workload accounts whose pathUSD balance slot each run proves.
const PROOF_ACCOUNTS: usize = 12;
/// Workload accounts whose allowance to one of their approval spenders each run proves.
const PROOF_OWNERS: usize = 6;
/// Colliding allowance pairs whose keys each run proves.
const COLLISION_GROUPS: usize = 2;
/// Random keys and addresses each run proves, which are almost always absent.
const RANDOM_KEYS: usize = 4;
/// Highest slot index `check-proofs` tries when looking for the TIP-20 balances mapping.
const MAX_MAPPING_SLOT: u64 = 32;

/// Asserts with the zone or L1 message: the Antithesis SDK needs each message to be a literal.
macro_rules! assert_on {
    ($zone:expr, $assert:ident, $condition:expr, $zone_message:literal, $l1_message:literal, $details:expr) => {
        if $zone {
            $assert!($condition, $zone_message, $details)
        } else {
            $assert!($condition, $l1_message, $details)
        }
    };
}

/// One node's proofs at one block.
struct NodeProofs {
    node: String,
    block_hash: B256,
    proofs: Vec<EIP1186AccountProofResponse>,
}

impl Context {
    pub(super) async fn check_proofs(&self) -> eyre::Result<()> {
        let accounts: Vec<Address> = shuffled(self.ledger.accounts()?)
            .into_iter()
            .take(PROOF_ACCOUNTS)
            .map(|account| account.address())
            .collect();
        let mut zone_slots: Vec<B256> = (0..RANDOM_KEYS).map(|_| random_b256()).collect();
        if let Some(index) = self.balances_mapping_slot(&accounts).await? {
            zone_slots.extend(accounts.iter().map(|account| mapping_key(*account, index)));
            // pathUSD's allowances mapping follows the balances one. Keys into owners'
            // approval sets cover set, cleared and never-set allowances.
            zone_slots.extend(
                accounts
                    .iter()
                    .take(PROOF_OWNERS)
                    .map(|owner| nested_mapping_key(*owner, random_spender(*owner), index + 1)),
            );
            // Half the time, one owner's whole approval set in the same request, so one proof
            // covers many keys of the same subtrie.
            if let Some(owner) = accounts.first().filter(|_| random_below(2) == 0) {
                zone_slots.extend((0..APPROVAL_SPENDERS).map(|spender| {
                    nested_mapping_key(*owner, approval_spender(*owner, spender), index + 1)
                }));
            }
        }
        // Keys of a few collision groups, which share long prefixes, nest subtries and may hold
        // leaves embedded in their parent branch.
        let collisions = self
            .ledger
            .records()?
            .into_iter()
            .filter_map(|record| match record {
                Record::Collision {
                    kind,
                    owner,
                    members,
                    ..
                } => Some((kind, owner, members)),
                _ => None,
            })
            .collect();
        for (kind, owner, members) in shuffled(collisions).into_iter().take(COLLISION_GROUPS) {
            zone_slots.extend(
                members
                    .into_iter()
                    .map(|member| collision_slot(kind, owner, member)),
            );
        }
        let mut addresses: Vec<Address> =
            vec![PATH_USD_ADDRESS, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS];
        addresses.extend(accounts.iter().copied());
        addresses.extend((0..RANDOM_KEYS).map(|_| Address::from_word(random_b256())));

        // Prove one block every reachable node holds, so their answers can be compared.
        let mut heights = Vec::new();
        for zone in &self.zones {
            if let Ok(height) = zone.get_block_number().await {
                heights.push(height);
            }
        }
        let Some(&lowest) = heights.iter().min() else {
            println!("check-proofs: no zone node reachable");
            return Ok(());
        };
        // Half the time a recent block, otherwise any earlier one, which nodes answer from
        // historical state rather than the latest trie.
        let historical = random_below(2) == 0;
        let height = if historical {
            random_below(lowest + 1)
        } else {
            lowest.saturating_sub(random_below(4))
        };
        let mut zone_proofs = Vec::new();
        for (url, zone) in self.zone_urls.iter().zip(&self.zones) {
            let requests: Vec<(Address, Vec<B256>)> = addresses
                .iter()
                .map(|address| {
                    let keys = if *address == PATH_USD_ADDRESS {
                        zone_slots.clone()
                    } else {
                        Vec::new()
                    };
                    (*address, keys)
                })
                .collect();
            match prove(zone, height, &requests).await {
                Ok(Some(proofs)) => zone_proofs.push(NodeProofs {
                    node: url.to_string(),
                    block_hash: proofs.0,
                    proofs: proofs.1,
                }),
                Ok(None) => {}
                Err(error) if is_rpc_error(&error) => println!("check-proofs: {url}: {error:#}"),
                Err(error) => return Err(error),
            }
        }
        assert_sometimes!(
            historical && lowest.saturating_sub(height) > 100 && zone_proofs.len() > 1,
            "Zone proofs served for a block over 100 blocks old",
            &json!({ "height": height, "tip": lowest, "nodes": zone_proofs.len() })
        );
        self.assert_proofs("Zone", height, zone_proofs).await?;

        // L1 proofs: the portal's storage holds the zone's settled state and deposit queue.
        let l1_height = match self.l1.get_block_number().await {
            Ok(height) => height.saturating_sub(random_below(4)),
            Err(error) => {
                println!("check-proofs: L1 unavailable: {error:#}");
                return Ok(());
            }
        };
        let mut portal_slots: Vec<B256> = (0..RANDOM_KEYS).map(|_| random_b256()).collect();
        portal_slots.extend((0..8u64).map(|slot| B256::from(U256::from(slot))));
        let mut l1_requests = vec![(self.portal, portal_slots), (PATH_USD_ADDRESS, Vec::new())];
        l1_requests.extend(accounts.iter().map(|account| (*account, Vec::new())));
        let mut l1_proofs = Vec::new();
        match prove(&self.l1, l1_height, &l1_requests).await {
            Ok(Some((block_hash, proofs))) => l1_proofs.push(NodeProofs {
                node: self.l1_url.to_string(),
                block_hash,
                proofs,
            }),
            Ok(None) => {}
            Err(error) if is_rpc_error(&error) => println!("check-proofs: L1: {error:#}"),
            Err(error) => return Err(error),
        }
        self.assert_proofs("L1", l1_height, l1_proofs).await
    }

    async fn assert_proofs(
        &self,
        chain: &str,
        height: u64,
        node_proofs: Vec<NodeProofs>,
    ) -> eyre::Result<()> {
        let zone = chain == "Zone";
        let mut by_block: BTreeMap<B256, Vec<&NodeProofs>> = BTreeMap::new();
        for node in &node_proofs {
            by_block.entry(node.block_hash).or_default().push(node);
        }
        for (block_hash, nodes) in &by_block {
            let Some(header) = self.header_root(chain, nodes[0], *block_hash).await? else {
                continue;
            };
            for node in nodes {
                for proof in &node.proofs {
                    let failure = verify(header, proof).err();
                    assert_on!(
                        zone,
                        assert_always,
                        failure.is_none(),
                        "Zone eth_getMultiProof verifies against the block's state root",
                        "L1 eth_getMultiProof verifies against the block's state root",
                        &json!({
                            "node": node.node,
                            "height": height,
                            "block": block_hash,
                            "state_root": header,
                            "address": proof.address,
                            "slots": proof.storage_proof.len(),
                            "failure": failure,
                        })
                    );
                    assert_on!(
                        zone,
                        assert_sometimes,
                        failure.is_none() && !proof.storage_proof.is_empty(),
                        "Zone storage proofs verify",
                        "L1 storage proofs verify",
                        &json!({ "node": node.node, "address": proof.address })
                    );
                }
            }
            // The test runs one L1 node, so only zone nodes have answers to compare.
            if zone {
                for pair in nodes.windows(2) {
                    let (a, b) = (pair[0], pair[1]);
                    let differing: Vec<Address> = a
                        .proofs
                        .iter()
                        .zip(&b.proofs)
                        .filter(|(x, y)| x != y)
                        .map(|(x, _)| x.address)
                        .collect();
                    assert_always!(
                        differing.is_empty(),
                        "Zone nodes serve the same proof for the same block",
                        &json!({
                            "nodes": [a.node, b.node],
                            "height": height,
                            "block": block_hash,
                            "addresses": differing,
                        })
                    );
                }
            }
        }
        if zone {
            assert_sometimes!(
                by_block.values().any(|nodes| nodes.len() > 1),
                "Zone proofs from several nodes compared",
                &json!({ "height": height })
            );
        }
        Ok(())
    }

    /// The state root of `block_hash` as the node that served the proof reports it.
    async fn header_root(
        &self,
        chain: &str,
        node: &NodeProofs,
        block_hash: B256,
    ) -> eyre::Result<Option<B256>> {
        let provider = if chain == "L1" {
            &self.l1
        } else {
            let index = self
                .zone_urls
                .iter()
                .position(|url| url.as_str() == node.node);
            &self.zones[index.unwrap_or_default()]
        };
        match provider.get_block_by_hash(block_hash).await {
            Ok(block) => Ok(block.map(|block| block.header.state_root)),
            Err(error) => {
                println!("check-proofs: {}: {error:#}", node.node);
                Ok(None)
            }
        }
    }

    /// Finds the storage index of pathUSD's balances mapping from an account holding a balance.
    async fn balances_mapping_slot(&self, accounts: &[Address]) -> eyre::Result<Option<u64>> {
        let zone = self.random_zone();
        for account in accounts {
            let Ok(balance) = ITIP20::new(PATH_USD_ADDRESS, zone)
                .balanceOf(*account)
                .from(*account)
                .call()
                .await
            else {
                return Ok(None);
            };
            if balance.is_zero() {
                continue;
            }
            for index in 0..MAX_MAPPING_SLOT {
                let Ok(value) = zone
                    .get_storage_at(PATH_USD_ADDRESS, mapping_key(*account, index).into())
                    .await
                else {
                    return Ok(None);
                };
                if value == balance {
                    return Ok(Some(index));
                }
            }
        }
        Ok(None)
    }
}

/// Fetches every requested proof at `height`, with the block hash they were served for. Returns
/// `None` when the node does not hold the block.
async fn prove(
    provider: &DynProvider,
    height: u64,
    requests: &[(Address, Vec<B256>)],
) -> eyre::Result<Option<(B256, Vec<EIP1186AccountProofResponse>)>> {
    let Some(block) = provider
        .get_block_by_number(BlockNumberOrTag::Number(height))
        .await?
    else {
        return Ok(None);
    };
    let block_hash = block.header.hash;
    // One multiproof for every target, so a single proof_v2 calculation covers many keys of the
    // same subtries and the V2 proof encoding is what gets verified.
    let proofs: Vec<EIP1186AccountProofResponse> = provider
        .raw_request(
            "eth_getMultiProof".into(),
            (requests, BlockId::hash(block_hash)),
        )
        .await?;
    eyre::ensure!(
        proofs.len() == requests.len(),
        "eth_getMultiProof returned {} proofs for {} targets",
        proofs.len(),
        requests.len()
    );
    Ok(Some((block_hash, proofs)))
}

/// Verifies an account proof against `state_root` and each storage proof against the account's
/// storage root.
fn verify(state_root: B256, proof: &EIP1186AccountProofResponse) -> Result<(), String> {
    let absent = proof.nonce == 0
        && proof.balance.is_zero()
        && (proof.code_hash == KECCAK_EMPTY || proof.code_hash.is_zero())
        && (proof.storage_hash == EMPTY_ROOT_HASH || proof.storage_hash.is_zero());
    let key = Nibbles::unpack(keccak256(proof.address));
    if absent {
        verify_proof(state_root, key, None, &proof.account_proof)
            .map_err(|error| format!("account exclusion proof: {error}"))?;
    } else {
        // Tempo accounts can carry an extension the RPC response leaves out, so the leaf's own
        // value is checked against the reported fields and then proven.
        let leaf = proof
            .account_proof
            .last()
            .and_then(|node| match TrieNode::decode(&mut node.as_ref()) {
                Ok(TrieNode::Leaf(leaf)) => Some(leaf.value),
                _ => None,
            })
            .ok_or("account proof does not end in a leaf")?;
        let account = TrieAccount::decode(&mut leaf.as_slice())
            .map_err(|error| format!("account leaf: {error}"))?;
        if (
            account.nonce,
            account.balance,
            account.storage_root,
            account.code_hash,
        ) != (
            proof.nonce,
            proof.balance,
            proof.storage_hash,
            proof.code_hash,
        ) {
            return Err(format!(
                "account leaf {account:?} does not match the response"
            ));
        }
        verify_proof(state_root, key, Some(leaf), &proof.account_proof)
            .map_err(|error| format!("account proof: {error}"))?;
    }
    let storage_root = if absent {
        EMPTY_ROOT_HASH
    } else {
        proof.storage_hash
    };
    for slot in &proof.storage_proof {
        let key = slot.key.as_b256();
        let expected = (!slot.value.is_zero()).then(|| alloy_rlp::encode(slot.value));
        verify_proof(
            storage_root,
            Nibbles::unpack(keccak256(key)),
            expected,
            &slot.proof,
        )
        .map_err(|error| format!("storage proof for {key}: {error}"))?;
    }
    Ok(())
}

/// The storage key of `account` in a Solidity-layout mapping at slot `index`.
fn mapping_key(account: Address, index: u64) -> B256 {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(account.as_slice());
    preimage[32..].copy_from_slice(&U256::from(index).to_be_bytes::<32>());
    keccak256(preimage)
}

/// The storage key of `outer`, `inner` in a Solidity-layout nested mapping at slot `index`.
fn nested_mapping_key(outer: Address, inner: Address, index: u64) -> B256 {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(inner.as_slice());
    preimage[32..].copy_from_slice(mapping_key(outer, index).as_slice());
    keccak256(preimage)
}

fn random_b256() -> B256 {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&antithesis_sdk::random::get_random().to_be_bytes());
    }
    B256::from(bytes)
}
