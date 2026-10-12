//! End-to-end coverage for the Zone stateless proof function.
//!
//! These tests intentionally cover only two primary paths:
//!
//! 1. A two-block transition that carries user state between blocks.
//! 2. Execution-root parity for a non-empty production-builder block.

use std::{collections::BTreeMap, sync::Arc};

use alloy::{
    consensus::{BlockHeader as _, Sealable as _},
    eips::BlockNumberOrTag,
    genesis::{Genesis, GenesisAccount},
    primitives::{Address, B256, Bytes, U256, address, keccak256},
    providers::Provider as _,
    rpc::types::TransactionRequest,
};
use reth_chainspec::EthChainSpec as _;
use reth_trie_common::{EMPTY_ROOT_HASH, HashBuilder, Nibbles, TrieAccount, proof::ProofRetainer};
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_precompiles::{
    PATH_USD_ADDRESS, TIP403_REGISTRY_ADDRESS,
    storage::StorageKey as _,
    tip20::tip20_slots,
    tip403_registry::{ALLOW_ALL_POLICY_ID, tip403_registry_slots},
};
use tempo_primitives::TempoHeader;
use zone_chainspec::ZoneChainSpec;
use zone_rpc::types::ZoneExecutionWitness;
use zone_spf::{
    BatchWitness, PublicInputs, SpfConfig, TempoImport, TempoStateWitness, ZoneBlock,
    ZoneStateWitness, prove_zone_batch,
};

use crate::utils::{
    DEFAULT_TIMEOUT, TIP20_TX_GAS, start_local_zone_with_fixture_and_withdrawal_batch_interval,
};

const ZONE_ID: u32 = 1;

#[tokio::test(flavor = "multi_thread")]
async fn spf_batch_execute() -> eyre::Result<()> {
    let genesis = funded_zone_genesis();
    let (zone, mut fixture) =
        start_local_zone_with_fixture_and_withdrawal_batch_interval(ZONE_ID, 2, 2, genesis.clone())
            .await?;
    let provider = zone.provider();
    let (wallet_provider, sender) = crate::utils::local_dev_zone_account(&zone)?;
    let initial_fee_balance = zone.balance_of(PATH_USD_ADDRESS, sender).await?;

    let first_pending = wallet_provider
        .send_transaction(state_changing_transaction(address!(
            "000000000000000000000000000000000000b001"
        )))
        .await?;
    let first_transaction_hash = *first_pending.tx_hash();
    let mut first_tempo_block = fixture.next_block();
    first_tempo_block.header.inner.state_root = EMPTY_ROOT_HASH;
    fixture.enqueue(&first_tempo_block, zone.deposit_queue(), vec![]);
    assert!(first_pending.get_receipt().await?.status());
    zone.wait_for_block_number(1, DEFAULT_TIMEOUT).await?;

    let second_pending = wallet_provider
        .send_transaction(state_changing_transaction(address!(
            "000000000000000000000000000000000000b002"
        )))
        .await?;
    let second_transaction_hash = *second_pending.tx_hash();
    let mut second_tempo_block = fixture.next_block();
    second_tempo_block.header.inner.state_root = EMPTY_ROOT_HASH;
    second_tempo_block.header.inner.parent_hash = first_tempo_block.header.hash_slow();
    fixture.enqueue(&second_tempo_block, zone.deposit_queue(), vec![]);
    assert!(second_pending.get_receipt().await?.status());
    zone.wait_for_block_number(2, DEFAULT_TIMEOUT).await?;

    let genesis_block = provider
        .get_block_by_number(0.into())
        .await?
        .expect("Zone genesis block");
    let first_built_block = provider
        .get_block_by_number(1.into())
        .await?
        .expect("first builder-produced Zone block");
    let second_built_block = provider
        .get_block_by_number(2.into())
        .await?
        .expect("second builder-produced Zone block");
    assert_eq!(first_built_block.transactions.len(), 2);
    assert_eq!(second_built_block.transactions.len(), 3);
    assert_eq!(provider.get_transaction_count(sender).await?, 2);
    assert!(
        zone.balance_of(PATH_USD_ADDRESS, sender).await? < initial_fee_balance,
        "both user transactions must charge the sender's proven fee-token balance"
    );

    let first_raw_transaction = provider
        .get_raw_transaction_by_hash(first_transaction_hash)
        .await?
        .expect("first raw user transaction");
    let second_raw_transaction = provider
        .get_raw_transaction_by_hash(second_transaction_hash)
        .await?
        .expect("second raw user transaction");

    let (state_root, zone_state_witness) = zone_state_witness(&genesis);
    assert_eq!(state_root, genesis_block.header.state_root());
    let tempo_header = TempoHeader::default();
    let tempo_header_rlp = Bytes::from(alloy_rlp::encode(&tempo_header));
    let config = spf_config(&genesis);
    let parent_header = config.chain_spec().genesis_header().clone();
    let parent_hash = parent_header.hash_slow();
    let first_hash = first_built_block.header.hash;
    let expected_hash = second_built_block.header.hash;

    let witness = BatchWitness {
        public_inputs: PublicInputs {
            parent_chain_id: 1_337,
            zone_id: ZONE_ID,
            tempo_block_number: second_tempo_block.header.number(),
            anchor_block_number: second_tempo_block.header.number(),
            anchor_block_hash: second_tempo_block.header.hash_slow(),
            expected_withdrawal_batch_index: 1,
        },
        zone_blocks: vec![
            ZoneBlock {
                number: first_built_block.header.number(),
                parent_hash,
                timestamp: first_built_block.header.timestamp(),
                timestamp_millis_part: first_built_block.header.timestamp_millis_part,
                beneficiary: first_built_block.header.beneficiary(),
                tempo_import: TempoImport::Full {
                    header_rlp: Bytes::from(alloy_rlp::encode(&first_tempo_block.header)),
                    deposits: vec![],
                    decryptions: vec![],
                    enabled_tokens: vec![],
                },
                finalize_withdrawal_batch_count: None,
                finalize_withdrawal_batch_encrypted_senders: vec![],
                transactions: vec![first_raw_transaction],
            },
            ZoneBlock {
                number: second_built_block.header.number(),
                parent_hash: first_hash,
                timestamp: second_built_block.header.timestamp(),
                timestamp_millis_part: second_built_block.header.timestamp_millis_part,
                beneficiary: second_built_block.header.beneficiary(),
                tempo_import: TempoImport::Full {
                    header_rlp: Bytes::from(alloy_rlp::encode(&second_tempo_block.header)),
                    deposits: vec![],
                    decryptions: vec![],
                    enabled_tokens: vec![],
                },
                finalize_withdrawal_batch_count: Some(U256::ZERO),
                finalize_withdrawal_batch_encrypted_senders: vec![],
                transactions: vec![second_raw_transaction],
            },
        ],
        parent_header,
        zone_state_witness,
        tempo_state_witness: TempoStateWitness {
            initial_tempo_header_rlp: tempo_header_rlp,
            node_pool: vec![],
        },
        tempo_ancestry_headers: vec![],
    };

    let output = prove_zone_batch(&config, witness)?;

    assert_eq!(output.block_transition.prevBlockHash, B256::ZERO);
    assert_eq!(output.block_transition.nextBlockHash, expected_hash);
    assert_eq!(output.next_zone_height, second_built_block.header.number());
    assert_eq!(
        output.deposit_queue_transition.prevProcessedHash,
        B256::ZERO
    );
    assert_eq!(
        output.deposit_queue_transition.nextProcessedHash,
        B256::ZERO
    );
    assert_eq!(output.deposit_queue_transition.prevDepositNumber, 0);
    assert_eq!(output.deposit_queue_transition.nextDepositNumber, 0);
    assert_eq!(output.withdrawal_queue_hash, B256::ZERO);
    assert_eq!(output.last_batch_commitment.withdrawal_batch_index, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn spf_builder_equivalence() -> eyre::Result<()> {
    let genesis = funded_zone_genesis();
    let built = build_single_transaction_block(&genesis, None).await?;

    let (state_root, zone_state_witness) = zone_state_witness(&genesis);
    assert_eq!(state_root, built.genesis_state_root);

    let config = spf_config(&genesis);
    let witness = built.batch_witness(&config, zone_state_witness, vec![]);

    let output = prove_zone_batch(&config, witness)?;

    assert_eq!(output.next_zone_height, 1);
    assert_eq!(
        output.block_transition.nextBlockHash, built.zone_hash,
        "SPF state, transaction, or receipt roots diverged from the production builder"
    );
    assert_eq!(
        output.deposit_queue_transition.prevProcessedHash,
        B256::ZERO
    );
    assert_eq!(
        output.deposit_queue_transition.nextProcessedHash,
        B256::ZERO
    );
    assert_eq!(output.withdrawal_queue_hash, B256::ZERO);
    assert_eq!(output.last_batch_commitment.withdrawal_batch_index, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn spf_replays_migrated_policy_transaction_with_parent_forks() -> eyre::Result<()> {
    let mut genesis = funded_zone_genesis();
    // Model a TIP-1092 migration: T9 reads the parent Tempo registry binding, while older forks
    // fall back to this legacy TIP-20 slot. Removing it makes the wrong fork choice observable.
    genesis
        .alloc
        .get_mut(&PATH_USD_ADDRESS)
        .expect("pathUSD genesis account")
        .storage
        .as_mut()
        .expect("pathUSD genesis storage")
        .remove(&B256::with_last_byte(7));

    let (tempo_state_root, tempo_state_nodes) =
        tempo_state_with_transfer_policy(PATH_USD_ADDRESS, ALLOW_ALL_POLICY_ID);
    let built = build_single_transaction_block(&genesis, Some(tempo_state_root)).await?;
    let legacy_policy_slot = B256::with_last_byte(7);
    assert!(
        !built
            .generated_witness
            .execution_witness
            .keys
            .iter()
            .any(|key| key.as_ref() == legacy_policy_slot),
        "production T9 execution must not witness the deleted legacy policy slot"
    );
    let zone_state_witness = ZoneStateWitness {
        node_pool: built.generated_witness.execution_witness.state.clone(),
        bytecodes: built.generated_witness.execution_witness.codes.clone(),
    };
    assert_eq!(config_state_root(&genesis), built.genesis_state_root);

    let config = spf_config(&genesis);
    let witness = built.batch_witness(&config, zone_state_witness, tempo_state_nodes);

    let output = prove_zone_batch(&config, witness)?;

    assert_eq!(output.next_zone_height, 1);
    assert_eq!(
        output.block_transition.nextBlockHash, built.zone_hash,
        "SPF state, transaction, or receipt roots diverged from the production builder"
    );
    Ok(())
}

struct BuiltTransactionBlock {
    genesis_state_root: B256,
    zone_number: u64,
    zone_timestamp: u64,
    zone_timestamp_millis_part: u64,
    zone_beneficiary: Address,
    zone_hash: B256,
    tempo_header: TempoHeader,
    raw_user_transaction: Bytes,
    generated_witness: ZoneExecutionWitness,
}

impl BuiltTransactionBlock {
    fn batch_witness(
        &self,
        config: &SpfConfig,
        zone_state_witness: ZoneStateWitness,
        tempo_state_nodes: Vec<Bytes>,
    ) -> BatchWitness {
        let parent_header = config.chain_spec().genesis_header().clone();
        let parent_hash = parent_header.hash_slow();
        BatchWitness {
            public_inputs: PublicInputs {
                parent_chain_id: 1_337,
                zone_id: ZONE_ID,
                tempo_block_number: self.tempo_header.number(),
                anchor_block_number: self.tempo_header.number(),
                anchor_block_hash: self.tempo_header.hash_slow(),
                expected_withdrawal_batch_index: 1,
            },
            parent_header,
            zone_blocks: vec![ZoneBlock {
                number: self.zone_number,
                parent_hash,
                timestamp: self.zone_timestamp,
                timestamp_millis_part: self.zone_timestamp_millis_part,
                beneficiary: self.zone_beneficiary,
                tempo_import: TempoImport::Full {
                    header_rlp: Bytes::from(alloy_rlp::encode(&self.tempo_header)),
                    deposits: vec![],
                    decryptions: vec![],
                    enabled_tokens: vec![],
                },
                finalize_withdrawal_batch_count: Some(U256::ZERO),
                finalize_withdrawal_batch_encrypted_senders: vec![],
                transactions: vec![self.raw_user_transaction.clone()],
            }],
            zone_state_witness,
            tempo_state_witness: TempoStateWitness {
                initial_tempo_header_rlp: Bytes::from(alloy_rlp::encode(TempoHeader::default())),
                node_pool: tempo_state_nodes,
            },
            tempo_ancestry_headers: vec![],
        }
    }
}

async fn build_single_transaction_block(
    genesis: &Genesis,
    tempo_state_root: Option<B256>,
) -> eyre::Result<BuiltTransactionBlock> {
    let (zone, mut fixture) =
        start_local_zone_with_fixture_and_withdrawal_batch_interval(ZONE_ID, 1, 1, genesis.clone())
            .await?;
    let (wallet_provider, sender) = crate::utils::local_dev_zone_account(&zone)?;
    let initial_fee_balance = zone.balance_of(PATH_USD_ADDRESS, sender).await?;
    let pending = wallet_provider
        .send_transaction(state_changing_transaction(address!(
            "000000000000000000000000000000000000b0b0"
        )))
        .await?;
    let user_transaction_hash = *pending.tx_hash();

    let mut l1_block = fixture.next_block();
    l1_block.header.inner.state_root = tempo_state_root.unwrap_or(EMPTY_ROOT_HASH);
    l1_block.header.timestamp_millis_part = 321;
    fixture.enqueue(&l1_block, zone.deposit_queue(), vec![]);
    assert!(
        pending.get_receipt().await?.status(),
        "user transaction must succeed"
    );
    zone.wait_for_block_number(1, DEFAULT_TIMEOUT).await?;

    let provider = zone.provider();
    let genesis_block = provider
        .get_block_by_number(0.into())
        .await?
        .expect("Zone genesis block");
    let built_block = provider
        .get_block_by_number(1.into())
        .await?
        .expect("builder-produced Zone block");
    assert_eq!(built_block.transactions.len(), 3);
    assert_eq!(provider.get_transaction_count(sender).await?, 1);
    assert!(
        zone.balance_of(PATH_USD_ADDRESS, sender).await? < initial_fee_balance,
        "the user transaction must charge the sender's proven fee-token balance"
    );

    let raw_user_transaction = provider
        .get_raw_transaction_by_hash(user_transaction_hash)
        .await?
        .expect("raw user transaction");
    let generated_witness = provider
        .raw_request(
            "debug_zoneExecutionWitness".into(),
            (BlockNumberOrTag::Number(1),),
        )
        .await?;

    Ok(BuiltTransactionBlock {
        genesis_state_root: genesis_block.header.state_root(),
        zone_number: built_block.header.number(),
        zone_timestamp: built_block.header.timestamp(),
        zone_timestamp_millis_part: built_block.header.timestamp_millis_part,
        zone_beneficiary: built_block.header.beneficiary(),
        zone_hash: built_block.header.hash,
        tempo_header: l1_block.header,
        raw_user_transaction,
        generated_witness,
    })
}

fn state_changing_transaction(recipient: Address) -> TransactionRequest {
    TransactionRequest::default()
        .to(recipient)
        .value(U256::ZERO)
        .gas_limit(TIP20_TX_GAS)
        .gas_price(TEMPO_T0_BASE_FEE as u128)
}

fn funded_zone_genesis() -> Genesis {
    let mut genesis = zone_node::genesis::genesis_template().expect("valid Zone genesis template");
    let sender = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    let fee_balance_slot = sender.mapping_slot(tip20_slots::BALANCES);
    genesis
        .alloc
        .get_mut(&PATH_USD_ADDRESS)
        .expect("pathUSD genesis account")
        .storage
        .get_or_insert_default()
        .insert(
            fee_balance_slot.into(),
            U256::from(1_000_000_000_u64).into(),
        );
    genesis
}

fn spf_config(genesis: &Genesis) -> SpfConfig {
    let mut genesis = genesis.clone();
    genesis.config.chain_id = zone_primitives::constants::zone_chain_id(1_337, ZONE_ID)
        .expect("valid zone genesis chain ID");
    let chain_spec = ZoneChainSpec::from_genesis(genesis).expect("valid zone genesis chain ID");
    SpfConfig::new(Arc::new(chain_spec))
}

fn tempo_state_with_transfer_policy(token: Address, policy_id: u64) -> (B256, Vec<Bytes>) {
    let policy_slot = token.mapping_slot(tip403_registry_slots::TOKEN_TRANSFER_POLICIES);
    let packed_policy = U256::from(policy_id) | (U256::ONE << u64::BITS);
    let genesis = Genesis {
        alloc: [(
            TIP403_REGISTRY_ADDRESS,
            GenesisAccount {
                storage: Some([(policy_slot.into(), packed_policy.into())].into()),
                ..Default::default()
            },
        )]
        .into(),
        ..Default::default()
    };

    let (state_root, nodes, _) = genesis_state_witness(&genesis);
    (state_root, nodes)
}

fn config_state_root(genesis: &Genesis) -> B256 {
    zone_state_witness(genesis).0
}

/// Convert the complete genesis allocation into the flat witness format consumed by SPF.
fn zone_state_witness(genesis: &Genesis) -> (B256, ZoneStateWitness) {
    let (state_root, node_pool, bytecodes) = genesis_state_witness(genesis);
    (
        state_root,
        ZoneStateWitness {
            node_pool,
            bytecodes,
        },
    )
}

fn genesis_state_witness(genesis: &Genesis) -> (B256, Vec<Bytes>, Vec<Bytes>) {
    let mut account_leaves = Vec::with_capacity(genesis.alloc.len());
    let mut node_pool = BTreeMap::<B256, Bytes>::new();
    let mut bytecodes = BTreeMap::<B256, Bytes>::new();

    for (address, account) in &genesis.alloc {
        let (storage_root, storage_nodes) = storage_trie(account);
        for node in storage_nodes {
            node_pool.entry(keccak256(&node)).or_insert(node);
        }

        let code_hash = account
            .code_hash()
            .unwrap_or(alloy_consensus::constants::KECCAK_EMPTY);
        if let Some(code) = &account.code {
            bytecodes.entry(code_hash).or_insert_with(|| code.clone());
        }
        let trie_account = TrieAccount {
            nonce: account.nonce.unwrap_or_default(),
            balance: account.balance,
            storage_root,
            code_hash,
        };
        account_leaves.push((keccak256(address), alloy_rlp::encode(trie_account)));
    }

    let (state_root, account_nodes) = trie(account_leaves);
    for node in account_nodes {
        node_pool.entry(keccak256(&node)).or_insert(node);
    }
    (
        state_root,
        node_pool.into_values().collect(),
        bytecodes.into_values().collect(),
    )
}

fn storage_trie(account: &GenesisAccount) -> (B256, Vec<Bytes>) {
    let leaves = account
        .storage_slots()
        .filter(|(_, value)| !value.is_zero())
        .map(|(slot, value)| (keccak256(slot), alloy_rlp::encode(value)))
        .collect();
    trie(leaves)
}

fn trie(mut leaves: Vec<(B256, Vec<u8>)>) -> (B256, Vec<Bytes>) {
    if leaves.is_empty() {
        return (EMPTY_ROOT_HASH, vec![]);
    }

    leaves.sort_unstable_by_key(|(key, _)| *key);
    let targets = leaves.iter().map(|(key, _)| Nibbles::unpack(key)).collect();
    let mut builder: HashBuilder =
        HashBuilder::default().with_proof_retainer(ProofRetainer::new(targets));
    for (key, value) in leaves {
        builder.add_leaf(Nibbles::unpack(key), &value);
    }
    let root = builder.root();
    let nodes = builder
        .take_proof_nodes()
        .into_nodes_sorted()
        .into_iter()
        .map(|(_, node)| node)
        .collect();
    (root, nodes)
}
