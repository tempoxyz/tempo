//! Builds the zone, its Tempo L1 state and the signed batch a case describes, with complete
//! witnesses for both states.

use std::{collections::BTreeMap, sync::Arc};

use alloy_consensus::{
    Header, Sealable as _, SignableTransaction as _, TxLegacy, constants::KECCAK_EMPTY,
};
use alloy_eips::Encodable2718 as _;
use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
use alloy_signer::SignerSync as _;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall as _;
use reth_chainspec::EthChainSpec as _;
use reth_trie_common::{EMPTY_ROOT_HASH, HashBuilder, Nibbles, TrieAccount, proof::ProofRetainer};
use tempo_chainspec::{hardfork::TempoHardfork, spec::TEMPO_T0_BASE_FEE};
use tempo_contracts::precompiles::{ADDRESS_REGISTRY_ADDRESS, ITIP20, PATH_USD_ADDRESS};
use tempo_precompiles::{
    address_registry::AddressRegistry,
    storage::{Handler as _, Slot, StorageCtx, StorageKey as _, hashmap::HashMapStorageProvider},
    tip20::tip20_slots,
    zone_factory::ZonePortalStorage,
};
use tempo_primitives::{MasterId, TempoAddressExt as _, TempoHeader, TempoTxEnvelope, UserTag};
use zone_chainspec::ZoneChainSpec;
use zone_primitives::constants::{
    TEMPO_STATE_ADDRESS, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, zone_chain_id,
};
use zone_spf::{
    BatchWitness, PublicInputs, SpfConfig, TempoImport, TempoStateWitness, ZoneBlock,
    ZoneStateWitness,
};

use crate::input::{Call, Recipient, SIGNERS, Target, ZoneCase};

/// Tempo L1 chain ID the zone's chain ID derives from.
pub const PARENT_CHAIN_ID: u64 = 1_337;
/// The zone's ID.
pub const ZONE_ID: u32 = 1;
/// pathUSD each signer starts with, in base units.
pub const STARTING_BALANCE: u64 = 1_000_000_000_000;
/// Gas limit of every user transaction.
pub const TX_GAS: u64 = 500_000;
/// The sequencer that receives each block's fees.
pub const BENEFICIARY: Address = Address::with_last_byte(0xbe);
/// The zone genesis template the node ships.
const GENESIS_TEMPLATE: &str = include_str!("../../node/assets/zone-dev-genesis.json");
/// Seconds between zone blocks.
const BLOCK_TIME: u64 = 1;

/// A call as it was sent: its block, its sender and the address it paid.
#[derive(Debug, Clone)]
pub struct SentCall {
    /// The case's call.
    pub call: Call,
    /// The address that signed it.
    pub sender: Address,
    /// The resolved recipient of a transfer, if the call is one.
    pub recipient: Option<Address>,
    /// The call's position in the case: block, then call index.
    pub position: (usize, usize),
}

/// Everything one run needs: the zone's config, the batch witness and the calls it carries.
pub struct Fixture {
    config: SpfConfig,
    witness: BatchWitness,
    sent: Vec<Vec<SentCall>>,
    signers: Vec<Address>,
    masters: BTreeMap<MasterId, Address>,
    genesis: Genesis,
}

impl Fixture {
    /// Builds `case`, leaving out the calls at `dropped` positions.
    pub fn new(case: &ZoneCase, dropped: &[(usize, usize)]) -> Self {
        let fork: TempoHardfork = case.fork.into();
        let signers: Vec<PrivateKeySigner> = (0..SIGNERS)
            .map(|index| {
                PrivateKeySigner::from_bytes(&crate::signer_key(index)).expect("valid key")
            })
            .collect();
        let addresses: Vec<Address> = signers.iter().map(|signer| signer.address()).collect();
        let masters: BTreeMap<MasterId, Address> = case
            .masters()
            .iter()
            .map(|master| (MasterId::from(master.id), addresses[master.owner.index()]))
            .collect();

        // Zone genesis: the bundled template on `fork`, with funded signers.
        let mut genesis: Genesis =
            serde_json::from_str(GENESIS_TEMPLATE).expect("valid zone genesis template");
        genesis.config.chain_id =
            zone_chain_id(PARENT_CHAIN_ID, ZONE_ID).expect("valid zone chain ID");
        zone_chainspec::test_utils::set_tempo_fork(&mut genesis, fork, 0);
        let path_usd = genesis
            .alloc
            .get_mut(&PATH_USD_ADDRESS)
            .expect("pathUSD genesis account")
            .storage
            .get_or_insert_default();
        for address in &addresses {
            path_usd.insert(
                balance_slot(*address).into(),
                U256::from(STARTING_BALANCE).into(),
            );
        }
        let supply_slot = B256::from(tip20_slots::TOTAL_SUPPLY);
        let supply = path_usd
            .get(&supply_slot)
            .map_or(U256::ZERO, |v| U256::from_be_bytes(v.0));
        path_usd.insert(
            supply_slot,
            (supply + U256::from(STARTING_BALANCE) * U256::from(SIGNERS)).into(),
        );

        // Tempo L1 state at the batch's anchor.
        let chain_spec =
            Arc::new(ZoneChainSpec::from_genesis(genesis.clone()).expect("valid zone genesis"));
        let config = SpfConfig::new(chain_spec);
        let portal = config.portal();
        let mut l1 = Genesis::default();
        precompile_writes(&mut l1, fork, || {
            ZonePortalStorage::new(portal)
                .transfers_enabled
                .write(case.l1.transfers_enabled)?;
            if case.l1.path_usd_paused {
                Slot::<bool>::new(tip20_slots::PAUSED, PATH_USD_ADDRESS).write(true)?;
            }
            let mut registry = AddressRegistry::new();
            for (id, owner) in &masters {
                registry.register_virtual_master_unchecked(*id, *owner)?;
            }
            Ok(())
        });
        let (l1_root, l1_nodes, _) = state_witness(&l1);

        // The zone's genesis is anchored to `TempoHeader::default()`; each zone block imports
        // one Tempo block on top of it, all committing to the same L1 state.
        let initial_tempo = TempoHeader::default();
        let mut tempo_headers = Vec::new();
        let mut parent_tempo = initial_tempo.clone();

        let parent_header = config.chain_spec().genesis_header().clone();

        let mut nonces = [0u64; SIGNERS];
        let mut sent = Vec::new();
        let mut zone_blocks = Vec::new();
        let blocks = case.blocks();
        for (block_index, calls) in blocks.iter().enumerate() {
            let tempo = TempoHeader {
                inner: Header {
                    number: parent_tempo.inner.number + 1,
                    parent_hash: parent_tempo.hash_slow(),
                    state_root: l1_root,
                    timestamp: parent_header.inner.timestamp
                        + BLOCK_TIME * (block_index as u64 + 1),
                    ..Default::default()
                },
                ..Default::default()
            };
            tempo_headers.push(tempo.clone());
            parent_tempo = tempo.clone();

            let mut block_sent = Vec::new();
            let mut transactions = Vec::new();
            for (call_index, call) in calls.iter().enumerate() {
                if dropped.contains(&(block_index, call_index)) {
                    continue;
                }
                let (from, to, data, recipient) = encode(call, &addresses, &masters, case);
                let nonce = nonces[from];
                nonces[from] += 1;
                let tx = TxLegacy {
                    chain_id: Some(config.chain_spec().chain_id()),
                    nonce,
                    gas_price: u128::from(TEMPO_T0_BASE_FEE),
                    gas_limit: TX_GAS,
                    to: TxKind::Call(to),
                    value: U256::ZERO,
                    input: data.into(),
                };
                let signature = signers[from]
                    .sign_hash_sync(&tx.signature_hash())
                    .expect("signing succeeds");
                let envelope = TempoTxEnvelope::Legacy(tx.into_signed(signature));
                transactions.push(Bytes::from(envelope.encoded_2718()));
                block_sent.push(SentCall {
                    call: call.clone(),
                    sender: addresses[from],
                    recipient,
                    position: (block_index, call_index),
                });
            }
            sent.push(block_sent);
            let is_last = block_index + 1 == blocks.len();
            zone_blocks.push(ZoneBlock {
                number: block_index as u64 + 1,
                // Chained below, once the blocks before it are known.
                parent_hash: B256::ZERO,
                timestamp: tempo.inner.timestamp,
                timestamp_millis_part: 0,
                beneficiary: BENEFICIARY,
                tempo_import: TempoImport::Full {
                    header_rlp: Bytes::from(alloy_rlp::encode(&tempo)),
                    deposits: vec![],
                    decryptions: vec![],
                    enabled_tokens: vec![],
                },
                finalize_withdrawal_batch_count: is_last.then_some(U256::ZERO),
                finalize_withdrawal_batch_encrypted_senders: vec![],
                transactions,
            });
        }

        let (_, zone_nodes, bytecodes) = state_witness(&genesis);
        let last = tempo_headers.last().expect("at least one block");
        let witness = BatchWitness {
            public_inputs: PublicInputs {
                parent_chain_id: PARENT_CHAIN_ID,
                zone_id: ZONE_ID,
                tempo_block_number: last.inner.number,
                anchor_block_number: last.inner.number,
                anchor_block_hash: last.hash_slow(),
                expected_withdrawal_batch_index: 1,
            },
            parent_header,
            zone_blocks,
            zone_state_witness: ZoneStateWitness {
                node_pool: zone_nodes,
                bytecodes,
            },
            tempo_state_witness: TempoStateWitness {
                initial_tempo_header_rlp: Bytes::from(alloy_rlp::encode(&initial_tempo)),
                node_pool: l1_nodes,
            },
            tempo_ancestry_headers: vec![],
        };

        let mut witness = witness;
        chain_parent_hashes(&config, &mut witness);

        Self {
            config,
            witness,
            sent,
            signers: addresses,
            masters,
            genesis,
        }
    }

    /// The zone's proof function config.
    pub fn config(&self) -> &SpfConfig {
        &self.config
    }

    /// The batch witness, with each block's parent hash chained to the one before.
    pub fn witness(&self) -> BatchWitness {
        self.witness.clone()
    }

    /// The calls sent, block by block.
    pub fn sent(&self) -> &[Vec<SentCall>] {
        &self.sent
    }

    /// The case position of the user transaction at `(block, transaction)`.
    pub fn call_at(&self, block: usize, transaction: usize) -> Option<(usize, usize)> {
        self.sent
            .get(block)?
            .get(transaction)
            .map(|call| call.position)
    }

    /// The zone signers.
    pub fn signers(&self) -> &[Address] {
        &self.signers
    }

    /// Registered masters by ID.
    pub fn masters(&self) -> &BTreeMap<MasterId, Address> {
        &self.masters
    }

    /// The pathUSD balance `account` starts the batch with.
    pub fn starting_balance(&self, account: Address) -> U256 {
        self.genesis
            .alloc
            .get(&PATH_USD_ADDRESS)
            .and_then(|account| account.storage.as_ref())
            .and_then(|storage| storage.get(&B256::from(balance_slot(account))))
            .map_or(U256::ZERO, |value| U256::from_be_bytes(value.0))
    }

    /// Every account an invariant reads the balance of: the signers, every recipient the case
    /// sends to, the masters and the beneficiary.
    pub fn tracked_accounts(&self) -> Vec<Address> {
        let mut accounts: Vec<Address> = self.signers.clone();
        accounts.extend(self.masters.values().copied());
        accounts.extend(self.sent.iter().flatten().filter_map(|call| call.recipient));
        accounts.push(BENEFICIARY);
        accounts.push(tempo_contracts::precompiles::TIP_FEE_MANAGER_ADDRESS);
        accounts.sort_unstable();
        accounts.dedup();
        accounts
    }
}

/// Sets each zone block's parent hash to the hash of the block before it.
///
/// A block's hash depends on its execution, so the harness asks the proof function: it executes
/// blocks `0..=k` followed by a placeholder, and the placeholder's parent-hash mismatch reports
/// block `k`'s hash.
fn chain_parent_hashes(config: &SpfConfig, witness: &mut BatchWitness) {
    witness.zone_blocks[0].parent_hash = witness.parent_header.hash_slow();
    for next in 1..witness.zone_blocks.len() {
        let mut probe = witness.clone();
        probe.zone_blocks.truncate(next);
        probe.zone_blocks.push(witness.zone_blocks[next].clone());
        let placeholder = probe.zone_blocks.last_mut().expect("just pushed");
        placeholder.parent_hash = B256::ZERO;
        match zone_spf::prove_zone_batch(config, probe) {
            Err(zone_spf::Error::BlockParentHashMismatch { expected, .. }) => {
                witness.zone_blocks[next].parent_hash = expected;
            }
            // An earlier block failed: later blocks never run, so their parent hash is moot.
            _ => return,
        }
    }
}

/// The pathUSD balance slot of `account`.
pub fn balance_slot(account: Address) -> U256 {
    account.mapping_slot(tip20_slots::BALANCES)
}

/// Encodes `call` as (signer index, target, calldata, resolved transfer recipient).
fn encode(
    call: &Call,
    signers: &[Address],
    masters: &BTreeMap<MasterId, Address>,
    case: &ZoneCase,
) -> (usize, Address, Vec<u8>, Option<Address>) {
    let recipient = |to: &Recipient| -> Address {
        match *to {
            Recipient::Signer(signer) => signers[signer.index()],
            Recipient::Virtual { master, tag } => {
                let ids: Vec<&MasterId> = masters.keys().collect();
                let id = if ids.is_empty() {
                    MasterId::from(case.masters().first().map_or([0xff; 4], |m| m.id))
                } else {
                    *ids[usize::from(master) % ids.len()]
                };
                Address::new_virtual(id, UserTag::from(tag))
            }
            Recipient::AnyVirtual { id, tag } => {
                Address::new_virtual(MasterId::from(id), UserTag::from(tag))
            }
            Recipient::Address(bytes) => Address::from(bytes),
        }
    };
    match call {
        Call::Transfer {
            from,
            to,
            amount,
            memo,
        } => {
            let to = recipient(to);
            let amount = U256::from(amount.0);
            let data = match memo {
                Some(memo) => ITIP20::transferWithMemoCall {
                    to,
                    amount,
                    memo: (*memo).into(),
                }
                .abi_encode(),
                None => ITIP20::transferCall { to, amount }.abi_encode(),
            };
            (from.index(), PATH_USD_ADDRESS, data, Some(to))
        }
        Call::Approve {
            owner,
            spender,
            amount,
        } => (
            owner.index(),
            PATH_USD_ADDRESS,
            ITIP20::approveCall {
                spender: signers[spender.index()],
                amount: U256::from(amount.0),
            }
            .abi_encode(),
            None,
        ),
        Call::TransferFrom {
            spender,
            from,
            to,
            amount,
        } => {
            let to = recipient(to);
            (
                spender.index(),
                PATH_USD_ADDRESS,
                ITIP20::transferFromCall {
                    from: signers[from.index()],
                    to,
                    amount: U256::from(amount.0),
                }
                .abi_encode(),
                Some(to),
            )
        }
        Call::Raw { from, to, data } => {
            let target = match to {
                Target::PathUsd => PATH_USD_ADDRESS,
                Target::Inbox => ZONE_INBOX_ADDRESS,
                Target::Outbox => ZONE_OUTBOX_ADDRESS,
                Target::TempoState => TEMPO_STATE_ADDRESS,
                Target::AddressRegistry => ADDRESS_REGISTRY_ADDRESS,
            };
            (from.index(), target, data.clone(), None)
        }
    }
}

/// Adds every slot `write` stores through the precompiles' typed storage to `genesis`.
fn precompile_writes(
    genesis: &mut Genesis,
    fork: TempoHardfork,
    write: impl FnOnce() -> tempo_precompiles::Result<()>,
) {
    let mut storage = HashMapStorageProvider::new_with_spec(1, fork);
    StorageCtx::enter(&mut storage, write).expect("in-memory L1 writes succeed");
    for (address, slot, value) in storage.into_storage() {
        genesis
            .alloc
            .entry(address)
            .or_default()
            .storage
            .get_or_insert_default()
            .insert(slot.into(), value.into());
    }
}

/// The state root of `genesis`'s allocation, every trie node and every bytecode.
fn state_witness(genesis: &Genesis) -> (B256, Vec<Bytes>, Vec<Bytes>) {
    let mut node_pool = BTreeMap::<B256, Bytes>::new();
    let mut bytecodes = BTreeMap::<B256, Bytes>::new();
    let mut leaves = Vec::with_capacity(genesis.alloc.len());
    for (address, account) in &genesis.alloc {
        let (storage_root, nodes) = storage_trie(account);
        for node in nodes {
            node_pool.entry(keccak256(&node)).or_insert(node);
        }
        let code_hash = account.code.as_ref().map_or(KECCAK_EMPTY, keccak256);
        if let Some(code) = &account.code {
            bytecodes.entry(code_hash).or_insert_with(|| code.clone());
        }
        let account = TrieAccount {
            nonce: account.nonce.unwrap_or_default(),
            balance: account.balance,
            storage_root,
            code_hash,
            ..Default::default()
        };
        leaves.push((keccak256(address), alloy_rlp::encode(account)));
    }
    let (root, nodes) = trie(leaves);
    for node in nodes {
        node_pool.entry(keccak256(&node)).or_insert(node);
    }
    (
        root,
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
    let mut builder = HashBuilder::default().with_proof_retainer(ProofRetainer::new(targets));
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
