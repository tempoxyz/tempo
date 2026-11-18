use std::collections::BTreeMap;

use alloy_consensus::{SignableTransaction as _, TxEip7702, TxLegacy};
use alloy_eips::{Encodable2718 as _, eip7702::Authorization};
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256, address};
use alloy_signer::SignerSync as _;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall as _;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{ITIP20, PATH_USD_ADDRESS};
use tempo_fuzz_types::{
    AccountInput, BlockContextInput, BlockHeaderInput, ChainSpecInput, ErrorClass, PreState,
    StateInput, TempoBlock, TempoBlockchainInput, TempoExecutionOutcome, TempoHarnessInput,
    TempoHarnessOutcome, TxOutcome,
};
use tempo_precompiles::{
    address_registry::AddressRegistry,
    storage::{Handler as _, StorageCtx, StorageKey as _, hashmap::HashMapStorageProvider},
    tip20::slots::{BALANCES, TOTAL_SUPPLY},
    zone_factory::{ZonePortalStorage, portal_address},
};
use tempo_primitives::{
    MasterId, TempoAddressExt as _, TempoTxEnvelope, UserTag,
    transaction::{
        Call, ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
        PrimitiveSignature, TempoSignature, TempoTransaction, configurable_account_digest,
        envelope::TEMPO_SYSTEM_TX_SIGNATURE,
    },
};
use zone_primitives::constants::zone_chain_id;

use crate::{L1Input, L1StateInput, ZoneHarnessInput, run};

const ZONE_ID: u32 = 1;
const SENDER: Address = address!("00000000000000000000000000000000000000a1");
const RECIPIENT: Address = address!("00000000000000000000000000000000000000b2");
const MASTER: Address = address!("00000000000000000000000000000000000000c3");
const MASTER_ID: [u8; 4] = [0xaa, 1, 2, 3];
const FUNDS: u64 = 1_000_000;
const TEMPO_CHAIN_ID: u64 = 1_337;

fn chain_id() -> u64 {
    zone_chain_id(TEMPO_CHAIN_ID, ZONE_ID).unwrap()
}

/// Every hardfork up to `fork` at genesis, the rest long after.
fn chain(fork: TempoHardfork) -> ChainSpecInput {
    let hardforks = TempoHardfork::VARIANTS
        .iter()
        .map(|&hardfork| (hardfork, if hardfork <= fork { 0 } else { u64::MAX / 2 }))
        .collect();
    ChainSpecInput {
        chain_id: chain_id(),
        hardforks,
    }
}

/// The zone genesis with `SENDER` holding pathUSD.
fn pre_state() -> PreState {
    let genesis: Genesis =
        serde_json::from_str(include_str!("../../node/assets/zone-dev-genesis.json")).unwrap();
    let path_usd = &genesis.alloc[&PATH_USD_ADDRESS];
    let mut storage: BTreeMap<U256, U256> = path_usd
        .storage
        .iter()
        .flatten()
        .map(|(slot, value)| ((*slot).into(), (*value).into()))
        .collect();
    storage.insert(SENDER.mapping_slot(BALANCES), U256::from(FUNDS));
    // Mint, rather than conjure, the sender's funds: TEMPO-TIP20-BALANCE-SUM holds of the pre-state.
    let supply = storage.entry(TOTAL_SUPPLY).or_default();
    *supply += U256::from(FUNDS);
    PreState::Genesis(StateInput {
        accounts: BTreeMap::from([(
            PATH_USD_ADDRESS,
            AccountInput {
                balance: path_usd.balance,
                nonce: path_usd.nonce.unwrap_or_default(),
                code: path_usd.code.clone().unwrap_or_default(),
                storage,
            },
        )]),
    })
}

/// Tempo L1 with the zone's portal opted in to transfers or not, and `MASTER_ID` registered.
fn l1(transfers_enabled: bool) -> L1StateInput {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
    StorageCtx::enter(&mut storage, || {
        ZonePortalStorage::new(portal_address(ZONE_ID))
            .transfers_enabled
            .write(transfers_enabled)?;
        AddressRegistry::new().register_virtual_master_unchecked(MasterId::from(MASTER_ID), MASTER)
    })
    .unwrap();
    let mut l1 = L1StateInput::default();
    for (account, slot, value) in storage.into_storage() {
        l1.storage.entry(account).or_default().insert(slot, value);
    }
    l1
}

fn transfer(nonce: u64, to: Address, amount: u64) -> Bytes {
    let input = ITIP20::transferCall {
        to,
        amount: U256::from(amount),
    }
    .abi_encode();
    TempoTxEnvelope::Legacy(
        TxLegacy {
            chain_id: Some(chain_id()),
            nonce,
            gas_price: 0,
            gas_limit: 1_000_000,
            to: TxKind::Call(PATH_USD_ADDRESS),
            value: U256::ZERO,
            input: input.into(),
        }
        .into_signed(Signature::test_signature()),
    )
    .encoded_2718()
    .into()
}

/// `blocks` of transfers from `SENDER` on `fork`, reading `l1`.
fn execute(
    fork: TempoHardfork,
    l1: L1StateInput,
    blocks: Vec<Vec<Bytes>>,
) -> TempoExecutionOutcome {
    let outcome = run(zone_input(fork, L1Input::State(l1), blocks, Some(SENDER)));
    let TempoHarnessOutcome::Blockchain(outcome) = outcome else {
        panic!("a blockchain input has a blockchain outcome");
    };
    outcome
}

/// A zone input of `blocks` on `fork`, reading `l1`, every transaction sent by `sender` or, without
/// one, by the account its signature recovers.
fn zone_input(
    fork: TempoHardfork,
    l1: L1Input,
    blocks: Vec<Vec<Bytes>>,
    sender: Option<Address>,
) -> ZoneHarnessInput {
    let blocks = blocks
        .into_iter()
        .enumerate()
        .map(|(index, txs)| TempoBlock {
            header: BlockHeaderInput::Context(BlockContextInput {
                block_number: index as u64 + 1,
                timestamp: index as u64 + 1,
                hardfork: fork,
                ..Default::default()
            }),
            senders: sender.map_or_else(Vec::new, |sender| vec![sender; txs.len()]),
            txs,
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("at least one block");
    ZoneHarnessInput {
        l1,
        input: TempoHarnessInput::Blockchain(TempoBlockchainInput {
            chain_spec: chain(fork),
            pre_state: pre_state(),
            blocks,
        }),
    }
}

/// The outcomes of the input's transactions: each block's receipts after its `advanceTempo`.
fn user_outcomes(outcome: &TempoExecutionOutcome) -> Vec<TxOutcome> {
    outcome
        .receipts
        .iter()
        .filter(|receipt| receipt.tx_index > 0)
        .map(|receipt| receipt.outcome.clone())
        .collect()
}

#[track_caller]
fn assert_clean(outcome: &TempoExecutionOutcome) {
    let why = tempo_fuzz_engine::ffi::last_rejection_string();
    assert_eq!(outcome.error, ErrorClass::None, "{why}");
    assert!(
        outcome.invariant_failures.is_empty(),
        "{:#?}",
        outcome.invariant_failures
    );
}

#[test]
fn empty_blocks_execute_on_every_zone_hardfork() {
    for &fork in crate::HARDFORKS {
        let outcome = execute(fork, l1(true), vec![vec![], vec![]]);
        assert_clean(&outcome);
        // Each block opens with advanceTempo, whose receipt the outcome records.
        assert_eq!(outcome.receipts.len(), 2, "{fork:?}");
        assert!(
            outcome
                .receipts
                .iter()
                .all(|r| r.outcome == TxOutcome::Success),
            "{fork:?}: {:?}",
            outcome.receipts
        );
    }
}

#[test]
fn t15_transfers_follow_the_portal_opt_in() {
    let outcome = execute(
        TempoHardfork::T15,
        l1(true),
        vec![vec![transfer(0, RECIPIENT, 100)]],
    );
    assert_clean(&outcome);
    assert_eq!(user_outcomes(&outcome), [TxOutcome::Success]);
    // The Tempo protocol invariants judge zone steps, not only Tempo L1's.
    for id in ["TEMPO-TIP20-TRANSFER-EVENTS", "TEMPO-TIP20-BALANCE-SUM"] {
        let counts = &outcome.invariant_counts[id];
        assert!(counts.armed > 0, "{id} never armed: {counts:?}");
    }

    for (fork, enabled) in [(TempoHardfork::T14, true), (TempoHardfork::T15, false)] {
        let outcome = execute(fork, l1(enabled), vec![vec![transfer(0, RECIPIENT, 100)]]);
        assert_clean(&outcome);
        assert_eq!(
            user_outcomes(&outcome),
            [TxOutcome::Revert],
            "{fork:?} enabled={enabled}"
        );
    }
}

#[test]
fn t15_virtual_address_transfers_resolve_through_l1_registry() {
    let registered = Address::new_virtual(MasterId::from(MASTER_ID), UserTag::from([7; 6]));
    let unregistered = Address::new_virtual(MasterId::from([0xbb, 0, 0, 0]), UserTag::from([7; 6]));
    let outcome = execute(
        TempoHardfork::T15,
        l1(true),
        vec![vec![
            transfer(0, registered, 100),
            transfer(1, unregistered, 100),
        ]],
    );
    assert_clean(&outcome);
    assert_eq!(
        user_outcomes(&outcome),
        [TxOutcome::Success, TxOutcome::Revert]
    );
    let master_balance = outcome.final_state.accounts[&PATH_USD_ADDRESS]
        .storage
        .get(&MASTER.mapping_slot(BALANCES))
        .copied();
    assert_eq!(master_balance, Some(U256::from(100)));
}

#[test]
fn non_zone_chain_ids_are_invalid() {
    let mut input = ZoneHarnessInput {
        l1: L1Input::State(L1StateInput::default()),
        input: TempoHarnessInput::Blockchain(TempoBlockchainInput {
            chain_spec: chain(TempoHardfork::T15),
            pre_state: pre_state(),
            blocks: vec![TempoBlock {
                header: BlockHeaderInput::Context(BlockContextInput::default()),
                txs: vec![],
                senders: vec![],
            }]
            .try_into()
            .unwrap(),
        }),
    };
    if let TempoHarnessInput::Blockchain(blockchain) = &mut input.input {
        blockchain.chain_spec.chain_id = 1;
    }
    let TempoHarnessOutcome::Blockchain(outcome) = run(input) else {
        panic!("a blockchain input has a blockchain outcome");
    };
    assert_eq!(outcome.error, ErrorClass::InvalidInput);
}

/// A configurable account owned by one deterministic key, its version-zero configuration, and the
/// account it derives.
fn owned_account(seed: u8) -> (PrivateKeySigner, ConfigurableAccountConfig, Address) {
    let owner = PrivateKeySigner::from_bytes(&B256::repeat_byte(seed)).unwrap();
    let config = ConfigurableAccountConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: 1,
        owners: vec![ConfigurableAccountOwner {
            owner: owner.address(),
            weight: 1,
        }],
    };
    let account = config.derive_account().unwrap();
    (owner, config, account)
}

/// A call to [`RECIPIENT`] on `chain_id` from `account`, approved by `owner` in a quorum carrying
/// `config`, without fees.
fn quorum_tx(
    chain_id: u64,
    account: Address,
    config: &ConfigurableAccountConfig,
    owner: &PrivateKeySigner,
) -> Bytes {
    let tx = TempoTransaction {
        chain_id,
        fee_token: Some(PATH_USD_ADDRESS),
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TxKind::Call(RECIPIENT),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        ..Default::default()
    };
    let digest = configurable_account_digest(tx.signature_hash(), account, config.version);
    let approval = PrimitiveSignature::Secp256k1(owner.sign_hash_sync(&digest).unwrap());
    let signature = ConfigurableAccountSignature::try_new(account, config.clone(), vec![approval])
        .expect("the witness has a valid shape");
    TempoTxEnvelope::AA(tx.into_signed(TempoSignature::ConfigurableAccount(signature)))
        .encoded_2718()
        .into()
}

/// A Tempo chain from its genesis on `fork`, one block per entry of `blocks`.
fn tempo_chain(fork: TempoHardfork, blocks: Vec<Vec<Bytes>>) -> TempoBlockchainInput {
    TempoBlockchainInput {
        chain_spec: ChainSpecInput {
            chain_id: TEMPO_CHAIN_ID,
            ..chain(fork)
        },
        pre_state: PreState::Genesis(StateInput::default()),
        blocks: blocks
            .into_iter()
            .enumerate()
            .map(|(index, txs)| TempoBlock {
                header: BlockHeaderInput::Context(BlockContextInput {
                    timestamp: index as u64 + 1,
                    hardfork: fork,
                    ..Default::default()
                }),
                txs,
                senders: Vec::new(),
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("at least one block"),
    }
}

/// `zone` blocks on a zone of the Tempo chain of `tempo` blocks, both on T14.
fn on_tempo(tempo: Vec<Vec<Bytes>>, zone: Vec<Vec<Bytes>>) -> TempoExecutionOutcome {
    let fork = TempoHardfork::T14;
    let input = zone_input(fork, L1Input::Chain(tempo_chain(fork, tempo)), zone, None);
    let TempoHarnessOutcome::Blockchain(outcome) = run(input) else {
        panic!("a blockchain input has a blockchain outcome");
    };
    outcome
}

/// How often `id` was judged and armed.
fn judged(outcome: &TempoExecutionOutcome, id: &str) -> (u64, u64) {
    let counts = outcome
        .invariant_counts
        .get(id)
        .copied()
        .unwrap_or_default();
    (counts.evaluated, counts.armed)
}

#[test]
fn zone_blocks_advance_through_the_tempo_chain() {
    let outcome = on_tempo(vec![vec![], vec![], vec![]], vec![vec![], vec![], vec![]]);
    assert_clean(&outcome);
    // Each zone block imports the next Tempo block, which TempoState checks links to the last.
    assert_eq!(outcome.receipts.len(), 3);
    assert!(
        outcome
            .receipts
            .iter()
            .all(|r| r.outcome == TxOutcome::Success),
        "{:?}",
        outcome.receipts
    );
    assert!(judged(&outcome, "TEMPO-ZONE-ACCOUNT-ANCHOR-ADVANCE").1 > 0);
}

#[test]
fn a_zone_transaction_signed_by_a_quorum_registered_on_tempo_executes() {
    let (owner, config, account) = owned_account(1);
    let register = quorum_tx(TEMPO_CHAIN_ID, account, &config, &owner);
    let send = quorum_tx(chain_id(), account, &config, &owner);
    let outcome = on_tempo(vec![vec![register]], vec![vec![send]]);

    assert_clean(&outcome);
    assert_eq!(user_outcomes(&outcome), [TxOutcome::Success]);
    // The account's quorum is judged against its Tempo commitment, which the zone mirrors.
    assert_eq!(
        judged(&outcome, "TEMPO-ZONE-ACCOUNT-QUORUM-COMMITMENT"),
        (1, 1)
    );
    for id in [
        "TEMPO-ZONE-ACCOUNT-COMMITMENT-MIRROR",
        "TEMPO-ZONE-ACCOUNT-INELIGIBLE",
        "TEMPO-ZONE-ACCOUNT-MARKER-CALL",
        "TEMPO-ZONE-ACCOUNT-ANCHOR-ADVANCE",
        "TEMPO-ZONE-ACCOUNT-COMMITMENT-ANCHORED",
        "TEMPO-ZONE-ACCOUNT-NO-WRITE",
        "TEMPO-ZONE-ACCOUNT-NO-AUTHORIZATION-LIST",
        "TEMPO-ZONE-ACCOUNT-CODE-SERVED",
        "TEMPO-ZONE-ACCOUNT-STATE-CLEAN",
        "TEMPO-ZONE-ACCOUNT-VIEW",
    ] {
        assert!(judged(&outcome, id).1 > 0, "{id} is never armed");
    }
}

#[test]
fn a_zone_block_leaves_out_transactions_the_zone_rejects() {
    let (owner, config, account) = owned_account(1);
    let register = quorum_tx(TEMPO_CHAIN_ID, account, &config, &owner);
    // A quorum of another owner, carrying a configuration Tempo does not hold for the account.
    let (stranger, mut stale, _) = owned_account(2);
    stale.owners[0].owner = stranger.address();
    let stale = quorum_tx(chain_id(), account, &stale, &stranger);
    let authorization = Authorization {
        chain_id: U256::from(chain_id()),
        address: RECIPIENT,
        nonce: 0,
    }
    .into_signed(Signature::test_signature());
    let authorizing: Bytes = TempoTxEnvelope::Eip7702(
        TxEip7702 {
            chain_id: chain_id(),
            gas_limit: 1_000_000,
            to: RECIPIENT,
            authorization_list: vec![authorization],
            ..Default::default()
        }
        .into_signed(Signature::test_signature()),
    )
    .encoded_2718()
    .into();
    let system: Bytes = TempoTxEnvelope::Legacy(
        TxLegacy {
            chain_id: Some(chain_id()),
            to: TxKind::Call(RECIPIENT),
            ..Default::default()
        }
        .into_signed(TEMPO_SYSTEM_TX_SIGNATURE),
    )
    .encoded_2718()
    .into();
    let send = quorum_tx(chain_id(), account, &config, &owner);
    let outcome = on_tempo(
        vec![vec![register]],
        vec![vec![stale, authorizing, system, send]],
    );

    assert_clean(&outcome);
    // Only the last transaction executed.
    assert_eq!(user_outcomes(&outcome), [TxOutcome::Success]);
    assert_eq!(
        judged(&outcome, "TEMPO-ZONE-ACCOUNT-QUORUM-COMMITMENT"),
        (1, 1)
    );
}

#[test]
fn bad_zone_inputs_on_a_tempo_chain_are_invalid() {
    let fork = TempoHardfork::T14;
    let input = |tempo: TempoBlockchainInput, zone: Vec<Vec<Bytes>>| {
        zone_input(fork, L1Input::Chain(tempo), zone, None)
    };
    let mut exact_tempo = tempo_chain(fork, vec![vec![]]);
    exact_tempo.pre_state = PreState::Exact {
        state: StateInput::default(),
        block_hashes: BTreeMap::new(),
    };
    let mut other_chain = tempo_chain(fork, vec![vec![]]);
    other_chain.chain_spec.chain_id = TEMPO_CHAIN_ID + 1;
    let with_code = |code: Bytes| {
        let mut input = input(tempo_chain(fork, vec![vec![]]), vec![vec![]]);
        let TempoHarnessInput::Blockchain(chain) = &mut input.input else {
            unreachable!()
        };
        let PreState::Genesis(state) = &mut chain.pre_state else {
            unreachable!()
        };
        state.accounts.insert(
            RECIPIENT,
            AccountInput {
                code,
                ..Default::default()
            },
        );
        input
    };
    let cases = [
        ("exact Tempo pre-state", input(exact_tempo, vec![vec![]])),
        (
            "more zone blocks",
            input(tempo_chain(fork, vec![vec![]]), vec![vec![], vec![]]),
        ),
        ("another chain's zone", input(other_chain, vec![vec![]])),
        (
            "marker code",
            with_code(tempo_primitives::account::CONFIGURABLE_ACCOUNT_CODE),
        ),
        (
            "delegation",
            with_code(Bytes::from_static(&[0xef, 0x01, 0x00, 0xaa])),
        ),
    ];
    for (case, input) in cases {
        let TempoHarnessOutcome::Blockchain(outcome) = run(input) else {
            panic!("a blockchain input has a blockchain outcome");
        };
        assert_eq!(
            (outcome.error, outcome.receipts.len()),
            (ErrorClass::InvalidInput, 0),
            "{case}"
        );
    }
}
