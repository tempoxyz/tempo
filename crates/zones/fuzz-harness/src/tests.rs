use std::collections::BTreeMap;

use alloy_consensus::{SignableTransaction as _, TxLegacy};
use alloy_eips::Encodable2718 as _;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256, address};
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
use tempo_primitives::{MasterId, TempoAddressExt as _, TempoTxEnvelope, UserTag};
use zone_primitives::constants::zone_chain_id;

use crate::{L1StateInput, ZoneHarnessInput, run};

const ZONE_ID: u32 = 1;
const SENDER: Address = address!("00000000000000000000000000000000000000a1");
const RECIPIENT: Address = address!("00000000000000000000000000000000000000b2");
const MASTER: Address = address!("00000000000000000000000000000000000000c3");
const MASTER_ID: [u8; 4] = [0xaa, 1, 2, 3];
const FUNDS: u64 = 1_000_000;

fn chain_id() -> u64 {
    zone_chain_id(1_337, ZONE_ID).unwrap()
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
            senders: vec![SENDER; txs.len()],
            txs,
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("at least one block");
    let outcome = run(ZoneHarnessInput {
        l1,
        input: TempoHarnessInput::Blockchain(TempoBlockchainInput {
            chain_spec: chain(fork),
            pre_state: pre_state(),
            blocks,
        }),
    });
    let TempoHarnessOutcome::Blockchain(outcome) = outcome else {
        panic!("a blockchain input has a blockchain outcome");
    };
    outcome
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
        l1: L1StateInput::default(),
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
