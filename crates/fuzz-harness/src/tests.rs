use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use alloy_consensus::{
    SignableTransaction, TxEip7702, TxLegacy, proofs::calculate_transaction_root,
};
use alloy_eips::{Decodable2718, Encodable2718, eip7702::Authorization};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256, address};
use alloy_signer::SignerSync as _;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use bincode::Options as _;
use commonware_codec::Encode as _;
use evm2::evm::{AccountInfo, Cache, Database as _};
use reth_consensus::HeaderValidator as _;
use reth_execution_types::{AccountUpdate, StateUpdate};
use reth_trie_common::{
    TrieAccount,
    root::{state_root_unhashed, storage_root_unhashed},
};
use tempo_chainspec::{
    constants::moderato::MODERATO_CHAIN_ID,
    hardfork::{TempoHardfork, TempoHardforks},
};
use tempo_contracts::precompiles::{CURRENT_COMMITTEE_ADDRESS, ITIP20, PATH_USD_ADDRESS};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_fuzz_types::{
    AccountDiff, AccountInput, BlockContextInput, BlockHeaderInput, ChainSpecInput, ErrorClass,
    FUZZ_ACCEPT, FUZZ_REJECT, InvariantScope, NonEmpty, PreState, StateChanges, StateInput,
    StorageChangeOutput, TempoBlock, TempoBlockchainInput, TempoExecutionOutcome,
    TempoHarnessCapabilities, TempoHarnessInput, TempoHarnessOutcome, TempoTransactionInput,
    TempoZoneInput, TxOutcome, ZoneBlock,
};
use tempo_precompiles::tip20::slots::{SUPPLY_CAP, TOTAL_SUPPLY};
use tempo_primitives::{
    TempoHeader, TempoTxEnvelope,
    transaction::{
        Call, ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
        PrimitiveSignature, TempoSignature, TempoTransaction, configurable_account_digest,
        envelope::TEMPO_SYSTEM_TX_SIGNATURE,
    },
};

use crate::{
    bincode_options, chain, execute,
    state::{self, Contracts, Net},
};

/// Dev account 0, funded with pathUSD in the dev genesis.
const SENDER: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const RECIPIENT: Address = address!("00000000000000000000000000000000000000aa");
/// The chain ID of [`ChainSpecInput::default`].
const CHAIN_ID: u64 = MODERATO_CHAIN_ID;

fn transfer(nonce: u64, amount: u64) -> Bytes {
    tip20_transfer(nonce, RECIPIENT, U256::from(amount), 1_000_000)
}

/// A pathUSD transfer, signed with a placeholder: tests give its sender.
fn tip20_transfer(nonce: u64, to: Address, amount: U256, gas_limit: u64) -> Bytes {
    let input = ITIP20::transferCall { to, amount }.abi_encode();
    call(nonce, PATH_USD_ADDRESS, input.into(), gas_limit)
}

/// A call without value, signed with a placeholder: tests give its sender.
fn call(nonce: u64, to: Address, input: Bytes, gas_limit: u64) -> Bytes {
    let tx = TempoTxEnvelope::Legacy(
        TxLegacy {
            chain_id: Some(CHAIN_ID),
            nonce,
            gas_price: 0,
            gas_limit,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input,
        }
        .into_signed(Signature::test_signature()),
    );
    tx.encoded_2718().into()
}

fn context(hardfork: TempoHardfork, timestamp: u64) -> BlockContextInput {
    BlockContextInput {
        hardfork,
        timestamp,
        ..Default::default()
    }
}

fn block(header: BlockHeaderInput, txs: Vec<Bytes>) -> TempoBlock {
    let senders = vec![SENDER; txs.len()];
    TempoBlock {
        header,
        txs,
        senders,
    }
}

/// A block at T4 holding `txs` from [`SENDER`].
fn t4_block(txs: Vec<Bytes>) -> TempoBlock {
    block(
        BlockHeaderInput::Context(context(TempoHardfork::T4, 0)),
        txs,
    )
}

fn transfer_block() -> TempoBlock {
    t4_block(vec![transfer(0, 7)])
}

/// The header of `t4_block(vec![tx])`, RLP-encoded after `edit`.
fn rlp_header(tx: &Bytes, edit: impl FnOnce(&mut TempoHeader)) -> Vec<u8> {
    let spec = chain::chain_spec(&ChainSpecInput::default()).unwrap();
    let context = BlockHeaderInput::Context(context(TempoHardfork::T4, 0));
    let mut header = chain::header(&spec, &context).unwrap();
    let tx = TempoTxEnvelope::decode_2718_exact(tx).unwrap();
    header.inner.transactions_root = calculate_transaction_root(&[tx]);
    edit(&mut header);
    alloy_rlp::encode(&header)
}

/// `blocks` on `pre_state` on the default chain.
fn input(pre_state: PreState, blocks: Vec<TempoBlock>) -> TempoBlockchainInput {
    TempoBlockchainInput {
        chain_spec: ChainSpecInput::default(),
        pre_state,
        blocks: blocks.try_into().expect("tests execute at least one block"),
    }
}

fn run(pre_state: PreState, blocks: Vec<TempoBlock>) -> TempoExecutionOutcome {
    run_input(input(pre_state, blocks))
}

fn run_input(input: TempoBlockchainInput) -> TempoExecutionOutcome {
    let TempoHarnessOutcome::Blockchain(outcome) =
        execute::run(TempoHarnessInput::Blockchain(input))
    else {
        panic!("a blockchain input has a blockchain outcome");
    };
    outcome
}

/// The storage changes `changes` records at `address`.
fn storage_at(
    changes: &StateChanges,
    address: Address,
) -> impl Iterator<Item = &StorageChangeOutput> {
    changes
        .storage
        .iter()
        .filter(move |change| change.address == address)
}

fn genesis() -> PreState {
    PreState::Genesis(StateInput::default())
}

fn one_account(address: Address, account: AccountInput) -> StateInput {
    StateInput {
        accounts: BTreeMap::from([(address, account)]),
    }
}

fn exact(state: StateInput) -> PreState {
    PreState::Exact {
        state,
        block_hashes: BTreeMap::new(),
    }
}

/// The whole dev genesis state, as an outcome reports it.
fn genesis_state() -> StateInput {
    let db = state::seed(&state::GENESIS, &genesis()).expect("the dev genesis seeds");
    let cache = db.cache.borrow();
    let accounts = state::after(&cache, &Net::default());
    state::encode(&accounts, &Contracts(&[&cache.contracts]))
}

/// The dev genesis as an exact pre-state for `blocks`, listing what they read, as an extractor
/// reading a witness would: every account and slot execution loads, zeros included, with its value
/// before the blocks.
fn exact_genesis(blocks: &[TempoBlock]) -> StateInput {
    let spec = Arc::new(chain::chain_spec(&ChainSpecInput::default()).unwrap());
    let db = state::seed(&state::GENESIS, &genesis()).unwrap();
    let blocks: Vec<_> = blocks
        .iter()
        .map(|block| execute::recover_block(&spec, block, None).unwrap())
        .collect();
    let mut outcome = TempoExecutionOutcome::default();
    let _ = execute::execute_blocks(
        &TempoEvmConfig::new(Arc::clone(&spec)),
        &TempoConsensus::new(spec),
        &db,
        &blocks,
        &mut outcome,
        None,
    );
    assert_eq!(outcome.error, ErrorClass::None);

    let before = genesis_state();
    let cache = db.cache.borrow();
    let accounts = cache
        .accounts
        .keys()
        .map(|address| {
            let mut listed = before.accounts.get(address).cloned().unwrap_or_default();
            for slot in cache
                .storage
                .get(address)
                .iter()
                .flat_map(|storage| storage.slots.keys())
            {
                listed.storage.entry(*slot).or_insert(U256::ZERO);
            }
            (*address, listed)
        })
        .collect();
    StateInput { accounts }
}

fn path_usd(state: &mut StateInput) -> &mut AccountInput {
    state
        .accounts
        .get_mut(&PATH_USD_ADDRESS)
        .expect("the dev genesis holds pathUSD")
}

/// The state root of `state`, computed independently of the harness.
fn trie_root(state: &StateInput) -> B256 {
    state_root_unhashed(state.accounts.iter().map(|(address, account)| {
        let storage = account
            .storage
            .iter()
            .map(|(slot, value)| (B256::from(*slot), *value));
        let trie_account = TrieAccount {
            nonce: account.nonce,
            balance: account.balance,
            storage_root: storage_root_unhashed(storage),
            code_hash: alloy_primitives::keccak256(&account.code),
            extension: Default::default(),
        };
        (*address, trie_account)
    }))
}

#[test]
fn a_transfer_reports_its_receipt_changes_and_state_root() {
    let outcome = run(genesis(), vec![transfer_block()]);

    assert_eq!(outcome.error, ErrorClass::None);
    assert_eq!(outcome.receipts.len(), 1);
    let receipt = &outcome.receipts[0];
    assert_eq!(receipt.outcome, TxOutcome::Success);
    assert_eq!(receipt.cumulative_gas_used, receipt.gas.tx_gas_used());
    assert_eq!(
        receipt.output,
        Bytes::from(U256::from(1).to_be_bytes::<32>())
    );
    assert_eq!(receipt.logs.len(), 1, "one Transfer event");
    assert!(
        outcome.invariant_failures.is_empty(),
        "{:?}",
        outcome.invariant_failures
    );

    // The transfer moves two pathUSD balances and creates the sender, which
    // the dev genesis funds only with pathUSD; the block's total includes it all.
    let sender = outcome.state_diff.blocks[0].txs[0]
        .accounts
        .iter()
        .find(|account| account.address == SENDER)
        .expect("the transaction bumps the sender's nonce");
    assert_eq!((sender.exists, sender.nonce), (Some(true), Some(1)));
    assert!(outcome.state_diff.total.accounts.contains(sender));
    let tx_changes = &outcome.state_diff.blocks[0].txs[0];
    let path_usd: Vec<_> = storage_at(tx_changes, PATH_USD_ADDRESS).collect();
    assert_eq!(path_usd.len(), 2, "{tx_changes:?}");
    for change in path_usd {
        assert!(outcome.state_diff.total.storage.contains(change));
    }

    assert_eq!(outcome.state_root, Some(trie_root(&outcome.final_state)));
    assert_ne!(outcome.final_state, genesis_state());
}

#[test]
fn changes_that_cancel_out_within_a_block_are_not_in_the_total() {
    // The recipient sends the transfer straight back: both balances end where
    // they started, so only the nonces change overall.
    let back = tip20_transfer(0, SENDER, U256::from(7), 1_000_000);
    let mut block = t4_block(vec![transfer(0, 7), back]);
    block.senders[1] = RECIPIENT;
    let outcome = run(genesis(), vec![block]);
    assert_eq!(outcome.error, ErrorClass::None);

    let path_usd = |changes| storage_at(changes, PATH_USD_ADDRESS).count();
    let txs = &outcome.state_diff.blocks[0].txs;
    assert_eq!((path_usd(&txs[0]), path_usd(&txs[1])), (2, 2));
    assert_eq!(
        path_usd(&outcome.state_diff.total),
        0,
        "{:?}",
        outcome.state_diff.total
    );
    let nonces = outcome
        .state_diff
        .total
        .accounts
        .iter()
        .filter(|account| account.nonce == Some(1));
    assert_eq!(nonces.count(), 2);
}

#[test]
fn receipts_tell_reverts_and_halts_apart() {
    let outcome = |amount, gas_limit| {
        let tx = tip20_transfer(0, RECIPIENT, amount, gas_limit);
        let outcome = run(genesis(), vec![t4_block(vec![tx])]);
        assert_eq!(outcome.error, ErrorClass::None);
        outcome.receipts[0].clone()
    };

    // More than the sender holds: the token reverts with its error.
    let reverted = outcome(U256::MAX, 1_000_000);
    assert_eq!(reverted.outcome, TxOutcome::Revert);
    assert!(!reverted.output.is_empty(), "the revert carries its error");

    // One gas short of what the transfer uses: it starts, and runs out.
    let needed = outcome(U256::from(1), 1_000_000).gas.tx_gas_used();
    let halted = outcome(U256::from(1), needed - 1);
    assert!(matches!(halted.outcome, TxOutcome::Halt(_)), "{halted:?}");
    assert_eq!(halted.gas.tx_gas_used(), needed - 1);
}

#[test]
fn system_calls_are_reported_apart_from_transactions() {
    // EIP-2935 stores the parent hash before the transactions run.
    let tx = transfer(0, 7);
    let rlp = rlp_header(&tx, |header| {
        header.inner.parent_hash = B256::repeat_byte(1)
    });
    let outcome = run(
        genesis(),
        vec![block(BlockHeaderInput::Rlp(rlp.into()), vec![tx])],
    );
    assert_eq!(outcome.error, ErrorClass::None);

    let history = alloy_eips::eip2935::HISTORY_STORAGE_ADDRESS;
    let parent = |changes| {
        storage_at(changes, history).any(|change| change.after == U256::from_be_bytes([1; 32]))
    };
    let steps = &outcome.state_diff.blocks[0];
    assert!(parent(&steps.pre_block), "{:?}", steps.pre_block);
    assert!(!parent(&steps.txs[0]));
    assert!(parent(&outcome.state_diff.total));
}

#[test]
fn an_exact_pre_state_replays_like_the_genesis_it_lists() {
    let from_genesis = run(genesis(), vec![transfer_block()]);
    let replayed = run(
        exact(exact_genesis(&[transfer_block()])),
        vec![transfer_block()],
    );

    assert_eq!(replayed.error, ErrorClass::None);
    assert_eq!(replayed.receipts, from_genesis.receipts);
    assert_eq!(replayed.state_diff, from_genesis.state_diff);
    assert_eq!(replayed.final_state, from_genesis.final_state);
    assert_eq!(replayed.state_root, None);
}

#[test]
fn reading_outside_an_exact_pre_state_is_reported() {
    // The sender's balance slot is one the transfer reads.
    let from_genesis = run(genesis(), vec![transfer_block()]);
    let read = storage_at(&from_genesis.state_diff.blocks[0].txs[0], PATH_USD_ADDRESS)
        .next()
        .expect("the transfer changes pathUSD")
        .slot;

    let mut state = exact_genesis(&[transfer_block()]);
    path_usd(&mut state).storage.remove(&read);
    let outcome = run(exact(state), vec![transfer_block()]);
    assert_eq!(outcome.error, ErrorClass::IncompletePreState);
    assert!(outcome.receipts.is_empty());
}

#[test]
fn an_exact_pre_state_answers_listed_block_hashes_only() {
    let hash = B256::repeat_byte(7);
    let db = state::seed(
        &state::GENESIS,
        &PreState::Exact {
            state: StateInput::default(),
            block_hashes: BTreeMap::from([(5, hash)]),
        },
    )
    .unwrap();
    assert_eq!(db.reader().get_block_hash(&U256::from(5)).unwrap(), hash);
    assert!(!db.pre.missed());
    assert!(db.reader().get_block_hash(&U256::from(6)).is_err());
    assert!(db.pre.missed());
}

#[test]
fn an_empty_account_a_transaction_touches_is_destroyed() {
    // An account holding only storage is empty, so EIP-161 removes it, storage
    // and all, once a transaction touches it.
    let ghost = address!("00000000000000000000000000000000000000cc");
    let pre_state = one_account(
        ghost,
        AccountInput {
            storage: BTreeMap::from([(U256::from(1), U256::from(5))]),
            ..Default::default()
        },
    );
    let touch = call(0, ghost, Bytes::new(), 1_000_000);
    let outcome = run(PreState::Genesis(pre_state), vec![t4_block(vec![touch])]);

    assert_eq!(outcome.error, ErrorClass::None);
    assert!(!outcome.final_state.accounts.contains_key(&ghost));
    let destroyed = AccountDiff {
        address: ghost,
        exists: Some(false),
        balance: None,
        nonce: None,
        code: None,
        storage_cleared: true,
    };
    assert!(
        outcome.state_diff.blocks[0].txs[0]
            .accounts
            .contains(&destroyed)
    );
    assert!(outcome.state_diff.total.accounts.contains(&destroyed));
}

#[test]
fn a_recreated_account_keeps_none_of_its_earlier_slots() {
    let mut pre = Cache::default();
    pre.accounts.insert(RECIPIENT, Some(AccountInfo::default()));
    pre.storage
        .entry(RECIPIENT)
        .or_default()
        .slots
        .insert(U256::from(1), U256::from(5));
    let recreated = StateUpdate {
        accounts: vec![AccountUpdate {
            address: RECIPIENT,
            original: Some(AccountInfo::default()),
            current: Some(AccountInfo::default().with_balance(U256::from(1))),
            created: true,
            wiped: true,
            storage: Vec::new(),
        }],
    };

    let after = state::after(&pre, &Net::of([&recreated]));
    assert_eq!(after[&RECIPIENT].info.balance, U256::from(1));
    assert!(after[&RECIPIENT].storage.is_empty());
}

#[test]
fn a_created_account_reads_its_unwritten_slots_as_zero_on_an_exact_pre_state() {
    // The extractor lists the target as empty, a block creates it, and later code reads a slot
    // nothing wrote: the account did not exist before, so the slot is zero rather than missing.
    let db = state::seed(
        &state::GENESIS,
        &exact(one_account(RECIPIENT, AccountInput::default())),
    )
    .unwrap();
    let created = StateUpdate {
        accounts: vec![AccountUpdate {
            address: RECIPIENT,
            original: None,
            current: Some(AccountInfo::default().with_balance(U256::from(1))),
            created: true,
            wiped: false,
            storage: Vec::new(),
        }],
    };
    db.commit(&Net::of([&created]), |_| None);

    let read = db.reader().get_storage(&RECIPIENT, &U256::from(1));
    assert_eq!(read.unwrap(), U256::ZERO);
    assert!(!db.pre.missed());
}

#[test]
fn an_epoch_boundary_block_updates_the_committee_after_its_transactions() {
    // From T8 on, the last block of an epoch carries the DKG outcome that the
    // committee is set from.
    let spec = chain::chain_spec(&ChainSpecInput::default()).unwrap();
    let epoch_length = spec.info.epoch_length().expect("the dev chain has epochs");
    let boundary = |extra_data: Bytes| {
        let mut context = context(TempoHardfork::T13, 0);
        context.block_number = epoch_length.get() - 1;
        context.extra_data = extra_data;
        let block = block(BlockHeaderInput::Context(context), Vec::new());
        run(genesis(), vec![block])
    };
    let outcome = boundary(OnchainDkgOutcome::dealt(1, 3).encode().to_vec().into());
    assert_eq!(outcome.error, ErrorClass::None);
    let committee = |changes| {
        storage_at(changes, CURRENT_COMMITTEE_ADDRESS)
            .next()
            .is_some()
    };
    let steps = &outcome.state_diff.blocks[0];
    assert!(committee(&steps.post_block), "{:?}", steps.post_block);
    assert!(!committee(&steps.pre_block));
    assert!(committee(&outcome.state_diff.total));

    assert_eq!(boundary(Bytes::new()).error, ErrorClass::Rejected);
}

#[test]
fn a_pre_state_that_breaks_an_invariant_is_invalid() {
    // pathUSD's supply is below its holders' balances and above its cap. The second token's supply
    // is missing from the pre-state, so its views are skipped, and checking goes on to the third,
    // whose cap is broken.
    fn token(index: u8) -> Address {
        Address::with_last_byte(index) | PATH_USD_ADDRESS
    }
    fn storage(state: &mut StateInput, index: u8) -> &mut BTreeMap<U256, U256> {
        &mut state.accounts.get_mut(&token(index)).unwrap().storage
    }
    let mut state = exact_genesis(&[transfer_block()]);
    storage(&mut state, 0).extend([(TOTAL_SUPPLY, U256::from(1)), (SUPPLY_CAP, U256::ZERO)]);
    storage(&mut state, 1).remove(&TOTAL_SUPPLY);
    storage(&mut state, 2).insert(SUPPLY_CAP, U256::ZERO);
    let outcome = run(exact(state), vec![transfer_block()]);

    assert_eq!(
        (outcome.error, outcome.receipts.len()),
        (ErrorClass::InvalidInput, 0)
    );
    let failures: HashSet<_> = outcome
        .invariant_failures
        .iter()
        .map(|failure| {
            let id = failure.id.strip_prefix("TEMPO-TIP20-").unwrap();
            let token = (0..4).find(|&index| failure.message.contains(&token(index).to_string()));
            (id, &failure.scope, token)
        })
        .collect();
    let start = InvariantScope::Execution;
    let expected = [
        ("SUPPLY-CAP", &start, 0),
        ("BALANCE-SUM", &start, 0),
        ("SUPPLY-CAP", &start, 2),
    ];
    assert_eq!(
        failures,
        expected
            .map(|(id, scope, token)| (id, scope, Some(token)))
            .into()
    );
}

#[test]
fn an_rlp_header_executes_exactly_as_given() {
    let tx = transfer(0, 7);
    let rlp = rlp_header(&tx, |_| {});
    let from_rlp = run(
        genesis(),
        vec![block(BlockHeaderInput::Rlp(rlp.into()), vec![tx])],
    );
    assert_eq!(from_rlp, run(genesis(), vec![transfer_block()]));
}

#[test]
fn a_failing_block_leaves_the_state_before_it() {
    let first = transfer_block();
    // Nonce 0 again: the second block's transaction is invalid.
    let second = t4_block(vec![transfer(0, 9)]);
    let only_first = run(genesis(), vec![first.clone()]);
    let outcome = run(genesis(), vec![first, second]);

    assert_eq!(outcome.error, ErrorClass::Rejected);
    assert_eq!(outcome.receipts, only_first.receipts);
    assert_eq!(outcome.state_diff, only_first.state_diff);
    assert_eq!(outcome.final_state, only_first.final_state);
    assert_eq!(outcome.state_root, only_first.state_root);
}

#[test]
fn bad_inputs_are_classified_rather_than_executed() {
    use ErrorClass::{InvalidInput, Rejected, RlpDecode};
    let tx = transfer(0, 7);
    let on_blocks = |blocks| input(genesis(), blocks);
    let on_pre = |pre_state| input(pre_state, vec![transfer_block()]);
    let on_chain = |chain_spec| TempoBlockchainInput {
        chain_spec,
        ..on_pre(genesis())
    };
    let on_rlp = |rlp: Vec<u8>| {
        on_blocks(vec![block(
            BlockHeaderInput::Rlp(rlp.into()),
            vec![tx.clone()],
        )])
    };

    let late = block(
        BlockHeaderInput::Context(context(TempoHardfork::T5, 0)),
        Vec::new(),
    );
    let mut t3_after_t4 = ChainSpecInput::default();
    t3_after_t4.hardforks.insert(TempoHardfork::T3, u64::MAX);
    let other_chain = ChainSpecInput {
        chain_id: 1337,
        ..Default::default()
    };
    let recoded = one_account(
        PATH_USD_ADDRESS,
        AccountInput {
            code: Bytes::from_static(&[0x00]),
            ..path_usd(&mut genesis_state()).clone()
        },
    );
    let bad_code = one_account(
        RECIPIENT,
        AccountInput {
            code: Bytes::from_static(&[0xef, 0x01, 0x00]),
            ..Default::default()
        },
    );
    let mut extra_sender = transfer_block();
    extra_sender.senders.push(SENDER);
    let mut trailing_tx = tx.to_vec();
    trailing_tx.push(0);
    let trailing_tx = t4_block(vec![trailing_tx.into()]);
    let mut trailing_header = rlp_header(&tx, |_| {});
    trailing_header.push(0);
    let wrong_root = rlp_header(&tx, |header| header.inner.transactions_root = B256::ZERO);
    let wrong_general_gas = rlp_header(&tx, |header| header.general_gas_limit += 1);
    let mut millis = context(TempoHardfork::T4, 0);
    millis.timestamp_millis_part = 1000;
    let millis = block(BlockHeaderInput::Context(millis), Vec::new());

    let cases = [
        (
            InvalidInput,
            vec![
                ("time reversal", on_blocks(vec![late, t4_block(vec![])])),
                ("T3 after T4", on_chain(t3_after_t4)),
                ("protocol code replaced", on_pre(PreState::Genesis(recoded))),
                ("7702, genesis", on_pre(PreState::Genesis(bad_code.clone()))),
                ("7702, exact", on_pre(exact(bad_code))),
                ("extra sender", on_blocks(vec![extra_sender])),
            ],
        ),
        (
            RlpDecode,
            vec![
                ("trailing tx", on_blocks(vec![trailing_tx])),
                ("trailing header", on_rlp(trailing_header)),
            ],
        ),
        (
            Rejected,
            vec![
                ("other chain", on_chain(other_chain)),
                ("wrong transactions root", on_rlp(wrong_root)),
                ("millisecond part of 1000", on_blocks(vec![millis])),
                ("wrong general gas limit", on_rlp(wrong_general_gas)),
            ],
        ),
    ];
    for (error, cases) in cases {
        for (case, input) in cases {
            let outcome = run_input(input);
            let applied = outcome.receipts.len();
            assert_eq!((outcome.error, applied), (error, 0), "{case}");
        }
    }
}

#[test]
fn the_schedule_defaults_unlisted_hardforks() {
    let chain = ChainSpecInput {
        chain_id: 1337,
        hardforks: BTreeMap::from([(TempoHardfork::T3, 100)]),
    };
    let spec = chain::chain_spec(&chain).unwrap();
    // Unlisted hardforks activate at their variant index...
    assert_eq!(spec.tempo_hardfork_at(0), TempoHardfork::Genesis);
    assert_eq!(spec.tempo_hardfork_at(1), TempoHardfork::T0);
    assert_eq!(spec.tempo_hardfork_at(99), TempoHardfork::T2);
    // ...or with the hardfork before them, if that is later.
    assert_eq!(spec.tempo_hardfork_at(100), TempoHardfork::latest());

    // The default is Moderato's schedule.
    let spec = chain::chain_spec(&ChainSpecInput::default()).unwrap();
    let t4 = TempoHardfork::T4.moderato_activation_timestamp().unwrap();
    assert_eq!(spec.tempo_hardfork_at(t4 - 1), TempoHardfork::T3);
    assert_eq!(spec.tempo_hardfork_at(t4), TempoHardfork::T4);
}

#[test]
fn a_context_header_lands_where_its_hardfork_is_active() {
    let spec = chain::chain_spec(&ChainSpecInput::default()).unwrap();
    let at = |hardfork, timestamp| {
        let context = BlockHeaderInput::Context(context(hardfork, timestamp));
        chain::header(&spec, &context).unwrap().inner.timestamp
    };
    let t3 = TempoHardfork::T3.moderato_activation_timestamp().unwrap();
    let t4 = TempoHardfork::T4.moderato_activation_timestamp().unwrap();
    assert_eq!(at(TempoHardfork::T3, 0), t3);
    assert_eq!(at(TempoHardfork::T3, t3 + 5), t3 + 5);
    assert_eq!(at(TempoHardfork::T3, u64::MAX), t4 - 1);
    // The latest hardfork has no end.
    assert_eq!(at(TempoHardfork::latest(), u64::MAX), u64::MAX);
}

#[test]
fn context_headers_pass_the_nodes_header_validation_at_every_hardfork() {
    let spec = Arc::new(chain::chain_spec(&ChainSpecInput::default()).unwrap());
    let consensus = TempoConsensus::new(Arc::clone(&spec));
    for &hardfork in TempoHardfork::VARIANTS {
        let context = BlockHeaderInput::Context(context(hardfork, 0));
        let header = chain::header(&spec, &context).unwrap();
        let header = reth_primitives_traits::SealedHeader::seal_slow(header);
        let result = consensus.validate_header(&header);
        assert!(result.is_ok(), "{hardfork:?}: {result:?}");
    }
}

#[test]
fn transaction_inputs_decode_and_recover_without_executing() {
    let outcome = |tx: Bytes, sender: Option<Address>| {
        let input = TempoHarnessInput::Transaction(TempoTransactionInput { tx, sender });
        let TempoHarnessOutcome::Transaction(outcome) = execute::run(input) else {
            panic!("a transaction input has a transaction outcome");
        };
        outcome
    };
    let tx = transfer(0, 1);

    let given = outcome(tx.clone(), Some(SENDER));
    assert_eq!(given.error, ErrorClass::None);
    assert_eq!(given.sender, Some(SENDER));
    assert_eq!(given.tx_type, Some(0));

    let mut undecodable = tx.to_vec();
    undecodable.push(0);
    assert_eq!(
        outcome(undecodable.into(), None).error,
        ErrorClass::RlpDecode
    );
}

#[test]
fn non_empty_encodes_as_a_sequence_and_rejects_an_empty_one() {
    let encode = |items: Vec<u8>| bincode_options().serialize(&items).unwrap();
    let decode = |bytes: &[u8]| bincode_options().deserialize::<NonEmpty<u8>>(bytes);

    let items = decode(&encode(vec![1, 2])).unwrap();
    assert_eq!(items.as_slice(), [1, 2]);
    assert_eq!(
        bincode_options().serialize(&items).unwrap(),
        encode(vec![1, 2])
    );
    assert!(decode(&encode(Vec::new())).is_err());
}

#[test]
fn the_c_abi_round_trips_and_rejects_what_does_not_decode() {
    let input = TempoHarnessInput::Blockchain(input(genesis(), vec![transfer_block()]));
    let bytes = bincode_options().serialize(&input).unwrap();
    let call = |input: &[u8], out: &mut Vec<u8>| {
        let mut written = 0;
        let status = unsafe {
            crate::tempo_fuzz_execute_with_result_v1(
                out.as_mut_ptr(),
                out.len(),
                &mut written,
                input.as_ptr(),
                input.len(),
            )
        };
        (status, written)
    };

    let (status, needed) = call(&bytes, &mut Vec::new());
    assert_eq!(status, FUZZ_REJECT);
    let mut out = vec![0; needed];
    assert_eq!(call(&bytes, &mut out), (FUZZ_ACCEPT, needed));
    let outcome: TempoHarnessOutcome = bincode_options().deserialize(&out).unwrap();
    assert_eq!(outcome, execute::run(input));

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(call(&trailing, &mut out).0, FUZZ_REJECT);

    let mut out = vec![0; 1024];
    let mut written = 0;
    let status =
        unsafe { crate::tempo_fuzz_capabilities_v1(out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!(status, FUZZ_ACCEPT);
    let capabilities: TempoHarnessCapabilities =
        bincode_options().deserialize(&out[..written]).unwrap();
    assert_eq!(capabilities.schema_version, 4);
    assert_eq!(
        capabilities.supported_hardforks.as_slice(),
        TempoHardfork::VARIANTS
    );
}

/// The chain ID of the zone [`TempoZoneInput`] runs, on the default chain.
fn zone_chain() -> u64 {
    zone_primitives::constants::zone_chain_id(CHAIN_ID, 1).unwrap()
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

/// A call to [`RECIPIENT`] on `chain_id` from `account`, approved by `owner` in a quorum
/// carrying `config`, without fees.
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

/// Tempo blocks at T14 holding `tempo`, then zone blocks holding `zone`.
fn zone_input(tempo: Vec<Vec<Bytes>>, zone: Vec<Vec<Bytes>>) -> TempoZoneInput {
    zone_input_at(TempoHardfork::T14, tempo, zone)
}

/// Tempo blocks at `hardfork` holding `tempo`, then zone blocks holding `zone`.
fn zone_input_at(
    hardfork: TempoHardfork,
    tempo: Vec<Vec<Bytes>>,
    zone: Vec<Vec<Bytes>>,
) -> TempoZoneInput {
    let blocks: Vec<TempoBlock> = tempo
        .into_iter()
        .map(|txs| TempoBlock {
            header: BlockHeaderInput::Context(context(hardfork, 0)),
            txs,
            senders: Vec::new(),
        })
        .collect();
    TempoZoneInput {
        tempo: input(genesis(), blocks),
        pre_state: StateInput::default(),
        blocks: zone.into_iter().map(|txs| ZoneBlock { txs }).collect(),
    }
}

fn run_zone(input: TempoZoneInput) -> TempoExecutionOutcome {
    let TempoHarnessOutcome::Zone(outcome) = execute::run(TempoHarnessInput::Zone(input)) else {
        panic!("a zone input has a zone outcome");
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
fn a_zone_transaction_signed_by_a_quorum_registered_on_tempo_executes() {
    let (owner, config, account) = owned_account(1);
    let register = quorum_tx(CHAIN_ID, account, &config, &owner);
    let send = quorum_tx(zone_chain(), account, &config, &owner);
    let outcome = run_zone(zone_input(vec![vec![register]], vec![vec![send]]));

    assert_eq!(
        outcome.error,
        ErrorClass::None,
        "{}",
        execute::with_rejection(str::to_string)
    );
    assert_eq!(outcome.receipts.len(), 1);
    assert_eq!(outcome.receipts[0].outcome, TxOutcome::Success);
    assert_eq!(outcome.invariant_failures, Vec::new());
    // The account's quorum is judged against its Tempo commitment, which the zone mirrors.
    assert_eq!(
        judged(&outcome, "TEMPO-ZONE-ACCOUNT-QUORUM-COMMITMENT"),
        (1, 1)
    );
    for id in [
        "TEMPO-ZONE-ACCOUNT-COMMITMENT-MIRROR",
        "TEMPO-ZONE-ACCOUNT-MARKER-CALL",
        "TEMPO-ZONE-ACCOUNT-ANCHOR-ADVANCE",
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
    let register = quorum_tx(CHAIN_ID, account, &config, &owner);
    // A quorum of another owner, carrying a configuration Tempo does not hold for the account.
    let (stranger, mut stale, _) = owned_account(2);
    stale.owners[0].owner = stranger.address();
    let stale = quorum_tx(zone_chain(), account, &stale, &stranger);
    let authorization = Authorization {
        chain_id: U256::from(zone_chain()),
        address: RECIPIENT,
        nonce: 0,
    }
    .into_signed(Signature::test_signature());
    let authorizing: Bytes = TempoTxEnvelope::Eip7702(
        TxEip7702 {
            chain_id: zone_chain(),
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
            chain_id: Some(zone_chain()),
            to: TxKind::Call(RECIPIENT),
            ..Default::default()
        }
        .into_signed(TEMPO_SYSTEM_TX_SIGNATURE),
    )
    .encoded_2718()
    .into();
    let send = quorum_tx(zone_chain(), account, &config, &owner);
    let zone = vec![vec![stale, authorizing, system, send]];
    let outcome = run_zone(zone_input(vec![vec![register]], zone));

    assert_eq!(
        outcome.error,
        ErrorClass::None,
        "{}",
        execute::with_rejection(str::to_string)
    );
    assert_eq!(outcome.invariant_failures, Vec::new());
    // Only the last transaction executed.
    assert_eq!(
        judged(&outcome, "TEMPO-ZONE-ACCOUNT-NO-AUTHORIZATION-LIST"),
        (1, 1)
    );
    assert_eq!(
        judged(&outcome, "TEMPO-ZONE-ACCOUNT-QUORUM-COMMITMENT"),
        (1, 1)
    );
}

#[test]
fn zone_checks_are_unarmed_before_t14() {
    let outcome = run_zone(zone_input_at(
        TempoHardfork::T13,
        vec![Vec::new()],
        vec![Vec::new()],
    ));

    assert_eq!(
        outcome.error,
        ErrorClass::None,
        "{}",
        execute::with_rejection(str::to_string)
    );
    assert_eq!(outcome.invariant_failures, Vec::new());
    for (id, counts) in &outcome.invariant_counts {
        if id.starts_with("TEMPO-ZONE-ACCOUNT-") {
            assert_eq!(counts.armed, 0, "{id}");
        }
    }
}

#[test]
fn a_zone_block_whose_anchor_failed_is_not_executed() {
    let (owner, config, account) = owned_account(1);
    let send = quorum_tx(zone_chain(), account, &config, &owner);
    // The second Tempo block's transaction skips a nonce, so the block fails.
    let failing = call(5, RECIPIENT, Bytes::new(), 1_000_000);
    let mut input = zone_input(
        vec![Vec::new(), vec![failing]],
        vec![Vec::new(), vec![send]],
    );
    input.tempo.blocks.as_mut_slice()[1].senders = vec![RECIPIENT];
    let outcome = run_zone(input);

    assert_eq!(outcome.error, ErrorClass::Rejected);
    assert_eq!(outcome.invariant_failures, Vec::new());
    assert_eq!(
        judged(&outcome, "TEMPO-ZONE-ACCOUNT-NO-AUTHORIZATION-LIST"),
        (0, 0)
    );
    assert!(judged(&outcome, "TEMPO-ZONE-ACCOUNT-ANCHOR-ADVANCE").1 > 0);
}

#[test]
fn bad_zone_inputs_are_classified_rather_than_executed() {
    let empty = || zone_input(vec![Vec::new()], vec![Vec::new()]);
    let mut exact_tempo = empty();
    exact_tempo.tempo.pre_state = exact(StateInput::default());
    let mut rlp_tempo = empty();
    rlp_tempo.tempo.blocks.as_mut_slice()[0].header =
        BlockHeaderInput::Rlp(rlp_header(&transfer(0, 7), |_| {}).into());
    let too_many = zone_input(vec![Vec::new()], vec![Vec::new(), Vec::new()]);
    let mut no_zone_chain = empty();
    no_zone_chain.tempo.chain_spec.chain_id = u64::MAX;
    let mut marker = empty();
    marker.pre_state = one_account(
        RECIPIENT,
        AccountInput {
            code: tempo_primitives::account::CONFIGURABLE_ACCOUNT_CODE,
            ..Default::default()
        },
    );
    let mut delegation = empty();
    delegation.pre_state = one_account(
        RECIPIENT,
        AccountInput {
            code: Bytes::from_static(&[0xef, 0x01, 0x00, 0xaa]),
            ..Default::default()
        },
    );
    let mut trailing = transfer(0, 7).to_vec();
    trailing.push(0);
    let undecodable = zone_input(vec![Vec::new()], vec![vec![trailing.into()]]);

    let cases = [
        (
            ErrorClass::InvalidInput,
            "exact Tempo pre-state",
            exact_tempo,
        ),
        (ErrorClass::InvalidInput, "RLP Tempo header", rlp_tempo),
        (ErrorClass::InvalidInput, "more zone blocks", too_many),
        (ErrorClass::InvalidInput, "no zone chain ID", no_zone_chain),
        (ErrorClass::InvalidInput, "marker code", marker),
        (ErrorClass::InvalidInput, "delegation", delegation),
        (ErrorClass::RlpDecode, "undecodable zone tx", undecodable),
    ];
    for (error, case, input) in cases {
        let outcome = run_zone(input);
        assert_eq!(
            (outcome.error, outcome.receipts.len()),
            (error, 0),
            "{case}"
        );
        assert!(outcome.invariant_counts.is_empty(), "{case}");
    }
}
