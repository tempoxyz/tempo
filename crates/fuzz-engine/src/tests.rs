use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use alloy_consensus::{
    SignableTransaction, TxLegacy, proofs::calculate_transaction_root, transaction::Recovered,
};
use alloy_eips::{Decodable2718, Encodable2718, eip2935::HISTORY_STORAGE_ADDRESS};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256, address};
use alloy_sol_types::SolCall;
use bincode::Options as _;
use commonware_codec::Encode as _;
use evm2::evm::{AccountInfo, Cache, Database as _};
use invariants_core::{Report, Violation};
use reth_consensus::HeaderValidator as _;
use reth_evm::BlockExecutionError;
use reth_execution_types::{AccountUpdate, StateUpdate};
use reth_trie_common::{
    TrieAccount,
    root::{state_root_unhashed, storage_root_unhashed},
};
use tempo_chainspec::{
    constants::moderato::MODERATO_CHAIN_ID,
    hardfork::{TempoHardfork, TempoHardforks},
};
use tempo_contracts::precompiles::{
    CURRENT_COMMITTEE_ADDRESS, ITIP20, ITIPFeeAMM, PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_evm::{TempoEvm, TempoEvmConfig, consensus::TempoConsensus};
use tempo_fuzz_types::{
    AccountDiff, AccountInput, BlockContextInput, BlockHeaderInput, ChainSpecInput, ErrorClass,
    HarnessInputKind, InvariantScope, NonEmpty, PreState, StateChanges, StateInput,
    StorageChangeOutput, TempoBlock, TempoBlockchainInput, TempoExecutionOutcome,
    TempoHarnessInput, TempoHarnessOutcome, TempoTransactionInput, TxIndex, TxOutcome,
};
use tempo_precompiles::{
    storage::StorageKey as _,
    tip20::{
        slots::{SUPPLY_CAP, TOTAL_SUPPLY},
        tip20_slots,
    },
};
use tempo_primitives::{
    TempoHeader, TempoTxEnvelope,
    crypto::mock,
    is_tip20_prefix,
    transaction::{
        Call, TempoTransaction,
        tt_signature::{PrimitiveSignature, TempoSignature, p256_keypair},
    },
};
use test_case::test_case;

use crate::{
    Chain, Engine, Rejection, Tempo, chain, execute,
    ffi::bincode_options,
    invariants,
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

/// An LP mint, from [`SENDER`] to itself, of only validator tokens into the pool of pathUSD and the
/// token after it.
fn mint_lp(nonce: u64) -> Bytes {
    let input = ITIPFeeAMM::mintCall {
        userToken: Address::with_last_byte(1) | PATH_USD_ADDRESS,
        validatorToken: PATH_USD_ADDRESS,
        amountValidatorToken: U256::from(10_000_000u64),
        to: SENDER,
    };
    call(
        nonce,
        TIP_FEE_MANAGER_ADDRESS,
        input.abi_encode().into(),
        2_000_000,
    )
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
    run_on(&Tempo, input).0
}

/// `input`'s outcome on `engine`, and why it stopped short.
fn run_on<E: Engine>(
    engine: &E,
    input: TempoBlockchainInput,
) -> (TempoExecutionOutcome, Option<Rejection>) {
    let (TempoHarnessOutcome::Blockchain(outcome), rejection) =
        execute::run(engine, TempoHarnessInput::Blockchain(input))
    else {
        panic!("a blockchain input has a blockchain outcome");
    };
    assert_eq!(
        rejection.as_ref().map(Rejection::class),
        Some(outcome.error).filter(|error| *error != ErrorClass::None),
        "a rejection explains every error"
    );
    let catalog = invariants::catalog::<E>();
    for id in outcome.invariant_counts.keys() {
        assert!(
            catalog.iter().any(|info| &info.id == id),
            "{id} is counted but not in the catalog"
        );
    }
    (outcome, rejection)
}

/// How many subjects `outcome` judged for `id`, was armed for and found broken.
fn counts(outcome: &TempoExecutionOutcome, id: &str) -> (u64, u64, u64) {
    let counts = outcome.invariant_counts[id];
    (counts.evaluated, counts.armed, counts.fired)
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
    let db = state::seed(&genesis(), Tempo.genesis()).expect("the dev genesis seeds");
    let cache = db.cache.borrow();
    let accounts = state::after(&cache, &Net::default());
    state::encode(&accounts, &Contracts(&[&cache.contracts]))
}

/// The dev genesis with the accounts of `edits` replaced, as an exact pre-state for `blocks`,
/// listing what they read, as an extractor reading a witness would: every account and slot
/// execution loads, zeros included, with its value before the blocks.
fn exact_genesis(edits: StateInput, blocks: &[TempoBlock]) -> StateInput {
    let spec = Arc::new(chain::chain_spec(&ChainSpecInput::default()).unwrap());
    let db = state::seed(&genesis(), Tempo.genesis()).unwrap();
    for (address, account) in &edits.accounts {
        state::insert(&mut db.cache.borrow_mut(), *address, account).unwrap();
    }
    let blocks: Vec<_> = blocks
        .iter()
        .map(|block| execute::recover_block(spec.as_ref(), block).unwrap())
        .collect();
    let mut outcome = TempoExecutionOutcome::default();
    let (_, _, rejection) = execute::execute_blocks(
        &Tempo,
        &TempoEvmConfig::new(Arc::clone(&spec)),
        &TempoConsensus::new(spec),
        &db,
        &blocks,
        &mut outcome,
    );
    assert_eq!((outcome.error, rejection), (ErrorClass::None, None));

    let mut before = genesis_state();
    before.accounts.extend(edits.accounts);
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
    // Only invariants that judged something are counted: the keychain's never apply here.
    assert!(outcome.invariant_counts["TEMPO-TIP20-BALANCE-SUM"].evaluated > 0);
    assert!(
        !outcome
            .invariant_counts
            .contains_key("TEMPO-KEYCHAIN-SPEND-LIMIT")
    );
    assert!(
        outcome
            .invariant_counts
            .values()
            .all(|counts| counts.evaluated > 0)
    );
    // A T4 block runs the checks that apply before T14, not those that apply from it.
    assert!(outcome.invariant_counts["TEMPO-ACCOUNT-FORK-GATED"].evaluated > 0);
    assert!(
        !outcome
            .invariant_counts
            .contains_key("TEMPO-ACCOUNT-ACCESS-KEY-TYPE")
    );
    // The block's first step checks every token's state, the transfer and the post-block step only
    // what they changed: pathUSD, and nothing. Only the transfer changed a token, so only it ran a
    // step check.
    let tokens = genesis_state()
        .accounts
        .keys()
        .filter(|address| is_tip20_prefix(**address))
        .count() as u64;
    assert_eq!(
        outcome.invariant_counts["TEMPO-TIP20-BALANCE-SUM"].evaluated,
        tokens + 1
    );
    assert_eq!(
        outcome.invariant_counts["TEMPO-TIP20-TRANSFER-EVENTS"].evaluated,
        1
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
        exact(exact_genesis(StateInput::default(), &[transfer_block()])),
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

    let mut state = exact_genesis(StateInput::default(), &[transfer_block()]);
    path_usd(&mut state).storage.remove(&read);
    let outcome = run(exact(state), vec![transfer_block()]);
    assert_eq!(outcome.error, ErrorClass::IncompletePreState);
    assert!(outcome.receipts.is_empty());
}

#[test]
fn an_exact_pre_state_answers_listed_block_hashes_only() {
    let hash = B256::repeat_byte(7);
    let db = state::seed(
        &PreState::Exact {
            state: StateInput::default(),
            block_hashes: BTreeMap::from([(5, hash)]),
        },
        Tempo.genesis(),
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
        &exact(one_account(RECIPIENT, AccountInput::default())),
        Tempo.genesis(),
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
    // is missing from the pre-state and the third's cap is broken, but the block touches neither,
    // so neither is checked.
    fn token(index: u8) -> Address {
        Address::with_last_byte(index) | PATH_USD_ADDRESS
    }
    fn storage(state: &mut StateInput, index: u8) -> &mut BTreeMap<U256, U256> {
        &mut state.accounts.get_mut(&token(index)).unwrap().storage
    }
    let mut state = exact_genesis(StateInput::default(), &[transfer_block()]);
    storage(&mut state, 0).extend([(TOTAL_SUPPLY, U256::from(1)), (SUPPLY_CAP, U256::ZERO)]);
    storage(&mut state, 1).remove(&TOTAL_SUPPLY);
    storage(&mut state, 2).insert(SUPPLY_CAP, U256::ZERO);
    let outcome = run(exact(state), vec![transfer_block()]);

    assert_eq!(
        (outcome.error, outcome.receipts.len()),
        (ErrorClass::BrokenPreState, 0)
    );
    let encoded = bincode_options().serialize(&outcome).unwrap();
    let decoded: TempoExecutionOutcome = bincode_options().deserialize(&encoded).unwrap();
    assert_eq!(decoded, outcome, "failures survive the wire");
    let failures: HashSet<_> = outcome
        .invariant_failures
        .iter()
        .map(|failure| {
            let id = failure.violation.id.strip_prefix("TEMPO-TIP20-").unwrap();
            let token = (0..4)
                .find(|&index| failure.violation.subject == format!("token={}", token(index)));
            (id, &failure.scope, token)
        })
        .collect();
    let start = InvariantScope::Execution;
    let expected = [("SUPPLY-CAP", &start, 0), ("BALANCE-SUM", &start, 0)];
    assert_eq!(
        failures,
        expected
            .map(|(id, scope, token)| (id, scope, Some(token)))
            .into()
    );
}

#[test]
fn a_system_step_runs_state_checks_but_no_step_checks() {
    // The EIP-2935 history contract, run as the block's pre-execution system call, moves 1 pathUSD
    // it holds to RECIPIENT. The executor drops the call's `Transfer` log.
    let mut code = vec![0x63];
    code.extend(ITIP20::transferCall::SELECTOR);
    code.extend([0x60, 0xe0, 0x1b, 0x60, 0x00, 0x52, 0x73]);
    code.extend(RECIPIENT);
    code.extend([0x60, 0x04, 0x52, 0x60, 0x01, 0x60, 0x24, 0x52]);
    code.extend([
        0x60, 0x00, 0x60, 0x00, 0x60, 0x44, 0x60, 0x00, 0x60, 0x00, 0x73,
    ]);
    code.extend(PATH_USD_ADDRESS);
    code.extend([0x5a, 0xf1, 0x50, 0x00]);
    let context = BlockContextInput {
        block_number: 1,
        ..context(TempoHardfork::T13, 0)
    };
    let blocks = vec![block(BlockHeaderInput::Context(context), Vec::new())];
    // A genesis pre-state keeps protocol code, so the edited genesis is given as an exact one.
    let mut path_usd = path_usd(&mut genesis_state()).clone();
    path_usd.storage.insert(
        HISTORY_STORAGE_ADDRESS.mapping_slot(tip20_slots::BALANCES),
        U256::from(1),
    );
    *path_usd.storage.entry(TOTAL_SUPPLY).or_default() += U256::from(1);
    let history = AccountInput {
        code: code.into(),
        ..Default::default()
    };
    let edits = StateInput {
        accounts: [
            (PATH_USD_ADDRESS, path_usd),
            (HISTORY_STORAGE_ADDRESS, history),
        ]
        .into(),
    };
    let state = exact_genesis(edits, &blocks);
    let (outcome, rejection) = run_on(&Tempo, input(exact(state), blocks));

    assert_eq!(outcome.error, ErrorClass::None, "{rejection:?}");
    let moved = storage_at(&outcome.state_diff.blocks[0].pre_block, PATH_USD_ADDRESS).count();
    assert!(moved > 0, "the system call moved pathUSD");
    assert!(
        outcome.invariant_failures.is_empty(),
        "{:?}",
        outcome.invariant_failures
    );
    assert!(outcome.invariant_counts["TEMPO-TIP20-BALANCE-SUM"].evaluated > 0);
    assert!(
        !outcome
            .invariant_counts
            .contains_key("TEMPO-TIP20-TRANSFER-EVENTS")
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
        let header = chain::header(spec.as_ref(), &context).unwrap();
        let header = reth_primitives_traits::SealedHeader::seal_slow(header);
        let result = consensus.validate_header(&header);
        assert!(result.is_ok(), "{hardfork:?}: {result:?}");
    }
}

#[test]
fn transaction_inputs_decode_and_recover_without_executing() {
    let outcome = |tx: Bytes, sender: Option<Address>| {
        let input = TempoHarnessInput::Transaction(TempoTransactionInput { tx, sender });
        let (TempoHarnessOutcome::Transaction(outcome), _) = execute::run(&Tempo, input) else {
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

/// Tempo L1, with every block whose header the harness builds opened and closed by a call from
/// [`SENDER`], at nonces 0 and 2 around the input's.
struct Opening;

impl Opening {
    fn call(nonce: u64) -> Recovered<TempoTxEnvelope> {
        let tx = call(nonce, RECIPIENT, Bytes::new(), 1_000_000);
        let tx = TempoTxEnvelope::decode_2718_exact(&tx).unwrap();
        Recovered::new_unchecked(tx, SENDER)
    }
}

impl Engine for Opening {
    type ChainSpec = <Tempo as Engine>::ChainSpec;
    type EvmConfig = <Tempo as Engine>::EvmConfig;
    type Consensus = <Tempo as Engine>::Consensus;
    type Checks = ();

    const IMPLEMENTATION: &'static str = "opening";
    const HARDFORKS: &'static [TempoHardfork] = Tempo::HARDFORKS;
    const INPUTS: &'static [HarnessInputKind] = Tempo::INPUTS;
    const FEE_AMM: Option<Address> = Tempo::FEE_AMM;
    const DEX: Option<Address> = Tempo::DEX;

    fn chain(&self, input: &ChainSpecInput) -> Result<Chain<Self>, Rejection> {
        let Chain {
            spec,
            evm_config,
            consensus,
        } = Tempo.chain(input)?;
        Ok(Chain {
            spec,
            evm_config,
            consensus,
        })
    }

    fn genesis(&self) -> &Cache {
        Tempo.genesis()
    }

    fn open_block(
        &self,
        _evm: &mut TempoEvm<'_>,
        _header: &TempoHeader,
    ) -> Result<Vec<Recovered<TempoTxEnvelope>>, BlockExecutionError> {
        Ok(vec![Self::call(0)])
    }

    fn close_block(
        &self,
        _evm: &mut TempoEvm<'_>,
        _header: &TempoHeader,
    ) -> Result<Vec<Recovered<TempoTxEnvelope>>, BlockExecutionError> {
        Ok(vec![Self::call(2)])
    }
}

#[test]
fn only_a_block_the_harness_builds_gets_the_chains_transactions() {
    let built = t4_block(vec![transfer(1, 7)]);
    let (outcome, rejection) = run_on(&Opening, input(genesis(), vec![built]));
    assert_eq!(rejection, None);
    assert!(
        outcome.invariant_failures.is_empty(),
        "{:?}",
        outcome.invariant_failures
    );
    let order: Vec<_> = outcome.receipts.iter().map(|receipt| receipt.tx).collect();
    assert_eq!(
        order,
        [
            TxIndex::Synthesized(0),
            TxIndex::Input(0),
            TxIndex::Synthesized(1)
        ]
    );
    let steps = &outcome.state_diff.blocks[0];
    assert_eq!((steps.synthesized.len(), steps.txs.len()), (2, 1));
    // The input's transfer is the one that moves pathUSD.
    assert_eq!(storage_at(&steps.txs[0], PATH_USD_ADDRESS).count(), 2);

    // A given header's block runs exactly the input's transactions, as on Tempo L1.
    let tx = transfer(0, 7);
    let block = block(
        BlockHeaderInput::Rlp(rlp_header(&tx, |_| {}).into()),
        vec![tx],
    );
    let (outcome, _) = run_on(&Opening, input(genesis(), vec![block.clone()]));
    assert_eq!(outcome, run(genesis(), vec![block]));
}

/// A legacy transaction signed with `signer`'s secp256k1 mock signature.
fn mock_legacy(signer: Address, nonce: u64, to: Address, input: Bytes) -> Bytes {
    let tx = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce,
        gas_price: 0,
        gas_limit: 1_000_000,
        to: TxKind::Call(to),
        value: U256::ZERO,
        input,
    };
    let signature = mock::secp256k1(signer, &tx.signature_hash());
    TempoTxEnvelope::Legacy(tx.into_signed(signature))
        .encoded_2718()
        .into()
}

/// Mocks pass end to end: legacy sender, ECRECOVER, P256VERIFY, WebAuthn sender and fee payer.
#[test]
fn mock_signatures_verify_end_to_end() {
    assert!(
        crate::crypto::enable(),
        "no input ran before mocks were enabled"
    );
    let digest = B256::repeat_byte(0x5a);
    let signer = address!("00000000000000000000000000000000000000c0");
    let signature = mock::secp256k1(signer, &digest);
    let ecrecover = [
        digest,
        B256::with_last_byte(27),
        signature.r().into(),
        signature.s().into(),
    ];
    let (_, x, y, p256_sender) = p256_keypair();
    let (r, s) = mock::p256(&x, &y, &digest);
    let p256verify = [digest, r, s, x, y].concat();
    let mut wrong = p256verify.clone();
    wrong[0] ^= 1;

    let mut aa = TempoTransaction {
        chain_id: CHAIN_ID,
        fee_token: Some(PATH_USD_ADDRESS),
        calls: vec![Call::new(RECIPIENT, Bytes::new())],
        gas_limit: 1_000_000,
        ..Default::default()
    };
    // SENDER, funded with pathUSD, sponsors the fees without its key.
    aa.fee_payer_signature = Some(mock::secp256k1(
        SENDER,
        &aa.fee_payer_signature_hash(p256_sender),
    ));
    let hash = aa.signature_hash();
    let webauthn = mock::webauthn(x, y, mock::webauthn_data(&hash), &hash).unwrap();
    let aa = TempoTxEnvelope::AA(aa.into_signed(TempoSignature::Primitive(
        PrimitiveSignature::WebAuthn(webauthn),
    )));

    let p256verify_address = address!("0000000000000000000000000000000000000100");
    let txs = vec![
        mock_legacy(
            SENDER,
            0,
            address!("0000000000000000000000000000000000000001"),
            ecrecover.concat().into(),
        ),
        mock_legacy(SENDER, 1, p256verify_address, p256verify.into()),
        mock_legacy(SENDER, 2, p256verify_address, wrong.into()),
        aa.encoded_2718().into(),
    ];
    // No senders, so the harness recovers them from the mock signatures.
    let block = TempoBlock {
        senders: Vec::new(),
        ..t4_block(txs)
    };
    let outcome = run(genesis(), vec![block]);
    assert_eq!(outcome.error, ErrorClass::None, "{outcome:?}");
    let receipts = &outcome.receipts;
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.outcome == TxOutcome::Success)
    );
    assert_eq!(receipts[0].output, Bytes::from(signer.into_word().0));
    assert_eq!(
        receipts[1].output,
        Bytes::from(U256::from(1).to_be_bytes::<32>())
    );
    assert_eq!(
        receipts[2].output,
        Bytes::new(),
        "a mock signature for another digest fails"
    );
    let sent = |tx: usize, sender: Address, nonce: u64| {
        outcome.state_diff.blocks[0].txs[tx]
            .accounts
            .iter()
            .any(|account| account.address == sender && account.nonce == Some(nonce))
    };
    assert!(sent(0, SENDER, 1), "the mock signature's signer sent it");
    assert!(
        sent(3, p256_sender, 1),
        "the WebAuthn key's account sent it"
    );
}

// The dev account holds pathUSD's issuer role, so its traced mint is judged.
#[test_case(
    call(
        0,
        PATH_USD_ADDRESS,
        ITIP20::mintCall { to: RECIPIENT, amount: U256::from(5) }.abi_encode().into(),
        1_000_000,
    ),
    &["TEMPO-TIP20-ROLE-AUTHZ"];
    "a role-gated call"
)]
// A call that leaves the token as it was is judged too.
#[test_case(
    call(
        0,
        Address::with_last_byte(1) | PATH_USD_ADDRESS,
        ITIP20::mintCall { to: RECIPIENT, amount: U256::ZERO }.abi_encode().into(),
        1_000_000,
    ),
    &["TEMPO-TIP20-ROLE-AUTHZ"];
    "a role-gated call with no effect"
)]
// Minting LP names its pool, whose holders then each burn it all on a throwaway state.
#[test_case(mint_lp(0), &["TEMPO-AMM5", "TEMPO-AMM-EXIT"]; "an LP mint")]
fn a_call_is_judged_by_the_checks_it_arms_and_holds(tx: Bytes, ids: &[&str]) {
    let outcome = run(genesis(), vec![t4_block(vec![tx])]);
    assert_eq!(outcome.receipts[0].outcome, TxOutcome::Success);
    for &id in ids.iter().chain(&["TEMPO-TRACE"]) {
        assert_eq!(counts(&outcome, id), (1, 1, 0), "{id}");
    }
    assert_eq!(outcome.invariant_failures, []);
}

#[test]
fn every_pool_is_exited_at_a_block_start_and_the_pools_lp_events_name_after_each_step() {
    // The exits judged over a block minting LP and then one holding `txs`.
    let exits = |txs: Vec<Bytes>| {
        let outcome = run(genesis(), vec![t4_block(vec![mint_lp(0)]), t4_block(txs)]);
        assert_eq!(outcome.invariant_failures, []);
        counts(&outcome, "TEMPO-AMM-EXIT").0
    };
    // The mint alone is judged once, so the second block's start exits pools no event named.
    let at_start = exits(Vec::new());
    assert!(at_start > 1, "{at_start}");
    let burn_lp = ITIPFeeAMM::burnCall {
        userToken: Address::with_last_byte(1) | PATH_USD_ADDRESS,
        validatorToken: PATH_USD_ADDRESS,
        liquidity: U256::from(1000),
        to: SENDER,
    };
    let burn = call(
        1,
        TIP_FEE_MANAGER_ADDRESS,
        burn_lp.abi_encode().into(),
        2_000_000,
    );
    assert_eq!(exits(vec![burn]), at_start + 1, "a burn names its pool");
    assert_eq!(
        exits(vec![transfer(1, 7)]),
        at_start,
        "a transfer names none"
    );
}

#[test]
fn an_exit_that_reads_outside_an_exact_pre_state_is_not_answered() {
    // The exact pre-state lists only what the mint read, and burning reads more.
    let block = t4_block(vec![mint_lp(0)]);
    let state = exact_genesis(StateInput::default(), std::slice::from_ref(&block));
    let outcome = run(exact(state), vec![block]);
    assert_eq!(outcome.error, ErrorClass::None);
    for id in ["TEMPO-AMM5", "TEMPO-AMM-EXIT"] {
        assert_eq!(counts(&outcome, id), (1, 0, 0), "{id}");
    }
    assert_eq!(outcome.invariant_failures, []);
}

#[test]
fn each_receipt_after_a_blocks_first_is_judged_for_its_cumulative_gas() {
    let block = t4_block(vec![transfer(0, 7), transfer(1, 7), transfer(2, 7)]);
    let outcome = run(genesis(), vec![block]);
    assert_eq!(counts(&outcome, "TEMPO-BLOCK-GAS-MONOTONIC"), (2, 2, 0));
}

/// An account no test's pre-state lists.
const UNLISTED: Address = address!("00000000000000000000000000000000000000bb");
/// The nonce that makes [`Watching`] flag an account.
const FLAGGED_NONCE: u64 = 7;

/// Tempo L1 without the account invariants, whose own check reads [`UNLISTED`] after every
/// step, records what ran and whether the read missed, and flags `flag` while its nonce is
/// [`FLAGGED_NONCE`].
#[derive(Default)]
struct Watching {
    flag: Option<Address>,
    seen: std::cell::RefCell<Vec<(tempo_invariants::Ran, bool, bool)>>,
    /// How many steps of its run each check came after.
    steps: std::cell::RefCell<Vec<usize>>,
}

impl Engine for Watching {
    type ChainSpec = <Tempo as Engine>::ChainSpec;
    type EvmConfig = <Tempo as Engine>::EvmConfig;
    type Consensus = <Tempo as Engine>::Consensus;
    type Checks = usize;

    const IMPLEMENTATION: &'static str = "watching";
    const HARDFORKS: &'static [TempoHardfork] = Tempo::HARDFORKS;
    const INPUTS: &'static [HarnessInputKind] = Tempo::INPUTS;
    const FEE_AMM: Option<Address> = Tempo::FEE_AMM;
    const DEX: Option<Address> = Tempo::DEX;
    const ACCOUNTS: bool = false;

    fn chain(&self, input: &ChainSpecInput) -> Result<Chain<Self>, Rejection> {
        let Chain {
            spec,
            evm_config,
            consensus,
        } = Tempo.chain(input)?;
        Ok(Chain {
            spec,
            evm_config,
            consensus,
        })
    }

    fn genesis(&self) -> &Cache {
        Tempo.genesis()
    }

    fn check_step(
        &self,
        steps: &mut usize,
        state: &crate::StepState<'_, Self::EvmConfig>,
        report: &mut Report,
    ) {
        self.steps.borrow_mut().push(*steps);
        *steps += 1;
        state.forget_missed();
        let _ = state.account(UNLISTED);
        self.seen
            .borrow_mut()
            .push((state.effects().ran.clone(), state.missed(), state.start()));
        if let Some(flag) = self.flag
            && let Some(Some(info)) = state.account(flag)
            && info.nonce == FLAGGED_NONCE
        {
            report.violations.push(Violation {
                id: "TEST-FLAGGED".into(),
                subject: flag.to_string(),
                detail: String::new(),
            });
        }
    }

    fn own_invariants() -> Vec<tempo_fuzz_types::InvariantInfo> {
        Vec::new()
    }
}

#[test]
fn a_chain_without_account_invariants_leaves_them_out_of_its_catalog() {
    use tempo_invariants::configurable_account as account;

    let ids = |catalog: Vec<tempo_fuzz_types::InvariantInfo>| -> HashSet<String> {
        catalog.into_iter().map(|info| info.id).collect()
    };
    let accounts: Vec<&str> = account::STEP_CHECKS
        .iter()
        .map(|check| check.id)
        .chain(account::LEAF_CHECKS.iter().map(|check| check.id))
        .chain([account::VIEW])
        .collect();
    let (tempo, watching) = (
        ids(invariants::catalog::<Tempo>()),
        ids(invariants::catalog::<Watching>()),
    );
    for id in accounts {
        assert!(tempo.contains(id), "Tempo's catalog lacks {id}");
        assert!(!watching.contains(id), "a chain without them lists {id}");
    }
    // Only the account invariants are left out.
    assert_eq!(
        tempo.difference(&watching).count(),
        account::STEP_CHECKS.len() + account::LEAF_CHECKS.len() + 1
    );
}

#[test]
fn the_chains_own_check_missing_an_exact_pre_state_leaves_execution_complete() {
    let engine = Watching::default();
    let state = exact_genesis(StateInput::default(), &[transfer_block()]);
    let (outcome, rejection) = run_on(&engine, input(exact(state), vec![transfer_block()]));
    assert_eq!((outcome.error, rejection), (ErrorClass::None, None));
    assert_eq!(outcome.receipts.len(), 1);
    // Every check's read missed, and none counted against execution.
    let seen = engine.seen.borrow();
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|(_, missed, _)| *missed), "{seen:?}");
}

#[test]
fn the_chains_own_check_sees_the_blocks_post_execution_changes() {
    let engine = Watching::default();
    let (outcome, _) = run_on(&engine, input(genesis(), vec![transfer_block()]));
    assert_eq!(outcome.error, ErrorClass::None);
    let ran: Vec<_> = engine
        .seen
        .borrow()
        .iter()
        .map(|(ran, _, start)| {
            assert!(!start, "only a pre-state checked on its own is a start");
            ran.clone()
        })
        .collect();
    assert!(
        matches!(ran.first(), Some(tempo_invariants::Ran::PreBlock)),
        "{ran:?}"
    );
    assert!(
        matches!(ran.last(), Some(tempo_invariants::Ran::PostBlock)),
        "{ran:?}"
    );
    assert_eq!(ran.iter().filter(|ran| ran.tx().is_some()).count(), 1);
}

#[test]
fn each_run_starts_the_chains_own_checks_afresh() {
    let engine = Watching::default();
    for _ in 0..2 {
        let (outcome, _) = run_on(&engine, input(genesis(), vec![transfer_block()]));
        assert_eq!(outcome.error, ErrorClass::None);
    }
    let steps = engine.steps.borrow();
    let per_run = steps.len() / 2;
    let expected: Vec<usize> = (0..per_run).chain(0..per_run).collect();
    assert_eq!(*steps, expected);
}

#[test]
fn a_pre_state_breaking_the_chains_own_check_is_broken() {
    let flag = address!("00000000000000000000000000000000000000cc");
    let engine = Watching {
        flag: Some(flag),
        ..Default::default()
    };
    let pre_state = PreState::Genesis(one_account(
        flag,
        AccountInput {
            nonce: FLAGGED_NONCE,
            ..Default::default()
        },
    ));
    let (outcome, rejection) = run_on(&engine, input(pre_state, vec![transfer_block()]));
    assert_eq!(outcome.error, ErrorClass::BrokenPreState);
    assert_eq!(
        rejection.map(|r| r.class()),
        Some(ErrorClass::BrokenPreState)
    );
    // The pre-state was checked on its own, after the steps that broke the check.
    assert!(matches!(engine.seen.borrow().last(), Some((_, _, true))));
    let failures: Vec<_> = outcome
        .invariant_failures
        .iter()
        .map(|failure| (failure.violation.id.as_ref(), failure.scope.clone()))
        .collect();
    assert_eq!(failures, [("TEST-FLAGGED", InvariantScope::Execution)]);
}
