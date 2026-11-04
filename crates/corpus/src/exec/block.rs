//! Block execution over a database, capturing per-transaction records and checking them.

use crate::{
    code,
    exec::db::{View, change_from_update},
    types::{Block as BlockInput, Case, Delta, Outcome, Phases, Transaction},
};
use alloy_consensus::{
    BlockHeader,
    transaction::{Recovered, TxHashRef},
};
use alloy_eip7928::bal::Bal;
use alloy_primitives::{Address, B256, Bytes, U256};
use bincode::Options;
use evm2::evm::Database;
use eyre::{OptionExt, WrapErr};
use parking_lot::Mutex;
use reth_consensus::FullConsensus;
use reth_evm::{
    ConfigureEvm,
    execute::{BlockExecutor, BlockExecutorFactory},
};
use reth_execution_types::StateUpdate;
use reth_primitives_traits::{Account, RecoveredBlock};
use reth_trie_common::bundle_state::{AccountInfoRevert, BundleState, RevertToSlot};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tempo_chainspec::TempoHardforks as _;
use tempo_evm::{ExecutorState, TempoBlockExecutor, TempoEvmConfig};
use tempo_primitives::{Block, TempoPrimitives, TempoTxEnvelope};

/// A block's execution records and resulting state.
#[derive(Debug)]
pub struct Executed {
    pub transactions: Vec<Transaction>,
    pub phases: Phases,
    pub bundle: BundleState,
    pub gas: u64,
}

type Updates = Arc<Mutex<Vec<StateUpdate>>>;

fn hooked(executor: &mut TempoBlockExecutor<'_>) -> eyre::Result<Updates> {
    let updates = Updates::default();
    let sink = updates.clone();
    eyre::ensure!(
        executor.set_state_hook(move |update| sink.lock().push(update)),
        "executor does not support state hooks"
    );
    Ok(updates)
}

fn drain(updates: &Updates) -> Vec<StateUpdate> {
    std::mem::take(&mut *updates.lock())
}

/// Converts committed updates into ordered stored commits. New code comes from `contracts`
/// or the shared code cache.
fn delta(updates: Vec<StateUpdate>, contracts: &HashMap<B256, Bytes>) -> eyre::Result<Delta> {
    let mut delta = Delta::default();
    for update in updates {
        let mut commit = BTreeMap::new();
        for account in &update.accounts {
            let change = change_from_update(account, |hash| {
                contracts
                    .get(&hash)
                    .cloned()
                    .or_else(|| code::code_bytes(&hash.0))
                    .ok_or_else(|| eyre::eyre!("missing created code {hash}"))
            })?;
            eyre::ensure!(
                commit
                    .insert(account.address.into_array(), change)
                    .is_none(),
                "duplicate account in one state update"
            );
        }
        if !commit.is_empty() {
            delta.0.push(commit);
        }
    }
    Ok(delta)
}

fn contracts(bundle: &BundleState) -> HashMap<B256, Bytes> {
    bundle
        .contracts
        .iter()
        .map(|(hash, code)| (*hash, code.original_bytes()))
        .collect()
}

fn executor<'a, DB: Database + 'a>(
    config: &'a TempoEvmConfig,
    db: DB,
    block: &'a RecoveredBlock<Block>,
) -> eyre::Result<TempoBlockExecutor<'a>> {
    let env = config.evm_env(block.header())?;
    let evm = ConfigureEvm::evm_with_env(config, db, env);
    let ctx = config.context_for_block(block.sealed_block())?;
    Ok(config.block_executor_factory().create_executor(evm, ctx))
}

/// Executes and commits `tx`, recording it with `before` and an empty delta: the caller fills
/// the delta from the state updates once created code is known.
fn transact(
    executor: &mut TempoBlockExecutor<'_>,
    tx: Recovered<&TempoTxEnvelope>,
    ordinal: u64,
    index: usize,
    before: Vec<u8>,
) -> eyre::Result<Transaction> {
    let hash = tx.tx_hash().0;
    let output = executor.execute_transaction_without_commit(tx)?;
    let r = output.result();
    let outcome = Outcome {
        status: u8::from(!r.status),
        reason: format!("{:?}", r.stop),
        created: r.created_address.map(|a| a.into_array()),
        gas: [
            r.total_gas_spent,
            r.refunded,
            r.floor_gas,
            r.state_gas_spent,
        ],
        charged_gas: r.tx_gas_used(),
        output: Some(r.output.to_vec()),
    };
    executor.commit_transaction(output)?;
    let receipt = executor.receipts().last().ok_or_eyre("missing receipt")?;
    Ok(Transaction {
        ordinal,
        index: index as u64,
        hash,
        before,
        after: boundary().serialize(&executor.executor_state())?,
        outcome,
        receipt: alloy_rlp::encode(receipt),
        delta: Delta::default(),
    })
}

/// Executes a block once, recording each transaction's boundary, outcome, receipt and
/// committed changes. With `expected`, every record is checked against its stored digests.
/// Consensus post-execution rules (gas, receipts root, bloom, BAL hash) are always checked.
pub fn execute_block<C, DB>(
    config: &TempoEvmConfig,
    consensus: &C,
    db: DB,
    block: &RecoveredBlock<Block>,
    first_tx: u64,
    expected: Option<(&[Case], &Phases)>,
) -> eyre::Result<Executed>
where
    C: FullConsensus<TempoPrimitives> + ?Sized,
    DB: Database,
{
    let mut executor = executor(config, db, block)?;
    if block.header().block_access_list_hash().is_some() {
        executor.enable_block_access_list_builder();
    }
    let updates = hooked(&mut executor)?;
    executor.apply_pre_execution_changes()?;
    let pre = drain(&updates);
    let mut records = Vec::new();
    for (index, tx) in block.transactions_recovered().enumerate() {
        let before = boundary().serialize(&executor.executor_state())?;
        let record = transact(&mut executor, tx, first_tx + index as u64, index, before)?;
        records.push((record, drain(&updates)));
    }
    let (output, bal) = executor.finish_with_block_access_list()?;
    let post = drain(&updates);
    let contracts = contracts(&output.state);
    let phases = Phases {
        pre: delta(pre, &contracts)?,
        post: delta(post, &contracts)?,
    };
    let transactions = records
        .into_iter()
        .map(|(mut record, updates)| {
            record.delta = delta(updates, &contracts)?;
            Ok(record)
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    if let Some((cases, expected_phases)) = expected {
        eyre::ensure!(
            cases.len() == transactions.len(),
            "transaction count mismatch"
        );
        let check = || -> eyre::Result<()> {
            phase_check("pre-execution", &expected_phases.pre, &phases.pre)?;
            for (case, actual) in cases.iter().zip(&transactions) {
                case.check(actual)?;
            }
            phase_check("post-execution", &expected_phases.post, &phases.post)
        };
        check().wrap_err_with(|| block_context(config, block))?;
    }
    let bal_hash = bal.map(|bal| Bal::from(bal).compute_hash_with_buf(&mut Vec::new()));
    consensus.validate_block_post_execution(block, &output.result, None, bal_hash)?;
    let gas = transactions.iter().map(Transaction::gas_used).sum();
    Ok(Executed {
        transactions,
        phases,
        bundle: output.state,
        gas,
    })
}

/// Executes one transaction alone: a fresh executor over `view` (the state before it),
/// restored from its `before` boundary, without pre-execution changes. Returns its record;
/// the caller applies its delta to carry the state forward.
pub fn run_standalone(
    config: &TempoEvmConfig,
    block: &RecoveredBlock<Block>,
    view: &View,
    ordinal: u64,
    index: usize,
    before: &[u8],
) -> eyre::Result<Transaction> {
    let mut executor = executor(config, view.clone(), block)?;
    let state: ExecutorState = boundary()
        .deserialize(before)
        .wrap_err("invalid transaction boundary")?;
    executor.with_executor_state(state);
    let updates = hooked(&mut executor)?;
    let tx = block
        .transactions_recovered()
        .nth(index)
        .ok_or_eyre("transaction index out of range")?;
    let mut record = transact(&mut executor, tx, ordinal, index, before.to_vec())?;
    let state = executor.into_state();
    record.delta = delta(drain(&updates), &contracts(&state))?;
    Ok(record)
}

/// Runs the block's transactions standalone from their stored records alone: the state
/// before each one is restored from the pre phase and the earlier stored deltas, without
/// executing the block. `select` picks which transactions run; each one that runs is checked
/// against its record.
pub fn standalone_cases(
    config: &TempoEvmConfig,
    block: &RecoveredBlock<Block>,
    mut view: View,
    phases: &Phases,
    cases: &[Case],
    mut select: impl FnMut(&Case) -> bool,
) -> eyre::Result<()> {
    view.apply(&phases.pre)?;
    for (index, case) in cases.iter().enumerate() {
        if select(case) {
            let actual = run_standalone(config, block, &view, case.ordinal, index, &case.before)?;
            case.check(&actual)
                .wrap_err_with(|| block_context(config, block))?;
        }
        view.apply(&case.delta)?;
    }
    Ok(())
}

/// Compares a block's recorded pre- or post-execution system changes with the replayed ones.
fn phase_check(phase: &str, recorded: &Delta, replayed: &Delta) -> eyre::Result<()> {
    if recorded == replayed {
        return Ok(());
    }
    let mut message = format!("{phase} delta mismatch");
    for line in recorded.diff(replayed) {
        message.push_str("\n  ");
        message.push_str(&line);
    }
    Err(eyre::eyre!(message))
}

/// The block a mismatch happened in: its number, hash, timestamp and active hardfork.
fn block_context(config: &TempoEvmConfig, block: &RecoveredBlock<Block>) -> String {
    let header = block.header();
    format!(
        "block {} ({}) at timestamp {}, hardfork {:?}",
        header.number(),
        block.hash(),
        header.timestamp(),
        config.chain_spec().tempo_hardfork_at(header.timestamp()),
    )
}

/// Decodes a stored block and checks it against its recorded hash and parent.
pub fn decode_block(
    input: &BlockInput,
    number: u64,
    parent: B256,
) -> eyre::Result<RecoveredBlock<Block>> {
    let block: Block = alloy_rlp::decode_exact(&input.rlp)?;
    eyre::ensure!(
        block.header.number() == number && block.header.parent_hash() == parent,
        "corpus block gap/order mismatch"
    );
    // The hash check below covers only the header; tie the body to it too.
    tempo_evm::consensus::validate_body_against_header(&block.body, &block.header)
        .map_err(|error| eyre::eyre!("block {number}: body does not match header: {error}"))?;
    eyre::ensure!(
        block.body.transactions.len() == input.senders.len(),
        "corpus sender count mismatch"
    );
    let block = RecoveredBlock::new_unhashed(
        block,
        input.senders.iter().copied().map(Address::from).collect(),
    );
    eyre::ensure!(
        block.hash().0 == input.hash,
        "corpus canonical hash mismatch"
    );
    Ok(block)
}

/// Checks a block's reverts against its historical changesets.
///
/// Reverts must match changeset entries exactly. A destroyed account may have extra changeset
/// slots (from the storage wipe) that are absent from reverts.
pub fn verify_changesets(
    bundle: &BundleState,
    changeset: &crate::types::ChangeSet,
    number: u64,
) -> eyre::Result<()> {
    let reverts = bundle.reverts.last().ok_or_eyre("missing block reverts")?;
    let mut accounts: HashMap<Address, Option<Account>> = changeset
        .accounts
        .iter()
        .map(|(address, info)| (Address::from(*address), info.as_ref().map(|i| i.account())))
        .collect();
    let mut storage: HashMap<Address, HashMap<B256, U256>> = HashMap::new();
    for ((address, key), value) in &changeset.storage {
        storage
            .entry(Address::from(*address))
            .or_default()
            .insert(B256::from(*key), U256::from_be_bytes(*value));
    }
    for (address, revert) in reverts {
        // `None` when the revert leaves the account alone, else the account it restores.
        let reverted = match &revert.account {
            AccountInfoRevert::DoNothing => None,
            AccountInfoRevert::DeleteIt => Some(None),
            AccountInfoRevert::RevertTo(info) => Some(Some(Account::from(info))),
        };
        match (reverted, accounts.remove(address)) {
            (None, None) => {}
            (None, Some(_)) => {
                eyre::bail!(
                    "block {number}: account {address} in changeset but revert is DoNothing"
                )
            }
            (Some(_), None) => {
                eyre::bail!("block {number}: account {address} reverted but not in changeset")
            }
            (Some(revert), Some(changeset)) => eyre::ensure!(
                revert == changeset,
                "block {number}: account {address} mismatch: revert={revert:?} changeset={changeset:?}"
            ),
        }
        let mut slots = storage.remove(address);
        for (key, slot) in &revert.storage {
            let key = B256::from(*key);
            let value = slots.as_mut().and_then(|s| s.remove(&key));
            match (slot, value) {
                // A slot of a destroyed and re-created account never read its original value.
                (RevertToSlot::Destroyed, _) => {}
                (RevertToSlot::Some(prev), Some(value)) => eyre::ensure!(
                    *prev == value,
                    "block {number}: {address} slot {key} mismatch: revert={prev} changeset={value}"
                ),
                (RevertToSlot::Some(_), None) => eyre::ensure!(
                    revert.wipe_storage,
                    "block {number}: {address} slot {key} reverted but not in changeset"
                ),
            }
        }
        if let Some(remaining) = slots.filter(|s| !s.is_empty()) {
            eyre::ensure!(
                revert.wipe_storage,
                "block {number}: {address} has {} unmatched changeset slots",
                remaining.len()
            );
        }
    }
    if let Some(address) = accounts.keys().next() {
        eyre::bail!("block {number}: account {address} in changeset but not in reverts");
    }
    // Storage-only changes have no account entry, so an address re-execution never touched
    // would otherwise go unchecked.
    if let Some((address, slots)) = storage.iter().find(|(_, slots)| !slots.is_empty()) {
        eyre::bail!(
            "block {number}: {address} has {} changeset slots but no revert",
            slots.len()
        );
    }
    Ok(())
}

/// Codec of a stored transaction boundary, an [`ExecutorState`]: the section id byte followed
/// by six big-endian counters, 49 bytes. Trailing bytes are rejected.
fn boundary() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_big_endian()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChangeSet;
    use reth_trie_common::bundle_state::{AccountRevert, Reverts};

    fn bundle(reverts: Vec<(Address, AccountRevert)>) -> BundleState {
        BundleState {
            reverts: Reverts::new(vec![reverts]),
            ..Default::default()
        }
    }

    #[test]
    fn changesets_check_storage_only_changes() {
        let mut changeset = ChangeSet::default();
        changeset
            .storage
            .insert(([1; 20], [2; 32]), U256::from(3).to_be_bytes());
        let revert = AccountRevert {
            storage: [(
                U256::from_be_bytes([2; 32]),
                RevertToSlot::Some(U256::from(3)),
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        verify_changesets(
            &bundle(vec![(Address::repeat_byte(1), revert)]),
            &changeset,
            7,
        )
        .unwrap();
        // An address re-execution never touched has no revert to match its slots.
        let err = verify_changesets(&bundle(vec![]), &changeset, 7).unwrap_err();
        assert!(err.to_string().contains("but no revert"), "{err}");
    }

    #[test]
    fn boundary_encoding_roundtrip() {
        for section in 0..5u8 {
            let mut bytes = vec![section];
            for value in [1, u64::MAX, 3, 4, 5, 6] {
                bytes.extend(value.to_be_bytes());
            }
            let state: ExecutorState = boundary().deserialize(&bytes).unwrap();
            assert_eq!(boundary().serialize(&state).unwrap(), bytes);
            assert!(
                boundary()
                    .deserialize::<ExecutorState>(&bytes[1..])
                    .is_err()
            );
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(boundary().deserialize::<ExecutorState>(&trailing).is_err());
        }
        let mut unknown = vec![5];
        unknown.extend([0; 48]);
        let err = boundary()
            .deserialize::<ExecutorState>(&unknown)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("expected a block section id from 0 to 4"),
            "{err}"
        );
    }
}
