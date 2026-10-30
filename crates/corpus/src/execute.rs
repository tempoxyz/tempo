//! Block execution over a database, capturing per-transaction records and checking them.

use crate::{
    code,
    types::{Block as BlockInput, Case, Delta, Outcome, Phases, Transaction},
    view::{View, change_from_update},
};
use alloy_consensus::{BlockHeader, transaction::TxHashRef};
use alloy_eip7928::bal::Bal;
use alloy_primitives::{Address, B256, Bytes, U256};
use evm2::evm::Database;
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
use tempo_evm::{TempoBlockExecutor, TempoEvmConfig, TempoTransactionBoundary};
use tempo_primitives::{Block, TempoPrimitives};

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

fn outcome(result: &tempo_evm::TempoTxResult) -> Outcome {
    let r = result.result();
    Outcome {
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
    }
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
        let before = executor.transaction_boundary().encode().to_vec();
        let output = executor.execute_transaction_without_commit(tx)?;
        let outcome = outcome(&output);
        executor.commit_transaction(output)?;
        let after = executor.transaction_boundary().encode().to_vec();
        let receipt = alloy_rlp::encode(
            executor
                .receipts()
                .last()
                .ok_or_else(|| eyre::eyre!("missing receipt"))?,
        );
        records.push((index, before, after, outcome, receipt, drain(&updates)));
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
        .map(|(index, before, after, outcome, receipt, updates)| {
            Ok(Transaction {
                ordinal: first_tx + index as u64,
                index: index as u64,
                hash: block.body().transactions[index].tx_hash().0,
                before,
                after,
                outcome,
                receipt,
                delta: delta(updates, &contracts)?,
            })
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    if let Some((cases, expected_phases)) = expected {
        eyre::ensure!(
            cases.len() == transactions.len(),
            "transaction count mismatch"
        );
        eyre::ensure!(
            expected_phases.pre == phases.pre,
            "pre-execution delta mismatch"
        );
        eyre::ensure!(
            expected_phases.post == phases.post,
            "post-execution delta mismatch"
        );
        for (case, actual) in cases.iter().zip(&transactions) {
            case.check(actual)?;
        }
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
    let boundary = TempoTransactionBoundary::decode(before)
        .ok_or_else(|| eyre::eyre!("invalid transaction boundary"))?;
    executor.restore_transaction_boundary(boundary);
    let updates = hooked(&mut executor)?;
    let tx = block
        .transactions_recovered()
        .nth(index)
        .ok_or_else(|| eyre::eyre!("transaction index out of range"))?;
    let output = executor.execute_transaction_without_commit(tx)?;
    let outcome = outcome(&output);
    executor.commit_transaction(output)?;
    let after = executor.transaction_boundary().encode().to_vec();
    let receipt = alloy_rlp::encode(
        executor
            .receipts()
            .last()
            .ok_or_else(|| eyre::eyre!("missing receipt"))?,
    );
    let state = executor.into_state();
    let delta = delta(drain(&updates), &contracts(&state))?;
    Ok(Transaction {
        ordinal,
        index: index as u64,
        hash: block.body().transactions[index].tx_hash().0,
        before: before.to_vec(),
        after,
        outcome,
        receipt,
        delta,
    })
}

/// Runs every transaction of a block standalone in one pass, carrying the state forward:
/// the state before each one is the pre phase plus every earlier transaction's checked delta.
/// `check` compares each standalone record against the block-execution record.
pub fn standalone_all(
    config: &TempoEvmConfig,
    block: &RecoveredBlock<Block>,
    mut view: View,
    phases: &Phases,
    expected: &[Transaction],
    mut check: impl FnMut(usize, &Transaction) -> eyre::Result<()>,
) -> eyre::Result<()> {
    view.apply(&phases.pre)?;
    for (index, record) in expected.iter().enumerate() {
        let actual = run_standalone(config, block, &view, record.ordinal, index, &record.before)?;
        check(index, &actual)?;
        view.apply(&record.delta)?;
    }
    Ok(())
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
    let reverts = bundle
        .reverts
        .last()
        .ok_or_else(|| eyre::eyre!("missing block reverts"))?;
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
        match &revert.account {
            AccountInfoRevert::DoNothing => eyre::ensure!(
                !accounts.contains_key(address),
                "block {number}: account {address} in changeset but revert is DoNothing"
            ),
            AccountInfoRevert::DeleteIt => {
                let info = accounts.remove(address).ok_or_else(|| {
                    eyre::eyre!("block {number}: account {address} deleted but not in changeset")
                })?;
                eyre::ensure!(
                    info.is_none(),
                    "block {number}: account {address} deleted but changeset has {info:?}"
                );
            }
            AccountInfoRevert::RevertTo(info) => {
                let changeset = accounts.remove(address).ok_or_else(|| {
                    eyre::eyre!("block {number}: account {address} reverted but not in changeset")
                })?;
                let revert = Some(Account::from(info));
                eyre::ensure!(
                    revert == changeset,
                    "block {number}: account {address} mismatch: revert={revert:?} changeset={changeset:?}"
                );
            }
        }
        let mut slots = storage.get_mut(address);
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
    Ok(())
}
