//! Capture of one block from the archive database into a self-contained corpus record.

use crate::{
    code,
    exec::{
        block::{Executed, execute_block, run_standalone, verify_changesets},
        db::{Keys, Recording, View},
    },
    types::{Block as BlockInput, Case, ChangeSet, ExtraPreState, Info, Input},
};
use alloy_consensus::BlockHeader;
use alloy_primitives::{KECCAK256_EMPTY, U256};
use evm2::evm::Database;
use reth_consensus::FullConsensus;
use reth_primitives_traits::{Account, RecoveredBlock};
use reth_storage_api::{ChangeSetReader, StorageChangeSetReader};
use std::sync::Arc;
use tempo_evm::TempoEvmConfig;
use tempo_primitives::{Block, TempoPrimitives};

/// A captured block: its stored input and verified per-transaction records.
#[derive(Debug)]
pub struct Captured {
    pub input: Arc<Input>,
    pub executed: Executed,
}

impl Captured {
    /// The stored per-transaction records.
    pub fn cases(&self) -> eyre::Result<Vec<Case>> {
        self.executed
            .transactions
            .iter()
            .map(|t| t.stored())
            .collect()
    }
}

/// Captures `block` from the archive.
///
/// Executes it through a recording database over the parent state to learn exactly what it
/// reads, then stores that pre-state, the block and its historical changesets. The capture is
/// verified before it is returned: the block's reverts match the changesets, its post-state
/// matches the canonical state after the block, it replays from the stored record alone with
/// identical outputs, and every transaction replays standalone with identical outputs.
pub fn capture<C, P, D>(
    config: &TempoEvmConfig,
    consensus: &C,
    provider: &P,
    mut db_at: impl FnMut(u64) -> eyre::Result<D>,
    block: &RecoveredBlock<Block>,
    first_tx: u64,
) -> eyre::Result<Captured>
where
    C: FullConsensus<TempoPrimitives> + ?Sized,
    P: ChangeSetReader + StorageChangeSetReader,
    D: Database,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let number = block.number();
    eyre::ensure!(number > 0, "genesis is context, not a captured block");
    let mut keys = Keys::default();
    let mut executed = execute_block(
        config,
        consensus,
        Recording {
            inner: db_at(number - 1)?,
            keys: &mut keys,
        },
        block,
        first_tx,
        None,
    )?;

    let accounts = provider.account_block_changeset(number)?;
    let storage = provider.storage_changeset(number)?;
    keys.accounts.extend(accounts.iter().map(|a| a.address));
    for (address, slot) in &storage {
        keys.accounts.insert(address.address());
        keys.storage
            .insert((address.address(), U256::from_be_bytes(slot.key.0)));
    }
    let changeset = ChangeSet {
        accounts: accounts
            .iter()
            .map(|a| (a.address.into_array(), a.info.as_ref().map(Info::capture)))
            .collect(),
        storage: storage
            .iter()
            .map(|(address, slot)| {
                (
                    (address.address().into_array(), slot.key.0),
                    slot.value.to_be_bytes(),
                )
            })
            .collect(),
    };
    eyre::ensure!(
        changeset.accounts.len() == accounts.len() && changeset.storage.len() == storage.len(),
        "duplicate changeset entries"
    );
    verify_changesets(&executed.bundle, &changeset, number)?;
    let block_input = BlockInput {
        hash: block.hash().0,
        rlp: alloy_rlp::encode(block.clone_block()),
        senders: block.senders().iter().map(|a| a.into_array()).collect(),
        changed_accounts: Vec::new(),
        changed_storage: Vec::new(),
    };

    // The execution result must equal the canonical state after the block.
    let mut canonical = db_at(number)?;
    for (address, account) in &executed.bundle.state {
        let actual = canonical.get_account(address)?;
        eyre::ensure!(
            account.info.as_ref().filter(|i| !i.is_empty())
                == actual.as_ref().filter(|i| !i.is_empty()),
            "captured account {address} disagrees with canonical poststate"
        );
        for (key, slot) in &account.storage {
            eyre::ensure!(
                canonical.get_storage(address, key)? == slot.present_value,
                "captured storage {address} {key} disagrees with canonical poststate"
            );
        }
    }

    let ExtraPreState {
        accounts,
        storage,
        code,
        hashes,
        ..
    } = pre_state(&mut db_at(number - 1)?, keys, block_input.hash)?;
    let mut input = Input {
        number,
        parent: block.parent_hash().0,
        block: block_input,
        accounts,
        storage,
        code,
        hashes,
        phases: Some(std::mem::take(&mut executed.phases)),
    };
    (input.block.changed_accounts, input.block.changed_storage) = input.mark(&changeset)?;
    eyre::ensure!(
        input.changeset()? == changeset,
        "changeset bitmap round trip mismatch"
    );
    let captured = Captured {
        input: Arc::new(input),
        executed,
    };

    // The stored record alone reproduces every output.
    let cases = captured.cases()?;
    let transactions = &captured.executed.transactions;
    let phases = captured.input.phases.as_ref().expect("set above");
    let replayed = execute_block(
        config,
        consensus,
        &View::new(captured.input.clone()),
        block,
        first_tx,
        Some((&cases, phases)),
    )?;
    eyre::ensure!(
        replayed.transactions == *transactions,
        "replay differs from capture"
    );
    // Every transaction also replays standalone, each from the state the earlier ones leave.
    let mut view = View::new(captured.input.clone());
    view.apply(&phases.pre)?;
    for (index, expected) in transactions.iter().enumerate() {
        let (actual, _) = run_standalone(
            config,
            block,
            &view,
            expected.ordinal,
            index,
            &expected.before,
            false,
        )?;
        eyre::ensure!(
            actual == *expected,
            "standalone transaction {} differs from block execution",
            expected.ordinal
        );
        view.apply(&expected.delta)?;
    }
    Ok(captured)
}

/// The values of `keys` in `db`, the state before block `hash`: accounts, with the code they hold,
/// slots, code and block hashes. Their code is cached ([`code::insert_code`]).
pub(crate) fn pre_state<D>(db: &mut D, keys: Keys, hash: [u8; 32]) -> eyre::Result<ExtraPreState>
where
    D: Database,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let mut state = ExtraPreState {
        hash,
        ..Default::default()
    };
    let mut code_hashes = keys.code;
    for address in &keys.accounts {
        let account = db.get_account(address)?;
        if let Some(account) = &account {
            code_hashes.insert(account.code_hash);
        }
        let info = account.map(|a| Info::capture(&Account::from(&a)));
        state.accounts.insert(address.into_array(), info);
    }
    for (address, key) in &keys.storage {
        state.storage.insert(
            (address.into_array(), key.to_be_bytes()),
            db.get_storage(address, key)?.to_be_bytes(),
        );
    }
    code_hashes.remove(&KECCAK256_EMPTY);
    for hash in code_hashes {
        if !code::has_code(&hash.0) {
            code::insert_code(&hash.0, &db.get_code_by_hash(&hash)?.original_bytes())?;
        }
        state.code.insert(hash.0);
    }
    for at in &keys.hashes {
        state
            .hashes
            .insert(*at, db.get_block_hash(&U256::from(*at))?.0);
    }
    Ok(state)
}
