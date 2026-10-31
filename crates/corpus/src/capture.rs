//! Capture of one block from the archive database into a self-contained corpus record.

use crate::{
    code,
    execute::{Executed, execute_block, standalone_all, verify_changesets},
    types::{Block as BlockInput, Case, ChangeSet, Chunk, Info},
    view::{Keys, Recording, View},
};
use alloy_consensus::BlockHeader;
use alloy_primitives::{KECCAK256_EMPTY, U256};
use evm2::evm::Database;
use parking_lot::Mutex;
use reth_consensus::FullConsensus;
use reth_primitives_traits::{Account, RecoveredBlock};
use reth_storage_api::{ChangeSetReader, StorageChangeSetReader};
use std::{collections::BTreeMap, sync::Arc};
use tempo_evm::TempoEvmConfig;
use tempo_primitives::{Block, TempoPrimitives};

/// A captured block: its stored input and verified per-transaction records.
#[derive(Debug)]
pub struct Captured {
    pub chunk: Arc<Chunk>,
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

fn info(account: Option<evm2::evm::AccountInfo>) -> eyre::Result<Option<Info>> {
    account
        .map(|a| Info::capture(&Account::from(&a)))
        .transpose()
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
    let keys = Arc::new(Mutex::new(Keys::default()));
    let executed = execute_block(
        config,
        consensus,
        Recording {
            inner: db_at(number - 1)?,
            keys: keys.clone(),
        },
        block,
        first_tx,
        None,
    )?;

    let accounts = provider.account_block_changeset(number)?;
    let storage = provider.storage_changeset(number)?;
    {
        let mut keys = keys.lock();
        keys.accounts.extend(accounts.iter().map(|a| a.address));
        for (address, slot) in &storage {
            keys.accounts.insert(address.address());
            keys.storage
                .insert((address.address(), U256::from_be_bytes(slot.key.0)));
        }
    }
    let changeset = ChangeSet {
        accounts: accounts
            .iter()
            .map(|a| {
                Ok((
                    a.address.into_array(),
                    a.info.as_ref().map(Info::capture).transpose()?,
                ))
            })
            .collect::<eyre::Result<_>>()?,
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
    let input = BlockInput {
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

    let keys = keys.lock();
    let mut initial = db_at(number - 1)?;
    let mut chunk = Chunk {
        start: number,
        end: number + 1,
        parent: block.parent_hash().0,
        blocks: vec![input],
        accounts: BTreeMap::new(),
        storage: BTreeMap::new(),
        code: Default::default(),
        hashes: BTreeMap::new(),
        phases: Some(Default::default()),
    };
    let mut code_hashes = keys.code.clone();
    for address in &keys.accounts {
        let account = initial.get_account(address)?;
        if let Some(account) = &account {
            code_hashes.insert(account.code_hash);
        }
        chunk
            .accounts
            .insert(address.into_array(), vec![(number - 1, info(account)?)]);
    }
    for (address, key) in &keys.storage {
        chunk.storage.insert(
            (address.into_array(), key.to_be_bytes()),
            vec![(number - 1, initial.get_storage(address, key)?.to_be_bytes())],
        );
    }
    for hash in code_hashes {
        if hash == KECCAK256_EMPTY {
            continue;
        }
        if !code::has_code(&hash.0) {
            code::insert_code(&hash.0, &initial.get_code_by_hash(&hash)?.original_bytes())?;
        }
        chunk.code.insert(hash.0);
    }
    for at in &keys.hashes {
        chunk
            .hashes
            .insert(*at, initial.get_block_hash(&U256::from(*at))?.0);
    }
    drop(keys);
    let (changed_accounts, changed_storage) = chunk.mark(&changeset)?;
    chunk.blocks[0].changed_accounts = changed_accounts;
    chunk.blocks[0].changed_storage = changed_storage;
    eyre::ensure!(
        chunk.changeset()? == changeset,
        "changeset bitmap round trip mismatch"
    );
    let Executed {
        transactions,
        phases,
        bundle,
        gas,
    } = executed;
    chunk.phases = Some(phases);
    chunk.validate()?;
    let chunk = Arc::new(chunk);

    // The stored record alone reproduces every output.
    let cases = transactions
        .iter()
        .map(|t| t.stored())
        .collect::<eyre::Result<Vec<_>>>()?;
    let phases = chunk.phases.as_ref().expect("set above");
    let replayed = execute_block(
        config,
        consensus,
        View::new(chunk.clone()),
        block,
        first_tx,
        Some((&cases, phases)),
    )?;
    eyre::ensure!(
        replayed.transactions == transactions,
        "replay differs from capture"
    );
    standalone_all(
        config,
        block,
        View::new(chunk.clone()),
        phases,
        &transactions,
        |index, actual| {
            eyre::ensure!(
                *actual == transactions[index],
                "standalone transaction {} differs from block execution",
                transactions[index].ordinal
            );
            Ok(())
        },
    )?;
    Ok(Captured {
        chunk,
        executed: Executed {
            transactions,
            phases: Default::default(),
            bundle,
            gas,
        },
    })
}
