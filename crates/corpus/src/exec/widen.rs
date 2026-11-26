//! Extra pre-state for inputs derived from corpus blocks, read from the archive.

use crate::{
    code,
    exec::{capture, db::Keys},
    fuzz,
    store::{self, MAX_RECORD_BYTES, Store, WINCODE},
    types::ExtraPreState,
};
use alloy_primitives::B256;
use bincode::Options as _;
use eyre::{OptionExt, WrapErr};
use reth_evm::database::StateProviderDatabase;
use reth_provider::{
    BlockHashReader, DatabaseProviderFactory, ProviderFactory,
    providers::{BlockchainProvider, ProviderNodeTypes},
};
use reth_storage_api::{DBProvider, StateProvider};
use slatedb::{Db, WriteBatch, config::Settings};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use tempo_fuzz_engine::{MissingPreState, Tempo, ffi};
use tempo_fuzz_types::{PreState, TempoHarnessInput};
use tempo_primitives::TempoPrimitives;
use tracing::info;

/// Inputs and options of a widen.
#[derive(Debug, Clone)]
pub struct WidenArgs {
    /// Directory of the inputs derived from each block, `<inputs>/<block>/<name>.bin`, each a
    /// [`TempoHarnessInput`] in the harness's encoding ([`ffi::bincode_options`]).
    pub inputs: PathBuf,
    /// Most rounds per block.
    pub rounds: usize,
    /// Worker threads.
    pub workers: usize,
}

/// Runs the inputs derived from each block on its exact pre-state, reads every key they read that
/// it does not hold from the archive state before the block, and repeats with those keys added
/// until no input reads a new one or for `rounds`. Stores what it found as the block's
/// [`ExtraPreState`], merged with the one stored before.
///
/// Blocking: run it on a blocking thread.
pub fn widen<N>(
    provider_factory: ProviderFactory<N>,
    store: Store,
    args: WidenArgs,
) -> eyre::Result<()>
where
    N: ProviderNodeTypes<Primitives = TempoPrimitives>,
{
    eyre::ensure!(
        ffi::enable_mock_crypto() != 0,
        "mock signatures did not turn on"
    );
    let mut blocks = fs::read_dir(&args.inputs)?
        .map(|entry| {
            let path = entry?.path();
            let block = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.parse().ok())
                .ok_or_else(|| eyre::eyre!("{} does not name a block", path.display()))?;
            eyre::Ok((block, path))
        })
        .collect::<eyre::Result<Vec<(u64, PathBuf)>>>()?;
    blocks.sort_unstable();
    if let Some(pair) = blocks.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        eyre::bail!(
            "{} and {} name the same block",
            pair[0].1.display(),
            pair[1].1.display()
        );
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (mut catalog, _) = runtime
        .block_on(store.catalog())?
        .ok_or_eyre("no corpus catalog")?;
    // A lease of our own, as replay takes: a fill extending the corpus retires the published
    // checkpoint with a grace lifetime a long widen can outlast.
    let lease = store.lease_published(&runtime, &mut catalog, || {})?;
    let reader = runtime.block_on(store.reader(&catalog))?;
    // Readers follow the extra store without a checkpoint, so widening never collects garbage.
    let extra = runtime.block_on(
        Db::builder(store.extra(), store.objects.clone())
            .with_settings(Settings {
                object_store_max_retries: store::SLATEDB_RETRIES,
                garbage_collector_options: None,
                ..Default::default()
            })
            .build(),
    )?;
    let state = BlockchainProvider::new(provider_factory.clone())?;
    let widen_block = |block: u64, dir: &PathBuf| -> eyre::Result<()> {
        eyre::ensure!(
            !lease.expiring(),
            "widen lease expires before it can be renewed"
        );
        let mut inputs = Vec::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "bin") {
                let input = ffi::bincode_options()
                    .deserialize::<TempoHarnessInput>(&fs::read(&path)?)
                    .wrap_err_with(|| format!("{} is not a harness input", path.display()))?;
                // Only an input on the block's exact pre-state can read past it.
                if let TempoHarnessInput::Blockchain(input) = input
                    && matches!(input.pre_state, PreState::Exact { .. })
                {
                    inputs.push(input);
                }
            }
        }
        let (_, base) = runtime.block_on(store::published(&reader, block))?;
        let mut found = runtime
            .block_on(store::extra_pre_state(Some(&extra), block))?
            .unwrap_or_else(|| ExtraPreState {
                hash: base.block.hash,
                ..Default::default()
            });
        let provider = provider_factory
            .database_provider_ro()?
            .disable_long_read_transaction_safety();
        eyre::ensure!(
            provider.block_hash(block)? == Some(B256::from(base.block.hash)),
            "the archive's block {block} is not the corpus's"
        );
        let mut db = StateProviderDatabase(
            state
                .state_provider_from_database(provider, base.parent.into())?
                .into_evm_state_provider(),
        );
        let size = |found: &ExtraPreState| {
            found.accounts.len() + found.storage.len() + found.code.len() + found.hashes.len()
        };
        let (before, stored_code) = (size(&found), found.code.clone());
        let (mut rounds, mut executions) = (0, 0);
        while rounds < args.rounds && !inputs.is_empty() {
            rounds += 1;
            executions += inputs.len();
            let pre_state = fuzz::pre_state(&base, Some(&found))?;
            let seeded = tempo_fuzz_engine::seed(&Tempo, &pre_state)
                .map_err(|class| eyre::eyre!("pre-state does not seed: {class:?}"))?;
            // The inputs run across the workers on the pre-state seeded once. One that missed
            // nothing read only real values, which added keys do not change, so it is done.
            let next = AtomicUsize::new(0);
            let missed = std::thread::scope(|scope| {
                let workers: Vec<_> = (0..args.workers)
                    .map(|_| {
                        scope.spawn(|| {
                            let mut missed = Vec::new();
                            let mut i = next.fetch_add(1, Ordering::Relaxed);
                            while let Some(input) = inputs.get(i) {
                                let mut input = input.clone();
                                input.pre_state = pre_state.clone();
                                let input = TempoHarnessInput::Blockchain(input);
                                // The hash of the block itself or a later one is not pre-block
                                // state: an input executing several blocks makes those itself.
                                let (_, mut misses) =
                                    tempo_fuzz_engine::run_collecting_on(&Tempo, &seeded, input);
                                misses.retain(|missing| {
                                    !matches!(missing, MissingPreState::BlockHash(n) if *n >= block)
                                });
                                missed.push((i, misses));
                                i = next.fetch_add(1, Ordering::Relaxed);
                            }
                            missed
                        })
                    })
                    .collect();
                // Every worker is joined before an error returns, so a second panic does not
                // reach the scope.
                let joined: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
                joined.into_iter().try_fold(Vec::new(), |mut all, missed| {
                    let missed =
                        missed.map_err(|_| eyre::eyre!("an input panicked the harness"))?;
                    all.extend(missed.into_iter().filter(|(_, missed)| !missed.is_empty()));
                    eyre::Ok(all)
                })
            })?;
            let mut keys = Keys::default();
            for missing in missed.iter().flat_map(|(_, missed)| missed) {
                match *missing {
                    MissingPreState::Account(address) => keys.accounts.insert(address),
                    MissingPreState::Storage(address, slot) => keys.storage.insert((address, slot)),
                    MissingPreState::Code(hash) => keys.code.insert(hash),
                    MissingPreState::BlockHash(number) => keys.hashes.insert(number),
                };
            }
            inputs = missed.into_iter().map(|(i, _)| inputs[i].clone()).collect();
            // Every miss is a key the pre-state does not hold yet.
            if keys.accounts.is_empty()
                && keys.storage.is_empty()
                && keys.code.is_empty()
                && keys.hashes.is_empty()
            {
                break;
            }
            let read = capture::pre_state(&mut db, keys, base.block.hash)?;
            found.accounts.extend(read.accounts);
            found.storage.extend(read.storage);
            found.hashes.extend(read.hashes);
            found.code.extend(
                read.code
                    .into_iter()
                    .filter(|hash| !base.code.contains(hash)),
            );
        }
        let added = size(&found) - before;
        info!(
            block,
            rounds,
            executions,
            added,
            accounts = found.accounts.len(),
            storage = found.storage.len(),
            code = found.code.len(),
            hashes = found.hashes.len(),
            "Widened block pre-state"
        );
        if added == 0 {
            return Ok(());
        }
        let bytes = wincode::config::serialize(&found, WINCODE)?;
        eyre::ensure!(
            bytes.len() <= MAX_RECORD_BYTES,
            "extra pre-state of block {block} exceeds the record limit"
        );
        let mut batch = WriteBatch::new();
        // Code an earlier widen stored for the block is already in the store.
        for hash in found.code.difference(&stored_code) {
            let bytes = code::code_bytes(hash).ok_or_eyre("read code missing from cache")?;
            batch.put(store::code_key(hash), bytes);
        }
        batch.put(store::key(block), bytes);
        runtime.block_on(extra.write(batch))?;
        Ok(())
    };
    // Blocks go one at a time: each round's inputs already use every worker.
    let widened = blocks.iter().try_for_each(|(block, dir)| {
        widen_block(*block, dir).wrap_err_with(|| format!("widening block {block}"))
    });
    let closed = runtime.block_on(extra.close()).map_err(Into::into);
    let released = lease.release(&runtime, &store);
    widened.and(closed).and(released)
}
