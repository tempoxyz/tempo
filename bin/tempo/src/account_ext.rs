//! Prepare a block-zero benchmark snapshot with persistent account extensions.

use std::{fs, path::PathBuf, time::Instant};

use alloy_primitives::{B256, keccak256};
use clap::Parser;
use eyre::ensure;
use reth_chainspec::EthChainSpec;
use reth_cli_commands::common::{AccessRights, EnvironmentArgs};
use reth_db_api::{
    cursor::{DbCursorRO, DbCursorRW},
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_ethereum::tasks::Runtime;
use reth_primitives_traits::AccountExtension;
use reth_provider::{
    BlockNumReader, DatabaseProviderFactory, StaticFileProviderFactory, StaticFileSegment,
    StaticFileWriter, StorageSettingsCache, TrieWriter,
};
use reth_storage_api::DBProvider;
use reth_trie::{IntermediateStateRootState, StateRootProgress};
use reth_trie_db::{
    DatabaseHashedCursorFactory, DatabaseStateRoot, DatabaseTrieCursorFactory, PackedKeyAdapter,
};
use tempo_chainspec::{TempoChainSpec, spec::TempoChainSpecParser};
use tracing::info;

#[derive(Debug, Parser)]
pub struct PrepareAccountExtensions {
    #[command(flatten)]
    env: EnvironmentArgs<TempoChainSpecParser>,

    /// Write the matching chain specification here. Must not already exist.
    #[arg(long)]
    output_genesis: PathBuf,

    /// Seed for reproducible, per-account 32-byte extensions.
    #[arg(long, default_value_t = 42)]
    seed: u64,
}

impl PrepareAccountExtensions {
    pub(crate) async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        ensure!(
            !self.output_genesis.exists(),
            "output genesis already exists"
        );
        let mut genesis = self.env.chain.genesis().clone();
        let environment = self
            .env
            .init::<tempo_node::node::TempoNode>(AccessRights::RW, runtime)?;
        let factory = environment.provider_factory;
        let mut provider = factory.database_provider_rw()?;
        ensure!(
            provider.last_block_number()? == 0,
            "snapshot must be at block zero"
        );
        ensure!(
            provider.cached_storage_settings().storage_v2,
            "snapshot must use storage v2"
        );
        provider.tx_mut().disable_long_read_transaction_safety();
        let tx = provider.tx_ref();
        let old_hash = {
            let mut cursor = tx.cursor_read::<tables::HeaderNumbers>()?;
            let (hash, number) = cursor
                .first()?
                .ok_or_else(|| eyre::eyre!("missing genesis"))?;
            ensure!(
                number == 0 && cursor.next()?.is_none(),
                "expected only a genesis header"
            );
            hash
        };

        let started = Instant::now();
        let mut accounts = 0u64;
        let mut cursor = tx.cursor_write::<tables::HashedAccounts>()?;
        let mut entry = cursor.first()?;
        while let Some((key, mut account)) = entry {
            let mut input = [0u8; 40];
            input[..8].copy_from_slice(&self.seed.to_be_bytes());
            input[8..].copy_from_slice(key.as_slice());
            // Extensions are trailing RLP fields in the account leaf, not raw payload bytes.
            account.extension =
                AccountExtension::copy_from_slice(&alloy_rlp::encode(keccak256(input)));
            cursor.upsert(key, &account)?;
            accounts += 1;
            entry = cursor.next()?;
        }
        drop(cursor);
        ensure!(accounts > 0, "snapshot has no hashed accounts");
        info!(
            accounts,
            "Filled account extensions; rebuilding account trie"
        );

        // Storage values and storage roots are unchanged. Keep their cached trie nodes.
        tx.clear::<tables::AccountsTrie>()?;
        type Root<'a, TX> = reth_trie::StateRoot<
            DatabaseTrieCursorFactory<&'a TX, PackedKeyAdapter>,
            DatabaseHashedCursorFactory<&'a TX>,
        >;
        let mut resume: Option<IntermediateStateRootState> = None;
        let mut trie_writes = 0usize;
        let root = loop {
            match Root::<_>::from_tx(tx)
                .with_intermediate_state(resume)
                .root_with_progress()?
            {
                StateRootProgress::Progress(state, _, updates) => {
                    trie_writes += provider.write_trie_updates(updates)?;
                    info!(trie_writes, elapsed = ?started.elapsed(), "Rebuilding account trie");
                    resume = Some(*state);
                }
                StateRootProgress::Complete(root, _, updates) => {
                    trie_writes += provider.write_trie_updates(updates)?;
                    break root;
                }
            }
        };
        ensure!(
            Root::<_>::from_tx(tx).root()? == root,
            "rebuilt trie root mismatch"
        );

        // Keep genesis alloc metadata in agreement for accounts represented there.
        for (address, account) in &mut genesis.alloc {
            if let Some(hashed) = tx.get::<tables::HashedAccounts>(keccak256(address))? {
                account.extension = hashed.extension;
            }
        }
        genesis
            .config
            .extra_fields
            .insert("benchmarkStateRoot".into(), serde_json::to_value(root)?);
        let spec = TempoChainSpec::from_genesis(genesis.clone());
        ensure!(
            spec.genesis_header().inner.state_root == root,
            "genesis root override failed"
        );
        let hash: B256 = spec.genesis_hash();
        let static_files = provider.static_file_provider();
        static_files.delete_segment(StaticFileSegment::Headers)?;
        {
            let mut writer = static_files.get_writer(0, StaticFileSegment::Headers)?;
            writer.append_header(spec.genesis_header(), &hash)?;
        }
        tx.delete::<tables::HeaderNumbers>(old_hash, None)?;
        tx.put::<tables::HeaderNumbers>(hash, 0)?;
        provider.commit()?;
        let verified = factory.database_provider_ro()?;
        let mut cursor = verified.tx_ref().cursor_read::<tables::HashedAccounts>()?;
        let mut count = 0;
        for entry in cursor.walk(None)? {
            let (_, account) = entry?;
            alloy_rlp::decode_exact::<B256>(&account.extension)?;
            count += 1;
        }
        ensure!(count == accounts, "persisted account count mismatch");
        ensure!(
            Root::<_>::from_tx(verified.tx_ref()).root()? == root,
            "persisted root mismatch"
        );
        fs::write(&self.output_genesis, serde_json::to_vec_pretty(&genesis)?)?;
        info!(accounts, trie_writes, state_root = %root, genesis_hash = %hash,
            elapsed = ?started.elapsed(), "Account extension snapshot complete");
        Ok(())
    }
}
