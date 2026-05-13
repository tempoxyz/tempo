//! Generate TIP20 state bloat and load it directly into a freshly initialized
//! storage-v2 database.

use std::{sync::Arc, thread, time::Instant};

use alloy_primitives::{Address, B256, U256, keccak256, map::B256Set};
use alloy_signer::utils::secret_key_to_address;
use alloy_signer_local::coins_bip39::{English, Mnemonic};
use clap::Parser;
use coins_bip32::prelude::*;
use eyre::{Context as _, ensure};
use rayon::prelude::*;
use reth_chainspec::EthereumHardforks;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::common::{AccessRights, CliNodeTypes, EnvironmentArgs};
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO, DbDupCursorRW},
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_ethereum::{chainspec::EthChainSpec, tasks::Runtime};
use reth_primitives_traits::{Account, StorageEntry};
use reth_provider::{BlockNumReader, DatabaseProviderFactory};
use reth_storage_api::{DBProvider, StorageSettingsCache, TrieWriter};
use reth_trie::{
    BranchNodeCompact, HashBuilder, HashedPostState, Nibbles,
    updates::{StorageTrieUpdates, StorageTrieUpdatesSorted},
};
use reth_trie_db::{DatabaseStateRoot, StorageTrieEntryLike, TrieTableAdapter};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_precompiles::tip20::tip20_slots;
use tempo_primitives::transaction::TIP20_PAYMENT_PREFIX;
use tracing::info;

/// Generate TIP20 state bloat and load it directly into a freshly initialized
/// storage-v2 database.
#[derive(Debug, Parser)]
pub(crate) struct InitStateBloat<C: reth_cli::chainspec::ChainSpecParser = TempoChainSpecParser> {
    #[command(flatten)]
    env: EnvironmentArgs<C>,

    /// Mnemonic to use for account generation.
    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,

    /// Target synthetic bloat size in MiB.
    #[arg(short, long, default_value = "1024")]
    size: u64,

    /// Token IDs to generate storage for. Uses reserved TIP20 addresses:
    /// 0x20C0...{token_id}.
    #[arg(short, long, default_values_t = vec![0u64])]
    token: Vec<u64>,

    /// Balance value to assign to each generated account, in smallest units.
    #[arg(long, default_value = "1000000")]
    balance: u64,

    /// Number of addresses to derive using proper BIP32. Remaining addresses use
    /// fast keccak-based derivation and are not signable.
    #[arg(long, default_value = "10000")]
    signable_count: usize,
}

impl<C: ChainSpecParser<ChainSpec: EthChainSpec + EthereumHardforks>> InitStateBloat<C> {
    /// Execute the init-state-bloat command.
    pub(crate) async fn execute<N>(self, runtime: Runtime) -> eyre::Result<()>
    where
        N: CliNodeTypes<ChainSpec = C::ChainSpec>,
    {
        info!(target: "tempo::cli", "Tempo init-state-bloat starting");

        let environment = self.env.init::<N>(AccessRights::RW, runtime)?;
        let provider_factory = environment.provider_factory;
        let provider_ro = provider_factory
            .database_provider_ro()?
            .disable_long_read_transaction_safety();
        let provider_rw = provider_factory.database_provider_rw()?;

        let last_block = provider_rw.last_block_number()?;
        ensure!(
            last_block == 0,
            "must be run on a freshly initialized database at block 0, but found block {last_block}"
        );
        ensure!(
            provider_rw.cached_storage_settings().use_hashed_state(),
            "only supports storage v2 hashed state"
        );

        let ctx = self.context()?;
        let balance_value = U256::from(self.balance);
        let total_supply = balance_value * U256::from(ctx.accounts_per_token);
        let hashed_total_supply_slot =
            keccak256(B256::from(tip20_slots::TOTAL_SUPPLY.to_be_bytes::<32>()));

        info!(
            target: "tempo::cli",
            size_mib = self.size,
            tokens = ctx.num_tokens,
            accounts_per_token = ctx.accounts_per_token,
            signable_accounts = ctx.actual_signable,
            "Generating state bloat"
        );

        for (id, address) in ctx.token_ids.iter().zip(&ctx.token_addresses) {
            info!(target: "tempo::cli", token_id = id, %address, "Using TIP20 token address");
        }

        let slots_started = Instant::now();
        let hashed_balance_slots = generate_hashed_balance_slots(&self.mnemonic, &ctx)?;
        info!(
            target: "tempo::cli",
            slots = hashed_balance_slots.len(),
            elapsed = ?slots_started.elapsed(),
            "Generated and sorted hashed balance slots"
        );

        let targets = load_token_targets(provider_rw.tx_ref(), &ctx)?;
        let token_set: B256Set = targets.iter().map(|target| target.hashed_address).collect();
        let non_token_storage = read_non_token_hashed_storage(provider_rw.tx_ref(), &token_set)?;

        info!(
            target: "tempo::cli",
            token_storage_blocks = targets.len(),
            preserved_storage_entries = non_token_storage.len(),
            "Writing hashed storage and storage trie nodes"
        );

        let storage_write_started = Instant::now();
        let (total_token_entries, storage_trie_writes) =
            reth_trie_db::with_adapter!(provider_rw, |A| {
                write_v2_hashed_storage_and_tries::<_, _, A>(
                    provider_rw.tx_ref(),
                    provider_ro.tx_ref(),
                    &targets,
                    non_token_storage,
                    &token_set,
                    &hashed_balance_slots,
                    balance_value,
                    hashed_total_supply_slot,
                    total_supply,
                )
            })?;
        drop(provider_ro);

        for target in &targets {
            provider_rw
                .tx_ref()
                .put::<tables::HashedAccounts>(target.hashed_address, target.account)?;
        }

        info!(
            target: "tempo::cli",
            total_token_entries,
            storage_trie_writes,
            elapsed = ?storage_write_started.elapsed(),
            "Hashed storage and storage tries written"
        );

        let state_root_started = Instant::now();
        let mut post_state = HashedPostState::with_capacity(targets.len());
        for target in &targets {
            post_state
                .accounts
                .insert(target.hashed_address, Some(target.account));
        }
        let post_state = post_state.into_sorted();

        let (state_root, account_updates) = reth_trie_db::with_adapter!(provider_rw, |A| {
            use reth_trie_db::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};
            type DbStateRoot<'a, TX, Adapter> = reth_trie::StateRoot<
                DatabaseTrieCursorFactory<&'a TX, Adapter>,
                DatabaseHashedCursorFactory<&'a TX>,
            >;

            <DbStateRoot<'_, _, A> as DatabaseStateRoot<_>>::overlay_root_with_updates(
                provider_rw.tx_ref(),
                &post_state,
            )?
        });
        let account_trie_writes = provider_rw.write_trie_updates(account_updates)?;

        info!(
            target: "tempo::cli",
            %state_root,
            account_trie_writes,
            elapsed = ?state_root_started.elapsed(),
            "State root computed from storage-v2 bloat"
        );

        provider_rw.commit()?;

        info!(
            target: "tempo::cli",
            total_blocks = ctx.num_tokens,
            total_entries = total_token_entries,
            %state_root,
            "Generated state bloat loaded successfully"
        );

        Ok(())
    }

    fn context(&self) -> eyre::Result<GeneratedStateBloatContext> {
        ensure!(
            !self.token.is_empty(),
            "at least one token ID must be specified"
        );
        ensure!(self.size > 0, "size must be greater than 0");
        ensure!(self.balance > 0, "balance must be greater than 0");

        let mut unique_tokens = self.token.clone();
        unique_tokens.sort_unstable();
        unique_tokens.dedup();
        let num_tokens = self.token.len() as u64;
        ensure!(
            unique_tokens.len() as u64 == num_tokens,
            "token IDs must be unique"
        );

        let target_bytes = self
            .size
            .checked_mul(1024 * 1024)
            .ok_or_else(|| eyre::eyre!("target size overflows u64"))?;

        // Keep a small per-token metadata allowance so the generated payload stays
        // just under the requested target size.
        let metadata_size = 40u64;
        let entry_size = 64u64;
        let overhead_per_token = metadata_size + entry_size;
        let available_for_balances = target_bytes.saturating_sub(num_tokens * overhead_per_token);
        let total_balance_entries = available_for_balances / entry_size;
        let accounts_per_token = total_balance_entries / num_tokens;
        ensure!(
            accounts_per_token > 0,
            "target size too small for the number of tokens"
        );

        let total_accounts = usize::try_from(accounts_per_token)
            .wrap_err("target size produces too many accounts for this platform")?;
        let actual_signable = self
            .signable_count
            .min(total_accounts)
            .min(u32::MAX as usize);
        let token_addresses: Vec<Address> =
            self.token.iter().map(|&id| token_address(id)).collect();

        Ok(GeneratedStateBloatContext {
            num_tokens,
            accounts_per_token,
            total_accounts,
            actual_signable,
            token_ids: self.token.clone(),
            token_addresses,
        })
    }
}

struct GeneratedStateBloatContext {
    num_tokens: u64,
    accounts_per_token: u64,
    total_accounts: usize,
    actual_signable: usize,
    token_ids: Vec<u64>,
    token_addresses: Vec<Address>,
}

struct TokenTarget {
    id: u64,
    address: Address,
    hashed_address: B256,
    account: Account,
    existing_storage: Vec<StorageEntry>,
}

struct StorageTrieRow {
    hashed_address: B256,
    nibbles: Nibbles,
    node: BranchNodeCompact,
}

struct PreservedStorageTrieRows<'a> {
    token_set: &'a B256Set,
    next: Option<StorageTrieRow>,
}

#[derive(Clone, Copy)]
enum StorageTrieCursorStep {
    First,
    Next,
}

fn generate_hashed_balance_slots(
    mnemonic: &str,
    sizing: &GeneratedStateBloatContext,
) -> eyre::Result<Vec<B256>> {
    let parent_key = Arc::new(derive_parent_key(mnemonic)?);
    let seed = keccak256(mnemonic.as_bytes());

    let mut slots: Vec<B256> = (0..sizing.total_accounts)
        .into_par_iter()
        .map(|index| {
            let address = if index < sizing.actual_signable {
                derive_signable_address(&parent_key, index as u32)
            } else {
                derive_address_fast(&seed, index as u64)
            };
            let slot = B256::from(
                compute_mapping_slot(address, tip20_slots::BALANCES).to_be_bytes::<32>(),
            );
            keccak256(slot)
        })
        .collect();

    slots.par_sort_unstable();
    slots.dedup();
    Ok(slots)
}

fn load_token_targets<TX: DbTx + DbTxMut>(
    tx: &TX,
    sizing: &GeneratedStateBloatContext,
) -> eyre::Result<Vec<TokenTarget>> {
    let mut targets = Vec::with_capacity(sizing.token_addresses.len());
    for (&id, &address) in sizing.token_ids.iter().zip(&sizing.token_addresses) {
        let hashed_address = keccak256(address);
        let account = tx
            .get::<tables::HashedAccounts>(hashed_address)?
            .unwrap_or_default();
        let mut existing_storage = read_hashed_storage_for_address(tx, hashed_address)?;
        existing_storage.sort_unstable_by_key(|entry| entry.key);
        targets.push(TokenTarget {
            id,
            address,
            hashed_address,
            account,
            existing_storage,
        });
    }
    targets.sort_unstable_by_key(|target| target.hashed_address);
    Ok(targets)
}

fn read_hashed_storage_for_address<TX: DbTx>(
    tx: &TX,
    hashed_address: B256,
) -> eyre::Result<Vec<StorageEntry>> {
    let mut cursor = tx.cursor_dup_read::<tables::HashedStorages>()?;
    let mut entries = Vec::new();
    for row in cursor.walk_dup(Some(hashed_address), None)? {
        let (_, entry) = row?;
        entries.push(entry);
    }
    Ok(entries)
}

fn read_non_token_hashed_storage<TX: DbTx>(
    tx: &TX,
    token_set: &B256Set,
) -> eyre::Result<Vec<(B256, StorageEntry)>> {
    let mut cursor = tx.cursor_read::<tables::HashedStorages>()?;
    let mut entries = Vec::new();
    for row in cursor.walk(None)? {
        let (hashed_address, entry) = row?;
        if !token_set.contains(&hashed_address) {
            entries.push((hashed_address, entry));
        }
    }
    Ok(entries)
}

fn write_v2_hashed_storage_and_tries<TX, SourceTX, A>(
    tx: &TX,
    storage_trie_source_tx: &SourceTX,
    targets: &[TokenTarget],
    non_token_storage: Vec<(B256, StorageEntry)>,
    token_set: &B256Set,
    hashed_balance_slots: &[B256],
    balance_value: U256,
    hashed_total_supply_slot: B256,
    total_supply: U256,
) -> eyre::Result<(u64, usize)>
where
    TX: DbTx + DbTxMut,
    SourceTX: DbTx,
    A: TrieTableAdapter,
{
    let mut preserved_trie_cursor = storage_trie_source_tx.cursor_read::<A::StorageTrieTable>()?;
    let mut preserved_trie =
        read_non_token_storage_trie_rows::<A, _>(&mut preserved_trie_cursor, token_set)?;

    tx.clear::<tables::HashedStorages>()?;
    tx.clear::<A::StorageTrieTable>()?;

    let mut hashed_cursor = tx.cursor_dup_write::<tables::HashedStorages>()?;
    let mut trie_cursor = tx.cursor_dup_write::<A::StorageTrieTable>()?;
    let mut non_token_iter = non_token_storage.into_iter().peekable();
    let mut total_token_entries = 0u64;
    let mut storage_trie_writes = 0usize;

    for target in targets {
        while let Some((hashed_address, _)) = non_token_iter.peek()
            && *hashed_address < target.hashed_address
        {
            let (hashed_address, entry) = non_token_iter
                .next()
                .expect("peeked non-token storage entry exists");
            hashed_cursor.append_dup(hashed_address, entry)?;
        }

        storage_trie_writes += append_preserved_storage_trie_rows::<A, _, _>(
            &mut trie_cursor,
            &mut preserved_trie_cursor,
            &mut preserved_trie,
            Some(target.hashed_address),
        )?;

        let token_started = Instant::now();
        let (((storage_root, updates, trie_entries), trie_elapsed), entries, append_elapsed) =
            thread::scope(|scope| -> eyre::Result<_> {
                let trie_handle = scope.spawn(|| {
                    let started = Instant::now();
                    let result = build_token_storage_trie_v2(
                        &target.existing_storage,
                        hashed_balance_slots,
                        balance_value,
                        hashed_total_supply_slot,
                        total_supply,
                    );
                    result.map(|value| (value, started.elapsed()))
                });

                let append_started = Instant::now();
                let entries = append_token_storage_entries_v2(
                    &mut hashed_cursor,
                    target.hashed_address,
                    &target.existing_storage,
                    hashed_balance_slots,
                    balance_value,
                    hashed_total_supply_slot,
                    total_supply,
                )?;
                let append_elapsed = append_started.elapsed();
                let trie_result = trie_handle
                    .join()
                    .map_err(|_| eyre::eyre!("storage trie worker panicked"))??;

                Ok((trie_result, entries, append_elapsed))
            })?;
        ensure!(
            entries == trie_entries,
            "storage trie entry count mismatch: wrote {entries}, trie saw {trie_entries}"
        );
        total_token_entries += entries;
        storage_trie_writes += append_token_storage_trie_updates::<A, _>(
            &mut trie_cursor,
            target.hashed_address,
            &updates,
        )?;

        info!(
            target: "tempo::cli",
            token_id = target.id,
            address = %target.address,
            hashed_address = %target.hashed_address,
            entries,
            storage_root = %storage_root,
            append_elapsed = ?append_elapsed,
            trie_elapsed = ?trie_elapsed,
            elapsed = ?token_started.elapsed(),
            "Token storage written"
        );
    }

    for (hashed_address, entry) in non_token_iter {
        hashed_cursor.append_dup(hashed_address, entry)?;
    }
    storage_trie_writes += append_preserved_storage_trie_rows::<A, _, _>(
        &mut trie_cursor,
        &mut preserved_trie_cursor,
        &mut preserved_trie,
        None,
    )?;

    Ok((total_token_entries, storage_trie_writes))
}

fn read_non_token_storage_trie_rows<'a, A, C>(
    cursor: &mut C,
    token_set: &'a B256Set,
) -> eyre::Result<PreservedStorageTrieRows<'a>>
where
    A: TrieTableAdapter,
    C: DbCursorRO<A::StorageTrieTable>,
{
    Ok(PreservedStorageTrieRows {
        token_set,
        next: next_non_token_storage_trie_row::<A, _>(
            cursor,
            token_set,
            StorageTrieCursorStep::First,
        )?,
    })
}

fn next_non_token_storage_trie_row<A, C>(
    cursor: &mut C,
    token_set: &B256Set,
    mut step: StorageTrieCursorStep,
) -> eyre::Result<Option<StorageTrieRow>>
where
    A: TrieTableAdapter,
    C: DbCursorRO<A::StorageTrieTable>,
{
    loop {
        let row = match step {
            StorageTrieCursorStep::First => cursor.first()?,
            StorageTrieCursorStep::Next => cursor.next()?,
        };
        step = StorageTrieCursorStep::Next;

        let Some((hashed_address, value)) = row else {
            return Ok(None);
        };
        if token_set.contains(&hashed_address) {
            continue;
        }

        let (subkey, node) = value.into_parts();
        return Ok(Some(StorageTrieRow {
            hashed_address,
            nibbles: A::subkey_to_nibbles(&subkey),
            node,
        }));
    }
}

fn append_preserved_storage_trie_rows<A, SourceC, DestC>(
    destination: &mut DestC,
    source: &mut SourceC,
    preserved: &mut PreservedStorageTrieRows<'_>,
    before_hashed_address: Option<B256>,
) -> eyre::Result<usize>
where
    A: TrieTableAdapter,
    SourceC: DbCursorRO<A::StorageTrieTable>,
    DestC: DbDupCursorRW<A::StorageTrieTable>,
{
    let mut writes = 0usize;
    loop {
        let should_append = match (&preserved.next, before_hashed_address) {
            (Some(row), Some(before)) => row.hashed_address < before,
            (Some(_), None) => true,
            (None, _) => false,
        };
        if !should_append {
            break;
        }

        let row = preserved
            .next
            .take()
            .expect("checked preserved trie row exists");
        append_storage_trie_row::<A, _>(destination, row)?;
        writes += 1;
        preserved.next = next_non_token_storage_trie_row::<A, _>(
            source,
            preserved.token_set,
            StorageTrieCursorStep::Next,
        )?;
    }
    Ok(writes)
}

fn append_token_storage_trie_updates<A, C>(
    cursor: &mut C,
    hashed_address: B256,
    updates: &StorageTrieUpdatesSorted,
) -> eyre::Result<usize>
where
    A: TrieTableAdapter,
    C: DbDupCursorRW<A::StorageTrieTable>,
{
    let mut writes = 0usize;
    for (nibbles, maybe_node) in updates.storage_nodes_ref() {
        let Some(node) = maybe_node else {
            continue;
        };
        if nibbles.is_empty() {
            continue;
        }
        append_storage_trie_row::<A, _>(
            cursor,
            StorageTrieRow {
                hashed_address,
                nibbles: *nibbles,
                node: node.clone(),
            },
        )?;
        writes += 1;
    }
    Ok(writes)
}

fn append_storage_trie_row<A, C>(cursor: &mut C, row: StorageTrieRow) -> eyre::Result<()>
where
    A: TrieTableAdapter,
    C: DbDupCursorRW<A::StorageTrieTable>,
{
    cursor.append_dup(
        row.hashed_address,
        A::StorageValue::new(A::StorageSubKey::from(row.nibbles), row.node),
    )?;
    Ok(())
}

fn append_token_storage_entries_v2<C>(
    cursor: &mut C,
    hashed_address: B256,
    existing_storage: &[StorageEntry],
    hashed_balance_slots: &[B256],
    balance_value: U256,
    hashed_total_supply_slot: B256,
    total_supply: U256,
) -> eyre::Result<u64>
where
    C: DbDupCursorRW<tables::HashedStorages>,
{
    for_each_token_storage_entry(
        existing_storage,
        hashed_balance_slots,
        balance_value,
        hashed_total_supply_slot,
        total_supply,
        |key, value| {
            cursor.append_dup(hashed_address, StorageEntry { key, value })?;
            Ok(())
        },
    )
}

fn build_token_storage_trie_v2(
    existing_storage: &[StorageEntry],
    hashed_balance_slots: &[B256],
    balance_value: U256,
    hashed_total_supply_slot: B256,
    total_supply: U256,
) -> eyre::Result<(B256, StorageTrieUpdatesSorted, u64)> {
    let balance_rlp = alloy_rlp::encode_fixed_size(&balance_value);
    let mut hash_builder = HashBuilder::default().with_updates(true);

    let entries = for_each_token_storage_entry(
        existing_storage,
        hashed_balance_slots,
        balance_value,
        hashed_total_supply_slot,
        total_supply,
        |key, value| {
            if value == balance_value {
                hash_builder
                    .add_leaf_unchecked(Nibbles::unpack_array(&key.0), balance_rlp.as_ref());
            } else {
                let encoded = alloy_rlp::encode_fixed_size(&value);
                hash_builder.add_leaf_unchecked(Nibbles::unpack_array(&key.0), encoded.as_ref());
            }
            Ok(())
        },
    )?;

    let storage_root = hash_builder.root();
    let mut updates = StorageTrieUpdates::deleted();
    updates.finalize(hash_builder, Default::default());
    Ok((storage_root, updates.into_sorted(), entries))
}

fn for_each_token_storage_entry(
    existing_storage: &[StorageEntry],
    hashed_balance_slots: &[B256],
    balance_value: U256,
    hashed_total_supply_slot: B256,
    total_supply: U256,
    mut f: impl FnMut(B256, U256) -> eyre::Result<()>,
) -> eyre::Result<u64> {
    let extras =
        token_extra_storage_entries(existing_storage, hashed_total_supply_slot, total_supply);
    let mut extra_index = 0usize;
    let mut entries = 0u64;

    for &slot in hashed_balance_slots {
        while let Some(extra) = extras.get(extra_index).copied()
            && extra.key < slot
        {
            if !extra.value.is_zero() {
                f(extra.key, extra.value)?;
                entries += 1;
            }
            extra_index += 1;
        }

        if let Some(extra) = extras.get(extra_index).copied()
            && extra.key == slot
        {
            if !extra.value.is_zero() {
                f(slot, extra.value)?;
                entries += 1;
            }
            extra_index += 1;
        } else {
            f(slot, balance_value)?;
            entries += 1;
        }
    }

    for extra in &extras[extra_index..] {
        if !extra.value.is_zero() {
            f(extra.key, extra.value)?;
            entries += 1;
        }
    }

    Ok(entries)
}

fn token_extra_storage_entries(
    existing_storage: &[StorageEntry],
    hashed_total_supply_slot: B256,
    total_supply: U256,
) -> Vec<StorageEntry> {
    let mut extras: Vec<StorageEntry> = Vec::with_capacity(existing_storage.len() + 1);
    for &entry in existing_storage {
        if let Some(last) = extras.last_mut()
            && last.key == entry.key
        {
            last.value = entry.value;
            continue;
        }
        extras.push(entry);
    }

    match extras.binary_search_by_key(&hashed_total_supply_slot, |entry| entry.key) {
        Ok(_) => {}
        Err(index) => extras.insert(
            index,
            StorageEntry {
                key: hashed_total_supply_slot,
                value: total_supply,
            },
        ),
    }

    extras
}

/// Compute a reserved TIP20 token address from a token ID.
fn token_address(token_id: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..12].copy_from_slice(&TIP20_PAYMENT_PREFIX);
    bytes[12..].copy_from_slice(&token_id.to_be_bytes());
    Address::from(bytes)
}

/// Fast address derivation using keccak256(seed || index).
fn derive_address_fast(seed: &B256, index: u64) -> Address {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(seed.as_slice());
    buf[32..].copy_from_slice(&index.to_be_bytes());
    let hash = keccak256(buf);
    Address::from_slice(&hash[12..])
}

fn derive_signable_address(parent_key: &XPriv, index: u32) -> Address {
    let child = parent_key
        .derive_child(index)
        .expect("child derivation should not fail");
    let key: &coins_bip32::prelude::SigningKey = child.as_ref();
    secret_key_to_address(key)
}

/// Derive the parent key for BIP44 Ethereum path: `m/44'/60'/0'/0`.
fn derive_parent_key(mnemonic_phrase: &str) -> eyre::Result<XPriv> {
    let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic_phrase)
        .map_err(|e| eyre::eyre!("invalid mnemonic: {e}"))?;
    mnemonic
        .derive_key("m/44'/60'/0'/0", None)
        .map_err(|e| eyre::eyre!("key derivation failed: {e}"))
}

/// Compute a Solidity mapping slot: `keccak256(pad32(key) || pad32(base_slot))`.
fn compute_mapping_slot(key: Address, base_slot: U256) -> U256 {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(key.as_slice());
    buf[32..].copy_from_slice(&base_slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}
