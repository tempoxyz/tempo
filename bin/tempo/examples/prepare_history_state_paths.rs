//! Add the history router and unique code corpus to a COPY of a block-zero fixture.
//! Never run this on a live node or a preserved `.virgin` snapshot.
use std::{fs, path::PathBuf, time::Instant};

use alloy_primitives::{Address, B256, Bytes, address, keccak256};
use clap::Parser;
use eyre::{OptionExt, ensure};
use reth_chainspec::EthChainSpec;
use reth_cli_commands::common::{AccessRights, EnvironmentArgs};
use reth_db_api::{
    models::{AccountBeforeTx, ShardedKey},
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_ethereum::tasks::{RuntimeBuilder, RuntimeConfig};
use reth_primitives_traits::{Account, Bytecode};
use reth_provider::{
    BlockNumReader, ChangeSetReader, DBProvider, DatabaseProviderFactory, RocksDBProviderFactory,
    StaticFileProviderFactory, StaticFileSegment, StorageSettingsCache, TrieWriter,
};
use reth_trie::{
    Nibbles, StateRootProgress,
    prefix_set::{PrefixSet, TriePrefixSets, TriePrefixSetsMut},
};
use reth_trie_db::{
    DatabaseHashedCursorFactory, DatabaseStateRoot, DatabaseTrieCursorFactory, PackedKeyAdapter,
};
use tempo_chainspec::spec::TempoChainSpecParser;

const ROUTER: Address = address!("535441544541434345535342454e434800000000");
const CODE_BYTES: usize = 24_576;
const BATCH: u64 = 4096;

#[derive(Parser)]
struct Args {
    #[command(flatten)]
    env: EnvironmentArgs<TempoChainSpecParser>,
    #[arg(long, default_value_t = 4_266_667)]
    code_count: u64,
    #[arg(long)]
    router_artifact: PathBuf,
    /// Replace only the router in an existing, offline, block-zero history fixture.
    #[arg(long)]
    replace_router: bool,
}

fn code_address(index: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = 0x60;
    bytes[12..].copy_from_slice(&index.to_be_bytes());
    Address::from(bytes)
}

fn code_body(index: u64) -> Bytes {
    let mut code = vec![0u8; CODE_BYTES];
    // STOP followed by unreachable deterministic data: distinct hashes without
    // executing the padding, and no compressible zero-filled corpus.
    blake3::Hasher::new()
        .update(&index.to_be_bytes())
        .finalize_xof()
        .fill(&mut code[1..]);
    Bytes::from(code)
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    ensure!(
        (1024..=8_000_000).contains(&args.code_count),
        "invalid code count"
    );
    ensure!(
        args.env.chain.chain().id() == 1337,
        "local chain 1337 required"
    );
    let dir = args
        .env
        .datadir
        .clone()
        .resolve_datadir(args.env.chain.chain())
        .data_dir()
        .to_path_buf();
    let name = dir
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_eyre("invalid fixture path")?;
    ensure!(
        name.contains("history_paths") && !name.ends_with(".virgin"),
        "use a dedicated history_paths scratch directory"
    );
    ensure!(
        dir.join("db/mdbx.dat").is_file(),
        "existing database required"
    );
    let marker = dir.join(".bench-meta/history-state-paths.json");
    let incomplete = dir.join(".bench-meta/history-state-paths.incomplete");
    ensure!(
        (marker.exists() == args.replace_router) && !incomplete.exists(),
        "fixture already prepared or incomplete; use a fresh copy"
    );
    let artifact: serde_json::Value = serde_json::from_slice(&fs::read(&args.router_artifact)?)?;
    let router = Bytecode::new_raw_checked(
        artifact["deployedBytecode"]["object"]
            .as_str()
            .ok_or_eyre("missing router bytecode")?
            .parse()?,
    )?;
    let router_hash = router.hash_slow();
    let runtime = RuntimeBuilder::new(RuntimeConfig::default()).build()?;
    let environment = args
        .env
        .init::<tempo_node::node::TempoNode>(AccessRights::RW, runtime)?;
    let factory = environment.provider_factory;
    let provider = factory.database_provider_rw()?;
    ensure!(
        provider.last_block_number()? == 0,
        "fixture must be at block zero"
    );
    ensure!(
        provider.cached_storage_settings().storage_v2,
        "storage v2 required"
    );
    let storage_entries = provider.tx_ref().entries::<tables::HashedStorages>()?;
    ensure!(storage_entries > 4096, "populated SLOAD fixture required");
    ensure!(
        args.replace_router
            || provider
                .tx_ref()
                .get::<tables::HashedAccounts>(keccak256(code_address(0)))?
                .is_none(),
        "code address range occupied"
    );
    let mut account = provider
        .tx_ref()
        .get::<tables::HashedAccounts>(keccak256(ROUTER))?
        .ok_or_eyre("missing SLOAD fixture account")?;
    if args.replace_router {
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&marker)?)?;
        ensure!(
            manifest["code_count"].as_u64() == Some(args.code_count),
            "code corpus count changed"
        );
        ensure!(
            manifest["hashed_storage_entries"].as_u64() == Some(storage_entries as u64),
            "storage count changed"
        );
        ensure!(
            manifest["router_code_hash"] == serde_json::to_value(account.bytecode_hash)?,
            "router provenance mismatch"
        );
        fs::write(&incomplete, "Offline router update in progress.\n")?;
        let previous = account.bytecode_hash;
        account.bytecode_hash = Some(router_hash);
        provider
            .tx_ref()
            .put::<tables::Bytecodes>(router_hash, router)?;
        provider
            .tx_ref()
            .put::<tables::HashedAccounts>(keccak256(ROUTER), account)?;
        let mut prefixes = TriePrefixSetsMut::default();
        prefixes
            .account_prefix_set
            .insert(Nibbles::unpack(keccak256(ROUTER)));
        type Root<'a, TX> = reth_trie::StateRoot<
            DatabaseTrieCursorFactory<&'a TX, PackedKeyAdapter>,
            DatabaseHashedCursorFactory<&'a TX>,
        >;
        let (root, updates) = Root::<_>::from_tx(provider.tx_ref())
            .with_prefix_sets(prefixes.freeze())
            .root_with_updates()?;
        provider.write_trie_updates(updates)?;
        provider.commit()?;
        manifest["previous_router_code_hash"] = serde_json::to_value(previous)?;
        manifest["router_code_hash"] = serde_json::to_value(router_hash)?;
        manifest["state_root"] = serde_json::to_value(root)?;
        fs::write(&marker, serde_json::to_vec_pretty(&manifest)?)?;
        fs::remove_file(incomplete)?;
        println!("{manifest}");
        return Ok(());
    }
    let existing_changes = provider.account_block_changeset(0)?;
    fs::write(
        &incomplete,
        "Do not run this database until preparation completes.\n",
    )?;
    account.bytecode_hash = Some(router_hash);
    provider
        .tx_ref()
        .put::<tables::Bytecodes>(router_hash, router)?;
    provider
        .tx_ref()
        .put::<tables::HashedAccounts>(keccak256(ROUTER), account)?;
    provider.commit()?;

    let started = Instant::now();
    let rocks = factory.rocksdb_provider();
    let mut history = rocks.batch_with_auto_commit();
    let block_zero = tables::BlockNumberList::new([0])?;
    for start in (0..args.code_count).step_by(BATCH as usize) {
        let provider = factory.database_provider_rw()?;
        let end = (start + BATCH).min(args.code_count);
        for index in start..end {
            let address = code_address(index);
            let code = Bytecode::new_raw_checked(code_body(index))?;
            let hash = code.hash_slow();
            ensure!(
                provider
                    .tx_ref()
                    .get::<tables::HashedAccounts>(keccak256(address))?
                    .is_none(),
                "code address occupied: {address}"
            );
            provider.tx_ref().put::<tables::Bytecodes>(hash, code)?;
            provider.tx_ref().put::<tables::HashedAccounts>(
                keccak256(address),
                Account {
                    nonce: 1,
                    balance: Default::default(),
                    bytecode_hash: Some(hash),
                },
            )?;
            history
                .put::<tables::AccountsHistory>(ShardedKey::new(address, u64::MAX), &block_zero)?;
        }
        provider.commit()?;
        if start / BATCH % 16 == 0 || end == args.code_count {
            let elapsed = started.elapsed().as_secs_f64();
            eprintln!(
                "code {end}/{} elapsed={elapsed:.1}s eta={:.1}s",
                args.code_count,
                elapsed * (args.code_count - end) as f64 / end as f64
            );
        }
    }
    history.commit()?;

    // Preserve genesis undo records, merging the new address range in sorted order.
    factory
        .static_file_provider()
        .delete_segment(StaticFileSegment::AccountChangeSets)?;
    let mut writer = factory.get_static_file_writer(0, StaticFileSegment::AccountChangeSets)?;
    writer.begin_account_changeset(0)?;
    let mut existing = existing_changes.into_iter().peekable();
    for index in 0..args.code_count {
        let address = code_address(index);
        while existing.peek().is_some_and(|entry| entry.address < address) {
            writer.append_account_changeset_entry(existing.next().unwrap())?;
        }
        writer.append_account_changeset_entry(AccountBeforeTx {
            address,
            info: None,
        })?;
    }
    for entry in existing {
        writer.append_account_changeset_entry(entry)?;
    }
    drop(writer);

    let provider = factory.database_provider_rw()?;
    let mut resume = None;
    type Root<'a, TX> = reth_trie::StateRoot<
        DatabaseTrieCursorFactory<&'a TX, PackedKeyAdapter>,
        DatabaseHashedCursorFactory<&'a TX>,
    >;
    // Every account path is revisited, but unchanged storage tries are reused.
    let root: B256 = loop {
        let prefixes = TriePrefixSets {
            account_prefix_set: PrefixSet::all_paths(),
            ..Default::default()
        };
        match Root::<_>::from_tx(provider.tx_ref())
            .with_prefix_sets(prefixes)
            .with_intermediate_state(resume)
            .root_with_progress()?
        {
            StateRootProgress::Progress(state, _, updates) => {
                provider.write_trie_updates(updates)?;
                resume = Some(*state);
                eprintln!(
                    "account trie elapsed={:.1}s",
                    started.elapsed().as_secs_f64()
                );
            }
            StateRootProgress::Complete(root, _, updates) => {
                provider.write_trie_updates(updates)?;
                break root;
            }
        }
    };
    ensure!(
        provider.tx_ref().entries::<tables::HashedStorages>()? == storage_entries,
        "storage entry count changed"
    );
    provider.commit()?;
    let manifest = serde_json::json!({"version":1,"code_count":args.code_count,"code_bytes":CODE_BYTES,
        "total_code_bytes":args.code_count * CODE_BYTES as u64,"code_base":code_address(0),
        "router":ROUTER,"router_code_hash":router_hash,"state_root":root,
        "hashed_storage_entries":storage_entries,"elapsed_seconds":started.elapsed().as_secs_f64(),
        "storage_layout":"original populated single-account SLOAD tree; writes change slots, code reads change addresses"});
    fs::write(&marker, serde_json::to_vec_pretty(&manifest)?)?;
    fs::remove_file(incomplete)?;
    println!("{manifest}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn corpus_is_deterministic_distinct_and_bounded() {
        assert_eq!(code_body(17), code_body(17));
        assert_ne!(keccak256(code_body(17)), keccak256(code_body(18)));
        assert_eq!(code_body(17).len(), CODE_BYTES);
        assert_eq!(code_body(17)[0], 0);
        assert!(code_address(17) < code_address(18));
        assert_eq!(
            code_address(0),
            address!("6000000000000000000000000000000000000000")
        );
    }
}
