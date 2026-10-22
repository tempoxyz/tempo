//! Offline rollback of a Zone's persisted canonical chain.

use std::{collections::HashSet, io::ErrorKind, path::PathBuf};

use alloy_eips::{BlockHashOrNumber, Encodable2718 as _};
use alloy_primitives::{B256, Bytes};
use eyre::{Context as _, OptionExt as _, ensure};
use reth_chainspec::EthChainSpec as _;
use reth_cli_commands::common::{AccessRights, Environment, EnvironmentArgs};
use reth_provider::{
    BlockBodyIndicesProvider as _, BlockExecutionWriter as _, BlockHashReader as _,
    BlockNumReader as _, ChainStateBlockReader as _, ChainStateBlockWriter as _,
    PruneCheckpointReader as _, StaticFileProviderFactory as _, TransactionsProvider as _,
    providers::RocksDBProvider,
};
use reth_tasks::{Runtime, RuntimeBuilder, RuntimeConfig, TokioConfig};
use reth_transaction_pool::{TransactionOrigin, maintain::TxBackup};
use tempo_primitives::TempoTxEnvelope;
use zone_chainspec::ZoneChainSpecParser;
use zone_node::ZoneNode;

/// Rewind a stopped Zone node, retaining the selected block. Defaults to a dry run.
#[derive(Debug, clap::Parser)]
pub(crate) struct RollbackZone {
    #[command(flatten)]
    env: EnvironmentArgs<ZoneChainSpecParser>,

    /// Canonical Zone block number or hash to retain; all descendants are removed.
    #[arg(long, value_name = "NUMBER_OR_HASH")]
    to_block: BlockHashOrNumber,

    /// Apply the rollback to disk. Stop the node and back up its data first.
    #[arg(long)]
    execute: bool,

    /// Node transaction backup path; defaults to the backup inside its data directory.
    #[arg(long = "txpool.transactions-backup", value_name = "PATH")]
    transactions_backup_path: Option<PathBuf>,
}

impl RollbackZone {
    /// Preview or apply a local rollback without contacting L1 or changing the Portal.
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let runtime = RuntimeBuilder::new(RuntimeConfig::default().with_tokio(
            TokioConfig::existing_handle(tokio::runtime::Handle::current()),
        ))
        .build()
        .wrap_err("failed building rollback runtime")?;
        tokio::task::spawn_blocking(move || self.rollback(runtime))
            .await
            .wrap_err("rollback task panicked")?
    }

    fn rollback(self, runtime: Runtime) -> eyre::Result<()> {
        let data_dir = self
            .env
            .datadir
            .clone()
            .resolve_datadir(self.env.chain.chain());
        // EnvironmentArgs otherwise creates a missing RocksDB even for read-only access.
        for path in [data_dir.db(), data_dir.static_files()] {
            ensure!(
                path.is_dir(),
                "missing Zone storage directory: {}",
                path.display()
            );
        }
        ensure!(
            RocksDBProvider::exists(data_dir.rocksdb()),
            "missing Zone RocksDB database: {}",
            data_dir.rocksdb().display()
        );
        let environment = self
            .env
            .init::<ZoneNode>(AccessRights::RoInconsistent, runtime.clone())
            .wrap_err("failed opening Zone storage for rollback preview")?;
        let plan = self.plan(&environment)?;
        println!("Zone data: {}", data_dir.data_dir().display());
        println!("Current head: {} ({})", plan.head, plan.head_hash);
        println!("Retain block: {} ({})", plan.target, plan.target_hash);
        println!("Remove {} blocks", plan.head - plan.target);
        drop(environment);
        if !self.execute {
            println!("Dry run; pass --execute to apply the rollback.");
            return Ok(());
        }
        if plan.target == plan.head {
            println!("Already at the requested block.");
            return Ok(());
        }

        // Acquire Reth's writer lock and repeat the checks before any unwind. Do not let
        // environment initialization automatically heal storage to a different target.
        let environment = self
            .env
            .init::<ZoneNode>(AccessRights::RwInconsistent, runtime)
            .wrap_err("failed opening Zone storage for rollback; stop the node first")?;
        ensure!(
            self.plan(&environment)? == plan,
            "Zone chain changed after rollback preview"
        );
        let provider = environment
            .provider_factory
            .provider_rw()
            .wrap_err("failed opening rollback transaction")?;
        let transactions_path = std::path::absolute(
            self.transactions_backup_path
                .unwrap_or_else(|| data_dir.txpool_transactions()),
        )
        .wrap_err("failed resolving transaction backup path")?;
        let mut backups = match std::fs::read(&transactions_path) {
            Ok(data) if !data.is_empty() => {
                if let Ok(backups) = serde_json::from_slice::<Vec<TxBackup>>(&data) {
                    backups
                } else {
                    // Reth also accepts its older RLP-list backup format.
                    alloy_rlp::decode_exact::<Vec<TempoTxEnvelope>>(&data)
                        .wrap_err(
                            "existing transaction backup is neither valid JSON nor legacy RLP",
                        )?
                        .into_iter()
                        .map(|tx| TxBackup {
                            rlp: tx.encoded_2718().into(),
                            origin: TransactionOrigin::Local,
                        })
                        .collect()
                }
            }
            Ok(_) => Vec::new(),
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error).wrap_err("failed reading existing transaction backup"),
        };
        let mut seen = backups
            .iter()
            .map(|backup| backup.rlp.clone())
            .collect::<HashSet<_>>();
        let previous_count = backups.len();
        for number in plan.target + 1..=plan.head {
            let indices = provider.block_body_indices(number)?.ok_or_eyre(format!(
                "missing transaction indices for Zone block {number}"
            ))?;
            let transactions = provider
                .transactions_by_tx_range(indices.tx_num_range())
                .wrap_err(format!(
                    "failed reading transactions from Zone block {number}"
                ))?;
            ensure!(
                u64::try_from(transactions.len())? == indices.tx_count,
                "missing transactions from Zone block {number}"
            );
            for transaction in transactions {
                if !transaction.is_system_tx() {
                    let rlp = Bytes::from(transaction.encoded_2718());
                    if seen.insert(rlp.clone()) {
                        backups.push(TxBackup {
                            rlp,
                            origin: TransactionOrigin::Local,
                        });
                    }
                }
            }
        }
        let saved = backups.len() - previous_count;
        if !backups.is_empty() {
            let parent = transactions_path
                .parent()
                .ok_or_eyre("transaction backup path must name a file")?;
            std::fs::create_dir_all(parent)
                .wrap_err("failed creating transaction backup directory")?;
            // Persist before the unwind: a crash or failed commit must not lose reverted txs.
            reth_fs_util::atomic_write_file(&transactions_path, |file| {
                serde_json::to_writer(file, &backups)
            })
            .wrap_err("failed saving reverted transactions; rollback was not applied")?;
        }
        provider
            .remove_block_and_execution_above(plan.target)
            .wrap_err("failed unwinding Zone blocks and execution state")?;
        // Zone forkchoice uses instant finality: head, safe, and finalized are identical.
        provider.save_safe_block_number(plan.target)?;
        provider.save_finalized_block_number(plan.target)?;
        provider
            .commit()
            .wrap_err("failed committing Zone rollback")?;

        let provider = environment.provider_factory.provider()?;
        ensure!(
            provider.last_block_number()? == plan.target
                && provider.block_hash(plan.target)? == Some(plan.target_hash)
                && provider.last_safe_block_number()? == Some(plan.target)
                && provider.last_finalized_block_number()? == Some(plan.target),
            "rollback committed but persisted head verification failed"
        );
        println!(
            "Rolled back to Zone block {} ({})",
            plan.target, plan.target_hash
        );
        println!(
            "Saved {saved} additional reverted user transactions for txpool recovery on restart: {}",
            transactions_path.display()
        );
        Ok(())
    }

    fn plan(&self, environment: &Environment<ZoneNode>) -> eyre::Result<RollbackPlan> {
        let provider = environment.provider_factory.provider()?;
        ensure!(
            provider.block_hash(0)? == Some(self.env.chain.genesis_hash()),
            "Zone genesis does not match the database"
        );
        ensure!(
            environment
                .provider_factory
                .static_file_provider()
                .check_consistency(&provider)?
                .is_none(),
            "Zone storage is inconsistent; repair it before rolling back"
        );
        let head = provider.last_block_number()?;
        let target = match self.to_block {
            BlockHashOrNumber::Number(number) => number,
            BlockHashOrNumber::Hash(hash) => provider
                .block_number(hash)?
                .ok_or_eyre(format!("Zone block {hash} was not found"))?,
        };
        ensure!(
            target <= head,
            "target Zone block {target} is above current head {head}"
        );
        let target_hash = provider
            .block_hash(target)?
            .ok_or_eyre(format!("Zone block {target} has no canonical hash"))?;
        if let BlockHashOrNumber::Hash(hash) = self.to_block {
            ensure!(target_hash == hash, "Zone block {hash} is not canonical");
        }
        provider
            .prune_modes_ref()
            .ensure_unwind_target_unpruned(head, target, &provider.get_prune_checkpoints()?)
            .wrap_err("rollback target requires pruned data")?;
        Ok(RollbackPlan {
            head,
            head_hash: provider
                .block_hash(head)?
                .ok_or_eyre("Zone head has no canonical hash")?,
            target,
            target_hash,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RollbackPlan {
    head: u64,
    head_hash: B256,
    target: u64,
    target_hash: B256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::Path, sync::Arc, time::Duration};

    use alloy::signers::{SignerSync as _, local::PrivateKeySigner};
    use alloy_consensus::{
        Header, SignableTransaction as _, Signed, TxLegacy, transaction::TxHashRef as _,
    };
    use alloy_primitives::{Address, TxKind, U256};
    use clap::Parser as _;
    use reth_chain_state::ExecutedBlock;
    use reth_db_api::{tables, transaction::DbTxMut as _};
    use reth_evm::execute::BlockExecutionOutput;
    use reth_primitives_traits::{RecoveredBlock, SignerRecoverable as _};
    use reth_provider::{
        HeaderProvider as _, PruneCheckpointWriter as _, SaveBlocksInput,
        StageCheckpointWriter as _,
    };
    use reth_prune_types::{PruneCheckpoint, PruneSegment};
    use reth_transaction_pool::{
        Pool, PoolConfig, PoolTransaction as _, TransactionPool as _,
        blobstore::InMemoryBlobStore,
        maintain::{LocalTransactionBackupConfig, backup_local_transactions_task},
        noop::MockTransactionValidator,
    };
    use reth_trie_common::{HashedPostState, KeccakKeyHasher, SortedTrieData};
    use revm::{database::states::BundleState, state::AccountInfo};
    use tempo_primitives::{
        Block, BlockBody, TempoHeader, TempoPrimitives, TempoReceipt,
        transaction::{Call, TempoTransaction, envelope::TEMPO_SYSTEM_TX_SIGNATURE},
    };
    use tempo_transaction_pool::{ordering::TempoTipOrdering, transaction::TempoPooledTransaction};

    const ACCOUNT: Address = Address::repeat_byte(0x11);

    fn command(directory: &Path, target: &str, execute: bool) -> RollbackZone {
        let mut args = vec![
            "rollback-zone".to_owned(),
            "--chain".to_owned(),
            directory.join("genesis.json").display().to_string(),
            "--datadir".to_owned(),
            directory.join("data").display().to_string(),
            "--to-block".to_owned(),
            target.to_owned(),
        ];
        if execute {
            args.push("--execute".to_owned());
        }
        RollbackZone::try_parse_from(args).unwrap()
    }

    fn fixture(storage_v2: bool) -> (tempfile::TempDir, Runtime, Vec<B256>) {
        let directory = tempfile::tempdir().unwrap();
        let chain_id = zone_primitives::constants::zone_chain_id(1337, 11).unwrap();
        std::fs::write(
            directory.path().join("genesis.json"),
            serde_json::json!({"config": {"chainId": chain_id}, "alloc": {}}).to_string(),
        )
        .unwrap();
        let runtime = Runtime::test();
        let mut args = command(directory.path(), "0", false);
        args.env.storage.v2 = storage_v2;
        let environment = args
            .env
            .init::<ZoneNode>(AccessRights::RW, runtime.clone())
            .unwrap();
        let mut parent_hash = args.env.chain.genesis_hash();
        let mut hashes = vec![parent_hash];
        let mut previous = None;
        for number in 1..=3 {
            let account = AccountInfo {
                balance: U256::from(number * 100),
                nonce: number,
                ..Default::default()
            };
            let mut builder = BundleState::builder(0..=0)
                .state_present_account_info(ACCOUNT, account.clone())
                .revert_account_info(0, ACCOUNT, Some(previous.clone()))
                .state_storage(
                    ACCOUNT,
                    [(
                        U256::from(1),
                        (U256::from((number - 1) * 1000), U256::from(number * 1000)),
                    )]
                    .into_iter()
                    .collect(),
                )
                .revert_storage(
                    0,
                    ACCOUNT,
                    vec![(U256::from(1), U256::from((number - 1) * 1000))],
                );
            if let Some(original) = previous {
                builder = builder.state_original_account_info(ACCOUNT, original);
            }
            let state = builder.build();
            let hashed_state = HashedPostState::from_bundle_state::<KeccakKeyHasher>(&state.state);
            let (state_root, trie_updates) = environment
                .provider_factory
                .latest()
                .unwrap()
                .state_root_with_updates(hashed_state.clone())
                .unwrap();
            let trie_data = SortedTrieData::new(
                Arc::new(hashed_state.into_sorted()),
                Arc::new(trie_updates.into_sorted()),
            );
            let header = TempoHeader {
                inner: Header {
                    number,
                    parent_hash,
                    timestamp: number,
                    state_root,
                    ..Default::default()
                },
                ..Default::default()
            };
            let transactions = block_transactions(number);
            let senders = transactions
                .iter()
                .map(|tx| tx.recover_signer().unwrap())
                .collect();
            let receipts = transactions
                .iter()
                .map(|tx| TempoReceipt {
                    tx_type: tx.tx_type(),
                    success: true,
                    cumulative_gas_used: 0,
                    logs: vec![],
                })
                .collect();
            let block = RecoveredBlock::new_unhashed(
                Block::new(
                    header,
                    BlockBody {
                        transactions,
                        ..Default::default()
                    },
                ),
                senders,
            );
            parent_hash = block.hash();
            hashes.push(parent_hash);
            let mut output = BlockExecutionOutput {
                state,
                ..Default::default()
            };
            output.result.receipts = receipts;
            let executed =
                ExecutedBlock::<TempoPrimitives>::new(Arc::new(block), Arc::new(output), trie_data);
            let provider = environment.provider_factory.provider_rw().unwrap();
            provider
                .save_blocks(&SaveBlocksInput::new(
                    vec![executed],
                    number - 1,
                    number - 1,
                    number,
                    number,
                ))
                .unwrap();
            provider.save_safe_block_number(number).unwrap();
            provider.save_finalized_block_number(number).unwrap();
            provider.commit().unwrap();
            previous = Some(account);
        }
        drop(environment);
        (directory, runtime, hashes)
    }

    fn assert_head(directory: &Path, runtime: Runtime, number: u64, hash: B256) {
        let args = command(directory, "0", false);
        let environment = args
            .env
            .init::<ZoneNode>(AccessRights::RO, runtime)
            .unwrap();
        let provider = environment.provider_factory.provider().unwrap();
        assert_eq!(provider.last_block_number().unwrap(), number);
        assert_eq!(provider.block_hash(number).unwrap(), Some(hash));
        assert_eq!(
            environment
                .provider_factory
                .latest()
                .unwrap()
                .state_root(Default::default())
                .unwrap(),
            provider
                .header_by_number(number)
                .unwrap()
                .unwrap()
                .inner
                .state_root
        );
        assert_eq!(provider.header_by_number(number + 1).unwrap(), None);
        assert_eq!(provider.last_safe_block_number().unwrap(), Some(number));
        assert_eq!(
            provider.last_finalized_block_number().unwrap(),
            Some(number)
        );
        let account = environment
            .provider_factory
            .latest()
            .unwrap()
            .basic_account(&ACCOUNT)
            .unwrap();
        assert_eq!(
            environment
                .provider_factory
                .latest()
                .unwrap()
                .storage(ACCOUNT, B256::with_last_byte(1))
                .unwrap()
                .unwrap_or_default(),
            U256::from(number * 1000)
        );
        if number == 0 {
            assert_eq!(account, None);
        } else {
            let account = account.unwrap();
            assert_eq!(account.balance, U256::from(number * 100));
            assert_eq!(account.nonce, number);
        }
    }

    #[test]
    fn rollback_restores_state_and_finality_in_both_storage_modes() {
        for storage_v2 in [false, true] {
            let (directory, runtime, hashes) = fixture(storage_v2);
            command(directory.path(), "1", false)
                .rollback(runtime.clone())
                .unwrap();
            assert_head(directory.path(), runtime.clone(), 3, hashes[3]);
            assert!(
                !directory
                    .path()
                    .join("data/txpool-transactions-backup.rlp")
                    .exists()
            );

            command(directory.path(), &hashes[1].to_string(), true)
                .rollback(runtime.clone())
                .unwrap();
            assert_head(directory.path(), runtime.clone(), 1, hashes[1]);
            command(directory.path(), "1", true)
                .rollback(runtime.clone())
                .unwrap();
            assert_head(directory.path(), runtime.clone(), 1, hashes[1]);

            command(directory.path(), "0", true)
                .rollback(runtime.clone())
                .unwrap();
            assert_head(directory.path(), runtime, 0, hashes[0]);
        }
    }

    #[test]
    fn invalid_targets_leave_the_chain_unchanged() {
        let (directory, runtime, hashes) = fixture(true);
        for execute in [false, true] {
            let unknown = B256::repeat_byte(0xff);
            for (target, expected) in [
                (
                    "4".to_owned(),
                    "target Zone block 4 is above current head 3".to_owned(),
                ),
                (
                    unknown.to_string(),
                    format!("Zone block {unknown} was not found"),
                ),
            ] {
                let error = command(directory.path(), &target, execute)
                    .rollback(runtime.clone())
                    .unwrap_err();
                assert_eq!(error.to_string(), expected);
                assert_head(directory.path(), runtime.clone(), 3, hashes[3]);
            }
        }
        let mut args = command(directory.path(), "1", true);
        let mut genesis = args.env.chain.genesis().clone();
        genesis.timestamp = 1;
        args.env.chain = Arc::new(zone_chainspec::ZoneChainSpec::from_genesis(genesis).unwrap());
        assert_eq!(
            args.rollback(runtime.clone()).unwrap_err().to_string(),
            "Zone genesis does not match the database"
        );
        assert_head(directory.path(), runtime, 3, hashes[3]);
    }

    #[test]
    fn noncanonical_hash_is_rejected() {
        let (directory, runtime, hashes) = fixture(true);
        let hash = B256::repeat_byte(0xfe);
        let args = command(directory.path(), &hash.to_string(), true);
        let environment = args
            .env
            .init::<ZoneNode>(AccessRights::RW, runtime.clone())
            .unwrap();
        let provider = environment.provider_factory.provider_rw().unwrap();
        provider
            .tx_ref()
            .put::<tables::HeaderNumbers>(hash, 1)
            .unwrap();
        provider.commit().unwrap();
        drop(environment);
        assert_eq!(
            args.rollback(runtime.clone()).unwrap_err().to_string(),
            format!("Zone block {hash} is not canonical")
        );
        assert_head(directory.path(), runtime, 3, hashes[3]);
    }

    #[test]
    fn pruned_and_inconsistent_storage_are_rejected() {
        let (directory, runtime, hashes) = fixture(true);
        let args = command(directory.path(), "1", true);
        let environment = args
            .env
            .init::<ZoneNode>(AccessRights::RW, runtime.clone())
            .unwrap();
        let provider = environment.provider_factory.provider_rw().unwrap();
        provider
            .save_prune_checkpoint(
                PruneSegment::AccountHistory,
                PruneCheckpoint::pruned_through(2),
            )
            .unwrap();
        provider.commit().unwrap();
        drop(environment);
        assert_eq!(
            args.rollback(runtime.clone()).unwrap_err().to_string(),
            "rollback target requires pruned data"
        );
        assert_head(directory.path(), runtime.clone(), 3, hashes[3]);

        let args = command(directory.path(), "2", true);
        let environment = args
            .env
            .init::<ZoneNode>(AccessRights::RW, runtime.clone())
            .unwrap();
        let provider = environment.provider_factory.provider_rw().unwrap();
        provider.update_pipeline_stages(4, true).unwrap();
        provider.commit().unwrap();
        drop(environment);
        assert_eq!(
            args.rollback(runtime.clone()).unwrap_err().to_string(),
            "Zone storage is inconsistent; repair it before rolling back"
        );
        assert_head(directory.path(), runtime, 3, hashes[3]);
    }

    #[test]
    fn missing_storage_is_not_created() {
        let (directory, runtime, _) = fixture(true);
        let rocksdb = directory.path().join("data/rocksdb");
        std::fs::remove_dir_all(&rocksdb).unwrap();
        std::fs::create_dir(&rocksdb).unwrap();
        assert_eq!(
            command(directory.path(), "0", false)
                .rollback(runtime.clone())
                .unwrap_err()
                .to_string(),
            format!("missing Zone RocksDB database: {}", rocksdb.display())
        );
        assert_eq!(std::fs::read_dir(&rocksdb).unwrap().count(), 0);
        std::fs::remove_dir_all(directory.path().join("data")).unwrap();
        let error = command(directory.path(), "0", true)
            .rollback(runtime)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "missing Zone storage directory: {}",
                directory.path().join("data/db").display()
            )
        );
        assert!(!directory.path().join("data").exists());
    }

    fn block_transactions(number: u64) -> Vec<TempoTxEnvelope> {
        let signer = PrivateKeySigner::from_bytes(&B256::from(U256::from(number))).unwrap();
        let system = TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                input: number.to_be_bytes().to_vec().into(),
                ..Default::default()
            },
            TEMPO_SYSTEM_TX_SIGNATURE,
        ));
        let legacy = TxLegacy {
            gas_price: 2_000_000_000,
            gas_limit: 21_000,
            to: TxKind::Call(Address::ZERO),
            ..Default::default()
        };
        let signature = signer.sign_hash_sync(&legacy.signature_hash()).unwrap();
        let legacy = legacy.into_signed(signature).into();
        let aa = TempoTransaction {
            nonce_key: U256::from(7),
            gas_limit: 100_000,
            max_fee_per_gas: 2_000_000_000,
            calls: vec![Call {
                to: TxKind::Call(Address::ZERO),
                value: U256::ZERO,
                input: Default::default(),
            }],
            ..Default::default()
        };
        let signer = PrivateKeySigner::from_bytes(&B256::from(U256::from(number + 100))).unwrap();
        let signature = signer.sign_hash_sync(&aa.signature_hash()).unwrap();
        vec![system, legacy, aa.into_signed(signature.into()).into()]
    }

    #[test]
    fn rollback_backup_is_reinserted_by_the_node_startup_task() {
        for storage_v2 in [false, true] {
            let (directory, runtime, hashes) = fixture(storage_v2);
            let backup_path = directory.path().join("data/txpool-transactions-backup.rlp");
            let pending = block_transactions(10).pop().unwrap();
            let duplicate = block_transactions(3).remove(1);
            let existing = vec![
                TxBackup {
                    rlp: pending.encoded_2718().into(),
                    origin: TransactionOrigin::Local,
                },
                TxBackup {
                    rlp: duplicate.encoded_2718().into(),
                    origin: TransactionOrigin::External,
                },
            ];
            let original = serde_json::to_vec(&existing).unwrap();
            std::fs::write(&backup_path, &original).unwrap();
            command(directory.path(), "1", false)
                .rollback(runtime.clone())
                .unwrap();
            assert_eq!(std::fs::read(&backup_path).unwrap(), original);

            command(directory.path(), "1", true)
                .rollback(runtime.clone())
                .unwrap();
            assert_head(directory.path(), runtime.clone(), 1, hashes[1]);
            let data = std::fs::read(&backup_path).unwrap();
            let backups: Vec<TxBackup> = serde_json::from_slice(&data).unwrap();
            let reverted = (2..=3)
                .flat_map(block_transactions)
                .filter(|tx| !tx.is_system_tx())
                .collect::<Vec<_>>();
            let expected = std::iter::once(&pending)
                .chain(&reverted)
                .map(|tx| Bytes::from(tx.encoded_2718()))
                .collect::<HashSet<_>>();
            assert_eq!(backups.len(), expected.len());
            assert_eq!(
                backups
                    .iter()
                    .map(|backup| backup.rlp.clone())
                    .collect::<HashSet<_>>(),
                expected
            );
            assert_eq!(backups[1].origin, TransactionOrigin::External);
            command(directory.path(), "1", true)
                .rollback(runtime.clone())
                .unwrap();
            assert_eq!(std::fs::read(&backup_path).unwrap(), data);

            let pool = Pool::new(
                MockTransactionValidator::<TempoPooledTransaction>::default(),
                TempoTipOrdering::default(),
                InMemoryBlobStore::default(),
                PoolConfig::default(),
            );
            let restore_pool = pool.clone();
            let config = LocalTransactionBackupConfig::with_local_txs_backup(backup_path.clone());
            runtime.spawn_critical_with_graceful_shutdown_signal(
                "restore rollback transactions",
                move |shutdown| backup_local_transactions_task(shutdown, restore_pool, config),
            );
            runtime.handle().block_on(async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while backup_path.exists() {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .unwrap();
            });
            for tx in std::iter::once(&pending).chain(&reverted) {
                let pooled = pool
                    .get(tx.tx_hash())
                    .expect("startup must restore reverted transactions");
                assert_eq!(pooled.transaction.clone_into_consensus().inner(), tx);
            }
            assert_eq!(pool.pool_size().total, expected.len());
            assert!(runtime.graceful_shutdown_with_timeout(Duration::from_secs(5)));
        }
    }

    #[test]
    fn legacy_backup_and_custom_path_preserve_pending_transactions() {
        let (directory, runtime, _) = fixture(true);
        let backup_path = directory.path().join("custom-backup.rlp");
        let pending = block_transactions(10).pop().unwrap();
        std::fs::write(&backup_path, alloy_rlp::encode(vec![pending.clone()])).unwrap();
        let mut args = command(directory.path(), "1", true);
        args.transactions_backup_path = Some(backup_path.clone());
        args.rollback(runtime.clone()).unwrap();
        let backups: Vec<TxBackup> =
            serde_json::from_slice(&std::fs::read(&backup_path).unwrap()).unwrap();
        assert_eq!(backups.len(), 5);
        assert_eq!(backups[0].rlp, pending.encoded_2718());
        assert_eq!(backups[0].origin, TransactionOrigin::Local);
        assert!(
            !directory
                .path()
                .join("data/txpool-transactions-backup.rlp")
                .exists()
        );

        let mut args = command(directory.path(), "0", true);
        args.transactions_backup_path = Some(backup_path.clone());
        args.rollback(runtime).unwrap();
        let backups: Vec<TxBackup> =
            serde_json::from_slice(&std::fs::read(&backup_path).unwrap()).unwrap();
        assert_eq!(backups.len(), 7);
    }

    #[test]
    fn backup_errors_abort_before_unwinding() {
        let (directory, runtime, hashes) = fixture(true);
        let backup_path = directory.path().join("data/txpool-transactions-backup.rlp");
        let corrupt = b"invalid backup";
        std::fs::write(&backup_path, corrupt).unwrap();
        assert_eq!(
            command(directory.path(), "1", true)
                .rollback(runtime.clone())
                .unwrap_err()
                .to_string(),
            "existing transaction backup is neither valid JSON nor legacy RLP"
        );
        assert_eq!(std::fs::read(&backup_path).unwrap(), corrupt);
        assert_head(directory.path(), runtime.clone(), 3, hashes[3]);

        std::fs::write(&backup_path, b"[]").unwrap();
        std::fs::create_dir(backup_path.with_extension("tmp")).unwrap();
        assert_eq!(
            command(directory.path(), "1", true)
                .rollback(runtime.clone())
                .unwrap_err()
                .to_string(),
            "failed saving reverted transactions; rollback was not applied"
        );
        assert_eq!(std::fs::read(&backup_path).unwrap(), b"[]");
        assert_head(directory.path(), runtime.clone(), 3, hashes[3]);

        std::fs::remove_file(&backup_path).unwrap();
        std::fs::create_dir(&backup_path).unwrap();
        assert_eq!(
            command(directory.path(), "1", true)
                .rollback(runtime.clone())
                .unwrap_err()
                .to_string(),
            "failed reading existing transaction backup"
        );
        assert_head(directory.path(), runtime, 3, hashes[3]);
    }

    #[test]
    fn missing_transaction_data_aborts_before_unwinding() {
        for missing_indices in [false, true] {
            let (directory, runtime, hashes) = fixture(true);
            let args = command(directory.path(), "1", true);
            let environment = args
                .env
                .init::<ZoneNode>(AccessRights::RW, runtime.clone())
                .unwrap();
            let provider = environment.provider_factory.provider_rw().unwrap();
            let expected = if missing_indices {
                assert!(
                    provider
                        .tx_ref()
                        .delete::<tables::BlockBodyIndices>(2, None)
                        .unwrap()
                );
                "missing transaction indices for Zone block 2"
            } else {
                let mut indices = provider.block_body_indices(2).unwrap().unwrap();
                indices.tx_count = 100;
                provider
                    .tx_ref()
                    .put::<tables::BlockBodyIndices>(2, indices)
                    .unwrap();
                "missing transactions from Zone block 2"
            };
            provider.commit().unwrap();
            drop(environment);
            assert_eq!(
                args.rollback(runtime.clone()).unwrap_err().to_string(),
                expected
            );
            assert_head(directory.path(), runtime, 3, hashes[3]);
            assert!(
                !directory
                    .path()
                    .join("data/txpool-transactions-backup.rlp")
                    .exists()
            );
        }
    }

    #[test]
    fn empty_backup_is_populated_without_duplicating_saved_transactions() {
        let (directory, runtime, hashes) = fixture(true);
        let backup_path = directory.path().join("data/txpool-transactions-backup.rlp");
        std::fs::write(&backup_path, b"").unwrap();
        command(directory.path(), "2", true)
            .rollback(runtime.clone())
            .unwrap();
        let backups: Vec<TxBackup> =
            serde_json::from_slice(&std::fs::read(&backup_path).unwrap()).unwrap();
        assert_eq!(backups.len(), 2);
        let all_reverted = (1..=3)
            .flat_map(block_transactions)
            .filter(|tx| !tx.is_system_tx())
            .map(|tx| TxBackup {
                rlp: tx.encoded_2718().into(),
                origin: TransactionOrigin::Local,
            })
            .collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&all_reverted).unwrap();
        std::fs::write(&backup_path, &bytes).unwrap();
        command(directory.path(), "0", true)
            .rollback(runtime.clone())
            .unwrap();
        assert_head(directory.path(), runtime, 0, hashes[0]);
        assert_eq!(std::fs::read(&backup_path).unwrap(), bytes);
    }
}
