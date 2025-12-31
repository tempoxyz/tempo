//! State bloating tool for testing.
//!
//! This tool opens an existing tempo node database and bloats it by minting
//! TIP20 balances for many random addresses.

use alloy::consensus::{Block as ConsensusBlock, BlockBody, BlockHeader as _, Header};
use alloy_primitives::{Address, B256, U256};
use eyre::WrapErr as _;
use indicatif::{ProgressBar, ProgressStyle};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use rayon::iter::IntoParallelRefIterator as _;
use reth_db::{init_db, mdbx::DatabaseArguments};
use reth_ethereum::provider::{
    DatabaseProviderFactory, ProviderFactory,
    providers::{RocksDBProvider, StaticFileProvider},
};
use reth_evm::{
    Evm, EvmEnv, EvmFactory,
    revm::{
        Database, DatabaseCommit,
        context::ContextTr,
        database::{State, states::bundle_state::BundleRetention},
    },
};
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_primitives_traits::RecoveredBlock;
use reth_provider::{
    BlockNumReader, BlockWriter, DBProvider, ExecutionOutcome, HeaderProvider, HistoryWriter,
    OriginalValuesKnown, StageCheckpointWriter, StateWriter,
};
use reth_revm::database::StateProviderDatabase;
use reth_trie_common::{EMPTY_ROOT_HASH, HashedPostState, KeccakKeyHasher};
use std::{fs::File, path::PathBuf, sync::Arc, time::Instant};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork};
use tempo_contracts::precompiles::ITIP20Factory;
use tempo_evm::evm::TempoEvmFactory;
use tempo_node::node::TempoNode;
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    storage::StorageCtx,
    tip20::{ISSUER_ROLE, ITIP20, TIP20Token, roles::DEFAULT_ADMIN_ROLE},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
};
use tempo_primitives::{Block, TempoHeader};

macro_rules! with_storage {
    ($evm:expr, $body:expr) => {{
        let ctx = $evm.ctx_mut();
        StorageCtx::enter_evm(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, || $body)
    }};
}

fn timed<T, E: Into<eyre::Report>>(
    name: &str,
    f: impl FnOnce() -> Result<T, E>,
) -> eyre::Result<T> {
    let start = Instant::now();
    let result = f().map_err(Into::into)?;
    println!("  {name}: {:.2?}", start.elapsed());
    Ok(result)
}

/// State bloating tool that writes TIP20 storage entries to an existing database.
#[derive(Debug, clap::Parser)]
pub(crate) struct StateBloat {
    /// Path to the node's data directory (e.g., ~/.local/share/tempo/mainnet)
    #[arg(long)]
    datadir: PathBuf,

    /// Path to the genesis.json file used to initialize the node
    #[arg(long)]
    genesis: PathBuf,

    /// Number of unique addresses to create TIP20 balances for
    #[arg(long, default_value = "1000000")]
    num_accounts: u64,

    /// Random seed for generating addresses (optional, for reproducibility)
    #[arg(long)]
    seed: Option<u64>,

    /// TIP20 balance to assign to each address
    #[arg(long, default_value = "1000000000000000000000")]
    balance_per_account: U256,

    /// Batch size for progress updates
    #[arg(long, default_value = "10000")]
    batch_size: u64,
}

impl StateBloat {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            datadir,
            genesis,
            num_accounts,
            seed,
            balance_per_account,
            batch_size,
        } = self;

        let seed = seed.unwrap_or_else(rand::random);
        println!("State bloating tool");
        println!("  Data directory: {}", datadir.display());
        println!("  Genesis file: {}", genesis.display());
        println!("  Accounts to create: {num_accounts}");
        println!("  Balance per account: {balance_per_account}");
        println!("  Using seed: {seed}");

        let db_path = datadir.join("db");
        let static_files_path = datadir.join("static_files");
        let rocksdb_path = datadir.join("rocksdb");

        eyre::ensure!(
            db_path.exists(),
            "Database not found at {}. Make sure the node has been initialized.",
            db_path.display()
        );

        let genesis_json: alloy::genesis::Genesis =
            serde_json::from_reader(File::open(&genesis).wrap_err_with(|| {
                format!("Failed to open genesis file at {}", genesis.display())
            })?)
            .wrap_err("Failed to parse genesis JSON")?;
        let chainspec = TempoChainSpec::from_genesis(genesis_json);

        println!("Opening database at {}...", db_path.display());

        let database = Arc::new(
            init_db(db_path.clone(), DatabaseArguments::default())
                .wrap_err_with(|| format!("Failed to open database at {}", db_path.display()))?,
        );

        let static_file_provider = StaticFileProvider::read_write(static_files_path.as_path())
            .wrap_err("Failed to open static files")?;

        let rocksdb = RocksDBProvider::builder(rocksdb_path)
            .build()
            .wrap_err("Failed to open RocksDB")?;

        let provider_factory = ProviderFactory::<NodeTypesWithDBAdapter<TempoNode, _>>::new(
            database,
            Arc::new(chainspec),
            static_file_provider,
            rocksdb,
        )
        .wrap_err("Failed to create provider factory")?;

        println!("Database opened successfully");

        // Get the last block number and its sealed header
        let last_block_num = provider_factory.last_block_number()?;
        let parent_header = provider_factory
            .sealed_header(last_block_num)?
            .ok_or_else(|| eyre::eyre!("Parent header not found for block {last_block_num}"))?;
        println!("  Last block number: {last_block_num}");

        // Get state provider for latest state
        let state_provider = provider_factory.latest()?;

        // Create State with bundle tracking enabled
        let mut db = State::builder()
            .with_database(StateProviderDatabase::new(state_provider))
            .with_bundle_update()
            .without_state_clear()
            .build();

        // Load PathUSD account and ensure it has a nonce so it's not considered empty
        let mut account = db.basic(PATH_USD_ADDRESS)?.unwrap_or_default();
        if account.nonce == 0 {
            account.nonce = 1;
            db.insert_account(PATH_USD_ADDRESS, account);
        }

        let mut env = EvmEnv::default().with_timestamp(U256::ZERO);
        env.cfg_env = env.cfg_env.with_spec(TempoHardfork::AllegroModerato);
        let factory = TempoEvmFactory::default();
        let mut evm = factory.create_evm(db, env);

        let admin = Address::ZERO;

        // Check if PathUSD already exists, if not initialize it
        println!("Checking PathUSD state...");
        let needs_init = with_storage!(&mut evm, {
            TIP20Token::new(0).name().map_or(true, |n| n.is_empty())
        });

        if needs_init {
            println!("Initializing TIP20 contracts...");
            with_storage!(&mut evm, {
                TIP403Registry::new().initialize()?;
                TIP20Factory::new().initialize()?;

                let token_address = TIP20Factory::new().create_token(
                    admin,
                    ITIP20Factory::createTokenCall {
                        name: "pathUSD".into(),
                        symbol: "pathUSD".into(),
                        currency: "USD".into(),
                        quoteToken: Address::ZERO,
                        admin,
                    },
                )?;
                eyre::ensure!(
                    token_address == PATH_USD_ADDRESS,
                    "PathUSD token address mismatch: expected {PATH_USD_ADDRESS}, got {token_address}"
                );

                // create_token already grants DEFAULT_ADMIN_ROLE to admin, so we only need ISSUER_ROLE
                let mut token = TIP20Token::new(0);
                token.grant_role_internal(admin, *ISSUER_ROLE)?;
                token.set_supply_cap(
                    admin,
                    ITIP20::setSupplyCapCall {
                        newSupplyCap: U256::from(u128::MAX),
                    },
                )?;
                Ok::<_, eyre::Report>(())
            })?;
        } else {
            // PathUSD exists but admin may not have roles (e.g., from a real genesis).
            // Grant both roles needed: DEFAULT_ADMIN_ROLE for set_supply_cap, ISSUER_ROLE for mint.
            println!("PathUSD already initialized, granting roles to admin...");
            with_storage!(&mut evm, {
                let mut token = TIP20Token::new(0);
                token.grant_role_internal(admin, DEFAULT_ADMIN_ROLE)?;
                token.grant_role_internal(admin, *ISSUER_ROLE)?;
                token.set_supply_cap(
                    admin,
                    ITIP20::setSupplyCapCall {
                        newSupplyCap: U256::from(u128::MAX),
                    },
                )?;
                Ok::<_, eyre::Report>(())
            })?;
        }

        println!("Minting TIP20 balances for {num_accounts} accounts...");

        let pb = ProgressBar::new(num_accounts);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("##-"),
        );

        let mint_start = Instant::now();
        let mut total_gas = 0u64;

        // Generate a single random starting address from the seed, then increment
        let mut seed_rng = StdRng::seed_from_u64(seed);
        let start_addr: U256 = U256::from_le_bytes(seed_rng.r#gen::<[u8; 32]>());

        with_storage!(&mut evm, {
            let mut token = TIP20Token::new(0);

            for i in 0..num_accounts {
                let addr_int = start_addr.wrapping_add(U256::from(i));
                let random_addr = Address::from_word(addr_int.into());

                let gas_before = StorageCtx.gas_used();
                token.mint(
                    admin,
                    ITIP20::mintCall {
                        to: random_addr,
                        amount: balance_per_account,
                    },
                )?;
                let gas_after = StorageCtx.gas_used();
                total_gas += gas_after - gas_before;

                if i % batch_size == 0 {
                    pb.set_position(i);
                }
            }
            pb.set_position(num_accounts);
            Ok::<_, eyre::Report>(())
        })?;
        let mint_duration = mint_start.elapsed();

        pb.finish_with_message("Done minting!");
        let mint_secs = mint_duration.as_secs_f64();
        let gas_per_sec = if mint_secs > 0.0 {
            total_gas as f64 / mint_secs
        } else {
            0.0
        };
        let mints_per_sec = if mint_secs > 0.0 {
            num_accounts as f64 / mint_secs
        } else {
            0.0
        };
        println!("Minting stats:");
        println!("  Total time: {:.2?}", mint_duration);
        println!("  Total gas: {}", total_gas);
        println!("  Gas/second: {:.0}", gas_per_sec);
        println!("  Mints/second: {:.0}", mints_per_sec);

        // Finalize the journaled state and commit to the db
        println!("Extracting state changes...");
        let extract_start = Instant::now();

        let evm_state = evm.ctx_mut().journaled_state.finalize();
        println!("  EVM state accounts: {}", evm_state.len());
        let storage_changes: usize = evm_state.values().map(|a| a.storage.len()).sum();
        println!("  EVM storage changes: {storage_changes}");

        // Commit the state to the database wrapper
        evm.ctx_mut().db_mut().commit(evm_state);

        // Now take the bundle
        let mut db = evm.into_db();
        db.merge_transitions(BundleRetention::Reverts);
        let bundle_state = db.take_bundle();

        println!("  Bundle state accounts: {}", bundle_state.state.len());
        let bundle_storage: usize = bundle_state.state.values().map(|a| a.storage.len()).sum();
        println!("  Bundle storage changes: {bundle_storage}");

        // Create hashed state from bundle state
        let hashed_state =
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle_state.state.par_iter());
        let hashed_state_sorted = hashed_state.into_sorted();

        let extract_duration = extract_start.elapsed();
        println!("  Extract/hash time: {:.2?}", extract_duration);

        // Create a synthetic block to append
        let new_block_number = last_block_num + 1;
        let synthetic_header = TempoHeader {
            general_gas_limit: parent_header.general_gas_limit,
            shared_gas_limit: parent_header.shared_gas_limit,
            timestamp_millis_part: 0,
            inner: Header {
                parent_hash: parent_header.hash(),
                number: new_block_number,
                timestamp: parent_header.timestamp() + 1,
                gas_limit: parent_header.gas_limit(),
                beneficiary: Address::ZERO,
                state_root: B256::ZERO, // Will be computed by trie updates
                transactions_root: EMPTY_ROOT_HASH,
                receipts_root: EMPTY_ROOT_HASH,
                ..Default::default()
            },
        };
        let synthetic_block: Block = ConsensusBlock {
            header: synthetic_header,
            body: BlockBody::default(),
        };
        let recovered_block = RecoveredBlock::new_unhashed(synthetic_block, vec![]);

        // Get a write provider and persist the state
        println!("Writing state to database...");
        let write_start = Instant::now();

        let provider = provider_factory
            .database_provider_rw()
            .wrap_err("Failed to get database provider")?;

        let execution_outcome = ExecutionOutcome::new(
            bundle_state,
            Default::default(), // receipts
            new_block_number,   // first_block
            Default::default(), // requests
        );

        timed(&format!("Insert block {new_block_number}"), || {
            provider.insert_block(recovered_block)
        })?;
        timed("Write state", || {
            provider.write_state(&execution_outcome, OriginalValuesKnown::No)
        })?;
        timed("Write hashed state", || {
            provider.write_hashed_state(&hashed_state_sorted)
        })?;
        timed("Update history indices", || {
            provider.update_history_indices(new_block_number..=new_block_number)
        })?;
        timed("Update pipeline stages", || {
            provider.update_pipeline_stages(new_block_number, false)
        })?;
        timed("Commit", || provider.commit())?;

        let write_duration = write_start.elapsed();
        let total_duration = mint_start.elapsed();

        println!("\nState bloating complete!");
        println!("  Added {} TIP20 balance slots for PathUSD", num_accounts);
        println!("  New block number: {new_block_number}");
        println!("\nTiming summary:");
        println!("  Minting:    {:.2?}", mint_duration);
        println!("  Extracting: {:.2?}", extract_duration);
        println!("  Writing:    {:.2?}", write_duration);
        println!("  Total:      {:.2?}", total_duration);
        println!("\nPerformance:");
        println!("  Total gas:    {}", total_gas);
        println!("  Gas/second:   {:.0}", gas_per_sec);
        println!("  Mints/second: {:.0}", mints_per_sec);

        Ok(())
    }
}
