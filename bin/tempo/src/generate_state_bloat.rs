//! Generate TIP20 state bloat directly into the database.
//!
//! This command derives TIP20 storage slots (total_supply + balances) and writes
//! them straight into the node's database using [`StorageLoader`], bypassing
//! the intermediate binary file that `tempo-xtask generate-state-bloat` produces.

use std::sync::Arc;

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_signer::utils::secret_key_to_address;
use alloy_signer_local::coins_bip39::{English, Mnemonic};
use clap::Parser;
use coins_bip32::prelude::*;
use eyre::ensure;
use rayon::prelude::*;
use reth_chainspec::EthereumHardforks;
use reth_cli_commands::common::{AccessRights, CliNodeTypes, EnvironmentArgs};
use reth_ethereum::{chainspec::EthChainSpec, tasks::Runtime};
use reth_provider::{BlockNumReader, DatabaseProviderFactory};
use reth_storage_api::DBProvider;
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_precompiles::tip20::tip20_slots;
use tempo_primitives::transaction::TIP20_PAYMENT_PREFIX;
use tracing::info;

use crate::init_state::StorageLoader;

/// Default chunk size: 256k entries per chunk.
const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Generate TIP20 state bloat directly into the database.
#[derive(Debug, Parser)]
pub(crate) struct GenerateStateBloat<C: reth_cli::chainspec::ChainSpecParser = TempoChainSpecParser>
{
    #[command(flatten)]
    env: EnvironmentArgs<C>,

    /// Mnemonic to use for account generation.
    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,

    /// Target state size in MiB (controls number of accounts per token).
    #[arg(short, long, default_value = "1024")]
    size: u64,

    /// Token IDs to generate storage for (can be specified multiple times).
    /// Uses reserved TIP20 addresses: 0x20C0...{token_id}
    #[arg(short, long, default_values_t = vec![0u64])]
    token: Vec<u64>,

    /// Balance value to assign to each account (in smallest units).
    #[arg(long, default_value = "1000000")]
    balance: u64,

    /// Number of addresses to derive using proper BIP32 (signable).
    /// Remaining addresses use fast keccak-based derivation (not signable).
    #[arg(long, default_value = "10000")]
    signable_count: usize,

    /// Number of entries to process per chunk. Controls peak memory usage.
    #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
    chunk_size: usize,
}

impl<C: reth_cli::chainspec::ChainSpecParser<ChainSpec: EthChainSpec + EthereumHardforks>>
    GenerateStateBloat<C>
{
    /// Execute the generate-state-bloat command.
    pub(crate) async fn execute<N>(self, runtime: Runtime) -> eyre::Result<()>
    where
        N: CliNodeTypes<ChainSpec = C::ChainSpec>,
    {
        info!(target: "tempo::cli", "Tempo generate-state-bloat starting");

        let environment = self.env.init::<N>(AccessRights::RW, runtime)?;
        let provider_factory = environment.provider_factory;
        let provider_rw = provider_factory.database_provider_rw()?;

        // Verify we're at genesis (block 0)
        let last_block = provider_rw.last_block_number()?;
        ensure!(
            last_block == 0,
            "generate-state-bloat must be run on a freshly initialized database at block 0, \
             but found block {last_block}"
        );

        ensure!(
            !self.token.is_empty(),
            "at least one token ID must be specified"
        );
        ensure!(self.size > 0, "size must be greater than 0");
        ensure!(self.chunk_size > 0, "chunk_size must be greater than 0");

        let target_bytes = self.size * 1024 * 1024;
        let num_tokens = self.token.len() as u64;

        // Calculate number of accounts needed (same formula as xtask).
        let header_size = 40u64;
        let entry_size = 64u64;
        let overhead_per_token = header_size + entry_size;
        let available_for_balances = target_bytes.saturating_sub(num_tokens * overhead_per_token);
        let total_balance_entries = available_for_balances / entry_size;
        let accounts_per_token = total_balance_entries / num_tokens;

        ensure!(
            accounts_per_token > 0,
            "target size too small for the number of tokens"
        );

        let total_accounts = accounts_per_token as usize;
        let actual_signable = self.signable_count.min(total_accounts);
        let num_chunks = total_accounts.div_ceil(self.chunk_size);

        // Derive parent key
        let parent_key = derive_parent_key(&self.mnemonic)?;
        let parent_key = Arc::new(parent_key);
        let seed = keccak256(self.mnemonic.as_bytes());

        // Generate token addresses
        let token_addresses: Vec<Address> =
            self.token.iter().map(|&id| token_address(id)).collect();

        // Precompute constants
        let balance_value = U256::from(self.balance);
        let total_supply = balance_value * U256::from(total_accounts);

        info!(
            target: "tempo::cli",
            num_tokens,
            accounts_per_token,
            num_chunks,
            chunk_size = self.chunk_size,
            "Generating state bloat"
        );

        let mut loader = StorageLoader::new();
        let mut is_first_chunk = true;

        for (chunk_idx, chunk_start) in (0..total_accounts).step_by(self.chunk_size).enumerate() {
            let chunk_end = (chunk_start + self.chunk_size).min(total_accounts);
            let chunk_indices: Vec<usize> = (chunk_start..chunk_end).collect();
            let chunk_len = chunk_indices.len();

            // Parallel address derivation + slot computation
            let parent_key_ref = Arc::clone(&parent_key);
            let slot_bytes: Vec<(Address, [u8; 32])> = chunk_indices
                .into_par_iter()
                .map(|i| {
                    let addr = if i < actual_signable {
                        let child = parent_key_ref
                            .derive_child(i as u32)
                            .expect("child derivation should not fail");
                        let key: &coins_bip32::prelude::SigningKey = child.as_ref();
                        let credential =
                            k256::ecdsa::SigningKey::from_bytes(&key.to_bytes()).unwrap();
                        secret_key_to_address(&credential)
                    } else {
                        derive_address_fast(&seed, i as u64)
                    };
                    let slot = compute_mapping_slot(addr, tip20_slots::BALANCES).to_be_bytes::<32>();
                    (addr, slot)
                })
                .collect();

            // Write entries for each token
            for token_addr in &token_addresses {
                loader.ensure_account(&provider_rw, *token_addr)?;

                // Only write total_supply in the first chunk
                if is_first_chunk {
                    loader.push_entry(
                        *token_addr,
                        B256::from(tip20_slots::TOTAL_SUPPLY.to_be_bytes::<32>()),
                        total_supply,
                    )?;
                }

                // Write balance entries
                for (_addr, slot) in &slot_bytes {
                    loader.push_entry(
                        *token_addr,
                        B256::from(*slot),
                        balance_value,
                    )?;
                }
            }

            is_first_chunk = false;

            info!(
                target: "tempo::cli",
                chunk = chunk_idx + 1,
                num_chunks,
                entries = chunk_len,
                total_entries = loader.total_entries(),
                "Chunk processed"
            );
        }

        let stats = loader.finish(&provider_rw)?;

        provider_rw.commit()?;

        info!(
            target: "tempo::cli",
            total_entries = stats.total_entries,
            state_root = %stats.state_root,
            "State bloat generated successfully"
        );

        Ok(())
    }
}

/// Compute a reserved TIP20 token address from a token ID.
fn token_address(token_id: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..12].copy_from_slice(&TIP20_PAYMENT_PREFIX);
    bytes[12..].copy_from_slice(&token_id.to_be_bytes());
    Address::from(bytes)
}

/// Fast address derivation using keccak256(seed || index).
fn derive_address_fast(seed: &[u8; 32], index: u64) -> Address {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(seed);
    buf[32..].copy_from_slice(&index.to_be_bytes());
    let hash = keccak256(buf);
    Address::from_slice(&hash[12..])
}

/// Derive the parent key for BIP44 Ethereum path: m/44'/60'/0'/0
fn derive_parent_key(mnemonic_phrase: &str) -> eyre::Result<XPriv> {
    let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic_phrase)
        .map_err(|e| eyre::eyre!("invalid mnemonic: {e}"))?;

    let master: XPriv = mnemonic
        .derive_key("m/44'/60'/0'/0", None)
        .map_err(|e| eyre::eyre!("key derivation failed: {e}"))?;

    Ok(master)
}

/// Compute a Solidity mapping slot: keccak256(pad32(key) || pad32(base_slot))
fn compute_mapping_slot(key: Address, base_slot: U256) -> U256 {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(key.as_slice());
    buf[32..].copy_from_slice(&base_slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}
