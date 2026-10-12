//! State bloat generation tool for generating large TIP20 storage state files.
//!
//! Generates a binary file containing TIP20 storage slots and a filled expiring nonce ring
//! that can be loaded during genesis initialization to create a bloated state.
//!
//! Uses chunked streaming to keep memory bounded regardless of target file size.

use alloy::{
    primitives::{Address, U256, keccak256},
    signers::{
        local::coins_bip39::{English, Mnemonic},
        utils::secret_key_to_address,
    },
};
use coins_bip32::prelude::*;
use eyre::{Context as _, ensure};
use indicatif::{ProgressBar, ProgressStyle};
use itertools::Itertools;
use rayon::prelude::*;
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::Arc,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS, nonce::NonceManager, storage::StorageKey, tip20::tip20_slots,
};
use tempo_primitives::transaction::TIP20_PAYMENT_PREFIX;

/// Magic bytes for the state bloat binary format (8 bytes)
const MAGIC: &[u8; 8] = b"TEMPOSB\x00";

/// Format version
const VERSION: u16 = 1;

/// Default chunk size: 256k entries per chunk (~16 MiB memory)
const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Generate state bloat file
#[derive(Debug, clap::Args)]
pub struct GenerateStateBloat {
    /// Mnemonic to use for account generation
    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,

    /// Read the account-generation mnemonic from a file.
    #[arg(long, value_name = "PATH", conflicts_with = "mnemonic")]
    mnemonic_file: Option<PathBuf>,

    /// Target TIP20 storage size in MiB (the filled nonce ring is additional)
    #[arg(short, long, default_value = "1024")]
    size: u64,

    /// Hardfork determining nonce ring capacity (defaults to the latest known fork).
    #[arg(long, default_value_t = *TempoHardfork::VARIANTS.last().unwrap())]
    nonce_ring_hardfork: TempoHardfork,

    /// Token IDs to generate storage for (can be specified multiple times)
    /// Uses reserved TIP20 addresses: 0x20C0...{token_id}
    #[arg(short, long, default_values_t = vec![0u64])]
    token: Vec<u64>,

    /// Output file path
    #[arg(short, long, default_value = "state_bloat.bin")]
    out: PathBuf,

    /// Balance value to assign to each account (in smallest units)
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

impl GenerateStateBloat {
    /// Generate the TIP20 binary storage dump described by these CLI arguments.
    pub async fn run(self) -> eyre::Result<()> {
        let Self {
            mnemonic,
            mnemonic_file,
            size,
            nonce_ring_hardfork,
            token: tokens,
            out,
            balance,
            signable_count,
            chunk_size,
        } = self;

        let mnemonic = if let Some(path) = mnemonic_file {
            let mnemonic = std::fs::read_to_string(&path)
                .wrap_err_with(|| format!("failed reading mnemonic file `{}`", path.display()))?;
            let mnemonic = mnemonic.trim();
            ensure!(
                !mnemonic.is_empty(),
                "mnemonic file `{}` is empty",
                path.display()
            );
            mnemonic.to_owned()
        } else {
            mnemonic
        };

        ensure!(
            !tokens.is_empty(),
            "at least one token ID must be specified"
        );
        ensure!(size > 0, "size must be greater than 0");
        ensure!(chunk_size > 0, "chunk_size must be greater than 0");

        let target_bytes = size * 1024 * 1024; // MiB to bytes
        let num_tokens = tokens.len() as u64;

        // Calculate number of accounts needed
        // Per token: 1 header (40 bytes) + 1 total_supply (64 bytes) + N balances (64 bytes each)
        // With chunking, each chunk gets its own header, so overhead increases slightly.
        // We calculate based on the simple model first, then adjust.
        let header_size = 40u64;
        let entry_size = 64u64;
        let overhead_per_token = header_size + entry_size; // header + total_supply
        let available_for_balances = target_bytes.saturating_sub(num_tokens * overhead_per_token);
        let total_balance_entries = available_for_balances / entry_size;
        let accounts_per_token = total_balance_entries / num_tokens;

        ensure!(
            accounts_per_token > 0,
            "target size too small for the number of tokens"
        );

        let total_accounts = accounts_per_token as usize;
        let actual_signable = signable_count.min(total_accounts);

        let estimated_size_mib =
            (num_tokens * (overhead_per_token + accounts_per_token * entry_size)) as f64
                / (1024.0 * 1024.0);
        let out_display = out.display();
        let num_chunks = total_accounts.div_ceil(chunk_size);
        println!("State bloat generation:");
        println!("  Target size: {size} MiB");
        println!("  Tokens: {num_tokens}");
        println!("  Accounts per token: {accounts_per_token}");
        println!("  Estimated TIP20 size: {estimated_size_mib:.2} MiB");
        let capacity = nonce_ring_hardfork.expiring_nonce_set_capacity();
        println!(
            "  Nonce ring: {capacity} entries ({nonce_ring_hardfork}), {:.2} MiB additional",
            f64::from(capacity) * 128.0 / (1024.0 * 1024.0)
        );
        println!("  Chunk size: {chunk_size} entries ({num_chunks} chunks)");
        println!("  Output: {out_display}");

        // Step 1: Derive parent key
        let parent_key = derive_parent_key(&mnemonic)?;
        let parent_key = Arc::new(parent_key);
        let seed = keccak256(mnemonic.as_bytes());

        // Step 2: Generate token addresses
        let token_addresses: Vec<Address> = tokens.iter().map(|&id| token_address(id)).collect();

        println!("\nToken addresses:");
        for (id, addr) in tokens.iter().zip(&token_addresses) {
            println!("  Token {id}: {addr}");
        }

        // Step 3: Precompute constants
        let balance_value = U256::from(balance);
        let total_supply = balance_value * U256::from(total_accounts);
        let balance_bytes = balance_value.to_be_bytes::<32>();
        let total_supply_bytes = total_supply.to_be_bytes::<32>();
        let total_supply_slot_bytes = tip20_slots::TOTAL_SUPPLY.to_be_bytes::<32>();

        // Step 4: Stream-write the binary file in chunks
        let file = File::create(&out).wrap_err("failed to create output file")?;
        let mut writer = BufWriter::with_capacity(64 * 1024 * 1024, file); // 64MB buffer

        println!("\nGenerating and writing in {num_chunks} chunks...");

        let pb = ProgressBar::new(total_accounts as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({per_sec}) ({eta})")
                .expect("valid template"),
        );

        let mut chunk_buf = Vec::with_capacity(chunk_size.min(total_accounts) * 64);

        let mut is_first_chunk = true;

        for chunk in &(0..total_accounts).chunks(chunk_size) {
            let chunk_indices: Vec<_> = chunk.collect();
            let chunk_len = chunk_indices.len();

            // Derive addresses and compute slot bytes for this chunk only
            let slot_bytes: Vec<[u8; 32]> = chunk_indices
                .into_par_iter()
                .map(|i| {
                    let addr = if i < actual_signable {
                        let child = parent_key
                            .derive_child(i as u32)
                            .expect("child derivation should not fail");
                        let key: &coins_bip32::prelude::SigningKey = child.as_ref();
                        let credential =
                            k256::ecdsa::SigningKey::from_bytes(&key.to_bytes()).unwrap();
                        secret_key_to_address(&credential)
                    } else {
                        derive_address_fast(&seed, i as u64)
                    };
                    addr.mapping_slot(tip20_slots::BALANCES).to_be_bytes::<32>()
                })
                .collect();

            // Write one block per token for this chunk
            for (token_idx, token_addr) in token_addresses.iter().enumerate() {
                let pair_count = chunk_len as u64 + if is_first_chunk { 1 } else { 0 };

                write_header(&mut writer, *token_addr, pair_count)?;

                // Only write total_supply in the first chunk for each token
                if is_first_chunk {
                    writer.write_all(&total_supply_slot_bytes)?;
                    writer.write_all(&total_supply_bytes)?;
                }

                // Write balance entries in chunks
                chunk_buf.clear();
                for slot in &slot_bytes {
                    chunk_buf.extend_from_slice(slot);
                    chunk_buf.extend_from_slice(&balance_bytes);
                }
                writer.write_all(&chunk_buf)?;

                // Only count progress once per chunk (on the last token)
                if token_idx == token_addresses.len() - 1 {
                    pb.inc(chunk_len as u64);
                }
            }

            is_first_chunk = false;
        }

        pb.finish_with_message("done");
        write_nonce_ring(&mut writer, 0..capacity)?;
        writer.flush()?;

        let file_size = std::fs::metadata(&out)?.len();
        println!(
            "\nGenerated {} ({:.2} MiB)",
            out.display(),
            file_size as f64 / (1024.0 * 1024.0)
        );

        Ok(())
    }
}

/// Populate both mappings so the first transaction evicts an existing, expired nonce.
fn write_nonce_ring(writer: &mut impl Write, indices: std::ops::Range<u32>) -> eyre::Result<()> {
    let manager = NonceManager::new();
    write_header(
        writer,
        NONCE_PRECOMPILE_ADDRESS,
        u64::from(indices.end - indices.start) * 2,
    )?;
    let mut input = *b"tempo-state-bloat-nonce\0\0\0\0";
    let index_start = input.len() - size_of::<u32>();
    for index in indices {
        input[index_start..].copy_from_slice(&index.to_be_bytes());
        let hash = keccak256(input);
        // Compute keys without caching millions of mapping handlers.
        let ring_slot = index.mapping_slot(manager.expiring_nonce_ring.slot());
        let seen_slot = hash.mapping_slot(manager.expiring_nonce_seen.slot());
        writer.write_all(&ring_slot.to_be_bytes::<32>())?;
        writer.write_all(hash.as_slice())?;
        writer.write_all(&seen_slot.to_be_bytes::<32>())?;
        writer.write_all(&U256::ONE.to_be_bytes::<32>())?;
    }
    // The default zero pointer is the next position after filling the whole ring.
    Ok(())
}

/// Compute a reserved TIP20 token address from a token ID.
/// Reserved addresses use the TIP20 prefix with the token ID in the last 8 bytes.
fn token_address(token_id: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..12].copy_from_slice(&TIP20_PAYMENT_PREFIX);
    bytes[12..].copy_from_slice(&token_id.to_be_bytes());
    Address::from(bytes)
}

/// Fast address derivation using keccak256(seed || index).
/// This is much faster than BIP32 but the resulting addresses are NOT signable.
/// Used for generating bloat addresses beyond the signable count.
fn derive_address_fast(seed: &[u8; 32], index: u64) -> Address {
    let mut buf = [0u8; 40]; // 32 bytes seed + 8 bytes index
    buf[..32].copy_from_slice(seed);
    buf[32..].copy_from_slice(&index.to_be_bytes());
    let hash = keccak256(buf);
    // Take last 20 bytes of hash as address
    Address::from_word(hash)
}

/// Derive the parent key for BIP44 Ethereum path: m/44'/60'/0'/0
/// This performs PBKDF2 once, then subsequent child derivations are fast.
fn derive_parent_key(mnemonic_phrase: &str) -> eyre::Result<XPriv> {
    let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic_phrase)
        .map_err(|e| eyre::eyre!("invalid mnemonic: {e}"))?;

    // Derive seed from mnemonic (this is the slow PBKDF2 step)
    let master: XPriv = mnemonic
        .derive_key("m/44'/60'/0'/0", None)
        .map_err(|e| eyre::eyre!("key derivation failed: {e}"))?;

    Ok(master)
}

/// Write a block header to the output.
/// Format: `[magic:8][version:2][flags:2][address:20][pair_count:8] = 40 bytes`
fn write_header(writer: &mut impl Write, address: Address, pair_count: u64) -> eyre::Result<()> {
    writer.write_all(MAGIC)?;
    writer.write_all(&VERSION.to_be_bytes())?;
    writer.write_all(&0u16.to_be_bytes())?; // flags (reserved)
    writer.write_all(address.as_slice())?;
    writer.write_all(&pair_count.to_be_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{B256, address};
    use clap::Parser;
    use std::io::{BufReader, Seek};
    use tempo_precompiles::storage::{
        Handler, PrecompileStorageProvider, StorageCtx, hashmap::HashMapStorageProvider,
    };

    #[test]
    fn filled_nonce_ring_evicts_and_wraps() -> eyre::Result<()> {
        for hardfork in [TempoHardfork::T10, TempoHardfork::T11] {
            let capacity = hardfork.expiring_nonce_set_capacity();
            let mut file = tempfile::tempfile()?;
            {
                let mut writer = BufWriter::new(&mut file);
                // Exercise real fork boundaries without writing millions of entries per test.
                write_nonce_ring(&mut writer, 0..1)?;
                write_nonce_ring(&mut writer, capacity - 1..capacity)?;
                writer.flush()?;
            }
            assert_eq!(file.metadata()?.len(), 2 * (40 + 128));
            file.rewind()?;

            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
            storage.set_timestamp(U256::from(1000));
            let mut entry = 0u32;
            let mut old_hash = B256::ZERO;
            let manager = NonceManager::new();
            let count = crate::read_dump(BufReader::new(file), |address, slot, value| {
                assert_eq!(address, NONCE_PRECOMPILE_ADDRESS);
                let index = if entry < 2 { 0 } else { capacity - 1 };
                if entry.is_multiple_of(2) {
                    assert_eq!(
                        U256::from_be_bytes(slot.0),
                        index.mapping_slot(manager.expiring_nonce_ring.slot())
                    );
                    assert!(!value.is_zero());
                    old_hash = B256::from(value);
                } else {
                    assert_eq!(
                        U256::from_be_bytes(slot.0),
                        old_hash.mapping_slot(manager.expiring_nonce_seen.slot())
                    );
                    assert_eq!(value, U256::ONE);
                }
                storage.sstore(address, U256::from_be_bytes(slot.0), value)?;
                entry += 1;
                Ok(())
            })?;
            assert_eq!(count, 4);

            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                let mut manager = NonceManager::new();
                assert_eq!(manager.expiring_nonce_ring_ptr.read()?, 0);
                for index in [0, capacity - 1] {
                    if index != 0 {
                        manager.expiring_nonce_ring_ptr.write(index)?;
                    }
                    let old_hash = manager.expiring_nonce_ring[index].read()?;
                    assert!(!old_hash.is_zero());
                    assert_eq!(manager.expiring_nonce_seen[old_hash].read()?, 1);
                    let hash = keccak256(index.to_be_bytes());
                    manager.check_and_mark_expiring_nonce(hash, 1020)?;
                    assert_eq!(manager.expiring_nonce_seen[old_hash].read()?, 0);
                    assert_eq!(manager.expiring_nonce_ring[index].read()?, hash);
                    assert_eq!(manager.expiring_nonce_seen[hash].read()?, 1020);
                    assert_eq!(
                        manager.expiring_nonce_ring_ptr.read()?,
                        (index + 1) % capacity
                    );
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn test_token_address() {
        let addr = token_address(0);
        assert_eq!(addr, address!("0x20C0000000000000000000000000000000000000"));

        let addr = token_address(1);
        assert_eq!(addr, address!("0x20C0000000000000000000000000000000000001"));
    }

    #[test]
    fn test_header_size() {
        let mut buf = Vec::new();
        write_header(&mut buf, Address::ZERO, 100).unwrap();
        assert_eq!(buf.len(), 40);
    }

    #[test]
    fn test_derive_parent_key_matches_mnemonic_builder() {
        use alloy::signers::local::MnemonicBuilder;

        let mnemonic = "test test test test test test test test test test test junk";
        let parent_key = derive_parent_key(mnemonic).unwrap();

        // Verify first 10 addresses match MnemonicBuilder::from_phrase_nth
        for i in 0..10u32 {
            let expected = MnemonicBuilder::from_phrase_nth(mnemonic, i);

            let child = parent_key.derive_child(i).unwrap();
            let key: &coins_bip32::prelude::SigningKey = child.as_ref();
            let credential = k256::ecdsa::SigningKey::from_bytes(&key.to_bytes()).unwrap();
            let actual = secret_key_to_address(&credential);

            assert_eq!(actual, expected.address(), "address mismatch at index {i}");
        }
    }

    #[test]
    fn test_entry_size() {
        let slot = U256::ZERO.to_be_bytes::<32>();
        let value = B256::with_last_byte(1);
        assert_eq!(slot.len() + value.len(), 64);
    }

    #[derive(Parser)]
    struct GeneratorCli {
        #[command(flatten)]
        args: GenerateStateBloat,
    }

    #[tokio::test]
    async fn mnemonic_file_matches_inline_dump() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mnemonic");
        let output = directory.path().join("state.bin");
        std::fs::write(&path, format!("{mnemonic}\n")).unwrap();
        let args = [
            "generate",
            "--size",
            "1",
            "--signable-count",
            "1",
            "--nonce-ring-hardfork",
            "T10",
            "--out",
            output.to_str().unwrap(),
        ];
        GeneratorCli::parse_from(args.into_iter().chain(["--mnemonic", mnemonic]))
            .args
            .run()
            .await
            .unwrap();
        let expected = std::fs::read(&output).unwrap();
        let mut nonce_entries = 0;
        let entries = crate::read_dump(expected.as_slice(), |address, _, _| {
            nonce_entries += u64::from(address == NONCE_PRECOMPILE_ADDRESS);
            Ok(())
        })
        .unwrap();
        assert_eq!(nonce_entries, 600_000);
        assert_eq!(entries - nonce_entries, 16_383); // 1 MiB of TIP20 state is preserved.
        let file_args = || {
            GeneratorCli::parse_from(
                args.into_iter()
                    .chain(["--mnemonic-file", path.to_str().unwrap()]),
            )
            .args
        };
        file_args().run().await.unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), expected);
        assert!(
            GeneratorCli::try_parse_from(args.into_iter().chain([
                "--mnemonic",
                mnemonic,
                "--mnemonic-file",
                path.to_str().unwrap(),
            ]))
            .is_err()
        );
        std::fs::remove_file(&output).unwrap();
        std::fs::write(&path, " \n").unwrap();
        assert!(file_args().run().await.is_err());
        assert!(!output.exists());
        std::fs::remove_file(&path).unwrap();
        assert!(file_args().run().await.is_err());
        assert!(!output.exists());
    }
}
