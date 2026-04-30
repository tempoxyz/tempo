//! State bloat generation tool for generating large TIP20 storage state files.
//!
//! Generates a binary file containing TIP20 storage slots (total_supply + balances)
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
use tempo_precompiles::tip20::tip20_slots;
use tempo_primitives::transaction::TIP20_PAYMENT_PREFIX;

/// Magic bytes for the state bloat binary format (8 bytes)
const MAGIC: &[u8; 8] = b"TEMPOSB\x00";

/// Format version
const VERSION: u16 = 1;

/// Default chunk size: 256k entries per chunk (~16 MiB memory)
const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Generate state bloat file
#[derive(Debug, clap::Args)]
pub(crate) struct GenerateStateBloat {
    /// Mnemonic to use for account generation
    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,

    /// Target file size in MiB
    #[arg(short, long, default_value = "1024")]
    size: u64,

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
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            mnemonic,
            size,
            token: tokens,
            out,
            balance,
            signable_count,
            chunk_size,
        } = self;

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
        println!("  Estimated file size: {estimated_size_mib:.2} MiB");
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
                    compute_mapping_slot(addr, tip20_slots::BALANCES).to_be_bytes::<32>()
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

        writer.flush()?;
        pb.finish_with_message("done");

        let file_size = std::fs::metadata(&out)?.len();
        println!(
            "\nGenerated {} ({:.2} MiB)",
            out.display(),
            file_size as f64 / (1024.0 * 1024.0)
        );

        Ok(())
    }
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
    Address::from_slice(&hash[12..])
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

/// Compute a Solidity mapping slot: keccak256(pad32(key) || pad32(base_slot))
fn compute_mapping_slot(key: Address, base_slot: U256) -> U256 {
    let mut buf = [0u8; 64];
    // Left-pad address to 32 bytes
    buf[12..32].copy_from_slice(key.as_slice());
    // Base slot as big-endian 32 bytes
    buf[32..].copy_from_slice(&base_slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
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

    #[test]
    fn test_token_address() {
        let addr = token_address(0);
        assert_eq!(
            addr,
            "0x20C0000000000000000000000000000000000000"
                .parse::<Address>()
                .unwrap()
        );

        let addr = token_address(1);
        assert_eq!(
            addr,
            "0x20C0000000000000000000000000000000000001"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn test_compute_mapping_slot() {
        // Verify the slot computation matches Solidity's keccak256(abi.encode(key, slot))
        let addr: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let slot = compute_mapping_slot(addr, tip20_slots::BALANCES);

        // The slot should be deterministic
        let slot2 = compute_mapping_slot(addr, tip20_slots::BALANCES);
        assert_eq!(slot, slot2);

        // Different addresses should produce different slots
        let other_addr: Address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
            .parse()
            .unwrap();
        let other_slot = compute_mapping_slot(other_addr, tip20_slots::BALANCES);
        assert_ne!(slot, other_slot);
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
        let value = U256::from(1).to_be_bytes::<32>();
        assert_eq!(slot.len() + value.len(), 64);
    }
}
