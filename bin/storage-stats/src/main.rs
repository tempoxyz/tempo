//! CLI tool to analyze storage consumption by address in the Tempo database.
//!
//! Iterates over PlainAccountState and PlainStorageState tables and calculates
//! top consumers by size in MB, recognizing known patterns like TIP-20 tokens,
//! DEX, Fee Manager, etc.
//!
//! Generates a treemap-style chart similar to Paradigm's "Distribution of Ethereum State".

#![allow(unreachable_pub)]

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use alloy_primitives::{Address, B256, U256};
use clap::Parser;
use eyre::{Context as _, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use reth_db::{open_db_read_only, tables};
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    database::Database,
    transaction::DbTx,
};
use serde::Serialize;

/// TIP-20 symbol storage slot (slot 3 in the contract layout)
const TIP20_SYMBOL_SLOT: U256 = U256::from_limbs([3, 0, 0, 0]);

/// Known contract patterns for classification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum KnownKind {
    Tip20Token,
    Tip20Factory,
    FeeManager,
    StablecoinDex,
    Tip403Registry,
    NoncePrecompile,
    ValidatorConfig,
    AccountKeychain,
    PathUsd,
    Multicall3,
    CreateX,
    Permit2,
    Unknown,
}

impl KnownKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Tip20Token => "TIP-20 Token",
            Self::Tip20Factory => "TIP-20 Factory",
            Self::FeeManager => "Fee Manager",
            Self::StablecoinDex => "Stablecoin DEX",
            Self::Tip403Registry => "TIP-403 Registry",
            Self::NoncePrecompile => "Nonce (2D)",
            Self::ValidatorConfig => "Validator Config",
            Self::AccountKeychain => "Account Keychain",
            Self::PathUsd => "pathUSD",
            Self::Multicall3 => "Multicall3",
            Self::CreateX => "CreateX",
            Self::Permit2 => "Permit2",
            Self::Unknown => "Unknown",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            Self::Tip20Token | Self::PathUsd => "Tokens",
            Self::Tip20Factory => "Token Infrastructure",
            Self::FeeManager => "Fee Infrastructure",
            Self::StablecoinDex => "DEX",
            Self::Tip403Registry => "Compliance",
            Self::NoncePrecompile => "Account Abstraction",
            Self::ValidatorConfig => "Consensus",
            Self::AccountKeychain => "Account Abstraction",
            Self::Multicall3 | Self::CreateX | Self::Permit2 => "Utilities",
            Self::Unknown => "Other",
        }
    }
}

mod addresses {
    use alloy_primitives::{Address, address};

    pub const TIP_FEE_MANAGER: Address =
        address!("0xfeec000000000000000000000000000000000000");
    pub const PATH_USD: Address = address!("0x20C0000000000000000000000000000000000000");
    pub const TIP403_REGISTRY: Address =
        address!("0x403C000000000000000000000000000000000000");
    pub const TIP20_FACTORY: Address =
        address!("0x20FC000000000000000000000000000000000000");
    pub const STABLECOIN_DEX: Address =
        address!("0xdec0000000000000000000000000000000000000");
    pub const NONCE_PRECOMPILE: Address =
        address!("0x4E4F4E4345000000000000000000000000000000");
    pub const VALIDATOR_CONFIG: Address =
        address!("0xCCCCCCCC00000000000000000000000000000000");
    pub const ACCOUNT_KEYCHAIN: Address =
        address!("0xAAAAAAAA00000000000000000000000000000000");
    pub const MULTICALL3: Address = address!("0xcA11bde05977b3631167028862bE2a173976CA11");
    pub const CREATEX: Address = address!("0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed");
    pub const PERMIT2: Address = address!("0x000000000022d473030f116ddee9f6b43ac78ba3");

    pub const TIP20_TOKEN_PREFIX: [u8; 4] = [0x20, 0xc0, 0x00, 0x00];
    pub const TIP20_FACTORY_PREFIX: [u8; 4] = [0x20, 0xfc, 0x00, 0x00];
    pub const FEE_MANAGER_PREFIX: [u8; 4] = [0xfe, 0xec, 0x00, 0x00];
    pub const DEX_PREFIX: [u8; 4] = [0xde, 0xc0, 0x00, 0x00];
    pub const TIP403_PREFIX: [u8; 4] = [0x40, 0x3c, 0x00, 0x00];
}

fn classify_address(addr: Address) -> KnownKind {
    let bytes = addr.as_slice();

    if addr == addresses::PATH_USD {
        return KnownKind::PathUsd;
    }
    if addr == addresses::TIP_FEE_MANAGER {
        return KnownKind::FeeManager;
    }
    if addr == addresses::TIP403_REGISTRY {
        return KnownKind::Tip403Registry;
    }
    if addr == addresses::TIP20_FACTORY {
        return KnownKind::Tip20Factory;
    }
    if addr == addresses::STABLECOIN_DEX {
        return KnownKind::StablecoinDex;
    }
    if addr == addresses::NONCE_PRECOMPILE {
        return KnownKind::NoncePrecompile;
    }
    if addr == addresses::VALIDATOR_CONFIG {
        return KnownKind::ValidatorConfig;
    }
    if addr == addresses::ACCOUNT_KEYCHAIN {
        return KnownKind::AccountKeychain;
    }
    if addr == addresses::MULTICALL3 {
        return KnownKind::Multicall3;
    }
    if addr == addresses::CREATEX {
        return KnownKind::CreateX;
    }
    if addr == addresses::PERMIT2 {
        return KnownKind::Permit2;
    }

    if bytes.starts_with(&addresses::TIP20_TOKEN_PREFIX) {
        return KnownKind::Tip20Token;
    }
    if bytes.starts_with(&addresses::TIP20_FACTORY_PREFIX) {
        return KnownKind::Tip20Factory;
    }
    if bytes.starts_with(&addresses::FEE_MANAGER_PREFIX) {
        return KnownKind::FeeManager;
    }
    if bytes.starts_with(&addresses::DEX_PREFIX) {
        return KnownKind::StablecoinDex;
    }
    if bytes.starts_with(&addresses::TIP403_PREFIX) {
        return KnownKind::Tip403Registry;
    }

    KnownKind::Unknown
}

fn is_tip20_address(addr: Address) -> bool {
    addr.as_slice().starts_with(&addresses::TIP20_TOKEN_PREFIX)
}

#[derive(Debug, Default, Clone)]
pub struct Usage {
    pub account_bytes: u64,
    pub storage_bytes: u64,
    pub account_entries: u64,
    pub storage_slots: u64,
}

impl Usage {
    pub fn total_bytes(&self) -> u64 {
        self.account_bytes + self.storage_bytes
    }

    pub fn total_mb(&self) -> f64 {
        self.total_bytes() as f64 / (1024.0 * 1024.0)
    }

    pub fn storage_mb(&self) -> f64 {
        self.storage_bytes as f64 / (1024.0 * 1024.0)
    }

    pub fn account_mb(&self) -> f64 {
        self.account_bytes as f64 / (1024.0 * 1024.0)
    }
}

#[derive(Debug, Parser)]
#[command(name = "storage-stats")]
#[command(about = "Analyze storage consumption by address in the Tempo database")]
#[command(version)]
pub struct Args {
    /// Path to the database directory
    #[arg(long, short = 'd')]
    pub db: PathBuf,

    /// Number of top consumers to display
    #[arg(long, short = 'n', default_value = "50")]
    pub top: usize,

    /// Minimum size in MB to display
    #[arg(long)]
    pub min_mb: Option<f64>,

    /// Show grouped totals by contract type
    #[arg(long)]
    pub group_by_type: bool,

    /// Output format (text, csv, json, treemap)
    #[arg(long, default_value = "text")]
    pub format: OutputFormat,

    /// Number of parallel workers for symbol resolution
    #[arg(long, default_value = "8")]
    pub workers: usize,
}

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Csv,
    Json,
    Treemap,
}

#[derive(Debug, Clone, Serialize)]
struct AddressStats {
    address: String,
    kind: KnownKind,
    label: String,
    category: String,
    total_bytes: u64,
    total_mb: f64,
    storage_bytes: u64,
    storage_mb: f64,
    account_bytes: u64,
    storage_slots: u64,
    account_entries: u64,
}

#[derive(Debug, Serialize)]
struct CategoryStats {
    category: String,
    total_bytes: u64,
    total_mb: f64,
    storage_mb: f64,
    account_mb: f64,
    storage_slots: u64,
    account_entries: u64,
    children: Vec<AddressStats>,
}

#[derive(Debug, Serialize)]
struct TreemapData {
    title: String,
    total_mb: f64,
    categories: Vec<CategoryStats>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    run(&args)
}

fn run(args: &Args) -> Result<()> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(args.workers)
        .build_global()
        .ok();

    eprintln!("Opening database at: {}", args.db.display());

    let db = Arc::new(
        open_db_read_only(&args.db, Default::default())
            .wrap_err_with(|| format!("Failed to open database at {}", args.db.display()))?,
    );

    let mut per_address: HashMap<Address, Usage> = HashMap::new();

    // Scan PlainAccountState
    eprintln!("Scanning PlainAccountState...");
    let account_count = scan_accounts(&db, &mut per_address)?;
    eprintln!("  Found {} accounts", account_count);

    // Scan PlainStorageState
    eprintln!("Scanning PlainStorageState...");
    let storage_count = scan_storage(&db, &mut per_address)?;
    eprintln!("  Found {} storage slots", storage_count);

    // Collect TIP-20 addresses to resolve symbols
    let tip20_addresses: Vec<Address> = per_address
        .keys()
        .filter(|addr| is_tip20_address(**addr))
        .copied()
        .collect();

    eprintln!(
        "Resolving {} TIP-20 token symbols in parallel...",
        tip20_addresses.len()
    );

    // Resolve symbols in parallel
    let symbols = resolve_tip20_symbols_parallel(&db, &tip20_addresses)?;

    // Build results with symbols
    let mut results: Vec<AddressStats> = per_address
        .into_iter()
        .map(|(address, usage)| {
            let kind = classify_address(address);
            let label = if let Some(symbol) = symbols.get(&address) {
                symbol.clone()
            } else if kind == KnownKind::PathUsd {
                "pathUSD".to_string()
            } else {
                kind.label().to_string()
            };

            AddressStats {
                address: format!("{}", address),
                category: kind.category().to_string(),
                kind,
                label,
                total_bytes: usage.total_bytes(),
                total_mb: usage.total_mb(),
                storage_bytes: usage.storage_bytes,
                storage_mb: usage.storage_mb(),
                account_bytes: usage.account_bytes,
                storage_slots: usage.storage_slots,
                account_entries: usage.account_entries,
            }
        })
        .collect();

    if let Some(min_mb) = args.min_mb {
        results.retain(|r| r.total_mb >= min_mb);
    }

    results.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));

    if args.group_by_type {
        output_grouped_totals(args, &results);
        eprintln!();
    }

    match args.format {
        OutputFormat::Treemap => output_treemap(&results),
        _ => output_top_consumers(args, &results),
    }

    Ok(())
}

fn scan_accounts<DB: Database>(
    db: &DB,
    per_address: &mut HashMap<Address, Usage>,
) -> Result<u64> {
    let tx = db.tx().wrap_err("Failed to start read transaction")?;
    let mut cursor = tx
        .cursor_read::<tables::PlainAccountState>()
        .wrap_err("Failed to open PlainAccountState cursor")?;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );

    let mut count = 0u64;

    for entry in cursor.walk(None)? {
        let (address, account) = entry?;

        let account_size = 20u64
            + 8
            + 32
            + if account.bytecode_hash.is_some() { 32 } else { 0 };

        let usage = per_address.entry(address).or_default();
        usage.account_bytes += account_size;
        usage.account_entries += 1;

        count += 1;
        if count % 100_000 == 0 {
            pb.set_message(format!("Scanned {} accounts", count));
        }
    }

    pb.finish_and_clear();
    Ok(count)
}

fn scan_storage<DB: Database>(
    db: &DB,
    per_address: &mut HashMap<Address, Usage>,
) -> Result<u64> {
    let tx = db.tx().wrap_err("Failed to start read transaction")?;
    let mut cursor = tx
        .cursor_dup_read::<tables::PlainStorageState>()
        .wrap_err("Failed to open PlainStorageState cursor")?;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );

    let mut count = 0u64;

    for entry in cursor.walk_dup(None, None)? {
        let (address, _storage_entry) = entry?;

        let entry_size = 64u64;

        let usage = per_address.entry(address).or_default();
        usage.storage_bytes += entry_size;
        usage.storage_slots += 1;

        if usage.storage_slots == 1 {
            usage.storage_bytes += 20;
        }

        count += 1;
        if count % 1_000_000 == 0 {
            pb.set_message(format!("Scanned {} storage slots", count));
        }
    }

    pb.finish_and_clear();
    Ok(count)
}

/// Resolve TIP-20 symbols in parallel by reading from storage slot 3
fn resolve_tip20_symbols_parallel<DB: Database + Sync>(
    db: &Arc<DB>,
    addresses: &[Address],
) -> Result<HashMap<Address, String>> {
    let results: Arc<Mutex<HashMap<Address, String>>> = Arc::new(Mutex::new(HashMap::new()));

    let pb = ProgressBar::new(addresses.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    addresses.par_iter().for_each(|&addr| {
        if let Ok(symbol) = read_tip20_symbol(db, addr) {
            if !symbol.is_empty() {
                results.lock().unwrap().insert(addr, symbol);
            }
        }
        pb.inc(1);
    });

    pb.finish_and_clear();

    let map = Arc::try_unwrap(results)
        .map_err(|_| eyre::eyre!("Failed to unwrap results"))?
        .into_inner()
        .map_err(|e| eyre::eyre!("Mutex poisoned: {}", e))?;

    Ok(map)
}

/// Read TIP-20 symbol from storage slot 3
fn read_tip20_symbol<DB: Database>(db: &DB, token_address: Address) -> Result<String> {
    let tx = db.tx()?;
    let mut cursor = tx.cursor_dup_read::<tables::PlainStorageState>()?;

    // Symbol is stored at slot 3 in TIP-20 contracts
    // For short strings (<=31 bytes), the data is stored inline:
    // - Bytes 0..len: UTF-8 string data (left-aligned)
    // - Byte 31 (LSB): length * 2

    if let Some(entry) = cursor.seek_by_key_subkey(token_address, B256::from(TIP20_SYMBOL_SLOT))? {
        let value = entry.value;
        let bytes = value.to_be_bytes::<32>();

        // Check if it's a short string (bit 0 of LSB is 0)
        let lsb = bytes[31];
        if lsb & 1 == 0 {
            let length = (lsb / 2) as usize;
            if length <= 31 {
                let s = String::from_utf8_lossy(&bytes[..length]);
                return Ok(s.to_string());
            }
        }
        // Long strings would need keccak256-based lookup, skip for now
    }

    Ok(String::new())
}

fn output_grouped_totals(args: &Args, results: &[AddressStats]) {
    let mut by_kind: HashMap<String, Usage> = HashMap::new();

    for r in results {
        let group = by_kind.entry(r.kind.label().to_string()).or_default();
        group.account_bytes += r.account_bytes;
        group.storage_bytes += r.storage_bytes;
        group.account_entries += r.account_entries;
        group.storage_slots += r.storage_slots;
    }

    let mut grouped: Vec<_> = by_kind.into_iter().collect();
    grouped.sort_by(|a, b| b.1.total_bytes().cmp(&a.1.total_bytes()));

    match args.format {
        OutputFormat::Text | OutputFormat::Treemap => {
            println!("\n=== Storage by Contract Type ===\n");
            println!(
                "{:<20} {:>12} {:>12} {:>12} {:>12} {:>10}",
                "Type", "Total (MB)", "Storage", "Account", "Slots", "Accounts"
            );
            println!("{}", "-".repeat(80));

            for (kind, usage) in &grouped {
                println!(
                    "{:<20} {:>12.3} {:>12.3} {:>12.3} {:>12} {:>10}",
                    kind,
                    usage.total_mb(),
                    usage.storage_mb(),
                    usage.account_mb(),
                    usage.storage_slots,
                    usage.account_entries,
                );
            }

            let total_usage = grouped.iter().fold(Usage::default(), |mut acc, (_, u)| {
                acc.account_bytes += u.account_bytes;
                acc.storage_bytes += u.storage_bytes;
                acc.account_entries += u.account_entries;
                acc.storage_slots += u.storage_slots;
                acc
            });

            println!("{}", "-".repeat(80));
            println!(
                "{:<20} {:>12.3} {:>12.3} {:>12.3} {:>12} {:>10}",
                "TOTAL",
                total_usage.total_mb(),
                total_usage.storage_mb(),
                total_usage.account_mb(),
                total_usage.storage_slots,
                total_usage.account_entries,
            );
        }
        OutputFormat::Csv => {
            println!("type,total_mb,storage_mb,account_mb,storage_slots,account_entries");
            for (kind, usage) in &grouped {
                println!(
                    "{},{:.3},{:.3},{:.3},{},{}",
                    kind,
                    usage.total_mb(),
                    usage.storage_mb(),
                    usage.account_mb(),
                    usage.storage_slots,
                    usage.account_entries,
                );
            }
        }
        OutputFormat::Json => {
            let json_data: Vec<_> = grouped
                .iter()
                .map(|(kind, usage)| {
                    serde_json::json!({
                        "type": kind,
                        "total_mb": usage.total_mb(),
                        "storage_mb": usage.storage_mb(),
                        "account_mb": usage.account_mb(),
                        "storage_slots": usage.storage_slots,
                        "account_entries": usage.account_entries,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json_data).unwrap_or_default()
            );
        }
    }
}

fn output_top_consumers(args: &Args, results: &[AddressStats]) {
    let top_n: Vec<_> = results.iter().take(args.top).collect();

    match args.format {
        OutputFormat::Text | OutputFormat::Treemap => {
            println!("\n=== Top {} Storage Consumers ===\n", args.top);
            println!(
                "{:>4} {:<44} {:<18} {:>12} {:>12} {:>10}",
                "Rank", "Address", "Label", "Total (MB)", "Storage", "Slots"
            );
            println!("{}", "-".repeat(104));

            for (i, r) in top_n.iter().enumerate() {
                let label = if r.label.len() > 17 {
                    format!("{}...", &r.label[..14])
                } else {
                    r.label.clone()
                };
                println!(
                    "{:>4} {:<44} {:<18} {:>12.3} {:>12.3} {:>10}",
                    i + 1,
                    r.address,
                    label,
                    r.total_mb,
                    r.storage_mb,
                    r.storage_slots,
                );
            }
        }
        OutputFormat::Csv => {
            println!("rank,address,label,category,total_mb,storage_mb,account_mb,storage_slots");
            for (i, r) in top_n.iter().enumerate() {
                println!(
                    "{},{},{},{},{:.3},{:.3},{:.3},{}",
                    i + 1,
                    r.address,
                    r.label,
                    r.category,
                    r.total_mb,
                    r.storage_mb,
                    r.account_bytes as f64 / (1024.0 * 1024.0),
                    r.storage_slots,
                );
            }
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&top_n).unwrap_or_default()
            );
        }
    }
}

fn output_treemap(results: &[AddressStats]) {
    // Group by category
    let mut categories: HashMap<String, Vec<&AddressStats>> = HashMap::new();
    for r in results {
        categories.entry(r.category.clone()).or_default().push(r);
    }

    let mut category_stats: Vec<CategoryStats> = categories
        .into_iter()
        .map(|(category, items)| {
            let total_bytes: u64 = items.iter().map(|i| i.total_bytes).sum();
            let storage_bytes: u64 = items.iter().map(|i| i.storage_bytes).sum();
            let account_bytes: u64 = items.iter().map(|i| i.account_bytes).sum();
            let storage_slots: u64 = items.iter().map(|i| i.storage_slots).sum();
            let account_entries: u64 = items.iter().map(|i| i.account_entries).sum();

            let mut children: Vec<AddressStats> = items
                .into_iter()
                .cloned()
                .collect();
            children.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
            children.truncate(20); // Top 20 per category

            CategoryStats {
                category,
                total_bytes,
                total_mb: total_bytes as f64 / (1024.0 * 1024.0),
                storage_mb: storage_bytes as f64 / (1024.0 * 1024.0),
                account_mb: account_bytes as f64 / (1024.0 * 1024.0),
                storage_slots,
                account_entries,
                children,
            }
        })
        .collect();

    category_stats.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));

    let total_mb: f64 = category_stats.iter().map(|c| c.total_mb).sum();

    let treemap = TreemapData {
        title: "Distribution of Tempo State".to_string(),
        total_mb,
        categories: category_stats,
    };

    // Print JSON for treemap visualization
    println!("{}", serde_json::to_string_pretty(&treemap).unwrap_or_default());

    // Also print a text-based treemap representation
    eprintln!("\n=== Distribution of Tempo State ({:.2} MB total) ===\n", total_mb);
    
    for cat in &treemap.categories {
        let pct = (cat.total_mb / total_mb) * 100.0;
        let bar_len = (pct / 2.0).round() as usize;
        let bar: String = "█".repeat(bar_len.min(50));
        
        eprintln!(
            "{:<25} {:>8.2} MB ({:>5.1}%) {}",
            cat.category,
            cat.total_mb,
            pct,
            bar
        );

        // Show top 5 children
        for child in cat.children.iter().take(5) {
            let child_pct = (child.total_mb / total_mb) * 100.0;
            eprintln!(
                "  └─ {:<21} {:>8.2} MB ({:>5.1}%)",
                if child.label.len() > 21 {
                    format!("{}...", &child.label[..18])
                } else {
                    child.label.clone()
                },
                child.total_mb,
                child_pct
            );
        }
        if cat.children.len() > 5 {
            eprintln!("     ... and {} more", cat.children.len() - 5);
        }
        eprintln!();
    }
}
