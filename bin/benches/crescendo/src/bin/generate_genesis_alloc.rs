use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use alloy::signers::local::MnemonicBuilder;
use alloy::signers::utils::secret_key_to_address;
use alloy_signer_local::coins_bip39::English;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use simple_tqdm::ParTqdm;

#[derive(Debug, Serialize, Deserialize)]
struct AccountBalance {
    balance: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const NUM_ACCOUNTS: u32 = 50_000;
    const MNEMONIC: &str = "test test test test test test test test test test test junk";

    println!("Generating {NUM_ACCOUNTS} accounts...");

    let genesis_alloc: BTreeMap<String, AccountBalance> = (0..NUM_ACCOUNTS)
        .into_par_iter()
        .tqdm()
        .map(|worker_id| {
            let signer =
                MnemonicBuilder::<English>::default().phrase(MNEMONIC).index(worker_id).unwrap().build().unwrap();

            let address = secret_key_to_address(signer.credential());

            (format!("{address:?}"), AccountBalance { balance: "0xD3C21BCECCEDA1000000".to_string() })
        })
        .collect();

    let output_path = Path::new("genesis-alloc.json");
    let json = serde_json::to_string_pretty(&genesis_alloc)?;
    fs::write(output_path, json)?;

    println!("\nSuccessfully generated {NUM_ACCOUNTS} accounts!");
    println!("Accounts saved to: {}", output_path.display());

    Ok(())
}
