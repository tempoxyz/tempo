//! Pre-flight check for V1→V2 validator migration.
//!
//! Reads all V1 validators and reports which ones would be skipped or cause a revert
//! during `ValidatorConfigV2.migrateValidator`.
//!
//! Migration heuristics (from ValidatorConfigV2.migrateValidator):
//!   SKIP   1. publicKey == 0 OR validatorAddress == address(0)
//!   SKIP   2. Duplicate publicKey (already seen earlier in the array)
//!   SKIP   3. Active validator whose ingress hash (full ip:port) collides with an earlier active
//!   REVERT 4. Duplicate active validatorAddress (AddressAlreadyHasValidator)

use std::collections::HashSet;

use alloy::{
    primitives::{Address, B256, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use eyre::Context;
use tempo_contracts::precompiles::{
    IValidatorConfig::getValidatorsCall, VALIDATOR_CONFIG_ADDRESS,
};

#[derive(Debug, clap::Args)]
pub(crate) struct CheckV1Migration {
    /// RPC endpoint URL
    #[arg(long)]
    rpc_url: String,
}

impl CheckV1Migration {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let provider = ProviderBuilder::new()
            .connect(&self.rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let call = getValidatorsCall {};
        let tx = TransactionRequest::default()
            .to(VALIDATOR_CONFIG_ADDRESS)
            .input(call.abi_encode().into());

        let result = provider
            .call(tx)
            .await
            .wrap_err("getValidators() call failed")?;

        let validators = getValidatorsCall::abi_decode_returns(&result)
            .wrap_err("failed to decode getValidators() return data")?;

        println!("=== V1 Validator Migration Pre-Flight ===");
        println!("Total V1 validators: {}", validators.len());
        println!();

        let mut skip_count: usize = 0;
        let mut revert_count: usize = 0;
        let mut ok_count: usize = 0;

        let mut seen_pubkeys = HashSet::<B256>::new();
        let mut active_addresses = HashSet::<Address>::new();
        let mut active_ingress_hashes = HashSet::<B256>::new();

        // Process in reverse order (migration iterates N-1 down to 0)
        for ri in 0..validators.len() {
            let i = validators.len() - 1 - ri;
            let v = &validators[i];

            // Check 1: zero pubkey or zero address
            if v.publicKey == B256::ZERO || v.validatorAddress == Address::ZERO {
                println!("SKIP  [idx {i}] zero pubkey or zero address");
                println!("  addr={}", v.validatorAddress);
                println!("  pubkey={}", v.publicKey);
                skip_count += 1;
                continue;
            }

            // Check 2: duplicate pubkey
            if !seen_pubkeys.insert(v.publicKey) {
                println!("SKIP  [idx {i}] duplicate publicKey");
                println!("  addr={}", v.validatorAddress);
                println!("  pubkey={}", v.publicKey);
                skip_count += 1;
                continue;
            }

            // Check 4 (before 3): duplicate active address → REVERT
            if active_addresses.contains(&v.validatorAddress) {
                println!("REVERT [idx {i}] AddressAlreadyHasValidator (dup active address)");
                println!("  addr={}", v.validatorAddress);
                revert_count += 1;
                continue;
            }

            // Check 3: active validator with duplicate ingress hash
            if v.active {
                let ingress_hash = keccak256(v.inboundAddress.as_bytes());
                if !active_ingress_hashes.insert(ingress_hash) {
                    println!("SKIP  [idx {i}] duplicate active ingress");
                    println!("  addr={}", v.validatorAddress);
                    println!("  ingress={}", v.inboundAddress);
                    skip_count += 1;
                    continue;
                }
                active_addresses.insert(v.validatorAddress);
            }

            println!("OK    [idx {i}] {}", v.validatorAddress);
            println!("  active={} ingress={}", v.active, v.inboundAddress);
            ok_count += 1;
        }

        println!();
        println!("=== Summary ===");
        println!("OK    : {ok_count}");
        println!("SKIP  : {skip_count}");
        println!("REVERT: {revert_count}");

        if revert_count > 0 {
            println!();
            println!(
                "WARNING: {revert_count} validator(s) would cause migration to REVERT."
            );
            println!("These must be resolved in V1 before migration can proceed.");
        }

        Ok(())
    }
}
