//! Tempo transaction integration tests.
//!
//! ## Generic tests (run on both localnet and testnet via `TestEnv`)
//!
//! RPC Matrices (`runners.rs`)
//!
//! - eth_sendRawTransaction: key type × fee payer × key setup (root key, access key with
//!   spending limits/expiry, zero pubkey, duplicate auth, unauthorized authorize, unauthorized
//!   key, invalid auth signature) × sync × test actions (no-op, empty, invalid create, transfer,
//!   admin call) × chain ID validation.
//! - eth_sendTransaction: key type (P256/WebAuthn) × fee payer × access key × batch calls;
//!   secp256k1 × fee payer.
//! - eth_fillTransaction: nonceKey + validBefore + validAfter + feeToken + fee payer.
//! - eth_estimateGas: key type + keychain + key auth overhead.
//! - E2E fill → sign → send: nonce modes × key types × pre-bumped protocol nonces.
//!
//! Scenario runners (`runners.rs`)
//!
//! - Sponsored raw tx flow (fee payer cosigning via fee_payer_signature_hash + sign_fee_payer).
//! - EIP-7702 authorization list (secp256k1 + P256 + WebAuthn delegation).
//! - Keychain authorization in auth list is skipped (attack prevention).
//! - Keychain expiry (never-expires, short-expiry, expired, past-expiry).
//! - Contract creation address correctness.
//!
//! ## Localnet-only tests (`local.rs`)
//!
//! All local matrix tests are parameterized over [`ForkSchedule`](crate::utils::ForkSchedule)
//! (Devnet / Testnet / Mainnet) via `test_case`.
//!
//! These tests require pool introspection, controlled block mining, or P2P networking:
//!
//! - 2D nonce pool ordering and comprehensive pool routing.
//! - 2D nonce out-of-order arrival.
//! - WebAuthn signature negative cases.
//! - Transaction propagation across 2D nonce channels.
//! - Keychain revocation TOCTOU DoS.
//! - Expiring nonce replay protection.
//! - Keychain spending limit TOCTOU DoS.

use crate::utils::ForkSchedule;
use test_case::test_case;

pub(crate) mod helpers;
mod runners;

pub(crate) mod types;
use types::TestEnv;

mod local;
mod testnet;

/// Run all matrix tests and scenario runners against a single environment.
async fn run_all_matrices(env: &mut impl TestEnv) -> eyre::Result<()> {
    // TODO(rusowsky): remove `skip_pre_t1c` and `check` after T1C activation on all networks
    let skip_pre_t1c = !env.hardfork().is_t1c();

    let check = |r: eyre::Result<()>| match r {
        Err(e)
            if skip_pre_t1c
                && (e.to_string().contains("not valid before T1C activation")
                    || e.to_string()
                        .contains("failed to decode signed transaction")) =>
        {
            eprintln!("SKIPPED: network is pre-T1C");
            Ok(())
        }
        other => other,
    };

    check(env.run_send_matrix().await)?;
    check(env.run_raw_send_matrix().await)?;
    check(env.run_fill_transaction_matrix().await)?;
    check(env.run_fill_sign_send_matrix().await)?;
    check(env.run_fee_payer_cosign_scenario().await)?;
    check(env.run_authorization_list_scenario().await)?;
    check(env.run_keychain_auth_list_skipped_scenario().await)?;
    check(env.run_keychain_expiry_scenario().await)?;
    check(env.run_create_contract_address_scenario().await)?;
    check(env.run_send_negative_scenario().await)?;
    check(env.run_nonce_rejection_scenario().await)?;
    check(env.run_fee_payer_negative_scenario().await)?;
    check(env.run_gas_fee_boundary_scenario().await)?;
    Ok(())
}

#[test_case(ForkSchedule::Devnet ; "devnet")]
#[test_case(ForkSchedule::Testnet ; "testnet")]
#[test_case(ForkSchedule::Mainnet ; "mainnet")]
#[tokio::test(flavor = "multi_thread")]
async fn test_matrices_local(schedule: ForkSchedule) -> eyre::Result<()> {
    run_all_matrices(&mut local::Localnet::with_schedule(schedule).await?).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gas_estimation_snapshots() -> eyre::Result<()> {
    // Auth group from case name. All `key_auth_*` variants collapse into "key_auth".
    fn group_of(k: &str) -> &str {
        let prefix = k.split("::").next().unwrap_or(k);
        if prefix.starts_with("key_auth") {
            "key_auth"
        } else {
            prefix
        }
    }

    let mut localnet = local::Localnet::new().await?;
    let results = localnet.run_estimate_gas_matrix().await?;
    let gas_estimation: indexmap::IndexMap<String, u64> = results.into_iter().collect();

    // Cheapest noop per group — used to order groups.
    let mut noop_gas: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for (k, &v) in gas_estimation
        .iter()
        .filter(|(k, _)| k.ends_with("::noop") || *k == "baseline")
    {
        noop_gas
            .entry(group_of(k).to_string())
            .and_modify(|e| *e = (*e).min(v))
            .or_insert(v);
    }

    // baseline → groups by cheapest noop → gas ascending within group.
    let mut gas_estimation = gas_estimation;
    gas_estimation.sort_by(|k1, v1, k2, v2| match (k1.as_str(), k2.as_str()) {
        ("baseline", _) => std::cmp::Ordering::Less,
        (_, "baseline") => std::cmp::Ordering::Greater,
        _ => {
            let (g1, g2) = (group_of(k1), group_of(k2));
            let ng = |g: &str| noop_gas.get(g).copied().unwrap_or(u64::MAX);
            ng(g1).cmp(&ng(g2)).then(g1.cmp(g2)).then(v1.cmp(v2))
        }
    });

    insta::assert_yaml_snapshot!(gas_estimation);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_matrices_testnet() -> eyre::Result<()> {
    let mut env = testnet::Testnet::new().await?;

    run_all_matrices(&mut env).await?;
    env.run_estimate_gas_matrix().await?;

    Ok(())
}
