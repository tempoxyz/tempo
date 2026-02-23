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
//! ## Localnet-only tests (`localnet.rs`)
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

pub(crate) mod helpers;
mod runners;

pub(crate) mod types;
use types::TestEnv;

mod localnet;
mod testnet;

/// Run all matrix tests and scenario runners against a single environment.
async fn run_all_matrices(env: &mut impl TestEnv) -> eyre::Result<()> {
    env.run_send_matrix().await?;
    env.run_raw_send_matrix().await?;
    env.run_estimate_gas_matrix().await?;
    env.run_fill_transaction_matrix().await?;
    env.run_fill_sign_send_matrix().await?;
    env.run_fee_payer_cosign_scenario().await?;
    env.run_authorization_list_scenario().await?;
    env.run_keychain_auth_list_skipped_scenario().await?;
    env.run_keychain_expiry_scenario().await?;
    env.run_create_contract_address_scenario().await?;
    env.run_send_negative_scenario().await?;
    env.run_nonce_rejection_scenario().await?;
    env.run_fee_payer_negative_scenario().await?;
    env.run_gas_fee_boundary_scenario().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_matrices_local() -> eyre::Result<()> {
    run_all_matrices(&mut helpers::Localnet::new().await?).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_matrices_testnet() -> eyre::Result<()> {
    run_all_matrices(&mut testnet::Testnet::new().await?).await
}
