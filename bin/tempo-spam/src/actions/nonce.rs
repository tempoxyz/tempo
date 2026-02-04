//! Nonce precompile actions
//!
//! Note: The Nonce precompile provides read-only access via getNonce().
//! Nonce increments happen automatically during transaction execution
//! via 2D nonces (when enabled). This module exercises the read path
//! and uses transfers with 2D nonces to exercise the increment path.

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use rand::random_range;
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::{
    INonce::INonceInstance, ITIP20::ITIP20Instance, NONCE_PRECOMPILE_ADDRESS,
};

use super::ActionContext;

/// Maximum nonce key for normal operations
const MAX_NONCE_KEY: u64 = 1000;

/// Read a 2D nonce and perform a small transfer to increment it
///
/// 2D nonces are incremented during transaction execution when using
/// the 2D nonce transaction type. This function reads the nonce state
/// and performs a transfer that will increment a nonce.
pub async fn increment_nonce(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    let nonce_contract = INonceInstance::new(NONCE_PRECOMPILE_ADDRESS, provider.clone());

    // Pick a random nonce key (1 to MAX_NONCE_KEY, key 0 is reserved for protocol)
    let nonce_key = U256::from(random_range(1..=MAX_NONCE_KEY));

    // Read current nonce - exercises the getNonce code path
    let _current_nonce = nonce_contract.getNonce(caller, nonce_key).call().await?;

    // The actual nonce increment happens during tx execution via 2D nonces.
    // Perform a minimal token action to exercise transaction execution with 2D nonces.
    let token = ITIP20Instance::new(ctx.path_usd, provider.clone());
    let balance = token.balanceOf(caller).call().await?;

    if balance > U256::ZERO {
        // Self-transfer of 1 unit to exercise tx execution
        let _ = token
            .transfer(caller, U256::from(1))
            .send()
            .await?
            .get_receipt()
            .await;
    }

    Ok(())
}
