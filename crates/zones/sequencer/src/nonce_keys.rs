//! Nonce key constants for zone sequencer L1 operations.
//!
//! Hankie's pool currently admits protocol nonce key 0 only, so all sequencer
//! L1 operations share key 0 on this branch.

use alloy_primitives::U256;

/// Nonce key for `submitBatch` calls.
pub const SUBMIT_BATCH_NONCE_KEY: U256 = U256::ZERO;

/// Nonce key for `processWithdrawals` calls.
pub const PROCESS_WITHDRAWAL_NONCE_KEY: U256 = U256::ZERO;

/// Nonce key for admin operations (`enableToken`, `setZoneGasRate`, `setMaxTempoGasRate`,
/// `setBouncebackGas`, `setSequencerEncryptionKey`, `pause`, `abdicate`,
/// `pauseDeposits`, `resumeDeposits`).
pub const ADMIN_OPS_NONCE_KEY: U256 = U256::ZERO;
