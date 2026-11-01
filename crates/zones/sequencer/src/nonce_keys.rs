//! Nonce key constants for zone sequencer L1 operations.
//!
//! Tempo's 2D nonce system allows each account to maintain independent nonce
//! counters ("lanes") keyed by a `U256` nonce key. Each sequencer operation
//! type uses a dedicated lane so that `submitBatch`, `processWithdrawals`, and
//! admin transactions can be submitted concurrently without nonce contention.
//!
//! Nonce management is handled by [`NonceKeyFiller`](tempo_alloy::fillers::NonceKeyFiller)
//! in the provider pipeline — callers only need to set `.nonce_key(KEY)` on
//! each contract call.

use alloy_primitives::{U256, uint};

/// Nonce key for `submitBatch` calls (highest throughput, one per batch cycle).
pub const SUBMIT_BATCH_NONCE_KEY: U256 = uint!(1_U256);

/// Nonce key for `processWithdrawals` calls (high throughput, N per batch).
pub const PROCESS_WITHDRAWAL_NONCE_KEY: U256 = uint!(2_U256);

/// Nonce key for admin operations (`enableToken`, `setZoneGasRate`, `setMaxTempoGasRate`,
/// `setBouncebackGas`, `setSequencerEncryptionKey`, `pause`, `abdicate`,
/// `pauseDeposits`, `resumeDeposits`). Low
/// frequency, shared key.
pub const ADMIN_OPS_NONCE_KEY: U256 = uint!(3_U256);
