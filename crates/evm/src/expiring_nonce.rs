use crate::{TempoEvmTypes, TempoInvalidTransaction};
use alloy_primitives::B256;
use core::fmt::Debug;
use evm2::{
    Evm,
    registry::{HandlerError, HandlerResult},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::NonceError;
use tempo_precompiles::{
    error::TempoPrecompileError,
    nonce::NonceManager,
    storage::{Handler as _, StorageCtx},
};

/// Validated expiring nonce entry produced by an expiring-nonce AA transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExpiringNonce {
    /// Replay-protection hash (`unique_tx_identifier` at T1B+, `tx_hash` before T1B).
    pub hash: B256,
    /// Upper-bound expiry timestamp from the transaction's `valid_before` field.
    pub valid_before: u64,
}

/// Pluggable replay-protection hooks for expiring-nonce AA transactions.
///
/// Shared validation (pre-T12 `nonce == 0`, presence of `valid_before`, and the active fork's
/// expiry window `timestamp < valid_before <= timestamp + max_expiry_secs`) runs in the AA
/// handler before delegating to [`Self::check`].
///
/// Implementations follow a two-phase lifecycle:
/// - [`Self::check`] runs during AA transaction preparation (`apply_nonce`).
/// - [`Self::commit`] runs only when the transaction actually commits in a block executor, or
///   when a direct `evm.transact()` caller commits the returned
///   [`crate::TempoTxResultExt::expiring_nonce`].
///
/// In-state implementations (such as [`TempoExpiringNonceManager`]) stage storage writes inside
/// EVM `PendingState` during [`Self::check`], where failed validation or uncommitted execution
/// automatically discards them, and leave [`Self::commit`] as a no-op.
///
/// Out-of-state implementations must not mutate external state during [`Self::check`] so failed
/// validation, simulations, and uncommitted speculative executions cannot pollute the replay set.
/// They record the entry in [`Self::commit`] instead.
pub trait ExpiringNonceManager: Debug + Send + Sync {
    /// Checks replay protection for `nonce` during AA transaction preparation.
    ///
    /// `host` provides the active spec, block timestamp, and EVM storage for in-state
    /// implementations. `ring_offset` is an optional prewarming slot offset used by the in-state
    /// circular buffer; out-of-state implementations may ignore it.
    ///
    /// Returns [`TempoInvalidTransaction::ExpiringNonceReplay`] (wrapped in [`HandlerError`]) when
    /// `nonce.hash` has already been seen and has not expired.
    fn check(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        nonce: ExpiringNonce,
        ring_offset: Option<usize>,
    ) -> HandlerResult<()>;

    /// Commits a validated expiring nonce when the transaction is accepted into a block or stream.
    ///
    /// Called by [`crate::TempoBlockExecutor`] and `ZoneBlockExecutor` when committing a
    /// transaction whose [`crate::TempoTxResultExt::expiring_nonce`] is `Some`. Direct
    /// `evm.transact()` callers outside a block executor must invoke this (or record
    /// `result.ext.expiring_nonce` themselves) after committing the transaction.
    ///
    /// The default implementation is a no-op for in-state managers whose writes are committed via
    /// EVM `PendingState`.
    fn commit(
        &self,
        _nonce: ExpiringNonce,
        _timestamp: u64,
        _spec: TempoHardfork,
    ) -> HandlerResult<()> {
        Ok(())
    }
}

/// Default expiring nonce manager backed by the in-state [`NonceManager`] circular buffer.
///
/// Stages the precompile storage writes into EVM `PendingState` during [`Self::check`] so that
/// raw `evm.transact()` callers, `eth_simulateV1`/`tempo_simulateV1`, BAL `BlockAccessIndex`
/// attribution, and `StorageActionReplay` observe a single atomic transaction diff. Failed
/// validation or discarded execution clears `PendingState`, and [`Self::commit`] is a no-op.
#[derive(Debug, Clone, Copy, Default)]
pub struct TempoExpiringNonceManager;

impl TempoExpiringNonceManager {
    /// Creates the default Tempo expiring nonce manager.
    pub const fn new() -> Self {
        Self
    }
}

impl ExpiringNonceManager for TempoExpiringNonceManager {
    fn check(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        nonce: ExpiringNonce,
        ring_offset: Option<usize>,
    ) -> HandlerResult<()> {
        let capacity = host.config_spec_id().expiring_nonce_set_capacity();
        StorageCtx::enter_evm_without_tip1060_accounting(host, || {
            let mut nonces = NonceManager::new();
            let previous_pointer = if let Some(index) = ring_offset {
                let pointer = nonces.expiring_nonce_ring_ptr.read().map_err(nonce_error)?;
                nonces
                    .expiring_nonce_ring_ptr
                    .write((pointer + index as u32) % capacity)
                    .map_err(nonce_error)?;
                Some(pointer)
            } else {
                None
            };
            nonces
                .check_and_mark_expiring_nonce(nonce.hash, nonce.valid_before)
                .map_err(|error| match error {
                    TempoPrecompileError::Database(_) | TempoPrecompileError::Fatal(_) => {
                        error.into()
                    }
                    TempoPrecompileError::NonceError(NonceError::ExpiringNonceReplay(_)) => {
                        TempoInvalidTransaction::ExpiringNonceReplay.into()
                    }
                    error => nonce_error(error),
                })?;
            if let Some(pointer) = previous_pointer {
                nonces
                    .expiring_nonce_ring_ptr
                    .write(pointer)
                    .map_err(nonce_error)?;
            }
            Ok(())
        })
    }
}

fn nonce_error(error: TempoPrecompileError) -> HandlerError {
    match error {
        TempoPrecompileError::Database(_) | TempoPrecompileError::Fatal(_) => error.into(),
        error => TempoInvalidTransaction::NonceManagerError(error.to_string()).into(),
    }
}
