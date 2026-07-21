use crate::TempoInvalidTransaction;
use alloy_evm::{Evm, revm::context::result::EVMError};
use tempo_revm::{TempoTxEnv, ValidationContext};

/// An EVM that can run Tempo's transaction-pool validation lifecycle.
///
/// Implementations must run the full Tempo validation pipeline without executing the transaction
/// and apply the pool-specific semantics:
/// - skip `valid_after`, because the pool queues transactions until they become executable;
/// - disable protocol nonce checking, because the pool queues future-nonce transactions;
/// - skip the EVM liquidity check, because the pool checks liquidity against its cached AMM view;
/// - restore `tx` and clear transaction-local state after both success and error;
/// - discard journaled writes (nonce updates, fee deduction, and key authorization) while retaining
///   warmed database reads for the rest of the batch.
///
/// Owning the complete lifecycle lets custom EVMs additionally clear adapter-specific state without
/// exposing their internal contexts or databases to the transaction pool.
pub trait TempoPoolValidationEvm: Evm<Tx = TempoTxEnv> {
    /// Validates `tx` using transaction-pool semantics.
    fn validate_pool_transaction(
        &mut self,
        tx: TempoTxEnv,
    ) -> Result<
        ValidationContext,
        EVMError<<<Self as Evm>::DB as alloy_evm::revm::Database>::Error, TempoInvalidTransaction>,
    >;
}
