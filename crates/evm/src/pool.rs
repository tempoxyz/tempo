use crate::TempoInvalidTransaction;
use alloy_evm::{
    Evm,
    revm::{Database, context::result::EVMError},
};
use tempo_revm::{TempoTxEnv, ValidationContext};

/// Result of validating a transaction with Tempo transaction-pool semantics.
pub type TempoPoolValidationResult<DBError> =
    Result<ValidationContext, EVMError<DBError, TempoInvalidTransaction>>;

/// An EVM that can run Tempo's transaction-pool validation lifecycle.
///
/// Implementations must run the full Tempo validation pipeline without executing the transaction
/// and apply the pool-specific semantics:
/// - skip `valid_after`, because the pool queues transactions until they become executable;
/// - disable protocol nonce checking, because the pool queues future-nonce transactions;
/// - skip the EVM liquidity check, because the pool checks liquidity against its cached AMM view;
/// - return `tx` and clear transaction-local state after both success and error;
/// - discard journaled writes (nonce updates, fee deduction, and key authorization) while retaining
///   warmed database reads for the rest of the batch.
///
/// Owning the complete lifecycle lets custom EVMs additionally clear adapter-specific state without
/// exposing their internal contexts or databases to the transaction pool.
pub trait TempoPoolValidationEvm: Evm<Tx = TempoTxEnv> {
    /// Configures this EVM for transaction-pool validation.
    fn configure_for_pool(&mut self);

    /// Validates `tx` using transaction-pool semantics and returns the transaction environment.
    fn validate_pool_transaction(
        &mut self,
        tx: TempoTxEnv,
    ) -> (
        TempoPoolValidationResult<<<Self as Evm>::DB as Database>::Error>,
        TempoTxEnv,
    );
}
