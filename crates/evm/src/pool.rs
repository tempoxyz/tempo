use crate::TempoTxEnv;
use alloy_primitives::Address;
use evm2::{AnyError, registry::HandlerError};

/// Error returned while validating a transaction with Tempo transaction-pool semantics.
#[derive(Debug)]
pub enum TempoPoolValidationError {
    /// A fatal host or database error.
    Fatal(AnyError),
    /// A transaction validation error.
    Invalid(HandlerError),
}

/// Context resolved by transaction-pool validation.
#[derive(Debug, Clone)]
pub struct ValidationContext {
    /// The fee token used to pay for this transaction.
    pub fee_token: Address,
    /// Expiry of the access key used or authorized by this transaction.
    pub key_expiry: Option<u64>,
}

/// Result of validating a transaction with Tempo transaction-pool semantics.
pub type TempoPoolValidationResult = Result<ValidationContext, TempoPoolValidationError>;

/// An EVM that can run Tempo's transaction-pool validation lifecycle.
///
/// Implementations must run the full Tempo validation pipeline without executing the transaction
/// and apply the pool-specific semantics:
/// - skip `valid_after`, because the pool queues transactions until they become executable;
/// - disable protocol nonce checking, because the pool queues future-nonce transactions;
/// - disable the block base-fee check, because pool admission enforces the T7 fee floor;
/// - skip the EVM liquidity check, because the pool checks liquidity against its cached AMM view;
/// - discard journaled writes (nonce updates, fee deduction, and key authorization).
///
/// Each validation returns the transaction and clears transaction-local state on both success
/// and error. Loaded database reads remain cached for subsequent transactions in the batch.
pub trait TempoPoolValidationEvm: reth_evm::Evm<Transaction = TempoTxEnv> {
    /// Configures Tempo's pool-only validation flags.
    ///
    /// The factory must also disable nonce and base-fee checks in the EVM environment.
    fn configure_for_pool(&mut self);

    /// Validates `tx` using transaction-pool semantics.
    fn validate_pool_transaction(
        &mut self,
        tx: TempoTxEnv,
    ) -> (TempoPoolValidationResult, TempoTxEnv);
}
