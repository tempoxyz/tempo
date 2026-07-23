use crate::{TempoEvmTypes, TempoTxEnv};
use alloy_consensus::transaction::Recovered;
use alloy_primitives::Address;
use evm2::{AnyError, Evm, registry::HandlerError};

/// Error returned while validating a transaction with Tempo transaction-pool semantics.
#[derive(Debug)]
pub enum TempoPoolValidationError {
    /// A fatal host or database error.
    Fatal(AnyError),
    /// A transaction validation error.
    Invalid(HandlerError),
}

/// An EVM that can run Tempo's transaction-pool validation lifecycle.
///
/// Implementations must run the full Tempo validation pipeline without executing the transaction
/// and apply the pool-specific semantics:
/// - skip `valid_after`, because the pool queues transactions until they become executable;
/// - skip the EVM liquidity check, because the pool checks liquidity against its cached AMM view;
/// - discard journaled writes (nonce updates, fee deduction, and key authorization).
pub trait TempoPoolValidationEvm {
    /// Validates `tx` using transaction-pool semantics.
    fn validate_pool_transaction(
        &mut self,
        tx: &Recovered<TempoTxEnv>,
    ) -> Result<(Address, Option<u64>), TempoPoolValidationError>;
}

impl TempoPoolValidationEvm for Evm<'_, TempoEvmTypes> {
    fn validate_pool_transaction(
        &mut self,
        tx: &Recovered<TempoTxEnv>,
    ) -> Result<(Address, Option<u64>), TempoPoolValidationError> {
        self.ext_mut().skip_valid_after_check = true;
        self.ext_mut().skip_liquidity_check = true;

        if let Err(err) = self.transact(tx).map(|executed| executed.discard()) {
            return match err {
                HandlerError::Fatal(code) => Err(TempoPoolValidationError::Fatal(self.error(code))),
                err => Err(TempoPoolValidationError::Invalid(err)),
            };
        }

        Ok((
            self.ext()
                .resolved_fee_token
                .expect("successful Tempo handler resolves a fee token"),
            self.ext().key_expiry,
        ))
    }
}
