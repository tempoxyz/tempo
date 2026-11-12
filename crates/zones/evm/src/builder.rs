//! What a zone block builder includes: the opening `advanceTempo` system transaction, and which
//! candidate transactions it executes or leaves out.

use std::error::Error;

use alloy_consensus::{SignableTransaction as _, TxLegacy};
use alloy_primitives::U256;
use alloy_sol_types::SolCall as _;
use reth_evm::{BlockExecutionError, BlockValidationError, InternalBlockExecutionError};
use reth_primitives_traits::Recovered;
use tempo_contracts::zones::{DecryptionData, EnabledToken, IZoneInbox, QueuedDeposit};
use tempo_primitives::{
    TempoHeader, TempoTxEnvelope,
    transaction::envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
};
use zone_precompiles::L1StateError;
use zone_primitives::constants::ZONE_INBOX_ADDRESS;

/// Safety margin reserved out of [`MAX_RLP_BLOCK_SIZE`] for everything in the block other than
/// pool transactions: the header, RLP list framing, `advanceTempo`, `finalizeWithdrawalBatch`
/// and the outer RLP string header.
///
/// Note: `finalizeWithdrawalBatch` is not bounded(~200 bytes per withdrawal).
/// So a large enough backlog can exceed this margin. OK because the cap is a soft target: block
/// size is not consensus-validated, so an overshoot creates a
/// warning, not a failed build. The p2p transport message cap `MAX_MESSAGE_SIZE` must stay comfortably above
/// [`MAX_RLP_BLOCK_SIZE`] so such blocks still replicate.
///
/// [`MAX_RLP_BLOCK_SIZE`]: zone_primitives::constants::MAX_RLP_BLOCK_SIZE
pub const BLOCK_SIZE_SAFETY_MARGIN: usize = 1024 * 1024;

/// Diagnostic retained when upstream Tempo precompile storage stringifies an [`L1StateError`].
const L1_STORAGE_UNAVAILABLE_ERROR_PREFIX: &str = "Tempo L1 storage unavailable";

/// Candidate transactions for a zone block and how the builder executes them, as
/// [`fill_block`] takes them.
pub trait BlockCandidates {
    /// A candidate transaction.
    type Tx;
    /// Why [`Self::screen`] rejects a candidate.
    type ScreenError;

    /// The next candidate, `None` once there are no more.
    fn next(&mut self) -> Option<Self::Tx>;

    /// Whether the build was cancelled, so no more candidates are executed.
    fn is_cancelled(&self) -> bool;

    /// Rejects a candidate before it is executed or counted against the size budget.
    fn screen(&self, tx: &Self::Tx) -> Result<(), Self::ScreenError>;

    /// The candidate's EIP-2718 encoded length, counted against the size budget.
    fn encoded_length(&self, tx: &Self::Tx) -> usize;

    /// Executes the candidate and commits it to the block.
    fn execute(&mut self, tx: &Self::Tx) -> Result<(), BlockExecutionError>;

    /// Notes that the candidate was left out of the block, and why.
    fn skip(&mut self, tx: &Self::Tx, why: Skipped<Self::ScreenError>);
}

/// Why [`fill_block`] left a candidate out of the block.
#[derive(Debug)]
pub enum Skipped<E> {
    /// [`BlockCandidates::screen`] rejected it.
    Screened(E),
    /// Including it would bring the packed candidate bytes to `size`, past `limit`.
    Oversized {
        /// The packed bytes with the candidate.
        size: usize,
        /// The size budget.
        limit: usize,
    },
    /// Its gas limit exceeds the gas left in the block.
    ExceedsGasLimit {
        /// The candidate's gas limit.
        transaction_gas_limit: u64,
        /// The gas left in the block.
        block_available_gas: u64,
    },
    /// The executor rejected it as invalid.
    Invalid {
        /// Whether only its nonce is too low, so it may have been included already.
        nonce_too_low: bool,
    },
    /// Executing it read Tempo state that could not be served.
    L1Unavailable(BlockExecutionError),
}

/// Whether [`fill_block`] ran out of candidates or was cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillOutcome {
    /// Every candidate was executed or skipped.
    Complete,
    /// The build was cancelled before the candidates ran out.
    Cancelled,
}

/// Executes `candidates` in order, leaving out each one the screen rejects, whose encoded length
/// would push the packed candidate bytes past `size_budget`, or that the executor rejects as
/// invalid, over the block's gas, or for unavailable Tempo state. Any other execution error stops
/// the block and is returned.
pub fn fill_block<C: BlockCandidates>(
    candidates: &mut C,
    size_budget: usize,
) -> Result<FillOutcome, BlockExecutionError> {
    let mut packed_tx_bytes = 0usize;
    while let Some(tx) = candidates.next() {
        if candidates.is_cancelled() {
            return Ok(FillOutcome::Cancelled);
        }

        if let Err(error) = candidates.screen(&tx) {
            candidates.skip(&tx, Skipped::Screened(error));
            continue;
        }

        let packed_bytes_with_tx = packed_tx_bytes.saturating_add(candidates.encoded_length(&tx));
        if packed_bytes_with_tx > size_budget {
            let why = Skipped::Oversized {
                size: packed_bytes_with_tx,
                limit: size_budget,
            };
            candidates.skip(&tx, why);
            continue;
        }

        match candidates.execute(&tx) {
            Ok(()) => packed_tx_bytes = packed_bytes_with_tx,
            Err(BlockExecutionError::Validation(
                BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit,
                    block_available_gas,
                },
            )) => {
                let why = Skipped::ExceedsGasLimit {
                    transaction_gas_limit,
                    block_available_gas,
                };
                candidates.skip(&tx, why);
            }
            Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                error, ..
            })) => {
                let why = Skipped::Invalid {
                    nonce_too_low: error.is_nonce_too_low(),
                };
                candidates.skip(&tx, why);
            }
            Err(error)
                if matches!(
                    &error,
                    BlockExecutionError::Internal(InternalBlockExecutionError::EVM { error, .. })
                        if is_l1_storage_unavailable(error)
                ) =>
            {
                candidates.skip(&tx, Skipped::L1Unavailable(error));
            }
            Err(error) => return Err(error),
        }
    }

    Ok(FillOutcome::Complete)
}

/// Builds the system `advanceTempo` transaction that opens a zone block, importing `header` with
/// its deposits, their decryptions and the tokens it enables.
pub fn build_advance_tempo_tx_from_parts(
    header: &TempoHeader,
    deposits: Vec<QueuedDeposit>,
    decryptions: Vec<DecryptionData>,
    enabled_tokens: Vec<EnabledToken>,
    chain_id: u64,
) -> Recovered<TempoTxEnvelope> {
    let calldata = IZoneInbox::advanceTempoCall {
        header: alloy_rlp::encode(header).into(),
        deposits,
        decryptions,
        enabledTokens: enabled_tokens,
    }
    .abi_encode();

    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 0,
        gas_limit: 0,
        to: ZONE_INBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: calldata.into(),
    };

    Recovered::new_unchecked(
        TempoTxEnvelope::Legacy(tx.into_signed(TEMPO_SYSTEM_TX_SIGNATURE)),
        TEMPO_SYSTEM_TX_SENDER,
    )
}

/// Whether `error`, or an error it wraps, says Tempo L1 storage was unavailable.
pub fn is_l1_storage_unavailable(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<L1StateError>()
            .is_some_and(L1StateError::is_unavailable)
            || error
                .to_string()
                .contains(L1_STORAGE_UNAVAILABLE_ERROR_PREFIX)
        {
            return true;
        }
        current = error.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256};

    #[test]
    fn stringified_l1_unavailability_is_recognized() {
        for error in [
            L1StateError::StorageUnavailable {
                account: Address::ZERO,
                slot: B256::ZERO,
                block_number: 1,
                reason: "RPC unavailable".into(),
            },
            L1StateError::AccountUnavailable {
                account: Address::ZERO,
                block_number: 1,
                reason: "RPC unavailable".into(),
            },
        ] {
            let stringified = std::io::Error::other(error.to_string());
            assert!(is_l1_storage_unavailable(&stringified), "{error}");
        }
    }
}
