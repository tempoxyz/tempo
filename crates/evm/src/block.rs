use crate::{TempoBlockExecutionCtx, evm::TempoEvm};
use alloy_consensus::{Transaction, transaction::TxHashRef};
use alloy_primitives::{B256, Bytes, TxHash};
use alloy_sol_types::SolCall;
use reth_evm::{
    Database, Evm, OnStateHook,
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockValidationError,
        ExecutableTx,
    },
    eth::{
        EthBlockExecutor,
        receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx},
    },
};
use reth_revm::{
    Inspector, State,
    context::result::{ExecutionResult, Output, ResultAndState, SuccessReason},
};
use tempo_chainspec::TempoChainSpec;
use tempo_precompiles::{
    STABLECOIN_EXCHANGE_ADDRESS, TIP_FEE_MANAGER_ADDRESS, stablecoin_exchange::IStablecoinExchange,
    tip_fee_manager::IFeeManager,
};
use tempo_primitives::{TempoReceipt, TempoTxEnvelope};
use tempo_revm::evm::TempoContext;
use tracing::trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BlockSection {
    /// Basic section of the block. Includes arbitrary transactions chosen by the proposer.
    ///
    /// Must use at most `non_shared_gas_left` gas.
    NonShared,
    /// Subblock authored by the given validator.
    SubBlock { proposer: B256 },
    /// Gas incentive transaction.
    GasIncentive,
    /// System transactions.
    System {
        seen_fee_manager: bool,
        seen_stablecoin_dex: bool,
    },
}

/// Builder for [`TempoReceipt`].
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub(crate) struct TempoReceiptBuilder;

impl ReceiptBuilder for TempoReceiptBuilder {
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;

    fn build_receipt<E: Evm>(
        &self,
        ctx: ReceiptBuilderCtx<'_, Self::Transaction, E>,
    ) -> Self::Receipt {
        let ReceiptBuilderCtx {
            tx,
            result,
            cumulative_gas_used,
            ..
        } = ctx;
        TempoReceipt {
            tx_type: tx.tx_type(),
            // Success flag was added in `EIP-658: Embedding transaction status code in
            // receipts`.
            success: result.is_success(),
            cumulative_gas_used,
            logs: result.into_logs(),
        }
    }
}

/// Block executor for Tempo. Wraps an inner [`EthBlockExecutor`].
pub(crate) struct TempoBlockExecutor<'a, DB: Database, I> {
    pub(crate) inner: EthBlockExecutor<
        'a,
        TempoEvm<&'a mut State<DB>, I>,
        &'a TempoChainSpec,
        TempoReceiptBuilder,
    >,

    section: BlockSection,
    seen_subblocks: Vec<(B256, Vec<TxHash>)>,

    non_shared_gas_left: u64,
    non_payment_gas_left: u64,
    shared_gas_left: u64,
}

impl<'a, DB, I> TempoBlockExecutor<'a, DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<&'a mut State<DB>>>,
{
    pub(crate) fn new(
        evm: TempoEvm<&'a mut State<DB>, I>,
        ctx: TempoBlockExecutionCtx<'a>,
        chain_spec: &'a TempoChainSpec,
    ) -> Self {
        Self {
            non_payment_gas_left: ctx.general_gas_limit,
            shared_gas_left: ctx.shared_gas_limit,
            non_shared_gas_left: evm.block().gas_limit - ctx.general_gas_limit,
            inner: EthBlockExecutor::new(
                evm,
                ctx.inner,
                chain_spec,
                TempoReceiptBuilder::default(),
            ),
            section: BlockSection::NonShared,
            seen_subblocks: Vec::new(),
        }
    }

    /// Validates a system transaction.
    fn validate_system_tx(
        &self,
        tx: &TempoTxEnvelope,
    ) -> Result<BlockSection, BlockValidationError> {
        let (mut seen_fee_manager, mut seen_stablecoin_dex) = match self.section {
            BlockSection::System {
                seen_fee_manager,
                seen_stablecoin_dex,
            } => (seen_fee_manager, seen_stablecoin_dex),
            _ => (false, false),
        };

        if tx.to() == Some(TIP_FEE_MANAGER_ADDRESS) {
            if seen_fee_manager {
                return Err(BlockValidationError::msg(
                    "duplicate fee manager system transaction",
                ));
            } else {
                seen_fee_manager = true;
            }
        } else if tx.to() == Some(STABLECOIN_EXCHANGE_ADDRESS) {
            if seen_stablecoin_dex {
                return Err(BlockValidationError::msg(
                    "duplicate stablecoin DEX system transaction",
                ));
            } else {
                seen_stablecoin_dex = true;
            }
        }

        let block = self.evm().block().number.to_be_bytes_vec();
        let to = tx.to().unwrap_or_default();
        if to == TIP_FEE_MANAGER_ADDRESS {
            let fee_input = IFeeManager::executeBlockCall
                .abi_encode()
                .into_iter()
                .chain(block)
                .collect::<Bytes>();
            if *tx.input() == fee_input && seen_fee_manager {
                return Err(BlockValidationError::msg(
                    "duplicate fee manager system transaction",
                ));
            } else {
                seen_fee_manager = true
            }
        } else if to == STABLECOIN_EXCHANGE_ADDRESS {
            let dex_input = IStablecoinExchange::executeBlockCall {}
                .abi_encode()
                .into_iter()
                .chain(block)
                .collect::<Bytes>();
            if *tx.input() == dex_input && seen_stablecoin_dex {
                return Err(BlockValidationError::msg(
                    "duplicate stablecoin DEX system transaction",
                ));
            } else {
                seen_stablecoin_dex = true;
            }
        } else {
            return Err(BlockValidationError::msg("invalid system transaction"));
        }

        Ok(BlockSection::System {
            seen_fee_manager,
            seen_stablecoin_dex,
        })
    }

    fn validate_tx(&self, tx: &TempoTxEnvelope) -> Result<BlockSection, BlockValidationError> {
        // Start with processing of transaction kinds that requre specific sections.
        if tx.is_system_tx() {
            self.validate_system_tx(tx)
        } else if let Some(tx_proposer) = tx.subblock_proposer() {
            match self.section {
                BlockSection::GasIncentive | BlockSection::System { .. } => {
                    Err(BlockValidationError::msg("subblock section already passed"))
                }
                BlockSection::NonShared => Ok(BlockSection::SubBlock {
                    proposer: tx_proposer,
                }),
                BlockSection::SubBlock { proposer } => {
                    if proposer == tx_proposer
                        || !self.seen_subblocks.iter().any(|(p, _)| *p == tx_proposer)
                    {
                        Ok(BlockSection::SubBlock { proposer })
                    } else {
                        Err(BlockValidationError::msg(
                            "proposer's subblock already processed",
                        ))
                    }
                }
            }
        } else {
            match self.section {
                BlockSection::NonShared => {
                    if tx.gas_limit() > self.non_shared_gas_left {
                        Err(BlockValidationError::msg(
                            "transaction gas limit exceeds available non-shared gas",
                        ))
                    } else if !tx.is_payment() && tx.gas_limit() > self.non_payment_gas_left {
                        Err(BlockValidationError::msg(
                            "transaction gas limit exceeds non-payment gas limit",
                        ))
                    } else {
                        Ok(BlockSection::NonShared)
                    }
                }
                BlockSection::SubBlock { .. } => {
                    // If we were just processing a subblock, assume that this transaction wants to make
                    // use of gas incentive section, thus concluding subblocks execution.
                    if tx.gas_limit() <= self.shared_gas_left {
                        Ok(BlockSection::GasIncentive)
                    } else {
                        Err(BlockValidationError::msg("not enough shared gas"))
                    }
                }
                BlockSection::GasIncentive => {
                    if tx.gas_limit() <= self.shared_gas_left {
                        Ok(BlockSection::GasIncentive)
                    } else {
                        Err(BlockValidationError::msg("not enough incentive gas"))
                    }
                }
                BlockSection::System { .. } => {
                    trace!(target: "tempo::block", tx_hash = ?*tx.tx_hash(), "Rejecting: regular transaction after system transaction");
                    Err(BlockValidationError::msg(
                        "regular transaction can't follow system transaction",
                    ))
                }
            }
        }
    }
}

impl<'a, DB, I> BlockExecutor for TempoBlockExecutor<'a, DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<&'a mut State<DB>>>,
{
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;
    type Evm = TempoEvm<&'a mut State<DB>, I>;

    fn apply_pre_execution_changes(&mut self) -> Result<(), reth_evm::block::BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<ResultAndState, BlockExecutionError> {
        self.validate_tx(tx.tx())?;

        let err = match self.inner.execute_transaction_without_commit(&tx) {
            Ok(result) => return Ok(result),
            Err(err) => err,
        };

        // Allow subblock transactions to fail with nonce too low if their nonce was valid at the top of the block.
        if tx.tx().subblock_proposer().is_some()
            && let BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                error, ..
            }) = &err
            && error.is_nonce_too_low()
        {
            let nonce_before_block = self
                .evm_mut()
                .db_mut()
                .transition_state
                .as_ref()
                .ok_or(BlockExecutionError::msg("missing transition state"))?
                .transitions
                .get(tx.signer())
                .and_then(|acc| acc.previous_info.as_ref())
                .map(|info| info.nonce)
                .unwrap_or_default();

            if nonce_before_block < tx.tx().nonce() {
                return Ok(ResultAndState {
                    result: ExecutionResult::Success {
                        reason: SuccessReason::Stop,
                        gas_used: Default::default(),
                        gas_refunded: Default::default(),
                        logs: Default::default(),
                        output: Output::Call(Default::default()),
                    },
                    state: Default::default(),
                });
            }
        }

        Err(err)
    }

    fn commit_transaction(
        &mut self,
        output: ResultAndState,
        tx: impl ExecutableTx<Self>,
    ) -> Result<u64, BlockExecutionError> {
        let gas_used = self.inner.commit_transaction(output, &tx)?;

        self.section = self.validate_tx(tx.tx())?;

        match self.section {
            BlockSection::NonShared => {
                self.non_shared_gas_left -= gas_used;
                if !tx.tx().is_payment() {
                    self.non_payment_gas_left -= gas_used;
                }
            }
            BlockSection::SubBlock { proposer } => {
                // subtract transaction gas limit from the shared gas
                self.shared_gas_left -= tx.tx().gas_limit();

                // record subblock transactions to verify later
                let last_subblock = if let Some(last) = self
                    .seen_subblocks
                    .last_mut()
                    .filter(|(p, _)| *p == proposer)
                {
                    last
                } else {
                    self.seen_subblocks.push((proposer, vec![]));
                    self.seen_subblocks.last_mut().unwrap()
                };

                last_subblock.1.push(*tx.tx().tx_hash());
            }
            BlockSection::GasIncentive => {
                self.shared_gas_left -= gas_used;
            }
            BlockSection::System { .. } => {
                // no gas spending
            }
        }

        Ok(gas_used)
    }

    fn finish(
        self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        if self.section
            != (BlockSection::System {
                seen_fee_manager: true,
                seen_stablecoin_dex: true,
            })
        {
            return Err(BlockValidationError::msg("system transactions not seen in block").into());
        }
        self.inner.finish()
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
}
