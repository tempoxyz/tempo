use crate::{TempoBlockExecutionCtx, evm::TempoEvm};
use alloy_consensus::{Transaction, transaction::TxHashRef};
use alloy_primitives::{B256, Bytes, U256};
use alloy_rlp::Decodable;
use alloy_sol_types::SolCall;
use commonware_codec::DecodeExt;
use commonware_cryptography::{
    Verifier,
    ed25519::{PublicKey, Signature},
};
use ed25519_consensus::VerificationKey;
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
use reth_revm::{Inspector, State, context::result::ResultAndState};
use std::collections::HashSet;
use tempo_chainspec::TempoChainSpec;
use tempo_payload_types::{SubBlock, SubBlockMetadata, SubBlockVersion};
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
        seen_subblocks_signatures: bool,
    },
}

#[derive(Debug, Clone, Default)]
struct ValidatorSetInfo {
    pub participants: Vec<B256>,
    pub current_validator: B256,
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
    seen_subblocks: Vec<(B256, u64, Vec<TempoTxEnvelope>)>,
    validator_set: Option<ValidatorSetInfo>,
    shared_gas_limit: u64,

    non_shared_gas_left: u64,
    non_payment_gas_left: u64,
    incentive_gas_used: u64,
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
            incentive_gas_used: 0,
            validator_set: None,
            non_payment_gas_left: ctx.general_gas_limit,
            non_shared_gas_left: evm.block().gas_limit - ctx.general_gas_limit,
            shared_gas_limit: ctx.shared_gas_limit,
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
        let (mut seen_fee_manager, mut seen_stablecoin_dex, mut seen_subblocks_signatures) =
            match self.section {
                BlockSection::System {
                    seen_fee_manager,
                    seen_stablecoin_dex,
                    seen_subblocks_signatures,
                } => (
                    seen_fee_manager,
                    seen_stablecoin_dex,
                    seen_subblocks_signatures,
                ),
                _ => (false, false, false),
            };

        let block = self.evm().block().number.to_be_bytes_vec();
        let to = tx.to().unwrap_or_default();
        if to == TIP_FEE_MANAGER_ADDRESS {
            if seen_fee_manager {
                return Err(BlockValidationError::msg(
                    "duplicate fee manager system transaction",
                ));
            }

            let fee_input = IFeeManager::executeBlockCall
                .abi_encode()
                .into_iter()
                .chain(block)
                .collect::<Bytes>();

            if *tx.input() != fee_input {
                return Err(BlockValidationError::msg(
                    "invalid fee manager system transaction",
                ));
            }

            seen_fee_manager = true;
        } else if to == STABLECOIN_EXCHANGE_ADDRESS {
            if seen_stablecoin_dex {
                return Err(BlockValidationError::msg(
                    "duplicate stablecoin DEX system transaction",
                ));
            }

            let dex_input = IStablecoinExchange::executeBlockCall {}
                .abi_encode()
                .into_iter()
                .chain(block)
                .collect::<Bytes>();

            if *tx.input() != dex_input {
                return Err(BlockValidationError::msg(
                    "invalid stablecoin DEX system transaction",
                ));
            }

            seen_stablecoin_dex = true;
        } else if to.is_zero() {
            if seen_subblocks_signatures {
                return Err(BlockValidationError::msg(
                    "duplicate subblocks metadata system transaction",
                ));
            }

            if tx.input().len() < U256::BYTES
                || tx.input()[tx.input().len() - U256::BYTES..] != block
            {
                return Err(BlockValidationError::msg(
                    "invalid subblocks metadata system transaction",
                ));
            }

            let mut buf = &tx.input()[..tx.input().len() - U256::BYTES];
            let Ok(metadata) = Vec::<SubBlockMetadata>::decode(&mut buf) else {
                return Err(BlockValidationError::msg(
                    "invalid subblocks metadata system transaction",
                ));
            };

            if !buf.is_empty() {
                return Err(BlockValidationError::msg(
                    "invalid subblocks metadata system transaction",
                ));
            }

            self.validate_shared_gas(&metadata)?;

            seen_subblocks_signatures = true;
        } else {
            return Err(BlockValidationError::msg("invalid system transaction"));
        }

        Ok(BlockSection::System {
            seen_fee_manager,
            seen_stablecoin_dex,
            seen_subblocks_signatures,
        })
    }

    fn validate_shared_gas(
        &self,
        metadata: &[SubBlockMetadata],
    ) -> Result<(), BlockValidationError> {
        // Skip incentive gas validation if validator set context is not available.
        let Some(validator_set) = &self.validator_set else {
            return Ok(());
        };
        let gas_per_subblock = self.shared_gas_limit / validator_set.participants.len() as u64;

        let mut incentive_gas = gas_per_subblock;
        let mut seen = HashSet::new();
        let mut next_non_empty = 0;
        for metadata in metadata {
            if !validator_set.participants.contains(&metadata.validator) {
                return Err(BlockValidationError::msg("invalid subblock validator"));
            }

            if metadata.validator == validator_set.current_validator {
                return Err(BlockValidationError::msg(
                    "proposer cannot submit subblocks",
                ));
            }

            if !seen.insert(metadata.validator) {
                return Err(BlockValidationError::msg(
                    "only one subblock per validator is allowed",
                ));
            }

            let (gas_used, transactions) = if let Some((validator, gas_used, txs)) =
                self.seen_subblocks.get(next_non_empty)
                && validator == &metadata.validator
            {
                next_non_empty += 1;
                (*gas_used, txs.clone())
            } else {
                (0, Vec::new())
            };

            let signature_hash = SubBlock {
                version: SubBlockVersion::V1,
                parent_hash: self.inner.ctx.parent_hash,
                transactions,
            }
            .signature_hash();

            let Ok(validator) =
                VerificationKey::try_from(AsRef::<[u8]>::as_ref(&metadata.validator))
                    .map(PublicKey::from)
            else {
                return Err(BlockValidationError::msg("invalid subblock validator"));
            };

            let Ok(signature) = Signature::decode(&mut metadata.signature.as_ref()) else {
                return Err(BlockValidationError::msg("invalid subblock signature"));
            };

            if !validator.verify(None, signature_hash.as_slice(), &signature) {
                return Err(BlockValidationError::msg("invalid subblock signature"));
            }

            if gas_used > gas_per_subblock {
                return Err(BlockValidationError::msg(
                    "subblock gas used exceeds gas per subblock",
                ));
            }

            incentive_gas += gas_per_subblock - gas_used;
        }

        if next_non_empty != self.seen_subblocks.len() {
            return Err(BlockValidationError::msg(
                "failed to map all non-empty subblocks to metadata",
            ));
        }

        if incentive_gas > self.incentive_gas_used {
            return Err(BlockValidationError::msg("incentive gas limit exceeded"));
        }

        Ok(())
    }

    fn validate_tx(
        &self,
        tx: &TempoTxEnvelope,
        gas_used: u64,
    ) -> Result<BlockSection, BlockValidationError> {
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
                        || !self
                            .seen_subblocks
                            .iter()
                            .any(|(p, _, _)| *p == tx_proposer)
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
                    if gas_used > self.non_shared_gas_left
                        || (!tx.is_payment() && gas_used > self.non_payment_gas_left)
                    {
                        // Assume that this transaction wants to make use of gas incentive section
                        //
                        // This would only be possible if no non-empty subblocks were included.
                        Ok(BlockSection::GasIncentive)
                    } else {
                        Ok(BlockSection::NonShared)
                    }
                }
                BlockSection::SubBlock { .. } => {
                    // If we were just processing a subblock, assume that this transaction wants to make
                    // use of gas incentive section, thus concluding subblocks execution.
                    Ok(BlockSection::GasIncentive)
                }
                BlockSection::GasIncentive => Ok(BlockSection::GasIncentive),
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
        self.inner.execute_transaction_without_commit(tx)
    }

    fn commit_transaction(
        &mut self,
        output: ResultAndState,
        tx: impl ExecutableTx<Self>,
    ) -> Result<u64, BlockExecutionError> {
        let next_section = self.validate_tx(tx.tx(), output.result.gas_used())?;

        let gas_used = self.inner.commit_transaction(output, &tx)?;

        self.section = next_section;

        match self.section {
            BlockSection::NonShared => {
                self.non_shared_gas_left -= gas_used;
                if !tx.tx().is_payment() {
                    self.non_payment_gas_left -= gas_used;
                }
            }
            BlockSection::SubBlock { proposer } => {
                // record subblock transactions to verify later
                let last_subblock = if let Some(last) = self
                    .seen_subblocks
                    .last_mut()
                    .filter(|(p, _, _)| *p == proposer)
                {
                    last
                } else {
                    self.seen_subblocks.push((proposer, 0, Vec::new()));
                    self.seen_subblocks.last_mut().unwrap()
                };

                last_subblock.1 += tx.tx().gas_limit();
                last_subblock.2.push(tx.tx().clone());
            }
            BlockSection::GasIncentive => {
                self.incentive_gas_used += gas_used;
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
                seen_subblocks_signatures: true,
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
