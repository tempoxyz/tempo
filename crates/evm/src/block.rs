use crate::{TempoBlockExecutionCtx, evm::TempoEvm};
use alloy_consensus::{Transaction, transaction::TxHashRef};
use alloy_evm::{
    Database, Evm,
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockValidationError,
        ExecutableTx, OnStateHook,
    },
    eth::{
        EthBlockExecutor,
        receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx},
    },
};
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_rlp::Decodable;
use alloy_sol_types::SolCall;
use commonware_codec::DecodeExt;
use commonware_cryptography::{
    Verifier,
    ed25519::{PublicKey, Signature},
};
use reth_revm::{Inspector, State, context::result::ResultAndState};
use revm::{
    DatabaseCommit,
    context::ContextTr,
    state::{Account, Bytecode},
};
use std::collections::{HashMap, HashSet};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};
use tempo_contracts::{CREATEX_ADDRESS, MULTICALL_ADDRESS};

use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    TIP20_REWARDS_REGISTRY_ADDRESS,
    tip_fee_manager::IFeeManager, tip20_rewards_registry::ITIP20RewardsRegistry,
};
use tempo_primitives::{
    SubBlock, SubBlockMetadata, TempoReceipt, TempoTxEnvelope, subblock::PartialValidatorKey,
};
use tempo_revm::{TempoHaltReason, evm::TempoContext};
use tracing::trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BlockSection {
    /// Start of block system transactions (rewards registry).
    StartOfBlock { seen_tip20_rewards_registry: bool },
    /// Basic section of the block. Includes arbitrary transactions chosen by the proposer.
    ///
    /// Must use at most `non_shared_gas_left` gas.
    NonShared,
    /// Subblock authored by the given validator.
    SubBlock { proposer: PartialValidatorKey },
    /// Gas incentive transaction.
    GasIncentive,
    /// End of block system transactions.
    System {
        seen_fee_manager: bool,
        seen_subblocks_signatures: bool,
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
    seen_subblocks: Vec<(PartialValidatorKey, Vec<TempoTxEnvelope>)>,
    validator_set: Option<Vec<B256>>,
    shared_gas_limit: u64,
    subblock_fee_recipients: HashMap<PartialValidatorKey, Address>,

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
            validator_set: ctx.validator_set,
            non_payment_gas_left: ctx.general_gas_limit,
            non_shared_gas_left: evm.block().gas_limit - ctx.shared_gas_limit,
            shared_gas_limit: ctx.shared_gas_limit,
            inner: EthBlockExecutor::new(
                evm,
                ctx.inner,
                chain_spec,
                TempoReceiptBuilder::default(),
            ),
            section: BlockSection::StartOfBlock {
                seen_tip20_rewards_registry: false,
            },
            seen_subblocks: Vec::new(),
            subblock_fee_recipients: ctx.subblock_fee_recipients,
        }
    }

    /// Validates a system transaction.
    fn validate_system_tx(
        &self,
        tx: &TempoTxEnvelope,
    ) -> Result<BlockSection, BlockValidationError> {
        let block = self.evm().block();
        let block_timestamp = block.timestamp;
        let block_number = block.number.to_be_bytes_vec();
        let to = tx.to().unwrap_or_default();

        if !self
            .inner
            .spec
            .is_moderato_active_at_timestamp(block_timestamp.to::<u64>())
        {
            // Handle start-of-block system transaction (rewards registry)
            // Only enforce this restriction when we haven't seen the rewards registry yet
            if let BlockSection::StartOfBlock {
                seen_tip20_rewards_registry: false,
            } = self.section
            {
                if to != TIP20_REWARDS_REGISTRY_ADDRESS {
                    return Err(BlockValidationError::msg(
                        "only rewards registry system transaction allowed at start of block",
                    ));
                }

                let finalize_streams_input = ITIP20RewardsRegistry::finalizeStreamsCall {}
                    .abi_encode()
                    .into_iter()
                    .chain(block_number)
                    .collect::<Bytes>();

                if *tx.input() != finalize_streams_input {
                    return Err(BlockValidationError::msg(
                        "invalid TIP20 rewards registry system transaction",
                    ));
                }

                return Ok(BlockSection::StartOfBlock {
                    seen_tip20_rewards_registry: true,
                });
            }
        }

        // Handle end-of-block system transactions (fee manager, subblocks signatures)
        let (mut seen_fee_manager, mut seen_subblocks_signatures) = match self.section {
            BlockSection::System {
                seen_fee_manager,
                seen_subblocks_signatures,
            } => (seen_fee_manager, seen_subblocks_signatures),
            _ => (false, false),
        };

        if to == TIP_FEE_MANAGER_ADDRESS {
            if seen_fee_manager {
                return Err(BlockValidationError::msg(
                    "duplicate fee manager system transaction",
                ));
            }

            let fee_input = IFeeManager::executeBlockCall
                .abi_encode()
                .into_iter()
                .chain(block_number)
                .collect::<Bytes>();

            if *tx.input() != fee_input {
                return Err(BlockValidationError::msg(
                    "invalid fee manager system transaction",
                ));
            }

            seen_fee_manager = true;
        } else if to.is_zero() {
            if seen_subblocks_signatures {
                return Err(BlockValidationError::msg(
                    "duplicate subblocks metadata system transaction",
                ));
            }

            if tx.input().len() < U256::BYTES
                || tx.input()[tx.input().len() - U256::BYTES..] != block_number
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
        let gas_per_subblock = self.shared_gas_limit / validator_set.len() as u64;

        let mut incentive_gas = 0;
        let mut seen = HashSet::new();
        let mut next_non_empty = 0;
        for metadata in metadata {
            if !validator_set.contains(&metadata.validator) {
                return Err(BlockValidationError::msg("invalid subblock validator"));
            }

            if !seen.insert(metadata.validator) {
                return Err(BlockValidationError::msg(
                    "only one subblock per validator is allowed",
                ));
            }

            let transactions = if let Some((validator, txs)) =
                self.seen_subblocks.get(next_non_empty)
                && validator.matches(metadata.validator)
            {
                next_non_empty += 1;
                txs.clone()
            } else {
                Vec::new()
            };

            let reserved_gas = transactions.iter().map(|tx| tx.gas_limit()).sum::<u64>();

            let signature_hash = SubBlock {
                version: metadata.version,
                fee_recipient: metadata.fee_recipient,
                parent_hash: self.inner.ctx.parent_hash,
                transactions: transactions.clone(),
            }
            .signature_hash();

            let Ok(validator) = PublicKey::decode(&mut metadata.validator.as_ref()) else {
                return Err(BlockValidationError::msg("invalid subblock validator"));
            };

            let Ok(signature) = Signature::decode(&mut metadata.signature.as_ref()) else {
                return Err(BlockValidationError::msg(
                    "invalid subblock signature encoding",
                ));
            };

            if !validator.verify(None, signature_hash.as_slice(), &signature) {
                return Err(BlockValidationError::msg("invalid subblock signature"));
            }

            if reserved_gas > gas_per_subblock {
                return Err(BlockValidationError::msg(
                    "subblock gas used exceeds gas per subblock",
                ));
            }

            incentive_gas += gas_per_subblock - reserved_gas;
        }

        if next_non_empty != self.seen_subblocks.len() {
            return Err(BlockValidationError::msg(
                "failed to map all non-empty subblocks to metadata",
            ));
        }

        if incentive_gas < self.incentive_gas_used {
            return Err(BlockValidationError::msg("incentive gas limit exceeded"));
        }

        Ok(())
    }

    fn validate_tx(
        &self,
        tx: &TempoTxEnvelope,
        gas_used: u64,
    ) -> Result<BlockSection, BlockValidationError> {
        let block = self.evm().block();
        let block_timestamp = block.timestamp.to::<u64>();
        let post_moderato = self
            .inner
            .spec
            .is_moderato_active_at_timestamp(block_timestamp);

        // Start with processing of transaction kinds that require specific sections.
        if tx.is_system_tx() {
            self.validate_system_tx(tx)
        } else if let Some(tx_proposer) = tx.subblock_proposer() {
            match self.section {
                BlockSection::StartOfBlock {
                    seen_tip20_rewards_registry,
                } if !post_moderato && !seen_tip20_rewards_registry => {
                    Err(BlockValidationError::msg(
                        "TIP20 rewards registry system transaction was not seen",
                    ))
                }
                BlockSection::GasIncentive | BlockSection::System { .. } => {
                    Err(BlockValidationError::msg("subblock section already passed"))
                }
                BlockSection::StartOfBlock { .. } | BlockSection::NonShared => {
                    Ok(BlockSection::SubBlock {
                        proposer: tx_proposer,
                    })
                }
                BlockSection::SubBlock { proposer } => {
                    if proposer == tx_proposer
                        || !self.seen_subblocks.iter().any(|(p, _)| *p == tx_proposer)
                    {
                        Ok(BlockSection::SubBlock {
                            proposer: tx_proposer,
                        })
                    } else {
                        Err(BlockValidationError::msg(
                            "proposer's subblock already processed",
                        ))
                    }
                }
            }
        } else {
            match self.section {
                BlockSection::StartOfBlock {
                    seen_tip20_rewards_registry,
                } if !post_moderato && !seen_tip20_rewards_registry => {
                    Err(BlockValidationError::msg(
                        "TIP20 rewards registry system transaction was not seen",
                    ))
                }
                BlockSection::StartOfBlock { .. } | BlockSection::NonShared => {
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

    fn apply_pre_execution_changes(&mut self) -> Result<(), alloy_evm::block::BlockExecutionError> {
        self.inner.apply_pre_execution_changes()?;

        // Initialize keychain precompile if allegretto is active
        let block_timestamp = self.evm().block().timestamp.to::<u64>();
        if self
            .inner
            .spec
            .is_allegretto_active_at_timestamp(block_timestamp)
        {
            let evm = self.evm_mut();
            let db = evm.ctx_mut().db_mut();

            // Load the keychain account from the cache
            let acc = db
                .load_cache_account(ACCOUNT_KEYCHAIN_ADDRESS)
                .map_err(BlockExecutionError::other)?;

            // Get existing account info or create default
            let mut acc_info = acc.account_info().unwrap_or_default();

            // Only initialize if the account has no code
            if acc_info.is_empty_code_hash() {
                // Set the keychain code
                let code = Bytecode::new_legacy(Bytes::from_static(&[0xef]));
                acc_info.code_hash = code.hash_slow();
                acc_info.code = Some(code);

                // Convert to revm account and mark as touched
                let mut revm_acc: Account = acc_info.into();
                revm_acc.mark_touch();

                // Commit the account to the database to ensure it persists
                // even if no transactions are executed in this block
                db.commit(HashMap::from_iter([(ACCOUNT_KEYCHAIN_ADDRESS, revm_acc)]));
            }
        }

        // Modify CreateX bytecode and upgrade Multicall to Multicall3 if AllegroModerato is active
        if self
            .inner
            .spec
            .is_allegro_moderato_active_at_timestamp(block_timestamp)
        {
            let evm = self.evm_mut();
            let db = evm.ctx_mut().db_mut();

            // Update CreateX bytecode if outdated
            let acc = db
                .load_cache_account(CREATEX_ADDRESS)
                .map_err(BlockExecutionError::other)?;

            let mut acc_info = acc.account_info().unwrap_or_default();

            let correct_code_hash =
                tempo_contracts::contracts::CREATEX_POST_ALLEGRO_MODERATO_BYTECODE_HASH;
            if acc_info.code_hash != correct_code_hash {
                acc_info.code_hash = correct_code_hash;
                acc_info.code = Some(Bytecode::new_legacy(
                    tempo_contracts::contracts::CREATEX_POST_ALLEGRO_MODERATO_BYTECODE,
                ));

                let mut revm_acc: Account = acc_info.into();
                revm_acc.mark_touch();

                db.commit(HashMap::from_iter([(CREATEX_ADDRESS, revm_acc)]));
            }

            // Update Multicall to Multicall3 if outdated
            let acc = db
                .load_cache_account(MULTICALL_ADDRESS)
                .map_err(BlockExecutionError::other)?;

            let mut acc_info = acc.account_info().unwrap_or_default();

            let correct_code_hash = tempo_contracts::contracts::MULTICALL3_DEPLOYED_BYTECODE_HASH;
            if acc_info.code_hash != correct_code_hash {
                acc_info.code_hash = correct_code_hash;
                acc_info.code = Some(Bytecode::new_legacy(
                    tempo_contracts::Multicall3::DEPLOYED_BYTECODE.clone(),
                ));

                let mut revm_acc: Account = acc_info.into();
                revm_acc.mark_touch();

                db.commit(HashMap::from_iter([(MULTICALL_ADDRESS, revm_acc)]));
            }
        }

        Ok(())
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<ResultAndState<TempoHaltReason>, BlockExecutionError> {
        let beneficiary = self.evm_mut().ctx_mut().block.beneficiary;
        // If we are dealing with a subblock transaction, configure the fee recipient context.
        if self.evm().ctx().cfg.spec.is_allegretto()
            && let Some(validator) = tx.tx().subblock_proposer()
        {
            let fee_recipient = *self
                .subblock_fee_recipients
                .get(&validator)
                .ok_or(BlockExecutionError::msg("invalid subblock transaction"))?;

            self.evm_mut().ctx_mut().block.beneficiary = fee_recipient;
        }
        let result = self.inner.execute_transaction_without_commit(tx);

        self.evm_mut().ctx_mut().block.beneficiary = beneficiary;

        result
    }

    fn commit_transaction(
        &mut self,
        output: ResultAndState<TempoHaltReason>,
        tx: impl ExecutableTx<Self>,
    ) -> Result<u64, BlockExecutionError> {
        let next_section = self.validate_tx(tx.tx(), output.result.gas_used())?;

        let gas_used = self.inner.commit_transaction(output, &tx)?;

        // TODO: remove once revm supports emitting logs for reverted transactions
        //
        // <https://github.com/tempoxyz/tempo/pull/729>
        let logs = self.inner.evm.take_revert_logs();
        if !logs.is_empty() {
            self.inner
                .receipts
                .last_mut()
                .expect("receipt was just pushed")
                .logs
                .extend(logs);
        }

        self.section = next_section;

        match self.section {
            BlockSection::StartOfBlock { .. } => {
                // no gas spending for start-of-block system transactions
            }
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
                    .filter(|(p, _)| *p == proposer)
                {
                    last
                } else {
                    self.seen_subblocks.push((proposer, Vec::new()));
                    self.seen_subblocks.last_mut().unwrap()
                };

                last_subblock.1.push(tx.tx().clone());
            }
            BlockSection::GasIncentive => {
                self.incentive_gas_used += gas_used;
            }
            BlockSection::System { .. } => {
                // no gas spending for end-of-block system transactions
            }
        }

        Ok(gas_used)
    }

    fn finish(
        self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        // Check that we ended in the System section with all end-of-block system txs seen
        let block_timestamp = self.evm().block().timestamp.to::<u64>();
        let is_allegro_moderato = self
            .inner
            .spec
            .is_allegro_moderato_active_at_timestamp(block_timestamp);

        // Post AllegroModerato, fee manager system tx is no longer required
        let expected_seen_fee_manager = !is_allegro_moderato;

        if self.section
            != (BlockSection::System {
                seen_fee_manager: expected_seen_fee_manager,
                seen_subblocks_signatures: true,
            })
        {
            return Err(
                BlockValidationError::msg("end-of-block system transactions not seen").into(),
            );
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
