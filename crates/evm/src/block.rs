use crate::{
    StorageActionReplayState, TempoBlockExecutionCtx, TempoEvm, TempoEvmTypes, TempoTxEnv,
};
use alloy_consensus::{Transaction, transaction::TxHashRef};
use alloy_eip7928::{BlockAccessIndex, BlockAccessList};
use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256};
use alloy_rlp::Decodable;
use alloy_sol_types::SolCall;
use commonware_codec::{DecodeExt, ReadExt};
use commonware_cryptography::{
    Verifier,
    ed25519::{PublicKey, Signature},
};
use evm2::{
    TxResult, TxResultWithState,
    bytecode::Bytecode,
    evm::{AccountChange, Bal, StateChanges, SystemTx},
};
use reth_chainspec::EthChainSpec;
use reth_evm::{
    BlockExecutionError, BlockExecutionOutput, BlockExecutor, BlockValidationError, GasOutput,
    ReceiptBuilder, ReceiptBuilderCtx,
};
use reth_evm_ethereum::EthBlockExecutor;
use reth_execution_types::HashedPostState;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tempo_chainspec::TempoChainSpec;
use tempo_contracts::precompiles::{
    ADDRESS_REGISTRY_ADDRESS, CURRENT_COMMITTEE_ADDRESS, ICurrentCommittee, INITIAL_FACTORY_OWNER,
    RECEIVE_POLICY_GUARD_ADDRESS, SIGNATURE_VERIFIER_ADDRESS, STORAGE_CREDITS_ADDRESS,
    TIP20_CHANNEL_RESERVE_ADDRESS, VALIDATOR_CONFIG_V2_ADDRESS, ZONE_FACTORY_ADDRESS,
};
use tempo_primitives::{
    SubBlock, SubBlockMetadata, TempoPrimitives, TempoReceipt, TempoTxEnvelope, TempoTxType,
    subblock::PartialValidatorKey,
};
use tracing::trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum BlockSection {
    /// Start of block system transactions.
    StartOfBlock,
    /// Basic section of the block. Includes arbitrary transactions chosen by the proposer.
    ///
    /// Must use at most `non_shared_gas_left` gas.
    NonShared,
    /// Subblock authored by the given validator.
    SubBlock { proposer: PartialValidatorKey },
    /// Gas incentive transaction.
    GasIncentive,
    /// End of block system transactions.
    System { seen_subblocks_signatures: bool },
}

/// Builder for [`TempoReceipt`].
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct TempoReceiptBuilder;

impl ReceiptBuilder<TempoTxType, TxResult<TempoEvmTypes>> for TempoReceiptBuilder {
    type Receipt = TempoReceipt;

    fn build_receipt(
        &self,
        ctx: ReceiptBuilderCtx<TempoTxType, TxResult<TempoEvmTypes>>,
    ) -> Self::Receipt {
        let ReceiptBuilderCtx {
            tx_type,
            result,
            cumulative_gas_used,
        } = ctx;
        TempoReceipt {
            tx_type,
            // Success flag was added in `EIP-658: Embedding transaction status code in
            // receipts`.
            success: result.status,
            cumulative_gas_used,
            logs: result.logs,
        }
    }
}

/// The result of executing a Tempo transaction.
///
/// This is an extension of [`TxResultWithState`] with context necessary for committing a Tempo transaction.
#[derive(Debug)]
pub struct TempoTxResult {
    /// Inner transaction execution result.
    inner: TxResultWithState<TempoEvmTypes>,
    /// Next section of the block.
    next_section: BlockSection,
    /// Whether the transaction is a payment transaction.
    is_payment: bool,
    /// Transaction type used to build its receipt.
    tx_type: TempoTxType,
    /// Full transaction that is being committed.
    ///
    /// This is only populated for subblock transactions for which we need to store
    /// the full transaction encoding for later validation of subblock hash.
    tx: Option<TempoTxEnvelope>,
    /// Block gas consumed by this transaction. The block `gas_used` field will be incremented by this value.
    block_gas_used: u64,
    /// Validator-credited fee (in the validator's fee token) reported by `collectFeePostTx`.
    ///
    /// Used by the payload builder to score blocks by actual proposer revenue. The value is the
    /// post-feeAMM amount, regardless of route shape — absorbs any number of pool haircuts.
    validator_fee: U256,
}

impl TempoTxResult {
    /// Creates a new [`TempoTxResult`] from a precomputed result and state.
    pub(crate) fn new_precomputed(
        tx: &TempoTxEnvelope,
        result: TxResult<TempoEvmTypes>,
        state: StateChanges,
        next_section: BlockSection,
        is_payment: bool,
        block_gas_used: u64,
        validator_fee: U256,
    ) -> Self {
        Self {
            inner: TxResultWithState {
                result,
                state_changes: state,
                _non_exhaustive: (),
            },
            next_section,
            is_payment,
            tx_type: tx.tx_type(),
            tx: matches!(next_section, BlockSection::SubBlock { .. }).then(|| tx.clone()),
            block_gas_used,
            validator_fee,
        }
    }

    /// Returns the EVM2 execution result.
    pub const fn result(&self) -> &TxResult<TempoEvmTypes> {
        &self.inner.result
    }

    /// Returns the block gas consumed by this transaction.
    pub fn block_gas_used(&self) -> u64 {
        self.block_gas_used
    }

    /// Returns the state gas consumed by this transaction.
    pub fn state_gas_used(&self) -> u64 {
        self.inner.result.state_gas_spent()
    }

    /// Returns the validator-credited fee amount (post-feeAMM haircut) for this transaction.
    pub fn validator_fee(&self) -> U256 {
        self.validator_fee
    }

    /// Returns the transaction's EVM2 state changes.
    pub const fn state_changes(&self) -> &StateChanges {
        &self.inner.state_changes
    }
}

impl AsRef<TxResult<TempoEvmTypes>> for TempoTxResult {
    fn as_ref(&self) -> &TxResult<TempoEvmTypes> {
        self.result()
    }
}

/// Block executor for Tempo.
///
/// Wraps an inner [`EthBlockExecutor`] and layers Tempo-specific block execution
/// logic on top: section-based transaction ordering (`BlockSection`), subblock
/// validation, shared/non-shared gas accounting, and gas incentive tracking.
#[expect(missing_debug_implementations)]
pub struct TempoBlockExecutor<'a> {
    pub(crate) inner: EthBlockExecutor<'a, TempoEvmTypes, TempoReceipt>,

    section: BlockSection,
    seen_subblocks: Vec<(PartialValidatorKey, Vec<TempoTxEnvelope>)>,
    validator_set: Option<Vec<B256>>,
    subblock_fee_recipients: HashMap<PartialValidatorKey, Address>,
    extra_data: Bytes,

    pub(crate) replay_state: StorageActionReplayState,

    shared_gas_limit: u64,
    non_shared_gas_left: u64,
    non_payment_gas_left: u64,
    incentive_gas_used: u64,
}

impl<'a> TempoBlockExecutor<'a> {
    pub(crate) fn new(
        evm: TempoEvm<'a>,
        ctx: TempoBlockExecutionCtx<'a>,
        chain_spec: &'a TempoChainSpec,
    ) -> Self {
        let block_gas_limit = evm.block().gas_limit.to::<u64>();
        let spec_id = evm.config_spec_id().into();
        Self {
            incentive_gas_used: 0,
            validator_set: ctx.validator_set,
            non_payment_gas_left: ctx.general_gas_limit,
            non_shared_gas_left: block_gas_limit.saturating_sub(ctx.shared_gas_limit),
            shared_gas_limit: ctx.shared_gas_limit,
            extra_data: ctx.inner.extra_data.clone(),
            inner: EthBlockExecutor::new_with_evm(
                evm,
                spec_id,
                ctx.inner,
                chain_spec,
                chain_spec
                    .deposit_contract()
                    .map(|contract| contract.address),
            ),
            section: BlockSection::StartOfBlock,
            seen_subblocks: Vec::new(),
            subblock_fee_recipients: ctx.subblock_fee_recipients,
            replay_state: StorageActionReplayState::default(),
        }
    }

    /// Deploys `0xEF` marker bytecode and initializes storage at a precompile address.
    ///
    /// This also dispatches the state change to the system caller's state hook so that the
    /// sparse trie task is aware of the change.
    fn deploy_precompile_at_boundary(
        &mut self,
        address: Address,
        storage: &[(U256, U256)],
    ) -> Result<(), BlockExecutionError> {
        let original = match self.inner.evm.state_mut().account_info_untracked(&address) {
            Ok(info) => info,
            Err(code) => {
                return Err(BlockExecutionError::other(
                    self.inner.evm.database_mut().error(code),
                ));
            }
        };
        if original
            .as_ref()
            .is_some_and(|info| info.code_hash != KECCAK256_EMPTY)
        {
            return Ok(());
        }

        let code = Bytecode::new_raw(Bytes::from_static(&[0xef]));
        let current = original.clone().unwrap_or_default().with_code(code.clone());
        let mut account = AccountChange::default();
        account.original = original;
        account.current = Some(current);
        let changes = StateChanges {
            accounts: [(address, account)].into_iter().collect(),
            code: [(code.hash_slow(), code)].into_iter().collect(),
            _non_exhaustive: (),
        };
        self.inner.commit_state_changes(&changes);
        Ok(())
    }

    /// Installs and initializes the TIP-1091 ZoneFactory when T9 first becomes active.
    ///
    /// The code marker is the one-time activation sentinel. The owner and initial zone ID are
    /// fixed T9 protocol constants.
    fn deploy_zone_factory_at_boundary(&mut self) -> Result<(), BlockExecutionError> {
        let factory_config =
            U256::from(1) | (U256::from_be_slice(INITIAL_FACTORY_OWNER.as_slice()) << u32::BITS);
        self.deploy_precompile_at_boundary(ZONE_FACTORY_ADDRESS, &[(U256::ZERO, factory_config)])
    }

    fn apply_current_committee_system_call(&mut self) -> Result<(), BlockExecutionError> {
        if !self.evm().config_spec_id().is_t8() {
            return Ok(());
        }

        let epoch_length = self.evm().block().ext.epoch_length.get();
        let block_number = self.evm().block().number.to::<u64>();
        if !block_number.saturating_add(1).is_multiple_of(epoch_length) {
            return Ok(());
        }

        let outcome =
            tempo_dkg_onchain_artifacts::OnchainDkgOutcome::read(&mut self.extra_data.as_ref())
                .map_err(|err| {
                    BlockValidationError::msg(format!(
                        "failed decoding boundary block extra data as DKG outcome: {err}"
                    ))
                })?;
        let epoch = outcome.epoch.get();
        let public_keys = outcome
            .players()
            .iter()
            .map(|key| B256::from_slice(key.as_ref()))
            .collect();

        let calldata = ICurrentCommittee::setCommitteeMembersCall {
            epoch,
            publicKeys: public_keys,
        }
        .abi_encode()
        .into();

        let result = self
            .evm_mut()
            .system_call(
                SystemTx::new(CURRENT_COMMITTEE_ADDRESS, calldata).with_caller(Address::ZERO),
            )
            .map_err(|err| BlockExecutionError::msg(err.to_string()))?
            .detach();

        if !result.result.status {
            return Err(BlockValidationError::msg("current committee system call failed").into());
        }

        self.inner.commit_state_changes(&result.state_changes);
        Ok(())
    }

    /// Validates a system transaction.
    pub(crate) fn validate_system_tx(
        &self,
        tx: &TempoTxEnvelope,
    ) -> Result<BlockSection, BlockValidationError> {
        let block = self.evm().block();
        let block_number = block.number.to_be_bytes::<32>();
        let to = tx.to().unwrap_or_default();

        // Handle end-of-block system transactions (subblocks signatures only)
        let mut seen_subblocks_signatures = match self.section {
            BlockSection::System {
                seen_subblocks_signatures,
            } => seen_subblocks_signatures,
            _ => false,
        };

        if to.is_zero() {
            if seen_subblocks_signatures {
                return Err(BlockValidationError::msg(
                    "duplicate subblocks metadata system transaction",
                ));
            }

            if self.evm().config_spec_id().is_t4() {
                return Err(BlockValidationError::msg("subblocks are disabled in T4+"));
            }

            let Some((metadata_input, input_block_number)) = tx.input().split_last_chunk::<32>()
            else {
                return Err(BlockValidationError::msg(
                    "invalid subblocks metadata system transaction",
                ));
            };

            if input_block_number != &block_number {
                return Err(BlockValidationError::msg(
                    "invalid subblocks metadata system transaction",
                ));
            }

            let mut buf = metadata_input;
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
            seen_subblocks_signatures,
        })
    }

    pub(crate) fn validate_shared_gas(
        &self,
        metadata: &[SubBlockMetadata],
    ) -> Result<(), BlockValidationError> {
        // Skip incentive gas validation if validator set context is not available.
        let Some(validator_set) = &self.validator_set else {
            return Ok(());
        };
        let gas_per_subblock = self
            .shared_gas_limit
            .checked_div(validator_set.len() as u64)
            .expect("validator set must not be empty");

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

            let reserved_gas = transactions
                .iter()
                .map(|tx| core::cmp::min(tx.gas_limit(), self.evm().version().tx_gas_limit_cap))
                .sum::<u64>();

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

            // TODO: Add namespace?
            if !validator.verify(&[], signature_hash.as_slice(), &signature) {
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

    /// Pre-validate a transaction before execution.
    ///
    /// This is only done for system transaction as they are effectively bypassing
    /// the regular block gas limit checks and we need to make sure that they
    /// only perform explicitly allowed actions.
    pub(crate) fn validate_tx_pre_execution(
        &self,
        tx: &TempoTxEnvelope,
    ) -> Result<Option<BlockSection>, BlockValidationError> {
        if tx.is_system_tx() {
            self.validate_system_tx(tx).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Returns whether `tx` qualifies for the payment lane under the active hardfork.
    ///
    /// T5+: TIP-1045 classification ([`is_payment_v2`]).
    /// Pre-T5: legacy TIP-20 prefix-only check ([`is_payment_v1`]).
    ///
    /// [`is_payment_v1`]: TempoTxEnvelope::is_payment_v1
    /// [`is_payment_v2`]: TempoTxEnvelope::is_payment_v2
    pub(crate) fn is_payment(&self, tx: &TempoTxEnvelope) -> bool {
        if self.evm().config_spec_id().is_t5() {
            tx.is_payment_v2()
        } else {
            tx.is_payment_v1()
        }
    }

    pub(crate) fn validate_tx(
        &self,
        tx: &TempoTxEnvelope,
        gas_used: u64,
    ) -> Result<BlockSection, BlockValidationError> {
        // Start with processing of transaction kinds that require specific sections.
        if tx.is_system_tx() {
            self.validate_system_tx(tx)
        } else if let Some(tx_proposer) = tx.subblock_proposer() {
            match self.section {
                BlockSection::GasIncentive | BlockSection::System { .. } => {
                    Err(BlockValidationError::msg("subblock section already passed"))
                }
                BlockSection::StartOfBlock | BlockSection::NonShared => {
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
                BlockSection::StartOfBlock | BlockSection::NonShared => {
                    if gas_used > self.non_shared_gas_left
                        || (!self.is_payment(tx) && gas_used > self.non_payment_gas_left)
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

impl<'a> BlockExecutor for TempoBlockExecutor<'a> {
    type Primitives = TempoPrimitives;
    type Evm = TempoEvm<'a>;
    type Transaction = TempoTxEnv;
    type TransactionResult = TxResult<TempoEvmTypes>;
    type TransactionResultWithState = TempoTxResult;
    type BlockAccessList = Bal;
    type TransactionOutput = GasOutput;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        if self
            .inner
            .ctx
            .withdrawals
            .as_ref()
            .is_some_and(|withdrawals| !withdrawals.is_empty())
        {
            return Err(BlockValidationError::msg("withdrawals are not permitted").into());
        }

        self.inner.apply_pre_execution_changes()?;

        // Deploy 0xEF marker bytecode to precompiles at their activation hardforks.
        if self.evm().config_spec_id().is_t2() {
            self.deploy_precompile_at_boundary(VALIDATOR_CONFIG_V2_ADDRESS)?;
        }
        if self.evm().config_spec_id().is_t3() {
            self.deploy_precompile_at_boundary(SIGNATURE_VERIFIER_ADDRESS)?;
            self.deploy_precompile_at_boundary(ADDRESS_REGISTRY_ADDRESS)?;
        }
        if self.evm().config_spec_id().is_t5() {
            self.deploy_precompile_at_boundary(TIP20_CHANNEL_RESERVE_ADDRESS)?;
        }
        if self.evm().config_spec_id().is_t6() {
            self.deploy_precompile_at_boundary(RECEIVE_POLICY_GUARD_ADDRESS)?;
        }
        if self.evm().config_spec_id().is_t7() {
            self.deploy_precompile_at_boundary(STORAGE_CREDITS_ADDRESS)?;
        }
        if self.evm().config_spec_id().is_t8() {
            self.deploy_precompile_at_boundary(CURRENT_COMMITTEE_ADDRESS)?;
        }

        Ok(())
    }

    fn receipts(&self) -> &[TempoReceipt] {
        self.inner.receipts()
    }

    fn execute_transaction_without_commit(
        &mut self,
        mut tx: Self::Transaction,
    ) -> Result<Self::TransactionResultWithState, BlockExecutionError> {
        // Remove any prewarming-specific context that was added to the tx env.
        tx.set_expiring_nonce_idx(None);
        let original = tx.transaction();
        let next_section = self.validate_tx_pre_execution(original)?;

        let block = *self.evm().block();
        // If we are dealing with a subblock transaction, configure the fee recipient context.
        if let Some(validator) = original.subblock_proposer() {
            let fee_recipient = *self
                .subblock_fee_recipients
                .get(&validator)
                .ok_or(BlockExecutionError::msg("invalid subblock transaction"))?;

            let mut subblock = block;
            subblock.beneficiary = fee_recipient;
            self.evm_mut().set_block(subblock);
        }
        let result = self
            .inner
            .execute_transaction_without_commit(&tx, original.gas_limit());

        self.evm_mut().set_block(block);

        let inner = result?;

        // TIP-1016 enabled: use block_regular_gas_used (excludes state gas) for section
        // validation, matching block gas limit semantics. TIP-1016 disabled: use tx_gas_used.
        let block_gas_used = if self.evm().version().feature(evm2::EvmFeatures::EIP8037) {
            inner.result.regular_gas_spent()
        } else {
            inner.result.tx_gas_used()
        };

        let next_section = if let Some(next_section) = next_section {
            // If pre-execution validation returned a section to use, just use it.
            next_section
        } else {
            self.validate_tx(original, block_gas_used)?
        };
        // Snapshot the per-tx validator-credited fee set by the handler's `reimburse_caller`
        let validator_fee = inner.result.ext.validator_fee;
        Ok(TempoTxResult {
            inner,
            next_section,
            is_payment: self.is_payment(original),
            tx_type: original.tx_type(),
            tx: matches!(next_section, BlockSection::SubBlock { .. }).then(|| original.clone()),
            block_gas_used,
            validator_fee,
        })
    }

    fn commit_transaction(
        &mut self,
        output: Self::TransactionResultWithState,
    ) -> Result<Self::TransactionOutput, BlockExecutionError> {
        let TempoTxResult {
            inner,
            next_section,
            is_payment,
            tx_type,
            tx,
            block_gas_used,
            validator_fee: _,
        } = output;

        let gas_output = self
            .inner
            .commit_transaction(inner, tx_type, 0, &TempoReceiptBuilder);

        self.section = next_section;

        match self.section {
            BlockSection::StartOfBlock => {
                // no gas spending for start-of-block system transactions
            }
            BlockSection::NonShared => {
                self.non_shared_gas_left -= block_gas_used;
                if !is_payment {
                    self.non_payment_gas_left -= block_gas_used;
                }
            }
            BlockSection::SubBlock { proposer } => {
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

                last_subblock
                    .1
                    .push(tx.expect("missing tx for subblock transaction"));
            }
            BlockSection::GasIncentive => {
                self.incentive_gas_used += block_gas_used;
            }
            BlockSection::System { .. } => {
                // no gas spending for end-of-block system transactions
            }
        }

        self.replay_state.commit_tx_changes();

        Ok(gas_output)
    }

    fn finish_with_block_access_list(
        mut self,
    ) -> Result<(BlockExecutionOutput<TempoReceipt>, Option<BlockAccessList>), BlockExecutionError>
    {
        let seen_subblock_signatures = match self.section {
            BlockSection::System {
                seen_subblocks_signatures,
            } => seen_subblocks_signatures,
            _ => false,
        };

        // Post T4, if subblocks metadata transaction was not seen, imply empty metadata.
        if !seen_subblock_signatures && self.evm().config_spec_id().is_t4() {
            self.validate_shared_gas(&[])?;
        }

        self.apply_current_committee_system_call()?;

        let amsterdam_eip8037_enabled = self.evm().version().feature(evm2::EvmFeatures::EIP8037);

        let regular_gas_used = self.inner.block_regular_gas_used();
        let (mut output, block_access_list) = self
            .inner
            .finish_with_block_access_list(&TempoReceiptBuilder)?;

        // TIP-1016 enabled: block header `gas_used` = block_regular_gas_used.
        // State gas is charged to users (in receipts) but exempted from block
        // capacity. block_regular_gas_used is accumulated per-tx as
        // max(total_spent - state_spent, floor) and is independent of refunds.
        //
        // TIP-1016 disabled: use the standard gas_used from the inner executor which equals
        // cumulative_tx_gas_used (total_spent - refunded), matching the original
        // block header semantics.
        if amsterdam_eip8037_enabled {
            output.result.gas_used = regular_gas_used;
        }

        Ok((output, block_access_list))
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        &mut self.inner.evm
    }

    fn evm(&self) -> &Self::Evm {
        &self.inner.evm
    }

    fn set_state_hook(&mut self, hook: impl FnMut(HashedPostState) + Send + 'static) -> bool {
        self.inner.set_state_hook(hook);
        true
    }

    fn convert_block_access_list(
        block_access_list: &BlockAccessList,
    ) -> Result<Self::BlockAccessList, BlockExecutionError> {
        Bal::try_from(block_access_list.as_slice()).map_err(BlockExecutionError::other)
    }

    fn set_block_access_list(&mut self, block_access_list: Arc<Self::BlockAccessList>) {
        self.inner.set_block_access_list(block_access_list);
    }

    fn set_block_access_index(&mut self, index: BlockAccessIndex) {
        self.inner.set_block_access_index(index);
    }

    fn enable_block_access_list_builder(&mut self) {
        self.inner.enable_block_access_list_builder();
    }

    fn take_block_access_list(&mut self) -> Option<BlockAccessList> {
        self.inner.take_block_access_list()
    }
}

// Test-only methods to set internal state without exposing fields as pub(crate)
#[cfg(test)]
impl TempoBlockExecutor<'_> {
    /// Set the block section for testing section transition logic.
    pub(crate) fn set_section_for_test(&mut self, section: BlockSection) {
        self.section = section;
    }

    /// Add a seen subblock for testing shared gas validation.
    pub(crate) fn add_seen_subblock_for_test(
        &mut self,
        proposer: PartialValidatorKey,
        txs: Vec<TempoTxEnvelope>,
    ) {
        self.seen_subblocks.push((proposer, txs));
    }

    /// Set incentive gas used for testing gas limit validation.
    pub(crate) fn set_incentive_gas_used_for_test(&mut self, gas: u64) {
        self.incentive_gas_used = gas;
    }

    /// Get the current section for assertions.
    pub(crate) fn section(&self) -> BlockSection {
        self.section
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestExecutorBuilder, test_chainspec};
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_primitives::{Bytes, Log, Signature, TxKind, bytes::BytesMut};
    use alloy_rlp::Encodable;
    use commonware_codec::Encode as _;
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{Signer, bls12381::dkg, ed25519::PrivateKey};
    use commonware_math::algebra::Random as _;
    use commonware_utils::{N3f1, TryFromIterator as _, ordered};
    use evm2::evm::{AccountInfo, InMemoryDB};
    use rand_08::SeedableRng as _;
    use reth_chainspec::EthChainSpec;
    use std::{
        iter::repeat_with,
        sync::{Arc, Mutex},
    };
    use tempo_chainspec::{TempoChainSpec, TempoHardfork, spec::DEV};
    use tempo_contracts::precompiles::{
        CURRENT_COMMITTEE_ADDRESS, ICurrentCommittee, PATH_USD_ADDRESS, ZONE_MESSENGER_ADDRESS,
        ZONE_PORTAL_IMPL_ADDRESS, ZONE_VERIFIER_ADDRESS,
    };
    use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
    use tempo_primitives::{
        SubBlockMetadata, TempoSignature, TempoTransaction, TempoTxType,
        subblock::{SubBlockVersion, TEMPO_SUBBLOCK_NONCE_KEY_PREFIX},
        transaction::{Call, envelope::TEMPO_SYSTEM_TX_SIGNATURE},
    };

    fn create_legacy_tx() -> TempoTxEnvelope {
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 0,
            gas_price: 1,
            gas_limit: 21000,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()))
    }

    fn create_tip20_empty_calldata_tx() -> TempoTxEnvelope {
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 0,
            gas_price: 1,
            gas_limit: 21000,
            to: TxKind::Call(PATH_USD_ADDRESS),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()))
    }

    fn create_dkg_outcome(epoch: u64, players: usize) -> OnchainDkgOutcome {
        let mut rng = rand_08::rngs::StdRng::seed_from_u64(epoch);
        let mut player_keys = repeat_with(|| PrivateKey::random(&mut rng))
            .take(players)
            .collect::<Vec<_>>();
        player_keys.sort_by_key(|key| key.public_key());

        let player_set =
            ordered::Set::try_from_iter(player_keys.iter().map(|key| key.public_key())).unwrap();
        let (output, shares) =
            dkg::deal::<_, _, N3f1>(&mut rng, Default::default(), player_set).unwrap();

        OnchainDkgOutcome {
            epoch: Epoch::new(epoch),
            output,
            next_players: shares.keys().clone(),
            is_next_full_dkg: false,
        }
    }

    fn read_current_committee(
        executor: &mut TempoBlockExecutor<'_>,
    ) -> ICurrentCommittee::getCommitteeMembersReturn {
        let result = executor
            .evm_mut()
            .system_call(SystemTx::new(
                CURRENT_COMMITTEE_ADDRESS,
                ICurrentCommittee::getCommitteeMembersCall {}
                    .abi_encode()
                    .into(),
            ))
            .unwrap();
        assert!(
            result.result().status,
            "getCommitteeMembers failed: {result:?}"
        );
        ICurrentCommittee::getCommitteeMembersCall::abi_decode_returns(&result.result().output)
            .unwrap()
    }

    #[test]
    fn test_build_receipt() {
        let builder = TempoReceiptBuilder;
        let tx = create_legacy_tx();
        let logs = vec![Log::new_unchecked(
            Address::ZERO,
            vec![B256::ZERO],
            Bytes::new(),
        )];
        let result = TxResult::<TempoEvmTypes> {
            status: true,
            total_gas_spent: 21000,
            logs,
            ..Default::default()
        };

        let cumulative_gas_used = 21000;

        let receipt = builder.build_receipt(ReceiptBuilderCtx {
            tx_type: tx.tx_type(),
            result,
            cumulative_gas_used,
        });

        assert_eq!(receipt.tx_type, TempoTxType::Legacy);
        assert!(receipt.success);
        assert_eq!(receipt.cumulative_gas_used, 21000);
        assert_eq!(receipt.logs.len(), 1);
        assert_eq!(receipt.logs[0].address, Address::ZERO);
    }

    #[test]
    fn test_validate_system_tx() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let executor = TestExecutorBuilder::default().build(&mut db, &chainspec);

        let signer = PrivateKey::from_seed(0);
        let metadata = vec![create_valid_subblock_metadata(B256::ZERO, &signer)];
        let input = create_system_tx_input(metadata, 1);
        let system_tx = create_system_tx(chainspec.chain().id(), input);

        let result = executor.validate_system_tx(&system_tx);
        assert!(
            result.is_ok(),
            "validate_system_tx failed: {:?}",
            result.err()
        );
        assert_eq!(
            result.unwrap(),
            BlockSection::System {
                seen_subblocks_signatures: true
            }
        );
    }

    fn create_system_tx_input(metadata: Vec<SubBlockMetadata>, block_number: u64) -> Bytes {
        let mut input = BytesMut::new();
        metadata.encode(&mut input);
        input.extend_from_slice(&U256::from(block_number).to_be_bytes::<32>());
        input.freeze().into()
    }

    fn create_system_tx(chain_id: u64, input: Bytes) -> TempoTxEnvelope {
        TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(chain_id),
                nonce: 0,
                gas_price: 0,
                gas_limit: 0,
                to: TxKind::Call(Address::ZERO),
                value: U256::ZERO,
                input,
            },
            TEMPO_SYSTEM_TX_SIGNATURE,
        ))
    }

    fn create_valid_subblock_metadata(parent_hash: B256, signer: &PrivateKey) -> SubBlockMetadata {
        let validator_key = B256::from_slice(&signer.public_key());
        let subblock = tempo_primitives::SubBlock {
            version: SubBlockVersion::V1,
            parent_hash,
            fee_recipient: Address::ZERO,
            transactions: vec![],
        };
        let signature_hash = subblock.signature_hash();
        let signature = signer.sign(&[], signature_hash.as_slice());

        SubBlockMetadata {
            version: SubBlockVersion::V1,
            validator: validator_key,
            fee_recipient: Address::ZERO,
            signature: Bytes::copy_from_slice(signature.as_ref()),
        }
    }

    #[test]
    fn test_validate_system_tx_duplicate_subblocks_system_tx() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let executor = TestExecutorBuilder::default()
            .with_section(BlockSection::System {
                seen_subblocks_signatures: true,
            })
            .build(&mut db, &chainspec);

        let signer = PrivateKey::from_seed(0);
        let metadata = vec![create_valid_subblock_metadata(B256::ZERO, &signer)];
        let input = create_system_tx_input(metadata, 1);
        let system_tx = create_system_tx(chainspec.chain().id(), input);

        let result = executor.validate_system_tx(&system_tx);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "duplicate subblocks metadata system transaction"
        );
    }

    #[test]
    fn test_validate_system_tx_invalid_sublocks_metadata() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let executor = TestExecutorBuilder::default().build(&mut db, &chainspec);

        let mut input = BytesMut::new();
        input.extend_from_slice(&[0xff, 0xff, 0xff]); // Invalid RLP
        input.extend_from_slice(&U256::from(1u64).to_be_bytes::<32>());
        let system_tx = create_system_tx(chainspec.chain().id(), input.freeze().into());

        let result = executor.validate_system_tx(&system_tx);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid subblocks metadata system transaction"
        );
    }

    #[test]
    fn test_validate_system_tx_invalid_system_tx() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let executor = TestExecutorBuilder::default().build(&mut db, &chainspec);

        // Create system tx with non-zero `to` address
        let system_tx = TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(chainspec.chain().id()),
                nonce: 0,
                gas_price: 0,
                gas_limit: 0,
                to: TxKind::Call(Address::repeat_byte(0x01)), // Non-zero address
                value: U256::ZERO,
                input: Bytes::new(),
            },
            TEMPO_SYSTEM_TX_SIGNATURE,
        ));

        let result = executor.validate_system_tx(&system_tx);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid system transaction"
        );
    }

    #[test]
    fn test_validate_system_tx_rejects_metadata_tx_in_t4() {
        let chainspec = DEV.clone();
        let mut db = InMemoryDB::default();
        let executor = TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T4)
            .build(&mut db, &chainspec);

        let signer = PrivateKey::from_seed(0);
        let metadata = vec![create_valid_subblock_metadata(B256::ZERO, &signer)];
        let input = create_system_tx_input(metadata, 1);
        let system_tx = create_system_tx(chainspec.chain().id(), input);

        let result = executor.validate_system_tx(&system_tx);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "subblocks are disabled in T4+"
        );
    }

    #[test]
    fn test_validate_shared_gas() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let signer = PrivateKey::from_seed(0);
        let validator_key = B256::from_slice(&signer.public_key());
        let executor = TestExecutorBuilder::default()
            .with_validator_set(vec![validator_key])
            .build(&mut db, &chainspec);

        let metadata = vec![create_valid_subblock_metadata(B256::ZERO, &signer)];
        let result = executor.validate_shared_gas(&metadata);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_shared_gas_set_does_not_contain_validator() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let signer = PrivateKey::from_seed(0);
        let different_validator = B256::repeat_byte(0x42); // Not the signer's key
        let executor = TestExecutorBuilder::default()
            .with_validator_set(vec![different_validator])
            .build(&mut db, &chainspec);

        let metadata = vec![create_valid_subblock_metadata(B256::ZERO, &signer)];
        let result = executor.validate_shared_gas(&metadata);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid subblock validator"
        );
    }

    #[test]
    fn test_validate_shared_gas_more_than_one_subblock_per_validator() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let signer = PrivateKey::from_seed(0);
        let validator_key = B256::from_slice(&signer.public_key());
        let executor = TestExecutorBuilder::default()
            .with_validator_set(vec![validator_key])
            .build(&mut db, &chainspec);

        // Same validator appears twice
        let m = create_valid_subblock_metadata(B256::ZERO, &signer);
        let metadata = vec![m.clone(), m];

        let result = executor.validate_shared_gas(&metadata);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "only one subblock per validator is allowed"
        );
    }

    #[test]
    fn test_validate_shared_gas_invalid_signature_encoding() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let signer = PrivateKey::from_seed(0);
        let validator_key = B256::from_slice(&signer.public_key());
        let executor = TestExecutorBuilder::default()
            .with_validator_set(vec![validator_key])
            .build(&mut db, &chainspec);

        // Create metadata with invalid signature encoding
        let metadata = vec![SubBlockMetadata {
            version: SubBlockVersion::V1,
            validator: validator_key,
            fee_recipient: Address::ZERO,
            signature: Bytes::from_static(&[0x01, 0x02, 0x03]),
        }];

        let result = executor.validate_shared_gas(&metadata);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid subblock signature encoding"
        );
    }

    #[test]
    fn test_validate_shared_gas_invalid_signature() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let signer = PrivateKey::from_seed(0);
        let validator_key = B256::from_slice(&signer.public_key());
        let executor = TestExecutorBuilder::default()
            .with_validator_set(vec![validator_key])
            .build(&mut db, &chainspec);

        // Create metadata with wrong signature
        let wrong_signer = PrivateKey::from_seed(1);
        let subblock = tempo_primitives::SubBlock {
            version: SubBlockVersion::V1,
            parent_hash: B256::ZERO,
            fee_recipient: Address::ZERO,
            transactions: vec![],
        };
        let signature_hash = subblock.signature_hash();
        let wrong_signature = wrong_signer.sign(&[], signature_hash.as_slice());

        let metadata = vec![SubBlockMetadata {
            version: SubBlockVersion::V1,
            validator: validator_key, // Correct validator
            fee_recipient: Address::ZERO,
            signature: Bytes::copy_from_slice(wrong_signature.as_ref()), // Wrong signature
        }];

        let result = executor.validate_shared_gas(&metadata);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid subblock signature"
        );
    }

    #[test]
    fn test_validate_shared_gas_gas_used_exceeds_gas_per_subblock() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let signer = PrivateKey::from_seed(0);
        let validator_key = B256::from_slice(&signer.public_key());
        let tx = create_legacy_tx();
        let proposer = PartialValidatorKey::from_slice(&validator_key[..15]);

        // Create subblock with transactions included
        let subblock = tempo_primitives::SubBlock {
            version: SubBlockVersion::V1,
            parent_hash: B256::ZERO,
            fee_recipient: Address::ZERO,
            transactions: vec![tx.clone()],
        };

        let executor = TestExecutorBuilder::default()
            .with_validator_set(vec![validator_key])
            .with_shared_gas_limit(100) // Low shared gas limit
            .with_seen_subblock(proposer, vec![tx])
            .build(&mut db, &chainspec);
        let signature_hash = subblock.signature_hash();
        let signature = signer.sign(&[], signature_hash.as_slice());

        let metadata = vec![SubBlockMetadata {
            version: SubBlockVersion::V1,
            validator: validator_key,
            fee_recipient: Address::ZERO,
            signature: Bytes::copy_from_slice(signature.as_ref()),
        }];

        let result = executor.validate_shared_gas(&metadata);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "subblock gas used exceeds gas per subblock"
        );
    }

    #[test]
    fn test_validate_shared_gas_unexpected_subblock_len() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let signer = PrivateKey::from_seed(0);
        let validator_key = B256::from_slice(&signer.public_key());

        // Add a seen subblock from a different validator that won't match metadata
        let different_key = B256::repeat_byte(0x99);
        let different_proposer = PartialValidatorKey::from_slice(&different_key[..15]);

        let executor = TestExecutorBuilder::default()
            .with_validator_set(vec![validator_key])
            .with_seen_subblock(different_proposer, vec![])
            .build(&mut db, &chainspec);

        // Metadata has validator_key but seen_subblocks has different_key
        let metadata = vec![create_valid_subblock_metadata(B256::ZERO, &signer)];

        let result = executor.validate_shared_gas(&metadata);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "failed to map all non-empty subblocks to metadata"
        );
    }

    #[test]
    fn test_validate_shared_gas_limit_exceeded() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let signer = PrivateKey::from_seed(0);
        let validator_key = B256::from_slice(&signer.public_key());

        // Set incentive_gas_used higher than available incentive gas
        let executor = TestExecutorBuilder::default()
            .with_validator_set(vec![validator_key])
            .with_incentive_gas_used(100_000_000)
            .build(&mut db, &chainspec);

        let metadata = vec![create_valid_subblock_metadata(B256::ZERO, &signer)];

        let result = executor.validate_shared_gas(&metadata);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "incentive gas limit exceeded"
        );
    }

    #[test]
    fn test_is_payment_uses_v2_from_t5() {
        let tx = create_tip20_empty_calldata_tx();
        assert!(
            tx.is_payment_v1(),
            "pre-T5 prefix check accepts TIP-20 target"
        );
        assert!(
            !tx.is_payment_v2(),
            "T5 classifier rejects empty calldata per TIP-1045"
        );

        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let pre_t5_executor = TestExecutorBuilder::default().build(&mut db, &chainspec);
        assert!(pre_t5_executor.is_payment(&tx));

        let chainspec = DEV.clone();
        let mut db = InMemoryDB::default();
        let t5_executor = TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T5)
            .build(&mut db, &chainspec);
        assert!(!t5_executor.is_payment(&tx));
    }

    #[test]
    fn test_validate_tx() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let executor = TestExecutorBuilder::default().build(&mut db, &chainspec);

        // Test regular transaction in StartOfBlock section goes to NonShared
        let tx = create_legacy_tx();
        let result = executor.validate_tx(&tx, 21000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), BlockSection::NonShared);
    }

    fn create_subblock_tx(proposer: &PartialValidatorKey) -> TempoTxEnvelope {
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[0] = TEMPO_SUBBLOCK_NONCE_KEY_PREFIX;
        nonce_bytes[1..16].copy_from_slice(proposer.as_slice());

        let tx = TempoTransaction {
            chain_id: 1,
            calls: vec![Call {
                to: Address::ZERO.into(),
                input: Default::default(),
                value: Default::default(),
            }],
            gas_limit: 21000,
            nonce_key: U256::from_be_bytes(nonce_bytes),
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            ..Default::default()
        };

        let signature = TempoSignature::from(Signature::test_signature());
        TempoTxEnvelope::AA(tx.into_signed(signature))
    }

    #[test]
    fn test_validate_tx_subblock_section_already_passed() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let signer = PrivateKey::from_seed(0);
        let validator_key = B256::from_slice(&signer.public_key());
        let proposer = PartialValidatorKey::from_slice(&validator_key[..15]);

        // Test with GasIncentive section
        let executor = TestExecutorBuilder::default()
            .with_section(BlockSection::GasIncentive)
            .build(&mut db, &chainspec);

        let subblock_tx = create_subblock_tx(&proposer);
        let result = executor.validate_tx(&subblock_tx, 21000);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "subblock section already passed"
        );

        // Also test with System section
        let mut db2 = InMemoryDB::default();
        let executor2 = TestExecutorBuilder::default()
            .with_section(BlockSection::System {
                seen_subblocks_signatures: false,
            })
            .build(&mut db2, &chainspec);

        let result = executor2.validate_tx(&subblock_tx, 21000);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "subblock section already passed"
        );
    }

    #[test]
    fn test_validate_tx_proposer_subblock_already_processed() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let signer1 = PrivateKey::from_seed(0);
        let validator_key1 = B256::from_slice(&signer1.public_key());
        let proposer1 = PartialValidatorKey::from_slice(&validator_key1[..15]);

        let signer2 = PrivateKey::from_seed(1);
        let validator_key2 = B256::from_slice(&signer2.public_key());
        let proposer2 = PartialValidatorKey::from_slice(&validator_key2[..15]);

        // Set section to SubBlock with a different proposer, and mark proposer1 as already seen
        let executor = TestExecutorBuilder::default()
            .with_section(BlockSection::SubBlock {
                proposer: proposer2,
            })
            .with_seen_subblock(proposer1, vec![])
            .build(&mut db, &chainspec);

        // Try to submit a tx for proposer1 (already processed)
        let subblock_tx = create_subblock_tx(&proposer1);
        let result = executor.validate_tx(&subblock_tx, 21000);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "proposer's subblock already processed"
        );
    }

    #[test]
    fn test_validate_tx_regular_tx_follow_system_tx() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();

        // Set section to System
        let executor = TestExecutorBuilder::default()
            .with_section(BlockSection::System {
                seen_subblocks_signatures: false,
            })
            .build(&mut db, &chainspec);

        // Try to validate a regular tx
        let tx = create_legacy_tx();
        let result = executor.validate_tx(&tx, 21000);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "regular transaction can't follow system transaction"
        );
    }

    #[test]
    fn test_commit_transaction() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_general_gas_limit(30_000_000)
            .with_parent_beacon_block_root(B256::ZERO)
            .build(&mut db, &chainspec);

        // Apply pre-execution changes first
        executor.apply_pre_execution_changes().unwrap();

        let tx = create_legacy_tx();
        let output = TempoTxResult {
            inner: TxResultWithState {
                result: TxResult {
                    status: true,
                    total_gas_spent: 21000,
                    ..Default::default()
                },
                ..Default::default()
            },
            next_section: BlockSection::NonShared,
            is_payment: false,
            tx_type: tx.tx_type(),
            tx: None,
            block_gas_used: 21000,
            validator_fee: U256::ZERO,
        };

        let gas_output = executor.commit_transaction(output).unwrap();

        assert_eq!(gas_output.tx_gas_used(), 21000);
        assert_eq!(executor.section(), BlockSection::NonShared);
    }

    #[test]
    fn test_current_committee_system_call_writes_boundary_outcome() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let outcome = create_dkg_outcome(42, 3);
        let expected_public_keys = outcome
            .players()
            .iter()
            .map(|key| B256::from_slice(key.as_ref()))
            .collect::<Vec<_>>();

        let mut executor = TestExecutorBuilder::default()
            .with_block_number(4)
            .with_epoch_length(5)
            .with_extra_data(outcome.encode().into())
            .with_spec(TempoHardfork::T8)
            .build(&mut db, &chainspec);
        executor
            .deploy_precompile_at_boundary(CURRENT_COMMITTEE_ADDRESS, &[])
            .unwrap();

        executor.apply_current_committee_system_call().unwrap();

        let committee = read_current_committee(&mut executor);
        assert_eq!(committee.epoch, outcome.epoch.get());
        assert_eq!(committee.publicKeys, expected_public_keys);
    }

    #[test]
    fn test_current_committee_system_call_skips_non_boundary_block() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_block_number(3)
            .with_epoch_length(5)
            .with_extra_data(Bytes::from_static(&[0xff]))
            .with_spec(TempoHardfork::T8)
            .build(&mut db, &chainspec);
        executor
            .deploy_precompile_at_boundary(CURRENT_COMMITTEE_ADDRESS, &[])
            .unwrap();

        executor.apply_current_committee_system_call().unwrap();

        let committee = read_current_committee(&mut executor);
        assert_eq!(committee.epoch, 0);
        assert!(committee.publicKeys.is_empty());
    }

    #[test]
    fn test_current_committee_system_call_rejects_invalid_boundary_extra_data() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_block_number(4)
            .with_epoch_length(5)
            .with_extra_data(Bytes::from_static(&[0xff]))
            .with_spec(TempoHardfork::T8)
            .build(&mut db, &chainspec);

        let err = executor.apply_current_committee_system_call().unwrap_err();
        assert!(
            err.to_string()
                .contains("failed decoding boundary block extra data as DKG outcome"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_finish() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let executor = TestExecutorBuilder::default().build(&mut db, &chainspec);

        let result = executor.finish();
        assert!(result.is_ok());
    }

    #[test]
    fn test_finish_t4_without_metadata_passes_when_incentive_gas_is_zero() {
        let chainspec = DEV.clone();
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .with_validator_set(vec![B256::repeat_byte(0x01)])
            .with_spec(TempoHardfork::T4)
            .build(&mut db, &chainspec);
        executor.apply_pre_execution_changes().unwrap();

        assert!(executor.finish().is_ok());
    }

    #[test]
    fn test_finish_t4_without_metadata_rejects_incentive_gas() {
        let chainspec = DEV.clone();
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .with_validator_set(vec![B256::repeat_byte(0x01)])
            .with_incentive_gas_used(1)
            .with_spec(TempoHardfork::T4)
            .build(&mut db, &chainspec);
        executor.apply_pre_execution_changes().unwrap();

        match executor.finish() {
            Err(err) => assert_eq!(err.to_string(), "incentive gas limit exceeded"),
            Ok(_) => panic!("finish should fail when T4 block has incentive gas without metadata"),
        }
    }

    #[test]
    fn test_commit_transaction_tracks_total_cumulative_gas() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_general_gas_limit(30_000_000)
            .with_parent_beacon_block_root(B256::ZERO)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();

        let tx = create_legacy_tx();
        let output = TempoTxResult {
            inner: TxResultWithState {
                result: TxResult {
                    status: true,
                    total_gas_spent: 21000,
                    ..Default::default()
                },
                ..Default::default()
            },
            next_section: BlockSection::NonShared,
            is_payment: false,
            tx_type: tx.tx_type(),
            tx: None,
            block_gas_used: 21000,
            validator_fee: U256::ZERO,
        };

        let gas_output = executor.commit_transaction(output).unwrap();

        // With zero storage creation gas, execution gas equals total gas
        assert_eq!(gas_output.tx_gas_used(), 21000);
    }

    #[test]
    fn test_cumulative_gas_accumulates_across_transactions() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_general_gas_limit(30_000_000)
            .with_parent_beacon_block_root(B256::ZERO)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();

        // Commit first transaction (21000 gas)
        let tx1 = create_legacy_tx();
        let output1 = TempoTxResult {
            inner: TxResultWithState {
                result: TxResult {
                    status: true,
                    total_gas_spent: 21000,
                    ..Default::default()
                },
                ..Default::default()
            },
            next_section: BlockSection::NonShared,
            is_payment: false,
            tx_type: tx1.tx_type(),
            tx: None,
            block_gas_used: 21000,
            validator_fee: U256::ZERO,
        };
        executor.commit_transaction(output1).unwrap();

        // Commit second transaction (50000 gas)
        let tx2 = create_legacy_tx();
        let output2 = TempoTxResult {
            inner: TxResultWithState {
                result: TxResult {
                    status: true,
                    total_gas_spent: 50000,
                    ..Default::default()
                },
                ..Default::default()
            },
            next_section: BlockSection::NonShared,
            is_payment: false,
            tx_type: tx2.tx_type(),
            tx: None,
            block_gas_used: 50000,
            validator_fee: U256::ZERO,
        };
        executor.commit_transaction(output2).unwrap();

        // Receipts should have cumulative total gas (tracked by inner executor)
        let receipts = executor.receipts();
        assert_eq!(receipts[0].cumulative_gas_used, 21000);
        assert_eq!(receipts[1].cumulative_gas_used, 71000);
    }

    #[test]
    fn test_finish_returns_execution_gas_for_block_header() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_general_gas_limit(30_000_000)
            .with_parent_beacon_block_root(B256::ZERO)
            .with_section(BlockSection::NonShared)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();

        // Manually set state to simulate a committed transaction (no state gas)
        executor
            .commit_transaction(TempoTxResult {
                inner: TxResultWithState {
                    result: TxResult {
                        status: true,
                        total_gas_spent: 21000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                next_section: BlockSection::NonShared,
                is_payment: false,
                tx_type: TempoTxType::Legacy,
                tx: None,
                block_gas_used: 21000,
                validator_fee: U256::ZERO,
            })
            .unwrap();

        let result = executor.finish().unwrap();
        // Block header gas_used = block_regular_gas_used
        assert_eq!(result.gas_used, 21000);
    }

    #[test]
    fn test_non_shared_gas_uses_execution_gas_only() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_general_gas_limit(30_000_000)
            .with_parent_beacon_block_root(B256::ZERO)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();

        let initial_non_shared = executor.non_shared_gas_left;

        let tx = create_legacy_tx();
        let output = TempoTxResult {
            inner: TxResultWithState {
                result: TxResult {
                    status: true,
                    total_gas_spent: 50_000,
                    ..Default::default()
                },
                ..Default::default()
            },
            next_section: BlockSection::NonShared,
            is_payment: false,
            tx_type: tx.tx_type(),
            tx: None,
            block_gas_used: 50_000,
            validator_fee: U256::ZERO,
        };
        executor.commit_transaction(output).unwrap();

        assert_eq!(executor.non_shared_gas_left, initial_non_shared - 50_000);
    }

    /// T4: payment lane gas accounting must exclude state gas and use
    /// block_regular_gas_used semantics (no refunds, no state gas).
    #[test]
    fn test_t4_non_shared_gas_excludes_state_gas() {
        let chainspec = Arc::new(TempoChainSpec::from_genesis(DEV.genesis().clone()));
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_general_gas_limit(30_000_000)
            .with_parent_beacon_block_root(B256::ZERO)
            .with_amsterdam_eip8037_enabled(true)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();

        let initial_non_shared = executor.non_shared_gas_left;
        let initial_non_payment = executor.non_payment_gas_left;

        // tx with total_gas_spent=300k, state_gas=100k
        // block_regular_gas_used = max(300k - 100k, 0) = 200k
        // tx_gas_used = max(300k - 0_refund, 0) = 300k
        let tx = create_legacy_tx();
        let output = TempoTxResult {
            inner: TxResultWithState {
                result: TxResult {
                    status: true,
                    total_gas_spent: 300_000,
                    state_gas_spent: 100_000,
                    ..Default::default()
                },
                ..Default::default()
            },
            next_section: BlockSection::NonShared,
            is_payment: false,
            tx_type: tx.tx_type(),
            tx: None,
            block_gas_used: 200_000,
            validator_fee: U256::ZERO,
        };
        executor.commit_transaction(output).unwrap();

        // non_shared_gas_left should decrease by regular gas (200k), not total (300k)
        assert_eq!(
            executor.non_shared_gas_left,
            initial_non_shared - 200_000,
            "T4: non_shared_gas_left should exclude state gas"
        );
        assert_eq!(
            executor.non_payment_gas_left,
            initial_non_payment - 200_000,
            "T4: non_payment_gas_left should exclude state gas"
        );
    }

    /// T4: incentive gas accounting must also exclude state gas.
    #[test]
    fn test_t4_incentive_gas_excludes_state_gas() {
        let chainspec = Arc::new(TempoChainSpec::from_genesis(DEV.genesis().clone()));
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_general_gas_limit(30_000_000)
            .with_parent_beacon_block_root(B256::ZERO)
            .with_amsterdam_eip8037_enabled(true)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();

        let tx = create_legacy_tx();
        let output = TempoTxResult {
            inner: TxResultWithState {
                result: TxResult {
                    status: true,
                    total_gas_spent: 300_000,
                    state_gas_spent: 100_000,
                    ..Default::default()
                },
                ..Default::default()
            },
            next_section: BlockSection::GasIncentive,
            is_payment: false,
            tx_type: tx.tx_type(),
            tx: None,
            block_gas_used: 200_000,
            validator_fee: U256::ZERO,
        };
        executor.commit_transaction(output).unwrap();

        assert_eq!(
            executor.incentive_gas_used, 200_000,
            "T4: incentive_gas_used should exclude state gas"
        );
    }

    #[test]
    fn test_apply_pre_execution_deploys_validator_v2_code() {
        // Dev chainspec has t2Time: 0, so T2 is active at any timestamp.
        let chainspec = Arc::new(TempoChainSpec::from_genesis(DEV.genesis().clone()));
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .with_spec(TempoHardfork::T2)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();
        let info = executor
            .evm()
            .state()
            .overlay_db()
            .account_info(&VALIDATOR_CONFIG_V2_ADDRESS)
            .unwrap();
        assert_ne!(info.code_hash, KECCAK256_EMPTY);
    }

    #[test]
    fn test_apply_pre_execution_deploys_signature_verifier_code() {
        // Dev chainspec has t3Time: 0, so T3 is active at any timestamp.
        let chainspec = Arc::new(TempoChainSpec::from_genesis(DEV.genesis().clone()));
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .with_spec(TempoHardfork::T3)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();
        let info = executor
            .evm()
            .state()
            .overlay_db()
            .account_info(&SIGNATURE_VERIFIER_ADDRESS)
            .unwrap();
        assert_ne!(info.code_hash, KECCAK256_EMPTY);
    }

    #[test]
    fn test_apply_pre_execution_deploys_guard_code() {
        // Dev chainspec has t6Time: 0, so T6 is active at any timestamp.
        let chainspec = Arc::new(TempoChainSpec::from_genesis(DEV.genesis().clone()));
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .with_spec(TempoHardfork::T6)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();
        let info = executor
            .evm()
            .state()
            .overlay_db()
            .account_info(&RECEIVE_POLICY_GUARD_ADDRESS)
            .unwrap();
        assert_ne!(info.code_hash, KECCAK256_EMPTY);
    }

    #[test]
    fn test_pre_t3_does_not_deploy_signature_verifier_code() {
        // Moderato does not have T4 active (no t3Time set), so the code should NOT be deployed.
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();
        let info = executor
            .evm()
            .state()
            .overlay_db()
            .account_info(&SIGNATURE_VERIFIER_ADDRESS);
        assert!(
            info.is_none() || info.unwrap().code_hash == KECCAK256_EMPTY,
            "SignatureVerifier code should not be deployed before T3"
        );
    }

    #[test]
    fn test_deploy_precompile_at_boundary_dispatches_state_hook() {
        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .build(&mut db, &chainspec);

        let hook_calls: Arc<Mutex<Vec<HashedPostState>>> = Arc::new(Mutex::new(Vec::new()));
        let hook_calls_clone = hook_calls.clone();
        executor.set_state_hook(move |state| hook_calls_clone.lock().unwrap().push(state));

        let addr = Address::with_last_byte(0xff);
        executor.deploy_precompile_at_boundary(addr).unwrap();

        // Verify code was deployed.
        let info = executor
            .evm()
            .state()
            .overlay_db()
            .account_info(&addr)
            .unwrap();
        assert_ne!(info.code_hash, KECCAK256_EMPTY);

        // Verify the state hook was called exactly once with the correct address.
        let calls = hook_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "state hook should be called exactly once");
        assert!(
            calls[0]
                .accounts
                .contains_key(&alloy_primitives::keccak256(addr)),
            "state hook should contain the deployed address"
        );
    }

    #[test]
    fn test_deploy_precompile_at_boundary_preserves_existing_original_info() {
        use std::sync::{Arc, Mutex};

        let chainspec = test_chainspec();
        let mut db = InMemoryDB::default();
        let addr = Address::with_last_byte(0xfe);
        let original_info = AccountInfo {
            balance: U256::from(42),
            nonce: 7,
            ..Default::default()
        };
        db.insert_account_info(&addr, original_info.clone());

        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .build(&mut db, &chainspec);

        let hook_calls: Arc<Mutex<Vec<HashedPostState>>> = Arc::new(Mutex::new(Vec::new()));
        let hook_calls_clone = hook_calls.clone();
        executor.set_state_hook(move |state| hook_calls_clone.lock().unwrap().push(state));

        executor.deploy_precompile_at_boundary(addr, &[]).unwrap();

        let calls = hook_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "state hook should be called exactly once");
        assert!(
            calls[0]
                .accounts
                .contains_key(&alloy_primitives::keccak256(addr)),
            "state hook should contain the deployed address"
        );
        let (_, tracked) = executor
            .inner
            .block_state()
            .accounts()
            .find(|(address, _)| *address == addr)
            .unwrap();
        assert_eq!(tracked.original, Some(original_info));
    }

    #[test]
    fn test_deploy_zone_factory_at_boundary_installs_atomic_t9_state() {
        assert_eq!(
            INITIAL_FACTORY_OWNER,
            address!("0xaF571FD4B3AD43a5807A5E58bFb25ea1aB327A14")
        );
        let chainspec = Arc::new(TempoChainSpec::from_genesis(DEV.genesis().clone()));
        let mut db = State::builder().with_bundle_update().build();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .build(&mut db, &chainspec);

        let hook_calls: Arc<Mutex<Vec<EvmState>>> = Arc::new(Mutex::new(Vec::new()));
        let hook_calls_clone = hook_calls.clone();
        executor
            .evm_mut()
            .db_mut()
            .set_state_hook(Some(Box::new(move |state: EvmState| {
                hook_calls_clone.lock().unwrap().push(state);
            })));

        executor.deploy_zone_factory_at_boundary().unwrap();
        executor.deploy_zone_factory_at_boundary().unwrap();
        drop(executor);

        let factory = db.load_cache_account(ZONE_FACTORY_ADDRESS).unwrap();
        assert_eq!(
            factory
                .account_info()
                .unwrap()
                .code
                .unwrap()
                .original_bytes(),
            Bytes::from_static(&[0xef])
        );
        let expected_factory_config =
            U256::from(1) | (U256::from_be_slice(INITIAL_FACTORY_OWNER.as_slice()) << u32::BITS);
        assert_eq!(
            factory.storage_slot(U256::ZERO),
            Some(expected_factory_config)
        );

        let calls = hook_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "T9 installation must be one atomic commit");
        assert!(calls[0].contains_key(&ZONE_FACTORY_ADDRESS));
        for address in [
            ZONE_PORTAL_IMPL_ADDRESS,
            ZONE_VERIFIER_ADDRESS,
            ZONE_MESSENGER_ADDRESS,
        ] {
            assert!(
                !calls[0].contains_key(&address),
                "shared runtimes are installed through the factory, not the T9 state hook"
            );
        }
    }

    /// TIP-1016 (T4+): block header `gas_used` = `block_regular_gas_used`.
    /// Receipts track `tx_gas_used` (what the user pays, including state gas).
    /// The difference between receipts total and header gas_used is the state gas
    /// exempted from block capacity.
    #[test]
    fn test_t4_finish_exempts_state_gas_from_header() {
        // DEV chainspec has T4 active at timestamp 0.
        let chainspec = Arc::new(TempoChainSpec::from_genesis(DEV.genesis().clone()));
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .with_amsterdam_eip8037_enabled(true)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();

        // Simulate: tx with total=300k, refund=30k, state=40k
        // tx_gas_used = max(300k - 30k, floor) = 270k  (receipt gas)
        // block_regular_gas_used = max(300k - 40k, floor) = 260k  (capacity gas)
        // block_state_gas_used = 40k
        let tx_gas_used = 270_000u64;
        let regular_gas = 260_000u64;
        let state_gas = 40_000u64;

        executor
            .commit_transaction(TempoTxResult {
                inner: TxResultWithState {
                    result: TxResult {
                        status: true,
                        total_gas_spent: 300_000,
                        state_gas_spent: state_gas,
                        refunded: 30_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                next_section: BlockSection::StartOfBlock,
                is_payment: false,
                tx_type: TempoTxType::Legacy,
                tx: None,
                block_gas_used: regular_gas,
                validator_fee: U256::ZERO,
            })
            .unwrap();

        let result = executor.finish().expect("finish should succeed");

        // T4: Block header gas_used must equal block_regular_gas_used
        assert_eq!(
            result.gas_used, regular_gas,
            "T4 header gas_used ({}) must equal block_regular_gas_used ({})",
            result.gas_used, regular_gas
        );

        // Receipt tracks total gas (what user pays, including state gas)
        let last_cumulative = result.receipts.last().unwrap().cumulative_gas_used;
        assert_eq!(last_cumulative, tx_gas_used);
    }

    #[test]
    fn test_t4_finish_uses_regular_gas_when_state_gas_is_higher() {
        let chainspec = Arc::new(TempoChainSpec::from_genesis(DEV.genesis().clone()));
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .with_amsterdam_eip8037_enabled(true)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();
        executor
            .commit_transaction(TempoTxResult {
                inner: TxResultWithState {
                    result: TxResult {
                        status: true,
                        total_gas_spent: 300_000,
                        state_gas_spent: 200_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                next_section: BlockSection::StartOfBlock,
                is_payment: false,
                tx_type: TempoTxType::Legacy,
                tx: None,
                block_gas_used: 100_000,
                validator_fee: U256::ZERO,
            })
            .unwrap();

        let result = executor.finish().expect("finish should succeed");
        assert_eq!(result.gas_used, 100_000);
    }

    /// Pre-T4: block header `gas_used` must use cumulative_tx_gas_used (post-refund),
    /// not block_regular_gas_used (pre-refund). This is a regression test for a bug
    /// where `finish()` unconditionally used block_regular_gas_used, causing re-execution
    /// of historical blocks to produce a gas mismatch when transactions had SSTORE refunds.
    #[test]
    fn test_pre_t4_finish_uses_cumulative_gas_with_refunds() {
        let chainspec = test_chainspec(); // MODERATO, T4 not active at timestamp 0

        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .build(&mut db, &chainspec);

        executor.apply_pre_execution_changes().unwrap();

        // Simulate: tx with total_spent=276078, refund=2800, state_gas=0 (pre-T4)
        // tx_gas_used = 276078 - 2800 = 273278 (post-refund, what goes in receipts)
        // block_regular_gas_used = 276078 (pre-refund, no state gas to subtract)
        let cumulative = 273_278u64; // post-refund
        let regular = 276_078u64; // pre-refund (no state gas subtraction pre-T4)

        executor
            .commit_transaction(TempoTxResult {
                inner: TxResultWithState {
                    result: TxResult {
                        status: true,
                        total_gas_spent: regular,
                        refunded: regular - cumulative,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                next_section: BlockSection::StartOfBlock,
                is_payment: false,
                tx_type: TempoTxType::Legacy,
                tx: None,
                block_gas_used: cumulative,
                validator_fee: U256::ZERO,
            })
            .unwrap();

        let result = executor.finish().expect("finish should succeed");

        // Pre-T4: header gas_used must equal cumulative_tx_gas_used (post-refund),
        // NOT block_regular_gas_used (pre-refund).
        assert_eq!(
            result.gas_used, cumulative,
            "pre-T4 header gas_used ({}) must equal cumulative_tx_gas_used ({}), \
             not block_regular_gas_used ({})",
            result.gas_used, cumulative, regular
        );
    }
}
