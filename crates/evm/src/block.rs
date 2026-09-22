use crate::{
    StorageActionReplayState, TempoBlockExecutionCtx, TempoEvm, TempoEvmTypes,
    transaction::ExecutionContext,
};
use alloy_consensus::{Transaction, transaction::TxHashRef};
use alloy_eip7928::{BlockAccessIndex, BlockAccessList};
use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256};
use alloy_rlp::Decodable;
use alloy_sol_types::SolCall;
use commonware_codec::ReadExt;
use evm2::{
    EvmTypes, TxResult, TxResultWithState,
    bytecode::Bytecode,
    evm::{Bal, PendingState, SystemTx},
};
use reth_evm::{
    BlockExecutionError, BlockExecutionOutput, BlockExecutor, BlockTransactionResult,
    BlockValidationError, ExecutorTx, GasOutput, ReceiptBuilder, ReceiptBuilderCtx, RecoveredTx,
};
use reth_evm_ethereum::{EthBlockExecutor, EthTransactionResultWithState};
use reth_execution_types::EvmState;
use std::sync::Arc;
use tempo_chainspec::TempoChainSpec;
use tempo_contracts::precompiles::{
    ADDRESS_REGISTRY_ADDRESS, CURRENT_COMMITTEE_ADDRESS, ICurrentCommittee, INITIAL_FACTORY_OWNER,
    InitialZoneFactoryAccount, RECEIVE_POLICY_GUARD_ADDRESS, SIGNATURE_VERIFIER_ADDRESS,
    STORAGE_CREDITS_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS, VALIDATOR_CONFIG_V2_ADDRESS,
    initial_zone_factory_state, t13_zone_factory_state,
};
use tempo_primitives::{SubBlockMetadata, TempoReceipt, TempoTxEnvelope, TempoTxType};
use tracing::trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum BlockSection {
    /// Start of block system transactions.
    StartOfBlock,
    /// Basic section of the block. Includes arbitrary transactions chosen by the proposer.
    ///
    /// Must use at most `non_shared_gas_left` gas.
    NonShared,
    /// Gas incentive transaction.
    GasIncentive,
    /// End of block system transactions.
    System { seen_subblocks_signatures: bool },
}

/// Builder for [`TempoReceipt`].
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct TempoReceiptBuilder;

impl ReceiptBuilder for TempoReceiptBuilder {
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;

    fn build_receipt<T: EvmTypes>(
        &self,
        ctx: ReceiptBuilderCtx<TempoTxType, TxResult<T>>,
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
    inner: EthTransactionResultWithState<TempoEvmTypes, TempoTxType>,
    /// Execution provenance used to exempt RPC simulations from block gas validation.
    execution_context: ExecutionContext,
    /// Next section of the block.
    next_section: BlockSection,
    /// Whether the transaction is a payment transaction.
    is_payment: bool,
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
    #[expect(
        clippy::too_many_arguments,
        reason = "preserve execution provenance alongside precomputed results"
    )]
    pub(crate) fn new_precomputed(
        tx: &TempoTxEnvelope,
        execution_context: ExecutionContext,
        result: TxResult<TempoEvmTypes>,
        state: PendingState,
        next_section: BlockSection,
        is_payment: bool,
        block_gas_used: u64,
        validator_fee: U256,
    ) -> Self {
        Self {
            inner: EthTransactionResultWithState::new(
                TxResultWithState {
                    result,
                    pending_state: state,
                    _non_exhaustive: (),
                },
                tx.tx_type(),
                0,
            ),
            execution_context,
            next_section,
            is_payment,
            block_gas_used,
            validator_fee,
        }
    }

    /// Returns the EVM2 execution result.
    pub const fn result(&self) -> &TxResult<TempoEvmTypes> {
        &self.inner.result().result
    }

    /// Returns the block gas consumed by this transaction.
    pub fn block_gas_used(&self) -> u64 {
        self.block_gas_used
    }

    /// Returns the state gas consumed by this transaction.
    pub fn state_gas_used(&self) -> u64 {
        self.inner.result().result.state_gas_spent()
    }

    /// Returns the validator-credited fee amount (post-feeAMM haircut) for this transaction.
    pub fn validator_fee(&self) -> U256 {
        self.validator_fee
    }

    /// Returns the transaction's pending EVM2 state.
    pub const fn pending_state(&self) -> &PendingState {
        &self.inner.result().pending_state
    }
}

impl BlockTransactionResult<TempoEvmTypes> for TempoTxResult {
    fn result(&self) -> &TxResultWithState<TempoEvmTypes> {
        self.inner.result()
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
/// logic on top: section-based transaction ordering (`BlockSection`), system transaction
/// validation, shared/non-shared gas accounting, and gas incentive tracking.
#[expect(missing_debug_implementations)]
pub struct TempoBlockExecutor<'a> {
    pub(crate) inner: EthBlockExecutor<'a, TempoEvmTypes, TempoReceiptBuilder>,

    section: BlockSection,
    extra_data: Bytes,

    pub(crate) replay_state: StorageActionReplayState,

    non_shared_gas_left: u64,
    non_payment_gas_left: u64,
    /// Incentive-section gas from real transactions; simulations are exempt.
    incentive_gas_used: u64,
    block_gas_used: u64,
}

impl<'a> TempoBlockExecutor<'a> {
    pub(crate) fn new(
        evm: TempoEvm<'a>,
        ctx: TempoBlockExecutionCtx<'a>,
        chain_spec: &'a TempoChainSpec,
    ) -> Self {
        let block_gas_limit = evm.block().gas_limit.to::<u64>();
        Self {
            incentive_gas_used: 0,
            block_gas_used: 0,
            non_payment_gas_left: ctx.general_gas_limit,
            non_shared_gas_left: block_gas_limit.saturating_sub(ctx.shared_gas_limit),
            extra_data: ctx.inner.extra_data.clone(),
            inner: EthBlockExecutor::new(evm, ctx.inner, chain_spec, TempoReceiptBuilder),
            section: BlockSection::StartOfBlock,
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
        let original = match self.evm_mut().state_mut().account_info_untracked(&address) {
            Ok(info) => info,
            Err(code) => {
                return Err(BlockExecutionError::other(
                    self.evm_mut().database_mut().error(code),
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
        let current = original.clone().unwrap_or_default().with_code(code);
        let mut state = PendingState::default();
        state.insert_account(address, original, Some(current));
        for &(slot, value) in storage {
            let original = match self
                .evm_mut()
                .state_mut()
                .storage_slot_untracked(&address, &slot)
            {
                Ok(value) => value,
                Err(code) => {
                    return Err(BlockExecutionError::other(
                        self.evm_mut().database_mut().error(code),
                    ));
                }
            };
            state.insert_storage(address, slot, original, value);
        }
        self.inner.commit_pending_state(&state);
        Ok(())
    }

    /// Installs and initializes the complete TIP-1091 state when T10 first becomes active.
    fn deploy_zone_factory_at_boundary(&mut self) -> Result<(), BlockExecutionError> {
        let [factory, portal, verifier, messenger] =
            initial_zone_factory_state(INITIAL_FACTORY_OWNER);

        let original = match self
            .evm_mut()
            .state_mut()
            .account_info_untracked(&factory.address)
        {
            Ok(info) => info,
            Err(code) => {
                return Err(BlockExecutionError::other(
                    self.evm_mut().database_mut().error(code),
                ));
            }
        };
        // Genesis allocations are authoritative, and the marker also records a completed
        // post-genesis installation.
        if original
            .as_ref()
            .is_some_and(|info| info.code_hash != KECCAK256_EMPTY)
        {
            return Ok(());
        }

        self.deploy_precompile_at_boundary(factory.address, factory.storage.as_slice())?;
        self.install_zone_runtimes_at_boundary([portal, verifier, messenger])?;
        Ok(())
    }

    /// Exercises the shared runtime upgrade path at T13.
    fn upgrade_zone_runtimes_at_boundary(&mut self) -> Result<(), BlockExecutionError> {
        let [_, portal, verifier, messenger] = t13_zone_factory_state(INITIAL_FACTORY_OWNER);
        self.install_zone_runtimes_at_boundary([portal, verifier, messenger])
    }

    /// Installs shared Zone runtimes without modifying their existing storage.
    fn install_zone_runtimes_at_boundary(
        &mut self,
        runtimes: [InitialZoneFactoryAccount; 3],
    ) -> Result<(), BlockExecutionError> {
        let mut state = PendingState::default();
        for runtime in runtimes {
            let destination = runtime.address;
            let original = match self
                .evm_mut()
                .state_mut()
                .account_info_untracked(&destination)
            {
                Ok(info) => info,
                Err(code) => {
                    return Err(BlockExecutionError::other(
                        self.evm_mut().database_mut().error(code),
                    ));
                }
            };
            let current = original
                .clone()
                .unwrap_or_default()
                .with_code(Bytecode::new_raw(runtime.code));
            if original
                .as_ref()
                .is_some_and(|info| info.code_hash == current.code_hash)
            {
                continue;
            }
            state.insert_account(destination, original, Some(current));
        }
        if !state.is_empty() {
            self.inner.commit_pending_state(&state);
        }
        Ok(())
    }

    fn apply_current_committee_system_call(&mut self) -> Result<(), BlockExecutionError> {
        if !self.evm().config_spec_id().is_t8() {
            return Ok(());
        }

        let epoch_length = self.evm().block().ext.epoch_length.get();
        let block_number = self.evm().block().number.saturating_to::<u64>();
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
        let epoch = outcome.epoch;
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

        self.inner.commit_pending_state(&result.pending_state);
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
            let Ok(_) = Vec::<SubBlockMetadata>::decode(&mut buf) else {
                return Err(BlockValidationError::msg(
                    "invalid subblocks metadata system transaction",
                ));
            };

            if !buf.is_empty() {
                return Err(BlockValidationError::msg(
                    "invalid subblocks metadata system transaction",
                ));
            }

            seen_subblocks_signatures = true;
        } else {
            return Err(BlockValidationError::msg("invalid system transaction"));
        }

        Ok(BlockSection::System {
            seen_subblocks_signatures,
        })
    }

    /// Pre-validate a transaction before execution.
    ///
    /// Reject reserved subblock nonces and restrict system transactions to explicitly
    /// allowed actions, since they bypass regular block gas limit checks.
    pub(crate) fn validate_tx_pre_execution(
        &self,
        tx: &TempoTxEnvelope,
    ) -> Result<Option<BlockSection>, BlockValidationError> {
        if tx.is_system_tx() {
            self.validate_system_tx(tx).map(Some)
        } else if tx.has_sub_block_nonce_key_prefix() {
            Err(BlockValidationError::msg(
                "subblock transactions are not supported",
            ))
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
        } else if tx.has_sub_block_nonce_key_prefix() {
            Err(BlockValidationError::msg(
                "subblock transactions are not supported",
            ))
        } else {
            match self.section {
                BlockSection::StartOfBlock | BlockSection::NonShared => {
                    if gas_used > self.non_shared_gas_left
                        || (!self.is_payment(tx) && gas_used > self.non_payment_gas_left)
                    {
                        // Historical blocks can use the gas incentive section after
                        // exhausting the non-shared or general gas budget.
                        Ok(BlockSection::GasIncentive)
                    } else {
                        Ok(BlockSection::NonShared)
                    }
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
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;
    type Evm = TempoEvm<'a>;
    type TransactionResultWithState = TempoTxResult;
    type BlockAccessList = Bal;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        if self
            .inner
            .context()
            .withdrawals
            .as_ref()
            .is_some_and(|withdrawals| !withdrawals.is_empty())
        {
            return Err(BlockValidationError::msg("withdrawals are not permitted").into());
        }

        self.inner.apply_pre_execution_changes()?;

        // Deploy 0xEF marker bytecode to precompiles at their activation hardforks.
        if self.evm().config_spec_id().is_t2() {
            self.deploy_precompile_at_boundary(VALIDATOR_CONFIG_V2_ADDRESS, &[])?;
        }
        if self.evm().config_spec_id().is_t3() {
            self.deploy_precompile_at_boundary(SIGNATURE_VERIFIER_ADDRESS, &[])?;
            self.deploy_precompile_at_boundary(ADDRESS_REGISTRY_ADDRESS, &[])?;
        }
        if self.evm().config_spec_id().is_t5() {
            self.deploy_precompile_at_boundary(TIP20_CHANNEL_RESERVE_ADDRESS, &[])?;
        }
        if self.evm().config_spec_id().is_t6() {
            self.deploy_precompile_at_boundary(RECEIVE_POLICY_GUARD_ADDRESS, &[])?;
        }
        if self.evm().config_spec_id().is_t7() {
            self.deploy_precompile_at_boundary(STORAGE_CREDITS_ADDRESS, &[])?;
        }
        if self.evm().config_spec_id().is_t8() {
            self.deploy_precompile_at_boundary(CURRENT_COMMITTEE_ADDRESS, &[])?;
        }
        if self.evm().config_spec_id().is_t10() {
            self.deploy_zone_factory_at_boundary()?;
        }
        if self.evm().config_spec_id().is_t13() {
            self.upgrade_zone_runtimes_at_boundary()?;
        }

        Ok(())
    }

    fn receipts(&self) -> &[TempoReceipt] {
        self.inner.receipts()
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutorTx<Self>,
    ) -> Result<Self::TransactionResultWithState, BlockExecutionError> {
        let (mut tx_env, recovered) = tx.into_parts();
        // Remove any prewarming-specific context that was added to the tx env.
        tx_env.inner_mut().set_expiring_nonce_idx(None);
        let execution_context = tx_env.inner().execution_context();
        let original = recovered.tx().clone();
        let next_section = self.validate_tx_pre_execution(&original)?;
        let inner = self
            .inner
            .execute_transaction_without_commit((tx_env, recovered))?;

        // TIP-1016 enabled: use block_regular_gas_used (excludes state gas) for section
        // validation, matching block gas limit semantics. TIP-1016 disabled: use tx_gas_used.
        let block_gas_used = if self.evm().version().feature(evm2::EvmFeatures::EIP8037) {
            inner.result().result.execution_gas_spent()
        } else {
            inner.result().result.tx_gas_used()
        };

        let next_section = if let Some(next_section) = next_section {
            // If pre-execution validation returned a section to use, just use it.
            next_section
        } else {
            self.validate_tx(&original, block_gas_used)?
        };
        // Snapshot the per-tx validator-credited fee set by the handler's `reimburse_caller`
        let validator_fee = inner.result().result.ext.validator_fee;
        Ok(TempoTxResult {
            inner,
            execution_context,
            next_section,
            is_payment: self.is_payment(&original),
            block_gas_used,
            validator_fee,
        })
    }

    fn commit_transaction(
        &mut self,
        output: Self::TransactionResultWithState,
    ) -> Result<GasOutput, BlockExecutionError> {
        let TempoTxResult {
            inner,
            execution_context,
            next_section,
            is_payment,
            block_gas_used,
            validator_fee: _,
        } = output;

        let gas_output = self.inner.commit_transaction(inner)?;
        self.block_gas_used = self.block_gas_used.saturating_add(block_gas_used);

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
            BlockSection::GasIncentive => {
                if matches!(execution_context, ExecutionContext::Transaction { .. }) {
                    self.incentive_gas_used += block_gas_used;
                }
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
        // T4 sets the shared gas limit to zero, so any gas spilled into the
        // incentive section exceeds the available block capacity.
        if self.evm().config_spec_id().is_t4() && self.incentive_gas_used > 0 {
            return Err(BlockValidationError::msg("incentive gas limit exceeded").into());
        }

        self.apply_current_committee_system_call()?;

        let block_gas_used = self.block_gas_used;
        let use_regular_gas = self.evm().version().feature(evm2::EvmFeatures::EIP8037);
        let (mut output, block_access_list) = self.inner.finish_with_block_access_list()?;

        // TIP-1016 enabled: block header `gas_used` = block_regular_gas_used.
        // State gas is charged to users (in receipts) but exempted from block
        // capacity. block_regular_gas_used is accumulated per-tx as
        // max(total_spent - state_spent, floor) and is independent of refunds.
        //
        // TIP-1016 disabled: use the standard gas_used from the inner executor which equals
        // cumulative_tx_gas_used (total_spent - refunded), matching the original
        // block header semantics.
        if use_regular_gas {
            output.result.gas_used = block_gas_used;
        }
        Ok((output, block_access_list))
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }

    fn set_state_hook(&mut self, hook: impl FnMut(EvmState) + Send + 'static) -> bool {
        self.inner.set_state_hook(hook);
        true
    }

    fn validate_transaction_gas_limit(
        &mut self,
        gas_limit: u64,
    ) -> Result<(), BlockExecutionError> {
        self.inner.validate_transaction_gas_limit(gas_limit)
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

    /// Get the current section for assertions.
    pub(crate) fn section(&self) -> BlockSection {
        self.section
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestExecutorBuilder, test_chainspec};
    use alloy_consensus::{Signed, TxLegacy, transaction::Recovered};
    use alloy_primitives::{Bytes, Log, Signature, TxKind, address, bytes::BytesMut};
    use alloy_rlp::Encodable;
    use commonware_codec::Encode as _;
    use commonware_cryptography::{
        Signer,
        bls12381::{dkg::feldman_desmedt as dkg, primitives::sharing::Mode},
        ed25519::PrivateKey,
    };
    use commonware_math::algebra::Random as _;
    use commonware_utils::{N3f1, TryFromIterator as _, ordered};
    use evm2::evm::{AccountInfo, InMemoryDB};
    use rand::SeedableRng as _;
    use reth_chainspec::EthChainSpec;
    use std::{
        iter::repeat_with,
        sync::{Arc, Mutex},
    };
    use tempo_chainspec::{TempoChainSpec, TempoHardfork, spec::DEV};
    use tempo_contracts::{
        precompiles::{
            CURRENT_COMMITTEE_ADDRESS, ICurrentCommittee, PATH_USD_ADDRESS, ZONE_FACTORY_ADDRESS,
            ZONE_MESSENGER_ADDRESS, ZONE_PORTAL_IMPL_ADDRESS, ZONE_VERIFIER_ADDRESS,
        },
        zones::{
            T13_ZONE_MESSENGER_RUNTIME, T13_ZONE_PORTAL_RUNTIME, T13_ZONE_VERIFIER_RUNTIME,
            ZONE_MESSENGER_RUNTIME, ZONE_PORTAL_RUNTIME, ZONE_VERIFIER_RUNTIME,
        },
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
        let mut rng = rand::rngs::StdRng::seed_from_u64(epoch);
        let mut player_keys = repeat_with(|| PrivateKey::random(&mut rng))
            .take(players)
            .collect::<Vec<_>>();
        player_keys.sort_by_key(|key| key.public_key());

        let player_set =
            ordered::Set::try_from_iter(player_keys.iter().map(|key| key.public_key())).unwrap();
        let (output, shares) =
            dkg::deal::<_, _, N3f1>(&mut rng, Mode::NonZeroCounter, player_set).unwrap();

        OnchainDkgOutcome {
            epoch,
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

        let receipt = builder.build_receipt::<TempoEvmTypes>(ReceiptBuilderCtx {
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
        let metadata = vec![create_subblock_metadata(&signer)];
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

    fn create_subblock_metadata(signer: &PrivateKey) -> SubBlockMetadata {
        SubBlockMetadata {
            version: SubBlockVersion::V1,
            validator: B256::from_slice(&signer.public_key()),
            fee_recipient: Address::ZERO,
            // Historical replay decodes the signature but does not verify it.
            signature: Bytes::from(vec![0; 64]),
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
        let metadata = vec![create_subblock_metadata(&signer)];
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
        let metadata = vec![create_subblock_metadata(&signer)];
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

    fn create_subblock_tx() -> TempoTxEnvelope {
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[0] = TEMPO_SUBBLOCK_NONCE_KEY_PREFIX;
        nonce_bytes[1..16].fill(0xff);

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
    fn test_subblock_nonce_rejected_before_execution_and_commit() {
        let chainspec = DEV.clone();
        for spec in [TempoHardfork::T3, TempoHardfork::T4, TempoHardfork::T11] {
            let mut db = InMemoryDB::default();
            let mut executor = TestExecutorBuilder::default()
                .with_spec(spec)
                .build(&mut db, &chainspec);
            let tx = create_subblock_tx();
            // Precomputed execution results must pass the same transaction-kind validation.
            assert_eq!(
                executor.validate_tx(&tx, 21_000).unwrap_err().to_string(),
                "subblock transactions are not supported"
            );
            let recovered = Recovered::new_unchecked(tx, Address::ZERO);
            let err = executor.execute_transaction(recovered).unwrap_err();
            assert!(
                matches!(&err, BlockExecutionError::Validation(_)),
                "{err:?}"
            );
            assert_eq!(err.to_string(), "subblock transactions are not supported");
        }
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
            execution_context: ExecutionContext::Transaction {
                tx_hash: B256::ZERO,
            },
            inner: EthTransactionResultWithState::new(
                TxResultWithState {
                    result: TxResult::<TempoEvmTypes> {
                        status: true,
                        total_gas_spent: 21000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                tx.tx_type(),
                0,
            ),
            next_section: BlockSection::NonShared,
            is_payment: false,
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
        assert_eq!(committee.epoch, outcome.epoch);
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
            .with_spec(TempoHardfork::T4)
            .build(&mut db, &chainspec);
        executor.apply_pre_execution_changes().unwrap();

        assert!(executor.finish().is_ok());
    }

    #[test]
    fn test_incentive_gas_validation_exempts_only_simulated_transactions() {
        for hardfork in [TempoHardfork::T3, TempoHardfork::T4] {
            for simulations in [
                vec![true],
                vec![false],
                vec![false, true],
                vec![true, false],
            ] {
                let chainspec = DEV.clone();
                let mut db = InMemoryDB::default();
                let mut executor = TestExecutorBuilder::default()
                    .with_parent_beacon_block_root(B256::ZERO)
                    .with_general_gas_limit(0)
                    .with_spec(hardfork)
                    .build(&mut db, &chainspec);
                executor.apply_pre_execution_changes().unwrap();
                for &simulation in &simulations {
                    executor
                        .commit_transaction(TempoTxResult {
                            execution_context: if simulation {
                                ExecutionContext::Simulation
                            } else {
                                ExecutionContext::Transaction {
                                    tx_hash: B256::ZERO,
                                }
                            },
                            inner: EthTransactionResultWithState::new(
                                TxResultWithState {
                                    result: TxResult::<TempoEvmTypes> {
                                        status: true,
                                        total_gas_spent: 21_000,
                                        ..Default::default()
                                    },
                                    ..Default::default()
                                },
                                TempoTxType::Legacy,
                                0,
                            ),
                            next_section: BlockSection::GasIncentive,
                            is_payment: false,
                            block_gas_used: 21_000,
                            validator_fee: U256::ZERO,
                        })
                        .unwrap();
                }
                let should_reject = hardfork == TempoHardfork::T4 && simulations.contains(&false);
                match executor.finish() {
                    Err(error) => {
                        assert!(should_reject);
                        assert_eq!(error.to_string(), "incentive gas limit exceeded");
                    }
                    Ok(_) => assert!(!should_reject),
                }
            }
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
            execution_context: ExecutionContext::Transaction {
                tx_hash: B256::ZERO,
            },
            inner: EthTransactionResultWithState::new(
                TxResultWithState {
                    result: TxResult::<TempoEvmTypes> {
                        status: true,
                        total_gas_spent: 21000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                tx.tx_type(),
                0,
            ),
            next_section: BlockSection::NonShared,
            is_payment: false,
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
            execution_context: ExecutionContext::Transaction {
                tx_hash: B256::ZERO,
            },
            inner: EthTransactionResultWithState::new(
                TxResultWithState {
                    result: TxResult::<TempoEvmTypes> {
                        status: true,
                        total_gas_spent: 21000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                tx1.tx_type(),
                0,
            ),
            next_section: BlockSection::NonShared,
            is_payment: false,
            block_gas_used: 21000,
            validator_fee: U256::ZERO,
        };
        executor.commit_transaction(output1).unwrap();

        // Commit second transaction (50000 gas)
        let tx2 = create_legacy_tx();
        let output2 = TempoTxResult {
            execution_context: ExecutionContext::Transaction {
                tx_hash: B256::ZERO,
            },
            inner: EthTransactionResultWithState::new(
                TxResultWithState {
                    result: TxResult::<TempoEvmTypes> {
                        status: true,
                        total_gas_spent: 50000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                tx2.tx_type(),
                0,
            ),
            next_section: BlockSection::NonShared,
            is_payment: false,
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
                execution_context: ExecutionContext::Transaction {
                    tx_hash: B256::ZERO,
                },
                inner: EthTransactionResultWithState::new(
                    TxResultWithState {
                        result: TxResult::<TempoEvmTypes> {
                            status: true,
                            total_gas_spent: 21000,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    TempoTxType::Legacy,
                    0,
                ),
                next_section: BlockSection::NonShared,
                is_payment: false,
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
            execution_context: ExecutionContext::Transaction {
                tx_hash: B256::ZERO,
            },
            inner: EthTransactionResultWithState::new(
                TxResultWithState {
                    result: TxResult::<TempoEvmTypes> {
                        status: true,
                        total_gas_spent: 50_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                tx.tx_type(),
                0,
            ),
            next_section: BlockSection::NonShared,
            is_payment: false,
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
            execution_context: ExecutionContext::Transaction {
                tx_hash: B256::ZERO,
            },
            inner: EthTransactionResultWithState::new(
                TxResultWithState {
                    result: TxResult::<TempoEvmTypes> {
                        status: true,
                        total_gas_spent: 300_000,
                        state_gas_spent: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                tx.tx_type(),
                0,
            ),
            next_section: BlockSection::NonShared,
            is_payment: false,
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
            execution_context: ExecutionContext::Transaction {
                tx_hash: B256::ZERO,
            },
            inner: EthTransactionResultWithState::new(
                TxResultWithState {
                    result: TxResult::<TempoEvmTypes> {
                        status: true,
                        total_gas_spent: 300_000,
                        state_gas_spent: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                tx.tx_type(),
                0,
            ),
            next_section: BlockSection::GasIncentive,
            is_payment: false,
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

        let hook_calls: Arc<Mutex<Vec<EvmState>>> = Arc::new(Mutex::new(Vec::new()));
        let hook_calls_clone = hook_calls.clone();
        executor.set_state_hook(move |state| hook_calls_clone.lock().unwrap().push(state));

        let addr = Address::with_last_byte(0xff);
        executor.deploy_precompile_at_boundary(addr, &[]).unwrap();

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
            calls[0].contains_key(&addr),
            "state hook should contain the deployed address"
        );
        assert_eq!(
            calls[0][&addr].original_info(),
            Default::default(),
            "state hook account should preserve original_info"
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

        let hook_calls: Arc<Mutex<Vec<EvmState>>> = Arc::new(Mutex::new(Vec::new()));
        let hook_calls_clone = hook_calls.clone();
        executor.set_state_hook(move |state| hook_calls_clone.lock().unwrap().push(state));

        executor.deploy_precompile_at_boundary(addr, &[]).unwrap();

        let calls = hook_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "state hook should be called exactly once");
        assert_eq!(
            calls[0][&addr].original_info(),
            reth_execution_types::revm_account(&original_info),
            "state hook account should preserve existing original_info"
        );
    }

    #[test]
    fn zone_runtime_upgrade_activates_at_t13() {
        for (activation, expected_runtimes) in [
            (
                u64::MAX,
                [
                    ZONE_PORTAL_RUNTIME,
                    ZONE_VERIFIER_RUNTIME,
                    ZONE_MESSENGER_RUNTIME,
                ],
            ),
            (
                0,
                [
                    T13_ZONE_PORTAL_RUNTIME,
                    T13_ZONE_VERIFIER_RUNTIME,
                    T13_ZONE_MESSENGER_RUNTIME,
                ],
            ),
        ] {
            let mut genesis = DEV.genesis().clone();
            genesis
                .config
                .extra_fields
                .insert_value("t13Time".into(), activation)
                .unwrap();
            let chainspec = Arc::new(TempoChainSpec::from_genesis(genesis));
            let mut db = InMemoryDB::default();
            let mut executor = TestExecutorBuilder::default()
                .with_spec(if activation == 0 {
                    TempoHardfork::T13
                } else {
                    TempoHardfork::T12
                })
                .with_parent_beacon_block_root(B256::ZERO)
                .build(&mut db, &chainspec);
            executor.apply_pre_execution_changes().unwrap();
            for (address, expected) in [
                ZONE_PORTAL_IMPL_ADDRESS,
                ZONE_VERIFIER_ADDRESS,
                ZONE_MESSENGER_ADDRESS,
            ]
            .into_iter()
            .zip(expected_runtimes)
            {
                let overlay = executor.evm().state().overlay_db();
                let info = overlay.account_info(&address).unwrap();
                let installed = &overlay.cache.contracts[&info.code_hash];
                assert_eq!(installed.original_bytes(), expected);
            }
        }
    }

    #[test]
    fn test_zone_runtime_hardfork_installation() {
        assert_eq!(
            INITIAL_FACTORY_OWNER,
            address!("0xaF571FD4B3AD43a5807A5E58bFb25ea1aB327A14")
        );
        let chainspec = Arc::new(TempoChainSpec::from_genesis(DEV.genesis().clone()));
        let mut db = InMemoryDB::default();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .build(&mut db, &chainspec);

        let hook_calls: Arc<Mutex<Vec<EvmState>>> = Arc::new(Mutex::new(Vec::new()));
        let hook_calls_clone = hook_calls.clone();
        executor.set_state_hook(move |state| hook_calls_clone.lock().unwrap().push(state));

        executor.deploy_zone_factory_at_boundary().unwrap();
        executor.deploy_zone_factory_at_boundary().unwrap();
        executor.upgrade_zone_runtimes_at_boundary().unwrap();
        executor.upgrade_zone_runtimes_at_boundary().unwrap();

        let factory = executor
            .evm()
            .state()
            .overlay_db()
            .account_info(&ZONE_FACTORY_ADDRESS)
            .unwrap();
        assert_eq!(
            executor.evm().state().overlay_db().cache.contracts[&factory.code_hash]
                .original_bytes(),
            Bytes::from_static(&[0xef])
        );
        let expected_factory_config =
            U256::from(1) | (U256::from_be_slice(INITIAL_FACTORY_OWNER.as_slice()) << u32::BITS);
        assert_eq!(
            executor.evm().state().overlay_db().cache.storage[&ZONE_FACTORY_ADDRESS].slots
                [&U256::ZERO],
            expected_factory_config
        );
        for (destination, expected) in [
            (ZONE_PORTAL_IMPL_ADDRESS, T13_ZONE_PORTAL_RUNTIME),
            (ZONE_VERIFIER_ADDRESS, T13_ZONE_VERIFIER_RUNTIME),
            (ZONE_MESSENGER_ADDRESS, T13_ZONE_MESSENGER_RUNTIME),
        ] {
            let info = executor
                .evm()
                .state()
                .overlay_db()
                .account_info(&destination)
                .unwrap();
            assert_eq!(
                executor.evm().state().overlay_db().cache.contracts[&info.code_hash]
                    .original_bytes(),
                expected
            );
        }

        let calls = hook_calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            3,
            "T10 installation and T13 replacement must each dispatch an update"
        );
        assert!(calls[0].contains_key(&ZONE_FACTORY_ADDRESS));
        for address in [
            ZONE_PORTAL_IMPL_ADDRESS,
            ZONE_VERIFIER_ADDRESS,
            ZONE_MESSENGER_ADDRESS,
        ] {
            assert!(
                calls[1].contains_key(&address),
                "shared runtime must be installed in the runtime state hook"
            );
            assert!(
                calls[2].contains_key(&address),
                "T13 runtime must be installed in the runtime state hook"
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
                execution_context: ExecutionContext::Transaction {
                    tx_hash: B256::ZERO,
                },
                inner: EthTransactionResultWithState::new(
                    TxResultWithState {
                        result: TxResult::<TempoEvmTypes> {
                            status: true,
                            total_gas_spent: 300_000,
                            state_gas_spent: state_gas,
                            refunded: 30_000,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    TempoTxType::Legacy,
                    0,
                ),
                next_section: BlockSection::StartOfBlock,
                is_payment: false,
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
                execution_context: ExecutionContext::Transaction {
                    tx_hash: B256::ZERO,
                },
                inner: EthTransactionResultWithState::new(
                    TxResultWithState {
                        result: TxResult::<TempoEvmTypes> {
                            status: true,
                            total_gas_spent: 300_000,
                            state_gas_spent: 200_000,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    TempoTxType::Legacy,
                    0,
                ),
                next_section: BlockSection::StartOfBlock,
                is_payment: false,
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
                execution_context: ExecutionContext::Transaction {
                    tx_hash: B256::ZERO,
                },
                inner: EthTransactionResultWithState::new(
                    TxResultWithState {
                        result: TxResult::<TempoEvmTypes> {
                            status: true,
                            total_gas_spent: regular,
                            refunded: regular - cumulative,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    TempoTxType::Legacy,
                    0,
                ),
                next_section: BlockSection::StartOfBlock,
                is_payment: false,
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
