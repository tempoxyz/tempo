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
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Decodable;
use commonware_codec::DecodeExt;
use commonware_cryptography::{
    Verifier,
    ed25519::{PublicKey, Signature},
};
use reth_revm::{Inspector, State, context::result::ResultAndState};
use std::collections::{HashMap, HashSet};
use tempo_chainspec::TempoChainSpec;
use tempo_primitives::{
    SubBlock, SubBlockMetadata, TempoReceipt, TempoTxEnvelope, subblock::PartialValidatorKey,
};
use tempo_revm::{TempoHaltReason, evm::TempoContext};
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
            section: BlockSection::StartOfBlock,
            seen_subblocks: Vec::new(),
            subblock_fee_recipients: ctx.subblock_fee_recipients,
        }
    }

    /// Validates a system transaction.
    pub(crate) fn validate_system_tx(
        &self,
        tx: &TempoTxEnvelope,
    ) -> Result<BlockSection, BlockValidationError> {
        let block = self.evm().block();
        let block_number = block.number.to_be_bytes_vec();
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
        self.inner.apply_pre_execution_changes()
    }

    fn receipts(&self) -> &[Self::Receipt] {
        self.inner.receipts()
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<ResultAndState<TempoHaltReason>, BlockExecutionError> {
        let beneficiary = self.evm_mut().ctx_mut().block.beneficiary;
        // If we are dealing with a subblock transaction, configure the fee recipient context.
        if let Some(validator) = tx.tx().subblock_proposer() {
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
            BlockSection::StartOfBlock => {
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
        if self.section
            != (BlockSection::System {
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

// Test-only methods to set internal state without exposing fields as pub(crate)
#[cfg(test)]
impl<'a, DB, I> TempoBlockExecutor<'a, DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<&'a mut State<DB>>>,
{
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
    use crate::test_utils::{TestExecutorBuilder, test_chainspec, test_evm};
    use alloy_consensus::{Signed, TxLegacy, transaction::Recovered};
    use alloy_evm::{block::BlockExecutor, eth::receipt_builder::ReceiptBuilder};
    use alloy_primitives::{Bytes, Log, Signature, TxKind, bytes::BytesMut};
    use alloy_rlp::Encodable;
    use commonware_cryptography::{Signer, ed25519::PrivateKey};
    use reth_chainspec::EthChainSpec;
    use reth_revm::State;
    use revm::{context::result::ExecutionResult, database::EmptyDB};
    use tempo_primitives::{
        SubBlockMetadata, TempoSignature, TempoTransaction, TempoTxType,
        subblock::{SubBlockVersion, TEMPO_SUBBLOCK_NONCE_KEY_PREFIX},
        transaction::{Call, envelope::TEMPO_SYSTEM_TX_SIGNATURE},
    };
    use tempo_revm::TempoHaltReason;

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

    #[test]
    fn test_build_receipt() {
        let builder = TempoReceiptBuilder;
        let tx = create_legacy_tx();
        let evm = test_evm(EmptyDB::default());

        let logs = vec![Log::new_unchecked(
            Address::ZERO,
            vec![B256::ZERO],
            Bytes::new(),
        )];
        let result: ExecutionResult<TempoHaltReason> = ExecutionResult::Success {
            reason: revm::context::result::SuccessReason::Return,
            gas_used: 21000,
            gas_refunded: 0,
            logs,
            output: revm::context::result::Output::Call(Bytes::new()),
        };

        let cumulative_gas_used = 21000;

        let receipt = builder.build_receipt(ReceiptBuilderCtx {
            tx: &tx,
            evm: &evm,
            result,
            state: &Default::default(),
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
        let mut db = State::builder().with_bundle_update().build();
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
        let mut db = State::builder().with_bundle_update().build();
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
        let mut db = State::builder().with_bundle_update().build();
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
        let mut db = State::builder().with_bundle_update().build();
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
    fn test_validate_shared_gas() {
        let chainspec = test_chainspec();
        let mut db = State::builder().with_bundle_update().build();
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
        let mut db = State::builder().with_bundle_update().build();
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
        let mut db = State::builder().with_bundle_update().build();
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
        let mut db = State::builder().with_bundle_update().build();
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
        let mut db = State::builder().with_bundle_update().build();
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
        let mut db = State::builder().with_bundle_update().build();
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
        let mut db = State::builder().with_bundle_update().build();
        let signer = PrivateKey::from_seed(0);
        let validator_key = B256::from_slice(&signer.public_key());

        // Add a seen subblock from a different validator that wont match metadata
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
        let mut db = State::builder().with_bundle_update().build();
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
    fn test_validate_tx() {
        let chainspec = test_chainspec();
        let mut db = State::builder().with_bundle_update().build();
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
        let mut db = State::builder().with_bundle_update().build();
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
        let mut db2 = State::builder().with_bundle_update().build();
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
        let mut db = State::builder().with_bundle_update().build();
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
        let mut db = State::builder().with_bundle_update().build();

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
        let mut db = State::builder().with_bundle_update().build();
        let mut executor = TestExecutorBuilder::default()
            .with_general_gas_limit(30_000_000)
            .with_parent_beacon_block_root(B256::ZERO)
            .build(&mut db, &chainspec);

        // Apply pre-execution changes first
        executor.apply_pre_execution_changes().unwrap();

        // Create execution result
        let output = ResultAndState {
            result: revm::context::result::ExecutionResult::Success {
                reason: revm::context::result::SuccessReason::Return,
                gas_used: 21000,
                gas_refunded: 0,
                logs: vec![],
                output: revm::context::result::Output::Call(Bytes::new()),
            },
            state: Default::default(),
        };

        let tx = create_legacy_tx();
        let recovered_tx = Recovered::new_unchecked(tx, Address::ZERO);
        let gas_used = executor.commit_transaction(output, &recovered_tx).unwrap();

        assert_eq!(gas_used, 21000);
        assert_eq!(executor.section(), BlockSection::NonShared);
    }

    #[test]
    fn test_finish() {
        let chainspec = test_chainspec();
        let mut db = State::builder().with_bundle_update().build();

        // Set section to System with seen_subblocks_signatures
        let executor = TestExecutorBuilder::default()
            .with_section(BlockSection::System {
                seen_subblocks_signatures: true,
            })
            .build(&mut db, &chainspec);

        let result = executor.finish();
        assert!(result.is_ok());
    }

    #[test]
    fn test_finish_system_tx_not_seen() {
        let chainspec = test_chainspec();
        let mut db = State::builder().with_bundle_update().build();
        let executor = TestExecutorBuilder::default().build(&mut db, &chainspec);

        // Section is StartOfBlock, so system tx not seen
        let result = executor.finish();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.to_string(), "end-of-block system transactions not seen");
    }
}
