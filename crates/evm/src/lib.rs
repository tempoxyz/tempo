//! Tempo EVM implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod action_replay;
mod assemble;
mod block;
mod common;
pub mod consensus;
mod context;
#[cfg(feature = "engine")]
mod engine;
pub mod error;
pub mod evm;
mod fee_manager;
mod handler;
mod instructions;
mod signature_gas;
#[cfg(test)]
mod test_utils;
mod transaction;
pub mod transaction_error;

pub use action_replay::{
    ExpiringNonceReplay, StorageActionReplay, StorageActionReplayError, StorageActionReplayOutcome,
    StorageActionReplayState,
};
pub use assemble::TempoBlockAssembler;
pub use block::{TempoBlockExecutor, TempoReceiptBuilder, TempoTxResult};
pub use common::{TempoStateAccess, TempoTx};
pub use context::{TempoBlockExecutionCtx, TempoNextBlockEnvAttributes};
pub use error::TempoEvmError;
pub use evm::{SYSTEM_CALL_GAS_LIMIT, TempoEvm, TempoEvmFactory};
pub use fee_manager::{FeeTokenResolver, ProtocolFeeContext, ProtocolFeeManager, TempoFeeManager};
pub use handler::{
    TempoBlockEnv, TempoBlockExt, TempoConfig, TempoConfigSelector, TempoEvmExt, TempoEvmTypes,
    TempoTxResultExt, build_tempo_evm, tempo_execution_config, tempo_opcode_config,
    tempo_tx_registry,
};
pub use transaction::{ExecutionContext, RecoveredTxEnvelope, TempoAaTx, TempoEvmTx, TempoTxEnv};
pub use transaction_error::{FeePaymentError, TempoInvalidTransaction};

use core::num::NonZeroU64;
use std::{borrow::Cow, sync::Arc};

use alloy_consensus::BlockHeader as _;
use alloy_eips::eip7840::BlobParams;
use alloy_primitives::{Address, U256};
use evm2::{ExecutionConfig, env::BlockEnv, evm::DynDatabase};
use reth_chainspec::EthChainSpec;
use reth_evm::{BlockExecutorFactory, ConfigureEvm, EvmEnvFor, SenderRecoveryCache};
use reth_evm_ethereum::{EthBlockExecutionCtx, EthEvmEnv};
use reth_primitives_traits::{SealedBlock, SealedHeader};
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
};
use tempo_precompiles::{TempoPrecompiles, error::Result as TempoResult, storage::StorageActions};
use tempo_primitives::{Block, TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope};

#[cfg(feature = "engine")]
use rayon as _;

/// Fully resolved Tempo execution environment.
pub type TempoEvmEnv = EthEvmEnv<TempoEvmTypes>;

/// Tempo-related EVM configuration.
#[derive(Debug, Clone)]
pub struct TempoEvmConfig {
    chain_spec: Arc<TempoChainSpec>,
    evm_factory: TempoEvmFactory,
    sender_recovery_cache: Option<SenderRecoveryCache>,
    /// Block assembler used by payload construction.
    pub block_assembler: TempoBlockAssembler,
}

impl FeeTokenResolver for TempoEvmConfig {
    fn resolve_fee_token<S, M>(
        &self,
        state: &mut S,
        tx: &TempoTxEnv,
        fee_payer: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> TempoResult<Address>
    where
        S: TempoStateAccess<M>,
    {
        TempoFeeManager::new().resolve_fee_token(state, tx, fee_payer, spec, actions)
    }
}

impl TempoEvmConfig {
    /// Creates a Tempo EVM config for `chain_spec`.
    pub fn new(chain_spec: Arc<TempoChainSpec>) -> Self {
        Self {
            evm_factory: TempoEvmFactory::default(),
            sender_recovery_cache: None,
            block_assembler: TempoBlockAssembler::new(chain_spec.clone()),
            chain_spec,
        }
    }

    /// Uses the provided sender recovery cache.
    pub fn with_sender_recovery_cache(mut self, cache: SenderRecoveryCache) -> Self {
        self.sender_recovery_cache = Some(cache);
        self
    }

    /// Returns the chain spec
    pub const fn chain_spec(&self) -> &Arc<TempoChainSpec> {
        &self.chain_spec
    }

    /// Returns the moderato EVM config.
    pub fn moderato() -> Self {
        Self::new(Arc::new(TempoChainSpec::moderato()))
    }

    /// Returns the mainnet EVM config.
    pub fn mainnet() -> Self {
        Self::new(Arc::new(TempoChainSpec::mainnet()))
    }

    fn resolved_env(
        &self,
        tempo_spec: tempo_chainspec::hardfork::TempoHardfork,
        block: BlockEnv<TempoEvmTypes>,
        blob_params: Option<BlobParams>,
    ) -> TempoEvmEnv {
        let config = tempo_execution_config(tempo_spec, self.chain_spec.chain().id());
        let mut version = *config.version();
        version.tx_gas_limit_cap = tempo_spec.tx_gas_limit_cap().unwrap_or(u64::MAX);
        if let Some(blob_params) = blob_params {
            version.max_blobs_per_tx = blob_params.max_blobs_per_tx as usize;
            version.blob_base_fee_update_fraction =
                u64::try_from(blob_params.update_fraction).unwrap_or(u64::MAX);
        }
        TempoEvmEnv::new_with_version(tempo_spec, block, version)
    }
}

impl BlockExecutorFactory for TempoEvmConfig {
    type EvmFactory = TempoEvmFactory;
    type EvmTypes = TempoEvmTypes;
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;
    type Evm<'a> = TempoEvm<'a>;
    type EvmEnv = TempoEvmEnv;
    type ExecutionCtx<'a> = TempoBlockExecutionCtx<'a>;
    type Executor<'a> = TempoBlockExecutor<'a>;

    fn create_executor<'a>(
        &'a self,
        evm: Self::Evm<'a>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> Self::Executor<'a>
    where
        Self: 'a,
    {
        TempoBlockExecutor::new(evm, ctx, self.chain_spec())
    }

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn evm_with_env<'a, DB>(&self, db: DB, env: Self::EvmEnv) -> Self::Evm<'a>
    where
        DB: DynDatabase + 'a,
    {
        let ext = self.evm_factory.evm_ext(TempoEvmExt::default());
        let precompiles = TempoPrecompiles::new(
            env.spec,
            ext.actions.clone(),
            ext.non_creditable_slots.clone(),
        );
        evm2::Evm::new_with_execution_config_and_ext(
            ExecutionConfig::for_spec_and_version(env.spec, env.version),
            env.spec,
            env.block,
            tempo_tx_registry(env.spec.into()),
            db,
            precompiles,
            ext,
        )
    }
}

impl ConfigureEvm for TempoEvmConfig {
    type Primitives = TempoPrimitives;
    type Error = TempoEvmError;
    type NextBlockEnvCtx = TempoNextBlockEnvAttributes;
    type BlockExecutorFactory = Self;
    type BlockAssembler = TempoBlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &TempoHeader) -> Result<EvmEnvFor<Self>, Self::Error> {
        let blob_params = self.chain_spec.blob_params_at_timestamp(header.timestamp());
        let tempo_spec = self.chain_spec.tempo_hardfork_at(header.timestamp());
        let block = TempoBlockEnv {
            number: U256::from(header.number()),
            beneficiary: header.beneficiary(),
            timestamp: U256::from(header.timestamp()),
            gas_limit: U256::from(header.gas_limit()),
            basefee: U256::from(header.base_fee_per_gas().unwrap_or_default()),
            difficulty: header.difficulty(),
            prevrandao: header
                .mix_hash()
                .map(|hash| U256::from_be_slice(hash.as_slice()))
                .unwrap_or_default(),
            blob_basefee: header
                .excess_blob_gas()
                .zip(blob_params)
                .map(|(excess, params)| U256::from(params.calc_blob_fee(excess)))
                .unwrap_or_default(),
            slot_num: U256::from(header.slot_number().unwrap_or_default()),
            ext: TempoBlockExt {
                timestamp_millis_part: header.timestamp_millis_part,
                epoch_length: self
                    .chain_spec
                    .info
                    .epoch_length()
                    .unwrap_or(NonZeroU64::MIN),
                proposer_public_key: header.consensus_context.map(|ctx| ctx.proposer),
            },
            _non_exhaustive: (),
        };
        Ok(self.resolved_env(tempo_spec, block, blob_params))
    }

    fn next_evm_env(
        &self,
        parent: &TempoHeader,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        let blob_params = self
            .chain_spec
            .blob_params_at_timestamp(attributes.timestamp);
        let excess_blob_gas = parent
            .maybe_next_block_excess_blob_gas(blob_params)
            .or_else(|| blob_params.map(|_| 0));
        let tempo_spec = self.chain_spec.tempo_hardfork_at(attributes.timestamp);
        let block = TempoBlockEnv {
            number: U256::from(parent.number().saturating_add(1)),
            beneficiary: attributes.suggested_fee_recipient,
            timestamp: U256::from(attributes.timestamp),
            gas_limit: U256::from(attributes.gas_limit),
            basefee: U256::from(
                self.chain_spec
                    .next_block_base_fee(parent, attributes.timestamp)
                    .unwrap_or_default(),
            ),
            difficulty: U256::ZERO,
            prevrandao: U256::from_be_slice(attributes.prev_randao.as_slice()),
            blob_basefee: excess_blob_gas
                .zip(blob_params)
                .map(|(excess, params)| U256::from(params.calc_blob_fee(excess)))
                .unwrap_or_default(),
            slot_num: U256::from(attributes.slot_number.unwrap_or_default()),
            ext: TempoBlockExt {
                timestamp_millis_part: attributes.timestamp_millis_part,
                epoch_length: self
                    .chain_spec
                    .info
                    .epoch_length()
                    .unwrap_or(NonZeroU64::MIN),
                proposer_public_key: attributes.consensus_context.map(|ctx| ctx.proposer),
            },
            _non_exhaustive: (),
        };
        Ok(self.resolved_env(tempo_spec, block, blob_params))
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<TempoBlockExecutionCtx<'a>, Self::Error>
    where
        Self: 'a,
    {
        Ok(TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: block.header().parent_hash(),
                parent_beacon_block_root: block.header().parent_beacon_block_root(),
                // no ommers in tempo
                ommers: &[],
                withdrawals: block
                    .body()
                    .withdrawals
                    .as_ref()
                    .map(|w| Cow::Borrowed(w.as_slice())),
                extra_data: block.extra_data().clone(),
                tx_count_hint: Some(block.body().transactions.len()),
                slot_number: block.slot_number(),
            },
            general_gas_limit: block.header().general_gas_limit,
            shared_gas_limit: block.header().shared_gas_limit,
            consensus_context: block.header().consensus_context,
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<TempoHeader>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<TempoBlockExecutionCtx<'_>, Self::Error> {
        Ok(TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: parent.hash(),
                parent_beacon_block_root: attributes.parent_beacon_block_root,
                slot_number: attributes.slot_number,
                ommers: &[],
                withdrawals: attributes
                    .inner
                    .withdrawals
                    .map(|w| Cow::Owned(w.into_inner())),
                extra_data: attributes.inner.extra_data,
                tx_count_hint: None,
            },
            general_gas_limit: attributes.general_gas_limit,
            shared_gas_limit: attributes.shared_gas_limit,
            consensus_context: attributes.consensus_context,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_chainspec;
    use alloy_consensus::{BlockHeader, Signed, TxLegacy};
    use alloy_primitives::{Address, B256, Bytes, TxKind};
    use alloy_rlp::{Encodable, bytes::BytesMut};
    use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::{
        BlockBody, SubBlockMetadata, TempoConsensusContext, TempoTxEnvelope, ed25519::PublicKey,
        subblock::SubBlockVersion, transaction::envelope::TEMPO_SYSTEM_TX_SIGNATURE,
    };

    #[test]
    fn test_evm_config_can_query_tempo_hardforks() {
        let evm_config = TempoEvmConfig::new(test_chainspec());
        let activation = evm_config
            .chain_spec()
            .tempo_fork_activation(TempoHardfork::Genesis);
        assert_eq!(activation, reth_chainspec::ForkCondition::Timestamp(0));
    }

    #[test]
    fn test_evm_env() {
        let evm_config = TempoEvmConfig::new(test_chainspec());

        let header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 100,
                timestamp: 1000,
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(1000),
                beneficiary: alloy_primitives::Address::repeat_byte(0x01),
                ..Default::default()
            },
            general_gas_limit: 10_000_000,
            timestamp_millis_part: 500,
            shared_gas_limit: 3_000_000,
            ..Default::default()
        };

        let result = evm_config.evm_env(&header);
        assert!(result.is_ok());

        let evm_env = result.unwrap();

        // Verify block env fields
        assert_eq!(evm_env.block.number, U256::from(header.number()));
        assert_eq!(evm_env.block.timestamp, U256::from(header.timestamp()));
        assert_eq!(evm_env.block.gas_limit, U256::from(header.gas_limit()));
        assert_eq!(evm_env.block.beneficiary, header.beneficiary());

        // Verify Tempo-specific field
        assert_eq!(evm_env.block.ext.timestamp_millis_part, 500);
        assert_eq!(evm_env.block.ext.proposer_public_key, None);

        let proposer = PublicKey::from_seed(0xab);
        let evm_env = evm_config
            .evm_env(&TempoHeader {
                consensus_context: Some(TempoConsensusContext {
                    epoch: 1,
                    view: 2,
                    parent_view: 1,
                    proposer,
                }),
                ..header
            })
            .unwrap();
        assert_eq!(evm_env.block.ext.proposer_public_key, Some(proposer));
    }

    /// Test that evm_env sets 30M gas limit cap for T1 hardfork as per [TIP-1000].
    ///
    /// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
    #[test]
    fn test_evm_env_t1_gas_cap() {
        use tempo_chainspec::spec::DEV;

        // DEV chainspec has T1 activated at timestamp 0
        let chainspec = DEV.clone();
        let evm_config = TempoEvmConfig::new(chainspec.clone());

        let header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 100,
                timestamp: 1000, // After T1 activation
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(1000),
                ..Default::default()
            },
            general_gas_limit: 10_000_000,
            timestamp_millis_part: 0,
            shared_gas_limit: 3_000_000,
            ..Default::default()
        };

        // Verify we're in T1
        assert!(chainspec.tempo_hardfork_at(header.timestamp()).is_t1());

        let evm_env = evm_config.evm_env(&header).unwrap();

        // Verify TIP-1000 gas limit cap is set
        assert_eq!(
            evm_env.version.tx_gas_limit_cap,
            tempo_chainspec::spec::TEMPO_T1_TX_GAS_LIMIT_CAP,
            "TIP-1000 requires 30M gas limit cap for T1 hardfork"
        );
    }

    #[test]
    fn test_next_evm_env() {
        let evm_config = TempoEvmConfig::new(test_chainspec());

        let parent = TempoHeader {
            inner: alloy_consensus::Header {
                number: 99,
                timestamp: 900,
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(1000),
                ..Default::default()
            },
            general_gas_limit: 10_000_000,
            timestamp_millis_part: 0,
            shared_gas_limit: 3_000_000,
            ..Default::default()
        };

        let attributes = TempoNextBlockEnvAttributes {
            inner: NextBlockEnvAttributes {
                timestamp: 1000,
                suggested_fee_recipient: alloy_primitives::Address::repeat_byte(0x02),
                prev_randao: B256::repeat_byte(0x03),
                gas_limit: 30_000_000,
                parent_beacon_block_root: Some(B256::ZERO),
                withdrawals: None,
                extra_data: Default::default(),
                slot_number: None,
            },
            general_gas_limit: 10_000_000,
            shared_gas_limit: 3_000_000,
            timestamp_millis_part: 750,
            consensus_context: None,
        };

        let result = evm_config.next_evm_env(&parent, &attributes);
        assert!(result.is_ok());

        let evm_env = result.unwrap();

        // Verify block env uses attributes
        // parent + 1
        assert_eq!(evm_env.block.number, U256::from(100));
        assert_eq!(evm_env.block.timestamp, U256::from(1000));
        assert_eq!(evm_env.block.beneficiary, Address::repeat_byte(0x02));
        assert_eq!(evm_env.block.gas_limit, U256::from(30_000_000));

        // Verify Tempo-specific field
        assert_eq!(evm_env.block.ext.timestamp_millis_part, 750);
        assert_eq!(evm_env.block.ext.proposer_public_key, None);

        let proposer = PublicKey::from_seed(0xcd);
        let evm_env = evm_config
            .next_evm_env(
                &parent,
                &TempoNextBlockEnvAttributes {
                    consensus_context: Some(TempoConsensusContext {
                        epoch: 1,
                        view: 2,
                        parent_view: 1,
                        proposer,
                    }),
                    ..attributes
                },
            )
            .unwrap();
        assert_eq!(evm_env.block.ext.proposer_public_key, Some(proposer));
    }

    #[test]
    fn test_context_for_block() {
        let chainspec = test_chainspec();
        let evm_config = TempoEvmConfig::new(chainspec.clone());

        // Create subblock metadata
        let validator_key = B256::repeat_byte(0x01);
        let fee_recipient = alloy_primitives::Address::repeat_byte(0x02);
        let metadata = vec![SubBlockMetadata {
            version: SubBlockVersion::V1,
            validator: validator_key,
            fee_recipient,
            signature: Bytes::from_static(&[0; 64]),
        }];

        // Create system tx with metadata
        let block_number = 1u64;
        let mut input = BytesMut::new();
        metadata.encode(&mut input);
        input.extend_from_slice(&U256::from(block_number).to_be_bytes::<32>());

        let system_tx = TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(reth_chainspec::EthChainSpec::chain(&*chainspec).id()),
                nonce: 0,
                gas_price: 0,
                gas_limit: 0,
                to: TxKind::Call(alloy_primitives::Address::ZERO),
                value: U256::ZERO,
                input: input.freeze().into(),
            },
            TEMPO_SYSTEM_TX_SIGNATURE,
        ));

        let header = TempoHeader {
            inner: alloy_consensus::Header {
                number: block_number,
                timestamp: 1000,
                gas_limit: 30_000_000,
                parent_beacon_block_root: Some(B256::ZERO),
                ..Default::default()
            },
            general_gas_limit: 10_000_000,
            timestamp_millis_part: 500,
            shared_gas_limit: 3_000_000,
            ..Default::default()
        };

        let body = BlockBody {
            transactions: vec![system_tx],
            ommers: vec![],
            withdrawals: None,
        };

        let block = Block { header, body };
        let sealed_block = SealedBlock::seal_slow(block);

        let result = evm_config.context_for_block(&sealed_block);
        assert!(result.is_ok());

        let context = result.unwrap();

        // Verify context fields
        assert_eq!(context.general_gas_limit, 10_000_000);
        assert_eq!(context.shared_gas_limit, 3_000_000);
    }

    #[test]
    fn test_context_for_block_t4_without_metadata() {
        use tempo_chainspec::spec::DEV;

        let chainspec = DEV.clone();
        let evm_config = TempoEvmConfig::new(chainspec);

        let header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 1,
                timestamp: 1000,
                gas_limit: 30_000_000,
                parent_beacon_block_root: Some(B256::ZERO),
                ..Default::default()
            },
            general_gas_limit: 10_000_000,
            timestamp_millis_part: 500,
            shared_gas_limit: 3_000_000,
            ..Default::default()
        };

        let body = BlockBody {
            transactions: vec![],
            ommers: vec![],
            withdrawals: None,
        };

        let block = Block { header, body };
        let sealed_block = SealedBlock::seal_slow(block);

        let context = evm_config.context_for_block(&sealed_block).unwrap();
        assert_eq!(context.general_gas_limit, 10_000_000);
    }

    #[test]
    fn test_context_for_next_block() {
        let evm_config = TempoEvmConfig::new(test_chainspec());

        let parent_header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 99,
                timestamp: 900,
                gas_limit: 30_000_000,
                ..Default::default()
            },
            general_gas_limit: 10_000_000,
            timestamp_millis_part: 0,
            shared_gas_limit: 0,
            ..Default::default()
        };
        let parent = SealedHeader::seal_slow(parent_header);

        let attributes = TempoNextBlockEnvAttributes {
            inner: NextBlockEnvAttributes {
                timestamp: 1000,
                suggested_fee_recipient: alloy_primitives::Address::repeat_byte(0x03),
                prev_randao: B256::repeat_byte(0x04),
                gas_limit: 30_000_000,
                parent_beacon_block_root: Some(B256::repeat_byte(0x05)),
                withdrawals: None,
                extra_data: Default::default(),
                slot_number: None,
            },
            general_gas_limit: 12_000_000,
            shared_gas_limit: 4_000_000,
            timestamp_millis_part: 999,
            consensus_context: None,
        };

        let result = evm_config.context_for_next_block(&parent, attributes);
        assert!(result.is_ok());

        let context = result.unwrap();

        // Verify context fields from attributes
        assert_eq!(context.general_gas_limit, 12_000_000);
        assert_eq!(context.shared_gas_limit, 4_000_000);
        assert_eq!(context.inner.parent_hash, parent.hash());
        assert_eq!(
            context.inner.parent_beacon_block_root,
            Some(B256::repeat_byte(0x05))
        );
    }
}
