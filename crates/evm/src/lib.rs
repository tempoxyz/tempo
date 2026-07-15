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
mod handler;
mod instructions;
#[cfg(test)]
mod test_utils;
mod transaction;

pub use action_replay::{
    ExpiringNonceReplay, StorageActionReplay, StorageActionReplayError, StorageActionReplayOutcome,
    StorageActionReplayState,
};
pub use assemble::TempoBlockAssembler;
pub use block::{TempoBlockExecutor, TempoReceiptBuilder, TempoTxResult};
pub use common::{TempoStateAccess, TempoTx};
pub use context::{TempoBlockExecutionCtx, TempoNextBlockEnvAttributes};
pub use error::{FeePaymentError, TempoEvmError, TempoInvalidTransaction};
pub use evm::{TempoEvm, TempoEvmFactory};
pub use handler::{
    ProtocolFeeManager, TempoBlockEnv, TempoBlockExt, TempoConfig, TempoConfigSelector,
    TempoEvmExt, TempoEvmTypes, TempoFeeManager, TempoTxResultExt, build_tempo_evm,
    tempo_execution_config, tempo_tx_registry,
};
pub use transaction::{TempoAaTx, TempoEvmTx, TempoTxEnv};

use alloy_consensus::{BlockHeader as _, Transaction};
use alloy_eips::eip7840::BlobParams;
use alloy_primitives::U256;
use alloy_rlp::Decodable;
use core::num::NonZeroU64;
use evm2::{EvmFeatures, ExecutionConfig, env::BlockEnv, evm::DynDatabase, version::GasId};
use reth_chainspec::EthChainSpec;
use reth_evm::{
    BlockExecutorFactory, ConfigureEvm, EvmEnv, EvmEnvFor, EvmTransactionValidationGasRules,
    EvmTransactionValidationLimits,
};
use reth_evm_ethereum::EthBlockExecutionCtx;
use reth_primitives_traits::{SealedBlock, SealedHeader};
use std::{borrow::Cow, sync::Arc};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};
use tempo_precompiles::TempoPrecompiles;
use tempo_primitives::{
    Block, SubBlockMetadata, TempoHeader, TempoPrimitives, subblock::PartialValidatorKey,
};

#[cfg(feature = "engine")]
use rayon as _;

/// Fully resolved Tempo execution environment.
#[derive(Clone, Debug)]
pub struct TempoEvmEnv {
    /// Active Tempo protocol revision.
    pub tempo_spec: tempo_chainspec::hardfork::TempoHardfork,
    /// Runtime gas and validation parameters.
    pub version: evm2::Version,
    /// Block fields visible to EVM execution.
    pub block: TempoBlockEnv,
}

impl Default for TempoEvmEnv {
    fn default() -> Self {
        let tempo_spec = tempo_chainspec::hardfork::TempoHardfork::default();
        let version = *tempo_execution_config(tempo_spec, 0).version();
        Self {
            tempo_spec,
            version,
            block: TempoBlockEnv::default(),
        }
    }
}

impl EvmEnv for TempoEvmEnv {
    type EvmTypes = TempoEvmTypes;

    fn spec_id(&self) -> tempo_chainspec::hardfork::TempoHardfork {
        self.tempo_spec
    }

    fn chain_id(&self) -> u64 {
        self.version.chain_id
    }

    fn block_env(&self) -> &BlockEnv<TempoEvmTypes> {
        &self.block
    }

    fn block_env_mut(&mut self) -> &mut BlockEnv<TempoEvmTypes> {
        &mut self.block
    }

    fn version(&self) -> &evm2::Version {
        &self.version
    }

    fn version_mut(&mut self) -> &mut evm2::Version {
        &mut self.version
    }

    fn block_base_fee(&self) -> u64 {
        self.block.basefee.to()
    }

    fn block_blob_base_fee(&self) -> u64 {
        self.block.blob_basefee.to()
    }

    fn transaction_validation_limits(&self) -> EvmTransactionValidationLimits {
        EvmTransactionValidationLimits {
            max_initcode_size: self.version.max_initcode_size,
            tx_gas_limit_cap: if self.version.feature(EvmFeatures::EIP8037) {
                0
            } else {
                self.version.tx_gas_limit_cap
            },
        }
    }

    fn transaction_validation_gas_rules(&self) -> EvmTransactionValidationGasRules {
        let params = &self.version.gas_params;
        let floor_gas_enabled = self.version.feature(EvmFeatures::EIP7623);
        EvmTransactionValidationGasRules {
            tx_base_gas: 21_000,
            tx_create_gas: if self.version.feature(EvmFeatures::EIP2) {
                u64::from(params.get(GasId::TxCreateCost))
            } else {
                Default::default()
            },
            tx_data_zero_gas: 4,
            tx_data_non_zero_gas: if self.version.feature(EvmFeatures::EIP2028) {
                16
            } else {
                68
            },
            tx_access_list_address_gas: u64::from(params.get(GasId::TxAccessListAddressCost)),
            tx_access_list_storage_key_gas: u64::from(
                params.get(GasId::TxAccessListStorageKeyCost),
            ),
            tx_access_list_floor_byte_multiplier: if floor_gas_enabled {
                u64::from(params.get(GasId::TxAccessListFloorByteMultiplier))
            } else {
                Default::default()
            },
            tx_initcode_word_gas: if self.version.feature(EvmFeatures::EIP3860) {
                u64::from(params.get(GasId::TxInitcodeCost))
            } else {
                Default::default()
            },
            tx_floor_gas_base: if floor_gas_enabled {
                u64::from(params.get(GasId::TxFloorCostBase))
            } else {
                Default::default()
            },
            tx_floor_gas_per_token: if floor_gas_enabled {
                u64::from(params.get(GasId::TxFloorCostPerToken))
            } else {
                Default::default()
            },
            tx_floor_gas_non_zero_token_multiplier: if floor_gas_enabled {
                u64::from(params.get(GasId::TxTokenNonZeroByteMultiplier))
            } else {
                Default::default()
            },
            tx_eip7702_per_empty_account_cost: if self.version.feature(EvmFeatures::EIP7702) {
                u64::from(params.get(GasId::TxEip7702PerEmptyAccountCost))
            } else {
                Default::default()
            },
        }
    }

    fn uses_separate_block_gas(&self) -> bool {
        self.version.feature(EvmFeatures::EIP8037)
    }

    fn regular_gas_limit_cap(&self) -> u64 {
        self.version.tx_gas_limit_cap
    }

    fn with_nonce_check_disabled(mut self) -> Self {
        self.version.features.remove(EvmFeatures::NONCE_CHECK);
        self
    }

    fn with_balance_check_disabled(mut self) -> Self {
        self.version.features.remove(EvmFeatures::BALANCE_CHECK);
        self
    }
}

/// Tempo-related EVM configuration.
#[derive(Debug, Clone)]
pub struct TempoEvmConfig {
    chain_spec: Arc<TempoChainSpec>,
    evm_factory: TempoEvmFactory,
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
            block_assembler: TempoBlockAssembler::new(chain_spec.clone()),
            chain_spec,
        }
    }

    /// Returns the chain spec.
    pub const fn chain_spec(&self) -> &Arc<TempoChainSpec> {
        &self.chain_spec
    }

    /// Returns the Moderato config.
    pub fn moderato() -> Self {
        Self::new(Arc::new(TempoChainSpec::moderato()))
    }

    /// Returns the mainnet config.
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
            version.blob_base_fee_update_fraction = blob_params
                .update_fraction
                .try_into()
                .expect("blob base fee update fraction exceeds u64");
        }
        TempoEvmEnv {
            tempo_spec,
            version,
            block,
        }
    }
}

impl BlockExecutorFactory for TempoEvmConfig {
    type Primitives = TempoPrimitives;
    type EvmFactory = TempoEvmFactory;
    type EvmTypes = TempoEvmTypes;
    type EvmTransaction = TempoTxEnv;
    type Transaction = TempoTxEnv;
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
            env.tempo_spec,
            ext.actions.clone(),
            ext.non_creditable_slots.clone(),
        );
        evm2::Evm::new_with_execution_config_and_ext(
            ExecutionConfig::for_spec_and_version(env.tempo_spec, env.version),
            env.tempo_spec,
            env.block,
            tempo_tx_registry(env.tempo_spec.into()),
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
        let block = block_env(
            header,
            blob_params,
            TempoBlockExt {
                timestamp_millis_part: header.timestamp_millis_part,
                epoch_length: self
                    .chain_spec
                    .info
                    .epoch_length()
                    .unwrap_or(NonZeroU64::MIN),
                proposer_public_key: header.consensus_context.map(|ctx| ctx.proposer),
            },
        );
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
        let header = TempoHeader {
            inner: alloy_consensus::Header {
                parent_hash: parent.inner.hash_slow(),
                beneficiary: attributes.suggested_fee_recipient,
                timestamp: attributes.timestamp,
                number: parent.number().saturating_add(1),
                gas_limit: attributes.gas_limit,
                base_fee_per_gas: Some(
                    self.chain_spec
                        .next_block_base_fee(parent, attributes.timestamp)
                        .unwrap_or_default(),
                ),
                mix_hash: attributes.prev_randao,
                slot_number: attributes.slot_number,
                excess_blob_gas,
                ..Default::default()
            },
            ..Default::default()
        };
        let tempo_spec = self.chain_spec.tempo_hardfork_at(attributes.timestamp);
        let block = block_env(
            &header,
            blob_params,
            TempoBlockExt {
                timestamp_millis_part: attributes.timestamp_millis_part,
                epoch_length: self
                    .chain_spec
                    .info
                    .epoch_length()
                    .unwrap_or(NonZeroU64::MIN),
                proposer_public_key: attributes.consensus_context.map(|ctx| ctx.proposer),
            },
        );
        Ok(self.resolved_env(tempo_spec, block, blob_params))
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<TempoBlockExecutionCtx<'a>, Self::Error>
    where
        Self: 'a,
    {
        // Decode validator -> fee_recipient mapping from the subblock metadata system transaction.
        let subblock_fee_recipients = block
            .body()
            .transactions
            .iter()
            .rev()
            .filter(|tx| tx.is_system_tx())
            .find_map(|tx| Vec::<SubBlockMetadata>::decode(&mut tx.input().as_ref()).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|metadata| {
                (
                    PartialValidatorKey::from_slice(&metadata.validator[..15]),
                    metadata.fee_recipient,
                )
            })
            .collect();

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
            // Not available when we only have a block body.
            validator_set: None,
            consensus_context: block.header().consensus_context,
            subblock_fee_recipients,
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
            // Fine to not validate during block building.
            validator_set: None,
            consensus_context: attributes.consensus_context,
            subblock_fee_recipients: attributes.subblock_fee_recipients,
        })
    }
}

fn block_env(
    header: &TempoHeader,
    blob_params: Option<BlobParams>,
    ext: TempoBlockExt,
) -> TempoBlockEnv {
    TempoBlockEnv {
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
        ext,
        _non_exhaustive: (),
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
    use std::collections::HashMap;
    use tempo_chainspec::{hardfork::TempoHardfork, spec::DEV};
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
                beneficiary: Address::repeat_byte(1),
                ..Default::default()
            },
            timestamp_millis_part: 500,
            general_gas_limit: 10_000_000,
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

        let proposer = PublicKey::from_seed([0xab; 32]);
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
        // DEV chainspec has T1 activated at timestamp 0
        let chainspec = DEV.clone();
        let evm_config = TempoEvmConfig::new(chainspec.clone());

        let header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 100,
                timestamp: 1000,
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
                suggested_fee_recipient: Address::repeat_byte(2),
                prev_randao: B256::repeat_byte(3),
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
            subblock_fee_recipients: HashMap::new(),
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

        let proposer = PublicKey::from_seed([0xcd; 32]);
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
        let fee_recipient = Address::repeat_byte(0x02);
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
                chain_id: Some(chainspec.chain().id()),
                nonce: 0,
                gas_price: 0,
                gas_limit: 0,
                to: TxKind::Call(Address::ZERO),
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
        assert!(context.validator_set.is_none());

        // Verify subblock_fee_recipients was extracted from metadata
        let partial_key = PartialValidatorKey::from_slice(&validator_key[..15]);
        assert_eq!(
            context.subblock_fee_recipients.get(&partial_key),
            Some(&fee_recipient)
        );
    }

    #[test]
    fn test_context_for_block_t4_without_metadata_has_empty_fee_recipients() {
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
        assert!(context.subblock_fee_recipients.is_empty());
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

        let fee_recipient = Address::repeat_byte(0x02);
        let mut subblock_fee_recipients = HashMap::new();
        let partial_key = PartialValidatorKey::from_slice(&[0x01; 15]);
        subblock_fee_recipients.insert(partial_key, fee_recipient);

        let attributes = TempoNextBlockEnvAttributes {
            inner: NextBlockEnvAttributes {
                timestamp: 1000,
                suggested_fee_recipient: Address::repeat_byte(0x03),
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
            subblock_fee_recipients: subblock_fee_recipients.clone(),
        };

        let result = evm_config.context_for_next_block(&parent, attributes);
        assert!(result.is_ok());

        let context = result.unwrap();

        // Verify context fields from attributes
        assert_eq!(context.general_gas_limit, 12_000_000);
        assert_eq!(context.shared_gas_limit, 4_000_000);
        assert!(context.validator_set.is_none());
        assert_eq!(context.inner.parent_hash, parent.hash());
        assert_eq!(
            context.inner.parent_beacon_block_root,
            Some(B256::repeat_byte(0x05))
        );

        // Verify subblock_fee_recipients passed through
        assert_eq!(
            context.subblock_fee_recipients.get(&partial_key),
            Some(&fee_recipient)
        );
    }
}
