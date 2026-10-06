//! Tempo EVM implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod action_replay;
mod assemble;
mod expiring_nonces;
mod pool;
pub use action_replay::{
    ExpiringNonceReplay, StorageActionReplay, StorageActionReplayError, StorageActionReplayOutcome,
    StorageActionReplayState,
};
use alloy_consensus::{BlockHeader as _, Sealable as _};
pub use assemble::TempoBlockAssembler;
pub use expiring_nonces::ExpiringNonceCache;
pub use pool::{TempoPoolValidationEvm, TempoPoolValidationResult};
mod block;
pub use block::{TempoBlockExecutor, TempoReceiptBuilder, TempoTxResult};
mod context;
pub use context::{TempoBlockExecutionCtx, TempoNextBlockEnvAttributes};
pub mod consensus;
#[cfg(feature = "engine")]
mod engine;
#[cfg(feature = "engine")]
use rayon as _;
mod error;
pub use error::TempoEvmError;
pub mod evm;
#[cfg(feature = "genesis")]
pub mod genesis;
use core::num::NonZeroU64;
use std::{borrow::Cow, sync::Arc};

use alloy_evm::{
    self, EvmEnv,
    block::BlockExecutorFactory,
    eth::{EthBlockExecutionCtx, NextEvmEnvAttributes},
    revm::Inspector,
};
use alloy_primitives::Address;
pub use evm::TempoEvmFactory;
use reth_chainspec::EthChainSpec;
use reth_evm::{self, ConfigureEvm, EvmEnvFor, SenderRecoveryCache, block::StateDB};
use reth_primitives_traits::{SealedBlock, SealedHeader};
use tempo_primitives::{Block, TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope};

use crate::evm::TempoEvm;
use reth_evm_ethereum::EthEvmConfig;
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
};
use tempo_precompiles::{error::Result as TempoResult, storage::StorageActions};
use tempo_revm::{TempoTxEnv, evm::TempoContext, gas_params::tempo_gas_params_with_amsterdam};

pub use tempo_revm::{
    FeeTokenResolver, ProtocolFeeContext, ProtocolFeeManager, TempoBlockEnv, TempoFeeManager,
    TempoInvalidTransaction, TempoStateAccess,
};

#[cfg(test)]
mod test_utils;

/// Tempo-related EVM configuration.
#[derive(Debug, Clone)]
pub struct TempoEvmConfig {
    /// Inner evm config
    pub inner: EthEvmConfig<TempoChainSpec, TempoEvmFactory>,

    /// Block assembler
    pub block_assembler: TempoBlockAssembler,

    /// Enables expiring nonce state outside the EVM trie.
    pub expiring_nonce_cache: Option<ExpiringNonceCache>,

    /// Pool admission uses post-tip state, including the inner validator's limits lookup.
    pool_validation: bool,
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
    /// Create a new [`TempoEvmConfig`] with the given chain spec and EVM factory.
    pub fn new(chain_spec: Arc<TempoChainSpec>) -> Self {
        let inner =
            EthEvmConfig::new_with_evm_factory(chain_spec.clone(), TempoEvmFactory::default());
        Self {
            inner,
            block_assembler: TempoBlockAssembler::new(chain_spec),
            expiring_nonce_cache: None,
            pool_validation: false,
        }
    }

    /// Enables the STF-breaking, reconstructible in-memory replay protection backend.
    pub fn with_expiring_nonce_source(
        mut self,
        source: impl Fn(alloy_primitives::B256) -> Result<Option<Block>, String> + Send + Sync + 'static,
    ) -> Self {
        self.expiring_nonce_cache = Some(ExpiringNonceCache::new(source));
        self.block_assembler.expiring_nonce_cache = self.expiring_nonce_cache.clone();
        self
    }

    fn expiring_nonce_state(
        &self,
        parent_hash: alloy_primitives::B256,
        timestamp: u64,
    ) -> Result<Option<tempo_expiring_nonces::ExpiringNonceState>, TempoEvmError> {
        let _timer = tempo_expiring_nonces::diagnostics::Timer::start("environment_nonce_state");
        let _span = tracing::info_span!(target: "tempo::expiring_nonces", "nonce_environment", %parent_hash, block_timestamp = timestamp).entered();
        self.expiring_nonce_cache
            .as_ref()
            .map(|cache| {
                let mut state = cache
                    .state_at(parent_hash, self.chain_spec())
                    .map_err(TempoEvmError::InvalidEvmConfig)?;
                state
                    .advance(timestamp)
                    .map_err(|e| TempoEvmError::InvalidEvmConfig(e.to_string()))?;
                Ok(state)
            })
            .transpose()
    }

    /// Configures header environments for pool admission against post-block state.
    /// Pass only this configuration to the pool; block execution uses parent state.
    pub fn for_pool_validation(mut self) -> Self {
        self.pool_validation = true;
        self
    }

    /// Constructs pool admission state directly from a verified post-block snapshot.
    /// Unlike execution, pool admission needs the tip's state, not its parent's.
    pub fn pool_evm_env_from_nonce_snapshot(
        &self,
        header: &TempoHeader,
        state: tempo_expiring_nonces::ExpiringNonceState,
    ) -> Result<EvmEnvFor<Self>, TempoEvmError> {
        if self.expiring_nonce_cache.is_none()
            || state.timestamp() != header.timestamp()
            || header.expiring_nonce_root != Some(state.root())
        {
            return Err(TempoEvmError::InvalidEvmConfig(
                "pool nonce snapshot does not match header".into(),
            ));
        }
        Ok(self.header_env(header, Some(state)))
    }

    fn header_env(
        &self,
        header: &TempoHeader,
        expiring_nonces: Option<tempo_expiring_nonces::ExpiringNonceState>,
    ) -> EvmEnvFor<Self> {
        let EvmEnv { cfg_env, block_env } = EvmEnv::for_eth_block(
            header,
            self.chain_spec(),
            self.chain_spec().chain_id(),
            self.chain_spec()
                .blob_params_at_timestamp(header.timestamp()),
        );

        let spec = self.chain_spec().tempo_hardfork_at(header.timestamp());

        // Apply TIP-1000 gas params for T1 hardfork.
        //
        // TIP-1016 (EIP-8037 state gas split) is gated by `cfg_env.enable_amsterdam_eip8037`
        // and is independent of the T4 hardfork. The flag is currently left at its default
        // (`false`) so TIP-1016 is disabled even on T4; flipping it on enables the regular/
        // state gas split everywhere it is checked downstream.
        //
        // TODO(TIP-1016): this is the place where we previously did
        // `cfg_env.enable_amsterdam_eip8037 = spec.is_t4();`. When TIP-1016 is ready to
        // ship, re-enable it here (or wire it through chain spec / cfg defaults) so the
        // state gas split activates on the appropriate hardfork.
        let amsterdam_eip8037_enabled = cfg_env.enable_amsterdam_eip8037;
        let mut cfg_env = cfg_env.with_spec_and_gas_params(
            spec,
            tempo_gas_params_with_amsterdam(spec, amsterdam_eip8037_enabled),
        );
        cfg_env.tx_gas_limit_cap = spec.tx_gas_limit_cap();

        EvmEnv {
            cfg_env,
            block_env: TempoBlockEnv {
                inner: block_env,
                timestamp_millis_part: header.timestamp_millis_part,
                epoch_length: self
                    .chain_spec()
                    .info
                    .epoch_length()
                    .unwrap_or(NonZeroU64::MIN),
                proposer_public_key: header.consensus_context.map(|ctx| ctx.proposer),
                expiring_nonces,
            },
        }
    }

    /// Uses the provided sender recovery cache.
    pub fn with_sender_recovery_cache(mut self, cache: SenderRecoveryCache) -> Self {
        self.inner = self.inner.with_sender_recovery_cache(cache);
        self
    }

    /// Returns the chain spec
    pub const fn chain_spec(&self) -> &Arc<TempoChainSpec> {
        self.inner.chain_spec()
    }

    /// Returns the inner EVM config
    pub const fn inner(&self) -> &EthEvmConfig<TempoChainSpec, TempoEvmFactory> {
        &self.inner
    }

    /// Returns the moderato EVM config.
    pub fn moderato() -> Self {
        Self::new(Arc::new(TempoChainSpec::moderato()))
    }

    /// Returns the mainnet EVM config.
    pub fn mainnet() -> Self {
        Self::new(Arc::new(TempoChainSpec::mainnet()))
    }
}

impl BlockExecutorFactory for TempoEvmConfig {
    type EvmFactory = TempoEvmFactory;
    type ExecutionCtx<'a> = TempoBlockExecutionCtx<'a>;
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;
    type TxExecutionResult = TempoTxResult;
    type Executor<'a, DB: StateDB, I: Inspector<TempoContext<DB>>> = TempoBlockExecutor<'a, DB, I>;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.executor_factory.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: TempoEvm<DB, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I>
    where
        DB: StateDB,
        I: Inspector<TempoContext<DB>>,
    {
        let mut executor = TempoBlockExecutor::new(evm, ctx, self.chain_spec());
        executor.expiring_nonce_cache = self.expiring_nonce_cache.clone();
        executor
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
        if header.number() != 0
            && header.expiring_nonce_root.is_some() != self.expiring_nonce_cache.is_some()
        {
            return Err(TempoEvmError::InvalidEvmConfig(
                "expiring nonce backend does not match header".into(),
            ));
        }
        if self.pool_validation {
            if let Some(cache) = &self.expiring_nonce_cache {
                let state = cache
                    .state_at(header.hash_slow(), self.chain_spec())
                    .map_err(TempoEvmError::InvalidEvmConfig)?;
                return Ok(self.header_env(header, Some(state)));
            }
        }
        let state = if header.number() == 0 {
            self.expiring_nonce_cache
                .as_ref()
                .map(|_| Default::default())
        } else {
            self.expiring_nonce_state(header.parent_hash(), header.timestamp())?
        };
        Ok(self.header_env(header, state))
    }

    fn next_evm_env(
        &self,
        parent: &TempoHeader,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        let EvmEnv { cfg_env, block_env } = EvmEnv::for_eth_next_block(
            parent,
            NextEvmEnvAttributes {
                timestamp: attributes.timestamp,
                suggested_fee_recipient: attributes.suggested_fee_recipient,
                prev_randao: attributes.prev_randao,
                gas_limit: attributes.gas_limit,
                slot_number: attributes.slot_number,
            },
            self.chain_spec()
                .next_block_base_fee(parent, attributes.timestamp)
                .unwrap_or_default(),
            self.chain_spec(),
            self.chain_spec().chain_id(),
            self.chain_spec()
                .blob_params_at_timestamp(attributes.timestamp),
        );

        let spec = self.chain_spec().tempo_hardfork_at(attributes.timestamp);

        // Apply TIP-1000 gas params for T1 hardfork. TIP-1016 is gated by
        // `cfg_env.enable_amsterdam_eip8037`, independent of the T4 hardfork
        // (see `evm_env_for_block` for details).
        //
        // TODO(TIP-1016): this is the place where we previously did
        // `cfg_env.enable_amsterdam_eip8037 = spec.is_t4();`. When TIP-1016 is ready to
        // ship, re-enable it here (or wire it through chain spec / cfg defaults) so the
        // state gas split activates on the appropriate hardfork.
        let amsterdam_eip8037_enabled = cfg_env.enable_amsterdam_eip8037;
        let mut cfg_env = cfg_env.with_spec_and_gas_params(
            spec,
            tempo_gas_params_with_amsterdam(spec, amsterdam_eip8037_enabled),
        );
        cfg_env.tx_gas_limit_cap = spec.tx_gas_limit_cap();

        Ok(EvmEnv {
            cfg_env,
            block_env: TempoBlockEnv {
                inner: block_env,
                timestamp_millis_part: attributes.timestamp_millis_part,
                epoch_length: self
                    .chain_spec()
                    .info
                    .epoch_length()
                    .unwrap_or(NonZeroU64::MIN),
                proposer_public_key: attributes.consensus_context.map(|ctx| ctx.proposer),
                expiring_nonces: self.expiring_nonce_state(
                    alloy_consensus::Sealable::hash_slow(parent),
                    attributes.timestamp,
                )?,
            },
        })
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<TempoBlockExecutionCtx<'a>, Self::Error> {
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
            expiring_nonce_root: block.header().expiring_nonce_root,
            block_hash: Some(block.hash()),
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
            expiring_nonce_root: None,
            block_hash: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_chainspec;
    use alloy_consensus::{BlockHeader, Signed, TxLegacy};
    use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
    use alloy_rlp::{Encodable, bytes::BytesMut};
    use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::{
        BlockBody, SubBlockMetadata, TempoConsensusContext, ed25519::PublicKey,
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
    fn pool_snapshot_environment_avoids_parent_history_and_checks_header() {
        let config = TempoEvmConfig::new(test_chainspec()).with_expiring_nonce_source(|_| {
            panic!("post-tip pool snapshots must not load parent history")
        });
        let mut state = tempo_expiring_nonces::ExpiringNonceState::default();
        state.advance(1000).unwrap();
        state.insert(B256::repeat_byte(1), 1010, 300, 100).unwrap();
        let mut header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 1,
                timestamp: 1000,
                gas_limit: 30_000_000,
                ..Default::default()
            },
            expiring_nonce_root: Some(state.root()),
            ..Default::default()
        };
        let env = config
            .pool_evm_env_from_nonce_snapshot(&header, state.clone())
            .unwrap();
        assert_eq!(env.block_env.expiring_nonces.as_ref(), Some(&state));
        assert_eq!(env.block_env.inner.timestamp, U256::from(1000));
        config
            .expiring_nonce_cache
            .as_ref()
            .unwrap()
            .remember(&state, Some(header.hash_slow()));
        let pool_config = config.clone().for_pool_validation();
        let limits_env = pool_config.evm_env(&header).unwrap();
        assert_eq!(limits_env.block_env.expiring_nonces.as_ref(), Some(&state));
        header.inner.timestamp = 1001;
        assert!(
            config
                .pool_evm_env_from_nonce_snapshot(&header, state.clone())
                .is_err()
        );
        header.inner.timestamp = 1000;
        header.expiring_nonce_root = Some(B256::ZERO);
        assert!(
            config
                .pool_evm_env_from_nonce_snapshot(&header, state)
                .is_err()
        );
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
        assert_eq!(evm_env.block_env.inner.number, U256::from(header.number()));
        assert_eq!(
            evm_env.block_env.inner.timestamp,
            U256::from(header.timestamp())
        );
        assert_eq!(evm_env.block_env.inner.gas_limit, header.gas_limit());
        assert_eq!(evm_env.block_env.inner.beneficiary, header.beneficiary());

        // Verify Tempo-specific field
        assert_eq!(evm_env.block_env.timestamp_millis_part, 500);
        assert_eq!(evm_env.block_env.proposer_public_key, None);

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
        assert_eq!(evm_env.block_env.proposer_public_key, Some(proposer));
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
            evm_env.cfg_env.tx_gas_limit_cap,
            Some(tempo_chainspec::spec::TEMPO_T1_TX_GAS_LIMIT_CAP),
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
        assert_eq!(evm_env.block_env.inner.number, U256::from(100));
        assert_eq!(evm_env.block_env.inner.timestamp, U256::from(1000));
        assert_eq!(
            evm_env.block_env.inner.beneficiary,
            Address::repeat_byte(0x02)
        );
        assert_eq!(evm_env.block_env.inner.gas_limit, 30_000_000);

        // Verify Tempo-specific field
        assert_eq!(evm_env.block_env.timestamp_millis_part, 750);
        assert_eq!(evm_env.block_env.proposer_public_key, None);

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
        assert_eq!(evm_env.block_env.proposer_public_key, Some(proposer));
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
                chain_id: Some(chainspec.chain_id()),
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
