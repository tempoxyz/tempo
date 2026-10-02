use std::{num::NonZeroU64, sync::Arc};

use alloy_evm::{Database, EvmEnv};
use alloy_primitives::{B256, Bytes};
use reth_chainspec::EthChainSpec;
use reth_evm::block::StateDB;
use reth_revm::context::BlockEnv;
use revm::inspector::NoOpInspector;
use tempo_chainspec::{TempoChainSpec, TempoHardfork, spec::MODERATO};
use tempo_revm::TempoBlockEnv;

use crate::{TempoBlockExecutionCtx, block::TempoBlockExecutor, evm::TempoEvm};
use alloy_evm::eth::EthBlockExecutionCtx;
use alloy_primitives::U256;

pub(crate) fn test_chainspec() -> Arc<TempoChainSpec> {
    Arc::new(TempoChainSpec::from_genesis(MODERATO.genesis().clone()))
}

pub(crate) fn test_evm<DB: Database>(db: DB) -> TempoEvm<DB, NoOpInspector> {
    test_evm_with_basefee(db, 1)
}

pub(crate) fn test_evm_with_basefee<DB: Database>(
    db: DB,
    basefee: u64,
) -> TempoEvm<DB, NoOpInspector> {
    TempoEvm::new(
        db,
        EvmEnv {
            block_env: TempoBlockEnv {
                inner: BlockEnv {
                    basefee,
                    gas_limit: 30_000_000,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },
    )
}

use crate::block::BlockSection;

pub(crate) struct TestExecutorBuilder {
    pub(crate) block_number: u64,
    pub(crate) epoch_length: NonZeroU64,
    pub(crate) parent_hash: B256,
    pub(crate) general_gas_limit: u64,
    pub(crate) shared_gas_limit: u64,
    pub(crate) parent_beacon_block_root: Option<B256>,
    /// Sets `cfg_env.enable_amsterdam_eip8037` to gate TIP-1016 behavior in tests.
    pub(crate) amsterdam_eip8037_enabled: bool,
    pub(crate) spec: TempoHardfork,
    pub(crate) extra_data: Bytes,
    pub(crate) fallback_tokens: Option<Vec<alloy_primitives::Address>>,
    // Test state to seed into the executor after creation
    pub(crate) initial_section: Option<BlockSection>,
}

impl Default for TestExecutorBuilder {
    fn default() -> Self {
        Self {
            block_number: 1,
            epoch_length: NonZeroU64::MIN,
            parent_hash: B256::ZERO,
            general_gas_limit: 10_000_000,
            shared_gas_limit: 10_000_000,
            parent_beacon_block_root: None,
            amsterdam_eip8037_enabled: false,
            spec: TempoHardfork::default(),
            extra_data: Bytes::new(),
            fallback_tokens: None,
            initial_section: None,
        }
    }
}

impl TestExecutorBuilder {
    pub(crate) fn with_block_number(mut self, block_number: u64) -> Self {
        self.block_number = block_number;
        self
    }

    pub(crate) fn with_epoch_length(mut self, epoch_length: u64) -> Self {
        self.epoch_length = NonZeroU64::new(epoch_length).expect("epoch length must be non-zero");
        self
    }

    pub(crate) fn with_extra_data(mut self, extra_data: Bytes) -> Self {
        self.extra_data = extra_data;
        self
    }

    pub(crate) fn with_spec(mut self, spec: TempoHardfork) -> Self {
        self.spec = spec;
        self
    }

    pub(crate) fn with_general_gas_limit(mut self, limit: u64) -> Self {
        self.general_gas_limit = limit;
        self
    }

    pub(crate) fn with_parent_beacon_block_root(mut self, root: B256) -> Self {
        self.parent_beacon_block_root = Some(root);
        self
    }

    /// Toggles `cfg_env.enable_amsterdam_eip8037`, which gates TIP-1016 (state gas split)
    /// behavior independently of the T4 hardfork.
    pub(crate) fn with_amsterdam_eip8037_enabled(mut self, enabled: bool) -> Self {
        self.amsterdam_eip8037_enabled = enabled;
        self
    }

    /// Set the initial block section for the executor (for testing section transitions).
    pub(crate) fn with_section(mut self, section: BlockSection) -> Self {
        self.initial_section = Some(section);
        self
    }

    pub(crate) fn build<'a, DB: StateDB>(
        self,
        db: DB,
        chainspec: &'a Arc<TempoChainSpec>,
    ) -> TempoBlockExecutor<'a, DB, NoOpInspector> {
        let mut cfg_env = revm::context::CfgEnv::default();
        cfg_env.enable_amsterdam_eip8037 = self.amsterdam_eip8037_enabled;
        cfg_env.spec = self.spec;
        if self.fallback_tokens.is_some() {
            cfg_env.chain_id = 42431;
            cfg_env.gas_params =
                tempo_revm::gas_params::tempo_gas_params_with_amsterdam(self.spec, false);
        }

        let evm = TempoEvm::new(
            db,
            EvmEnv {
                cfg_env,
                block_env: TempoBlockEnv {
                    inner: BlockEnv {
                        number: U256::from(self.block_number),
                        basefee: 1,
                        gas_limit: 30_000_000,
                        ..Default::default()
                    },
                    epoch_length: self.epoch_length,
                    ..Default::default()
                },
            },
        );

        let ctx = TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: self.parent_hash,
                parent_beacon_block_root: self.parent_beacon_block_root,
                ommers: &[],
                withdrawals: None,
                extra_data: self.extra_data,
                tx_count_hint: None,
                slot_number: None,
            },
            general_gas_limit: self.general_gas_limit,
            shared_gas_limit: self.shared_gas_limit,
            consensus_context: None,
        };

        let evm = if let Some(tokens) = self.fallback_tokens {
            evm.with_fee_manager(tempo_revm::TestFallbackFeeManager(tokens))
        } else {
            evm
        };
        let mut executor = TempoBlockExecutor::new(evm, ctx, chainspec);

        // Apply test-specific initial state
        if let Some(section) = self.initial_section {
            executor.set_section_for_test(section);
        }

        executor
    }
}

/// T14 environment matching the replay fixture's chain and gas tables.
pub(crate) fn fallback_test_evm<DB: Database>(db: DB) -> TempoEvm<DB, NoOpInspector> {
    let mut cfg_env = revm::context::CfgEnv::new_with_spec_and_gas_params(
        TempoHardfork::T14,
        tempo_revm::gas_params::tempo_gas_params_with_amsterdam(TempoHardfork::T14, false),
    );
    cfg_env.chain_id = 42431;
    TempoEvm::new(
        db,
        EvmEnv {
            cfg_env,
            block_env: TempoBlockEnv {
                inner: BlockEnv {
                    basefee: 1,
                    gas_limit: 30_000_000,
                    ..Default::default()
                },
                ..Default::default()
            },
        },
    )
}

/// A real sponsored payment with a 2D nonce, eligible for parallel prewarming.
/// The sponsor has no preference and TIP-20 inference is disabled by sponsorship.
pub(crate) fn fallback_payment_fixture(
    balances: [u64; 3],
) -> (
    revm::database::CacheDB<revm::database::EmptyDB>,
    tempo_revm::TempoTxEnv,
    reth_primitives_traits::Recovered<tempo_primitives::TempoTxEnvelope>,
    Vec<alloy_primitives::Address>,
) {
    use alloy_evm::{Evm, FromRecoveredTx};
    use alloy_primitives::{Address, Signature, TxKind};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::SolCall;
    use revm::{
        DatabaseCommit,
        context::JournalTr,
        database::{CacheDB, EmptyDB},
    };
    use tempo_contracts::precompiles::ITIP20;
    use tempo_precompiles::{
        PATH_USD_ADDRESS,
        storage::{StorageActions, StorageCtx},
        test_util::TIP20Setup,
        tip_fee_manager::TipFeeManager,
    };
    use tempo_primitives::{
        TempoTxEnvelope,
        transaction::{Call, TempoTransaction},
    };

    let sender = Address::repeat_byte(0x11);
    let sponsor = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x22)).unwrap();
    let payer = sponsor.address();
    let mut evm = fallback_test_evm(CacheDB::new(EmptyDB::default()));
    let tokens = StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
        TIP20Setup::path_usd(sender)
            .with_issuer(sender)
            .with_mint(sender, U256::from(2_000_000))
            .with_mint(payer, U256::from(balances[0]))
            .apply()?;
        let mut tokens = vec![PATH_USD_ADDRESS];
        for (index, balance) in balances[1..].iter().enumerate() {
            let token = TIP20Setup::create("Fallback", "FB", sender)
                .with_salt(B256::repeat_byte(index as u8 + 1))
                .with_issuer(sender)
                .with_mint(sender, U256::from(1_000_000))
                .with_mint(payer, U256::from(*balance))
                .apply()?;
            TipFeeManager::new().mint(
                sender,
                token.address(),
                PATH_USD_ADDRESS,
                U256::from(500_000),
                sender,
            )?;
            tokens.push(token.address());
        }
        Ok::<_, tempo_precompiles::error::TempoPrecompileError>(tokens)
    })
    .unwrap();
    let setup = evm.ctx_mut().journaled_state.finalize();
    evm.db_mut().commit(setup);
    let mut tx = TempoTransaction {
        chain_id: 42431,
        gas_limit: 1_000_000,
        max_fee_per_gas: 20_000_000_000,
        max_priority_fee_per_gas: 0,
        nonce_key: U256::ONE,
        calls: vec![Call {
            to: TxKind::Call(PATH_USD_ADDRESS),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: Address::repeat_byte(0x33),
                amount: U256::ONE,
            }
            .abi_encode()
            .into(),
        }],
        ..Default::default()
    };
    tx.fee_payer_signature = Some(
        sponsor
            .sign_hash_sync(&tx.fee_payer_signature_hash(sender))
            .unwrap(),
    );
    let envelope = TempoTxEnvelope::AA(tx.into_signed(Signature::test_signature().into()));
    let tx_env = tempo_revm::TempoTxEnv::from_recovered_tx(&envelope, sender);
    assert_eq!(tx_env.fee_payer().unwrap(), payer);
    let recovered = reth_primitives_traits::Recovered::new_unchecked(envelope, sender);
    let db = evm.db_mut().clone();
    (db, tx_env, recovered, tokens)
}
