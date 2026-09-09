//! Signed transaction integration fixtures for the T12 account-leaf protocol.
use alloy_evm::{Evm, EvmEnv};
use alloy_primitives::{Address, B256, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use revm::{
    Database, DatabaseCommit,
    context::{CfgEnv, JournalTr},
    database::{EmptyDB, State, states::bundle_state::BundleRetention},
    state::{Account, AccountInfo, Bytecode, TransactionId},
};
use tempo_chainspec::TempoHardfork;
use tempo_contracts::precompiles::{NATIVE_MULTISIG_ADDRESS, native_multisig::INativeMultisig};
use tempo_evm::evm::TempoEvm;
use tempo_precompiles::{
    account_keychain::AccountKeychain,
    storage::{StorageActions, StorageCtx},
    test_util::TIP20Setup,
    tip403_registry::TIP403Registry,
};
use tempo_primitives::{
    AASigned, TempoBlockEnv, TempoSignature, TempoTransaction,
    account::decode_config_commitment,
    transaction::{
        Call, MultisigConfig, MultisigOwner, MultisigSignature, PrimitiveSignature, multisig_digest,
    },
};
use tempo_revm::gas_params::tempo_gas_params;

struct Fixture {
    evm: TempoEvm<State<EmptyDB>>,
    owner: PrivateKeySigner,
    config: MultisigConfig,
    account: Address,
}

impl Fixture {
    fn new() -> Self {
        Self::with_parent(true)
    }

    fn with_parent(configurable: bool) -> Self {
        let owner = PrivateKeySigner::from_bytes(&B256::repeat_byte(1)).unwrap();
        let factory = Address::repeat_byte(0x71);
        let config = MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![MultisigOwner {
                owner: owner.address(),
                weight: 1,
            }],
        };
        let account = if configurable {
            config.derive_account(factory).unwrap()
        } else {
            owner.address()
        };
        let mut db = State::builder().with_bundle_update().build();
        let mut seed = Account::new_not_existing(TransactionId::ZERO);
        seed.info.nonce = 3;
        seed.info.balance = U256::from(42);
        seed.mark_touch();
        db.commit([(account, seed)].into_iter().collect());
        let cfg = CfgEnv::new_with_spec_and_gas_params(
            TempoHardfork::T12,
            tempo_gas_params(TempoHardfork::T12),
        );
        let mut evm = TempoEvm::new(
            db,
            EvmEnv::new(
                cfg,
                TempoBlockEnv {
                    multisig_recovery_factory: Some(factory),
                    ..Default::default()
                },
            ),
        );
        StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
            TIP403Registry::new().initialize()?;
            AccountKeychain::new().initialize()?;
            TIP20Setup::path_usd(owner.address()).apply()
        })
        .unwrap();
        let state = evm.ctx_mut().journaled_state.finalize();
        evm.db_mut().commit(state);
        evm.db_mut().merge_transitions(BundleRetention::Reverts);
        Self {
            evm,
            owner,
            config,
            account,
        }
    }

    fn signed(&self, nonce: u64, calls: Vec<Call>) -> AASigned {
        let tx = TempoTransaction {
            chain_id: 1,
            nonce,
            gas_limit: 1_000_000,
            calls,
            ..Default::default()
        };
        let digest = multisig_digest(tx.signature_hash(), self.account, self.config.version);
        let signature = MultisigSignature::try_new(
            self.account,
            self.config.clone(),
            vec![PrimitiveSignature::Secp256k1(
                self.owner.sign_hash_sync(&digest).unwrap(),
            )],
        )
        .unwrap();
        tx.into_signed(TempoSignature::Multisig(signature))
    }

    fn getter(&self) -> Call {
        Call {
            to: TxKind::Call(NATIVE_MULTISIG_ADDRESS),
            value: U256::ZERO,
            input: INativeMultisig::getConfigCommitmentCall {
                account: self.account,
            }
            .abi_encode()
            .into(),
        }
    }

    fn rotation(current: &MultisigConfig, next: &MultisigConfig) -> Call {
        let owners = |config: &MultisigConfig| {
            config
                .owners
                .iter()
                .map(|owner| INativeMultisig::MultisigOwner {
                    owner: owner.owner,
                    weight: owner.weight,
                })
                .collect()
        };
        Call {
            to: TxKind::Call(NATIVE_MULTISIG_ADDRESS),
            value: U256::ZERO,
            input: INativeMultisig::updateConfigCall {
                current: INativeMultisig::MultisigConfig {
                    salt: current.salt,
                    version: current.version,
                    threshold: current.threshold,
                    owners: owners(current),
                },
                threshold: next.threshold,
                owners: owners(next),
            }
            .abi_encode()
            .into(),
        }
    }

    fn commitment(&mut self) -> B256 {
        decode_config_commitment(
            &self
                .evm
                .db_mut()
                .basic(self.account)
                .unwrap()
                .unwrap()
                .extension,
            true,
        )
        .unwrap()
    }

    fn install_contract(&mut self, address: Address, code: Vec<u8>) -> Call {
        let code = Bytecode::new_legacy(code.into());
        self.evm.db_mut().insert_account(
            address,
            AccountInfo {
                code_hash: code.hash_slow(),
                code: Some(code),
                ..Default::default()
            },
        );
        Call {
            to: TxKind::Call(address),
            value: U256::ZERO,
            input: Default::default(),
        }
    }
}

mod tests;
