//! Signed transaction integration fixtures for the T14 account-leaf protocol.
use alloy_consensus::transaction::Recovered;
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, B256, TxKind, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use evm2::{
    ExecutionConfig, TxResult, Version,
    bytecode::Bytecode,
    evm::{AccountChangeRef, AccountInfo, InMemoryDB, StateChangeSink, StorageChange},
};
use reth_evm::{BlockExecutorFactory, BundleState};
use reth_execution_types::{BlockState, TransactionChanges};
use reth_primitives_traits::SignedTransaction;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount};
use tempo_evm::{
    TempoBlockEnv, TempoEvm, TempoEvmConfig, TempoEvmEnv, TempoEvmTypes, TempoTxEnv,
    tempo_execution_config, tempo_tx_registry,
};
use tempo_precompiles::{
    TempoPrecompiles, account_keychain::AccountKeychain, storage::StorageCtx,
    test_util::TIP20Setup, tip403_registry::TIP403Registry,
};
use tempo_primitives::{
    AASigned, TempoSignature, TempoTransaction, TempoTxEnvelope,
    account::decode_config_commitment,
    transaction::{
        CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, Call, ConfigurableAccountConfig,
        ConfigurableAccountOwner, ConfigurableAccountSignature, PrimitiveSignature,
        configurable_account_digest,
    },
};

/// The gas limit of the transactions built by `aa_tx`.
const AA_GAS_LIMIT: u64 = 1_000_000;

/// The chain ID of the fixture's EVM and of the transactions it signs.
const CHAIN_ID: u64 = 1;

struct Fixture {
    evm: TempoEvm<'static>,
    owner: PrivateKeySigner,
    config: ConfigurableAccountConfig,
    account: Address,
}

impl Fixture {
    fn new() -> Self {
        Self::with_parent(true)
    }

    fn with_parent(configurable: bool) -> Self {
        Self::with_spec(configurable, TempoHardfork::T14)
    }

    fn with_spec(configurable: bool, spec: TempoHardfork) -> Self {
        Self::with_cfg(configurable, spec, |_| {})
    }

    /// A fixture at `spec` whose EVM version `configure` adjusts before the EVM is built, so
    /// that the precompiles, which read it when the EVM is built, see the change too.
    fn with_cfg(
        configurable: bool,
        spec: TempoHardfork,
        configure: impl FnOnce(&mut Version),
    ) -> Self {
        let owner = signer(1);
        let config = ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![ConfigurableAccountOwner {
                owner: owner.address(),
                weight: 1,
            }],
        };
        let account = if configurable {
            config.derive_account().unwrap()
        } else {
            owner.address()
        };
        let mut version = *tempo_execution_config(spec, CHAIN_ID).version();
        version.tx_gas_limit_cap = spec.tx_gas_limit_cap().unwrap_or(u64::MAX);
        configure(&mut version);
        let mut evm = BlockExecutorFactory::evm_with_env(
            &TempoEvmConfig::moderato(),
            InMemoryDB::default(),
            TempoEvmEnv::new_with_version(spec, TempoBlockEnv::default(), version),
        );
        // The accepted overlay holds the whole state, so `genesis_bundle` and executors see it.
        evm.overlay_db_mut().insert_account_info(
            &account,
            AccountInfo::default()
                .with_nonce(3)
                .with_balance(U256::from(42)),
        );
        in_storage_ctx(&mut evm, || {
            TIP403Registry::new().initialize()?;
            AccountKeychain::new().initialize()?;
            TIP20Setup::path_usd(owner.address()).apply()
        })
        .unwrap();
        Self {
            evm,
            owner,
            config,
            account,
        }
    }

    fn getter(&self) -> Call {
        Call {
            to: TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS),
            value: U256::ZERO,
            input: IConfigurableAccount::getConfigCommitmentCall {
                account: self.account,
            }
            .abi_encode()
            .into(),
        }
    }

    fn rotation(current: &ConfigurableAccountConfig, next: &ConfigurableAccountConfig) -> Call {
        Call {
            to: TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS),
            value: U256::ZERO,
            input: IConfigurableAccount::updateConfigCall {
                current: IConfigurableAccount::ConfigurableAccountConfig {
                    salt: current.salt,
                    version: current.version,
                    threshold: current.threshold,
                    owners: abi_owners(current),
                },
                threshold: next.threshold,
                owners: abi_owners(next),
            }
            .abi_encode()
            .into(),
        }
    }

    /// The configuration `upgradeAccount` commits for this account: the upgrade salt at version 1.
    fn upgraded(
        &self,
        threshold: u8,
        owners: Vec<ConfigurableAccountOwner>,
    ) -> ConfigurableAccountConfig {
        ConfigurableAccountConfig {
            salt: keccak256(
                [CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, self.account.as_slice()].concat(),
            ),
            version: 1,
            threshold,
            owners,
        }
    }

    /// An `upgradeAccount` call that migrates the sender to `config`.
    fn upgrade(config: &ConfigurableAccountConfig) -> Call {
        Call {
            to: TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS),
            value: U256::ZERO,
            input: IConfigurableAccount::upgradeAccountCall {
                threshold: config.threshold,
                owners: abi_owners(config),
            }
            .abi_encode()
            .into(),
        }
    }

    /// An AA transaction signed by the account's root key (a primitive signature).
    fn primitive(&self, nonce: u64, calls: Vec<Call>) -> AASigned {
        self.sign_primitive(aa_tx(nonce, calls))
    }

    fn sign_primitive(&self, tx: TempoTransaction) -> AASigned {
        let signature = self.owner.sign_hash_sync(&tx.signature_hash()).unwrap();
        tx.into_signed(signature.into())
    }

    fn signed(&self, nonce: u64, calls: Vec<Call>) -> AASigned {
        configurable_account_signed(self, aa_tx(nonce, calls))
    }

    /// Executes `tx` for the account and commits its state, whether or not it reverts.
    fn run<T>(&mut self, tx: &T) -> TxResult<TempoEvmTypes>
    where
        T: Clone + Into<TempoTxEnvelope>,
    {
        self.run_as(self.account, tx)
    }

    /// Executes `tx` sent by `sender` and commits its state, whether or not it reverts.
    fn run_as<T>(&mut self, sender: Address, tx: &T) -> TxResult<TempoEvmTypes>
    where
        T: Clone + Into<TempoTxEnvelope>,
    {
        self.evm.transact(&tx_env(tx, sender)).unwrap().commit()
    }

    /// The account's info as the EVM reads it now, `None` when the account does not exist.
    fn info(&mut self, address: Address) -> Option<AccountInfo> {
        self.evm.read_account_info(&address).unwrap()
    }

    /// Replaces `address`'s info in the EVM's database with `update` applied to it.
    fn update_account(&mut self, address: Address, update: impl FnOnce(&mut AccountInfo)) {
        let mut info = self.info(address).unwrap_or_default();
        update(&mut info);
        self.evm
            .overlay_db_mut()
            .insert_account_info(&address, info);
    }

    fn commitment(&mut self) -> B256 {
        let account = self.account;
        decode_config_commitment(&self.info(account).unwrap().extension, TempoHardfork::T14)
            .unwrap()
    }

    /// Replaces the block environment with `update` applied.
    fn update_block(&mut self, update: impl FnOnce(&mut TempoBlockEnv)) {
        let mut block = *self.evm.block();
        update(&mut block);
        self.evm.set_block(block);
    }

    /// Replaces the EVM version with `configure` applied, keeping the state. The precompiles are
    /// rebuilt too, since they share the version and the storage-action recorder.
    fn reconfigure(&mut self, configure: impl FnOnce(&mut Version)) {
        let spec = self.evm.config_spec_id();
        let mut version = *self.evm.version();
        configure(&mut version);
        let precompiles = TempoPrecompiles::<TempoEvmTypes>::new(
            spec,
            self.evm.ext().actions.clone(),
            self.evm.ext().non_creditable_slots.clone(),
        );
        self.evm.set_execution_config(
            ExecutionConfig::for_spec_and_version(spec, version),
            spec,
            tempo_tx_registry(spec.into()),
            precompiles,
        );
    }

    /// The accepted state as a bundle that creates every account, to persist as a genesis.
    fn genesis_bundle(&self) -> BundleState {
        let cache = &self.evm.overlay_db().cache;
        let mut changes = TransactionChanges::default();
        for (hash, code) in &cache.contracts {
            let Ok(()) = changes.bytecode(*hash, code);
        }
        for (address, info) in &cache.accounts {
            let Some(info) = info else { continue };
            let Ok(()) = changes.account(AccountChangeRef {
                address: *address,
                original: None,
                current: Some(info),
                created: true,
                selfdestructed: false,
            });
        }
        for (address, storage) in &cache.storage {
            for (key, value) in &storage.slots {
                let Ok(()) = changes.storage(StorageChange {
                    address: *address,
                    key: *key,
                    original: U256::ZERO,
                    current: *value,
                });
            }
        }
        let mut block = BlockState::new();
        block.commit(&changes);
        block.into_bundle()
    }

    fn install_contract(&mut self, address: Address, code: Vec<u8>) -> Call {
        self.evm.overlay_db_mut().insert_account_info(
            &address,
            AccountInfo::default().with_code(Bytecode::new_legacy(code.into())),
        );
        Call {
            to: TxKind::Call(address),
            value: U256::ZERO,
            input: Default::default(),
        }
    }
}

/// Runs `f` in a storage context of `evm` and accepts its writes.
fn in_storage_ctx<R>(evm: &mut TempoEvm<'static>, f: impl FnOnce() -> R) -> R {
    let result = StorageCtx::enter_evm(evm, f);
    evm.state_mut().commit_transaction();
    evm.state_mut().clear_transaction_state();
    result
}

/// The EVM transaction of `tx` sent by `sender`.
fn tx_env<T>(tx: &T, sender: Address) -> Recovered<TempoTxEnv>
where
    T: Clone + Into<TempoTxEnvelope>,
{
    let envelope: TempoTxEnvelope = tx.clone().into();
    Recovered::new_unchecked(TempoTxEnv::from(envelope.with_signer(sender)), sender)
}

/// An unsigned AA transaction on the protocol nonce lane, with no fee, sponsor, validity window
/// or authorizations.
fn aa_tx(nonce: u64, calls: Vec<Call>) -> TempoTransaction {
    TempoTransaction {
        chain_id: CHAIN_ID,
        fee_token: None,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: AA_GAS_LIMIT,
        calls,
        access_list: AccessList(Vec::new()),
        nonce_key: U256::ZERO,
        nonce,
        fee_payer_signature: None,
        valid_before: None,
        valid_after: None,
        key_authorization: None,
        tempo_authorization_list: Vec::new(),
    }
}

/// The deterministic test key whose private key is `seed` repeated.
fn signer(seed: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(seed)).unwrap()
}

/// Signs `tx` as the account's configurable account, with the fixture's current configuration.
fn configurable_account_signed(f: &Fixture, tx: TempoTransaction) -> AASigned {
    configurable_account_signed_by(f.account, &f.config, &f.owner, tx)
}

/// Signs `tx` as the configurable `account` with `config`, approved by `owner`.
fn configurable_account_signed_by(
    account: Address,
    config: &ConfigurableAccountConfig,
    owner: &PrivateKeySigner,
    tx: TempoTransaction,
) -> AASigned {
    let signature = configurable_account_approval(account, config, owner, tx.signature_hash());
    tx.into_signed(TempoSignature::ConfigurableAccount(signature))
}

/// `owner`'s approval of `inner_digest` as the configurable `account` with `config`.
fn configurable_account_approval(
    account: Address,
    config: &ConfigurableAccountConfig,
    owner: &PrivateKeySigner,
    inner_digest: B256,
) -> ConfigurableAccountSignature {
    let digest = configurable_account_digest(inner_digest, account, config.version);
    let approval = PrimitiveSignature::Secp256k1(owner.sign_hash_sync(&digest).unwrap());
    ConfigurableAccountSignature::try_new(account, config.clone(), vec![approval]).unwrap()
}

fn abi_owners(
    config: &ConfigurableAccountConfig,
) -> Vec<IConfigurableAccount::ConfigurableAccountOwner> {
    config
        .owners
        .iter()
        .map(|owner| IConfigurableAccount::ConfigurableAccountOwner {
            owner: owner.owner,
            weight: owner.weight,
        })
        .collect()
}

mod tests;
