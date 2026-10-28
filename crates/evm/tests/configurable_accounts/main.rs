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
    evm::{AccountInfo, InMemoryDB},
};
use reth_evm::BlockExecutorFactory;
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
        ConfigurableAccountOwner, PrimitiveSignature,
    },
};

/// The gas limit of the transactions built by `aa_tx`.
const AA_GAS_LIMIT: u64 = 1_000_000;

/// The chain ID of the fixture's EVM and of the transactions it signs.
const CHAIN_ID: u64 = 1;

struct Fixture {
    evm: TempoEvm<'static>,
    owner: PrivateKeySigner,
    account: Address,
}

impl Fixture {
    fn new() -> Self {
        Self::with_spec(TempoHardfork::T14)
    }

    fn with_spec(spec: TempoHardfork) -> Self {
        Self::with_cfg(spec, |_| {})
    }

    /// A fixture at `spec` whose EVM version `configure` adjusts before the EVM is built, so
    /// that the precompiles, which read it when the EVM is built, see the change too.
    fn with_cfg(spec: TempoHardfork, configure: impl FnOnce(&mut Version)) -> Self {
        let owner = signer(1);
        let account = owner.address();
        let mut version = *tempo_execution_config(spec, CHAIN_ID).version();
        version.tx_gas_limit_cap = spec.tx_gas_limit_cap().unwrap_or(u64::MAX);
        configure(&mut version);
        let mut evm = BlockExecutorFactory::evm_with_env(
            &TempoEvmConfig::moderato(),
            InMemoryDB::default(),
            TempoEvmEnv::new_with_version(spec, TempoBlockEnv::default(), version),
        );
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
