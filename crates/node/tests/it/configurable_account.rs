//! Gas of the simulated configurable-account owner approvals that RPC preprocessing builds.
//!
//! The test runs a request through the production [`TempoEvmConfig`] EVM for a T14 chain with the
//! recovery factory configured.

use std::sync::Arc;

use alloy::{
    consensus::Header,
    primitives::{Address, B256, Bytes},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use evm2::evm::InMemoryDB;
use reth_evm::{ConfigureEvm, EvmEnvFor};
use reth_rpc_eth_api::TryIntoTxEnv;
use serde_json::{Value, from_str, from_value, json};
use tempo_alloy::rpc::{
    ConfigurableAccountSimulationApproval, ConfigurableAccountSimulationSpec,
    TempoTransactionRequest,
};
use tempo_chainspec::TempoChainSpec;
use tempo_evm::{TempoEvm, TempoEvmConfig};
use tempo_precompiles::{PATH_USD_ADDRESS, storage::StorageCtx, test_util::TIP20Setup};
use tempo_primitives::{
    TempoHeader,
    transaction::{ConfigurableAccountConfig, ConfigurableAccountOwner, SignatureType},
};

const CHAIN_ID: u64 = 1337;
const FACTORY: Address = Address::repeat_byte(0x71);
const DELEGATE: Address = Address::repeat_byte(0x44);

fn evm_config() -> TempoEvmConfig {
    let mut genesis: Value = from_str(include_str!("../assets/test-genesis.json")).unwrap();
    genesis["config"]["configurableAccountRecoveryFactory"] = json!(FACTORY);
    TempoEvmConfig::new(Arc::new(TempoChainSpec::from_genesis(
        from_value(genesis).unwrap(),
    )))
}

fn evm_env(config: &TempoEvmConfig) -> EvmEnvFor<TempoEvmConfig> {
    let header = TempoHeader {
        inner: Header {
            number: 1,
            timestamp: 1,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(0),
            ..Default::default()
        },
        general_gas_limit: 30_000_000,
        shared_gas_limit: 30_000_000,
        ..Default::default()
    };
    let env = config.evm_env(&header).unwrap();
    assert!(env.spec.is_t14());
    env
}

fn evm(db: InMemoryDB) -> TempoEvm<'static> {
    let config = evm_config();
    let env = evm_env(&config);
    let mut evm = config.evm_with_env(db, env);
    StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
        TIP20Setup::path_usd(Address::repeat_byte(0x01)).apply()
    })
    .unwrap();
    evm
}

/// A fresh one-owner configurable account and its derived address.
fn configurable_account(owner: &PrivateKeySigner) -> (ConfigurableAccountConfig, Address) {
    let config = ConfigurableAccountConfig {
        salt: B256::repeat_byte(0x5a),
        version: 0,
        threshold: 1,
        owners: vec![ConfigurableAccountOwner {
            owner: owner.address(),
            weight: 1,
        }],
    };
    let account = config.derive_account(FACTORY).unwrap();
    (config, account)
}

/// A simulated `WebAuthn` owner approval is charged its modeled data as nonzero calldata.
#[test]
fn simulated_webauthn_approvals_charge_worst_case_data() {
    let owner = PrivateKeySigner::random();
    let (config, account) = configurable_account(&owner);
    let gas_used = |key_type: SignatureType, key_data: Option<Bytes>| {
        let spec = ConfigurableAccountSimulationSpec {
            signer: None,
            config: config.clone(),
            approvals: vec![ConfigurableAccountSimulationApproval {
                owner: owner.address(),
                key_type: Some(key_type),
                key_data,
            }],
        };
        let request = TempoTransactionRequest {
            inner: TransactionRequest::default()
                .from(account)
                .to(DELEGATE)
                .gas_limit(5_000_000),
            fee_token: Some(PATH_USD_ADDRESS),
            key_type: Some(SignatureType::ConfigurableAccount),
            configurable_account_simulation_signature: Some(spec.mock_signature(account).unwrap()),
            configurable_account_simulation: Some(spec),
            configurable_account_simulation_prepared: true,
            ..Default::default()
        };
        let mut env = evm_env(&evm_config());
        env.version.chain_id = CHAIN_ID;
        let tx = request.try_into_tx_env(&env).unwrap();
        let result = evm(InMemoryDB::default()).transact(&tx).unwrap().commit();
        assert!(result.status, "{result:?}");
        result.tx_gas_used()
    };
    // Same witness with no WebAuthn data isolates the data charge.
    let empty = gas_used(SignatureType::P256, None);
    for size in [128u16, 800, 1920] {
        let webauthn = gas_used(
            SignatureType::WebAuthn,
            Some(Bytes::from(size.to_be_bytes())),
        );
        assert_eq!(webauthn - empty, u64::from(size) * 16, "size {size}");
    }
}
