//! Gas of the simulated configurable-account owner approvals that RPC simulation builds.
//!
//! The test runs a request through the production [`TempoEvmConfig`] EVM for a T14 chain.

use std::sync::Arc;

use alloy::{
    consensus::Header,
    primitives::{Address, B256, Bytes},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, InMemoryDB},
};
use reth_evm::{ConfigureEvm, EvmEnvFor};
use reth_rpc_eth_api::TryIntoTxEnv;
use serde_json::from_str;
use tempo_alloy::rpc::{
    ConfigurableAccountSimulationApproval, ConfigurableAccountSimulationSpec,
    TempoTransactionRequest,
};
use tempo_chainspec::TempoChainSpec;
use tempo_evm::{TempoEvm, TempoEvmConfig};
use tempo_precompiles::{
    PATH_USD_ADDRESS, configurable_account::CONFIGURABLE_ACCOUNT_CODE, storage::StorageCtx,
    test_util::TIP20Setup,
};
use tempo_primitives::{
    TempoHeader,
    account::encode_config_commitment,
    transaction::{ConfigurableAccountConfig, ConfigurableAccountOwner, SignatureType},
};

const CHAIN_ID: u64 = 1337;
const DELEGATE: Address = Address::repeat_byte(0x44);

fn evm_config() -> TempoEvmConfig {
    TempoEvmConfig::new(Arc::new(TempoChainSpec::from_genesis(
        from_str(include_str!("../assets/test-genesis.json")).unwrap(),
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

/// A one-owner configurable account, and a database where it has that configuration.
fn configurable_account(
    owner: &PrivateKeySigner,
) -> (ConfigurableAccountConfig, Address, InMemoryDB) {
    let config = ConfigurableAccountConfig {
        salt: B256::repeat_byte(0x5a),
        version: 1,
        threshold: 1,
        owners: vec![ConfigurableAccountOwner {
            owner: owner.address(),
            weight: 1,
        }],
    };
    let account = Address::repeat_byte(0x5c);
    let mut info = AccountInfo::default().with_code(Bytecode::new_raw(CONFIGURABLE_ACCOUNT_CODE));
    info.extension = encode_config_commitment(config.commitment().unwrap()).into();
    let mut db = InMemoryDB::default();
    db.insert_account_info(&account, info);
    (config, account, db)
}

/// A simulated `WebAuthn` owner approval is charged its modeled data as nonzero calldata.
#[test]
fn simulated_webauthn_approvals_charge_worst_case_data() {
    let owner = PrivateKeySigner::random();
    let (config, account, db) = configurable_account(&owner);
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
            configurable_account_simulation: Some(spec),
            ..Default::default()
        };
        let mut env = evm_env(&evm_config());
        env.version.chain_id = CHAIN_ID;
        let tx = request.try_into_tx_env(&env).unwrap();
        let result = evm(db.clone()).transact(&tx).unwrap().commit();
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
