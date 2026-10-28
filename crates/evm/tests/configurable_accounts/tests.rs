use super::*;
use alloy_consensus::{Header, SignableTransaction, TxEip1559, TxEip2930, TxEip7702, TxLegacy};
use alloy_eips::{
    eip2930::AccessList,
    eip7702::{Authorization, SignedAuthorization},
};
use alloy_primitives::{Bytes, KECCAK256_EMPTY, LogData, bytes, keccak256};
use alloy_sol_types::{SolError, SolEvent};
use evm2::{
    EvmFeatures,
    evm::DynDatabase,
    version::{GasId, GasParams},
};
use reth_chainspec::EthChainSpec;
use reth_evm::{BlockExecutor, ConfigureEvm};
use reth_execution_types::BundleSource;
use reth_primitives_traits::Block as _;
use serde_json::json;
use std::{num::NonZeroU64, sync::Arc};
use tempo_chainspec::{TempoChainSpec, spec::DEV};
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, PATH_USD_ADDRESS, account_keychain::IAccountKeychain, nonce::INonce,
    tip20::ITIP20,
};
use tempo_evm::TempoEvmConfig;
use tempo_precompiles::{
    configurable_account::CONFIGURABLE_ACCOUNT_CODE_HASH, error::TempoPrecompileError,
    nonce::NonceManager, storage::keccak_cost, tip20::TIP20Token,
};
use tempo_primitives::{
    Block as TempoBlock, SignatureType, TempoHeader, TempoTxEnvelope,
    transaction::{
        CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN, KeyAuthorization, KeychainSignature,
        TEMPO_EXPIRING_NONCE_KEY, TempoSignedAuthorization, calc_gas_balance_spending,
    },
};

/// Gas of the expiring-nonce replay protection: two cold SLOADs, a warm access and three warm
/// SSTORE resets.
const EXPIRING_NONCE_GAS: u64 = 2 * 2_100 + 100 + 3 * 2_900;

/// The expiry of an expiring-nonce transaction: just after the fixture's block timestamp of 1.
const EXPIRING_VALID_BEFORE: NonZeroU64 = NonZeroU64::new(2).expect("expiry is nonzero");

/// TIP-1016's split of the new-account cost: 25k regular and 225k state gas. T14's table keeps the
/// split off, so the test that needs state gas applies it on top.
const SPLIT_NEW_ACCOUNT_COST: [(GasId, u32); 2] = [
    (GasId::NewAccountCost, 25_000),
    (GasId::NewAccountState, 225_000),
];

/// The path-USD balance and allowance, the keychain keys and the 2D nonce of an account.
#[derive(Debug, PartialEq, Eq)]
struct AccountSnapshot {
    balance: U256,
    allowance: U256,
    keys: Vec<IAccountKeychain::KeyInfo>,
    nonce: u64,
}

#[derive(Clone, Copy, Debug)]
enum RootTx {
    Legacy,
    Eip2930,
    Eip1559,
    Aa,
}

/// The nonce lane of a transaction, which decides how TIP-1000 charges the sender's creation.
#[derive(Clone, Copy, Debug)]
enum NonceLane {
    Protocol,
    /// The protocol lane of a simulation: the nonce check is disabled and the transaction nonce is
    /// not zero, so the `nonce == 0` charge does not apply.
    ProtocolSimulated,
    TwoD,
    Expiring,
}

/// The block regular and state gas of a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockGas {
    regular: u64,
    state: u64,
}

impl BlockGas {
    fn plus(self, other: Self) -> Self {
        Self {
            regular: self.regular + other.regular,
            state: self.state + other.state,
        }
    }
}

/// The sender of an `upgradeAccount` transaction.
#[derive(Clone, Copy, Debug)]
enum UpgradeSender {
    /// No balance and nonce zero.
    Empty,
    /// A balance and nonce zero.
    Funded,
    /// The fixture's account at nonce 3, on the protocol lane.
    Settled,
}

/// The gas parameters of `spec`'s EVM version.
fn tempo_gas_params(spec: TempoHardfork) -> GasParams {
    tempo_execution_config(spec, CHAIN_ID).version().gas_params
}

fn activation_config() -> TempoEvmConfig {
    let mut genesis = DEV.genesis().clone();
    genesis.config.chain_id = 1;
    for (field, value) in [
        ("t12Time", 0),
        ("t13Time", 0),
        ("t14Time", 10),
        ("t15Time", 1_000),
    ] {
        genesis
            .config
            .extra_fields
            .insert(field.into(), json!(value));
    }
    TempoEvmConfig::new(Arc::new(TempoChainSpec::from_genesis(genesis)))
}

/// Weight-one owners in the ascending order a configuration requires.
fn owner_set(mut addresses: Vec<Address>) -> Vec<ConfigurableAccountOwner> {
    addresses.sort();
    addresses
        .into_iter()
        .map(|owner| ConfigurableAccountOwner { owner, weight: 1 })
        .collect()
}

/// Mints path USD, which pays transaction fees by default.
fn fund(f: &mut Fixture, account: Address, amount: u64) {
    in_storage_ctx(&mut f.evm, || {
        TIP20Setup::path_usd(f.owner.address())
            .with_issuer(f.owner.address())
            .with_mint(account, U256::from(amount))
            .apply()
    })
    .unwrap();
}

fn balance(f: &mut Fixture, account: Address) -> U256 {
    in_storage_ctx(&mut f.evm, || {
        TIP20Token::from_address(PATH_USD_ADDRESS)?.balance_of(ITIP20::balanceOfCall { account })
    })
    .unwrap()
}

/// A transaction of `kind` signed by the account's secp256k1 root whose only call is `call`.
fn root_tx(f: &Fixture, kind: RootTx, nonce: u64, call: Call) -> TempoTxEnvelope {
    let Call { to, value, input } = call;
    let sign = |hash: B256| f.owner.sign_hash_sync(&hash).unwrap();
    match kind {
        RootTx::Legacy => {
            let tx = TxLegacy {
                chain_id: Some(1),
                nonce,
                gas_price: 0,
                gas_limit: 1_000_000,
                to,
                value,
                input,
            };
            let signature = sign(tx.signature_hash());
            TempoTxEnvelope::Legacy(tx.into_signed(signature))
        }
        RootTx::Eip2930 => {
            let tx = TxEip2930 {
                chain_id: 1,
                nonce,
                gas_price: 0,
                gas_limit: 1_000_000,
                to,
                value,
                access_list: AccessList(Vec::new()),
                input,
            };
            let signature = sign(tx.signature_hash());
            TempoTxEnvelope::Eip2930(tx.into_signed(signature))
        }
        RootTx::Eip1559 => {
            let tx = TxEip1559 {
                chain_id: 1,
                nonce,
                gas_limit: 1_000_000,
                max_fee_per_gas: 0,
                max_priority_fee_per_gas: 0,
                to,
                value,
                access_list: AccessList(Vec::new()),
                input,
            };
            let signature = sign(tx.signature_hash());
            TempoTxEnvelope::Eip1559(tx.into_signed(signature))
        }
        RootTx::Aa => TempoTxEnvelope::AA(f.primitive(nonce, vec![Call { to, value, input }])),
    }
}

fn authorization(signer: &PrivateKeySigner, target: Address, nonce: u64) -> SignedAuthorization {
    let authorization = Authorization {
        chain_id: U256::ONE,
        address: target,
        nonce,
    };
    let signature = signer
        .sign_hash_sync(&authorization.signature_hash())
        .unwrap();
    authorization.into_signed(signature)
}

/// An EIP-7702 transaction signed by `sender` carrying `authorizations`.
fn type4(
    sender: &PrivateKeySigner,
    nonce: u64,
    to: Address,
    input: Bytes,
    authorizations: Vec<SignedAuthorization>,
) -> TempoTxEnvelope {
    let tx = TxEip7702 {
        chain_id: 1,
        nonce,
        gas_limit: 1_000_000,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to,
        value: U256::ZERO,
        access_list: AccessList(Vec::new()),
        authorization_list: authorizations,
        input,
    };
    let signature = sender.sign_hash_sync(&tx.signature_hash()).unwrap();
    TempoTxEnvelope::Eip7702(tx.into_signed(signature))
}

/// Delegates the account to `target` (the zero address clears the delegation) with a real
/// type-4 transaction at `nonce`; the authorization consumes the next nonce.
fn set_delegation(f: &mut Fixture, nonce: u64, target: Address) {
    let tx = type4(
        &f.owner,
        nonce,
        Address::repeat_byte(0x73),
        Bytes::new(),
        vec![authorization(&f.owner, target, nonce + 1)],
    );
    let result = f.run(&tx);
    assert!(result.status, "{result:?}");
}

/// Authorizes `key` for the account with a root-signed grant at `nonce`.
fn grant_key(f: &mut Fixture, nonce: u64, key: &PrivateKeySigner, expiry: u64) {
    let mut grant = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key.address());
    if expiry != 0 {
        grant = grant.with_expiry(expiry);
    }
    let approval = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
    let tx = f.sign_primitive(TempoTransaction {
        key_authorization: Some(grant.into_signed(PrimitiveSignature::Secp256k1(approval))),
        ..aa_tx(nonce, vec![f.getter()])
    });
    let result = f.run(&tx);
    assert!(result.status, "{result:?}");
}

/// A transaction signed by the access key `key` on behalf of the account.
fn keychain_tx(f: &Fixture, key: &PrivateKeySigner, nonce: u64, calls: Vec<Call>) -> AASigned {
    keychain_signed(aa_tx(nonce, calls), key, f.account)
}

/// `tx` signed by the access key `key` on behalf of `parent`.
fn keychain_signed(tx: TempoTransaction, key: &PrivateKeySigner, parent: Address) -> AASigned {
    let signature = key
        .sign_hash_sync(&KeychainSignature::signing_hash(
            tx.signature_hash(),
            parent,
        ))
        .unwrap();
    tx.into_signed(TempoSignature::Keychain(KeychainSignature::new(
        parent,
        PrimitiveSignature::Secp256k1(signature),
    )))
}

/// A contract that forwards its calldata to the configurable account precompile and reverts with
/// the result.
fn forwarder(f: &mut Fixture) -> Call {
    let code = [
        bytes!("365f5f375f5f365f5f73").as_ref(),
        CONFIGURABLE_ACCOUNT_ADDRESS.as_slice(),
        bytes!("5af1503d5f5f3e3d5ffd").as_ref(),
    ]
    .concat();
    f.install_contract(Address::repeat_byte(0x55), code)
}

/// The data of the configurable account precompile's logs; fee transfers and key grants log too.
fn configurable_account_logs(result: &TxResult<TempoEvmTypes>) -> Vec<LogData> {
    result
        .logs
        .iter()
        .filter(|log| log.address == CONFIGURABLE_ACCOUNT_ADDRESS)
        .map(|log| log.data.clone())
        .collect()
}

fn assert_upgraded(
    f: &mut Fixture,
    result: &TxResult<TempoEvmTypes>,
    config: &ConfigurableAccountConfig,
) {
    let commitment = config.commitment().unwrap();
    assert!(result.status, "{result:?}");
    assert_eq!(
        IConfigurableAccount::upgradeAccountCall::abi_decode_returns(&result.output).unwrap(),
        commitment
    );
    let event = IConfigurableAccount::AccountUpgraded {
        account: f.account,
        commitment,
        salt: config.salt,
        threshold: config.threshold,
        owners: abi_owners(config),
    };
    assert_eq!(configurable_account_logs(result), [event.encode_log_data()]);
    assert_eq!(f.commitment(), commitment);
    assert_eq!(
        f.info(f.account).unwrap().code_hash,
        CONFIGURABLE_ACCOUNT_CODE_HASH
    );
}

/// Runs the transaction `tx` builds on `f` and asserts it reverts with exactly `error`.
fn expect_revert(
    mut f: Fixture,
    label: &str,
    tx: impl FnOnce(&mut Fixture) -> TempoTxEnvelope,
    error: &[u8],
) {
    let tx = tx(&mut f);
    let result = f.run(&tx);
    assert!(result.stop.is_revert(), "{label}: {result:?}");
    assert_eq!(&result.output, error, "{label}");
    assert!(configurable_account_logs(&result).is_empty(), "{label}");
}

#[test]
fn configurable_account_marker_is_installed_at_t14() {
    let config = activation_config();
    let mut db = InMemoryDB::default();
    for (number, timestamp) in [(1, 9), (2, 10), (3, 11)] {
        let block = TempoBlock::uncle(TempoHeader {
            inner: Header {
                number,
                timestamp,
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(0),
                parent_beacon_block_root: Some(B256::ZERO),
                ..Default::default()
            },
            general_gas_limit: 30_000_000,
            ..Default::default()
        })
        .seal_slow();
        let mut executor = config.executor_for_block(db.clone(), &block).unwrap();
        assert_eq!(
            executor.evm().config_spec_id(),
            if timestamp < 10 {
                TempoHardfork::T13
            } else {
                TempoHardfork::T14
            }
        );
        executor.apply_pre_execution_changes().unwrap();
        let output = executor.finish().unwrap();
        db.commit_source(&BundleSource(&output.state));
        let marker = db
            .get_account(&CONFIGURABLE_ACCOUNT_ADDRESS)
            .unwrap()
            .unwrap_or_default();
        assert_eq!(marker.code_hash == KECCAK256_EMPTY, timestamp < 10);
    }
}

/// Seeds `address` as an empty account, or as a non-empty one (a balance, nonce zero).
fn seed_account(f: &mut Fixture, address: Address, empty: bool) {
    let balance = if empty { U256::ZERO } else { U256::ONE };
    f.evm
        .overlay_db_mut()
        .insert_account_info(&address, AccountInfo::default().with_balance(balance));
}

/// Runs `tx` and returns its block gas.
fn block_gas(f: &mut Fixture, tx: &AASigned) -> BlockGas {
    let result = f.run(tx);
    assert!(result.status, "{result:?}");
    BlockGas {
        regular: result.execution_gas_spent(),
        state: result.state_gas_spent(),
    }
}

/// An unsigned transaction on `lane` (at nonce zero, except on the simulated lane, which also
/// disables the nonce check of `f`).
fn lane_tx(f: &mut Fixture, lane: NonceLane, calls: Vec<Call>) -> TempoTransaction {
    let nonce = match lane {
        NonceLane::ProtocolSimulated => {
            f.reconfigure(|version| version.features.remove(EvmFeatures::NONCE_CHECK));
            1
        }
        NonceLane::Protocol | NonceLane::TwoD | NonceLane::Expiring => 0,
    };
    TempoTransaction {
        nonce_key: match lane {
            NonceLane::Protocol | NonceLane::ProtocolSimulated => U256::ZERO,
            NonceLane::TwoD => U256::ONE,
            NonceLane::Expiring => TEMPO_EXPIRING_NONCE_KEY,
        },
        valid_before: matches!(lane, NonceLane::Expiring).then_some(EXPIRING_VALID_BEFORE),
        gas_limit: 5_000_000,
        ..aa_tx(nonce, calls)
    }
}

/// Migrates the fixture's account for real, to a configuration owned by `owner`.
fn migrate(f: &mut Fixture, nonce: u64, owner: Address) -> ConfigurableAccountConfig {
    let config = f.upgraded(1, owner_set(vec![owner]));
    let tx = f.primitive(nonce, vec![Fixture::upgrade(&config)]);
    let result = f.run(&tx);
    assert_upgraded(f, &result, &config);
    config
}

#[test]
fn eoa_migration_commits_configuration() {
    assert_eq!(
        CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN,
        b"tempo:configurable-account:upgrade"
    );
    let others = [signer(2).address(), signer(3).address()];
    for kind in [RootTx::Legacy, RootTx::Eip2930, RootTx::Eip1559, RootTx::Aa] {
        for root_listed in [false, true] {
            let mut f = Fixture::new();
            let mut members = others.to_vec();
            if root_listed {
                members.push(f.owner.address());
            }
            let config = f.upgraded(2, owner_set(members));
            let tx = root_tx(&f, kind, 3, Fixture::upgrade(&config));
            let result = f.run(&tx);
            assert_upgraded(&mut f, &result, &config);
            assert_eq!(
                config.salt,
                keccak256(
                    [
                        b"tempo:configurable-account:upgrade".as_slice(),
                        f.account.as_slice()
                    ]
                    .concat()
                ),
                "{kind:?}"
            );
            assert_eq!(f.info(f.account).unwrap().nonce, 4);
        }
    }

    // A nonce-zero account with no balance migrates under a fee payer, which pays.
    let mut f = Fixture::new();
    f.evm.overlay_db_mut().insert_account_info(
        &f.account,
        AccountInfo::new(U256::ZERO, 0, KECCAK256_EMPTY, Some(Bytecode::default())),
    );
    let sponsor = signer(9);
    fund(&mut f, sponsor.address(), 50_000_000);
    let config = f.upgraded(1, owner_set(others.to_vec()));
    let mut tx = TempoTransaction {
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 1,
        fee_token: Some(PATH_USD_ADDRESS),
        ..aa_tx(0, vec![Fixture::upgrade(&config)])
    };
    tx.fee_payer_signature = Some(
        sponsor
            .sign_hash_sync(&tx.fee_payer_signature_hash(f.account))
            .unwrap(),
    );
    let tx = f.sign_primitive(tx);
    let result = f.run(&tx);
    assert_upgraded(&mut f, &result, &config);
    let fee = calc_gas_balance_spending(result.tx_gas_used(), 1);
    assert!(fee > U256::ZERO);
    assert_eq!(
        balance(&mut f, sponsor.address()),
        U256::from(50_000_000) - fee
    );
    let account = f.account;
    assert_eq!(balance(&mut f, account), U256::ZERO);
    assert_eq!(f.info(account).unwrap().nonce, 1);
}

#[test]
fn eoa_migration_error_order() {
    let only_call = IConfigurableAccount::UpgradeMustBeOnlyCall {}.abi_encode();
    let root_required = IConfigurableAccount::PrimitiveRootRequired {}.abi_encode();
    let has_code = IConfigurableAccount::AccountHasCode {}.abi_encode();
    let invalid_config = IConfigurableAccount::InvalidConfig {}.abi_encode();
    let member = signer(2).address();
    let base = Fixture::new().upgraded(1, owner_set(vec![member]));
    let upgrade = Fixture::upgrade(&base);
    let zero_threshold = ConfigurableAccountConfig {
        threshold: 0,
        ..base.clone()
    };
    let delegate = Address::repeat_byte(0x74);

    // 1: the call must be the transaction's only call, however the account signs.
    expect_revert(
        Fixture::new(),
        "upgrade then call",
        |f| f.primitive(3, vec![upgrade.clone(), f.getter()]).into(),
        &only_call,
    );
    expect_revert(
        Fixture::new(),
        "call then upgrade",
        |f| f.primitive(3, vec![f.getter(), upgrade.clone()]).into(),
        &only_call,
    );
    expect_revert(
        Fixture::new(),
        "nested call",
        |f| {
            let mut call = forwarder(f);
            call.input = upgrade.input.clone();
            f.primitive(3, vec![call]).into()
        },
        &only_call,
    );
    expect_revert(
        Fixture::new(),
        "type-4 authorization list",
        |f| {
            let authorizations = vec![authorization(&signer(5), Address::ZERO, 0)];
            type4(
                &f.owner,
                3,
                CONFIGURABLE_ACCOUNT_ADDRESS,
                upgrade.input.clone(),
                authorizations,
            )
        },
        &only_call,
    );
    expect_revert(
        Fixture::new(),
        "AA authorization list",
        |f| {
            let authorization = Authorization {
                chain_id: U256::ONE,
                address: Address::ZERO,
                nonce: 0,
            };
            let signature = signer(5)
                .sign_hash_sync(&authorization.signature_hash())
                .unwrap();
            f.sign_primitive(TempoTransaction {
                tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
                    authorization,
                    signature.into(),
                )],
                ..aa_tx(3, vec![upgrade.clone()])
            })
            .into()
        },
        &only_call,
    );
    expect_revert(
        Fixture::new(),
        "key authorization",
        |f| {
            let grant =
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, signer(6).address());
            let approval = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
            f.sign_primitive(TempoTransaction {
                key_authorization: Some(grant.into_signed(PrimitiveSignature::Secp256k1(approval))),
                ..aa_tx(3, vec![upgrade.clone()])
            })
            .into()
        },
        &only_call,
    );
    // 1 before 2: a batch is rejected before the signer is.
    expect_revert(
        Fixture::new(),
        "access key batch",
        |f| {
            let key = signer(6);
            grant_key(f, 3, &key, 0);
            keychain_tx(f, &key, 4, vec![upgrade.clone(), f.getter()]).into()
        },
        &only_call,
    );

    // 2: only a primitive root signature may migrate.
    expect_revert(
        Fixture::new(),
        "access key",
        |f| {
            let key = signer(6);
            grant_key(f, 3, &key, 0);
            keychain_tx(f, &key, 4, vec![upgrade.clone()]).into()
        },
        &root_required,
    );
    // 2 before 3: a delegated account with an access key.
    expect_revert(
        Fixture::new(),
        "delegated access key",
        |f| {
            set_delegation(f, 3, delegate);
            let key = signer(6);
            grant_key(f, 5, &key, 0);
            keychain_tx(f, &key, 6, vec![upgrade.clone()]).into()
        },
        &root_required,
    );

    // 3: an account with code, here a 7702 delegation.
    expect_revert(
        Fixture::new(),
        "delegated account",
        |f| {
            set_delegation(f, 3, delegate);
            f.primitive(5, vec![upgrade.clone()]).into()
        },
        &has_code,
    );
    // 3 before 5: the invalid configuration is not reached.
    expect_revert(
        Fixture::new(),
        "delegated account, invalid configuration",
        |f| {
            set_delegation(f, 3, delegate);
            f.primitive(5, vec![Fixture::upgrade(&zero_threshold)])
                .into()
        },
        &has_code,
    );

    // 5: every invalid configuration is the same error, not the fine-grained ones.
    let heavy = (1..=49).map(Address::with_last_byte).collect::<Vec<_>>();
    let sorted = owner_set(vec![member, signer(3).address()]);
    let invalid = [
        ("zero threshold", zero_threshold),
        (
            "threshold above total weight",
            ConfigurableAccountConfig {
                threshold: 2,
                ..base.clone()
            },
        ),
        (
            "no owners",
            ConfigurableAccountConfig {
                owners: vec![],
                ..base.clone()
            },
        ),
        (
            "too many owners",
            ConfigurableAccountConfig {
                owners: owner_set(heavy),
                ..base.clone()
            },
        ),
        (
            "zero weight",
            ConfigurableAccountConfig {
                owners: vec![ConfigurableAccountOwner {
                    owner: member,
                    weight: 0,
                }],
                ..base.clone()
            },
        ),
        (
            "zero owner",
            ConfigurableAccountConfig {
                owners: vec![ConfigurableAccountOwner {
                    owner: Address::ZERO,
                    weight: 1,
                }],
                ..base.clone()
            },
        ),
        (
            "duplicate owner",
            ConfigurableAccountConfig {
                owners: vec![sorted[0].clone(), sorted[0].clone()],
                ..base.clone()
            },
        ),
        (
            "unsorted owners",
            ConfigurableAccountConfig {
                owners: vec![sorted[1].clone(), sorted[0].clone()],
                ..base.clone()
            },
        ),
        (
            "total weight above 255",
            ConfigurableAccountConfig {
                owners: vec![
                    ConfigurableAccountOwner {
                        weight: 200,
                        ..sorted[0].clone()
                    },
                    ConfigurableAccountOwner {
                        weight: 100,
                        ..sorted[1].clone()
                    },
                ],
                ..base
            },
        ),
    ];
    for (label, config) in &invalid {
        expect_revert(
            Fixture::new(),
            label,
            |f| f.primitive(3, vec![Fixture::upgrade(config)]).into(),
            &invalid_config,
        );
    }
}

#[test]
fn eoa_migration_after_delegation_cleared() {
    let mut f = Fixture::new();
    let config = f.upgraded(1, owner_set(vec![signer(2).address()]));
    let tx = f.primitive(5, vec![Fixture::upgrade(&config)]);
    set_delegation(&mut f, 3, Address::repeat_byte(0x74));
    let result = f.run(&tx);
    assert_eq!(
        result.output,
        IConfigurableAccount::AccountHasCode {}.abi_encode()
    );
    assert_eq!(f.commitment(), B256::ZERO);

    // An earlier transaction clearing the delegation makes the account eligible again.
    set_delegation(&mut f, 6, Address::ZERO);
    let info = f.info(f.account).unwrap();
    assert_eq!(info.code_hash, KECCAK256_EMPTY);
    assert_eq!(info.nonce, 8);
    let tx = f.primitive(8, vec![Fixture::upgrade(&config)]);
    let result = f.run(&tx);
    assert_upgraded(&mut f, &result, &config);
}

#[test]
fn eoa_migration_failure_keeps_fee_and_nonce() {
    let member = signer(2).address();
    let base = Fixture::new().upgraded(1, owner_set(vec![member]));
    let zero_threshold = ConfigurableAccountConfig {
        threshold: 0,
        ..base.clone()
    };
    for batch in [false, true] {
        let (label, error) = if batch {
            (
                "batch",
                IConfigurableAccount::UpgradeMustBeOnlyCall {}.abi_encode(),
            )
        } else {
            (
                "invalid configuration",
                IConfigurableAccount::InvalidConfig {}.abi_encode(),
            )
        };
        let mut f = Fixture::new();
        let account = f.account;
        fund(&mut f, account, 50_000_000);
        let config = if batch { &base } else { &zero_threshold };
        let mut calls = vec![Fixture::upgrade(config)];
        if batch {
            calls.push(f.getter());
        }
        let tx = f.sign_primitive(TempoTransaction {
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            fee_token: Some(PATH_USD_ADDRESS),
            ..aa_tx(3, calls)
        });
        let result = f.run(&tx);
        assert!(result.stop.is_revert(), "{label}: {result:?}");
        assert_eq!(result.output, error, "{label}");
        assert!(configurable_account_logs(&result).is_empty(), "{label}");
        let fee = calc_gas_balance_spending(result.tx_gas_used(), 1);
        assert!(fee > U256::ZERO, "{label}");
        assert_eq!(
            balance(&mut f, account),
            U256::from(50_000_000) - fee,
            "{label}"
        );
        assert_eq!(f.commitment(), B256::ZERO, "{label}");
        assert_eq!(
            f.info(account).unwrap().code_hash,
            KECCAK256_EMPTY,
            "{label}"
        );
        assert_eq!(f.info(account).unwrap().nonce, 4, "{label}");
    }
}

#[test]
fn eoa_migration_gas_schedule() {
    let members = owner_set(vec![
        signer(2).address(),
        signer(3).address(),
        signer(4).address(),
    ]);
    let params = tempo_gas_params(TempoHardfork::T14);
    // Pinned totals: (owners, gas_used). Legacy and AA primitive transactions cost the same.
    let pins = [(1, 275_598), (3, 277_770)];
    for (count, expected) in pins {
        for kind in [RootTx::Legacy, RootTx::Aa] {
            let mut f = Fixture::new();
            let config = f.upgraded(1, members[..count].to_vec());
            let call = Fixture::upgrade(&config);
            let tx = root_tx(&f, kind, 3, call.clone());
            let result = f.run(&tx);
            assert!(result.status, "{result:?}");

            // Intrinsic: 21000 plus 4 per zero and 16 per non-zero calldata byte.
            let intrinsic = 21_000
                + call
                    .input
                    .iter()
                    .map(|b| if *b == 0 { 4 } else { 16 })
                    .sum::<u64>();
            // The precompile charges, in order: ABI input, the origin TLOAD, the eligibility
            // TLOAD, the account access for X, the 42-byte salt preimage hash, the commitment
            // preimage hash, the zero to non-zero commitment write, and LOG3 with the ABI-encoded
            // data (salt, threshold, owners).
            let input = 30 * (call.input.len() as u64).div_ceil(32);
            let salt = keccak_cost(CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN.len() + 20).unwrap();
            let commitment =
                keccak_cost(CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN.len() + 32 + 8 + 2 + count * 21)
                    .unwrap();
            let warm_read = params.get(GasId::WarmStorageReadCost);
            let origin = warm_read;
            let tload = warm_read;
            let account_access = warm_read;
            let write = params.get(GasId::NewAccountCost);
            let log_data = (4 + count as u64 * 2) * 32;
            let log = 375 + 3 * 375 + 8 * log_data;
            let components = intrinsic
                + input
                + origin
                + salt
                + commitment
                + tload
                + account_access
                + write
                + log;
            assert_eq!(
                components, expected,
                "{count} owners, {kind:?}: component sum"
            );
            assert_eq!(result.tx_gas_used(), expected, "{count} owners, {kind:?}");
        }
    }
}

/// Gas of `upgradeAccount` from `sender` on `lane`, paid by the sender or by a fee sponsor, with
/// TIP-1016's state gas split on or off.
fn sender_upgrade_gas(
    lane: NonceLane,
    sender: UpgradeSender,
    sponsored: bool,
    state_gas_split: bool,
) -> BlockGas {
    let mut f = Fixture::with_cfg(TempoHardfork::T14, |cfg| {
        if state_gas_split {
            cfg.features.insert(EvmFeatures::EIP8037);
            for (id, cost) in SPLIT_NEW_ACCOUNT_COST {
                cfg.gas_params.set(id, cost);
            }
        }
    });
    let account = f.account;
    match sender {
        UpgradeSender::Empty => seed_account(&mut f, account, true),
        UpgradeSender::Funded => seed_account(&mut f, account, false),
        UpgradeSender::Settled => {}
    }
    let config = f.upgraded(1, owner_set(vec![signer(2).address()]));
    let mut tx = lane_tx(&mut f, lane, vec![Fixture::upgrade(&config)]);
    if matches!(sender, UpgradeSender::Settled) {
        tx.nonce = 3;
    }
    if sponsored {
        let sponsor = signer(9);
        fund(&mut f, sponsor.address(), 50_000_000);
        tx.max_fee_per_gas = 1;
        tx.fee_token = Some(PATH_USD_ADDRESS);
        tx.fee_payer_signature = Some(
            sponsor
                .sign_hash_sync(&tx.fee_payer_signature_hash(account))
                .unwrap(),
        );
    }
    let tx = f.sign_primitive(tx);
    let gas = block_gas(&mut f, &tx);
    assert_eq!(f.commitment(), config.commitment().unwrap());
    gas
}

#[test]
fn eoa_migration_charges_the_new_account_cost_once_for_every_nonce_type() {
    for state_gas_split in [false, true] {
        let new_account = if state_gas_split {
            BlockGas {
                regular: u64::from(SPLIT_NEW_ACCOUNT_COST[0].1),
                state: u64::from(SPLIT_NEW_ACCOUNT_COST[1].1),
            }
        } else {
            let params = tempo_gas_params(TempoHardfork::T14);
            BlockGas {
                regular: params.get(GasId::NewAccountCost),
                state: params.new_account_state_gas(),
            }
        };
        for lane in [
            NonceLane::Protocol,
            NonceLane::ProtocolSimulated,
            NonceLane::TwoD,
            NonceLane::Expiring,
        ] {
            for sponsored in [false, true] {
                // The `nonce == 0` charge covers the protocol lane's sender, which the nonce
                // write creates before the call, and the nonce-key slot of a 2D lane. The
                // expiring lane pays its replay-protection storage instead. A simulated
                // protocol lane has no such charge.
                let lane_gas = match lane {
                    NonceLane::Protocol | NonceLane::TwoD => new_account,
                    NonceLane::ProtocolSimulated => BlockGas {
                        regular: 0,
                        state: 0,
                    },
                    NonceLane::Expiring => BlockGas {
                        regular: EXPIRING_NONCE_GAS,
                        state: 0,
                    },
                };
                // Only the 2D and expiring lanes leave the sender empty when `upgradeAccount`
                // commits, so only there does the upgrade pay the creation. The simulated
                // protocol lane's nonce write creates the sender all the same. As for
                // registration, the state part counts as block state gas.
                let upgrade_gas = match lane {
                    NonceLane::Protocol | NonceLane::ProtocolSimulated => BlockGas {
                        regular: 0,
                        state: 0,
                    },
                    NonceLane::TwoD | NonceLane::Expiring => new_account,
                };
                let label =
                    format!("{lane:?}, sponsored: {sponsored}, state gas split: {state_gas_split}");
                // A sender at nonce 3 pays no lane charge and has no creation to pay.
                let settled = sender_upgrade_gas(
                    NonceLane::Protocol,
                    UpgradeSender::Settled,
                    sponsored,
                    state_gas_split,
                );
                let funded =
                    sender_upgrade_gas(lane, UpgradeSender::Funded, sponsored, state_gas_split);
                assert_eq!(funded, settled.plus(lane_gas), "funded sender, {label}");
                let empty =
                    sender_upgrade_gas(lane, UpgradeSender::Empty, sponsored, state_gas_split);
                assert_eq!(empty, funded.plus(upgrade_gas), "empty sender, {label}");
            }
        }
    }
}

#[test]
fn eoa_migration_preserves_account_state() {
    let mut f = Fixture::new();
    let account = f.account;
    let spender = signer(7).address();
    let keys = [signer(11), signer(12), signer(13)];
    fund(&mut f, account, 50_000_000);

    // Allowance, then an ordinary, a revoked and an expiring access key.
    let approve = Call {
        to: TxKind::Call(PATH_USD_ADDRESS),
        value: U256::ZERO,
        input: ITIP20::approveCall {
            spender,
            amount: U256::from(77),
        }
        .abi_encode()
        .into(),
    };
    let tx = f.primitive(3, vec![approve]);
    assert!(f.run(&tx).status);
    grant_key(&mut f, 4, &keys[0], 0);
    grant_key(&mut f, 5, &keys[1], 0);
    let revoke = Call {
        to: TxKind::Call(ACCOUNT_KEYCHAIN_ADDRESS),
        value: U256::ZERO,
        input: IAccountKeychain::revokeKeyCall {
            keyId: keys[1].address(),
        }
        .abi_encode()
        .into(),
    };
    let tx = f.primitive(6, vec![revoke]);
    assert!(f.run(&tx).status);
    grant_key(&mut f, 7, &keys[2], 1000);
    f.update_block(|block| block.timestamp = U256::from(2000));
    // A used 2D nonce lane; the nonce manager needs its precompile account to persist.
    in_storage_ctx(&mut f.evm, || NonceManager::new().initialize()).unwrap();
    let lane = U256::from(5);
    let tx = f.sign_primitive(TempoTransaction {
        nonce_key: lane,
        ..aa_tx(0, vec![f.getter()])
    });
    assert!(f.run(&tx).status);

    let snapshot = |f: &mut Fixture| {
        in_storage_ctx(&mut f.evm, || {
            let token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
            let keychain = AccountKeychain::new();
            Ok::<_, TempoPrecompileError>(AccountSnapshot {
                balance: token.balance_of(ITIP20::balanceOfCall { account })?,
                allowance: token.allowance(ITIP20::allowanceCall {
                    owner: account,
                    spender,
                })?,
                keys: keys
                    .iter()
                    .map(|key| {
                        keychain.get_key(IAccountKeychain::getKeyCall {
                            account,
                            keyId: key.address(),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                nonce: NonceManager::new().get_nonce(INonce::getNonceCall {
                    account,
                    nonceKey: lane,
                })?,
            })
        })
        .unwrap()
    };
    let before = snapshot(&mut f);
    assert_eq!(before.allowance, U256::from(77));
    assert_eq!(before.nonce, 1);

    let config = migrate(&mut f, 8, signer(2).address());
    assert_eq!(snapshot(&mut f), before);
    assert_eq!(f.info(account).unwrap().nonce, 9);

    // The access key still cannot rotate the migrated account or migrate it again.
    let next = ConfigurableAccountConfig {
        version: 2,
        ..config.clone()
    };
    let mut rejected = |nonce, call, error: Vec<u8>| {
        let tx = keychain_tx(&f, &keys[0], nonce, vec![call]);
        let result = f.run(&tx);
        assert_eq!(&result.output, &error);
    };
    rejected(
        9,
        Fixture::rotation(&config, &next),
        IConfigurableAccount::UnauthorizedConfigurableAccountCaller {}.abi_encode(),
    );
    rejected(
        10,
        Fixture::upgrade(&config),
        IConfigurableAccount::PrimitiveRootRequired {}.abi_encode(),
    );
    assert_eq!(f.commitment(), config.commitment().unwrap());
}

#[test]
fn eoa_migration_inactive_before_t14() {
    let mut f = Fixture::with_spec(TempoHardfork::T13);
    let config = f.upgraded(1, owner_set(vec![signer(2).address()]));
    for (nonce, kind) in [(3, RootTx::Legacy), (4, RootTx::Aa)] {
        // The call reaches an empty account: it succeeds without state or logs.
        let tx = root_tx(&f, kind, nonce, Fixture::upgrade(&config));
        let result = f.run(&tx);
        assert!(result.status, "{kind:?}: {result:?}");
        assert!(result.output.is_empty(), "{kind:?}");
        assert!(result.logs.is_empty(), "{kind:?}");
        assert_eq!(f.commitment(), B256::ZERO, "{kind:?}");
        assert_eq!(f.info(f.account).unwrap().nonce, nonce + 1);
    }
}
