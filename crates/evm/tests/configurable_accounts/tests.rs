use super::*;
use alloy_consensus::{Header, SignableTransaction, TxEip1559, TxEip2930, TxEip7702, TxLegacy};
use alloy_eips::{
    eip2930::{AccessList, AccessListItem},
    eip7702::{Authorization, SignedAuthorization},
};
use alloy_primitives::{Bytes, KECCAK256_EMPTY, LogData, aliases::U96, bytes, keccak256};
use alloy_sol_types::{SolError, SolEvent, SolValue};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use evm2::{
    EvmFeatures,
    evm::{DynDatabase, registry::HandlerError},
    interpreter::InstrStop,
    version::{GasId, GasParams},
};
use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use reth_chainspec::EthChainSpec;
use reth_ethereum_primitives::Block as EthereumBlock;
use reth_evm::{BlockExecutor, ConfigureEvm};
use reth_execution_types::{BundleSource, ExecutionOutcome};
use reth_primitives_traits::{Block as _, SignedTransaction};
use reth_provider::{
    BlockExecutionWriter, BlockWriter, OriginalValuesKnown, StateWriter, TrieWriter,
    providers::BlockchainProvider, test_utils::create_test_provider_factory,
};
use reth_stages::{MerkleCheckpoint, StorageRootMerkleCheckpoint, stages::MerkleStage};
use reth_storage_api::{
    AccountReader, ChangeSetReader, DBProvider, HistoryWriter, StateProviderFactory,
    StateRootProvider, StateWriteConfig, StorageSettingsCache,
};
use reth_trie::{HashedPostState, KeccakKeyHasher, StateRoot, StateRootProgress, StoredSubNode};
use reth_trie_db::{
    DatabaseHashedCursorFactory, DatabaseStateRoot, DatabaseTrieCursorFactory, with_adapter,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{num::NonZeroU64, sync::Arc};
use tempo_chainspec::{TempoChainSpec, spec::DEV};
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, AccountKeychainError, ISignatureVerifier, ITIP20ChannelReserve,
    PATH_USD_ADDRESS, SIGNATURE_VERIFIER_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS,
    ZONE_PORTAL_PREFIX, account_keychain::IAccountKeychain,
    configurable_account::IConfigurableAccountShim, nonce::INonce, tip20::ITIP20,
};
use tempo_evm::{
    TempoEvmConfig, TempoInvalidTransaction,
    transaction_error::{ConfigurableAccountError, FeePaymentError, RootKeyRole},
};
use tempo_precompiles::{
    Precompile,
    configurable_account::{CONFIGURABLE_ACCOUNT_CODE, CONFIGURABLE_ACCOUNT_CODE_HASH, shim},
    error::TempoPrecompileError,
    input_cost,
    nonce::NonceManager,
    signature_verifier::SignatureVerifier,
    storage::keccak_cost,
    tip20::{PERMIT_TYPEHASH, TIP20Token},
    tip20_channel_reserve::TIP20ChannelReserve,
};
use tempo_primitives::{
    Block as TempoBlock, SignatureType, TempoHeader, TempoTxEnvelope,
    account::encode_config_commitment,
    transaction::{
        CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN, ConfigurableAccountQuorumError,
        ConfigurableAccountStateError, KeyAuthorization, KeychainSignature, SignedKeyAuthorization,
        TEMPO_EXPIRING_NONCE_KEY, TempoSignedAuthorization, TokenLimit, calc_gas_balance_spending,
        derive_p256_address,
        tt_signature::{P256SignatureWithPreHash, WebAuthnSignature, normalize_p256_s},
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

/// A call target that touches `account`'s code size: its gas shows whether the account is warm.
const PROBE: Address = Address::repeat_byte(0x99);

/// The nonce, the 7702 delegation target (`None` without code) and whether the account's
/// configuration commitment is set.
#[derive(Debug, PartialEq, Eq)]
struct AccountState {
    nonce: u64,
    delegation: Option<Address>,
    retired: bool,
}

/// An account seeded with `nonce`, and the `entries` that precede the fresh authority in the
/// list.
struct ListVariant {
    name: &'static str,
    nonce: u64,
    entries: Vec<Entry>,
}

#[derive(Clone, Copy, Debug)]
enum SigKind {
    Secp256k1,
    P256,
    WebAuthn,
    /// The secp256k1 key signing as an access key of its own address, which it names as the
    /// authority.
    Keychain,
}

/// One authorization-list entry: the authority is derived from `kind` and `seed`.
#[derive(Clone, Copy, Debug)]
struct Entry {
    kind: SigKind,
    seed: u8,
    chain_id: u64,
    target: Address,
    nonce: u64,
}

impl Entry {
    fn new(kind: SigKind, seed: u8, target: Address, nonce: u64) -> Self {
        Self {
            kind,
            seed,
            chain_id: 1,
            target,
            nonce,
        }
    }

    fn authorization(&self) -> Authorization {
        Authorization {
            chain_id: U256::from(self.chain_id),
            address: self.target,
            nonce: self.nonce,
        }
    }

    fn address(&self) -> Address {
        self.sign().0
    }

    /// The authority and the entry signed by it with its own key type.
    fn sign(&self) -> (Address, TempoSignedAuthorization) {
        let authorization = self.authorization();
        let hash = authorization.signature_hash();
        let (address, signature) = match self.kind {
            SigKind::Secp256k1 => {
                let key = signer(self.seed);
                let signature = key.sign_hash_sync(&hash).unwrap();
                (key.address(), TempoSignature::from(signature))
            }
            SigKind::Keychain => {
                let key = signer(self.seed);
                let signature = key
                    .sign_hash_sync(&KeychainSignature::signing_hash(hash, key.address()))
                    .unwrap();
                (
                    key.address(),
                    TempoSignature::Keychain(KeychainSignature::new(
                        key.address(),
                        PrimitiveSignature::Secp256k1(signature),
                    )),
                )
            }
            SigKind::P256 | SigKind::WebAuthn => {
                let (address, primitive) = p256_primitive(self.kind, self.seed, hash);
                (address, TempoSignature::Primitive(primitive))
            }
        };
        (
            address,
            TempoSignedAuthorization::new_unchecked(authorization, signature),
        )
    }

    /// The entry as an EIP-7702 authorization, which only a secp256k1 authority can sign.
    fn legacy(&self) -> SignedAuthorization {
        assert!(matches!(self.kind, SigKind::Secp256k1), "{self:?}");
        let authorization = self.authorization();
        let signature = signer(self.seed)
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap();
        authorization.into_signed(signature)
    }
}

/// The key kinds a keychain signature can carry: its inner signature is a primitive one.
const KEY_KINDS: [SigKind; 3] = [SigKind::P256, SigKind::WebAuthn, SigKind::Secp256k1];

/// Settled amount, deposit and close request of the channel, with the balances of its payee and
/// payer and of the precompile that holds the deposit.
#[derive(Debug, PartialEq, Eq)]
struct ChannelSnapshot {
    settled: U96,
    deposit: U96,
    close_requested_at: u32,
    payee_balance: U256,
    payer_balance: U256,
    reserve_balance: U256,
}

/// An open path USD channel and its identity.
struct Opened {
    id: B256,
    descriptor: ITIP20ChannelReserve::ChannelDescriptor,
}

#[derive(Clone, Copy, Debug)]
enum Redeem {
    Settle,
    Close,
}

impl Redeem {
    /// The payee's call redeeming `amount` of the channel with `signature`.
    fn call(self, channel: &Opened, amount: u64, signature: Bytes) -> Call {
        let descriptor = channel.descriptor.clone();
        let cumulative_amount = U96::from(amount);
        let input = match self {
            Self::Settle => ITIP20ChannelReserve::settleCall {
                descriptor,
                cumulativeAmount: cumulative_amount,
                signature,
            }
            .abi_encode(),
            Self::Close => ITIP20ChannelReserve::closeCall {
                descriptor,
                cumulativeAmount: cumulative_amount,
                captureAmount: cumulative_amount,
                signature,
            }
            .abi_encode(),
        };
        Call {
            to: TxKind::Call(TIP20_CHANNEL_RESERVE_ADDRESS),
            value: U256::ZERO,
            input: input.into(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum SignedAction {
    Permit,
    Redeem(Redeem),
}

#[derive(Clone, Copy, Debug)]
enum Verifier {
    Keychain,
    KeychainAdmin,
    ConfigurableAccount,
}

impl Verifier {
    fn call(self, account: Address, hash: B256, signature: Bytes) -> Call {
        let input = match self {
            Self::Keychain => ISignatureVerifier::verifyKeychainCall {
                account,
                hash,
                signature,
            }
            .abi_encode(),
            Self::KeychainAdmin => ISignatureVerifier::verifyKeychainAdminCall {
                account,
                hash,
                signature,
            }
            .abi_encode(),
            Self::ConfigurableAccount => ISignatureVerifier::verifyConfigurableAccountCall {
                account,
                hash,
                signature,
            }
            .abi_encode(),
        };
        Call {
            to: TxKind::Call(SIGNATURE_VERIFIER_ADDRESS),
            value: U256::ZERO,
            input: input.into(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum KeychainCheck {
    VerifyAccessKey,
    VerifyAdminRoot,
    IsAdminRoot,
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
            let mut f = Fixture::with_parent(false);
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
    let mut f = Fixture::with_parent(false);
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
    let base = Fixture::with_parent(false).upgraded(1, owner_set(vec![member]));
    let upgrade = Fixture::upgrade(&base);
    let zero_threshold = ConfigurableAccountConfig {
        threshold: 0,
        ..base.clone()
    };
    let delegate = Address::repeat_byte(0x74);

    // 1: the call must be the transaction's only call, however the account signs.
    expect_revert(
        Fixture::with_parent(false),
        "upgrade then call",
        |f| f.primitive(3, vec![upgrade.clone(), f.getter()]).into(),
        &only_call,
    );
    expect_revert(
        Fixture::with_parent(false),
        "call then upgrade",
        |f| f.primitive(3, vec![f.getter(), upgrade.clone()]).into(),
        &only_call,
    );
    expect_revert(
        Fixture::with_parent(false),
        "nested call",
        |f| {
            let mut call = forwarder(f);
            call.input = upgrade.input.clone();
            f.primitive(3, vec![call]).into()
        },
        &only_call,
    );
    expect_revert(
        Fixture::with_parent(false),
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
        Fixture::with_parent(false),
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
        Fixture::with_parent(false),
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
        Fixture::with_parent(false),
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
        Fixture::with_parent(false),
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
        Fixture::with_parent(false),
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
        Fixture::with_parent(false),
        "delegated account",
        |f| {
            set_delegation(f, 3, delegate);
            f.primitive(5, vec![upgrade.clone()]).into()
        },
        &has_code,
    );
    // 3 before 5: the invalid configuration is not reached.
    expect_revert(
        Fixture::with_parent(false),
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
            Fixture::with_parent(false),
            label,
            |f| f.primitive(3, vec![Fixture::upgrade(config)]).into(),
            &invalid_config,
        );
    }
}

#[test]
fn eoa_migration_after_delegation_cleared() {
    let mut f = Fixture::with_parent(false);
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
    let base = Fixture::with_parent(false).upgraded(1, owner_set(vec![member]));
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
        let mut f = Fixture::with_parent(false);
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
            let mut f = Fixture::with_parent(false);
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
    let mut f = Fixture::with_cfg(false, TempoHardfork::T14, |cfg| {
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
    let mut f = Fixture::with_parent(false);
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
    let mut f = Fixture::with_spec(false, TempoHardfork::T13);
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

/// Seeds retirement, adding the protocol marker to code-free T14 accounts.
/// Existing incompatible code is preserved for tests of corrupted account states.
fn retire(f: &mut Fixture, account: Address) {
    let mut info = f
        .info(account)
        .unwrap_or_else(|| AccountInfo::default().with_balance(U256::ZERO));
    info.extension = encode_config_commitment(B256::repeat_byte(0x77)).into();
    if f.evm.config_spec_id().is_t14() && info.code_hash == KECCAK256_EMPTY {
        info = info.with_code(Bytecode::new_raw(CONFIGURABLE_ACCOUNT_CODE));
    }
    f.evm.overlay_db_mut().insert_account_info(&account, info);
}

/// Migrates the primitive account `key`, which is not the fixture's account, with
/// `upgradeAccount` to a configuration owned by `owner`.
fn migrate_key(
    f: &mut Fixture,
    key: &PrivateKeySigner,
    nonce: u64,
    owner: &PrivateKeySigner,
) -> ConfigurableAccountConfig {
    let config = ConfigurableAccountConfig {
        salt: keccak256(
            [
                CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN,
                key.address().as_slice(),
            ]
            .concat(),
        ),
        version: 1,
        threshold: 1,
        owners: owner_set(vec![owner.address()]),
    };
    let tx = aa_tx(nonce, vec![Fixture::upgrade(&config)]);
    let signature = key.sign_hash_sync(&tx.signature_hash()).unwrap();
    let result = f.run_as(key.address(), &tx.into_signed(signature.into()));
    assert!(result.status, "{result:?}");
    let info = f.info(key.address()).unwrap();
    assert_eq!(
        decode_config_commitment(&info.extension, TempoHardfork::T14).unwrap(),
        config.commitment().unwrap()
    );
    config
}

/// `tx` signed as an access key of `parent` by the configurable account `delegate`, whose owner
/// quorum under `config` is `owner`.
fn delegate_keychain_signed(
    tx: TempoTransaction,
    parent: Address,
    delegate: Address,
    config: &ConfigurableAccountConfig,
    owner: &PrivateKeySigner,
) -> AASigned {
    let digest = KeychainSignature::signing_hash(tx.signature_hash(), parent);
    tx.into_signed(TempoSignature::Keychain(KeychainSignature::new(
        parent,
        configurable_account_approval(delegate, config, owner, digest),
    )))
}

/// A transaction of the fixture's account, signed by its root, that grants `key` as `key_type`.
fn grant_tx(f: &Fixture, nonce: u64, key_type: SignatureType, key: Address) -> AASigned {
    let grant = KeyAuthorization::unrestricted(1, key_type, key);
    let signature = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
    f.sign_primitive(TempoTransaction {
        key_authorization: Some(grant.into_signed(PrimitiveSignature::Secp256k1(signature))),
        ..aa_tx(nonce, vec![f.getter()])
    })
}

/// The keychain's rejection of a `signature` type for a key stored as `stored`.
fn type_mismatch(stored: SignatureType, signature: SignatureType) -> TempoInvalidTransaction {
    let error = TempoPrecompileError::from(AccountKeychainError::signature_type_mismatch(
        stored.into(),
        signature.into(),
    ));
    TempoInvalidTransaction::KeychainValidationFailed {
        reason: format!("{error:?}"),
    }
}

/// The environment of `tx` sent by `sender`, optionally as a plain RPC simulation request.
fn env_of<T>(tx: &T, sender: Address, simulation: bool) -> Recovered<TempoTxEnv>
where
    T: Clone + Into<TempoTxEnvelope>,
{
    if simulation {
        simulation_env(tx, sender, None)
    } else {
        tx_env(tx, sender)
    }
}

/// The RPC simulation environment of `tx` sent by `sender`, whose key ID `key_id` overrides.
fn simulation_env<T>(tx: &T, sender: Address, key_id: Option<Address>) -> Recovered<TempoTxEnv>
where
    T: Clone + Into<TempoTxEnvelope>,
{
    let env = tx_env(tx, sender).into_inner();
    let unique_tx_identifier = env.unique_tx_identifier();
    Recovered::new_unchecked(
        env.with_simulation_overrides(unique_tx_identifier, None, key_id),
        sender,
    )
}

/// The handler error that executing `env` fails with.
fn transact_err(f: &mut Fixture, env: &Recovered<TempoTxEnv>) -> HandlerError {
    match f.evm.transact(env) {
        Err(error) => error,
        Ok(executed) => panic!("expected a validation error, got {:?}", executed.discard()),
    }
}

/// The handler error `tx` fails with when sent by `sender`.
fn handler_rejection<T>(f: &mut Fixture, tx: &T, sender: Address) -> HandlerError
where
    T: Clone + Into<TempoTxEnvelope>,
{
    transact_err(f, &env_of(tx, sender, false))
}

/// The Tempo validation error `tx` fails with when sent by `sender`.
fn rejection<T>(f: &mut Fixture, tx: &T, sender: Address) -> TempoInvalidTransaction
where
    T: Clone + Into<TempoTxEnvelope>,
{
    let error = handler_rejection(f, tx, sender);
    error
        .external_ref::<TempoInvalidTransaction>()
        .cloned()
        .unwrap_or_else(|| panic!("expected a Tempo validation error, got {error:?}"))
}

fn retired(account: Address, role: RootKeyRole) -> TempoInvalidTransaction {
    TempoInvalidTransaction::RootKeyRetired { account, role }
}

/// `tx` with `payer` as its fee payer, for sender `sender`.
fn sponsored(
    mut tx: TempoTransaction,
    payer: &PrivateKeySigner,
    sender: Address,
) -> TempoTransaction {
    tx.fee_payer_signature = Some(
        payer
            .sign_hash_sync(&tx.fee_payer_signature_hash(sender))
            .unwrap(),
    );
    tx
}

/// A grant of `key` for the account, signed by `signer`.
fn grant_by(signer: &PrivateKeySigner, key: Address) -> SignedKeyAuthorization {
    let grant = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key);
    let signature = signer.sign_hash_sync(&grant.signature_hash()).unwrap();
    grant.into_signed(PrimitiveSignature::Secp256k1(signature))
}

#[test]
fn retired_root_rejects_sender_signatures() {
    let other = signer(2).address();
    // A P256 and a WebAuthn signature are primitive too; only their type reaches validation.
    let p256 = PrimitiveSignature::from_bytes(&[&[0x01u8][..], &[0x11; 129][..]].concat()).unwrap();
    let webauthn =
        PrimitiveSignature::from_bytes(&[&[0x02u8][..], &[0x22; 37 + 20 + 128][..]].concat())
            .unwrap();
    for kind in [RootTx::Legacy, RootTx::Eip2930, RootTx::Eip1559, RootTx::Aa] {
        let mut f = Fixture::with_parent(false);
        // Before the migration the same signatures are accepted.
        let tx = root_tx(&f, kind, 3, f.getter());
        let result = f.run(&tx);
        assert!(result.status, "{kind:?}: {result:?}");
        migrate(&mut f, 4, other);
        let account = f.account;

        let tx = root_tx(&f, kind, 5, f.getter());
        let error = rejection(&mut f, &tx, account);
        assert_eq!(error, retired(account, RootKeyRole::Sender), "{kind:?}");
        assert!(!error.is_bad_transaction(), "{kind:?}");
        // A repeated migration is a root-signed transaction like any other.
        let again = f.upgraded(1, owner_set(vec![signer(3).address()]));
        let tx = root_tx(&f, kind, 5, Fixture::upgrade(&again));
        assert_eq!(
            rejection(&mut f, &tx, account),
            retired(account, RootKeyRole::Sender),
            "{kind:?}"
        );
        assert_eq!(
            f.commitment(),
            f.upgraded(1, owner_set(vec![other])).commitment().unwrap()
        );
        assert_eq!(f.info(account).unwrap().nonce, 5);
    }

    let mut f = Fixture::with_parent(false);
    migrate(&mut f, 3, other);
    let account = f.account;
    let expected = retired(account, RootKeyRole::Sender);
    // EIP-7702, a 2D nonce lane, and the other primitive signature types.
    let tx = type4(
        &f.owner,
        4,
        other,
        Bytes::new(),
        vec![authorization(&f.owner, other, 5)],
    );
    assert_eq!(rejection(&mut f, &tx, account), expected);
    let lane = TempoTransaction {
        nonce_key: U256::ONE,
        ..aa_tx(0, vec![f.getter()])
    };
    let tx = f.sign_primitive(lane);
    assert_eq!(rejection(&mut f, &tx, account), expected);
    for signature in [p256, webauthn] {
        let tx = aa_tx(4, vec![f.getter()]).into_signed(TempoSignature::Primitive(signature));
        assert_eq!(rejection(&mut f, &tx, account), expected);
    }

    // A plain RPC simulation does not check the sender.
    let tx = f.primitive(4, vec![f.getter()]);
    let output = f
        .evm
        .transact(&env_of(&tx, account, true))
        .unwrap()
        .detach();
    assert!(output.result.status, "{:?}", output.result);
    // A signed transaction, the only other origin, is not a simulation: the sender is checked.
    let error = transact_err(&mut f, &env_of(&tx, account, false));
    assert!(
        error.external_ref::<TempoInvalidTransaction>() == Some(&expected),
        "{error:?}"
    );

    // The retirement starts at T14: the same state is accepted before it.
    let mut before = Fixture::with_spec(false, TempoHardfork::T13);
    let account = before.account;
    retire(&mut before, account);
    let tx = before.primitive(3, vec![before.getter()]);
    let result = before.run(&tx);
    assert!(result.status, "{result:?}");
}

#[test]
fn retired_root_rejects_delegated_roles() {
    let new_key = signer(7);
    let other = signer(2).address();

    // The bootstrap flow, a root-signed grant used by the new key in the same
    // transaction, is accepted before the migration and rejected after it.
    for migrated in [false, true] {
        let mut f = Fixture::with_parent(false);
        if migrated {
            migrate(&mut f, 3, other);
        }
        let nonce = if migrated { 4 } else { 3 };
        let account = f.account;
        let tx = TempoTransaction {
            key_authorization: Some(grant_by(&f.owner, new_key.address())),
            ..aa_tx(nonce, vec![f.getter()])
        };
        let tx = keychain_signed(tx, &new_key, account);
        if migrated {
            assert_eq!(
                rejection(&mut f, &tx, account),
                retired(account, RootKeyRole::KeyAuthorizationSigner)
            );
        } else {
            let result = f.run(&tx);
            assert!(result.status, "{result:?}");
        }
    }

    // A native transaction of the migrated account may not carry a grant signed by its
    // retired root; the configurable-account-signed grant is accepted (see the guard test).
    let mut f = Fixture::with_parent(false);
    let root = f.owner.address();
    f.config = migrate(&mut f, 3, root);
    let account = f.account;
    let tx = TempoTransaction {
        key_authorization: Some(grant_by(&f.owner, new_key.address())),
        ..aa_tx(4, vec![f.getter()])
    };
    let tx = configurable_account_signed(&f, tx);
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(account, RootKeyRole::KeyAuthorizationSigner)
    );

    // An access key that migrated can no longer sign transactions; its parent is not affected.
    let mut f = Fixture::with_parent(false);
    let key = signer(4);
    grant_key(&mut f, 3, &key, 0);
    let account = f.account;
    let tx = keychain_signed(aa_tx(4, vec![f.getter()]), &key, account);
    // Control: the access key still works while it has no commitment.
    let output = f
        .evm
        .transact(&env_of(&tx, account, false))
        .unwrap()
        .detach();
    assert!(output.result.status, "{:?}", output.result);
    retire(&mut f, key.address());
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(key.address(), RootKeyRole::AccessKey)
    );

    // A sponsor that migrates after signing can no longer pay, even for a transaction
    // it signed earlier.
    let mut f = Fixture::with_parent(false);
    let sponsor = signer(5);
    let account = f.account;
    let tx = sponsored(aa_tx(3, vec![f.getter()]), &sponsor, account);
    let tx = f.sign_primitive(tx);
    let output = f
        .evm
        .transact(&env_of(&tx, account, false))
        .unwrap()
        .detach();
    assert!(output.result.status, "{:?}", output.result);
    retire(&mut f, sponsor.address());
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(sponsor.address(), RootKeyRole::FeePayer)
    );
    // Simulation checks every role but the sender.
    let error = transact_err(&mut f, &env_of(&tx, account, true));
    assert!(
        error.external_ref::<TempoInvalidTransaction>()
            == Some(&retired(sponsor.address(), RootKeyRole::FeePayer)),
        "{error:?}"
    );

    // The treasury A granted the primitive key B an allowance of 100, then B migrates for real.
    let mut f = Fixture::with_parent(false);
    let key = signer(6);
    let new_owner = signer(8);
    let account = f.account;
    fund(&mut f, account, 1_000);
    let grant = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key.address())
        .with_limits(vec![TokenLimit {
            token: PATH_USD_ADDRESS,
            limit: U256::from(100),
            period: 0,
        }]);
    let approval = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
    let tx = f.sign_primitive(TempoTransaction {
        key_authorization: Some(grant.into_signed(PrimitiveSignature::Secp256k1(approval))),
        ..aa_tx(3, vec![f.getter()])
    });
    let result = f.run(&tx);
    assert!(result.status, "{result:?}");
    let remaining = |f: &mut Fixture| {
        in_storage_ctx(&mut f.evm, || {
            AccountKeychain::new().get_remaining_limit(IAccountKeychain::getRemainingLimitCall {
                account,
                keyId: key.address(),
                token: PATH_USD_ADDRESS,
            })
        })
        .unwrap()
    };
    let spend = |amount: u64| Call {
        to: TxKind::Call(PATH_USD_ADDRESS),
        value: U256::ZERO,
        input: ITIP20::transferCall {
            to: Address::repeat_byte(0x66),
            amount: U256::from(amount),
        }
        .abi_encode()
        .into(),
    };
    let tx = keychain_tx(&f, &key, 4, vec![spend(30)]);
    let result = f.run(&tx);
    assert!(result.status, "{result:?}");
    assert_eq!(remaining(&mut f), U256::from(70));

    seed_eoa(&mut f, key.address(), 0);
    let key_config = migrate_key(&mut f, &key, 0, &new_owner);

    // Its retired root no longer signs for A, whether recovered or named by a simulation.
    let tx = keychain_tx(&f, &key, 5, vec![spend(20)]);
    let expected = retired(key.address(), RootKeyRole::AccessKey);
    assert_eq!(rejection(&mut f, &tx, account), expected);
    let error = transact_err(&mut f, &simulation_env(&tx, account, Some(key.address())));
    assert!(
        error.external_ref::<TempoInvalidTransaction>() == Some(&expected),
        "{error:?}"
    );
    // The override also names the key when another key signed the request.
    let placeholder = keychain_tx(&f, &signer(7), 5, vec![f.getter()]);
    let error = transact_err(
        &mut f,
        &simulation_env(&placeholder, account, Some(key.address())),
    );
    assert!(
        error.external_ref::<TempoInvalidTransaction>() == Some(&expected),
        "{error:?}"
    );

    // Its owner quorum uses the same grant: the limit and the spent counter carry over.
    let tx = delegate_keychain_signed(
        aa_tx(5, vec![spend(20)]),
        account,
        key.address(),
        &key_config,
        &new_owner,
    );
    let result = f.run(&tx);
    assert!(result.status, "{result:?}");
    assert_eq!(remaining(&mut f), U256::from(50));

    // The treasury cannot register the migrated key ID again, as either type: the grant is
    // rejected as a reuse.
    for key_type in [SignatureType::Secp256k1, SignatureType::ConfigurableAccount] {
        let regrant = grant_tx(&f, 6, key_type, key.address());
        assert_eq!(
            rejection(&mut f, &regrant, account),
            TempoInvalidTransaction::KeychainPrecompileError {
                reason: TempoPrecompileError::from(AccountKeychainError::key_already_exists())
                    .to_string()
            },
            "{key_type:?}"
        );
    }

    // A primitive grant whose key ID has no commitment does not accept a quorum signature: its
    // delegate has not migrated.
    let unmigrated_owner = signer(9);
    let unmigrated_config = ConfigurableAccountConfig {
        salt: B256::repeat_byte(9),
        version: 0,
        threshold: 1,
        owners: owner_set(vec![unmigrated_owner.address()]),
    };
    let unmigrated = unmigrated_config.derive_account().unwrap();
    let tx = grant_tx(&f, 6, SignatureType::Secp256k1, unmigrated);
    let result = f.run(&tx);
    assert!(result.status, "{result:?}");
    let tx = delegate_keychain_signed(
        aa_tx(7, vec![f.getter()]),
        account,
        unmigrated,
        &unmigrated_config,
        &unmigrated_owner,
    );
    assert_eq!(
        rejection(&mut f, &tx, account),
        type_mismatch(SignatureType::Secp256k1, SignatureType::ConfigurableAccount)
    );

    // A configurable delegate grant does not accept a primitive signature that recovers to its
    // key ID.
    let primitive_delegate = signer(10);
    let tx = grant_tx(
        &f,
        7,
        SignatureType::ConfigurableAccount,
        primitive_delegate.address(),
    );
    let result = f.run(&tx);
    assert!(result.status, "{result:?}");
    let tx = keychain_tx(&f, &primitive_delegate, 8, vec![f.getter()]);
    assert_eq!(
        rejection(&mut f, &tx, account),
        type_mismatch(SignatureType::ConfigurableAccount, SignatureType::Secp256k1)
    );
}

#[test]
fn retired_root_keeps_owner_parent_and_sender_authority() {
    // What stays valid for a migrated account X.
    let mut f = Fixture::with_parent(false);
    let old_key = signer(2);
    grant_key(&mut f, 3, &old_key, 0);
    // X lists its retired root as the owner of its new configuration.
    let root = f.owner.address();
    f.config = migrate(&mut f, 4, root);
    let account = f.account;
    fund(&mut f, account, 50_000_000);
    let transfer = Call {
        to: TxKind::Call(PATH_USD_ADDRESS),
        value: U256::ZERO,
        input: ITIP20::transferCall {
            to: Address::repeat_byte(0x66),
            amount: U256::from(10),
        }
        .abi_encode()
        .into(),
    };
    let revoke = Call {
        to: TxKind::Call(ACCOUNT_KEYCHAIN_ADDRESS),
        value: U256::ZERO,
        input: IAccountKeychain::revokeKeyCall {
            keyId: old_key.address(),
        }
        .abi_encode()
        .into(),
    };

    // X's old uncommitted access key still signs for X.
    let tx = keychain_tx(&f, &old_key, 5, vec![f.getter()]);
    let result = f.run(&tx);
    assert!(result.status, "{result:?}");

    // X pays its own fees in a configurable account transaction, and its calls authenticate as X.
    let before = balance(&mut f, account);
    let tx = configurable_account_signed(
        &f,
        TempoTransaction {
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            fee_token: Some(PATH_USD_ADDRESS),
            ..aa_tx(6, vec![transfer])
        },
    );
    let result = f.run(&tx);
    assert!(result.status, "{result:?}");
    let fee = calc_gas_balance_spending(result.tx_gas_used(), 1);
    assert!(fee > U256::ZERO);
    assert_eq!(
        balance(&mut f, account),
        before - fee - U256::from(10),
        "the transfer and the fee both come from X"
    );
    // Root-level keychain administration (no access key) is still X's to use.
    let tx = f.signed(7, vec![revoke]);
    let result = f.run(&tx);
    assert!(result.status, "{result:?}");
    let tx = keychain_tx(&f, &old_key, 8, vec![f.getter()]);
    // The revocation took effect: the keychain, not the retirement, now rejects the key.
    assert!(matches!(
        rejection(&mut f, &tx, account),
        TempoInvalidTransaction::KeychainValidationFailed { .. }
    ));

    // Another configurable account M that lists the retired X accepts X's approval.
    let mut m = Fixture::new();
    let owner = m.owner.address();
    retire(&mut m, owner);
    let tx = m.signed(3, vec![m.getter()]);
    let result = m.run(&tx);
    assert!(result.status, "{result:?}");
}

/// Gas used by `tx` at `spec` on a fresh unmigrated fixture with the access key `key` granted.
fn gas_at(
    spec: TempoHardfork,
    key: &PrivateKeySigner,
    tx: impl FnOnce(&Fixture) -> AASigned,
) -> u64 {
    let mut f = Fixture::with_spec(false, spec);
    grant_key(&mut f, 3, key, 0);
    let tx = tx(&f);
    let result = f.run(&tx);
    assert!(result.status, "{spec:?}: {result:?}");
    // Before the minimum-gas floor, which hides small differences.
    result.total_gas_spent
}

#[test]
fn retired_root_error_order_and_access_gas() {
    let (signer_s, payer, key) = (signer(4), signer(5), signer(6));
    let mut f = Fixture::with_parent(false);
    let account = f.account;
    // Every role names a retired account: the sender, the grant signer, the fee payer, and the
    // access key.
    for address in [account, signer_s.address(), payer.address(), key.address()] {
        retire(&mut f, address);
    }
    let target = signer(7).address();
    // A root-signed grant for a root-signed transaction; a grant signed by an access key must
    // travel with that key.
    let root_grant = grant_by(&f.owner, target);
    let key_grant = {
        let grant = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, target)
            .with_account(account);
        let signature = signer_s.sign_hash_sync(&grant.signature_hash()).unwrap();
        grant.into_signed(PrimitiveSignature::Secp256k1(signature))
    };
    let sponsor = |tx: TempoTransaction| sponsored(tx, &payer, account);

    // Sender, then key authorization signer, then fee payer, then access key.
    let tx = f.sign_primitive(sponsor(TempoTransaction {
        key_authorization: Some(root_grant),
        ..aa_tx(3, vec![f.getter()])
    }));
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(account, RootKeyRole::Sender)
    );
    let tx = keychain_signed(
        sponsor(TempoTransaction {
            key_authorization: Some(key_grant),
            ..aa_tx(3, vec![f.getter()])
        }),
        &signer_s,
        account,
    );
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(signer_s.address(), RootKeyRole::KeyAuthorizationSigner)
    );
    let tx = keychain_signed(sponsor(aa_tx(3, vec![f.getter()])), &key, account);
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(payer.address(), RootKeyRole::FeePayer)
    );
    let tx = keychain_signed(aa_tx(3, vec![f.getter()]), &key, account);
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(key.address(), RootKeyRole::AccessKey)
    );

    // Request validation comes first: the sponsor may not be the sender.
    let tx = f.sign_primitive(sponsored(aa_tx(3, vec![f.getter()]), &f.owner, account));
    assert_eq!(
        rejection(&mut f, &tx, account),
        TempoInvalidTransaction::SelfSponsoredFeePayer
    );
    // Nonce, intrinsic gas and balance errors come after, with or without a commitment.
    let mut fresh = Fixture::with_parent(false);
    let mut fresh_rejection = |label: &str, edit: fn(&mut TempoTransaction)| {
        let mut tx = aa_tx(3, vec![f.getter()]);
        edit(&mut tx);
        let signed = f.sign_primitive(tx);
        assert_eq!(
            rejection(&mut f, &signed, account),
            retired(account, RootKeyRole::Sender),
            "{label}"
        );
        handler_rejection(&mut fresh, &signed, account)
    };
    assert_eq!(
        fresh_rejection("nonce", |tx| tx.nonce = 99),
        HandlerError::InvalidNonce {
            expected: 3,
            got: 99
        }
    );
    let error = fresh_rejection("intrinsic gas", |tx| tx.gas_limit = 1);
    assert!(
        matches!(error, HandlerError::IntrinsicGasTooLow { got: 1, .. }),
        "{error:?}"
    );
    let error = fresh_rejection("balance", |tx| {
        tx.max_fee_per_gas = 1_000_000_000_000;
        tx.fee_token = Some(PATH_USD_ADDRESS);
    });
    assert_eq!(
        error.external_ref::<TempoInvalidTransaction>(),
        Some(&TempoInvalidTransaction::CollectFeePreTx(
            FeePaymentError::InsufficientFeeTokenBalance {
                fee: calc_gas_balance_spending(1_000_000, 1_000_000_000_000),
                balance: U256::ZERO,
            }
        )),
        "{error:?}"
    );

    // Gas: each distinct non-caller role account is charged one account access from T14.
    let params = tempo_gas_params(TempoHardfork::T14);
    let warm = params.get(GasId::WarmStorageReadCost);
    let cold = warm + params.cold_account_additional_cost();
    let other = signer(8);
    let delta = |tx: &dyn Fn(&Fixture) -> AASigned| {
        gas_at(TempoHardfork::T14, &key, tx) - gas_at(TempoHardfork::T13, &key, tx)
    };
    let listed = AccessList(vec![AccessListItem {
        address: payer.address(),
        storage_keys: Vec::new(),
    }]);
    // T14 prices every transaction a little differently, with or without role checks; the
    // role charges are measured on top of a plain transaction.
    let base = delta(&|f| f.primitive(4, vec![f.getter()]));
    // The caller is free, even as the grant signer.
    let grant_tx = |f: &Fixture| {
        let grant = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, other.address());
        let signature = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
        f.sign_primitive(TempoTransaction {
            key_authorization: Some(grant.into_signed(PrimitiveSignature::Secp256k1(signature))),
            ..aa_tx(4, vec![f.getter()])
        })
    };
    assert_eq!(delta(&grant_tx), base);
    // A cold fee payer costs a cold access, an access-listed one a warm access.
    let paid = |f: &Fixture, payer: &PrivateKeySigner, list: &AccessList| {
        f.sign_primitive(sponsored(
            TempoTransaction {
                access_list: list.clone(),
                ..aa_tx(4, vec![f.getter()])
            },
            payer,
            f.account,
        ))
    };
    assert_eq!(
        delta(&|f| paid(f, &payer, &AccessList(Vec::new()))),
        base + cold
    );
    assert_eq!(delta(&|f| paid(f, &payer, &listed)), base + warm);
    // The access key and the fee payer are one account here: one access, not two.
    let keyed = |f: &Fixture, payer: &PrivateKeySigner| {
        keychain_signed(
            sponsored(aa_tx(4, vec![f.getter()]), payer, f.account),
            &key,
            f.account,
        )
    };
    assert_eq!(delta(&|f| keyed(f, &key)), base + cold);
    assert_eq!(delta(&|f| keyed(f, &payer)), base + 2 * cold);
    // An access-listed access key costs a warm access.
    let key_listed = AccessList(vec![AccessListItem {
        address: key.address(),
        storage_keys: Vec::new(),
    }]);
    assert_eq!(
        delta(&|f| keychain_signed(
            TempoTransaction {
                access_list: key_listed.clone(),
                ..aa_tx(4, vec![f.getter()])
            },
            &key,
            f.account
        )),
        base + warm
    );
}

/// The P256 or WebAuthn signature of the key seeded by `seed` over `hash`, and the key's address.
fn p256_primitive(kind: SigKind, seed: u8, hash: B256) -> (Address, PrimitiveSignature) {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let pub_key_x = B256::from_slice(point.x().unwrap());
    let pub_key_y = B256::from_slice(point.y().unwrap());
    let primitive = if matches!(kind, SigKind::P256) {
        let signature: p256::ecdsa::Signature = key.sign_prehash(&Sha256::digest(hash)).unwrap();
        let bytes = signature.to_bytes();
        PrimitiveSignature::P256(P256SignatureWithPreHash {
            r: B256::from_slice(&bytes[..32]),
            s: normalize_p256_s(&bytes[32..]).unwrap(),
            pub_key_x,
            pub_key_y,
            pre_hash: true,
        })
    } else {
        let mut authenticator_data = vec![0u8; 37];
        authenticator_data[..32].copy_from_slice(&[0xAA; 32]);
        authenticator_data[32] = 0x01;
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://tempo.xyz","crossOrigin":false}}"#,
            URL_SAFE_NO_PAD.encode(hash)
        );
        let mut message = Sha256::new();
        message.update(&authenticator_data);
        message.update(Sha256::digest(client_data.as_bytes()));
        let signature: p256::ecdsa::Signature = key.sign_prehash(&message.finalize()).unwrap();
        let bytes = signature.to_bytes();
        authenticator_data.extend_from_slice(client_data.as_bytes());
        PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: authenticator_data.into(),
            r: B256::from_slice(&bytes[..32]),
            s: normalize_p256_s(&bytes[32..]).unwrap(),
            pub_key_x,
            pub_key_y,
        })
    };
    (derive_p256_address(&pub_key_x, &pub_key_y), primitive)
}

/// A transaction sent by `sender` (nonce 0) that calls `to` and carries `entries`, as an
/// EIP-7702 transaction or as an AA transaction's `tempo_authorization_list`.
fn listed_tx(
    sender: &PrivateKeySigner,
    aa: bool,
    to: Address,
    entries: &[Entry],
) -> TempoTxEnvelope {
    if aa {
        let tx = TempoTransaction {
            tempo_authorization_list: entries.iter().map(|entry| entry.sign().1).collect(),
            ..aa_tx(
                0,
                vec![Call {
                    to: TxKind::Call(to),
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
            )
        };
        let signature = sender.sign_hash_sync(&tx.signature_hash()).unwrap();
        TempoTxEnvelope::AA(tx.into_signed(signature.into()))
    } else {
        type4(
            sender,
            0,
            to,
            Bytes::new(),
            entries.iter().map(Entry::legacy).collect(),
        )
    }
}

/// Seeds `address` as an existing account without code at `nonce`.
fn seed_eoa(f: &mut Fixture, address: Address, nonce: u64) {
    f.evm.overlay_db_mut().insert_account_info(
        &address,
        AccountInfo {
            nonce,
            ..AccountInfo::default().with_balance(U256::ONE)
        },
    );
}

fn account_state(f: &mut Fixture, address: Address) -> AccountState {
    let info = f
        .info(address)
        .unwrap_or_else(|| AccountInfo::default().with_balance(U256::ZERO));
    let delegation = (info.code_hash != KECCAK256_EMPTY
        && info.code_hash != CONFIGURABLE_ACCOUNT_CODE_HASH)
        .then(|| {
            let code = info.code.clone().unwrap_or_else(|| {
                f.evm
                    .overlay_db_mut()
                    .get_code_by_hash(&info.code_hash)
                    .unwrap()
            });
            let bytes = code.original_bytes();
            assert_eq!(bytes[..3], [0xef, 0x01, 0x00], "{bytes:?}");
            Address::from_slice(&bytes[3..])
        });
    let retired = !decode_config_commitment(&info.extension, TempoHardfork::T14)
        .unwrap()
        .is_zero();
    AccountState {
        nonce: info.nonce,
        delegation,
        retired,
    }
}

fn probe(f: &mut Fixture, account: Address) {
    f.install_contract(
        PROBE,
        [&[0x73u8][..], account.as_slice(), &[0x3b, 0x50, 0x00]].concat(),
    );
}

#[test]
fn retired_root_authorization_list_entries_skipped() {
    let target = Address::repeat_byte(0x55);
    let sender = signer(2);
    let existing = Entry::new(SigKind::Secp256k1, 7, target, 2);
    let fresh = Entry::new(SigKind::Secp256k1, 6, target, 0);

    for (aa, kind) in [
        (false, SigKind::Secp256k1),
        (true, SigKind::Secp256k1),
        (true, SigKind::P256),
        (true, SigKind::WebAuthn),
    ] {
        let label = format!("aa {aa}, {kind:?}");
        let x = Entry::new(kind, 9, target, 5);
        let mismatched = Entry { nonce: 6, ..x };
        // Runs the transaction with `entry` for the authority at nonce 5, retired or not.
        let run = |entry: Entry, retire_x: bool| {
            let mut f = Fixture::with_parent(false);
            seed_eoa(&mut f, x.address(), 5);
            seed_eoa(&mut f, existing.address(), 2);
            if retire_x {
                retire(&mut f, x.address());
            }
            probe(&mut f, x.address());
            let tx = listed_tx(&sender, aa, PROBE, &[entry, existing, fresh]);
            let result = f.run_as(sender.address(), &tx);
            assert!(result.status, "{label}: {result:?}");
            (f, result.tx_gas_used())
        };

        let (mut f, skipped_gas) = run(x, true);
        // The retired authority is untouched, the other entries applied.
        assert_eq!(
            account_state(&mut f, x.address()),
            AccountState {
                nonce: 5,
                delegation: None,
                retired: true
            },
            "{label}"
        );
        assert_eq!(
            account_state(&mut f, existing.address()),
            AccountState {
                nonce: 3,
                delegation: Some(target),
                retired: false
            },
            "{label}"
        );
        assert_eq!(
            account_state(&mut f, fresh.address()),
            AccountState {
                nonce: 1,
                delegation: Some(target),
                retired: false
            },
            "{label}"
        );

        // Same gas, warming and refunds as an entry revm itself skips for its nonce.
        let (mut control, mismatched_gas) = run(mismatched, false);
        assert_eq!(
            account_state(&mut control, x.address()),
            AccountState {
                nonce: 5,
                delegation: None,
                retired: false
            },
            "{label}"
        );
        assert_eq!(skipped_gas, mismatched_gas, "{label}");

        // Without the retirement the entry applies. Its gas is the same too: the authorization
        // refund is disabled since T1, so only the warming above is observable.
        let (mut applied, applied_gas) = run(x, false);
        assert_eq!(
            account_state(&mut applied, x.address()),
            AccountState {
                nonce: 6,
                delegation: Some(target),
                retired: false
            },
            "{label}"
        );
        assert_eq!(applied_gas, skipped_gas, "{label}");
    }
}

#[test]
fn retired_root_authorization_list_entries_skipped_after_a_same_block_migration() {
    // TIP-1112: an entry the root key signed before migrating, relayed by a later transaction
    // of the same block, is skipped.
    let target = Address::repeat_byte(0x55);
    let sender = signer(2);
    let fresh = Entry::new(SigKind::Secp256k1, 6, target, 0);
    for aa in [false, true] {
        let mut f = Fixture::with_parent(false);
        let account = f.account;
        // Signed by the fixture's root key for the nonce its migration leaves.
        let entry = Entry::new(SigKind::Secp256k1, 1, target, 4);
        assert_eq!(entry.address(), account);
        let tx = listed_tx(&sender, aa, Address::repeat_byte(0x73), &[entry, fresh]);
        migrate(&mut f, 3, signer(3).address());

        let result = f.run_as(sender.address(), &tx);
        assert!(result.status, "aa {aa}: {result:?}");
        assert_eq!(
            account_state(&mut f, account),
            AccountState {
                nonce: 4,
                delegation: None,
                retired: true
            },
            "aa {aa}"
        );
        assert_eq!(
            account_state(&mut f, fresh.address()),
            AccountState {
                nonce: 1,
                delegation: Some(target),
                retired: false
            },
            "aa {aa}"
        );
    }
}

#[test]
fn retired_root_authorization_list_variants() {
    let target = Address::repeat_byte(0x55);
    let sender = signer(2);
    let fresh = Entry::new(SigKind::Secp256k1, 6, target, 0);
    let x = Entry::new(SigKind::Secp256k1, 9, target, 5);
    let address = x.address();

    let rows = [
        // A wildcard chain id is loaded by revm like a matching one.
        ListVariant {
            name: "chain id 0",
            nonce: 5,
            entries: vec![Entry { chain_id: 0, ..x }],
        },
        // An EOA migrated on a 2D nonce lane keeps protocol nonce 0, where its entry would apply.
        ListVariant {
            name: "nonce 0",
            nonce: 0,
            entries: vec![Entry { nonce: 0, ..x }],
        },
        // Every entry of the authority is skipped, whatever its nonce.
        ListVariant {
            name: "repeated",
            nonce: 5,
            entries: vec![x, Entry { nonce: 6, ..x }, Entry { nonce: 5, ..x }],
        },
    ];
    for aa in [false, true] {
        for ListVariant {
            name,
            nonce,
            entries,
        } in &rows
        {
            let label = format!("aa {aa}, {name}");
            let mut f = Fixture::with_parent(false);
            let info = AccountInfo {
                nonce: *nonce,
                ..AccountInfo::default().with_balance(U256::ONE)
            };
            f.evm.overlay_db_mut().insert_account_info(&address, info);
            retire(&mut f, address);
            let mut entries = entries.clone();
            entries.push(fresh);
            let tx = listed_tx(&sender, aa, Address::repeat_byte(0x73), &entries);
            let result = f.run_as(sender.address(), &tx);
            assert!(result.status, "{label}: {result:?}");
            assert_eq!(
                account_state(&mut f, address),
                AccountState {
                    nonce: *nonce,
                    delegation: None,
                    retired: true
                },
                "{label}"
            );
            assert_eq!(
                account_state(&mut f, fresh.address()),
                AccountState {
                    nonce: 1,
                    delegation: Some(target),
                    retired: false
                },
                "{label}"
            );
        }
    }
}

#[test]
fn retired_root_authorization_list_entries_apply_before_t14() {
    let target = Address::repeat_byte(0x55);
    let sender = signer(2);
    let x = Entry::new(SigKind::Secp256k1, 9, target, 5);
    for aa in [false, true] {
        let mut f = Fixture::with_spec(false, TempoHardfork::T13);
        seed_eoa(&mut f, x.address(), 5);
        retire(&mut f, x.address());
        let tx = listed_tx(&sender, aa, Address::repeat_byte(0x73), &[x]);
        let result = f.run_as(sender.address(), &tx);
        assert!(result.status, "aa {aa}: {result:?}");
        assert_eq!(
            account_state(&mut f, x.address()),
            AccountState {
                nonce: 6,
                delegation: Some(target),
                retired: true
            },
            "aa {aa}"
        );
    }
}

#[test]
fn authorization_list_gas_is_unchanged_by_the_retired_root_skip() {
    // The skip may only read the authorities revm itself loads: whatever the list holds, T14
    // warms the same accounts and charges the same gas as T13, where nothing is skipped.
    let target = Address::repeat_byte(0x55);
    let sender = signer(2);
    let x = Entry::new(SigKind::Secp256k1, 9, target, 5);
    let rows = [
        ("matching", x),
        ("chain id 0", Entry { chain_id: 0, ..x }),
        ("other chain id", Entry { chain_id: 2, ..x }),
        ("nonce mismatch", Entry { nonce: 6, ..x }),
        (
            "nonce max",
            Entry {
                nonce: u64::MAX,
                ..x
            },
        ),
    ];
    for aa in [false, true] {
        for (name, entry) in rows {
            for retired in [false, true] {
                let label = format!("aa {aa}, {name}, retired {retired}");
                let run = |spec: TempoHardfork| {
                    let mut f = Fixture::with_spec(false, spec);
                    seed_eoa(&mut f, x.address(), 5);
                    if retired {
                        retire(&mut f, x.address());
                    }
                    probe(&mut f, x.address());
                    let tx = listed_tx(&sender, aa, PROBE, &[entry]);
                    let result = f.run_as(sender.address(), &tx);
                    assert!(result.status, "{label}: {result:?}");
                    result.tx_gas_used()
                };
                assert_eq!(run(TempoHardfork::T14), run(TempoHardfork::T13), "{label}");
            }
        }
    }
}

#[test]
fn keychain_authorization_list_entries_stay_skipped() {
    // The T0 filter drops a keychain-signed entry before the retired-root check reads its
    // authority: retired or not, the named account is neither delegated nor warmed, as at T13.
    let sender = signer(2);
    let x = Entry::new(SigKind::Keychain, 9, Address::repeat_byte(0x55), 5);
    for retired in [false, true] {
        let run = |spec: TempoHardfork| {
            let label = format!("{spec:?}, retired {retired}");
            let mut f = Fixture::with_spec(false, spec);
            seed_eoa(&mut f, x.address(), 5);
            if retired {
                retire(&mut f, x.address());
            }
            probe(&mut f, x.address());
            let tx = listed_tx(&sender, true, PROBE, &[x]);
            let result = f.run_as(sender.address(), &tx);
            assert!(result.status, "{label}: {result:?}");
            assert_eq!(
                account_state(&mut f, x.address()),
                AccountState {
                    nonce: 5,
                    delegation: None,
                    retired
                },
                "{label}"
            );
            result.tx_gas_used()
        };
        assert_eq!(
            run(TempoHardfork::T14),
            run(TempoHardfork::T13),
            "retired {retired}"
        );
    }
}

/// Executes `calls` as one AA transaction that `sender` sends at its current nonce.
fn send(f: &mut Fixture, sender: Address, calls: Vec<Call>) -> TxResult<TempoEvmTypes> {
    send_listed(f, sender, calls, AccessList(Vec::new()), AA_GAS_LIMIT)
}

fn send_listed(
    f: &mut Fixture,
    sender: Address,
    calls: Vec<Call>,
    access_list: AccessList,
    gas_limit: u64,
) -> TxResult<TempoEvmTypes> {
    let nonce = nonce_of(f, sender);
    let tx = f.sign_primitive(TempoTransaction {
        gas_limit,
        access_list,
        ..aa_tx(nonce, calls)
    });
    f.run_as(sender, &tx)
}

/// An existing relayer, so that the new-account charge of its first transaction does not enter
/// the gas of the checks that it sends.
fn seed_relayer(f: &mut Fixture) {
    f.evm
        .overlay_db_mut()
        .insert_account_info(&signer(9).address(), AccountInfo::default().with_nonce(1));
}

/// Executes `call` from the relayer with `gas_limit` and `warm` in the access list.
fn relayed(
    f: &mut Fixture,
    call: Call,
    gas_limit: u64,
    warm: Option<Address>,
) -> TxResult<TempoEvmTypes> {
    let access_list = AccessList(
        warm.into_iter()
            .map(|address| AccessListItem {
                address,
                storage_keys: Vec::new(),
            })
            .collect(),
    );
    send_listed(f, signer(9).address(), vec![call], access_list, gas_limit)
}

/// Asserts that `result` reverted with exactly `error` and logged nothing.
fn assert_reverts_with(result: &TxResult<TempoEvmTypes>, error: impl SolError, label: &str) {
    assert!(result.stop.is_revert(), "{label}: {result:?}");
    assert_eq!(&result.output, &error.abi_encode(), "{label}");
    assert!(result.logs.is_empty(), "{label}");
}

fn permit_retired(account: Address) -> ITIP20::RootKeyRetired {
    ITIP20::RootKeyRetired { account }
}

fn voucher_retired(account: Address) -> ITIP20ChannelReserve::RootKeyRetired {
    ITIP20ChannelReserve::RootKeyRetired { account }
}

/// A path USD `permit` of `owner` to `spender`, signed by `key` over the token's current nonce.
fn permit_signed(
    f: &mut Fixture,
    owner: Address,
    key: &PrivateKeySigner,
    spender: Address,
    deadline: u64,
) -> Call {
    let (nonce, separator) = in_storage_ctx(&mut f.evm, || {
        let token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
        Ok::<_, TempoPrecompileError>((
            token.nonces(ITIP20::noncesCall { owner })?,
            token.domain_separator()?,
        ))
    })
    .unwrap();
    let (value, deadline) = (U256::from(100), U256::from(deadline));
    // The ABI encoding of the permit's six static fields: one 32-byte word each.
    let struct_hash = keccak256(
        [
            PERMIT_TYPEHASH,
            owner.into_word(),
            spender.into_word(),
            value.into(),
            nonce.into(),
            deadline.into(),
        ]
        .concat(),
    );
    let digest = keccak256(
        [
            &[0x19, 0x01][..],
            separator.as_slice(),
            struct_hash.as_slice(),
        ]
        .concat(),
    );
    let signature = key.sign_hash_sync(&digest).unwrap();
    Call {
        to: TxKind::Call(PATH_USD_ADDRESS),
        value: U256::ZERO,
        input: ITIP20::permitCall {
            owner,
            spender,
            value,
            deadline,
            v: signature.v_byte(),
            r: signature.r().into(),
            s: signature.s().into(),
        }
        .abi_encode()
        .into(),
    }
}

/// The permit nonce of `owner` and its path USD allowance for `spender`.
fn permit_state(f: &mut Fixture, owner: Address, spender: Address) -> (U256, U256) {
    in_storage_ctx(&mut f.evm, || {
        let token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
        Ok::<_, TempoPrecompileError>((
            token.nonces(ITIP20::noncesCall { owner })?,
            token.allowance(ITIP20::allowanceCall { owner, spender })?,
        ))
    })
    .unwrap()
}

#[test]
fn retired_root_permit_reverts() {
    let (spender, relayer) = (signer(8).address(), signer(9).address());
    let mut f = Fixture::with_parent(false);
    let x = f.account;
    let old_key = f.owner.clone();

    // Signed while X's root key still works, relayed after it migrated: the attack path.
    let early = permit_signed(&mut f, x, &old_key, spender, 1_000);
    let config = migrate(&mut f, 3, x);
    assert_eq!(f.commitment(), config.commitment().unwrap());
    let result = send(&mut f, relayer, vec![early]);
    assert_reverts_with(&result, permit_retired(x), "relayed after migration");
    assert_eq!(permit_state(&mut f, x, spender), (U256::ZERO, U256::ZERO));

    // Signed after the migration with the old root key.
    let late = permit_signed(&mut f, x, &old_key, spender, 1_000);
    let result = send(&mut f, relayer, vec![late]);
    assert_reverts_with(&result, permit_retired(x), "signed after migration");
    assert_eq!(permit_state(&mut f, x, spender), (U256::ZERO, U256::ZERO));
}

#[test]
fn retired_root_permit_error_order() {
    let (owner, spender, relayer) = (signer(4), signer(8).address(), signer(9).address());
    let x = owner.address();
    let mut f = Fixture::with_parent(false);
    retire(&mut f, x);
    f.update_block(|block| block.timestamp = U256::from(2000));

    // The control side of each order: a valid, unexpired signature by the committed owner.
    let valid = permit_signed(&mut f, x, &owner, spender, 3_000);
    let result = send(&mut f, relayer, vec![valid]);
    assert_reverts_with(&result, permit_retired(x), "valid permit");

    // A signature by another key is an invalid signature, not a retired root.
    let forged = permit_signed(&mut f, x, &signer(5), spender, 3_000);
    let result = send(&mut f, relayer, vec![forged]);
    assert_reverts_with(&result, ITIP20::InvalidSignature {}, "forged permit");
    // An uncommitted owner gets the same error.
    let other = signer(6);
    let forged = permit_signed(&mut f, other.address(), &signer(5), spender, 3_000);
    let result = send(&mut f, relayer, vec![forged]);
    assert_reverts_with(&result, ITIP20::InvalidSignature {}, "forged, uncommitted");

    // An expired deadline keeps its own error for the committed owner.
    let expired = permit_signed(&mut f, x, &owner, spender, 1_000);
    let result = send(&mut f, relayer, vec![expired]);
    assert_reverts_with(&result, ITIP20::PermitExpired {}, "expired permit");
    assert_eq!(permit_state(&mut f, x, spender), (U256::ZERO, U256::ZERO));
}

#[test]
fn retired_root_permit_reverts_before_writing() {
    let (owner, spender, relayer) = (signer(4), signer(8).address(), signer(9).address());
    let x = owner.address();
    let mut retired = Fixture::with_parent(false);
    let mut stale = Fixture::with_parent(false);
    let permit = permit_signed(&mut retired, x, &owner, spender, 1_000);
    // Each fixture grants one permit first (another owner's in `retired`, one spending X's nonce 0
    // in `stale`), so the two relays below read the same state apart from X's permit nonce.
    for (f, earlier) in [(&mut retired, signer(6)), (&mut stale, owner.clone())] {
        let call = permit_signed(f, earlier.address(), &earlier, signer(7).address(), 1_000);
        let result = send(f, signer(10).address(), vec![call]);
        assert!(result.status, "{result:?}");
        retire(f, x);
    }

    // The valid permit of the committed owner reverts with `RootKeyRetired`; the same permit
    // over a spent nonce fails the signature check instead.
    let result = send(&mut retired, relayer, vec![permit.clone()]);
    assert_reverts_with(&result, permit_retired(x), "valid permit");
    let retired_gas = result.tx_gas_used();
    let result = send(&mut stale, relayer, vec![permit]);
    assert_reverts_with(&result, ITIP20::InvalidSignature {}, "stale permit");

    // Both read the nonce and recover the signer, and the retired permit adds only the cold
    // commitment read: it reverts before the nonce and allowance writes, whose gas a revert keeps.
    assert_eq!(retired_gas - result.tx_gas_used(), 2600);
}

#[test]
fn retired_root_permit_stays_allowed() {
    let (owner, spender, relayer) = (signer(4), signer(8).address(), signer(9).address());
    // At T14 only the owner's root key is at stake: a committed spender is no authority here.
    // Before T14 the retirement does not exist, so even a committed owner's permit is good.
    for (spec, retired) in [
        (TempoHardfork::T13, owner.address()),
        (TempoHardfork::T14, spender),
    ] {
        let mut f = Fixture::with_spec(false, spec);
        retire(&mut f, retired);
        let permit = permit_signed(&mut f, owner.address(), &owner, spender, 1_000);
        let result = send(&mut f, relayer, vec![permit]);
        assert!(result.status, "{spec:?}: {result:?}");
        assert_eq!(
            permit_state(&mut f, owner.address(), spender),
            (U256::ONE, U256::from(100)),
            "{spec:?}"
        );
        assert_eq!(result.logs.len(), 1, "{spec:?}");
    }
}

fn nonce_of(f: &mut Fixture, account: Address) -> u64 {
    f.info(account).map_or(0, |info| info.nonce)
}

/// Funds `payer` with `deposit` and opens a channel to `payee` with the given voucher signer.
fn open_channel(
    f: &mut Fixture,
    payer: Address,
    payee: Address,
    authorized_signer: Address,
    deposit: u64,
) -> Opened {
    // Genesis initializes the precompile; the fixture does not.
    if f.info(TIP20_CHANNEL_RESERVE_ADDRESS).is_none() {
        in_storage_ctx(&mut f.evm, || TIP20ChannelReserve::new().initialize()).unwrap();
    }
    fund(f, payer, deposit);
    let call = open_call(payee, authorized_signer, deposit);
    let result = send(f, payer, vec![call]);
    assert!(result.status, "{result:?}");
    let opened = result
        .logs
        .iter()
        .find_map(|log| ITIP20ChannelReserve::ChannelOpened::decode_log(log).ok())
        .expect("channel opened")
        .data;
    Opened {
        id: opened.channelId,
        descriptor: ITIP20ChannelReserve::ChannelDescriptor {
            payer,
            payee,
            operator: Address::ZERO,
            token: PATH_USD_ADDRESS,
            salt: opened.salt,
            authorizedSigner: authorized_signer,
            expiringNonceHash: opened.expiringNonceHash,
        },
    }
}

/// The call opening a path USD channel to `payee` with the given voucher signer.
fn open_call(payee: Address, authorized_signer: Address, deposit: u64) -> Call {
    Call {
        to: TxKind::Call(TIP20_CHANNEL_RESERVE_ADDRESS),
        value: U256::ZERO,
        input: ITIP20ChannelReserve::openCall {
            payee,
            operator: Address::ZERO,
            token: PATH_USD_ADDRESS,
            deposit: U96::from(deposit),
            salt: B256::repeat_byte(0x5a),
            authorizedSigner: authorized_signer,
        }
        .abi_encode()
        .into(),
    }
}

/// A voucher of `key` for `amount` cumulative units of the channel.
fn voucher(f: &mut Fixture, channel: &Opened, key: &PrivateKeySigner, amount: u64) -> Bytes {
    let digest = in_storage_ctx(&mut f.evm, || {
        TIP20ChannelReserve::new().get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
            channelId: channel.id,
            cumulativeAmount: U96::from(amount),
        })
    })
    .unwrap();
    Bytes::from(key.sign_hash_sync(&digest).unwrap().as_bytes())
}

fn channel_snapshot(f: &mut Fixture, channel: &Opened) -> ChannelSnapshot {
    let state = in_storage_ctx(&mut f.evm, || {
        TIP20ChannelReserve::new().get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
            channelId: channel.id,
        })
    })
    .unwrap();
    ChannelSnapshot {
        settled: state.settled,
        deposit: state.deposit,
        close_requested_at: state.closeRequestedAt,
        payee_balance: balance(f, channel.descriptor.payee),
        payer_balance: balance(f, channel.descriptor.payer),
        reserve_balance: balance(f, TIP20_CHANNEL_RESERVE_ADDRESS),
    }
}

/// A channel from `payer` to a fresh payee, one voucher of `payer`'s key for 60 units, and the
/// voucher signer's configuration still uncommitted.
fn voucher_setup(
    f: &mut Fixture,
    payer: &PrivateKeySigner,
    authorized_signer: &PrivateKeySigner,
) -> (Opened, Bytes) {
    let authorized = if authorized_signer.address() == payer.address() {
        Address::ZERO
    } else {
        authorized_signer.address()
    };
    let channel = open_channel(f, payer.address(), signer(5).address(), authorized, 100);
    let signature = voucher(f, &channel, authorized_signer, 60);
    (channel, signature)
}

#[test]
fn retired_root_channel_voucher_reverts() {
    /// Which root key retires, and how.
    #[derive(Clone, Copy)]
    enum Retire {
        /// The payer is committed and signs for itself.
        CommitPayer,
        /// The authorized signer is committed, the payer is not: the signer's root key signed.
        CommitSigner,
        /// The payer migrates for real, in a block after the voucher was signed (this harness has
        /// one block environment; the node test uses real blocks).
        MigratePayer,
    }
    let payee = signer(5).address();
    // (case, payer seed, voucher signer seed, how the root key retires). Seed 1 is the fixture's
    // own account, the only one a real migration can retire.
    let cases = [
        ("payer signs", 4, 4, Retire::CommitPayer),
        ("signer", 4, 6, Retire::CommitSigner),
        ("migrated payer", 1, 1, Retire::MigratePayer),
    ];
    for redeem in [Redeem::Settle, Redeem::Close] {
        for (case, payer_seed, signer_seed, how) in cases {
            let label = format!("{redeem:?}, {case}");
            let (payer, voucher_signer) = (signer(payer_seed), signer(signer_seed));
            let mut f = Fixture::with_parent(false);
            let (channel, signature) = voucher_setup(&mut f, &payer, &voucher_signer);
            let retired = match how {
                Retire::CommitPayer => {
                    retire(&mut f, payer.address());
                    payer.address()
                }
                Retire::CommitSigner => {
                    retire(&mut f, voucher_signer.address());
                    voucher_signer.address()
                }
                Retire::MigratePayer => {
                    assert_eq!(payer.address(), f.account, "{label}");
                    let nonce = nonce_of(&mut f, payer.address());
                    migrate(&mut f, nonce, signer(2).address());
                    payer.address()
                }
            };
            // A voucher signed before the retirement stays redeemable: the deposit is already
            // in the channel and payable only to its payee.
            let before = channel_snapshot(&mut f, &channel);
            let call = redeem.call(&channel, 60, signature);
            let result = send(&mut f, payee, vec![call]);
            assert!(result.status, "{label}: {result:?}");
            let after = channel_snapshot(&mut f, &channel);
            assert_eq!(
                after.payee_balance,
                before.payee_balance + U256::from(60),
                "{label}: payee"
            );

            // The retired root key gains no authority over new deposits.
            let new_payer = signer(10).address();
            fund(&mut f, new_payer, 100);
            let call = open_call(payee, retired, 100);
            let result = send(&mut f, new_payer, vec![call]);
            assert_reverts_with(&result, voucher_retired(retired), &format!("{label}: open"));
        }
    }
}

#[test]
fn retired_root_channel_voucher_stays_allowed() {
    let (payer, delegate, payee) = (signer(4), signer(6), signer(5).address());
    // At T14 the payer is committed but its authorized signer is not: only the signer's root key
    // signed, so the voucher is good. Before T14 the payer's own retired root key is good too.
    for (spec, voucher_signer) in [
        (TempoHardfork::T13, &payer),
        (TempoHardfork::T14, &delegate),
    ] {
        for redeem in [Redeem::Settle, Redeem::Close] {
            let mut f = Fixture::with_spec(false, spec);
            let (channel, signature) = voucher_setup(&mut f, &payer, voucher_signer);
            retire(&mut f, payer.address());
            let before = channel_snapshot(&mut f, &channel);
            let call = redeem.call(&channel, 60, signature);
            let result = send(&mut f, payee, vec![call]);
            assert!(result.status, "{spec:?} {redeem:?}: {result:?}");
            let after = channel_snapshot(&mut f, &channel);
            assert_eq!(
                after.payee_balance,
                before.payee_balance + U256::from(60),
                "{spec:?} {redeem:?}: payee"
            );
            assert_ne!(after, before, "{spec:?} {redeem:?}");
        }
    }
}

#[test]
fn retired_root_channel_close_without_capture_stays_allowed() {
    // Closing without capturing anything verifies no voucher, so a retired payer still gets its
    // refund through the payee's close.
    let (payer, payee) = (signer(4), signer(5).address());
    let mut f = Fixture::with_parent(false);
    let (channel, signature) = voucher_setup(&mut f, &payer, &payer);
    retire(&mut f, payer.address());
    let before = channel_snapshot(&mut f, &channel);
    let call = Call {
        to: TxKind::Call(TIP20_CHANNEL_RESERVE_ADDRESS),
        value: U256::ZERO,
        input: ITIP20ChannelReserve::closeCall {
            descriptor: channel.descriptor.clone(),
            cumulativeAmount: U96::from(60),
            captureAmount: U96::ZERO,
            signature,
        }
        .abi_encode()
        .into(),
    };
    let result = send(&mut f, payee, vec![call]);
    assert!(result.status, "{result:?}");
    let after = channel_snapshot(&mut f, &channel);
    assert_eq!(after.payee_balance, before.payee_balance, "payee");
    assert_eq!(
        after.payer_balance,
        before.payer_balance + U256::from(100),
        "payer refund"
    );
}

#[test]
fn retired_root_channel_voucher_error_order() {
    let (payer, payee) = (signer(4), signer(5).address());
    for redeem in [Redeem::Settle, Redeem::Close] {
        let mut f = Fixture::with_parent(false);
        let (channel, valid) = voucher_setup(&mut f, &payer, &payer);
        retire(&mut f, payer.address());
        // Another key's voucher, and garbage, keep the existing signature error for a committed
        // signer; a voucher the committed signer really signed is redeemable.
        let forged = voucher(&mut f, &channel, &signer(7), 60);
        for (label, signature) in [("forged", forged), ("garbage", Bytes::from(vec![0x42; 65]))] {
            let call = redeem.call(&channel, 60, signature);
            let result = send(&mut f, payee, vec![call]);
            assert_reverts_with(
                &result,
                ITIP20ChannelReserve::InvalidSignature {},
                &format!("{redeem:?} {label}"),
            );
        }
        let call = redeem.call(&channel, 60, valid);
        let result = send(&mut f, payee, vec![call]);
        assert!(result.status, "{redeem:?} valid: {result:?}");
    }
}

/// Gas of one `action` verifying the signature of an uncommitted key, with that key's account
/// listed in the access list (warm) or not (cold).
fn signature_gas(spec: TempoHardfork, action: SignedAction, warm: bool) -> u64 {
    let (key, payee, relayer) = (signer(4), signer(5).address(), signer(9).address());
    let mut f = Fixture::with_spec(false, spec);
    let (sender, call) = match action {
        SignedAction::Permit => (
            relayer,
            permit_signed(&mut f, key.address(), &key, signer(8).address(), 1_000),
        ),
        SignedAction::Redeem(redeem) => {
            let (channel, signature) = voucher_setup(&mut f, &key, &key);
            (payee, redeem.call(&channel, 60, signature))
        }
    };
    let access_list = if warm {
        AccessList(vec![AccessListItem {
            address: key.address(),
            storage_keys: Vec::new(),
        }])
    } else {
        AccessList(Vec::new())
    };
    let result = send_listed(&mut f, sender, vec![call], access_list, AA_GAS_LIMIT);
    assert!(result.status, "{action:?} at {spec:?}: {result:?}");
    result.tx_gas_used()
}

#[test]
fn retired_root_signature_checks_cost_the_commitment_read() {
    for action in [
        SignedAction::Permit,
        SignedAction::Redeem(Redeem::Settle),
        SignedAction::Redeem(Redeem::Close),
    ] {
        for warm in [false, true] {
            let before = signature_gas(TempoHardfork::T13, action, warm);
            let after = signature_gas(TempoHardfork::T14, action, warm);
            // Reads follow the normal account-access schedule: a cold account load, or a warm
            // one when the key's account is in the access list. An already loaded commitment adds
            // nothing on top. Redeeming a voucher reads no commitment.
            let read = match (action, warm) {
                (SignedAction::Permit, false) => 2600,
                (SignedAction::Permit, true) => 100,
                (SignedAction::Redeem(_), _) => 0,
            };
            assert_eq!(after - before, read, "{action:?}, warm: {warm}");
        }
    }
}

/// A keychain signature naming `account`, made by the key of `kind` seeded by `seed` over `hash`,
/// with that key's address.
fn keychain_signature(kind: SigKind, seed: u8, account: Address, hash: B256) -> (Address, Bytes) {
    let signing_hash = KeychainSignature::signing_hash(hash, account);
    let (key, primitive) = match kind {
        SigKind::Secp256k1 => {
            let key = signer(seed);
            let signature = key.sign_hash_sync(&signing_hash).unwrap();
            (key.address(), PrimitiveSignature::Secp256k1(signature))
        }
        SigKind::P256 | SigKind::WebAuthn => p256_primitive(kind, seed, signing_hash),
        SigKind::Keychain => panic!("a keychain signature wraps a primitive one"),
    };
    let signature = TempoSignature::Keychain(KeychainSignature::new(account, primitive));
    (key, signature.to_bytes())
}

/// The keychain signature of the key seeded by `seed` as the root of its own address.
fn root_keychain_signature(kind: SigKind, seed: u8, hash: B256) -> (Address, Bytes) {
    let (address, _) = keychain_signature(kind, seed, Address::ZERO, hash);
    keychain_signature(kind, seed, address, hash)
}

/// Grants `key` of `kind` to the fixture's account, signed by its root.
fn grant_kind(f: &mut Fixture, nonce: u64, kind: SigKind, key: Address, admin: bool) {
    let signature_type = match kind {
        SigKind::Secp256k1 => SignatureType::Secp256k1,
        SigKind::P256 => SignatureType::P256,
        SigKind::WebAuthn => SignatureType::WebAuthn,
        SigKind::Keychain => panic!("a key has a primitive signature type"),
    };
    let mut grant = KeyAuthorization::unrestricted(1, signature_type, key);
    if admin {
        grant = grant.into_admin(f.account);
    }
    let approval = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
    let tx = f.sign_primitive(TempoTransaction {
        key_authorization: Some(grant.into_signed(PrimitiveSignature::Secp256k1(approval))),
        ..aa_tx(nonce, vec![f.getter()])
    });
    let result = f.run(&tx);
    assert!(result.status, "{kind:?} {key}: {result:?}");
}

fn is_admin_key_call(account: Address, key_id: Address) -> Call {
    Call {
        to: TxKind::Call(ACCOUNT_KEYCHAIN_ADDRESS),
        value: U256::ZERO,
        input: IAccountKeychain::isAdminKeyCall {
            account,
            keyId: key_id,
        }
        .abi_encode()
        .into(),
    }
}

/// Sends `call` from an unrelated relayer, with `warm` in the access list, and returns the
/// boolean it returns and the gas it used.
fn bool_query(f: &mut Fixture, call: Call, warm: Option<Address>, label: &str) -> (bool, u64) {
    let access_list = AccessList(
        warm.into_iter()
            .map(|address| AccessListItem {
                address,
                storage_keys: Vec::new(),
            })
            .collect(),
    );
    let relayer = signer(9).address();
    let nonce = nonce_of(f, relayer);
    let tx = f.sign_primitive(TempoTransaction {
        access_list,
        ..aa_tx(nonce, vec![call])
    });
    // A precompile failure surfaces as an EVM error, not a revert: report it with the label.
    let output = f
        .evm
        .transact(&tx_env(&tx, relayer))
        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
    let result = output.commit();
    assert!(result.status, "{label}: {result:?}");
    let returned = bool::abi_decode(&result.output).expect(label);
    (returned, result.tx_gas_used())
}

#[test]
fn retired_root_keychain_verifiers_reject() {
    let hash = B256::repeat_byte(0x42);
    for kind in KEY_KINDS {
        // An access key granted by the account: a committed key ID is rejected, an uncommitted one
        // under a committed account is not.
        for (key_committed, account_committed) in [(false, false), (true, false), (false, true)] {
            let expected = !key_committed;
            let label = format!(
                "{kind:?} key committed {key_committed}, account committed {account_committed}"
            );
            let mut f = Fixture::with_parent(false);
            let account = f.account;
            let (key, signature) = keychain_signature(kind, 7, account, hash);
            grant_kind(&mut f, 3, kind, key, false);
            if key_committed {
                retire(&mut f, key);
            }
            if account_committed {
                retire(&mut f, account);
            }
            let call = Verifier::Keychain.call(account, hash, signature);
            assert_eq!(
                bool_query(&mut f, call, None, &label).0,
                expected,
                "{label}"
            );
        }
        // The root key of its own address: the implicit admin, or a stored row of its own.
        for committed in [false, true] {
            let label = format!("{kind:?} root, committed {committed}");
            let mut f = Fixture::with_parent(false);
            let (root, signature) = root_keychain_signature(kind, 1, hash);
            if matches!(kind, SigKind::Secp256k1) {
                assert_eq!(root, f.account, "{label}");
                // The fixture's root signs, so it can also store a non-admin row for itself.
                grant_kind(&mut f, 3, kind, root, false);
            }
            if committed {
                retire(&mut f, root);
            }
            let admin = Verifier::KeychainAdmin.call(root, hash, signature.clone());
            assert_eq!(
                bool_query(&mut f, admin, None, &label).0,
                !committed,
                "admin {label}"
            );
            if matches!(kind, SigKind::Secp256k1) {
                let plain = Verifier::Keychain.call(root, hash, signature);
                assert_eq!(
                    bool_query(&mut f, plain, None, &label).0,
                    !committed,
                    "plain {label}"
                );
            }
        }
    }
}

#[test]
fn retired_root_is_not_an_implicit_admin_key() {
    for committed in [false, true] {
        let mut f = Fixture::with_parent(false);
        let account = f.account;
        // A stored non-admin row of the root's own address never makes it an admin key.
        grant_kind(&mut f, 3, SigKind::Secp256k1, account, false);
        if committed {
            retire(&mut f, account);
        }
        let label = format!("(X, X), committed {committed}");
        let call = is_admin_key_call(account, account);
        assert_eq!(
            bool_query(&mut f, call, None, &label).0,
            !committed,
            "{label}"
        );
        if committed {
            // The retired root falls through to the stored-row lookup, like any other key ID:
            // the same gas as an unknown key's, plus the one warm commitment read.
            let root = is_admin_key_call(account, account);
            let (_, root_gas) = bool_query(&mut f, root, Some(account), &label);
            let unknown = is_admin_key_call(account, signer(8).address());
            let (admin, unknown_gas) = bool_query(&mut f, unknown, Some(account), &label);
            assert!(!admin, "{label}");
            assert_eq!(root_gas, unknown_gas + 100, "{label}");
        }
    }
}

#[test]
fn retired_root_signatures_still_recover_and_keychain_format_is_unchanged() {
    let hash = B256::repeat_byte(0x42);
    let mut f = Fixture::with_parent(false);
    let account = f.account;
    retire(&mut f, account);
    let signature = f.owner.sign_hash_sync(&hash).unwrap();
    let raw: Bytes = PrimitiveSignature::Secp256k1(signature).to_bytes();
    let recover = Call {
        to: TxKind::Call(SIGNATURE_VERIFIER_ADDRESS),
        value: U256::ZERO,
        input: ISignatureVerifier::recoverCall {
            hash,
            signature: raw.clone(),
        }
        .abi_encode()
        .into(),
    };
    let result = send(&mut f, signer(9).address(), vec![recover]);
    assert!(result.status, "{result:?}");
    assert_eq!(
        ISignatureVerifier::recoverCall::abi_decode_returns(&result.output).unwrap(),
        account
    );
    let verify = Call {
        to: TxKind::Call(SIGNATURE_VERIFIER_ADDRESS),
        value: U256::ZERO,
        input: ISignatureVerifier::verifyCall {
            signer: account,
            hash,
            signature: raw,
        }
        .abi_encode()
        .into(),
    };
    assert!(bool_query(&mut f, verify, None, "verify").0);
    // A V2 keychain signature whose inner signature is a configurable account one is not a
    // keychain one, retired key or not, whether the configurable account names the parent account
    // or another.
    let signing_hash = KeychainSignature::signing_hash(hash, account);
    let other_owner = signer(3);
    let other_config = ConfigurableAccountConfig {
        owners: vec![ConfigurableAccountOwner {
            owner: other_owner.address(),
            weight: 1,
        }],
        ..f.config.clone()
    };
    for named in [account, signer(2).address()] {
        let approval =
            configurable_account_approval(named, &other_config, &other_owner, signing_hash);
        let signature = TempoSignature::Keychain(KeychainSignature::new(account, approval));
        for function in [Verifier::Keychain, Verifier::KeychainAdmin] {
            let call = function.call(account, hash, signature.to_bytes());
            let result = send(&mut f, signer(9).address(), vec![call]);
            assert_reverts_with(
                &result,
                ISignatureVerifier::InvalidFormat {},
                &format!("{function:?} naming {named}"),
            );
        }
    }
}

#[test]
fn retired_root_keychain_checks_are_unchanged_before_t14() {
    let hash = B256::repeat_byte(0x42);
    for function in [Verifier::Keychain, Verifier::KeychainAdmin] {
        let admin = matches!(function, Verifier::KeychainAdmin);
        let label = format!("{function:?}");
        // The commitment is seeded the way the pre-T14 authorization-list test does.
        let mut f = Fixture::with_spec(false, TempoHardfork::T13);
        let account = f.account;
        let (key, signature) = keychain_signature(SigKind::Secp256k1, 7, account, hash);
        grant_kind(&mut f, 3, SigKind::Secp256k1, key, admin);
        retire(&mut f, key);
        retire(&mut f, account);
        let call = function.call(account, hash, signature);
        assert!(
            bool_query(&mut f, call, None, &label).0,
            "access key {label}"
        );
    }
    let mut f = Fixture::with_spec(false, TempoHardfork::T13);
    let account = f.account;
    retire(&mut f, account);
    let (root, signature) = root_keychain_signature(SigKind::Secp256k1, 1, hash);
    assert_eq!(root, account);
    let call = Verifier::KeychainAdmin.call(account, hash, signature);
    assert!(bool_query(&mut f, call, None, "root verifier").0);
    let call = is_admin_key_call(account, account);
    assert!(bool_query(&mut f, call, None, "isAdminKey").0);
}

/// Gas of one `check` at `spec` with the address whose commitment it reads listed in the access
/// list (warm) or not (cold). Each check returns true.
fn keychain_check_gas(spec: TempoHardfork, check: KeychainCheck, warm: bool) -> u64 {
    let hash = B256::repeat_byte(0x42);
    let mut f = Fixture::with_spec(false, spec);
    let account = f.account;
    let (key, signature) = keychain_signature(SigKind::Secp256k1, 7, account, hash);
    let (call, warm_account) = match check {
        KeychainCheck::VerifyAccessKey => {
            grant_kind(&mut f, 3, SigKind::Secp256k1, key, false);
            (Verifier::Keychain.call(account, hash, signature), key)
        }
        KeychainCheck::VerifyAdminRoot => {
            let (root, signature) = root_keychain_signature(SigKind::Secp256k1, 1, hash);
            (Verifier::KeychainAdmin.call(root, hash, signature), root)
        }
        KeychainCheck::IsAdminRoot => (is_admin_key_call(account, account), account),
    };
    let label = format!("{check:?} at {spec:?}, warm {warm}");
    let (returned, gas) = bool_query(&mut f, call, warm.then_some(warm_account), &label);
    assert!(returned, "{label}");
    gas
}

#[test]
fn retired_root_keychain_checks_cost_the_commitment_read() {
    for check in [
        KeychainCheck::VerifyAccessKey,
        KeychainCheck::VerifyAdminRoot,
        KeychainCheck::IsAdminRoot,
    ] {
        for warm in [false, true] {
            let before = keychain_check_gas(TempoHardfork::T13, check, warm);
            let after = keychain_check_gas(TempoHardfork::T14, check, warm);
            // Reads follow the normal account-access schedule. An already loaded commitment adds
            // no separate read or surcharge.
            let read = if warm { 100 } else { 2600 };
            assert_eq!(after - before, read, "{check:?}, warm: {warm}");
        }
    }
}

/// The result and gas of `verifyKeychain` for a signature of an access key of the fixture's
/// account whose own address is committed (and so retired at T14 only), checked against that
/// account or, when `mismatched`, against another one than the signature names.
fn retired_key_check(spec: TempoHardfork, mismatched: bool) -> (bool, u64) {
    let hash = B256::repeat_byte(0x42);
    let mut f = Fixture::with_spec(false, spec);
    let account = f.account;
    let (key, signature) = keychain_signature(SigKind::Secp256k1, 7, account, hash);
    grant_kind(&mut f, 3, SigKind::Secp256k1, key, false);
    retire(&mut f, key);
    let checked = if mismatched {
        signer(5).address()
    } else {
        account
    };
    let call = Verifier::Keychain.call(checked, hash, signature);
    bool_query(&mut f, call, None, &format!("mismatched: {mismatched}"))
}

#[test]
fn retired_root_keychain_verifiers_check_in_order() {
    // Cold reads: the key's commitment, and the keychain slot of its grant.
    let (read, lookup) = (2600, 2100);
    // A signature naming another account is rejected before the key's commitment is read: the
    // same result and the same gas as at T13, where no commitment is read at all.
    let after = retired_key_check(TempoHardfork::T14, true);
    assert!(!after.0);
    assert_eq!(after, retired_key_check(TempoHardfork::T13, true));
    // A retired key is rejected before its grant is looked up: the commitment read replaces the
    // grant lookup that accepts the same signature at T13.
    let (accepted, before) = retired_key_check(TempoHardfork::T13, false);
    let (rejected, after) = retired_key_check(TempoHardfork::T14, false);
    assert!(accepted);
    assert!(!rejected);
    assert_eq!(after + lookup, before + read);
}

#[test]
fn retired_root_check_in_admin_caller_reads_the_warm_sender() {
    // A non-admin row of the root's own address is the one way `transaction_key` names the
    // account itself. The commitment read on that branch hits the already loaded sender.
    let gas_at = |spec: TempoHardfork| {
        let mut f = Fixture::with_spec(false, spec);
        let (account, owner) = (f.account, f.owner.clone());
        grant_kind(&mut f, 3, SigKind::Secp256k1, account, false);
        let revoke = Call {
            to: TxKind::Call(ACCOUNT_KEYCHAIN_ADDRESS),
            value: U256::ZERO,
            input: IAccountKeychain::revokeKeyCall { keyId: account }
                .abi_encode()
                .into(),
        };
        let tx = keychain_tx(&f, &owner, 4, vec![revoke]);
        let result = f.run(&tx);
        assert!(result.status, "{spec:?}: {result:?}");
        result.tx_gas_used()
    };
    // The sender is always loaded: one warm account access, nothing more.
    assert_eq!(gas_at(TempoHardfork::T14) - gas_at(TempoHardfork::T13), 100);
}

#[test]
fn native_commitment_only_account_evm_semantics() {
    let target = Address::repeat_byte(0x44);
    let commitment = B256::repeat_byte(0x99);
    // EXTCODEHASH, zero/value CALL, and SELFDESTRUCT must treat the leaf as existing.
    for operation in [0x3f, 0xf1, 0xff] {
        for value in [0u8, 1] {
            let mut gas = Vec::new();
            for (nonce, extension) in [(1, B256::ZERO), (0, commitment), (0, B256::ZERO)] {
                let mut f = Fixture::new();
                let info = AccountInfo {
                    nonce,
                    extension: encode_config_commitment(extension).into(),
                    ..Default::default()
                };
                f.evm.overlay_db_mut().insert_account_info(&target, info);
                let mut code = if operation == 0xf1 {
                    vec![0x5f, 0x5f, 0x5f, 0x5f, 0x60, value, 0x73]
                } else {
                    vec![0x73]
                };
                code.extend_from_slice(target.as_slice());
                match operation {
                    0x3f => code.extend_from_slice(&[0x3f, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]),
                    0xf1 => code.extend_from_slice(&[0x5a, 0xf1, 0x00]),
                    0xff => code.push(0xff),
                    _ => unreachable!(),
                }
                let contract = Address::repeat_byte(0x55);
                let call = f.install_contract(contract, code);
                f.update_account(contract, |info| info.balance = U256::from(value));
                let output = f.run(&f.signed(3, vec![call]));
                assert!(output.status, "{output:?}");
                if operation == 0x3f {
                    let expected = if nonce != 0 || !extension.is_zero() {
                        KECCAK256_EMPTY
                    } else {
                        B256::ZERO
                    };
                    assert_eq!(&output.output, expected.as_slice());
                }
                gas.push(output.tx_gas_used());
                if !extension.is_zero() {
                    let info = f
                        .info(target)
                        .expect("config-only leaf must survive state clearing");
                    assert_eq!(
                        decode_config_commitment(&info.extension, TempoHardfork::T14).unwrap(),
                        commitment
                    );
                    assert_eq!(info.nonce, 0);
                }
            }
            assert_eq!(gas[0], gas[1], "operation={operation:x}, value={value}");
            if operation != 0x3f && value != 0 {
                assert!(gas[2] > gas[1], "only an empty target pays new-account gas");
            }
        }
    }
}

#[test]
fn native_commitment_activation_database_lifecycle() {
    let factory = create_test_provider_factory();
    let mut fixture = Fixture::new();
    let config = activation_config();
    let commitment = fixture.config.commitment().unwrap();
    // The account registers its commitment in block 1.
    let expected = |block: u64| if block == 0 { B256::ZERO } else { commitment };
    let mut roots = Vec::new();
    let mut parent_hash = B256::ZERO;
    for block in 0..=2 {
        let bundle = if block == 0 {
            fixture.genesis_bundle()
        } else {
            let tx = fixture.signed(block + 2, vec![fixture.getter()]);
            let block_env = TempoBlock::uncle(TempoHeader {
                inner: Header {
                    number: block,
                    timestamp: 9 + block,
                    gas_limit: 30_000_000,
                    base_fee_per_gas: Some(0),
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(0),
                    parent_beacon_block_root: Some(B256::ZERO),
                    ..Default::default()
                },
                general_gas_limit: 30_000_000,
                ..Default::default()
            })
            .seal_slow();
            let mut executor = config
                .executor_for_block(
                    InMemoryDB {
                        cache: fixture.evm.overlay_db().cache.clone(),
                        ..Default::default()
                    },
                    &block_env,
                )
                .unwrap();
            assert_eq!(executor.evm().config_spec_id(), TempoHardfork::T14);
            executor.apply_pre_execution_changes().unwrap();
            let recovered = TempoTxEnvelope::AA(tx).with_signer(fixture.account);
            executor
                .execute_transaction(recovered.as_recovered_ref())
                .unwrap();
            let output = executor.finish().unwrap();
            assert!(output.result.receipts[0].success);
            fixture.evm.commit_source(&BundleSource(&output.state));
            output.state
        };
        assert!(
            bundle.state().contains_key(&fixture.account),
            "account missing from executed bundle at {block}"
        );
        let hashed = HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle.state());
        let (root, updates) = factory
            .latest()
            .unwrap()
            .state_root_with_updates(hashed.clone())
            .unwrap();
        let chain_block = EthereumBlock::uncle(Header {
            number: block,
            timestamp: 9 + block,
            state_root: root,
            parent_hash,
            ..Default::default()
        })
        .try_into_recovered()
        .unwrap();
        parent_hash = chain_block.hash();
        let provider = factory.provider_rw().unwrap();
        provider.insert_block(&chain_block).unwrap();
        provider
            .write_state(
                &ExecutionOutcome::new(bundle, vec![vec![]], block, vec![]),
                OriginalValuesKnown::Yes,
                StateWriteConfig::default(),
            )
            .unwrap();
        provider.write_hashed_state(&hashed.into_sorted()).unwrap();
        provider.write_trie_updates(updates).unwrap();
        provider.update_history_indices(block..=block).unwrap();
        provider.commit().unwrap();
        let latest = factory.latest().unwrap();
        let account = latest
            .basic_account(&fixture.account)
            .unwrap()
            .unwrap_or_else(|| panic!("persisted account missing at {block}"));
        assert_eq!(
            decode_config_commitment(&account.extension, TempoHardfork::T14).unwrap(),
            expected(block)
        );
        assert_eq!(latest.state_root(Default::default()).unwrap(), root);
        roots.push(root);
    }
    assert_ne!(roots[0], roots[1]);
    {
        let blockchain = BlockchainProvider::new(factory.clone()).unwrap();
        for block in [0, 1] {
            let historical = blockchain.history_by_block_number(block).unwrap();
            let account = historical.basic_account(&fixture.account).unwrap().unwrap();
            assert_eq!(
                decode_config_commitment(&account.extension, TempoHardfork::T14).unwrap(),
                expected(block)
            );
        }
    }
    let before_second = factory
        .provider()
        .unwrap()
        .get_account_before_block(2, fixture.account)
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_config_commitment(&before_second.info.unwrap().extension, TempoHardfork::T14)
            .unwrap(),
        commitment
    );
    for block in [1, 0] {
        let provider = factory.unwind_provider_rw().unwrap();
        provider.remove_block_and_execution_above(block).unwrap();
        provider.commit().unwrap();
        let latest = factory.latest().unwrap();
        let account = latest.basic_account(&fixture.account).unwrap().unwrap();
        assert_eq!(
            decode_config_commitment(&account.extension, TempoHardfork::T14).unwrap(),
            expected(block)
        );
        assert_eq!(
            latest.state_root(Default::default()).unwrap(),
            roots[usize::try_from(block).unwrap()]
        );
    }
}

/// Exercises the stage's persisted checkpoint codec with real partial storage-trie work.
/// Reopens database transactions, not a process or a full `Stage::execute` pipeline.
#[test]
fn native_commitment_persisted_storage_trie_resume_and_proof() {
    let factory = create_test_provider_factory();
    let mut fixture = Fixture::new();
    let commitment = fixture.config.commitment().unwrap();
    let mut info = fixture.info(fixture.account).unwrap();
    info.extension = encode_config_commitment(commitment).into();
    fixture
        .evm
        .overlay_db_mut()
        .insert_account_info(&fixture.account, info);
    for slot in 0..128u64 {
        fixture.evm.overlay_db_mut().insert_account_storage(
            &fixture.account,
            &U256::from(slot),
            &U256::from(slot + 1),
        );
    }
    let bundle = fixture.genesis_bundle();
    let hashed = HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle.state());
    let expected_root = factory
        .latest()
        .unwrap()
        .state_root(hashed.clone())
        .unwrap();
    {
        let provider = factory.provider_rw().unwrap();
        provider
            .insert_block(
                &EthereumBlock::uncle(Header {
                    state_root: expected_root,
                    ..Default::default()
                })
                .try_into_recovered()
                .unwrap(),
            )
            .unwrap();
        provider
            .write_state(
                &ExecutionOutcome::new(bundle, vec![vec![]], 0, vec![]),
                OriginalValuesKnown::Yes,
                StateWriteConfig::default(),
            )
            .unwrap();
        provider.write_hashed_state(&hashed.into_sorted()).unwrap();
        provider.commit().unwrap();
    }

    let stage = MerkleStage::default_execution();
    let mut storage_resumptions = 0;
    let mut completed_root = None;
    for _ in 0..512 {
        // Drop/commit the previous RW transaction before reading its persisted checkpoint.
        let provider = factory.provider_rw().unwrap();
        let checkpoint = stage.get_execution_checkpoint(&*provider).unwrap();
        if let Some(storage) = checkpoint
            .as_ref()
            .filter(|checkpoint| checkpoint.last_account_key == keccak256(fixture.account))
            .and_then(|checkpoint| checkpoint.storage_root_checkpoint.as_ref())
        {
            storage_resumptions += 1;
            assert_eq!(
                decode_config_commitment(&storage.account_extension, TempoHardfork::T14).unwrap(),
                commitment
            );
        }
        match with_adapter!(&provider, |A| {
            StateRoot::<DatabaseTrieCursorFactory<_, A>, DatabaseHashedCursorFactory<_>>::from_tx(
                provider.tx_ref(),
            )
            .with_intermediate_state(checkpoint.map(Into::into))
            .with_threshold(4)
            .root_with_progress()
        })
        .unwrap()
        {
            StateRootProgress::Progress(state, _, updates) => {
                provider.write_trie_updates(updates).unwrap();
                let mut checkpoint = MerkleCheckpoint::new(
                    0,
                    state.account_root_state.last_hashed_key,
                    state
                        .account_root_state
                        .walker_stack
                        .into_iter()
                        .map(StoredSubNode::from)
                        .collect(),
                    state.account_root_state.hash_builder.into(),
                );
                checkpoint.storage_root_checkpoint = state.storage_root_state.map(|storage| {
                    StorageRootMerkleCheckpoint::new(
                        storage.state.last_hashed_key,
                        storage
                            .state
                            .walker_stack
                            .into_iter()
                            .map(StoredSubNode::from)
                            .collect(),
                        storage.state.hash_builder.into(),
                        storage.account,
                    )
                });
                stage
                    .save_execution_checkpoint(&*provider, Some(checkpoint))
                    .unwrap();
            }
            StateRootProgress::Complete(root, _, updates) => {
                provider.write_trie_updates(updates).unwrap();
                stage.save_execution_checkpoint(&*provider, None).unwrap();
                completed_root = Some(root);
            }
        }
        provider.commit().unwrap();
        if completed_root.is_some() {
            break;
        }
    }
    assert!(
        storage_resumptions > 0,
        "must resume inside an account's nonempty storage trie"
    );
    assert_eq!(completed_root, Some(expected_root));
    let latest = factory.latest().unwrap();
    let proof = latest
        .proof(
            Default::default(),
            fixture.account,
            &[B256::ZERO, B256::with_last_byte(127)],
        )
        .unwrap();
    assert_eq!(
        decode_config_commitment(&proof.info.as_ref().unwrap().extension, TempoHardfork::T14)
            .unwrap(),
        commitment
    );
    assert_eq!(proof.storage_proofs.len(), 2);
    for (key, value) in [
        (B256::ZERO, U256::ONE),
        (B256::with_last_byte(127), U256::from(128)),
    ] {
        assert_eq!(
            proof
                .storage_proofs
                .iter()
                .find(|proof| proof.key == key)
                .unwrap()
                .value,
            value
        );
    }
    proof.verify(expected_root).unwrap();
    // Verification must bind the fifth account field, not merely the ordinary account fields.
    let mut wrong_commitment = proof;
    wrong_commitment.info.as_mut().unwrap().extension =
        encode_config_commitment(B256::repeat_byte(0x99)).into();
    assert!(wrong_commitment.verify(expected_root).is_err());
}

/// The first valid transaction registers the configuration whatever its calls do, keeps the
/// account's balance and storage, and the next transaction runs against the registered
/// commitment. Transactions rejected for too little intrinsic gas or an unpaid fee register
/// nothing.
#[test]
fn native_first_transaction_registers() {
    for caught in [false, true] {
        let mut f = Fixture::new();
        let account = f.account;
        let (slot, value) = (U256::from(7), U256::from(91));
        f.evm
            .overlay_db_mut()
            .insert_account_storage(&account, &slot, &value);
        let before = f.info(account).unwrap();

        let low_gas = configurable_account_signed(
            &f,
            TempoTransaction {
                gas_limit: 21_000,
                ..aa_tx(3, vec![f.getter()])
            },
        );
        let error = handler_rejection(&mut f, &low_gas, account);
        assert!(
            matches!(error, HandlerError::IntrinsicGasTooLow { .. }),
            "{error:?}"
        );
        // The account holds no fee token, so collecting the fee fails after validation.
        let unpaid = configurable_account_signed(
            &f,
            TempoTransaction {
                max_fee_per_gas: 1_000_000_000_000,
                fee_token: Some(PATH_USD_ADDRESS),
                ..aa_tx(3, vec![f.getter()])
            },
        );
        let error = rejection(&mut f, &unpaid, account);
        assert!(
            matches!(error, TempoInvalidTransaction::CollectFeePreTx(_)),
            "{error:?}"
        );
        assert!(f.commitment().is_zero());

        // The child writes slot zero, then reverts: the batch fails, or its parent catches the
        // failed CALL and persists that in its own slot zero.
        let reverter = Address::repeat_byte(0x55);
        let revert = f.install_contract(reverter, bytes!("600160005560006000fd").to_vec());
        let catcher = Address::repeat_byte(0x56);
        let calls = if caught {
            let code = [
                bytes!("6000600060006000600073").as_ref(),
                reverter.as_slice(),
                bytes!("5af11560005500").as_ref(),
            ]
            .concat();
            vec![f.install_contract(catcher, code)]
        } else {
            vec![f.getter(), revert]
        };
        let result = f.run(&f.signed(3, calls));
        assert_eq!(result.status, caught, "caught {caught}: {result:?}");
        assert_eq!(result.logs, []);
        assert_eq!(f.commitment(), f.config.commitment().unwrap());
        let after = f.info(account).unwrap();
        assert_eq!(after.code_hash, CONFIGURABLE_ACCOUNT_CODE_HASH);
        assert_eq!(
            (after.balance, after.nonce),
            (before.balance, before.nonce + 1)
        );
        let mut storage =
            |address, slot| f.evm.overlay_db_mut().get_storage(&address, &slot).unwrap();
        assert_eq!(storage(account, slot), value);
        assert_eq!(storage(reverter, U256::ZERO), U256::ZERO);
        assert_eq!(storage(catcher, U256::ZERO), U256::from(caught));

        let result = f.run(&f.signed(4, vec![f.getter()]));
        assert!(result.status, "{result:?}");
        assert_eq!(
            IConfigurableAccount::getConfigCommitmentCall::abi_decode_returns(&result.output)
                .unwrap(),
            f.config.commitment().unwrap()
        );
    }
}

/// Gas of a first registration of the sender on `lane` (at transaction nonce zero, except on the
/// simulated lane), whose only call is a `CREATE` when `create_first` and a read of the
/// commitment otherwise.
fn sender_registration_gas(lane: NonceLane, create_first: bool, empty_sender: bool) -> BlockGas {
    let mut f = Fixture::new();
    let account = f.account;
    seed_account(&mut f, account, empty_sender);
    let call = if create_first {
        Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: bytes!("00"),
        }
    } else {
        f.getter()
    };
    let tx = lane_tx(&mut f, lane, vec![call]);
    let tx = configurable_account_signed(&f, tx);
    block_gas(&mut f, &tx)
}

#[test]
fn registration_charges_the_new_account_cost_once_for_every_nonce_type() {
    let params = tempo_gas_params(TempoHardfork::T14);
    let new_account = BlockGas {
        regular: params.get(GasId::NewAccountCost),
        state: params.new_account_state_gas(),
    };
    struct Row {
        lane: NonceLane,
        create_first: bool,
        registration_charges_new_account: bool,
    }
    // The `nonce == 0` charge of the protocol lane creates the sender; a 2D `nonce == 0` charge
    // pays the nonce-key slot, so registration still pays. A first-call CREATE from a nonce-zero
    // sender pays the creation on a 2D or expiring lane, so registration adds nothing. A protocol
    // lane without the `nonce == 0` charge has no CREATE charge either, so registration pays.
    for Row {
        lane,
        create_first,
        registration_charges_new_account,
    } in [
        Row {
            lane: NonceLane::Protocol,
            create_first: false,
            registration_charges_new_account: false,
        },
        Row {
            lane: NonceLane::Protocol,
            create_first: true,
            registration_charges_new_account: false,
        },
        Row {
            lane: NonceLane::TwoD,
            create_first: false,
            registration_charges_new_account: true,
        },
        Row {
            lane: NonceLane::Expiring,
            create_first: false,
            registration_charges_new_account: true,
        },
        Row {
            lane: NonceLane::TwoD,
            create_first: true,
            registration_charges_new_account: false,
        },
        Row {
            lane: NonceLane::Expiring,
            create_first: true,
            registration_charges_new_account: false,
        },
        Row {
            lane: NonceLane::ProtocolSimulated,
            create_first: true,
            registration_charges_new_account: true,
        },
    ] {
        let funded = sender_registration_gas(lane, create_first, false);
        let empty = sender_registration_gas(lane, create_first, true);
        let expected = if registration_charges_new_account {
            funded.plus(new_account)
        } else {
            funded
        };
        assert_eq!(empty, expected, "{lane:?}, create first: {create_first}");
    }
}

/// A native or migrated configurable account rotates its owners in a batch whose later calls see
/// the new commitment, and the next transaction in the same block must use the new configuration.
#[test]
fn configurable_account_rotation() {
    for migrated in [false, true] {
        let mut f = if migrated {
            let mut f = Fixture::with_parent(false);
            let owner = f.owner.address();
            f.config = migrate(&mut f, 3, owner);
            f
        } else {
            Fixture::new()
        };
        let (account, nonce, block) = (f.account, 3 + u64::from(migrated), *f.evm.block());
        let next_owner = signer(2);
        let next = ConfigurableAccountConfig {
            version: f.config.version + 1,
            owners: owner_set(vec![next_owner.address()]),
            ..f.config.clone()
        };
        let result = f.run(&f.signed(nonce, vec![Fixture::rotation(&f.config, &next), f.getter()]));
        assert!(result.status, "migrated {migrated}: {result:?}");
        assert_eq!(result.logs.len(), 1);
        assert_eq!(
            IConfigurableAccount::getConfigCommitmentCall::abi_decode_returns(&result.output)
                .unwrap(),
            next.commitment().unwrap()
        );
        assert_eq!(f.commitment(), next.commitment().unwrap());

        let stale = f.signed(nonce + 1, vec![f.getter()]);
        let error = rejection(&mut f, &stale, account);
        assert!(
            matches!(
                error,
                TempoInvalidTransaction::ConfigurableAccount(
                    ConfigurableAccountError::ConfigurationCommitmentMismatch { .. }
                )
            ),
            "migrated {migrated}: {error:?}"
        );
        f.config = next;
        f.owner = next_owner;
        assert!(
            f.run(&f.signed(nonce + 1, vec![f.getter()])).status,
            "migrated {migrated}"
        );
        assert_eq!(
            (f.evm.block().number, f.evm.block().timestamp),
            (block.number, block.timestamp)
        );
    }
}

#[test]
fn simulation_of_registered_account_can_rotate_configuration() {
    let mut f = Fixture::new();
    assert!(f.run(&f.signed(3, vec![f.getter()])).status);
    let next = ConfigurableAccountConfig {
        version: 1,
        ..f.config.clone()
    };
    // RPC simulation signs with a placeholder primitive signature, never an owner witness.
    let tx = f.primitive(4, vec![Fixture::rotation(&f.config, &next)]);
    let output = f
        .evm
        .transact(&simulation_env(&tx, f.account, None))
        .unwrap()
        .detach();
    assert!(output.result.status, "{:?}", output.result);
}

#[test]
fn native_batch_rotation_failures_roll_back_together() {
    for (registered, halt) in [(true, false), (true, true), (false, false), (false, true)] {
        native_batch_rotation_failure(registered, halt);
    }
}

/// Names the row of a table test that is running when it panics.
struct Case(String);

impl Drop for Case {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("failing case: {}", self.0);
        }
    }
}

fn native_batch_rotation_failure(registered: bool, halt: bool) {
    let _case = Case(format!("registered={registered}, halt={halt}"));
    let mut f = Fixture::new();
    let mut nonce = 3;
    if registered {
        let output = f.run(&f.signed(nonce, vec![f.getter()]));
        assert!(output.status);
        nonce += 1;
    }
    let v1 = ConfigurableAccountConfig {
        version: 1,
        owners: vec![ConfigurableAccountOwner {
            owner: signer(2).address(),
            weight: 1,
        }],
        ..f.config.clone()
    };
    let v2 = ConfigurableAccountConfig {
        version: 2,
        owners: vec![ConfigurableAccountOwner {
            owner: signer(3).address(),
            weight: 1,
        }],
        ..f.config.clone()
    };
    let revert = f.install_contract(
        Address::repeat_byte(0x55),
        if halt {
            bytes!("fe").to_vec()
        } else {
            bytes!("60006000fd").to_vec()
        },
    );
    let rotations = vec![
        Fixture::rotation(&f.config, &v1),
        Fixture::rotation(&v1, &v2),
    ];
    let mut calls = rotations.clone();
    calls.push(revert);
    let output = f.run(&f.signed(nonce, calls));
    assert_eq!(output.stop.is_halt(), halt);
    assert_eq!(output.stop.is_revert(), !halt);
    assert_eq!(output.logs, []);
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
    nonce += 1;
    assert_eq!(f.info(f.account).unwrap().nonce, nonce);
    // The original witness remains valid. Each successful update must read the
    // previous call's journaled commitment, not the transaction-start leaf.
    let output = f.run(&f.signed(nonce, rotations));
    assert!(output.status, "{output:?}");
    assert_eq!(output.logs.len(), 2);
    assert_eq!(f.commitment(), v2.commitment().unwrap());
}

/// Each configurable sender check rejects the transaction without consuming its nonce or
/// registering the account, so the owners' approval of the same nonce still runs afterwards.
#[test]
fn configurable_sender_rejections() {
    use ConfigurableAccountError::*;
    let invalid = TempoInvalidTransaction::ConfigurableAccount;
    // An authorization-list entry signed by a configurable account, whatever the hardfork.
    let authorized = |f: &Fixture| {
        let authorization = Authorization {
            chain_id: U256::ONE,
            address: Address::ZERO,
            nonce: 0,
        };
        let approval = configurable_account_approval(
            f.account,
            &f.config,
            &f.owner,
            authorization.signature_hash(),
        );
        f.sign_primitive(TempoTransaction {
            tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
                authorization,
                TempoSignature::ConfigurableAccount(approval),
            )],
            ..aa_tx(3, vec![f.getter()])
        })
    };
    let mut t13 = Fixture::with_spec(true, TempoHardfork::T13);
    let account = t13.account;
    let tx = t13.signed(3, vec![t13.getter()]);
    assert_eq!(
        rejection(&mut t13, &tx, account),
        invalid(UnsupportedContext),
        "0x05 at T13"
    );
    let tx = authorized(&t13);
    let label = "authorization at T13";
    assert_eq!(
        rejection(&mut t13, &tx, account),
        invalid(InvalidSignatureContext),
        "{label}"
    );

    let mut f = Fixture::new();
    let account = f.account;
    let other = signer(9).address();
    seed_account(&mut f, other, false);
    let signed = f.signed(3, vec![f.getter()]);
    // In a signed transaction and in RPC simulation alike, the account the signature names must
    // be the sender.
    let mismatch = invalid(AccountMismatch {
        expected: other,
        actual: account,
    });
    let error = transact_err(&mut f, &simulation_env(&signed, other, None));
    assert_eq!(
        error.external_ref(),
        Some(&mismatch),
        "simulation: {error:?}"
    );
    // A block carries the sender, so execution checks the quorum itself.
    let stranger = configurable_account_signed_by(
        account,
        &f.config,
        &signer(0x77),
        aa_tx(3, vec![f.getter()]),
    );
    for (label, tx, sender, expected) in [
        (
            "authorization",
            authorized(&f),
            account,
            invalid(InvalidSignatureContext),
        ),
        ("names another sender", signed.clone(), other, mismatch),
        (
            "non-owner approval",
            stranger,
            account,
            invalid(Quorum(ConfigurableAccountQuorumError::SignerNotOwner)),
        ),
    ] {
        assert_eq!(rejection(&mut f, &tx, sender), expected, "{label}");
    }
    let info = f.info(account).unwrap();
    let delegated = info
        .clone()
        .with_code(Bytecode::new_eip7702(Address::repeat_byte(0x74)));
    f.evm
        .overlay_db_mut()
        .insert_account_info(&account, delegated);
    assert_eq!(
        rejection(&mut f, &signed, account),
        invalid(InvalidAccount { account }),
        "code"
    );
    f.evm.overlay_db_mut().insert_account_info(&account, info);
    assert!(f.commitment().is_zero());
    let result = f.run(&signed);
    assert!(result.status, "{result:?}");

    // Once registered, another configuration fails with the mismatch the account state reports,
    // worded as the state error is.
    let registered = f.commitment();
    let stale = ConfigurableAccountConfig {
        salt: B256::repeat_byte(0x5b),
        ..f.config.clone()
    };
    let tx = configurable_account_signed_by(account, &stale, &f.owner, aa_tx(4, vec![f.getter()]));
    let error = rejection(&mut f, &tx, account);
    let TempoInvalidTransaction::ConfigurableAccount(ConfigurationCommitmentMismatch {
        expected,
        actual,
    }) = error
    else {
        panic!("{error:?}");
    };
    assert_eq!(expected, registered);
    assert_ne!(actual, registered);
    assert_eq!(
        error.to_string(),
        ConfigurableAccountStateError::CommitmentMismatch { expected, actual }.to_string()
    );
}

/// A configurable-account signature adds its TIP-1114 verification cost `V - 3,000` to intrinsic
/// gas, on top of the first-use account proof and the TIP-1108 registration write.
#[test]
fn native_signature_verification_is_intrinsic_gas() {
    let calls = vec![Call {
        to: TxKind::Call(Address::repeat_byte(0x44)),
        value: U256::ZERO,
        input: Bytes::new(),
    }];
    // The root and the configurable account both hold nonce 3, so no new-account cost differs.
    let mut root = Fixture::with_parent(false);
    let tx = root.primitive(3, calls.clone());
    let primitive = root.run(&tx);
    assert!(primitive.status, "{primitive:?}");

    let mut f = Fixture::new();
    let witness = [alloy_rlp::encode(f.account), alloy_rlp::encode(&f.config)].concat();
    let native = f.run(&f.signed(3, calls));
    assert!(native.status, "{native:?}");
    assert!(!f.commitment().is_zero());

    // K(n) = 30 + 6 * ceil(n / 32); one owner, one secp256k1 approval.
    let keccak = |len: u64| 30 + 6 * len.div_ceil(32);
    let calldata: u64 = witness
        .iter()
        .map(|byte| if *byte == 0 { 4 } else { 16 })
        .sum();
    // V - 3,000: witness calldata, commitment K(75 + 21), digest K(96), approval 3,000 - 3,000.
    let verification = calldata + keccak(75 + 21) + keccak(96);
    // First use: derivation K(68 + 21), plus the registration write, priced like account creation.
    let new_account = tempo_gas_params(TempoHardfork::T14).get(GasId::NewAccountCost);
    let first_use = keccak(68 + 21) + new_account;
    assert_eq!(
        native.tx_gas_used() - primitive.tx_gas_used(),
        verification + first_use
    );
}

/// A threshold above eight is met by eight approvals whose weights reach it.
#[test]
fn native_threshold_above_eight_is_met_by_eight_approvals() {
    let mut f = Fixture::new();
    let mut owners = (1..=9).map(signer).collect::<Vec<_>>();
    owners.sort_by_key(PrivateKeySigner::address);
    let config = ConfigurableAccountConfig {
        salt: B256::repeat_byte(9),
        version: 0,
        threshold: 9,
        owners: owners
            .iter()
            .enumerate()
            .map(|(index, owner)| ConfigurableAccountOwner {
                owner: owner.address(),
                weight: if index == 0 { 2 } else { 1 },
            })
            .collect(),
    };
    let account = config.derive_account().unwrap();
    seed_account(&mut f, account, false);
    let tx = aa_tx(0, vec![f.getter()]);
    let digest = configurable_account_digest(tx.signature_hash(), account, config.version);
    let approvals = owners[..8]
        .iter()
        .map(|owner| PrimitiveSignature::Secp256k1(owner.sign_hash_sync(&digest).unwrap()))
        .collect();
    let signature =
        ConfigurableAccountSignature::try_new(account, config.clone(), approvals).unwrap();
    let result = f.run_as(
        account,
        &tx.into_signed(TempoSignature::ConfigurableAccount(signature)),
    );
    assert!(result.status, "{result:?}");
    assert_eq!(
        decode_config_commitment(&f.info(account).unwrap().extension, TempoHardfork::T14).unwrap(),
        config.commitment().unwrap()
    );
}

/// The hash that the configurable account verification tests approve.
const CONFIGURABLE_ACCOUNT_HASH: B256 = B256::repeat_byte(0x42);

#[derive(Clone, Copy, Debug)]
enum Verdict {
    Valid,
    Invalid,
    Reverts,
}

/// How the verified account is loaded.
#[derive(Clone, Copy, Debug)]
enum Access {
    Cold,
    /// In the access list of the transaction.
    Listed,
    /// An EVM precompile.
    Warm,
}

/// The `verifyConfigurableAccount` call of `signature`.
fn verify_configurable_account_call(
    account: Address,
    hash: B256,
    signature: &ConfigurableAccountSignature,
) -> Call {
    Verifier::ConfigurableAccount.call(
        account,
        hash,
        TempoSignature::ConfigurableAccount(signature.clone()).to_bytes(),
    )
}

/// Checks what `verifyConfigurableAccount` returns for `signature` and the gas of the transaction:
/// its calldata, the ABI input, and the charge for `signature`: the account access, the
/// verification and, while the account is unregistered, the derivation of its address.
fn check_configurable_account_verdict(
    f: &mut Fixture,
    account: Address,
    signature: &ConfigurableAccountSignature,
    registered: bool,
    access: Access,
    verdict: Verdict,
    label: &str,
) {
    let spec = TempoHardfork::T14;
    let params = tempo_gas_params(spec);
    let cold_extra = match access {
        Access::Cold => params.cold_account_additional_cost(),
        Access::Listed | Access::Warm => 0,
    };
    let access_gas = params.get(GasId::WarmStorageReadCost) + cold_extra;
    let initial = if registered {
        0
    } else {
        signature.config().derivation_gas().unwrap()
    };
    let charge = access_gas + signature.verification_gas().unwrap() + initial;

    let call = verify_configurable_account_call(account, CONFIGURABLE_ACCOUNT_HASH, signature);
    let zeros = call.input.iter().filter(|byte| **byte == 0).count() as u64;
    let nonzeros = call.input.len() as u64 - zeros;
    let listed = matches!(access, Access::Listed).then_some(account);
    // Each address in the access list costs 2400 intrinsic gas.
    let access_list = if listed.is_some() { 2_400 } else { 0 };
    // Intrinsic gas: 21000 plus 4 per zero and 16 per non-zero calldata byte. A transaction
    // uses at least its calldata floor: 21000 plus 10 per zero and 40 per non-zero byte.
    let execution = 21_000
        + 4 * zeros
        + 16 * nonzeros
        + access_list
        + input_cost(spec, call.input.len()).unwrap()
        + charge;
    let floor = 21_000 + 10 * zeros + 40 * nonzeros;
    let result = relayed(f, call, 1_000_000, listed);
    assert_eq!(result.tx_gas_used(), execution.max(floor), "{label}: gas");
    match verdict {
        Verdict::Valid | Verdict::Invalid => {
            assert!(result.status, "{label}: {result:?}");
            let valid = matches!(verdict, Verdict::Valid);
            assert_eq!(bool::abi_decode(&result.output).unwrap(), valid, "{label}");
        }
        Verdict::Reverts => {
            assert_reverts_with(&result, ISignatureVerifier::InvalidSignature {}, label)
        }
    }
}

#[test]
fn verify_configurable_account_before_and_after_rotation() {
    let mut f = Fixture::new();
    seed_relayer(&mut f);
    let account = f.account;
    let (cold, listed) = (Access::Cold, Access::Listed);

    // Unregistered: the initial configuration derives the account, and nothing is written.
    let initial =
        configurable_account_approval(account, &f.config, &f.owner, CONFIGURABLE_ACCOUNT_HASH);
    assert_eq!(initial.verification_gas().unwrap(), 4_024);
    let valid = Verdict::Valid;
    check_configurable_account_verdict(
        &mut f,
        account,
        &initial,
        false,
        cold,
        valid,
        "unregistered",
    );
    assert_eq!(f.commitment(), B256::ZERO);
    // An initial configuration is version 0: a later version has no commitment to match.
    let later = ConfigurableAccountConfig {
        version: 1,
        ..f.config.clone()
    };
    let unregistered_later =
        configurable_account_approval(account, &later, &f.owner, CONFIGURABLE_ACCOUNT_HASH);
    let invalid = Verdict::Invalid;
    check_configurable_account_verdict(
        &mut f,
        account,
        &unregistered_later,
        false,
        cold,
        invalid,
        "unregistered later version",
    );

    // Registered by a rotation: only the new configuration matches, and the derivation is not
    // charged any more.
    let next_owner = signer(2);
    let next = ConfigurableAccountConfig {
        version: 1,
        owners: vec![ConfigurableAccountOwner {
            owner: next_owner.address(),
            weight: 1,
        }],
        ..f.config.clone()
    };
    let rotate = f.signed(3, vec![Fixture::rotation(&f.config, &next)]);
    assert!(f.run(&rotate).status);
    assert_eq!(f.commitment(), next.commitment().unwrap());
    let current =
        configurable_account_approval(account, &next, &next_owner, CONFIGURABLE_ACCOUNT_HASH);
    check_configurable_account_verdict(&mut f, account, &current, true, cold, valid, "rotated");
    let label = "rotated, listed account";
    check_configurable_account_verdict(&mut f, account, &current, true, listed, valid, label);
    let stale =
        configurable_account_approval(account, &f.config, &f.owner, CONFIGURABLE_ACCOUNT_HASH);
    let label = "stale configuration";
    check_configurable_account_verdict(&mut f, account, &stale, true, cold, invalid, label);
}

#[test]
fn verify_configurable_account_false_cases_charge_before_they_check() {
    let mut f = Fixture::new();
    seed_relayer(&mut f);
    let account = f.account;
    let (cold, invalid) = (Access::Cold, Verdict::Invalid);
    let valid =
        configurable_account_approval(account, &f.config, &f.owner, CONFIGURABLE_ACCOUNT_HASH);

    // The signature names another account than the one checked.
    let names_other = configurable_account_approval(
        signer(5).address(),
        &f.config,
        &f.owner,
        CONFIGURABLE_ACCOUNT_HASH,
    );
    let label = "account mismatch";
    check_configurable_account_verdict(&mut f, account, &names_other, false, cold, invalid, label);

    // Accounts that cannot be configurable accounts, even when the signature names them: a
    // Tempo and an EVM precompile, a virtual address and a zone portal.
    let mut virtual_address = Address::ZERO;
    virtual_address.0[4..14].fill(0xfd);
    let mut zone_portal = Address::with_last_byte(1);
    zone_portal.0[..12].copy_from_slice(ZONE_PORTAL_PREFIX.as_slice());
    for (address, access) in [
        (CONFIGURABLE_ACCOUNT_ADDRESS, cold),
        (Address::with_last_byte(1), Access::Warm),
        (virtual_address, cold),
        (zone_portal, cold),
    ] {
        let names_address =
            configurable_account_approval(address, &f.config, &f.owner, CONFIGURABLE_ACCOUNT_HASH);
        check_configurable_account_verdict(
            &mut f,
            address,
            &names_address,
            false,
            access,
            invalid,
            &format!("invalid account {address}"),
        );
    }

    // A signature that derives another account than the one it names.
    let other_salt = ConfigurableAccountConfig {
        salt: B256::repeat_byte(1),
        ..f.config.clone()
    };
    let misderived =
        configurable_account_approval(account, &other_salt, &f.owner, CONFIGURABLE_ACCOUNT_HASH);
    let label = "initial account mismatch";
    check_configurable_account_verdict(&mut f, account, &misderived, false, cold, invalid, label);

    // An account with non-marker code is rejected, however well signed.
    let label = "valid";
    check_configurable_account_verdict(&mut f, account, &valid, false, cold, Verdict::Valid, label);
    let info = f.info(account).unwrap();
    f.evm
        .overlay_db_mut()
        .insert_account_info(&account, info.with_code(Bytecode::new_legacy(bytes!("00"))));
    let label = "account with code";
    check_configurable_account_verdict(&mut f, account, &valid, false, cold, invalid, label);
}

#[test]
fn verify_configurable_account_reverts() {
    let mut f = Fixture::new();
    seed_relayer(&mut f);
    let account = f.account;

    // Anything that is not a configurable account signature is a format error.
    let secp =
        PrimitiveSignature::Secp256k1(f.owner.sign_hash_sync(&CONFIGURABLE_ACCOUNT_HASH).unwrap());
    let keychain = TempoSignature::Keychain(KeychainSignature::new(account, secp.clone()));
    for (label, signature) in [
        ("primitive", secp.to_bytes()),
        ("keychain", keychain.to_bytes()),
        ("empty", Bytes::new()),
        ("truncated", Bytes::from_static(&[0x05, 0xc0])),
    ] {
        let call =
            Verifier::ConfigurableAccount.call(account, CONFIGURABLE_ACCOUNT_HASH, signature);
        let result = relayed(&mut f, call, 1_000_000, None);
        assert_reverts_with(&result, ISignatureVerifier::InvalidFormat {}, label);
    }

    // Approvals that do not verify revert after the charge: another hash, and a key outside the
    // configuration.
    let other_hash =
        configurable_account_approval(account, &f.config, &f.owner, B256::repeat_byte(0x43));
    let stranger =
        configurable_account_approval(account, &f.config, &signer(7), CONFIGURABLE_ACCOUNT_HASH);
    for (label, signature) in [("other hash", &other_hash), ("unknown owner", &stranger)] {
        check_configurable_account_verdict(
            &mut f,
            account,
            signature,
            false,
            Access::Cold,
            Verdict::Reverts,
            label,
        );
    }
    assert_eq!(f.commitment(), B256::ZERO);
}

#[test]
fn verify_configurable_account_runs_in_a_staticcall() {
    let mut f = Fixture::new();
    seed_relayer(&mut f);
    let account = f.account;
    // Returns the result of a STATICCALL to the verifier, and reverts with its revert data.
    let code = [
        bytes!("365f5f375f5f365f73").as_ref(),
        SIGNATURE_VERIFIER_ADDRESS.as_slice(),
        bytes!("5afa3d5f5f3e6029573d5ffd5b3d5ff3").as_ref(),
    ]
    .concat();
    let proxy = f.install_contract(Address::repeat_byte(0x56), code);
    let through_proxy = |signature: &ConfigurableAccountSignature, hash| Call {
        input: verify_configurable_account_call(account, hash, signature).input,
        ..proxy.clone()
    };

    let valid =
        configurable_account_approval(account, &f.config, &f.owner, CONFIGURABLE_ACCOUNT_HASH);
    let result = relayed(
        &mut f,
        through_proxy(&valid, CONFIGURABLE_ACCOUNT_HASH),
        1_000_000,
        None,
    );
    assert!(result.status, "{result:?}");
    assert!(bool::abi_decode(&result.output).unwrap());
    // The unregistered account is read, not registered.
    assert_eq!(f.commitment(), B256::ZERO);
    let other_hash = B256::repeat_byte(0x43);
    let result = relayed(&mut f, through_proxy(&valid, other_hash), 1_000_000, None);
    assert_reverts_with(
        &result,
        ISignatureVerifier::InvalidSignature {},
        "other hash",
    );
}

#[test]
fn verify_configurable_account_needs_its_gas() {
    for registered in [false, true] {
        let mut f = Fixture::new();
        seed_relayer(&mut f);
        let account = f.account;
        if registered {
            let next = ConfigurableAccountConfig {
                version: 1,
                ..f.config.clone()
            };
            let rotate = f.signed(3, vec![Fixture::rotation(&f.config, &next)]);
            assert!(f.run(&rotate).status);
            f.config = next;
        }
        let signature =
            configurable_account_approval(account, &f.config, &f.owner, CONFIGURABLE_ACCOUNT_HASH);
        let call = verify_configurable_account_call(account, CONFIGURABLE_ACCOUNT_HASH, &signature);
        // The gas the call uses when it has plenty is exactly what it needs.
        let result = relayed(&mut f, call.clone(), 1_000_000, None);
        assert!(result.status, "{result:?}");
        let needed = result.tx_gas_used();
        let result = relayed(&mut f, call.clone(), needed, None);
        assert!(result.status, "registered: {registered}: {result:?}");
        let result = relayed(&mut f, call, needed - 1, None);
        assert!(
            matches!(result.stop, InstrStop::PrecompileOOG),
            "registered: {registered}: {result:?}"
        );
    }
}

/// Registration exposes the marker immediately and dispatches only the selected read-only hooks.
#[test]
fn configurable_account_marker_dispatch() {
    let mut f = Fixture::new();
    let account = f.account;
    assert_eq!(f.info(account).unwrap().code_hash, KECCAK256_EMPTY);
    let receive = Call {
        to: TxKind::Call(account),
        value: U256::ZERO,
        input: Bytes::new(),
    };
    let result = f.run(&f.signed(3, vec![receive.clone()]));
    assert!(result.status, "{result:?}");
    assert!(result.output.is_empty());
    assert_eq!(
        f.info(account).unwrap().code_hash,
        CONFIGURABLE_ACCOUNT_CODE_HASH
    );
    assert_eq!(
        keccak256(&CONFIGURABLE_ACCOUNT_CODE),
        CONFIGURABLE_ACCOUNT_CODE_HASH
    );
    let hook = IConfigurableAccountShim::onERC721ReceivedCall {
        operator: Address::ZERO,
        from: Address::ZERO,
        tokenId: U256::ONE,
        data: bytes!("1234"),
    }
    .abi_encode();
    // Like a Solidity callee, the hook accepts trailing data and a final `bytes` without its
    // padding, but not a cut into the `bytes` value itself.
    let mut trailing = hook.clone();
    trailing.push(0);
    let unpadded = hook[..hook.len() - 30].to_vec();
    let truncated = hook[..hook.len() - 31].to_vec();
    for (offset, input) in [trailing, unpadded].into_iter().enumerate() {
        let result = f.run(&f.signed(
            4 + offset as u64,
            vec![Call {
                input: input.into(),
                ..receive.clone()
            }],
        ));
        assert!(result.status, "{result:?}");
        assert_eq!(
            result.output,
            IConfigurableAccountShim::onERC721ReceivedCall::abi_encode_returns(
                &IConfigurableAccountShim::onERC721ReceivedCall::SELECTOR.into()
            )
        );
    }
    for (offset, input) in [
        bytes!("01"),
        bytes!("ffffffff"),
        bytes!("01ffc9a7"),
        bytes!("f23a6e61"),
        bytes!("bc197c81"),
        bytes!("1626ba7e"),
        truncated.into(),
    ]
    .into_iter()
    .enumerate()
    {
        let result = f.run(&f.signed(
            6 + offset as u64,
            vec![Call {
                input,
                ..receive.clone()
            }],
        ));
        assert!(result.stop.is_revert(), "{result:?}");
        assert!(result.output.is_empty());
        assert_eq!(
            f.info(account).unwrap().code_hash,
            CONFIGURABLE_ACCOUNT_CODE_HASH
        );
    }
    // An ERC-1271 call without the signature's padding, as Solady sends it, is still answered.
    seed_relayer(&mut f);
    let approval =
        configurable_account_approval(account, &f.config, &f.owner, CONFIGURABLE_ACCOUNT_HASH);
    let signature = TempoSignature::ConfigurableAccount(approval).to_bytes();
    assert_ne!(signature.len() % 32, 0);
    let unpadded_len = 4 + 3 * 32 + signature.len();
    let mut input = IConfigurableAccountShim::isValidSignatureCall {
        hash: CONFIGURABLE_ACCOUNT_HASH,
        signature,
    }
    .abi_encode();
    input.truncate(unpadded_len);
    let call = Call {
        input: input.into(),
        ..receive
    };
    let result = relayed(&mut f, call, 1_000_000, None);
    assert!(result.status, "{result:?}");
    assert_eq!(
        result.output,
        IConfigurableAccountShim::isValidSignatureCall::abi_encode_returns(
            &[0x16, 0x26, 0xba, 0x7e].into()
        )
    );
}

/// A failing verification reverts through the shim exactly as the verifier does.
#[test]
fn configurable_account_erc1271_propagates_verifier_reverts() {
    let mut f = Fixture::new();
    let account = f.account;
    assert!(f.run(&f.signed(3, vec![f.getter()])).status);
    seed_relayer(&mut f);
    let signature =
        configurable_account_approval(account, &f.config, &f.owner, CONFIGURABLE_ACCOUNT_HASH);
    let call = |hash, signature: Bytes| Call {
        to: TxKind::Call(account),
        value: U256::ZERO,
        input: IConfigurableAccountShim::isValidSignatureCall { hash, signature }
            .abi_encode()
            .into(),
    };
    let witness = TempoSignature::ConfigurableAccount(signature).to_bytes();
    let result = relayed(&mut f, call(B256::ZERO, witness), 1_000_000, None);
    assert_reverts_with(
        &result,
        ISignatureVerifier::InvalidSignature {},
        "invalid owner signature",
    );
    let malformed = call(CONFIGURABLE_ACCOUNT_HASH, Bytes::new());
    let result = relayed(&mut f, malformed, 1_000_000, None);
    assert_reverts_with(
        &result,
        ISignatureVerifier::InvalidFormat {},
        "malformed witness",
    );
}

/// The marker is reserved for registered accounts and must remain an invalid opcode elsewhere.
#[test]
fn configurable_marker_is_gated_by_fork_and_commitment() {
    for (spec, committed, code) in [
        (TempoHardfork::T13, true, bytes!("ef")),
        (TempoHardfork::T14, false, bytes!("ef")),
        (TempoHardfork::T14, true, bytes!("ef00")),
    ] {
        let mut f = Fixture::with_spec(false, spec);
        let target = Address::repeat_byte(0x55);
        let call = f.install_contract(target, code.to_vec());
        if committed {
            f.update_account(target, |info| {
                info.extension = encode_config_commitment(B256::repeat_byte(1)).into()
            });
        }
        let result = f.run(&f.primitive(3, vec![call]));
        assert_eq!(result.stop, InstrStop::OpcodeNotFound);
        assert!(result.output.is_empty());
    }
}

/// Calls through the marker use the storage context of the EVM call kind.
#[test]
fn configurable_marker_static_and_delegate_calls() {
    let mut f = Fixture::new();
    let account = f.account;
    assert!(f.run(&f.signed(3, vec![f.getter()])).status);
    seed_relayer(&mut f);
    let approval =
        configurable_account_approval(account, &f.config, &f.owner, CONFIGURABLE_ACCOUNT_HASH);
    let input = IConfigurableAccountShim::isValidSignatureCall {
        hash: CONFIGURABLE_ACCOUNT_HASH,
        signature: TempoSignature::ConfigurableAccount(approval).to_bytes(),
    }
    .abi_encode();
    for kind in [0xfa, 0xf4, 0xf2] {
        let prefix = if kind == 0xf2 {
            bytes!("365f5f375f5f365f5f73")
        } else {
            bytes!("365f5f375f5f365f73")
        };
        let code = [
            prefix.as_ref(),
            account.as_slice(),
            &[0x5a, kind],
            bytes!("503d5f5f3e3d5ff3").as_ref(),
        ]
        .concat();
        let mut call = f.install_contract(Address::repeat_byte(kind), code);
        call.input = input.clone().into();
        let result = relayed(&mut f, call, 1_000_000, None);
        assert!(result.status, "{result:?}");
        let expected = if kind == 0xfa {
            [0x16, 0x26, 0xba, 0x7e]
        } else {
            [0xff; 4]
        };
        assert_eq!(
            result.output,
            IConfigurableAccountShim::isValidSignatureCall::abi_encode_returns(&expected.into())
        );
    }
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
}

#[test]
fn configurable_shim_matches_verifier_gas_and_propagates_oog() {
    let mut f = Fixture::new();
    assert!(f.run(&f.signed(3, vec![f.getter()])).status);
    let account = f.account;
    let approval =
        configurable_account_approval(account, &f.config, &f.owner, CONFIGURABLE_ACCOUNT_HASH);
    let signature = TempoSignature::ConfigurableAccount(approval).to_bytes();
    let direct = ISignatureVerifier::verifyConfigurableAccountCall {
        account,
        hash: CONFIGURABLE_ACCOUNT_HASH,
        signature: signature.clone(),
    }
    .abi_encode();
    let input = IConfigurableAccountShim::isValidSignatureCall {
        hash: CONFIGURABLE_ACCOUNT_HASH,
        signature,
    }
    .abi_encode();
    let direct_gas = in_storage_ctx(&mut f.evm, || {
        let result = SignatureVerifier::new()
            .call(&direct, Address::ZERO)
            .unwrap();
        assert!(
            ISignatureVerifier::verifyConfigurableAccountCall::abi_decode_returns(result.bytes())
                .unwrap()
        );
        StorageCtx.gas_used()
    });
    let shim_gas = in_storage_ctx(&mut f.evm, || {
        assert_eq!(
            shim::call(account, &input).unwrap().bytes(),
            IConfigurableAccountShim::isValidSignatureCall::abi_encode_returns(
                &[0x16, 0x26, 0xba, 0x7e].into()
            )
        );
        StorageCtx.gas_used()
    });
    assert_eq!(shim_gas, direct_gas);
    let mut shim_with_gas = |gas_limit, input: &[u8]| {
        let mut gas = evm2::interpreter::GasTracker::new(gas_limit);
        let mut provider = tempo_precompiles::storage::evm::EvmPrecompileStorageProvider::new(
            &mut f.evm,
            &mut gas,
            TempoHardfork::T14,
            true,
        );
        StorageCtx::enter(&mut provider, || shim::call(account, input))
    };
    assert!(shim_with_gas(shim_gas - 1, &input).is_err_and(|error| error.is_oog()));
    // The receive hook pays for its whole input before decoding it.
    let receive = IConfigurableAccountShim::onERC721ReceivedCall {
        operator: Address::ZERO,
        from: Address::ZERO,
        tokenId: U256::ZERO,
        data: vec![0; 1 << 20].into(),
    }
    .abi_encode();
    let receive_gas = input_cost(TempoHardfork::T14, receive.len()).unwrap();
    assert!(shim_with_gas(receive_gas - 1, &receive).is_err_and(|error| error.is_oog()));
    assert_eq!(
        shim_with_gas(receive_gas, &receive).unwrap().bytes(),
        IConfigurableAccountShim::onERC721ReceivedCall::abi_encode_returns(
            &IConfigurableAccountShim::onERC721ReceivedCall::SELECTOR.into()
        )
    );
}

/// A registered parent with incompatible code cannot act through its access keys.
#[test]
fn native_committed_keychain_parent_with_incompatible_code_is_rejected() {
    let mut f = Fixture::with_parent(false);
    let key = signer(2);
    grant_key(&mut f, 3, &key, 0);
    let root = f.owner.address();
    f.config = migrate(&mut f, 4, root);
    let account = f.account;
    let result = f.run(&keychain_tx(&f, &key, 5, vec![f.getter()]));
    assert!(result.status, "{result:?}");

    f.update_account(account, |info| {
        *info = info
            .clone()
            .with_code(Bytecode::new_eip7702(Address::repeat_byte(0x74)));
    });
    let tx = keychain_tx(&f, &key, 6, vec![f.getter()]);
    assert_eq!(
        rejection(&mut f, &tx, account),
        TempoInvalidTransaction::ConfigurableAccount(ConfigurableAccountError::InvalidAccount {
            account
        })
    );
}

/// A grant naming a configurable delegate that does not sign charges one access to it, cold or
/// access-listed. Used by the delegate in the same transaction, the grant costs as much as one
/// used by a primitive access key: no access beyond the signing key's own.
#[test]
fn native_granted_configurable_account_access_is_charged_once() {
    /// The signer of the transaction that carries or uses the grant.
    #[derive(Clone, Copy)]
    enum GrantUser {
        /// The parent's root key, granting the configurable delegate.
        Root,
        /// The configurable delegate.
        Delegate,
        /// A primitive access key.
        AccessKey,
    }
    let params = tempo_gas_params(TempoHardfork::T14);
    let warm = params.get(GasId::WarmStorageReadCost);
    let cold = warm + params.cold_account_additional_cost();
    let owner = signer(2);
    let config = ConfigurableAccountConfig {
        salt: B256::repeat_byte(2),
        version: 0,
        threshold: 1,
        owners: vec![ConfigurableAccountOwner {
            owner: owner.address(),
            weight: 1,
        }],
    };
    let delegate = config.derive_account().unwrap();
    let access_key = signer(3);
    // Gas of a transaction signed by `user`, with the grant inline or in an earlier transaction.
    let gas = |user: GrantUser, inline: bool, listed: bool| {
        let mut f = Fixture::with_parent(false);
        let parent = f.account;
        let grant = match user {
            GrantUser::Root | GrantUser::Delegate => {
                KeyAuthorization::unrestricted(1, SignatureType::ConfigurableAccount, delegate)
            }
            GrantUser::AccessKey => {
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, access_key.address())
            }
        };
        let approval = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
        let grant = grant.into_signed(PrimitiveSignature::Secp256k1(approval));
        let mut nonce = 3;
        if !inline {
            let tx = f.sign_primitive(TempoTransaction {
                key_authorization: Some(grant.clone()),
                ..aa_tx(nonce, vec![f.getter()])
            });
            let result = f.run(&tx);
            assert!(result.status, "{result:?}");
            nonce += 1;
        }
        let tx = TempoTransaction {
            key_authorization: inline.then_some(grant),
            access_list: AccessList(
                listed
                    .then_some(AccessListItem {
                        address: delegate,
                        storage_keys: Vec::new(),
                    })
                    .into_iter()
                    .collect(),
            ),
            ..aa_tx(nonce, vec![f.getter()])
        };
        let tx = match user {
            GrantUser::Root => f.sign_primitive(tx),
            GrantUser::Delegate => delegate_keychain_signed(tx, parent, delegate, &config, &owner),
            GrantUser::AccessKey => keychain_signed(tx, &access_key, parent),
        };
        let result = f.run(&tx);
        assert!(result.status, "{result:?}");
        // Before the minimum-gas floor, which hides small differences.
        result.total_gas_spent
    };
    // Listing the delegate costs 2400 and turns its one cold access into a warm one.
    assert_eq!(
        gas(GrantUser::Root, true, false) + 2_400 + warm,
        gas(GrantUser::Root, true, true) + cold
    );
    // Using the grant in the transaction that carries it adds the same for both keys.
    assert_eq!(
        gas(GrantUser::Delegate, true, false) + gas(GrantUser::AccessKey, false, false),
        gas(GrantUser::AccessKey, true, false) + gas(GrantUser::Delegate, false, false)
    );
}
