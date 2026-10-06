//! Executes transactions signed with real OIDC RS256 v1 circuit proofs, verified with the
//! development chain's genesis key.

use alloy_consensus::transaction::SignerRecoverable;
use alloy_evm::FromRecoveredTx;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, hex};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use revm::{
    Context, ExecuteCommitEvm, MainContext,
    context::{CfgEnv, result::EVMError},
    database::{CacheDB, EmptyDB},
    state::AccountInfo,
};
use serde_json::Value;
use tempo_chainspec::{hardfork::TempoHardfork, spec::DEV};
use tempo_precompiles::key_publisher::{ACTIVE, KEY_PUBLISHER_ADDRESS, key_valid_until_slot};
use tempo_primitives::{
    AASigned, TempoSignature, TempoTransaction,
    transaction::{
        Call, PrimitiveSignature, ZK_NAMESPACE_OIDC, ZK_SCHEME_OIDC_RS256_V1, ZkProof, ZkSignature,
        zk_address,
    },
};
use tempo_revm::{
    TempoBlockEnv, TempoEvm, TempoInvalidTransaction, TempoTxEnv,
    gas_params::tempo_gas_params_with_amsterdam, zk::ZkSignatureError,
};

/// Written by `circuits/oidc-rs256/scripts/vectors.ts`.
const VECTORS: &str = include_str!("../../zk/testdata/oidc_rs256_v1_dev.json");

/// The first account of the test mnemonic; the vectors' proofs commit to it as the access key.
const ACCESS_KEY: B256 = B256::new(hex!(
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
));

const PUBLISHER_ID: B256 = B256::repeat_byte(0x11);

#[test]
fn dev_genesis_key_accepts_circuit_proofs() -> eyre::Result<()> {
    tempo_evm::set_zk_verifying_keys(&DEV)?;
    let vectors: Value = serde_json::from_str(VECTORS)?;
    let identity = Identity::new(&vectors["signature"])?;

    let mut evm = identity.evm();
    let signed = identity.sign(transaction(0), identity.proof);
    assert_eq!(signed.recover_signer()?, identity.address());
    assert!(evm.transact_commit(tx_env(&signed))?.is_success());

    // The message-form proof commits to a digest, not this access key and expiry.
    let message_proof = proof(&vectors["message"]["proof"]);
    let signed = identity.sign(transaction(1), message_proof);
    assert_eq!(
        zk_error(evm.transact_commit(tx_env(&signed))),
        ZkSignatureError::Invalid
    );

    let mut tampered = identity.proof;
    tampered[255] ^= 1;
    let signed = identity.sign(transaction(1), tampered);
    assert!(evm.transact_commit(tx_env(&signed)).is_err());
    Ok(())
}

/// The OIDC identity of the vectors' signature-form statement.
struct Identity {
    issuer: B256,
    key_hash: B256,
    address_seed: B256,
    issued_at: u64,
    valid_until: u64,
    proof: [u8; 256],
    access_key: PrivateKeySigner,
}

impl Identity {
    fn new(statement: &Value) -> eyre::Result<Self> {
        let access_key = PrivateKeySigner::from_bytes(&ACCESS_KEY)?;
        assert_eq!(
            access_key.address(),
            Address::from_slice(&bytes(&statement["accessKeyId"]))
        );
        Ok(Self {
            issuer: word(&statement["issuer"]),
            key_hash: word(&statement["keyHash"]),
            address_seed: word(&statement["addressSeed"]),
            issued_at: statement["issuedAt"].as_u64().unwrap(),
            valid_until: statement["validUntil"].as_u64().unwrap(),
            proof: proof(&statement["proof"]),
            access_key,
        })
    }

    fn address(&self) -> Address {
        zk_address(
            ZK_NAMESPACE_OIDC,
            &PUBLISHER_ID,
            &self.issuer,
            &self.address_seed,
        )
    }

    /// An EVM at the dev chain's latest hardfork, inside the proof's validity window, with the
    /// issuer key active and the identity's account funded.
    fn evm(&self) -> TempoEvm<CacheDB<EmptyDB>, ()> {
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = TempoHardfork::T14;
        cfg.gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T14, false);
        cfg.chain_id = DEV.inner.chain.id();

        let mut block = TempoBlockEnv::default();
        block.inner.timestamp = U256::from(self.issued_at + 100);

        let mut db = CacheDB::new(EmptyDB::new());
        db.insert_account_info(
            self.address(),
            AccountInfo {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        db.insert_account_storage(
            KEY_PUBLISHER_ADDRESS,
            key_valid_until_slot(PUBLISHER_ID, self.issuer, self.key_hash),
            U256::from(ACTIVE),
        )
        .unwrap();

        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(block)
            .with_cfg(cfg)
            .with_tx(Default::default());
        TempoEvm::new(ctx, ())
    }

    /// Signs `tx` with a ZK signature carrying `proof`.
    fn sign(&self, tx: TempoTransaction, proof: [u8; 256]) -> AASigned {
        let mut signature = ZkSignature::new(
            ZK_SCHEME_OIDC_RS256_V1,
            PUBLISHER_ID,
            self.issuer,
            self.key_hash,
            self.address_seed,
            self.issued_at,
            self.valid_until,
            ZkProof::from(proof),
            PrimitiveSignature::default(),
        );
        let hash = signature.signing_hash(&tx.signature_hash());
        signature.access_key_signature =
            PrimitiveSignature::Secp256k1(self.access_key.sign_hash_sync(&hash).unwrap());
        tx.into_signed(TempoSignature::from(signature))
    }
}

/// A call to the identity precompile.
fn transaction(nonce: u64) -> TempoTransaction {
    TempoTransaction {
        chain_id: DEV.inner.chain.id(),
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TxKind::Call(Address::with_last_byte(4)),
            value: U256::ZERO,
            input: Bytes::from_static(&[1, 2, 3]),
        }],
        nonce,
        ..Default::default()
    }
}

fn tx_env(signed: &AASigned) -> TempoTxEnv {
    TempoTxEnv::from_recovered_tx(signed, signed.recover_signer().unwrap())
}

fn zk_error<T: core::fmt::Debug, E: core::fmt::Debug>(
    result: Result<T, EVMError<E, TempoInvalidTransaction>>,
) -> ZkSignatureError {
    match result {
        Err(EVMError::Transaction(TempoInvalidTransaction::ZkSignature(error))) => error,
        other => panic!("expected a ZK signature error, got {other:?}"),
    }
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn word(value: &Value) -> B256 {
    B256::from_slice(&bytes(value))
}

fn proof(value: &Value) -> [u8; 256] {
    bytes(value).try_into().unwrap()
}
