//! TIP-1131 ZK signatures, validated through the EVM handler.

use super::*;
use crate::{signature_gas::zk_signature_verification_gas, zk::ZkSignatureError};
use alloy_consensus::transaction::SignerRecoverable;
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use revm::context::result::EVMError;
use tempo_precompiles::key_publisher::{
    ACTIVE, IKeyPublisher, KEY_PUBLISHER_ADDRESS, compute_publisher_id, key_valid_until_slot,
};
use tempo_primitives::{
    AASigned,
    transaction::{
        KeyAuthorizationSignature, SignedKeyAuthorization, ZK_NAMESPACE_OIDC,
        ZK_SCHEME_OIDC_RS256_V1, ZkProof, ZkSignature, zk_address,
    },
};
use tempo_zk::{
    SignatureStatement,
    test_utils::{TestTrapdoor, install_test_verifying_key},
};

const NOW: u64 = 1_700_000_000;
const ISSUER: B256 = B256::with_last_byte(2);
const KEY_HASH: B256 = B256::with_last_byte(3);
const ADDRESS_SEED: B256 = B256::with_last_byte(4);

/// An OIDC identity that signs with a fresh secp256k1 access key and test proofs.
struct Identity {
    trapdoor: TestTrapdoor,
    access_key: PrivateKeySigner,
    publisher_id: B256,
    issued_at: u64,
    valid_until: u64,
}

impl Identity {
    fn new(publisher_id: B256) -> Self {
        Self {
            trapdoor: install_test_verifying_key(ZK_SCHEME_OIDC_RS256_V1),
            access_key: PrivateKeySigner::random(),
            publisher_id,
            issued_at: NOW - 10,
            valid_until: NOW + 500,
        }
    }

    fn address(&self) -> Address {
        zk_address(
            ZK_NAMESPACE_OIDC,
            &self.publisher_id,
            &ISSUER,
            &ADDRESS_SEED,
        )
    }

    fn statement(&self) -> SignatureStatement {
        SignatureStatement {
            scheme: ZK_SCHEME_OIDC_RS256_V1,
            issuer: ISSUER,
            key_hash: KEY_HASH,
            address_seed: ADDRESS_SEED,
            access_key_id: self.access_key.address(),
            valid_until: self.valid_until,
            issued_at: self.issued_at,
        }
    }

    /// Returns a ZK signature over the context digest `d`, carrying `proof`.
    fn sign_with_proof(&self, d: B256, proof: [u8; 256]) -> ZkSignature {
        let mut signature = ZkSignature::new(
            ZK_SCHEME_OIDC_RS256_V1,
            self.publisher_id,
            ISSUER,
            KEY_HASH,
            ADDRESS_SEED,
            self.issued_at,
            self.valid_until,
            ZkProof::from(proof),
            PrimitiveSignature::default(),
        );
        let hash = signature.signing_hash(&d);
        signature.access_key_signature =
            PrimitiveSignature::Secp256k1(self.access_key.sign_hash_sync(&hash).unwrap());
        signature
    }

    fn sign(&self, d: B256) -> ZkSignature {
        let input = self.statement().public_input().unwrap();
        self.sign_with_proof(d, self.trapdoor.prove(&input, 1))
    }

    fn sign_tx(&self, tx: TempoTransaction) -> AASigned {
        let signature = self.sign(tx.signature_hash());
        tx.into_signed(TempoSignature::from(signature))
    }

    /// Signs `tx` with the access key as a V2 keychain signature for this identity.
    fn sign_tx_with_access_key(&self, tx: TempoTransaction) -> AASigned {
        let hash = KeychainSignature::signing_hash(tx.signature_hash(), self.address());
        let signature = self.access_key.sign_hash_sync(&hash).unwrap();
        tx.into_signed(TempoSignature::Keychain(KeychainSignature::new(
            self.address(),
            PrimitiveSignature::Secp256k1(signature),
        )))
    }
}

fn evm_at(spec: TempoHardfork, identity: &Identity) -> TempoEvm<InMemoryDB, ()> {
    let mut evm = create_funded_evm_at_spec_with_timestamp(identity.address(), NOW, spec);
    list_key(&mut evm, identity.publisher_id, ACTIVE);
    evm
}

fn list_key(evm: &mut TempoEvm<InMemoryDB, ()>, publisher_id: B256, valid_until: u64) {
    evm.ctx
        .db_mut()
        .insert_account_storage(
            KEY_PUBLISHER_ADDRESS,
            key_valid_until_slot(publisher_id, ISSUER, KEY_HASH),
            U256::from(valid_until),
        )
        .unwrap();
}

fn tx_env(signed: &AASigned) -> TempoTxEnv {
    TempoTxEnv::from_recovered_tx(signed, signed.recover_signer().unwrap())
}

fn zk_error<T: core::fmt::Debug, DB: core::fmt::Debug>(
    result: Result<T, EVMError<DB, TempoInvalidTransaction>>,
) -> ZkSignatureError {
    match result {
        Err(EVMError::Transaction(TempoInvalidTransaction::ZkSignature(err))) => err,
        other => panic!("expected a ZK signature error, got {other:?}"),
    }
}

fn identity_call() -> TempoTransaction {
    TxBuilder::new().call_identity(&[1, 2, 3]).build()
}

#[test]
fn zk_signed_transaction_executes() -> eyre::Result<()> {
    let identity = Identity::new(B256::repeat_byte(0x11));
    let mut evm = evm_at(TempoHardfork::T14, &identity);

    let signed = identity.sign_tx(identity_call());
    // Sender recovery derives the address without any cryptography.
    assert_eq!(signed.recover_signer()?, identity.address());

    let result = evm.transact_commit(tx_env(&signed))?;
    assert!(result.is_success());
    Ok(())
}

#[test]
fn zk_signatures_are_rejected_before_t14() {
    let identity = Identity::new(B256::repeat_byte(0x11));
    let mut evm = evm_at(TempoHardfork::T13, &identity);
    let signed = identity.sign_tx(identity_call());
    assert_eq!(
        zk_error(evm.transact(tx_env(&signed))),
        ZkSignatureError::NotActive
    );
}

#[test]
fn zk_signatures_need_an_active_issuer_key() {
    let identity = Identity::new(B256::repeat_byte(0x11));
    let signed = identity.sign_tx(identity_call());

    for (valid_until, accepted) in [(0, false), (NOW - 1, false), (NOW, true), (ACTIVE, true)] {
        let mut evm = evm_at(TempoHardfork::T14, &identity);
        list_key(&mut evm, identity.publisher_id, valid_until);
        let result = evm.transact(tx_env(&signed));
        if accepted {
            assert!(
                result.unwrap().result.is_success(),
                "valid until {valid_until}"
            );
        } else {
            assert_eq!(zk_error(result), ZkSignatureError::KeyInactive);
        }
    }
}

#[test]
fn zk_signatures_enforce_time_bounds() {
    let cases = [
        // Expired one second before the block.
        (NOW - 500, NOW - 1, Some("expired")),
        (NOW - 500, NOW, None),
        // Issued up to 60 seconds after the block.
        (NOW + 60, NOW + 600, None),
        (NOW + 61, NOW + 600, Some("future")),
        // At most the scheme's 600-second window.
        (NOW - 10, NOW + 590, None),
        (NOW - 10, NOW + 591, Some("window")),
    ];
    for (issued_at, valid_until, error) in cases {
        let mut identity = Identity::new(B256::repeat_byte(0x11));
        identity.issued_at = issued_at;
        identity.valid_until = valid_until;
        let mut evm = evm_at(TempoHardfork::T14, &identity);
        let result = evm.transact(tx_env(&identity.sign_tx(identity_call())));
        match error {
            None => assert!(
                result.unwrap().result.is_success(),
                "{issued_at} {valid_until}"
            ),
            Some("expired") => {
                assert!(matches!(zk_error(result), ZkSignatureError::Expired { .. }))
            }
            Some("future") => {
                assert!(matches!(
                    zk_error(result),
                    ZkSignatureError::IssuedInFuture { .. }
                ))
            }
            Some(_) => assert_eq!(zk_error(result), ZkSignatureError::WindowTooLong),
        }
    }
}

#[test]
fn zk_signatures_reject_bad_proofs_and_replays() {
    let identity = Identity::new(B256::repeat_byte(0x11));
    let tx = identity_call();
    let d = tx.signature_hash();

    // A proof of a different statement.
    let mut other = identity.statement();
    other.valid_until -= 1;
    let wrong = identity.trapdoor.prove(&other.public_input().unwrap(), 1);
    let signed = tx
        .clone()
        .into_signed(TempoSignature::from(identity.sign_with_proof(d, wrong)));
    let mut evm = evm_at(TempoHardfork::T14, &identity);
    assert_eq!(
        zk_error(evm.transact(tx_env(&signed))),
        ZkSignatureError::Invalid
    );

    // A second valid proof of the same statement, swapped in after the access key signed: the
    // access key signs the proof bytes, so a re-randomized or replaced proof fails.
    let input = identity.statement().public_input().unwrap();
    let mut signature = identity.sign(d);
    signature.proof = ZkProof::from(identity.trapdoor.prove(&input, 2));
    let signed = tx.into_signed(TempoSignature::from(signature));
    assert_eq!(
        zk_error(evm.transact(tx_env(&signed))),
        ZkSignatureError::Invalid
    );

    // A signature for one transaction reused on another.
    let signature = identity.sign(d);
    let replayed = TxBuilder::new()
        .call_identity(&[9])
        .build()
        .into_signed(TempoSignature::from(signature));
    assert_eq!(
        zk_error(evm.transact(tx_env(&replayed))),
        ZkSignatureError::Invalid
    );
}

#[test]
fn zk_signatures_cannot_sign_authorization_list_entries() {
    let identity = Identity::new(B256::repeat_byte(0x11));
    let key_pair = P256KeyPair::random();
    let authorization = Authorization {
        chain_id: U256::from(1),
        address: Address::repeat_byte(0x42),
        nonce: 0,
    };
    let entry = TempoSignedAuthorization::new_unchecked(
        authorization.clone(),
        TempoSignature::from(identity.sign(authorization.signature_hash())),
    );
    assert!(entry.recover_authority().is_err());

    let tx = TxBuilder::new()
        .call_identity(&[1])
        .authorization(entry)
        .build();
    let signed = key_pair.sign_tx(tx).unwrap();
    let mut evm =
        create_funded_evm_at_spec_with_timestamp(key_pair.address, NOW, TempoHardfork::T14);
    assert_eq!(
        zk_error(evm.transact(tx_env(&signed))),
        ZkSignatureError::NotAccepted
    );
}

#[test]
fn zk_key_authorization_registers_an_access_key() -> eyre::Result<()> {
    let identity = Identity::new(B256::repeat_byte(0x11));
    let mut evm = evm_at(TempoHardfork::T14, &identity);

    // The first transaction carries a key authorization signed with a ZK signature, and is
    // signed by the access key the sign-in committed to.
    let key_authorization =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, identity.access_key.address());
    let signature = identity.sign(key_authorization.signature_hash());
    let key_authorization = SignedKeyAuthorization::new(
        key_authorization,
        KeyAuthorizationSignature::from(signature),
    );
    let tx = TxBuilder::new()
        .call_identity(&[1])
        .key_authorization(key_authorization)
        .build();
    let signed = identity.sign_tx_with_access_key(tx);
    assert_eq!(signed.recover_signer()?, identity.address());
    assert!(evm.transact_commit(tx_env(&signed))?.is_success());

    // Later transactions are signed by the access key alone, with no proof.
    let tx = TxBuilder::new().call_identity(&[2]).nonce(1).build();
    let signed = identity.sign_tx_with_access_key(tx);
    assert!(evm.transact_commit(tx_env(&signed))?.is_success());
    Ok(())
}

#[test]
fn zk_key_authorization_must_sign_for_the_sender() {
    let identity = Identity::new(B256::repeat_byte(0x11));
    let key_pair = P256KeyPair::random();
    let key_authorization =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, identity.access_key.address());
    let signature = identity.sign(key_authorization.signature_hash());
    let tx = TxBuilder::new()
        .call_identity(&[1])
        .key_authorization(SignedKeyAuthorization::new(key_authorization, signature))
        .build();
    let signed = key_pair.sign_tx(tx).unwrap();
    let mut evm = evm_at(TempoHardfork::T14, &identity);
    fund_account(&mut evm, key_pair.address);
    assert_eq!(
        zk_error(evm.transact(tx_env(&signed))),
        ZkSignatureError::SignerNotSender
    );
}

#[test]
fn revocation_earlier_in_the_block_applies() -> eyre::Result<()> {
    let owner = P256KeyPair::random();
    let salt = B256::repeat_byte(5);
    let identity = Identity::new(compute_publisher_id(owner.address, salt));
    let mut evm = create_funded_evm_at_spec_with_timestamp(owner.address, NOW, TempoHardfork::T14);
    fund_account(&mut evm, identity.address());

    let create = IKeyPublisher::createPublisherCall {
        salt,
        owner: owner.address,
        initialKeys: vec![IKeyPublisher::IssuerKeys {
            issuer: ISSUER,
            keyHashes: vec![KEY_HASH],
        }],
    };
    let tx = TxBuilder::new()
        .call(KEY_PUBLISHER_ADDRESS, &create.abi_encode())
        .gas_limit(5_000_000)
        .build();
    assert!(
        evm.transact_commit(tx_env(&owner.sign_tx(tx)?))?
            .is_success()
    );

    let signed = identity.sign_tx(identity_call());
    assert!(evm.transact_commit(tx_env(&signed))?.is_success());

    let revoke = IKeyPublisher::revokeKeyCall {
        publisherId: identity.publisher_id,
        issuer: ISSUER,
        keyHash: KEY_HASH,
    };
    let tx = TxBuilder::new()
        .call(KEY_PUBLISHER_ADDRESS, &revoke.abi_encode())
        .gas_limit(5_000_000)
        .nonce(1)
        .build();
    assert!(
        evm.transact_commit(tx_env(&owner.sign_tx(tx)?))?
            .is_success()
    );

    let signed = identity.sign_tx(TxBuilder::new().call_identity(&[1]).nonce(1).build());
    assert_eq!(
        zk_error(evm.transact(tx_env(&signed))),
        ZkSignatureError::KeyInactive
    );
    Ok(())
}

#[test]
fn zk_signatures_pay_verification_gas() -> eyre::Result<()> {
    let identity = Identity::new(B256::repeat_byte(0x11));
    let tx = identity_call();
    let zk_env = tx_env(&identity.sign_tx(tx.clone()));
    let secp = PrivateKeySigner::random();
    let secp_signed = tx.into_signed(TempoSignature::from(secp.sign_hash_sync(&B256::ZERO)?));
    let secp_env = TempoTxEnv::from_recovered_tx(&secp_signed, secp.address());

    let gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T14, false);
    let intrinsic = |env: &TempoTxEnv| {
        crate::calculate_aa_batch_intrinsic_gas(
            env.tempo_tx_env.as_ref().unwrap(),
            &gas_params,
            None::<core::iter::Empty<&alloy_eips::eip2930::AccessListItem>>,
            TempoHardfork::T14,
        )
        .unwrap()
        .initial_total_gas()
    };
    let signature = zk_env
        .tempo_tx_env
        .as_ref()
        .unwrap()
        .signature
        .as_zk()
        .unwrap();
    assert_eq!(
        intrinsic(&zk_env) - intrinsic(&secp_env),
        zk_signature_verification_gas(signature)
    );
    Ok(())
}
