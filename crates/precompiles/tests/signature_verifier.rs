//! Keychain signature verification against retired roots and stored key types.

use alloy::primitives::{Address, B256, Bytes};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use tempo_chainspec::hardfork::TempoHardfork::{self, T13, T14};
use tempo_contracts::precompiles::IAccountKeychain::{
    KeyRestrictions,
    SignatureType::{self, P256, Secp256k1},
};
use tempo_precompiles::{
    account_keychain::AccountKeychain,
    signature_verifier::SignatureVerifier,
    storage::{ConfigCommitmentWriteGas, StorageCtx, hashmap::HashMapStorageProvider},
};
use tempo_primitives::transaction::tt_signature::{
    KeychainSignature, P256SignatureWithPreHash, PrimitiveSignature, TempoSignature,
    derive_p256_address, normalize_p256_s,
};

use Committed::{Account, Nobody, Signer};

const HASH: B256 = B256::repeat_byte(0x42);
const COMMITMENT: B256 = B256::repeat_byte(0x11);

/// A signing key of one of the primitive signature types.
enum Key {
    Secp256k1(PrivateKeySigner),
    P256(SigningKey),
}

impl Key {
    fn random(signature_type: SignatureType) -> Self {
        match signature_type {
            SignatureType::Secp256k1 => Self::Secp256k1(PrivateKeySigner::random()),
            SignatureType::P256 => Self::P256(SigningKey::random(&mut OsRng)),
            other => panic!("unsupported test key type {other:?}"),
        }
    }

    fn p256_coordinates(key: &SigningKey) -> (B256, B256) {
        let point = key.verifying_key().to_encoded_point(false);
        (
            B256::from_slice(point.x().unwrap()),
            B256::from_slice(point.y().unwrap()),
        )
    }

    /// The address a signature by this key recovers to.
    fn address(&self) -> Address {
        match self {
            Self::Secp256k1(signer) => signer.address(),
            Self::P256(key) => {
                let (x, y) = Self::p256_coordinates(key);
                derive_p256_address(&x, &y)
            }
        }
    }

    fn sign(&self, digest: B256) -> PrimitiveSignature {
        match self {
            Self::Secp256k1(signer) => {
                PrimitiveSignature::Secp256k1(signer.sign_hash_sync(&digest).unwrap())
            }
            Self::P256(key) => {
                let (pub_key_x, pub_key_y) = Self::p256_coordinates(key);
                let (signature, _) = key.sign_prehash_recoverable(digest.as_slice()).unwrap();
                PrimitiveSignature::P256(P256SignatureWithPreHash {
                    r: B256::from_slice(&signature.r().to_bytes()),
                    s: normalize_p256_s(&signature.s().to_bytes()).unwrap(),
                    pub_key_x,
                    pub_key_y,
                    pre_hash: false,
                })
            }
        }
    }
}

/// An access-key grant from the account to the signing key.
#[derive(Clone, Copy, Debug)]
struct Grant {
    stored_type: SignatureType,
    admin: bool,
}

/// Which address has a configuration commitment.
#[derive(Clone, Copy, Debug)]
enum Committed {
    Nobody,
    Signer,
    Account,
}

const fn key(stored_type: SignatureType) -> Option<Grant> {
    Some(Grant {
        stored_type,
        admin: false,
    })
}

const fn admin_key(stored_type: SignatureType) -> Option<Grant> {
    Some(Grant {
        stored_type,
        admin: true,
    })
}

/// Storage at T14 with `grant` registered and a commitment on each of `committed`, switched to
/// `spec` afterwards so that earlier forks can see state that only T14 can write.
fn storage_at(
    spec: TempoHardfork,
    account: Address,
    key_id: Address,
    grant: Option<Grant>,
    committed: &[Address],
) -> HashMapStorageProvider {
    let mut storage = HashMapStorageProvider::new_with_spec(1, T14);
    StorageCtx::enter(&mut storage, || {
        let mut keychain = AccountKeychain::new();
        keychain.initialize().unwrap();
        keychain.set_tx_origin(account).unwrap();
        match grant {
            Some(Grant {
                stored_type,
                admin: true,
            }) => keychain
                .authorize_admin_key(account, key_id, stored_type, None)
                .unwrap(),
            Some(Grant {
                stored_type,
                admin: false,
            }) => keychain
                .authorize_key(
                    account,
                    key_id,
                    stored_type,
                    KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: Vec::new(),
                        allowAnyCalls: true,
                        allowedCalls: Vec::new(),
                    },
                    None,
                )
                .unwrap(),
            None => {}
        }
        for address in committed {
            StorageCtx
                .set_config_commitment(*address, COMMITMENT, ConfigCommitmentWriteGas::Intrinsic)
                .unwrap();
        }
    });
    storage.set_spec(spec);
    storage
}

/// A keychain signature over [`HASH`] by `key` for `account`.
fn keychain_signature(key: &Key, account: Address) -> Bytes {
    TempoSignature::Keychain(KeychainSignature::new(
        account,
        key.sign(KeychainSignature::signing_hash(HASH, account)),
    ))
    .to_bytes()
}

#[test]
fn keychain_verification_by_retired_roots_and_stored_key_types() {
    /// A keychain signature by a signer of `signer_type` at `spec`, and whether
    /// `verify_keychain` and `verify_keychain_admin` accept it.
    struct Case {
        spec: TempoHardfork,
        signer_type: SignatureType,
        /// The grant to the signer; none when the signer is the account's root key.
        grant: Option<Grant>,
        committed: Committed,
        expected: (bool, bool),
    }

    const fn case(
        spec: TempoHardfork,
        signer_type: SignatureType,
        grant: Option<Grant>,
        committed: Committed,
        expected: (bool, bool),
    ) -> Case {
        Case {
            spec,
            signer_type,
            grant,
            committed,
            expected,
        }
    }
    let cases = [
        // The root is implicitly admin, but is not an access key.
        case(T14, Secp256k1, None, Nobody, (false, true)),
        case(T14, Secp256k1, None, Account, (false, false)),
        case(T13, Secp256k1, None, Account, (false, true)),
        // An access key; a commitment on its own address retires it from T14.
        case(T14, Secp256k1, key(Secp256k1), Nobody, (true, false)),
        case(T14, Secp256k1, admin_key(Secp256k1), Nobody, (true, true)),
        case(T14, Secp256k1, key(Secp256k1), Signer, (false, false)),
        case(T14, Secp256k1, admin_key(Secp256k1), Signer, (false, false)),
        case(T13, Secp256k1, key(Secp256k1), Signer, (true, false)),
        case(T13, Secp256k1, admin_key(Secp256k1), Signer, (true, true)),
        // A commitment on the granting account does not retire the grantee.
        case(T14, Secp256k1, key(Secp256k1), Account, (true, false)),
        case(T14, Secp256k1, admin_key(Secp256k1), Account, (true, true)),
        // The stored type is compared with the signature type from T14.
        case(T14, P256, key(P256), Nobody, (true, false)),
        case(T14, P256, key(Secp256k1), Nobody, (false, false)),
        case(T13, P256, key(P256), Nobody, (true, false)),
        case(T13, P256, key(Secp256k1), Nobody, (true, false)),
    ];
    for Case {
        spec,
        signer_type,
        grant,
        committed,
        expected,
    } in cases
    {
        let signer = Key::random(signer_type);
        let account = match grant {
            Some(_) => Address::repeat_byte(0x01),
            None => signer.address(),
        };
        let committed_addresses = match committed {
            Nobody => vec![],
            Signer => vec![signer.address()],
            Account => vec![account],
        };
        let name =
            format!("{spec:?}, {signer_type:?} signer, grant: {grant:?}, committed: {committed:?}");
        let mut storage = storage_at(spec, account, signer.address(), grant, &committed_addresses);
        let signature = keychain_signature(&signer, account);
        let actual = StorageCtx::enter(&mut storage, || {
            let verifier = SignatureVerifier::new();
            (
                verifier
                    .verify_keychain(account, HASH, signature.clone())
                    .expect(&name),
                verifier
                    .verify_keychain_admin(account, HASH, signature)
                    .expect(&name),
            )
        });
        assert_eq!(actual, expected, "{name}");
    }
}

#[test]
fn keychain_signature_must_embed_the_verified_account() {
    let key = Key::random(Secp256k1);
    let account = Address::repeat_byte(0x01);
    let mut storage = storage_at(T14, account, key.address(), admin_key(Secp256k1), &[]);
    let signature = keychain_signature(&key, account);
    StorageCtx::enter(&mut storage, || {
        let verifier = SignatureVerifier::new();
        let other = Address::repeat_byte(0x02);
        assert!(
            !verifier
                .verify_keychain(other, HASH, signature.clone())
                .unwrap()
        );
        assert!(
            !verifier
                .verify_keychain_admin(other, HASH, signature)
                .unwrap()
        );
    });
}

#[test]
fn implicit_root_admin_status_ends_with_the_commitment_from_t14() {
    let account = Address::repeat_byte(0x01);
    struct Case {
        spec: TempoHardfork,
        committed: Vec<Address>,
        admin: bool,
    }
    for Case {
        spec,
        committed,
        admin,
    } in [
        Case {
            spec: T14,
            committed: vec![],
            admin: true,
        },
        Case {
            spec: T14,
            committed: vec![account],
            admin: false,
        },
        Case {
            spec: T13,
            committed: vec![account],
            admin: true,
        },
    ] {
        let mut storage = storage_at(spec, account, Address::repeat_byte(0x03), None, &committed);
        StorageCtx::enter(&mut storage, || {
            assert_eq!(
                AccountKeychain::new()
                    .is_admin_key(account, account)
                    .unwrap(),
                admin,
                "{spec:?}, committed: {committed:?}"
            );
        });
    }
}
