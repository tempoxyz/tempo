//! Configurable account types of published `tempo-primitives`, exercised through their public API.

use alloy_primitives::{Address, B256, Bytes, Signature, U256, address, b256, keccak256};
use alloy_rlp::{Decodable, Encodable, Error as RlpError, Header, decode_exact};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use proptest::prelude::*;
use tempo_primitives::transaction::{
    ACCOUNT_PROXY_INIT_CODE_HASH, CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN,
    CONFIGURABLE_ACCOUNT_CREATE2_PREIMAGE_LEN, CONFIGURABLE_ACCOUNT_DOMAIN,
    CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN, ConfigurableAccountConfig,
    ConfigurableAccountConfigError, ConfigurableAccountOwner, ConfigurableAccountQuorumError,
    ConfigurableAccountSignature, ConfigurableAccountSignatureError, ConfigurableAccountStateError,
    ConfigurableAccountWeightAccumulator, KeychainSignature,
    MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES, MAX_CONFIGURABLE_ACCOUNT_OWNERS,
    MAX_CONFIGURABLE_ACCOUNT_SIGNATURES, PrimitiveSignature, SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT,
    TempoSignature, configurable_account_digest,
    tt_signature::{SIGNATURE_TYPE_WEBAUTHN, WebAuthnSignature},
};

// Deliberately non-production factory fixture: TIP-1110 has not selected its public address.
const TEST_FACTORY: Address = Address::repeat_byte(0x99);

/// An encoding that configurable account signature decoding rejects, with the error it reports.
struct MalformedEncoding {
    case: &'static str,
    encoded: Vec<u8>,
    error: RlpError,
}

/// A zero-salt config holding the `(owner, weight)` entries in the order given.
fn configurable_account_config(
    version: u64,
    threshold: u8,
    owners: &[(Address, u8)],
) -> ConfigurableAccountConfig {
    ConfigurableAccountConfig {
        salt: B256::ZERO,
        version,
        threshold,
        owners: owners
            .iter()
            .map(|&(owner, weight)| ConfigurableAccountOwner { owner, weight })
            .collect(),
    }
}

fn current_config(owner: Address) -> ConfigurableAccountConfig {
    configurable_account_config(1, 1, &[(owner, 1)])
}

fn indexed_owner(index: u16) -> Address {
    Address::left_padding_from(&index.to_be_bytes())
}

/// `count` ascending owners of equal weight.
fn indexed_owners(count: usize, weight: u8) -> Vec<(Address, u8)> {
    (1..=u16::try_from(count).unwrap())
        .map(|index| (indexed_owner(index), weight))
        .collect()
}

/// A secp256k1 owner approval with fixed scalars: decoding checks its shape, not its signer.
fn owner_approval() -> PrimitiveSignature {
    PrimitiveSignature::Secp256k1(Signature::new(U256::ONE, U256::from(2), false))
}

/// The bytes of an all-zero WebAuthn owner approval `encoded_len` bytes long: the type byte,
/// then the authenticator data and four 32-byte fields.
fn webauthn_approval_bytes(encoded_len: usize) -> Vec<u8> {
    [vec![SIGNATURE_TYPE_WEBAUTHN], vec![0; encoded_len - 1]].concat()
}

/// The WebAuthn owner approval decoded from [`webauthn_approval_bytes`]; decoding accepts
/// lengths up to the size cap.
fn webauthn_approval(encoded_len: usize) -> PrimitiveSignature {
    PrimitiveSignature::from_bytes(&webauthn_approval_bytes(encoded_len)).unwrap()
}

fn encoded_configurable_account_signature(
    account: Address,
    config: &ConfigurableAccountConfig,
    signatures: Vec<Vec<u8>>,
) -> Vec<u8> {
    let signatures = signatures.into_iter().map(Bytes::from).collect::<Vec<_>>();
    let payload_length = account.length() + config.length() + signatures.length();
    let mut encoded = Vec::new();
    Header {
        list: true,
        payload_length,
    }
    .encode(&mut encoded);
    account.encode(&mut encoded);
    config.encode(&mut encoded);
    signatures.encode(&mut encoded);
    encoded
}

/// Builds `levels` of nested current-configuration configurable account signatures, where the
/// innermost approval is primitive and each outer level has a single nested configurable account
/// owner.
fn nested_configurable_account_encoding(levels: usize) -> Vec<u8> {
    let mut current = encoded_configurable_account_signature(
        indexed_owner(100),
        &current_config(indexed_owner(200)),
        vec![owner_approval().to_bytes().to_vec()],
    );
    for level in 1..u16::try_from(levels).unwrap() {
        let mut nested_approval = vec![SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT];
        nested_approval.extend_from_slice(&current);
        current = encoded_configurable_account_signature(
            indexed_owner(100 + level),
            &current_config(indexed_owner(200 + level)),
            vec![nested_approval],
        );
    }
    current
}

/// The error decoding reports for an encoding that breaks `rule`: the rule's message.
fn decode_error(rule: ConfigurableAccountSignatureError) -> RlpError {
    // `RlpError::Custom` holds a `&'static str`, which a variant gives only through `Display`.
    RlpError::Custom(Box::leak(rule.to_string().into_boxed_str()))
}

fn malformed_configurable_account_encodings() -> Vec<MalformedEncoding> {
    let account = indexed_owner(1);
    let config = current_config(indexed_owner(2));
    let approval = owner_approval().to_bytes().to_vec();
    // A nested configurable account or keychain approval carries a type byte no primitive
    // signature has.
    let unknown_type = RlpError::Custom("Unknown signature type identifier");
    let keychain_owner = |keychain: KeychainSignature| {
        encoded_configurable_account_signature(
            account,
            &config,
            vec![TempoSignature::Keychain(keychain).to_bytes().to_vec()],
        )
    };
    vec![
        MalformedEncoding {
            case: "a nested configurable account owner",
            encoded: nested_configurable_account_encoding(2),
            error: unknown_type,
        },
        MalformedEncoding {
            case: "two levels of nested configurable account owners",
            encoded: nested_configurable_account_encoding(3),
            error: unknown_type,
        },
        MalformedEncoding {
            case: "4096 levels of nested configurable account owners",
            encoded: nested_configurable_account_encoding(4096),
            error: unknown_type,
        },
        MalformedEncoding {
            case: "a keychain owner",
            encoded: keychain_owner(KeychainSignature::new(indexed_owner(2), owner_approval())),
            error: unknown_type,
        },
        MalformedEncoding {
            case: "a v1 keychain owner",
            encoded: keychain_owner(KeychainSignature::new_v1(
                indexed_owner(2),
                owner_approval(),
            )),
            error: unknown_type,
        },
        MalformedEncoding {
            case: "an invalid config",
            encoded: encoded_configurable_account_signature(
                account,
                &configurable_account_config(0, 0, &[]),
                vec![approval.clone()],
            ),
            error: decode_error(ConfigurableAccountSignatureError::InvalidConfig(
                ConfigurableAccountConfigError::EmptyOwners,
            )),
        },
        MalformedEncoding {
            case: "more owners than the cap",
            encoded: encoded_configurable_account_signature(
                account,
                &configurable_account_config(
                    0,
                    8,
                    &indexed_owners(MAX_CONFIGURABLE_ACCOUNT_OWNERS + 1, 1),
                ),
                vec![approval.clone()],
            ),
            error: decode_error(ConfigurableAccountSignatureError::InvalidConfig(
                ConfigurableAccountConfigError::TooManyOwners,
            )),
        },
        MalformedEncoding {
            case: "more approvals than the cap",
            encoded: encoded_configurable_account_signature(
                account,
                &config,
                vec![approval; MAX_CONFIGURABLE_ACCOUNT_SIGNATURES + 1],
            ),
            error: decode_error(ConfigurableAccountSignatureError::TooManySignatures),
        },
        // The primitive decoder bounds a WebAuthn approval before the owner size cap applies.
        MalformedEncoding {
            case: "an approval over the size cap",
            encoded: encoded_configurable_account_signature(
                account,
                &config,
                vec![webauthn_approval_bytes(
                    MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES + 1,
                )],
            ),
            error: RlpError::Custom("Invalid WebAuthn signature length"),
        },
    ]
}

/// Owner-approval bytes of every primitive shape, accepted ones (with the non-canonical
/// secp256k1 parity bytes and P256 pre-hash flags that decoding normalizes) and arbitrary ones.
fn owner_approval_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        (
            prop::collection::vec(any::<u8>(), 64),
            prop::sample::select(vec![0u8, 1, 27, 28]),
        )
            .prop_map(|(scalars, parity)| [scalars, vec![parity]].concat()),
        prop::collection::vec(any::<u8>(), 129).prop_map(|fields| [vec![0x01], fields].concat()),
        prop::collection::vec(any::<u8>(), 128..=192)
            .prop_map(|fields| [vec![0x02], fields].concat()),
        prop::collection::vec(any::<u8>(), 0..=192),
    ]
}

#[cfg(feature = "arbitrary")]
#[test]
fn arbitrary_bounded_approvals() {
    use arbitrary::{Arbitrary, Unstructured};

    let mut primitive_types = [false; 3];
    let mut approval_counts = [false; MAX_CONFIGURABLE_ACCOUNT_SIGNATURES];
    let mut saw_max_webauthn = false;
    // 0xab repeated 10,000 times previously produced an oversized WebAuthn approval.
    for size in [0, 1, 256, 10_000] {
        for byte in 0..=u8::MAX {
            let input = vec![byte; size];
            let signature =
                ConfigurableAccountSignature::arbitrary(&mut Unstructured::new(&input)).unwrap();
            approval_counts[signature.signatures().len() - 1] = true;
            for approval in signature.signatures() {
                assert!(
                    approval.encoded_length() <= MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES
                );
                match approval {
                    PrimitiveSignature::Secp256k1(_) => primitive_types[0] = true,
                    PrimitiveSignature::P256(_) => primitive_types[1] = true,
                    PrimitiveSignature::WebAuthn(_) => {
                        primitive_types[2] = true;
                        saw_max_webauthn |= approval.encoded_length()
                            == MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES;
                    }
                }
            }
            let bytes = alloy_rlp::encode(&signature);
            assert_eq!(
                ConfigurableAccountSignature::decode(&mut bytes.as_slice()).unwrap(),
                signature
            );
        }
    }
    assert!(primitive_types.into_iter().all(|seen| seen));
    assert!(approval_counts.into_iter().all(|seen| seen));
    assert!(saw_max_webauthn);
}

#[test]
fn config_validation_reports_the_first_broken_rule() {
    let [low, high] = [1, 2].map(indexed_owner);
    let account = indexed_owner(0x10);
    // Nine owners of weight 30 but one of weight 1: the eight heaviest reach 240, of 241.
    let one_light_owner = |index: usize| {
        let mut owners = indexed_owners(MAX_CONFIGURABLE_ACCOUNT_SIGNATURES + 1, 30);
        owners[index].1 = 1;
        owners
    };

    struct ConfigCase {
        case: &'static str,
        config: ConfigurableAccountConfig,
        for_account: Option<Address>,
        expected: Result<u8, ConfigurableAccountConfigError>,
    }

    for ConfigCase {
        case,
        config,
        for_account,
        expected,
    } in [
        ConfigCase {
            case: "no owners, before the threshold",
            config: configurable_account_config(0, 0, &[]),
            for_account: None,
            expected: Err(ConfigurableAccountConfigError::EmptyOwners),
        },
        ConfigCase {
            case: "more owners than the cap, before the threshold",
            config: configurable_account_config(
                0,
                0,
                &indexed_owners(MAX_CONFIGURABLE_ACCOUNT_OWNERS + 1, 1),
            ),
            for_account: None,
            expected: Err(ConfigurableAccountConfigError::TooManyOwners),
        },
        ConfigCase {
            case: "as many owners as the cap",
            config: configurable_account_config(
                0,
                8,
                &indexed_owners(MAX_CONFIGURABLE_ACCOUNT_OWNERS, 1),
            ),
            for_account: None,
            expected: Ok(48),
        },
        ConfigCase {
            case: "a zero threshold, before every owner entry",
            config: configurable_account_config(0, 0, &[(Address::ZERO, 0)]),
            for_account: None,
            expected: Err(ConfigurableAccountConfigError::ZeroThreshold),
        },
        ConfigCase {
            case: "a zero owner anywhere, before an earlier zero weight",
            config: configurable_account_config(0, 1, &[(low, 0), (Address::ZERO, 1)]),
            for_account: None,
            expected: Err(ConfigurableAccountConfigError::ZeroOwner),
        },
        ConfigCase {
            case: "a zero weight",
            config: configurable_account_config(0, 1, &[(low, 1), (high, 0)]),
            for_account: None,
            expected: Err(ConfigurableAccountConfigError::ZeroWeight),
        },
        ConfigCase {
            case: "a zero weight, before ordering",
            config: configurable_account_config(0, 1, &[(high, 1), (low, 0)]),
            for_account: None,
            expected: Err(ConfigurableAccountConfigError::ZeroWeight),
        },
        ConfigCase {
            case: "an adjacent duplicate",
            config: configurable_account_config(0, 1, &[(low, 1), (low, 1)]),
            for_account: None,
            expected: Err(ConfigurableAccountConfigError::DuplicateOwner),
        },
        ConfigCase {
            case: "a nonadjacent duplicate",
            config: configurable_account_config(0, 1, &[(low, 1), (high, 1), (low, 1)]),
            for_account: None,
            expected: Err(ConfigurableAccountConfigError::DuplicateOwner),
        },
        ConfigCase {
            case: "descending owners, before the weight total",
            config: configurable_account_config(0, 1, &[(high, 128), (low, 128)]),
            for_account: None,
            expected: Err(ConfigurableAccountConfigError::OwnersNotAscending),
        },
        ConfigCase {
            case: "ascending owners",
            config: configurable_account_config(0, 2, &[(low, 1), (high, 2)]),
            for_account: None,
            expected: Ok(3),
        },
        ConfigCase {
            case: "the largest threshold and total weight",
            config: configurable_account_config(0, u8::MAX, &[(low, u8::MAX)]),
            for_account: None,
            expected: Ok(u8::MAX),
        },
        // The eight heaviest of nine owners of weight 29 cannot reach the threshold either.
        ConfigCase {
            case: "a weight total past u8::MAX, before reachability",
            config: configurable_account_config(
                0,
                u8::MAX,
                &indexed_owners(MAX_CONFIGURABLE_ACCOUNT_SIGNATURES + 1, 29),
            ),
            for_account: None,
            expected: Err(ConfigurableAccountConfigError::TotalWeightExceedsMax),
        },
        ConfigCase {
            case: "the eight heaviest owners reach the threshold, light owner first",
            config: configurable_account_config(0, 240, &one_light_owner(0)),
            for_account: None,
            expected: Ok(241),
        },
        ConfigCase {
            case: "the eight heaviest owners reach the threshold, light owner in the middle",
            config: configurable_account_config(0, 240, &one_light_owner(4)),
            for_account: None,
            expected: Ok(241),
        },
        ConfigCase {
            case: "the eight heaviest owners reach the threshold, light owner last",
            config: configurable_account_config(
                0,
                240,
                &one_light_owner(MAX_CONFIGURABLE_ACCOUNT_SIGNATURES),
            ),
            for_account: None,
            expected: Ok(241),
        },
        ConfigCase {
            case: "a threshold past the eight heaviest owners",
            config: configurable_account_config(0, 241, &one_light_owner(0)),
            for_account: None,
            expected: Err(ConfigurableAccountConfigError::ThresholdExceedsWeight),
        },
        ConfigCase {
            case: "an initial config owning its account",
            config: configurable_account_config(0, 1, &[(account, 1)]),
            for_account: Some(account),
            expected: Err(ConfigurableAccountConfigError::AccountIsOwner),
        },
        ConfigCase {
            case: "self-ownership, before its own zero weight",
            config: configurable_account_config(0, 1, &[(account, 0)]),
            for_account: Some(account),
            expected: Err(ConfigurableAccountConfigError::AccountIsOwner),
        },
        ConfigCase {
            case: "self-ownership anywhere, before an earlier zero weight",
            config: configurable_account_config(0, 1, &[(high, 0), (account, 1)]),
            for_account: Some(account),
            expected: Err(ConfigurableAccountConfigError::AccountIsOwner),
        },
        ConfigCase {
            case: "a later version owning its account",
            config: current_config(account),
            for_account: Some(account),
            expected: Ok(1),
        },
        ConfigCase {
            case: "the last version owning its account",
            config: configurable_account_config(u64::MAX, 1, &[(account, 1)]),
            for_account: Some(account),
            expected: Ok(1),
        },
    ] {
        match for_account {
            Some(account) => {
                assert_eq!(config.validate_for_account(account), expected, "{case}");
            }
            None => {
                assert_eq!(config.validate(), expected, "{case}");
                // Deriving the account and committing to the config validate it first.
                assert_eq!(
                    config.derive_account(TEST_FACTORY).err(),
                    expected.err(),
                    "{case}"
                );
                assert_eq!(config.commitment().err(), expected.err(), "{case}");
            }
        }
    }
}

#[test]
fn configurable_account_signature_construction_reports_the_first_broken_rule() {
    let account = Address::repeat_byte(0x11);
    let config = current_config(indexed_owner(2));
    let empty_config = configurable_account_config(0, 0, &[]);
    let largest = webauthn_approval(MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES);
    // Decoding rejects an approval over the size cap, so it is built field by field.
    let oversized = PrimitiveSignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(vec![
            0;
            MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES - 4 * 32
        ]),
        r: B256::ZERO,
        s: B256::ZERO,
        pub_key_x: B256::ZERO,
        pub_key_y: B256::ZERO,
    });
    assert_eq!(
        largest.encoded_length(),
        MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES
    );
    assert_eq!(
        oversized.encoded_length(),
        MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES + 1
    );

    struct ConstructionCase {
        case: &'static str,
        account: Address,
        config: ConfigurableAccountConfig,
        approvals: Vec<PrimitiveSignature>,
        expected: Result<(), ConfigurableAccountSignatureError>,
    }

    for ConstructionCase {
        case,
        account,
        config,
        approvals,
        expected,
    } in [
        ConstructionCase {
            case: "a zero account, before the config and the approvals",
            account: Address::ZERO,
            config: empty_config.clone(),
            approvals: Vec::new(),
            expected: Err(ConfigurableAccountSignatureError::ZeroAccount),
        },
        ConstructionCase {
            case: "an invalid config, before the approvals",
            account,
            config: empty_config,
            approvals: Vec::new(),
            expected: Err(ConfigurableAccountSignatureError::InvalidConfig(
                ConfigurableAccountConfigError::EmptyOwners,
            )),
        },
        ConstructionCase {
            case: "initial self-ownership of the named account",
            account,
            config: configurable_account_config(0, 1, &[(account, 1)]),
            approvals: vec![owner_approval()],
            expected: Err(ConfigurableAccountSignatureError::InvalidConfig(
                ConfigurableAccountConfigError::AccountIsOwner,
            )),
        },
        ConstructionCase {
            case: "no approvals",
            account,
            config: config.clone(),
            approvals: Vec::new(),
            expected: Err(ConfigurableAccountSignatureError::EmptySignatures),
        },
        ConstructionCase {
            case: "more approvals than the cap, before their sizes",
            account,
            config: config.clone(),
            approvals: vec![oversized.clone(); MAX_CONFIGURABLE_ACCOUNT_SIGNATURES + 1],
            expected: Err(ConfigurableAccountSignatureError::TooManySignatures),
        },
        ConstructionCase {
            case: "an approval over the size cap after one within it",
            account,
            config: config.clone(),
            approvals: vec![owner_approval(), oversized],
            expected: Err(ConfigurableAccountSignatureError::OwnerSignatureTooLarge),
        },
        ConstructionCase {
            case: "as many approvals of the largest size as the caps allow",
            account,
            config,
            approvals: vec![largest; MAX_CONFIGURABLE_ACCOUNT_SIGNATURES],
            expected: Ok(()),
        },
    ] {
        assert_eq!(
            ConfigurableAccountSignature::try_new(account, config, approvals.clone())
                .map(|signature| signature.signatures().to_vec()),
            expected.map(|()| approvals),
            "{case}"
        );
    }
}

#[test]
fn configurable_account_signature_rlp_roundtrips_and_rejects_malformed_encodings() {
    let account = Address::repeat_byte(0x11);
    let config = current_config(indexed_owner(2));
    let approvals = vec![
        owner_approval(),
        webauthn_approval(MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES),
    ];
    let signature =
        ConfigurableAccountSignature::try_new(account, config.clone(), approvals.clone()).unwrap();

    // The wire form is the account, the complete config and each approval's bytes, in order.
    let encoded = alloy_rlp::encode(&signature);
    assert_eq!(
        encoded,
        encoded_configurable_account_signature(
            account,
            &config,
            approvals
                .iter()
                .map(|approval| approval.to_bytes().to_vec())
                .collect(),
        )
    );
    assert_eq!(
        decode_exact::<ConfigurableAccountSignature>(&encoded),
        Ok(signature)
    );

    for MalformedEncoding {
        case,
        encoded,
        error,
    } in malformed_configurable_account_encodings()
    {
        assert_eq!(
            ConfigurableAccountSignature::decode(&mut encoded.as_slice()),
            Err(error),
            "{case}"
        );
    }
}

#[test]
fn sixty_five_byte_owners_remain_untyped() {
    for first in [0x03, 0x04, 0x05] {
        let mut primitive = owner_approval().to_bytes().to_vec();
        primitive[0] = first;
        let expected =
            PrimitiveSignature::Secp256k1(Signature::try_from(primitive.as_slice()).unwrap());
        let encoded = encoded_configurable_account_signature(
            indexed_owner(1),
            &current_config(indexed_owner(2)),
            vec![primitive],
        );
        let decoded = ConfigurableAccountSignature::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded.signatures(), [expected]);
    }
}

#[test]
fn configurable_account_hashes_follow_vectors_and_documented_layout() {
    let inner_digest = B256::repeat_byte(0x42);

    // Vectors over one owner of weight 1 at threshold 1, independently reproduced with raw
    // keccak and CREATE2 hashing over the placeholder account proxy hash.
    let owner = Address::repeat_byte(0x11);
    let initial = configurable_account_config(0, 1, &[(owner, 1)]);
    assert_eq!(
        initial.account_salt_preimage().map(keccak256),
        Ok(b256!(
            "641ad6eccc3adf35fac828d5cbb727e2489c904a905420e794e8275b6150bfe1"
        ))
    );
    assert_eq!(
        initial.derive_account(TEST_FACTORY),
        Ok(address!("87c346a9029d675f296db533b12e146439cf20d5"))
    );
    assert_eq!(
        initial.commitment(),
        Ok(b256!(
            "79cc3a5fcbe18cb8cbbd2b41393750ccf3bbc20533a846755767fa10068ae01d"
        ))
    );
    let digest_account = address!("91847576f406d0842ad7c1a0c97c22a122e64278");
    assert_eq!(
        configurable_account_digest(inner_digest, digest_account, 0),
        b256!("e6fa513b5ab32da6f116443f13191096bce77b4850f4d51f3aa436fa7650c964")
    );
    let current = ConfigurableAccountSignature::try_new(
        digest_account,
        current_config(owner),
        vec![owner_approval()],
    )
    .unwrap();
    assert_eq!(
        current.digest(inner_digest),
        b256!("285c850cb2803beb10f2f212dac73784a1a03b3991ba79081b24bfa91beb9182")
    );
    assert_eq!(
        current.config_commitment(),
        b256!("ee570a0f26f17b41cdf0952a04ee01ea23495b0c0a59f9c904b0d60cb76453c3")
    );
    // The most owners, each of weight 1, at threshold 8, reproduced the same way.
    assert_eq!(
        configurable_account_config(0, 8, &indexed_owners(MAX_CONFIGURABLE_ACCOUNT_OWNERS, 1))
            .derive_account(TEST_FACTORY),
        Ok(address!("7a4279bb3f1b8b54d703484317f64eae6814e827"))
    );

    // The documented preimage layouts, built by hand.
    let owners = [(indexed_owner(1), 2), (indexed_owner(2), 3)];
    let mut config = configurable_account_config(9, 4, &owners);
    config.salt = B256::repeat_byte(0x07);
    let mut owner_set = vec![4, 2];
    for (owner, weight) in owners {
        owner_set.extend_from_slice(owner.as_slice());
        owner_set.push(weight);
    }

    let salt_preimage = [
        CONFIGURABLE_ACCOUNT_DOMAIN,
        config.salt.as_slice(),
        owner_set.as_slice(),
    ]
    .concat();
    assert_eq!(config.account_salt_preimage(), Ok(salt_preimage.clone()));
    assert_eq!(config.account_salt_preimage_len(), salt_preimage.len());

    let commitment_preimage = [
        CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN,
        config.salt.as_slice(),
        &config.version.to_be_bytes(),
        owner_set.as_slice(),
    ]
    .concat();
    assert_eq!(
        config.commitment_preimage(),
        Ok(commitment_preimage.clone())
    );
    assert_eq!(config.commitment_preimage_len(), commitment_preimage.len());
    assert_eq!(config.commitment(), Ok(keccak256(&commitment_preimage)));

    let create2_preimage = [
        &[0xff][..],
        TEST_FACTORY.as_slice(),
        keccak256(&salt_preimage).as_slice(),
        ACCOUNT_PROXY_INIT_CODE_HASH.as_slice(),
    ]
    .concat();
    assert_eq!(
        create2_preimage.len(),
        CONFIGURABLE_ACCOUNT_CREATE2_PREIMAGE_LEN
    );
    let account = Address::from_word(keccak256(&create2_preimage));
    assert_eq!(config.derive_account(TEST_FACTORY), Ok(account));

    let digest_preimage = [
        CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN,
        inner_digest.as_slice(),
        account.as_slice(),
        &config.version.to_be_bytes(),
    ]
    .concat();
    assert_eq!(
        configurable_account_digest(inner_digest, account, config.version),
        keccak256(digest_preimage)
    );

    // An owner approval cannot replay across accounts that share owners, or across versions.
    let mut resalted = config.clone();
    resalted.salt = B256::repeat_byte(0x08);
    let resalted_account = resalted.derive_account(TEST_FACTORY).unwrap();
    assert_ne!(resalted_account, account, "the salt sets the account");
    assert_ne!(
        configurable_account_digest(inner_digest, resalted_account, config.version),
        configurable_account_digest(inner_digest, account, config.version),
        "the account sets the digest"
    );
    assert_ne!(
        configurable_account_digest(inner_digest, account, config.version + 1),
        configurable_account_digest(inner_digest, account, config.version),
        "the version sets the digest"
    );

    // Each preimage bounds the owner count on its own.
    let oversized = configurable_account_config(
        0,
        1,
        &indexed_owners(MAX_CONFIGURABLE_ACCOUNT_OWNERS + 1, 1),
    );
    assert_eq!(
        oversized.account_salt_preimage(),
        Err(ConfigurableAccountConfigError::TooManyOwners)
    );
    assert_eq!(
        oversized.commitment_preimage(),
        Err(ConfigurableAccountConfigError::TooManyOwners)
    );
}

#[test]
fn configurable_account_quorum_reports_the_first_broken_rule() {
    let [first, second, third] = [1, 2, 3].map(indexed_owner);
    let config = configurable_account_config(0, 4, &[(first, 1), (second, 3), (third, 2)]);
    assert_eq!(
        [first, second, third, indexed_owner(4)].map(|owner| config.owner_weight(owner)),
        [Some(1), Some(3), Some(2), None]
    );

    // Records each recovered owner with its configured weight, in order.
    let quorum = |threshold: u8,
                  approvals: Vec<(Address, u8)>|
     -> Result<(), ConfigurableAccountQuorumError> {
        let mut accumulator = ConfigurableAccountWeightAccumulator::new(threshold)?;
        for (owner, weight) in approvals {
            accumulator.record_owner(owner, weight)?;
        }
        accumulator.finish()
    };
    let light = (first, 1);
    let heavy = (second, 3);

    struct QuorumCase {
        case: &'static str,
        threshold: u8,
        approvals: Vec<(Address, u8)>,
        expected: Result<(), ConfigurableAccountQuorumError>,
    }

    for QuorumCase {
        case,
        threshold,
        approvals,
        expected,
    } in [
        QuorumCase {
            case: "a zero threshold",
            threshold: 0,
            approvals: Vec::new(),
            expected: Err(ConfigurableAccountQuorumError::ZeroThreshold),
        },
        QuorumCase {
            case: "no approvals",
            threshold: 1,
            approvals: Vec::new(),
            expected: Err(ConfigurableAccountQuorumError::EmptySignatures),
        },
        QuorumCase {
            case: "a signer of zero weight, read as outside the owner set",
            threshold: 2,
            approvals: vec![(first, 0)],
            expected: Err(ConfigurableAccountQuorumError::SignerNotOwner),
        },
        QuorumCase {
            case: "a repeated owner",
            threshold: 2,
            approvals: vec![light, light],
            expected: Err(ConfigurableAccountQuorumError::SignersNotAscending),
        },
        QuorumCase {
            case: "descending owners",
            threshold: 4,
            approvals: vec![heavy, light],
            expected: Err(ConfigurableAccountQuorumError::SignersNotAscending),
        },
        QuorumCase {
            case: "more approvals than the cap below quorum, before ordering",
            threshold: u8::MAX,
            approvals: [
                indexed_owners(MAX_CONFIGURABLE_ACCOUNT_SIGNATURES, 1),
                vec![light],
            ]
            .concat(),
            expected: Err(ConfigurableAccountQuorumError::TooManySignatures),
        },
        QuorumCase {
            case: "as many approvals as the cap",
            threshold: u8::try_from(MAX_CONFIGURABLE_ACCOUNT_SIGNATURES).unwrap(),
            approvals: indexed_owners(MAX_CONFIGURABLE_ACCOUNT_SIGNATURES, 1),
            expected: Ok(()),
        },
        QuorumCase {
            case: "an approval after quorum",
            threshold: 1,
            approvals: vec![light, heavy],
            expected: Err(ConfigurableAccountQuorumError::ExcessSignatures),
        },
        QuorumCase {
            case: "an approval after quorum, before its entry is checked",
            threshold: 1,
            approvals: vec![light, (Address::ZERO, 0)],
            expected: Err(ConfigurableAccountQuorumError::ExcessSignatures),
        },
        QuorumCase {
            case: "weight below the threshold",
            threshold: 4,
            approvals: vec![heavy],
            expected: Err(ConfigurableAccountQuorumError::WeightBelowThreshold),
        },
        QuorumCase {
            case: "weight at the threshold",
            threshold: 4,
            approvals: vec![light, heavy],
            expected: Ok(()),
        },
    ] {
        assert_eq!(quorum(threshold, approvals), expected, "{case}");
    }
}

#[test]
fn configurable_account_approvals_report_the_first_broken_rule() {
    let [first, second, outsider] = [1, 2, 3].map(|seed| {
        PrivateKeySigner::from_bytes(&B256::repeat_byte(seed)).expect("nonzero scalar is a key")
    });
    let mut owners = [first.address(), second.address()];
    owners.sort();
    let config = configurable_account_config(0, 2, &owners.map(|owner| (owner, 1)));
    let account = config.derive_account(TEST_FACTORY).unwrap();
    let inner_digest = B256::repeat_byte(0x42);
    let digest = configurable_account_digest(inner_digest, account, config.version);
    let approve = |signer: &PrivateKeySigner| {
        PrimitiveSignature::Secp256k1(signer.sign_hash_sync(&digest).unwrap())
    };
    let [low, high] = owners.map(|owner| {
        approve(if owner == first.address() {
            &first
        } else {
            &second
        })
    });
    let unrecoverable =
        PrimitiveSignature::Secp256k1(Signature::new(U256::ZERO, U256::ZERO, false));

    struct ApprovalCase {
        case: &'static str,
        threshold: u8,
        approvals: Vec<PrimitiveSignature>,
        expected: Result<(), ConfigurableAccountQuorumError>,
    }

    for ApprovalCase {
        case,
        threshold,
        approvals,
        expected,
    } in [
        ApprovalCase {
            case: "owners in ascending order reaching the threshold",
            threshold: 2,
            approvals: vec![low.clone(), high.clone()],
            expected: Ok(()),
        },
        ApprovalCase {
            case: "weight below the threshold",
            threshold: 2,
            approvals: vec![low.clone()],
            expected: Err(ConfigurableAccountQuorumError::WeightBelowThreshold),
        },
        ApprovalCase {
            case: "owners in descending order",
            threshold: 2,
            approvals: vec![high.clone(), low.clone()],
            expected: Err(ConfigurableAccountQuorumError::SignersNotAscending),
        },
        ApprovalCase {
            case: "an approval that recovers no signer",
            threshold: 2,
            approvals: vec![low.clone(), unrecoverable],
            expected: Err(
                ConfigurableAccountQuorumError::OwnerSignatureRecoveryFailed { approval_index: 1 },
            ),
        },
        ApprovalCase {
            case: "a signer outside the owner set",
            threshold: 2,
            approvals: vec![approve(&outsider), high.clone()],
            expected: Err(ConfigurableAccountQuorumError::SignerNotOwner),
        },
        ApprovalCase {
            case: "an approval after quorum",
            threshold: 1,
            approvals: vec![low, high],
            expected: Err(ConfigurableAccountQuorumError::ExcessSignatures),
        },
    ] {
        let signature = ConfigurableAccountSignature::try_new(
            account,
            configurable_account_config(config.version, threshold, &owners.map(|owner| (owner, 1))),
            approvals,
        )
        .unwrap();
        assert_eq!(signature.verify_approvals(inner_digest), expected, "{case}");
    }
}

#[test]
fn configurable_account_commitment_reports_the_first_broken_rule() {
    let owners = [(indexed_owner(1), 1)];
    let account = configurable_account_config(0, 1, &owners)
        .derive_account(TEST_FACTORY)
        .unwrap();
    let other_factory = Address::repeat_byte(0x98);
    let signature = |version: u64| {
        ConfigurableAccountSignature::try_new(
            account,
            configurable_account_config(version, 1, &owners),
            vec![owner_approval()],
        )
        .unwrap()
    };
    let [initial_commitment, current_commitment] =
        [0, 1].map(|version| signature(version).config_commitment());

    struct CommitmentCase {
        case: &'static str,
        version: u64,
        stored: B256,
        factory: Option<Address>,
        expected: Result<(), ConfigurableAccountStateError>,
    }

    for CommitmentCase {
        case,
        version,
        stored,
        factory,
        expected,
    } in [
        CommitmentCase {
            case: "a stored commitment equal to the witness",
            version: 1,
            stored: current_commitment,
            factory: None,
            expected: Ok(()),
        },
        CommitmentCase {
            case: "a stored commitment differing from the witness",
            version: 1,
            stored: initial_commitment,
            factory: Some(TEST_FACTORY),
            expected: Err(ConfigurableAccountStateError::CommitmentMismatch {
                expected: initial_commitment,
                actual: current_commitment,
            }),
        },
        CommitmentCase {
            case: "first use of the account the factory derives",
            version: 0,
            stored: B256::ZERO,
            factory: Some(TEST_FACTORY),
            expected: Ok(()),
        },
        CommitmentCase {
            case: "first use at a version above zero",
            version: 1,
            stored: B256::ZERO,
            factory: Some(TEST_FACTORY),
            expected: Err(ConfigurableAccountStateError::UnregisteredVersion { actual: 1 }),
        },
        CommitmentCase {
            case: "first use without a configured factory",
            version: 0,
            stored: B256::ZERO,
            factory: None,
            expected: Err(ConfigurableAccountStateError::FactoryNotConfigured),
        },
        CommitmentCase {
            case: "first use against a factory deriving another account",
            version: 0,
            stored: B256::ZERO,
            factory: Some(other_factory),
            expected: Err(ConfigurableAccountStateError::InitialAccountMismatch {
                expected: configurable_account_config(0, 1, &owners)
                    .derive_account(other_factory)
                    .unwrap(),
                actual: account,
            }),
        },
    ] {
        assert_eq!(
            signature(version).validate_account_commitment(stored, factory),
            expected,
            "{case}"
        );
    }
}

#[cfg(feature = "serde")]
mod serde_json_and_binary {
    use super::{
        ConfigurableAccountSignature, MalformedEncoding, RlpError, current_config, indexed_owner,
        malformed_configurable_account_encodings, owner_approval,
    };
    use alloy_primitives::{Address, Bytes};
    use serde::{
        Deserialize as _,
        de::{
            Error as _,
            value::{BorrowedBytesDeserializer, Error as DeError},
        },
    };
    use serde_json::{from_value, to_value};

    fn decode_binary_configurable_account_signature(
        bytes: &[u8],
    ) -> Result<ConfigurableAccountSignature, DeError> {
        ConfigurableAccountSignature::deserialize(BorrowedBytesDeserializer::new(bytes))
    }

    #[test]
    fn configurable_account_signature_serde_roundtrips_rlp_bytes() {
        let signature = ConfigurableAccountSignature::try_new(
            Address::repeat_byte(0x11),
            current_config(indexed_owner(2)),
            vec![owner_approval()],
        )
        .unwrap();
        let encoded = alloy_rlp::encode(&signature);

        let json = to_value(&signature).unwrap();
        assert_eq!(json, to_value(Bytes::from(encoded.clone())).unwrap());
        assert_eq!(
            from_value::<ConfigurableAccountSignature>(json).unwrap(),
            signature
        );
        assert_eq!(
            decode_binary_configurable_account_signature(&encoded),
            Ok(signature)
        );
        // The bytes hold exactly one signature.
        let trailing = [encoded, vec![0x80]].concat();
        assert_eq!(
            decode_binary_configurable_account_signature(&trailing),
            Err(DeError::custom(RlpError::UnexpectedLength))
        );
    }

    #[test]
    fn configurable_account_signature_serde_rejects_malformed_encodings() {
        for MalformedEncoding {
            case,
            encoded,
            error,
        } in malformed_configurable_account_encodings()
        {
            assert_eq!(
                decode_binary_configurable_account_signature(&encoded),
                Err(DeError::custom(error)),
                "{case}"
            );
            let json = to_value(Bytes::from(encoded)).unwrap();
            assert_eq!(
                from_value::<ConfigurableAccountSignature>(json)
                    .unwrap_err()
                    .to_string(),
                error.to_string(),
                "{case}"
            );
        }
    }
}

proptest! {
    #[test]
    fn proptest_configurable_account_signature_decode_follows_owner_approval_decoding(
        account in any::<Address>().prop_filter("configurable accounts are nonzero", |account| !account.is_zero()),
        approvals in prop::collection::vec(
            owner_approval_bytes(),
            1..=MAX_CONFIGURABLE_ACCOUNT_SIGNATURES,
        ),
    ) {
        let config = current_config(indexed_owner(2));
        let decoded = decode_exact::<ConfigurableAccountSignature>(
            encoded_configurable_account_signature(account, &config, approvals.clone()),
        );
        match approvals
            .iter()
            .map(|approval| decode_exact::<PrimitiveSignature>(alloy_rlp::encode(approval.as_slice())))
            .collect::<Result<Vec<_>, _>>()
        {
            // Accepted approvals decode in order and re-encode canonically.
            Ok(signatures) => {
                let decoded = decoded.unwrap();
                prop_assert_eq!(decoded.account(), account);
                prop_assert_eq!(decoded.config(), &config);
                prop_assert_eq!(decoded.signatures(), signatures.as_slice());

                let reencoded = alloy_rlp::encode(&decoded);
                let canonical_approvals = signatures
                    .iter()
                    .map(|signature| signature.to_bytes().to_vec())
                    .collect();
                prop_assert_eq!(
                    &reencoded,
                    &encoded_configurable_account_signature(account, &config, canonical_approvals)
                );
                prop_assert_eq!(
                    decode_exact::<ConfigurableAccountSignature>(reencoded),
                    Ok(decoded)
                );
            }
            // The first rejected approval's error is the signature's.
            Err(error) => prop_assert_eq!(decoded, Err(error)),
        }
    }
}
