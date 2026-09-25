use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use alloy_eips::BlockId;
use alloy_network::TransactionBuilder;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_provider::Provider;
use eyre::{ensure, Result, WrapErr};
use hkdf::Hkdf;
use k256::{
    ecdh::diffie_hellman,
    elliptic_curve::{
        rand_core::{OsRng, RngCore},
        sec1::ToEncodedPoint,
    },
    PublicKey, SecretKey,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use txgen_cli::ScenarioActionContext;

const PREPARE_ENCRYPTED_DEPOSIT: &str = "prepare_encrypted_deposit";
pub(crate) const SCENARIO_ACTIONS: &[&str] = &[PREPARE_ENCRYPTED_DEPOSIT];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrepareEncryptedDepositArgs {
    recipient: Address,
    sender: Address,
    zone_id: u32,
    portal_address: Option<Address>,
    #[serde(default)]
    memo: B256,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedEncryptedDeposit {
    chain_id: u64,
    encrypted: EncryptedDepositOutput,
    key_index: String,
    portal_address: String,
    zone_id: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedDepositOutput {
    ephemeral_pubkey_x: String,
    ephemeral_pubkey_y_parity: u8,
    ciphertext: String,
    nonce: String,
    tag: String,
}

struct EncryptedDeposit {
    ephemeral_pubkey_x: B256,
    ephemeral_pubkey_y_parity: u8,
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    tag: [u8; 16],
}

pub(crate) async fn invoke(
    action: &str,
    arguments: &serde_yaml::Value,
    context: ScenarioActionContext<'_>,
) -> Result<serde_yaml::Value> {
    match action {
        PREPARE_ENCRYPTED_DEPOSIT => {
            let arguments: PrepareEncryptedDepositArgs = serde_yaml::from_value(arguments.clone())
                .wrap_err("invalid prepare_encrypted_deposit arguments")?;
            prepare_encrypted_deposit(arguments, context).await
        }
        _ => Err(eyre::eyre!("unsupported Tempo scenario action '{action}'")),
    }
}

async fn prepare_encrypted_deposit(
    arguments: PrepareEncryptedDepositArgs,
    context: ScenarioActionContext<'_>,
) -> Result<serde_yaml::Value> {
    let portal_address = match arguments.portal_address {
        Some(portal_address) => portal_address,
        None => configured_portal_address(context.chain_id, arguments.zone_id)?,
    };
    let (sequencer_x, sequencer_y_parity, key_index) =
        active_encryption_key(context.query_provider, portal_address).await?;
    let encrypted = encrypt_deposit(
        sequencer_x,
        sequencer_y_parity,
        arguments.recipient,
        arguments.memo,
        arguments.sender,
        portal_address,
        key_index,
    )?;

    serde_yaml::to_value(PreparedEncryptedDeposit {
        chain_id: context.chain_id,
        encrypted: EncryptedDepositOutput {
            ephemeral_pubkey_x: encrypted.ephemeral_pubkey_x.to_string(),
            ephemeral_pubkey_y_parity: encrypted.ephemeral_pubkey_y_parity,
            ciphertext: Bytes::from(encrypted.ciphertext).to_string(),
            nonce: format!("0x{}", hex::encode(encrypted.nonce)),
            tag: format!("0x{}", hex::encode(encrypted.tag)),
        },
        key_index: key_index.to_string(),
        portal_address: portal_address.to_string(),
        zone_id: arguments.zone_id,
    })
    .wrap_err("failed to encode prepared encrypted deposit")
}

fn configured_portal_address(chain_id: u64, zone_id: u32) -> Result<Address> {
    match (chain_id, zone_id) {
        (42_431, 6) => Ok("0x7069DeC4E64Fd07334A0933eDe836C17259c9B23".parse()?),
        (42_431, 7) => Ok("0x3F5296303400B56271b476F5A0B9cBF74350D6Ac".parse()?),
        _ => {
            Err(eyre::eyre!("no portal address configured for zone {zone_id} on chain {chain_id}"))
        }
    }
}

async fn active_encryption_key(
    provider: &alloy_provider::DynProvider<alloy_network::AnyNetwork>,
    portal: Address,
) -> Result<(B256, u8, U256)> {
    for _ in 0..2 {
        let count_before = encryption_key_count(provider, portal).await?;
        ensure!(count_before > U256::ZERO, "ZonePortal has no encryption key");
        let (x, y_parity) = sequencer_encryption_key(provider, portal).await?;
        let count_after = encryption_key_count(provider, portal).await?;
        if count_before == count_after {
            return Ok((x, normalize_y_parity(y_parity)?, count_before - U256::from(1)));
        }
    }
    Err(eyre::eyre!("ZonePortal encryption key rotated while preparing the recipient"))
}

async fn encryption_key_count(
    provider: &alloy_provider::DynProvider<alloy_network::AnyNetwork>,
    portal: Address,
) -> Result<U256> {
    let output = call_portal(provider, portal, "encryptionKeyCount()").await?;
    ensure!(output.len() == 32, "invalid encryptionKeyCount response length");
    Ok(U256::from_be_slice(&output))
}

async fn sequencer_encryption_key(
    provider: &alloy_provider::DynProvider<alloy_network::AnyNetwork>,
    portal: Address,
) -> Result<(B256, u8)> {
    let output = call_portal(provider, portal, "sequencerEncryptionKey()").await?;
    ensure!(output.len() == 96, "invalid sequencerEncryptionKey response length");
    ensure!(
        output[32..63].iter().all(|byte| *byte == 0),
        "sequencerEncryptionKey returned an invalid y parity"
    );
    Ok((B256::from_slice(&output[..32]), output[63]))
}

async fn call_portal(
    provider: &alloy_provider::DynProvider<alloy_network::AnyNetwork>,
    portal: Address,
    signature: &str,
) -> Result<Bytes> {
    let selector = &keccak256(signature.as_bytes())[..4];
    provider
        .call(
            provider
                .transaction_request()
                .with_to(portal)
                .with_input(Bytes::copy_from_slice(selector)),
        )
        .block(BlockId::latest())
        .await
        .wrap_err_with(|| format!("failed to call ZonePortal.{signature}"))
}

fn normalize_y_parity(y_parity: u8) -> Result<u8> {
    match y_parity {
        0 | 1 => Ok(0x02 + y_parity),
        0x02 | 0x03 => Ok(y_parity),
        _ => Err(eyre::eyre!("invalid sequencer encryption key y parity {y_parity}")),
    }
}

fn encrypt_deposit(
    sequencer_x: B256,
    sequencer_y_parity: u8,
    recipient: Address,
    memo: B256,
    sender: Address,
    portal: Address,
    key_index: U256,
) -> Result<EncryptedDeposit> {
    let mut rng = OsRng;
    let ephemeral_key = SecretKey::random(&mut rng);
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    encrypt_deposit_with_material(
        sequencer_x,
        sequencer_y_parity,
        recipient,
        memo,
        sender,
        portal,
        key_index,
        &ephemeral_key,
        nonce,
    )
}

#[expect(clippy::too_many_arguments)]
fn encrypt_deposit_with_material(
    sequencer_x: B256,
    sequencer_y_parity: u8,
    recipient: Address,
    memo: B256,
    sender: Address,
    portal: Address,
    key_index: U256,
    ephemeral_key: &SecretKey,
    nonce: [u8; 12],
) -> Result<EncryptedDeposit> {
    let mut sequencer_bytes = [0u8; 33];
    sequencer_bytes[0] = sequencer_y_parity;
    sequencer_bytes[1..].copy_from_slice(sequencer_x.as_slice());
    let sequencer_key = PublicKey::from_sec1_bytes(&sequencer_bytes)
        .map_err(|_| eyre::eyre!("invalid sequencer encryption public key"))?;

    let ephemeral_public = ephemeral_key.public_key().to_encoded_point(true);
    let ephemeral_bytes = ephemeral_public.as_bytes();
    let ephemeral_pubkey_x = B256::from_slice(&ephemeral_bytes[1..]);
    let ephemeral_pubkey_y_parity = ephemeral_bytes[0];
    let shared_secret =
        diffie_hellman(ephemeral_key.to_nonzero_scalar(), sequencer_key.as_affine());

    let mut info = [0u8; 104];
    info[..20].copy_from_slice(portal.as_slice());
    info[20..52].copy_from_slice(&key_index.to_be_bytes::<32>());
    info[52..84].copy_from_slice(ephemeral_pubkey_x.as_slice());
    info[84..].copy_from_slice(sender.as_slice());
    let hkdf = Hkdf::<Sha256>::new(Some(b"ecies-aes-key"), shared_secret.raw_secret_bytes());
    let mut aes_key = [0u8; 32];
    hkdf.expand(&info, &mut aes_key).map_err(|_| eyre::eyre!("HKDF expansion failed"))?;

    let mut ciphertext = Vec::with_capacity(64);
    ciphertext.extend_from_slice(recipient.as_slice());
    ciphertext.extend_from_slice(memo.as_slice());
    ciphertext.resize(64, 0);
    let cipher = Aes256Gcm::new_from_slice(&aes_key).expect("AES-256 key has a fixed size");
    let nonce_value = Nonce::from(nonce);
    let tag = cipher
        .encrypt_in_place_detached(&nonce_value, &[], &mut ciphertext)
        .map_err(|_| eyre::eyre!("AES-GCM encryption failed"))?;

    Ok(EncryptedDeposit {
        ephemeral_pubkey_x,
        ephemeral_pubkey_y_parity,
        ciphertext,
        nonce,
        tag: tag.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_network::AnyNetwork;
    use alloy_provider::ProviderBuilder;
    use alloy_transport::mock::Asserter;
    use sha2::Digest;

    #[test]
    fn matches_zone_encrypted_deposit_vector() {
        let sequencer_key =
            SecretKey::from_slice(&Sha256::digest(b"test-sequencer-key")).expect("valid test key");
        let sequencer_public = sequencer_key.public_key().to_encoded_point(true);
        let ephemeral_key =
            SecretKey::from_slice(&Sha256::digest(b"test-ephemeral-key")).expect("valid test key");
        let encrypted = encrypt_deposit_with_material(
            B256::from_slice(&sequencer_public.as_bytes()[1..]),
            sequencer_public.as_bytes()[0],
            Address::repeat_byte(0xbb),
            B256::repeat_byte(0xcc),
            Address::repeat_byte(0xdd),
            Address::repeat_byte(0xaa),
            U256::from(42),
            &ephemeral_key,
            [0u8; 12],
        )
        .unwrap();

        assert_eq!(
            encrypted.ephemeral_pubkey_x,
            "0x7b887881dba35dbe999162629d80071921e38f49749104b7648d865c56eeb5a0"
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(encrypted.ephemeral_pubkey_y_parity, 3);
        assert_eq!(
            Bytes::from(encrypted.ciphertext),
            "0xabf635c21eade9d5e71e418178dc854b707373e194e64e784380f4532eb360ed24271dab9482dc32424257661b89b487c414ebdb22003ae12b67ff3d8bc213f5"
                .parse::<Bytes>()
                .unwrap()
        );
        assert_eq!(encrypted.nonce, [0u8; 12]);
        assert_eq!(
            encrypted.tag,
            hex::decode("9687cf944502560139fb6ac8d77e8897").unwrap().as_slice()
        );
    }

    #[test]
    fn binds_encrypted_deposit_to_sender() {
        let sequencer_key =
            SecretKey::from_slice(&Sha256::digest(b"test-sequencer-key")).expect("valid test key");
        let sequencer_public = sequencer_key.public_key().to_encoded_point(true);
        let ephemeral_key =
            SecretKey::from_slice(&Sha256::digest(b"test-ephemeral-key")).expect("valid test key");
        let encrypt_for = |sender| {
            encrypt_deposit_with_material(
                B256::from_slice(&sequencer_public.as_bytes()[1..]),
                sequencer_public.as_bytes()[0],
                Address::repeat_byte(0xbb),
                B256::repeat_byte(0xcc),
                sender,
                Address::repeat_byte(0xaa),
                U256::from(42),
                &ephemeral_key,
                [0u8; 12],
            )
            .unwrap()
        };

        let alice = encrypt_for(Address::repeat_byte(0xdd));
        let bob = encrypt_for(Address::repeat_byte(0xee));
        assert_ne!(alice.ciphertext, bob.ciphertext);
        assert_ne!(alice.tag, bob.tag);
    }

    #[test]
    fn resolves_viem_portal_addresses() {
        assert_eq!(
            configured_portal_address(42_431, 7).unwrap(),
            "0x3F5296303400B56271b476F5A0B9cBF74350D6Ac".parse::<Address>().unwrap()
        );
        assert!(configured_portal_address(42_431, 8).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_portal_without_an_encryption_key() {
        let asserter = Asserter::new();
        asserter.push_success(&Bytes::from(vec![0u8; 32]));
        let provider = ProviderBuilder::new_with_network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone())
            .erased();
        let arguments = serde_yaml::from_str(
            r#"
portalAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
recipient: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
sender: "0xdddddddddddddddddddddddddddddddddddddddd"
zoneId: 9
"#,
        )
        .unwrap();

        let error = invoke(
            PREPARE_ENCRYPTED_DEPOSIT,
            &arguments,
            ScenarioActionContext { chain: "l1", chain_id: 1, query_provider: &provider },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("no encryption key"));
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn requires_deposit_sender() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new_with_network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone())
            .erased();
        let arguments = serde_yaml::from_str(
            r#"
portalAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
recipient: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
zoneId: 9
"#,
        )
        .unwrap();

        let error = invoke(
            PREPARE_ENCRYPTED_DEPOSIT,
            &arguments,
            ScenarioActionContext { chain: "l1", chain_id: 1, query_provider: &provider },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("invalid prepare_encrypted_deposit arguments"));
        assert!(format!("{error:?}").contains("missing field `sender`"));
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prepares_payload_from_active_portal_key() {
        let sequencer_key =
            SecretKey::from_slice(&Sha256::digest(b"test-sequencer-key")).expect("valid test key");
        let sequencer_public = sequencer_key.public_key().to_encoded_point(true);
        let key_count = U256::from(43).to_be_bytes::<32>();
        let mut key_response = [0u8; 96];
        key_response[..32].copy_from_slice(&sequencer_public.as_bytes()[1..]);
        key_response[63] = sequencer_public.as_bytes()[0];
        key_response[76..].copy_from_slice(&[0x11; 20]);

        let asserter = Asserter::new();
        asserter.push_success(&Bytes::copy_from_slice(&key_count));
        asserter.push_success(&Bytes::copy_from_slice(&key_response));
        asserter.push_success(&Bytes::copy_from_slice(&key_count));
        let provider = ProviderBuilder::new_with_network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone())
            .erased();
        let arguments = serde_yaml::from_str(
            r#"
portalAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
recipient: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
sender: "0xdddddddddddddddddddddddddddddddddddddddd"
zoneId: 9
"#,
        )
        .unwrap();
        let output = invoke(
            PREPARE_ENCRYPTED_DEPOSIT,
            &arguments,
            ScenarioActionContext { chain: "l1", chain_id: 1, query_provider: &provider },
        )
        .await
        .unwrap();
        let output = output.as_mapping().unwrap();

        assert_eq!(output["chainId"].as_u64(), Some(1));
        assert_eq!(output["keyIndex"].as_str(), Some("42"));
        assert_eq!(output["zoneId"].as_u64(), Some(9));
        let encrypted = output["encrypted"].as_mapping().unwrap();
        assert!(matches!(encrypted["ephemeralPubkeyYParity"].as_u64(), Some(2 | 3)));
        assert_eq!(encrypted["ciphertext"].as_str().unwrap().len(), 2 + 64 * 2);
        assert_eq!(encrypted["nonce"].as_str().unwrap().len(), 2 + 12 * 2);
        assert_eq!(encrypted["tag"].as_str().unwrap().len(), 2 + 16 * 2);
        assert!(asserter.read_q().is_empty());
    }
}
