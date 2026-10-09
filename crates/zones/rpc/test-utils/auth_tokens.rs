use alloy_primitives::{Address, B256, Bytes};
use base64::Engine as _;
use p256::{
    EncodedPoint,
    ecdsa::{SigningKey as P256SigningKey, signature::hazmat::PrehashSigner},
};
use sha2::{Digest, Sha256};
use tempo_primitives::transaction::tt_signature::{
    KeychainSignature, PrimitiveSignature, TempoSignature, WebAuthnSignature, normalize_p256_s,
};

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

pub(crate) fn build_signed_token_blob(signature: TempoSignature, fields: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(signature.encoded_length() + fields.len());
    blob.extend_from_slice(signature.to_bytes().as_ref());
    blob.extend_from_slice(fields);
    blob
}

pub(crate) fn build_token_with_signature(signature: TempoSignature, fields: &[u8]) -> String {
    alloy_primitives::hex::encode(build_signed_token_blob(signature, fields))
}

pub(crate) fn sign_p256_signature(
    digest: B256,
    signing_key: &P256SigningKey,
) -> eyre::Result<TempoSignature> {
    let pre_hashed = Sha256::digest(digest);
    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&pre_hashed)?;
    let sig_bytes = signature.to_bytes();
    let (pub_key_x, pub_key_y) = p256_public_key(signing_key);

    Ok(TempoSignature::Primitive(PrimitiveSignature::P256(
        tempo_primitives::transaction::tt_signature::P256SignatureWithPreHash {
            r: B256::from_slice(&sig_bytes[0..32]),
            s: normalize_p256_s(&sig_bytes[32..64]).map_err(|err| eyre::eyre!(err))?,
            pub_key_x,
            pub_key_y,
            pre_hash: true,
        },
    )))
}

pub(crate) fn sign_webauthn_signature(
    signing_key: &P256SigningKey,
    challenge_digest: B256,
) -> eyre::Result<TempoSignature> {
    let mut authenticator_data = vec![0u8; 37];
    authenticator_data[0..32].copy_from_slice(&[0xAA; 32]);
    authenticator_data[32] = 0x01;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_digest);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://example.com","crossOrigin":false}}"#
    );
    let client_data_hash = Sha256::digest(client_data_json.as_bytes());
    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data);
    final_hasher.update(client_data_hash);
    let message_hash = final_hasher.finalize();
    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&message_hash)?;
    let sig_bytes = signature.to_bytes();
    let (pub_key_x, pub_key_y) = p256_public_key(signing_key);
    let mut webauthn_data = authenticator_data;
    webauthn_data.extend_from_slice(client_data_json.as_bytes());

    Ok(TempoSignature::Primitive(PrimitiveSignature::WebAuthn(
        WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data),
            r: B256::from_slice(&sig_bytes[0..32]),
            s: normalize_p256_s(&sig_bytes[32..64]).map_err(|err| eyre::eyre!(err))?,
            pub_key_x,
            pub_key_y,
        },
    )))
}

pub(crate) fn sign_keychain_signature(
    digest: B256,
    signing_key: &P256SigningKey,
    root_account: Address,
    version: u8,
) -> eyre::Result<(TempoSignature, Address)> {
    let signing_hash = match version {
        0x03 => digest,
        0x04 => KeychainSignature::signing_hash(digest, root_account),
        _ => {
            eyre::bail!("unsupported keychain version");
        }
    };
    let primitive = match sign_p256_signature(signing_hash, signing_key)? {
        TempoSignature::Primitive(primitive) => primitive,
        TempoSignature::Keychain(_) => unreachable!("primitive signature expected"),
    };
    let signature = if version == 0x03 {
        TempoSignature::Keychain(KeychainSignature::new_v1(root_account, primitive))
    } else {
        TempoSignature::Keychain(KeychainSignature::new(root_account, primitive))
    };
    let key_id = match &signature {
        TempoSignature::Keychain(keychain) => keychain
            .key_id(&digest)
            .map_err(|err| eyre::eyre!("inner key recovery failed: {err}"))?,
        TempoSignature::Primitive(_) => unreachable!("keychain signature expected"),
    };

    Ok((signature, key_id))
}

fn p256_public_key(signing_key: &P256SigningKey) -> (B256, B256) {
    let encoded = EncodedPoint::from(signing_key.verifying_key());
    (
        B256::from_slice(encoded.x().expect("x coordinate present")),
        B256::from_slice(encoded.y().expect("y coordinate present")),
    )
}
