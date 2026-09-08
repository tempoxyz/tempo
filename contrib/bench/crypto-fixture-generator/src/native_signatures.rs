//! Ordinary native SignatureVerifier fixtures; native execution is checked at setup.
use super::*;
use p256::ecdsa::signature::hazmat::PrehashVerifier;

fn add_signature(
    rows: &mut Vec<Value>,
    kind: &str,
    hash: &[u8],
    signature: Vec<u8>,
    signer: &[u8],
    crypto_gas: u64,
) {
    assert_eq!(hash.len(), 32);
    assert_eq!(signer.len(), 20);
    assert!(signature.len() <= 512);
    for verify in [false, true] {
        let method = if verify { "verify" } else { "recover" };
        let declaration = if verify {
            "verify(address,bytes32,bytes)"
        } else {
            "recover(bytes32,bytes)"
        };
        let selector = keccak256(declaration);
        let mut input = selector[..4].to_vec();
        if verify {
            input.extend(pad(signer, 32));
        }
        input.extend_from_slice(hash);
        input.extend(pad(&[if verify { 96 } else { 64 }], 32));
        input.extend(pad(&(signature.len() as u64).to_be_bytes(), 32));
        input.extend_from_slice(&signature);
        input.resize(4 + (input.len() - 4).next_multiple_of(32), 0);
        assert!(input.len() <= 1024);
        let expected = if verify {
            pad(&[1], 32)
        } else {
            pad(signer, 32)
        };
        rows.push(json!({
            "name": format!("native-{kind}-{method}"),
            "address": "0x5165300000000000000000000000000000000000",
            "input": format!("0x{}", hex::encode(input)),
            "expected": format!("0x{}", hex::encode(expected)),
            "source_crypto_gas": crypto_gas,
            "fork": "T10",
            "oracle": "locally verified fixed-test-key signature and derived signer; native ABI execution requires runtime constructor validation",
            "source": "Tempo SignatureVerifier and tt_signature formats; source_crypto_gas excludes ABI input and other native overhead"
        }));
    }
}

pub(super) fn fixtures() -> Vec<Value> {
    let mut rows = Vec::new();
    let hash = [0xaau8; 32];
    let signing = k256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let (signature, recovery) = signing.sign_prehash_recoverable(&hash).unwrap();
    signing
        .verifying_key()
        .verify_prehash(&hash, &signature)
        .unwrap();
    let public = signing.verifying_key().to_encoded_point(false);
    let address = keccak256(&public.as_bytes()[1..]);
    let recovery_input = [
        hash.to_vec(),
        pad(&[27 + recovery.to_byte()], 32),
        signature.to_bytes().to_vec(),
    ]
    .concat();
    assert_eq!(output(1, &recovery_input).0, pad(&address[12..], 32));
    let mut encoded = signature.to_bytes().to_vec();
    encoded.push(27 + recovery.to_byte());
    add_signature(&mut rows, "secp256k1", &hash, encoded, &address[12..], 3000);

    // Public deterministic test key, never a wallet key or a real passkey.
    let signing = p256::ecdsa::SigningKey::from_bytes(&[11u8; 32].into()).unwrap();
    let public = signing.verifying_key().to_encoded_point(false);
    let address = keccak256(&public.as_bytes()[1..]);
    for prehash in [false, true] {
        let message = if prehash {
            output(2, &hash).0
        } else {
            hash.to_vec()
        };
        let signature: p256::ecdsa::Signature = signing.sign_prehash(&message).unwrap();
        let signature = signature.normalize_s().unwrap_or(signature);
        signing
            .verifying_key()
            .verify_prehash(&message, &signature)
            .unwrap();
        let encoded = [
            vec![1],
            signature.to_bytes().to_vec(),
            public.as_bytes()[1..].to_vec(),
            vec![u8::from(prehash)],
        ]
        .concat();
        assert_eq!(encoded.len(), 130);
        add_signature(
            &mut rows,
            if prehash { "p256-prehash" } else { "p256-raw" },
            &hash,
            encoded,
            &address[12..],
            8000,
        );
    }

    let client = json!({
        "type": "webauthn.get",
        // Base64url without padding of the fixed 32-byte 0xaa challenge above.
        "challenge": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo",
        "origin": "https://bench.example",
        "crossOrigin": false,
    })
    .to_string()
    .into_bytes();
    let mut auth_data = output(2, b"bench.example").0;
    auth_data.extend_from_slice(&[5, 0, 0, 0, 0]); // UP + UV, zero sign count; no extensions.
    assert_eq!(auth_data.len(), 37);
    let message = output(2, &[auth_data.clone(), output(2, &client).0].concat()).0;
    let signature: p256::ecdsa::Signature = signing.sign_prehash(&message).unwrap();
    let signature = signature.normalize_s().unwrap_or(signature);
    signing
        .verifying_key()
        .verify_prehash(&message, &signature)
        .unwrap();
    let encoded = [
        vec![2],
        auth_data,
        client,
        signature.to_bytes().to_vec(),
        public.as_bytes()[1..].to_vec(),
    ]
    .concat();
    add_signature(&mut rows, "webauthn", &hash, encoded, &address[12..], 8000);
    assert_eq!(rows.len(), 8);
    rows
}
