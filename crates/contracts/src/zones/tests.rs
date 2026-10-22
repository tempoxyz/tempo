use super::*;
use alloc::vec;
use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256};
use alloy_sol_types::SolValue;

#[test]
fn test_decryption_data_encoding_uses_trimmed_layout() {
    let shared_secret = B256::repeat_byte(0x11);
    let shared_secret_y_parity = 0x02;
    let proof_s = B256::repeat_byte(0x33);
    let proof_c = B256::repeat_byte(0x44);

    let decryption = DecryptionData {
        sharedSecret: shared_secret,
        sharedSecretYParity: shared_secret_y_parity,
        cpProof: ChaumPedersenProof {
            s: proof_s,
            c: proof_c,
        },
    };

    let encoded = decryption.abi_encode();
    let expected_y_parity_word = B256::with_last_byte(shared_secret_y_parity);

    assert_eq!(
        encoded.len(),
        4 * 32,
        "DecryptionData must encode as four ABI words"
    );
    assert_eq!(
        &encoded[0..32],
        shared_secret.as_slice(),
        "word 0 is sharedSecret"
    );
    assert_eq!(
        &encoded[32..64],
        expected_y_parity_word.as_slice(),
        "word 1 is sharedSecretYParity"
    );
    assert_eq!(&encoded[64..96], proof_s.as_slice(), "word 2 is cpProof.s");
    assert_eq!(&encoded[96..128], proof_c.as_slice(), "word 3 is cpProof.c");
}

#[test]
fn test_sender_tag_matches_plaintext_hash() {
    let sender = Address::with_last_byte(1);
    let tx_hash = B256::repeat_byte(0x22);
    let fallback_nonce = 7u64;
    let plaintext = Withdrawal::authenticated_sender_plaintext(sender, tx_hash);
    let mut tag_preimage = [0u8; 60];
    tag_preimage[..52].copy_from_slice(&plaintext);
    tag_preimage[52..].copy_from_slice(&fallback_nonce.to_be_bytes());

    assert_eq!(&plaintext[..20], sender.as_slice());
    assert_eq!(&plaintext[20..], tx_hash.as_slice());
    assert_eq!(
        Withdrawal::sender_tag(sender, tx_hash, fallback_nonce),
        keccak256(tag_preimage)
    );
}

#[test]
fn test_router_callback_encoding_matches_tuple() {
    let encrypted = DepositPayload {
        ephemeralPubkeyX: B256::repeat_byte(0x22),
        ephemeralPubkeyYParity: 0x02,
        ciphertext: Bytes::from(vec![0xaa, 0xbb, 0xcc, 0xdd]),
        nonce: [0x33; 12].into(),
        tag: [0x44; 16].into(),
    };
    let callback = SwapAndDepositRouterCallback {
        token_out: address!("0x0000000000000000000000000000000000001002"),
        target_portal: address!("0x0000000000000000000000000000000000002002"),
        key_index: U256::from(7),
        encrypted: encrypted.clone(),
        tempo_refund_recipient: address!("0x0000000000000000000000000000000000004002"),
        min_amount_out: 5678,
    };

    let tuple_encoding = (
        callback.token_out,
        callback.target_portal,
        callback.key_index,
        encrypted,
        callback.tempo_refund_recipient,
        callback.min_amount_out,
    )
        .abi_encode_params();

    assert_eq!(callback.abi_encode(), tuple_encoding);
}
