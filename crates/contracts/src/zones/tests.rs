use super::*;
use alloc::vec;
use alloy_primitives::{Address, B256, Bytes, U256, address, b256, keccak256};
use alloy_sol_types::{SolCall, SolEvent, SolStruct, SolValue};
use std::println;

#[test]
fn test_withdrawal_bounce_back_abi_encode_vs_params() {
    let d = WithdrawalBounceBackDeposit {
        token: address!("0x0000000000000000000000000000000000001000"),
        to: Address::with_last_byte(2),
        amount: 1000u128,
    };

    let encoded = d.abi_encode();
    let encoded_params = d.abi_encode_params();

    println!("abi_encode length: {}", encoded.len());
    println!("abi_encode_params length: {}", encoded_params.len());
    println!("abi_encode hex:\n{}", const_hex::encode(&encoded));
    println!(
        "abi_encode_params hex:\n{}",
        const_hex::encode(&encoded_params)
    );
    println!("Are they equal: {}", encoded == encoded_params);
}

#[test]
fn test_queued_withdrawal_bounce_back_encoding() {
    let deposit = WithdrawalBounceBackDeposit {
        token: address!("0x0000000000000000000000000000000000001000"),
        to: Address::with_last_byte(2),
        amount: 1000u128,
    };

    let deposit_data = Bytes::from(deposit.abi_encode());

    let qd = QueuedDeposit {
        depositType: DepositType::WithdrawalBounceBack,
        rejected: false,
        depositData: deposit_data,
    };

    println!(
        "DepositType::WithdrawalBounceBack abi_encode: {}",
        const_hex::encode(DepositType::WithdrawalBounceBack.abi_encode())
    );
    println!(
        "deposit.abi_encode() length: {}",
        deposit.abi_encode().len()
    );
    println!(
        "deposit.abi_encode(): {}",
        const_hex::encode(deposit.abi_encode())
    );
    println!(
        "QueuedDeposit.abi_encode() length: {}",
        qd.abi_encode().len()
    );
    println!(
        "QueuedDeposit.abi_encode(): {}",
        const_hex::encode(qd.abi_encode())
    );

    // Now test the full advanceTempo call encoding
    let header_bytes = Bytes::from(vec![0xc0]); // minimal RLP empty list
    let calldata = IZoneInbox::advanceTempoCall {
        header: header_bytes,
        deposits: vec![qd],
        decryptions: vec![],
        enabledTokens: vec![],
    }
    .abi_encode();

    println!("\nadvanceTempo calldata length: {}", calldata.len());
    println!(
        "advanceTempo selector: {}",
        const_hex::encode_prefixed(&calldata[..4])
    );
    println!(
        "advanceTempo full calldata:\n{}",
        const_hex::encode(&calldata)
    );
}

#[test]
fn test_withdrawal_bounce_back_hash_chain_matches_solidity() {
    let deposit = WithdrawalBounceBackDeposit {
        token: address!("0x0000000000000000000000000000000000001000"),
        to: Address::with_last_byte(2),
        amount: 1000u128,
    };
    let prev_hash = B256::ZERO;

    let solidity_encoding = (
        DepositType::WithdrawalBounceBack,
        deposit.clone(),
        prev_hash,
    )
        .abi_encode();
    let solidity_hash = keccak256(&solidity_encoding);

    let rust_encoding = (DepositType::WithdrawalBounceBack, deposit, prev_hash).abi_encode();
    let rust_hash = keccak256(&rust_encoding);

    assert_eq!(solidity_encoding, rust_encoding, "ABI encodings must match");
    assert_eq!(
        solidity_hash, rust_hash,
        "WithdrawalBounceBackDeposit hash chains must match"
    );
}

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

#[test]
fn shared_bindings_preserve_wire_abi() {
    assert_eq!(
        IZoneFactory::createZoneCall::SELECTOR,
        [0x89, 0x67, 0x7d, 0x9e]
    );
    assert_eq!(
        IZoneVerifier::verifyCall::SELECTOR,
        [0xeb, 0xb2, 0xdd, 0xc9]
    );
    assert_eq!(legacySubmitBatchCall::SELECTOR, [0x78, 0xfb, 0x15, 0x9b]);
    assert_eq!(submitBatchCall::SELECTOR, [0x4c, 0xd6, 0xc7, 0xc7]);
    assert_eq!(
        ZonePortalPreT13Retired::submitBatchCall::SELECTOR,
        legacySubmitBatchCall::SELECTOR
    );
    assert_eq!(
        LegacyBatchSubmitted::SIGNATURE_HASH,
        b256!("5a66941dc92cb865480c966eff640c02b1d00d544b74332fd67c6f1cbfccdf39")
    );
    assert_eq!(
        BatchSubmitted::SIGNATURE_HASH,
        b256!("2ad9ed3f2b3ff263b7a3cf97621dfc164b1d2303160c10d0dc421f866d0d54ef")
    );
    assert_eq!(
        ZonePortal::LeaderUpdated::SIGNATURE_HASH,
        b256!("0e49bd8bbce34618e6af3bb74d587a65fa2a594df80b7cc21d690ee78c6d7a69")
    );
}

#[test]
fn native_verifier_and_portal_share_transition_types() {
    use crate::precompiles::IZoneVerifier as NativeVerifier;
    use core::any::TypeId;

    assert_eq!(
        TypeId::of::<BlockTransition>(),
        TypeId::of::<NativeVerifier::BlockTransition>()
    );
    assert_eq!(
        TypeId::of::<DepositQueueTransition>(),
        TypeId::of::<NativeVerifier::DepositQueueTransition>()
    );
    assert_eq!(
        TypeId::of::<TokenEnablementTransition>(),
        TypeId::of::<NativeVerifier::TokenEnablementTransition>()
    );
    assert_eq!(
        TypeId::of::<ZonePortal::Role>(),
        TypeId::of::<crate::precompiles::ZonePortalRole>()
    );
}

#[cfg(feature = "serde")]
#[test]
fn shared_verifier_call_supports_cli_serialization() {
    fn assert_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>() {}
    assert_serde::<IZoneVerifier::verifyCall>();
    assert_serde::<NitroBatchAttestation>();
}

#[test]
fn shared_nitro_attestation_matches_solidity_golden_vector() {
    let attestation = NitroBatchAttestation {
        parentChainId: U256::from(42_431),
        verifier: ZONE_VERIFIER_ADDRESS,
        zoneId: 12,
        tempoBlockNumber: 9,
        anchorBlockNumber: 10,
        anchorBlockHash: B256::with_last_byte(11),
        expectedWithdrawalBatchIndex: 13,
        nextZoneHeight: U256::from(14),
        prevBlockHash: B256::with_last_byte(1),
        nextBlockHash: B256::with_last_byte(2),
        prevProcessedHash: B256::with_last_byte(3),
        nextProcessedHash: B256::with_last_byte(4),
        prevDepositNumber: 5,
        nextDepositNumber: 6,
        prevProcessedTokenCount: 7,
        nextProcessedTokenCount: 8,
        withdrawalQueueHash: B256::with_last_byte(9),
        verifierConfigHash: keccak256([1]),
    };
    assert_eq!(
        keccak256(NitroBatchAttestation::eip712_encode_type().as_bytes()),
        b256!("b6f39555cba9bf38842c669ea0c90bca6aad793881d75a0034e33352fbecb25e")
    );
    assert_eq!(
        attestation.eip712_hash_struct(),
        b256!("1a703e80dd395e4720d1c88c877ed9f7d77c03052a985133b25cbf3e2b745b9d")
    );
}
