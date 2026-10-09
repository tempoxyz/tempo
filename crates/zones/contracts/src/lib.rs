//! ABI bindings for the Tempo Zone protocol contracts.
//!
//! These bindings cover the contracts the sequencer interacts with across both layers:
//!
//! - **ZonePortal** — deployed on Tempo L1. Escrows gas tokens, manages the deposit queue,
//!   accepts batch proofs, and processes withdrawals back to L1 recipients.
//! - **ZoneOutbox** — deployed on the Zone L2. Collects user withdrawal requests, builds
//!   withdrawal hash chains, and exposes `LastBatch` state for proof generation.
//! - **ZoneInbox** — deployed on the Zone L2. Advances finalized Tempo state, activates bridged
//!   tokens, processes deposits, and tracks deposit queue progress.
//! - **TempoState** — deployed on the Zone L2. Stores the finalized Tempo block checkpoint and
//!   provides anchored Tempo storage reads to zone system execution.
//! - **ZoneFactory** — native TIP-1091 precompile on Tempo L1.
//! - **SwapAndDepositRouter** — deployed on Tempo L1.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// auto-generated sol! builders for events/errors/functions with many fields trigger this
#![allow(clippy::too_many_arguments)]

extern crate alloc;

/// Helper macro to allow feature-gating rpc and serde implementations.
macro_rules! sol {
    ($($input:tt)*) => {
        #[cfg(all(feature = "rpc", feature = "serde"))]
        alloy_sol_types::sol! {
            #[sol(rpc)]
            #[derive(serde::Serialize, serde::Deserialize)]
            $($input)*
        }
        #[cfg(all(feature = "rpc", not(feature = "serde")))]
        alloy_sol_types::sol! {
            #[sol(rpc)]
            $($input)*
        }
        #[cfg(all(not(feature = "rpc"), feature = "serde"))]
        alloy_sol_types::sol! {
            #[derive(serde::Serialize, serde::Deserialize)]
            $($input)*
        }
        #[cfg(all(not(feature = "rpc"), not(feature = "serde")))]
        alloy_sol_types::sol! {
            $($input)*
        }
    };
}

pub(crate) use sol;

pub mod precompiles;

pub use precompiles::*;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256};
    use alloy_sol_types::{SolCall, SolValue};

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
}
