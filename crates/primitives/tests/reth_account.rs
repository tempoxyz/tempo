#![cfg(all(feature = "evm", feature = "reth-codec"))]
//! TIP-1108 commitment round trips through reth account representations.

use alloy_primitives::{B256, U256};
use alloy_rlp::Header;
use reth_codecs::Compact;
use reth_primitives_traits::Account;
use revm::state::AccountInfo;
use tempo_primitives::account::{decode_config_commitment, encode_config_commitment};

/// Decodes a trie leaf into its RLP string fields, asserting canonical list framing.
fn leaf_fields(mut buf: &[u8]) -> Vec<&[u8]> {
    let header = Header::decode(&mut buf).unwrap();
    assert!(header.list);
    assert_eq!(header.payload_length, buf.len());
    let mut fields = Vec::new();
    while !buf.is_empty() {
        fields.push(Header::decode_bytes(&mut buf, false).unwrap());
    }
    fields
}

#[test]
fn commitment_survives_account_representations() {
    let commitment = B256::repeat_byte(9);
    let mut info = AccountInfo::default().with_extension(encode_config_commitment(commitment));
    assert!(info.exists());
    info.set_nonce(3);
    info.set_balance(U256::from(7));
    let account = Account::from(info);
    let mut encoded = Vec::new();
    let len = account.to_compact(&mut encoded);
    let (decoded, rest) = Account::from_compact(&encoded, len);
    assert_eq!(rest, b"");
    assert_eq!(decoded, account);
    let trie = decoded.into_trie_account(B256::repeat_byte(4));
    // The opaque payload is raw, but the consensus leaf contains exactly one RLP string.
    let encoded = alloy_rlp::encode(&trie);
    let fields = leaf_fields(&encoded);
    assert_eq!(fields.len(), 5);
    let payload = fields[4];
    assert_eq!(payload.len(), 33);
    assert_eq!(payload[0], 0);
    assert_eq!(&payload[1..], commitment);
    let mut legacy = trie.clone();
    legacy.extension = Default::default();
    assert_eq!(leaf_fields(&alloy_rlp::encode(&legacy)).len(), 4);
    assert_eq!(
        decode_config_commitment(&trie.extension, true),
        Ok(commitment)
    );
    let mut reloaded: AccountInfo = Account::from(trie).into();
    assert_eq!(reloaded.nonce, 3);
    assert_eq!(reloaded.balance, U256::from(7));
    reloaded.set_nonce(0);
    reloaded.set_balance(U256::ZERO);
    assert!(reloaded.exists());
    assert_eq!(
        decode_config_commitment(&reloaded.extension, true),
        Ok(commitment)
    );
}
