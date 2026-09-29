//! TIP-1108 commitment round trips through reth account representations.

use crate::account::{decode_config_commitment, encode_config_commitment};
use alloy_primitives::{B256, U256};
use reth_codecs::Compact;
use reth_primitives_traits::Account;
use revm::state::AccountInfo;

#[test]
fn commitment_survives_account_representations() {
    let commitment = B256::repeat_byte(9);
    let mut info = AccountInfo::default().with_extension(encode_config_commitment(commitment));
    assert!(!info.is_empty());
    info.nonce = 3;
    info.balance = U256::from(7);
    let account = Account::from(info);
    let mut encoded = Vec::new();
    let len = account.to_compact(&mut encoded);
    let (decoded, rest) = Account::from_compact(&encoded, len);
    assert!(rest.is_empty());
    assert_eq!(decoded, account);
    let trie = decoded.into_trie_account(B256::repeat_byte(4));
    // The opaque payload is raw, but the consensus leaf contains exactly one RLP string.
    let encoded = alloy_rlp::encode(&trie);
    let mut fields = encoded.as_slice();
    let header = alloy_rlp::Header::decode(&mut fields).unwrap();
    assert!(header.list);
    assert_eq!(header.payload_length, fields.len());
    for _ in 0..4 {
        alloy_rlp::Header::decode_bytes(&mut fields, false).unwrap();
    }
    assert_eq!(fields, alloy_rlp::encode(commitment));
    let mut legacy = trie.clone();
    legacy.extension = Default::default();
    let legacy = alloy_rlp::encode(&legacy);
    let mut fields = legacy.as_slice();
    let header = alloy_rlp::Header::decode(&mut fields).unwrap();
    assert!(header.list);
    assert_eq!(header.payload_length, fields.len());
    for _ in 0..4 {
        alloy_rlp::Header::decode_bytes(&mut fields, false).unwrap();
    }
    assert!(fields.is_empty());
    assert_eq!(
        decode_config_commitment(&trie.extension, true),
        Ok(commitment)
    );
    let mut reloaded: AccountInfo = Account::from(trie).into();
    assert_eq!(reloaded.nonce, 3);
    assert_eq!(reloaded.balance, U256::from(7));
    reloaded.nonce = 0;
    reloaded.balance = U256::ZERO;
    assert!(!reloaded.is_empty());
    assert_eq!(
        decode_config_commitment(&reloaded.extension, true),
        Ok(commitment)
    );
}
