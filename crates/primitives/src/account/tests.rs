use super::*;
#[cfg(all(feature = "reth", feature = "evm", feature = "reth-codec"))]
use alloy_primitives::U256;
#[cfg(all(feature = "reth", feature = "evm", feature = "reth-codec"))]
use reth_codecs::Compact;
#[cfg(all(feature = "reth", feature = "evm", feature = "reth-codec"))]
use reth_primitives_traits::Account;
#[cfg(all(feature = "reth", feature = "evm", feature = "reth-codec"))]
use revm::state::AccountInfo;

#[test]
fn commitment_roundtrip_and_t14_gate() {
    assert!(encode_config_commitment(B256::ZERO).is_empty());
    for active in [false, true] {
        assert_eq!(decode_config_commitment(&[], active), Ok(B256::ZERO));
    }
    let hash = B256::repeat_byte(7);
    let payload = encode_config_commitment(hash);
    assert_eq!(payload.as_ref(), hash.as_slice());
    assert_eq!(decode_config_commitment(&payload, true), Ok(hash));
    assert_eq!(
        decode_config_commitment(&payload, false),
        Err(alloy_rlp::Error::Custom("account commitment before T14"))
    );
}

#[test]
fn rejects_malformed_and_noncanonical_extensions() {
    let mut trailing = encode_config_commitment(B256::repeat_byte(7)).to_vec();
    trailing.push(0x80);
    for payload in [
        vec![0; 32],
        vec![7; 31],
        vec![7; 33],
        vec![0xc0],
        vec![0xa0, 7],
        trailing,
        alloy_rlp::encode(B256::repeat_byte(7)),
    ] {
        assert!(
            decode_config_commitment(&payload, true).is_err(),
            "{payload:?}"
        );
    }
}

#[cfg(all(feature = "reth", feature = "evm", feature = "reth-codec"))]
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
