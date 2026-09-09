use super::*;

#[test]
fn commitment_roundtrip_and_historical_gate() {
    assert!(encode_config_commitment(B256::ZERO).is_empty());
    for active in [false, true] {
        assert_eq!(decode_config_commitment(&[], active), Ok(B256::ZERO));
    }
    let hash = B256::repeat_byte(7);
    let payload = encode_config_commitment(hash);
    assert_eq!(payload.len(), 33);
    assert_eq!(payload[0], 0xa0);
    assert_eq!(decode_config_commitment(&payload, true), Ok(hash));
    assert!(decode_config_commitment(&payload, false).is_err());
}

#[test]
fn rejects_malformed_and_noncanonical_extensions() {
    let mut trailing = encode_config_commitment(B256::repeat_byte(7)).to_vec();
    trailing.push(0x80);
    let mut noncanonical = vec![0xb8, 32];
    noncanonical.extend([7; 32]);
    for payload in [
        alloy_rlp::encode(B256::ZERO),
        alloy_rlp::encode(&[7u8; 31][..]),
        alloy_rlp::encode(&[7u8; 33][..]),
        vec![0xc0],
        vec![0xa0, 7],
        trailing,
        noncanonical,
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
    use reth_codecs::Compact;
    use reth_primitives_traits::Account;
    use revm::state::AccountInfo;

    let commitment = B256::repeat_byte(9);
    let mut info = AccountInfo::default().with_extension(encode_config_commitment(commitment));
    assert!(!info.is_empty());
    info.nonce = 3;
    info.balance = alloy_primitives::U256::from(7);
    let account = Account::from(info);
    let mut encoded = Vec::new();
    let len = account.to_compact(&mut encoded);
    let (decoded, rest) = Account::from_compact(&encoded, len);
    assert!(rest.is_empty());
    assert_eq!(decoded, account);
    let trie = decoded.into_trie_account(B256::repeat_byte(4));
    assert_eq!(
        decode_config_commitment(&trie.extension, true),
        Ok(commitment)
    );
    let mut reloaded: AccountInfo = Account::from(trie).into();
    assert_eq!(reloaded.nonce, 3);
    assert_eq!(reloaded.balance, alloy_primitives::U256::from(7));
    reloaded.nonce = 0;
    reloaded.balance = alloy_primitives::U256::ZERO;
    assert!(!reloaded.is_empty());
    assert_eq!(
        decode_config_commitment(&reloaded.extension, true),
        Ok(commitment)
    );
}
