use super::*;

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
