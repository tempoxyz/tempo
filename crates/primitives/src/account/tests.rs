use super::*;

#[test]
fn commitment_roundtrip_and_t14_gate() {
    assert!(encode_config_commitment(B256::ZERO).is_empty());
    for active in [false, true] {
        assert_eq!(decode_config_commitment(&[], active), Ok(B256::ZERO));
    }
    let hash = B256::repeat_byte(7);
    let payload = encode_config_commitment(hash);
    assert_eq!(payload.len(), 33);
    assert_eq!(payload[0], 0);
    assert_eq!(&payload[1..], hash.as_slice());
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
    let mut unknown_tag = encode_config_commitment(B256::repeat_byte(7)).to_vec();
    unknown_tag[0] = 1;
    assert_eq!(
        decode_config_commitment(&[0; 32], true),
        Err(alloy_rlp::Error::Custom(
            "tagged account commitment must be 33 bytes"
        ))
    );
    for payload in [
        vec![7; 32],
        vec![0; 32],
        vec![7; 31],
        vec![7; 33],
        vec![0; 33],
        unknown_tag,
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
