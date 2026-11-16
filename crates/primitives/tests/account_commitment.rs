use alloy_primitives::B256;
use alloy_rlp::Error;
use tempo_contracts::TempoHardfork;
use tempo_primitives::account::{decode_config_commitment, encode_config_commitment};
use test_case::test_case;

#[test]
fn commitment_roundtrip_and_t14_gate() {
    assert!(encode_config_commitment(B256::ZERO).is_empty());
    for hardfork in [TempoHardfork::T13, TempoHardfork::T14] {
        assert_eq!(decode_config_commitment(&[], hardfork), Ok(B256::ZERO));
    }
    let hash = B256::repeat_byte(7);
    let payload = encode_config_commitment(hash);
    assert_eq!(payload.len(), 33);
    assert_eq!(payload[0], 0);
    assert_eq!(&payload[1..], hash);
    assert_eq!(
        decode_config_commitment(&payload, TempoHardfork::T14),
        Ok(hash)
    );
    assert_eq!(
        decode_config_commitment(&payload, TempoHardfork::T13),
        Err(Error::Custom("account commitment before T14"))
    );
}

#[test]
fn rejects_untagged_32_byte_commitment() {
    assert_eq!(
        decode_config_commitment(&[0; 32], TempoHardfork::T14),
        Err(Error::Custom("tagged account commitment must be 33 bytes"))
    );
}

#[test_case(vec![7; 32])]
#[test_case(vec![0; 32])]
#[test_case(vec![7; 31])]
#[test_case(vec![7; 33])]
#[test_case(vec![0; 33])]
#[test_case({ let mut unknown_tag = encode_config_commitment(B256::repeat_byte(7)).to_vec(); unknown_tag[0] = 1; unknown_tag }; "unknown_tag")]
#[test_case(vec![0xc0])]
#[test_case(vec![0xa0, 7])]
#[test_case({ let mut trailing = encode_config_commitment(B256::repeat_byte(7)).to_vec(); trailing.push(0x80); trailing }; "trailing")]
#[test_case(alloy_rlp::encode(B256::repeat_byte(7)); "rlp_encoded_hash")]
fn rejects_malformed_and_noncanonical_extensions(payload: Vec<u8>) {
    assert!(decode_config_commitment(&payload, TempoHardfork::T14).is_err());
}
