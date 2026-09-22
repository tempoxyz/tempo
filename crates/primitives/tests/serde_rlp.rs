#![cfg(feature = "serde")]

use alloy_primitives::Bytes;
use serde::{Deserialize, Serialize};
use tempo_primitives::TempoHeader;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Proof {
    #[serde(with = "tempo_primitives::serde_rlp")]
    header: TempoHeader,
}

#[derive(Serialize, Deserialize)]
struct EncodedProof {
    header: Bytes,
}

#[test]
fn preserves_json() {
    let proof = Proof {
        header: TempoHeader::default(),
    };
    let json = serde_json::to_value(&proof).unwrap();
    assert_eq!(json["header"], serde_json::to_value(&proof.header).unwrap());
    assert_eq!(serde_json::from_value::<Proof>(json).unwrap(), proof);
}

#[test]
fn messagepack_uses_rlp_bytes() {
    let proof = Proof {
        header: TempoHeader::default(),
    };
    let encoded = rmp_serde::to_vec(&proof).unwrap();
    let raw: EncodedProof = rmp_serde::from_slice(&encoded).unwrap();
    assert_eq!(raw.header.as_ref(), alloy_rlp::encode(&proof.header));
    assert_eq!(encoded, rmp_serde::to_vec(&raw).unwrap());
    assert_eq!(rmp_serde::from_slice::<Proof>(&encoded).unwrap(), proof);
    assert_eq!(
        rmp_serde::from_read::<_, Proof>(encoded.as_slice()).unwrap(),
        proof
    );
}

#[test]
fn rejects_invalid_rlp() {
    let encoded = rmp_serde::to_vec(&EncodedProof {
        header: Bytes::new(),
    })
    .unwrap();
    assert!(rmp_serde::from_slice::<Proof>(&encoded).is_err());
}

#[test]
fn rejects_trailing_rlp_bytes() {
    let mut rlp = alloy_rlp::encode(TempoHeader::default());
    rlp.push(0x80);
    let encoded = rmp_serde::to_vec(&EncodedProof { header: rlp.into() }).unwrap();
    assert!(rmp_serde::from_slice::<Proof>(&encoded).is_err());
}
