#![no_main]

use alloy_rlp::{Decodable, Encodable};
use libfuzzer_sys::fuzz_target;
use tempo_primitives::{
    SubBlockMetadata, TempoHeader, TempoTransaction,
    transaction::{KeyAuthorization, TempoSignedAuthorization, TokenLimit},
};

fn assert_canonical_roundtrip<T>(data: &[u8], name: &str)
where
    T: Decodable + Encodable,
{
    let mut input = data;
    let Ok(decoded) = T::decode(&mut input) else {
        return;
    };

    let consumed = data.len() - input.len();
    let reencoded = alloy_rlp::encode(decoded);
    assert_eq!(
        reencoded,
        data[..consumed],
        "{name}: encode(decode(bytes)) produced non-canonical RLP"
    );
}

fuzz_target!(|data: &[u8]| {
    assert_canonical_roundtrip::<TempoHeader>(data, "TempoHeader");
    assert_canonical_roundtrip::<TempoTransaction>(data, "TempoTransaction");
    assert_canonical_roundtrip::<TempoSignedAuthorization>(data, "TempoSignedAuthorization");
    assert_canonical_roundtrip::<KeyAuthorization>(data, "KeyAuthorization");
    assert_canonical_roundtrip::<TokenLimit>(data, "TokenLimit");
    assert_canonical_roundtrip::<SubBlockMetadata>(data, "SubBlockMetadata");
});
