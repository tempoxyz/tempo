//! TIP-1108 configuration commitments in the opaque account extension payload.

use alloy_primitives::{B256, Bytes};
use alloy_rlp::Error;
use tempo_contracts::TempoHardfork;

const COMMITMENT_FORMAT_TAG: u8 = 0;

/// Returns the format tag followed by `hash`, or an empty payload when `hash` is zero.
pub fn encode_config_commitment(hash: B256) -> Bytes {
    if hash.is_zero() {
        Bytes::new()
    } else {
        [&[COMMITMENT_FORMAT_TAG][..], hash.as_slice()]
            .concat()
            .into()
    }
}

/// Validates the entire extension under `hardfork`: a non-empty payload is rejected before T14.
pub fn decode_config_commitment(
    payload: &[u8],
    hardfork: TempoHardfork,
) -> alloy_rlp::Result<B256> {
    if payload.is_empty() {
        return Ok(B256::ZERO);
    }
    if !hardfork.is_t14() {
        return Err(Error::Custom("account commitment before T14"));
    }
    if payload[0] != COMMITMENT_FORMAT_TAG {
        return Err(Error::Custom("unsupported account commitment format"));
    }
    let hash = B256::try_from(&payload[1..])
        .map_err(|_| Error::Custom("tagged account commitment must be 33 bytes"))?;
    if hash.is_zero() {
        return Err(Error::Custom("explicit zero account commitment"));
    }
    Ok(hash)
}
