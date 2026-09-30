//! TIP-1108 configuration commitments in the opaque account extension payload.

use alloc::vec::Vec;
use alloy_primitives::{B256, Bytes};
use alloy_rlp::Error;

const COMMITMENT_FORMAT_TAG: u8 = 0;

/// Returns the raw fifth-field payload; the trie adds RLP framing. Zero omits the field.
pub fn encode_config_commitment(hash: B256) -> Bytes {
    if hash.is_zero() {
        Bytes::new()
    } else {
        let mut payload = Vec::with_capacity(1 + B256::len_bytes());
        payload.push(COMMITMENT_FORMAT_TAG);
        payload.extend_from_slice(hash.as_slice());
        payload.into()
    }
}

/// Validates the entire extension at the requested block's hardfork.
pub fn decode_config_commitment(payload: &[u8], t14_active: bool) -> alloy_rlp::Result<B256> {
    if payload.is_empty() {
        return Ok(B256::ZERO);
    }
    if !t14_active {
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

#[cfg(test)]
mod tests;
