//! TIP-1108 configuration commitments in the opaque account extension payload.

use alloy_primitives::{B256, Bytes};
use alloy_rlp::Error;

/// Returns the raw fifth-field payload; the trie adds RLP framing. Zero omits the field.
pub fn encode_config_commitment(hash: B256) -> Bytes {
    if hash.is_zero() {
        Bytes::new()
    } else {
        Bytes::copy_from_slice(hash.as_slice())
    }
}

/// Validates the entire extension at the requested block's hardfork.
pub fn decode_config_commitment(payload: &[u8], t12_active: bool) -> alloy_rlp::Result<B256> {
    if payload.is_empty() {
        return Ok(B256::ZERO);
    }
    if !t12_active {
        return Err(Error::Custom("account commitment before T12"));
    }
    let hash = B256::try_from(payload)
        .map_err(|_| Error::Custom("account commitment must be 32 bytes"))?;
    if hash.is_zero() {
        return Err(Error::Custom("explicit zero account commitment"));
    }
    Ok(hash)
}

#[cfg(test)]
mod tests;
