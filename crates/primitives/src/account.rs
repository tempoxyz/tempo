//! TIP-1108 configuration commitments in the opaque account extension payload.

use alloy_primitives::{B256, Bytes};
use alloy_rlp::{Decodable, Error};

/// Encodes the optional fifth account-leaf field. Zero preserves the legacy leaf.
pub fn encode_config_commitment(hash: B256) -> Bytes {
    if hash.is_zero() {
        Bytes::new()
    } else {
        alloy_rlp::encode(hash).into()
    }
}

/// Validates the entire extension at the requested block's hardfork.
pub fn decode_config_commitment(mut payload: &[u8], t12_active: bool) -> alloy_rlp::Result<B256> {
    if payload.is_empty() {
        return Ok(B256::ZERO);
    }
    if !t12_active {
        return Err(Error::Custom("account commitment before T12"));
    }
    let hash = B256::decode(&mut payload)?;
    if hash.is_zero() {
        return Err(Error::Custom("explicit zero account commitment"));
    }
    if !payload.is_empty() {
        return Err(Error::Custom("trailing account extension fields"));
    }
    Ok(hash)
}

#[cfg(test)]
mod tests;
