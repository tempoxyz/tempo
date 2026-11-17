//! `Secp256k1Lib`: the curve checks and key-to-address derivation the portal applies to
//! sequencer encryption keys and deposit ephemeral keys.
//!
//! The Solidity library raises to a power through the MODEXP precompile; the native portal computes
//! the same results with [`U256::pow_mod`], so no modexp gas is charged.

use crate::{error::Result, storage::StorageCtx};
use alloy::primitives::{Address, B256, U256, uint};

/// `Secp256k1Lib.SECP256K1_P`: the field prime.
pub(crate) const SECP256K1_P: U256 =
    uint!(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F_U256);

/// `Secp256k1Lib.SECP256K1_HALF_PM1`: `(p - 1) / 2`, Euler's criterion exponent.
const SECP256K1_HALF_PM1: U256 =
    uint!(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFE17_U256);

/// `Secp256k1Lib.SECP256K1_SQRT_EXP`: `(p + 1) / 4`, the square-root exponent.
const SECP256K1_SQRT_EXP: U256 =
    uint!(0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C_U256);

/// `Secp256k1Lib.isCompressedYParity`.
pub(crate) fn is_compressed_y_parity(y_parity: u8) -> bool {
    y_parity == 0x02 || y_parity == 0x03
}

/// `Secp256k1Lib.isValidX`: `x` is a nonzero field element and `x^3 + 7` is a quadratic
/// residue, so `x` is the X coordinate of a curve point.
pub(crate) fn is_valid_x(x: B256) -> bool {
    let px = U256::from_be_bytes(x.0);
    if px.is_zero() || px >= SECP256K1_P {
        return false;
    }
    curve_rhs(px).pow_mod(SECP256K1_HALF_PM1, SECP256K1_P) == U256::ONE
}

/// `Secp256k1Lib.deriveAddress`: the address of the compressed public key `(x, y_parity)`.
/// Charges the keccak256 gas through the storage context.
pub(crate) fn derive_address(x: B256, y_parity: u8) -> Result<Address> {
    let px = U256::from_be_bytes(x.0);
    let mut y = curve_rhs(px).pow_mod(SECP256K1_SQRT_EXP, SECP256K1_P);
    if y.bit(0) == (y_parity == 0x02) {
        y = SECP256K1_P - y;
    }
    let hash = StorageCtx.keccak256(&[px.to_be_bytes::<32>(), y.to_be_bytes::<32>()].concat())?;
    Ok(Address::from_word(hash))
}

/// `Secp256k1Lib._curveRhs`: `x^3 + 7 mod p`.
fn curve_rhs(px: U256) -> U256 {
    px.mul_mod(px, SECP256K1_P)
        .mul_mod(px, SECP256K1_P)
        .add_mod(U256::from(7), SECP256K1_P)
}
