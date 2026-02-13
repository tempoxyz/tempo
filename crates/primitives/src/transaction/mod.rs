pub mod envelope;
pub mod key_authorization;
pub mod tempo_transaction;
pub mod tt_authorization;
pub mod tt_signature;
pub mod tt_signed;

pub use tt_authorization::{MAGIC, RecoveredTempoAuthorization, TempoSignedAuthorization};
// Re-export Authorization from alloy for convenience
pub use tt_signature::{
    KeychainSignature, PrimitiveSignature, TempoSignature, derive_p256_address,
};

pub use alloy_eips::eip7702::Authorization;
pub use envelope::{TempoTxEnvelope, TempoTxType, TempoTypedTransaction};
pub use key_authorization::{KeyAuthorization, SignedKeyAuthorization, TokenLimit};
pub use tempo_transaction::{
    Call, MAX_WEBAUTHN_SIGNATURE_LENGTH, P256_SIGNATURE_LENGTH, SECP256K1_SIGNATURE_LENGTH,
    SignatureType, TEMPO_EXPIRING_NONCE_KEY, TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS,
    TEMPO_TX_TYPE_ID, TempoTransaction, validate_calls,
};
pub use tt_signed::AASigned;

use alloy_primitives::{U256, uint};

/// Scaling factor for converting gas prices (attodollars) to TIP-20 token amounts (microdollars).
///
/// This factor is 10^12, which converts from attodollars (10^-18 USD) to microdollars (10^-6 USD):
/// - Gas prices are in attodollars at 10^-18 USD precision
/// - TIP-20 tokens use 6 decimals (microdollars at 10^-6 USD precision)
/// - Conversion: attodollars / 10^12 = microdollars
pub const TEMPO_GAS_PRICE_SCALING_FACTOR: U256 = uint!(1_000_000_000_000_U256);

/// Calculates gas balance spending in TIP-20 token units (microdollars).
///
/// Takes gas parameters in attodollars and converts to microdollars (TIP-20 token units).
/// Formula: (gas_limit × gas_price) / 10^12 = microdollars
pub fn calc_gas_balance_spending(gas_limit: u64, gas_price: u128) -> U256 {
    U256::from(gas_limit)
        .saturating_mul(U256::from(gas_price))
        .div_ceil(TEMPO_GAS_PRICE_SCALING_FACTOR)
}
