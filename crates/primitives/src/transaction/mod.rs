pub mod envelope;
pub mod key_authorization;
pub mod tempo_transaction;
pub mod tt_authorization;
pub mod tt_signature;
pub mod tt_signed;

pub use tt_authorization::{MAGIC, RecoveredTempoAuthorization, TempoSignedAuthorization};
// Re-export Authorization from alloy for convenience
pub use tt_signature::{
    KeychainSignature, KeychainVersion, KeychainVersionError, PrimitiveSignature, TempoSignature,
    derive_p256_address,
};

pub use crate::address::TIP20_TOKEN_PREFIX as TIP20_PAYMENT_PREFIX;
pub use alloy_eips::eip7702::Authorization;
pub use envelope::{TempoTxEnvelope, TempoTxType, TempoTypedTransaction};
pub use key_authorization::{
    CallScope, KeyAuthorization, KeyAuthorizationChainIdError, SelectorRule,
    SignedKeyAuthorization, TokenLimit,
};
pub use tempo_transaction::{
    Call, MAX_WEBAUTHN_SIGNATURE_LENGTH, P256_SIGNATURE_LENGTH, SECP256K1_SIGNATURE_LENGTH,
    SignatureType, TEMPO_EXPIRING_NONCE_KEY, TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS,
    TEMPO_TX_TYPE_ID, TempoTransaction, validate_calls,
};
pub use tt_signed::AASigned;

use alloc::vec::Vec;
use alloy_consensus::SignableTransaction;
use alloy_primitives::{Address, B256, Signature, U256, uint};

/// Computes the sender-scoped transaction identifier used for replay-sensitive features.
///
/// The identifier is `keccak256(encode_for_signing || sender)`, making it unique per recovered
/// sender while remaining invariant to signatures that do not change the signed payload.
pub(crate) fn unique_tx_identifier_from_signable<T>(tx: &T, sender: Address) -> B256
where
    T: SignableTransaction<Signature>,
{
    let mut buf = Vec::with_capacity(tx.payload_len_for_signature() + sender.as_slice().len());
    tx.encode_for_signing(&mut buf);
    buf.extend_from_slice(sender.as_slice());
    alloy_primitives::keccak256(buf)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calc_gas_balance_spending_variations() {
        // zero gas → zero spending
        assert_eq!(calc_gas_balance_spending(0, 1_000_000_000), U256::ZERO);

        // zero price → zero spending
        assert_eq!(calc_gas_balance_spending(21000, 0), U256::ZERO);

        // both zero
        assert_eq!(calc_gas_balance_spending(0, 0), U256::ZERO);

        // exact division: 1 gas * 10^12 attodollars = 1 microdollar
        assert_eq!(
            calc_gas_balance_spending(1, 1_000_000_000_000),
            U256::from(1)
        );

        // rounds up via div_ceil: 1 gas * 1 attodollar → ceil(1 / 10^12) = 1
        assert_eq!(calc_gas_balance_spending(1, 1), U256::from(1));

        // typical tx: 21000 gas * 1 gwei (10^9 attodollars)
        // = 21000 * 10^9 / 10^12 = 21000 / 1000 = 21
        assert_eq!(
            calc_gas_balance_spending(21000, 1_000_000_000),
            U256::from(21)
        );

        // large values don't overflow (saturating_mul)
        let result = calc_gas_balance_spending(u64::MAX, u128::MAX);
        assert!(result > U256::ZERO);
    }
}
