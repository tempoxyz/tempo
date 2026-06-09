use super::tip20_channel_reserve::MAX_PAYMENT_CALLDATA_LEN;
pub use ITIP20Stealth::{
    ITIP20StealthErrors as TIP20StealthError, ITIP20StealthEvents as TIP20StealthEvent,
};
use alloy_sol_types::SolInterface;

crate::sol! {
    /// TIP-1069 canonical stealth-address transfer precompile.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITIP20Stealth {
        /// @notice Emitted for each stealth payment routed through TIP20Stealth.
        /// @param token TIP-20 token transferred.
        /// @param stealthAddress Derived stealth Tempo account receiving funds.
        /// @param metadata Packed scheme, ephemeral public key, and view tag.
        /// @param memo Opaque memo bytes.
        event Announce(address indexed token, address indexed stealthAddress, bytes metadata, bytes memo);

        /// @notice Atomically transfer `amount` of `token` from msg.sender to `stealthAddress`.
        function transfer(address token, address stealthAddress, uint256 amount, bytes calldata metadata, bytes calldata memo) external returns (bool);

        error InvalidMetadata();
        error UnknownScheme();
        error PrecompileCustody();
    }
}

/// secp256k1 stealth-address derivation scheme.
pub const TIP20_STEALTH_SCHEME_SECP256K1: u8 = 0x01;
/// P-256 stealth-address derivation scheme.
pub const TIP20_STEALTH_SCHEME_P256: u8 = 0x02;
/// Metadata length for all TIP-1069 v1 schemes.
pub const TIP20_STEALTH_V1_METADATA_LEN: usize = 35;

impl ITIP20Stealth::ITIP20StealthCalls {
    /// Returns true when `input` is an ABI-valid `TIP20Stealth.transfer` call.
    pub fn is_payment(input: &[u8]) -> bool {
        if input.len() > MAX_PAYMENT_CALLDATA_LEN {
            return false;
        }

        matches!(
            Self::abi_decode(input),
            Ok(Self::transfer(call)) if is_valid_payment_metadata(&call.metadata)
        )
    }
}

fn is_valid_payment_metadata(metadata: &[u8]) -> bool {
    let Some((&scheme, _)) = metadata.split_first() else {
        return false;
    };

    matches!(
        scheme,
        TIP20_STEALTH_SCHEME_SECP256K1 | TIP20_STEALTH_SCHEME_P256
    ) && metadata.len() == TIP20_STEALTH_V1_METADATA_LEN
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use alloy_primitives::{Address, Bytes, U256};
    use alloy_sol_types::SolCall;

    fn metadata(scheme: u8) -> Bytes {
        let mut metadata = vec![0u8; TIP20_STEALTH_V1_METADATA_LEN];
        metadata[0] = scheme;
        metadata[1] = 0x02;
        metadata[34] = 0xa7;
        metadata.into()
    }

    fn transfer_calldata(metadata: Bytes, memo: Bytes) -> Vec<u8> {
        ITIP20Stealth::transferCall {
            token: Address::random(),
            stealthAddress: Address::random(),
            amount: U256::ONE,
            metadata,
            memo,
        }
        .abi_encode()
    }

    #[test]
    fn test_is_payment_accepts_valid_metadata_schemes() {
        for scheme in [TIP20_STEALTH_SCHEME_SECP256K1, TIP20_STEALTH_SCHEME_P256] {
            assert!(ITIP20Stealth::ITIP20StealthCalls::is_payment(
                &transfer_calldata(metadata(scheme), Bytes::new())
            ));
        }
    }

    #[test]
    fn test_is_payment_rejects_invalid_metadata() {
        assert!(!ITIP20Stealth::ITIP20StealthCalls::is_payment(
            &transfer_calldata(Bytes::new(), Bytes::new())
        ));

        assert!(!ITIP20Stealth::ITIP20StealthCalls::is_payment(
            &transfer_calldata(metadata(0xff), Bytes::new())
        ));

        let mut short = metadata(TIP20_STEALTH_SCHEME_SECP256K1).to_vec();
        short.pop();
        assert!(!ITIP20Stealth::ITIP20StealthCalls::is_payment(
            &transfer_calldata(short.into(), Bytes::new())
        ));
    }

    #[test]
    fn test_is_payment_rejects_oversized_calldata() {
        let calldata = transfer_calldata(
            metadata(TIP20_STEALTH_SCHEME_SECP256K1),
            vec![0; MAX_PAYMENT_CALLDATA_LEN].into(),
        );
        assert!(calldata.len() > MAX_PAYMENT_CALLDATA_LEN);
        assert!(!ITIP20Stealth::ITIP20StealthCalls::is_payment(&calldata));
    }
}
