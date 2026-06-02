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

impl ITIP20Stealth::ITIP20StealthCalls {
    /// Returns true when `input` is an ABI-valid `TIP20Stealth.transfer` call.
    pub fn is_payment(input: &[u8]) -> bool {
        matches!(Self::abi_decode(input), Ok(Self::transfer(_)))
    }
}
