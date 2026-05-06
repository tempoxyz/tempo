pub use ITIP20Factory::{
    ITIP20FactoryErrors as TIP20FactoryError, ITIP20FactoryEvents as TIP20FactoryEvent,
    createToken_0Call as createTokenCall, createToken_1Call as createTokenWithLogoCall,
};
use alloy_primitives::Address;

crate::sol! {
  #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    #[allow(clippy::too_many_arguments)]
    interface ITIP20Factory {
        error AddressReserved();
        error AddressNotReserved();
        error InvalidQuoteToken();
        error TokenAlreadyExists(address token);

        event TokenCreated(address indexed token, string name, string symbol, string currency, address quoteToken, address admin, bytes32 salt);

        function createToken(
            string memory name,
            string memory symbol,
            string memory currency,
            address quoteToken,
            address admin,
            bytes32 salt
        ) external returns (address);

        /// @notice Creates a token and sets its logoURI atomically (TIP-1026).
        /// @dev Solidity overload of `createToken` with an additional `logoURI` argument.
        ///      The macro expands the two overloads to `createToken_0Call` (legacy) and
        ///      `createToken_1Call` (with logo); both selectors are supported post-T5
        ///      (legacy remains supported pre-T5 as well).
        ///      The logo URI is validated **before** the token is deployed.
        ///      Reverts with `LogoURITooLong` if `bytes(logoURI).length > 256`, or
        ///      with `InvalidLogoURI` if `logoURI` is non-empty and either has no
        ///      parseable scheme (RFC 3986 §3.1) or its scheme is not in the
        ///      allowlist (`https`, `http`, `ipfs`, `data`, case-insensitive).
        ///      The `LogoURIUpdated` event is emitted by the new token (not the factory)
        ///      with `updater = msg.sender`.
        function createToken(
            string memory name,
            string memory symbol,
            string memory currency,
            address quoteToken,
            address admin,
            bytes32 salt,
            string memory logoURI
        ) external returns (address);

        function isTIP20(address token) public view returns (bool);

        function getTokenAddress(address sender, bytes32 salt) public pure returns (address);
    }
}

impl TIP20FactoryError {
    /// Creates an error when attempting to use a reserved address.
    pub const fn address_reserved() -> Self {
        Self::AddressReserved(ITIP20Factory::AddressReserved {})
    }

    /// Creates an error when address is not in the reserved range.
    pub const fn address_not_reserved() -> Self {
        Self::AddressNotReserved(ITIP20Factory::AddressNotReserved {})
    }

    /// Creates an error for invalid quote token.
    pub const fn invalid_quote_token() -> Self {
        Self::InvalidQuoteToken(ITIP20Factory::InvalidQuoteToken {})
    }

    /// Creates an error when token already exists at the given address.
    pub const fn token_already_exists(token: Address) -> Self {
        Self::TokenAlreadyExists(ITIP20Factory::TokenAlreadyExists { token })
    }
}
