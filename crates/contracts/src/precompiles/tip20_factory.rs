pub use ITIP20Factory::{
    ITIP20FactoryErrors as TIP20FactoryError, ITIP20FactoryEvents as TIP20FactoryEvent,
    createToken_0Call as createTokenCall, createToken_1Call as createTokenWithLogoCall,
};

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
        ///      Reverts with `LogoURITooLong` if `bytes(logoURI).length > 256`, or
        ///      with `InvalidLogoURI` if `logoURI` is non-empty and either has no
        ///      parseable scheme or its scheme is not in the allow-list.
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
