pub use ITIP20Factory::{
    ITIP20FactoryErrors as TIP20FactoryError, ITIP20FactoryEvents as TIP20FactoryEvent,
};

crate::sol! {
  #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
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

        function isTIP20(address token) public view returns (bool);

        function getTokenAddress(address sender, bytes32 salt) public view returns (address);
    }
}
