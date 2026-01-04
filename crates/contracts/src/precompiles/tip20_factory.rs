pub use ITIP20Factory::ITIP20FactoryEvents as TIP20FactoryEvent;

crate::sol! {
  #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITIP20Factory {
        event TokenCreated(address indexed token, uint256 indexed tokenId, string name, string symbol, string currency, address quoteToken, address admin);

        function createToken(
            string memory name,
            string memory symbol,
            string memory currency,
            address quoteToken,
            address admin
        ) external returns (address);

        function tokenIdCounter() external view returns (uint256);

        function isTIP20(address token) public view returns (bool);
    }
}
