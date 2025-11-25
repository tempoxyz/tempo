pub use ITIP20Factory::ITIP20FactoryEvents as TIP20FactoryEvent;
use alloy::sol;

sol! {
  #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc, abi)]
    interface ITIP20Factory {
        event TokenCreated(address indexed token, uint256 indexed tokenId, string name, string symbol, string currency, address quoteToken, address admin, address feeRecipient);


        /// createToken call pre Allegretto hardfork
        function createToken(
            string memory name,
            string memory symbol,
            string memory currency,
            address quoteToken,
            address admin,
        ) external returns (address);

        /// createToken call post Allegretto hardfork
        function createToken(
            string memory name,
            string memory symbol,
            string memory currency,
            address quoteToken,
            address admin,
            address feeRecipient
        ) external returns (address);

        function tokenIdCounter() external view returns (uint256);

        function isTIP20(address token) public view returns (bool);
    }
}
