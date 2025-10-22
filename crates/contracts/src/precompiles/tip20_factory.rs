pub use ITIP20Factory::ITIP20FactoryEvents as TIP20FactoryEvent;
use alloy::sol;

sol! {
  #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface ITIP20Factory {
        event TokenCreated(address indexed token, uint256 indexed tokenId, string name, string symbol, string currency, address admin);

        function createToken(
            string memory name,
            string memory symbol,
            string memory currency,
            address quoteToken,
            address admin
        ) external returns (uint256);

        function tokenIdCounter() external view returns (uint256);
    }
}
