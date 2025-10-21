use alloy::sol;

sol! {
    /// TIP20Factory interface for creating and managing TIP20 token instances.
    ///
    /// The factory provides functionality to:
    /// - Create new TIP20 token instances with specified parameters
    /// - Track and query created tokens
    /// - Manage token creation permissions and policies
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface ITIP20Factory {
        /// Create a new TIP20 token
        /// @param name The token name
        /// @param symbol The token symbol  
        /// @param currency The currency denomination
        /// @param quoteToken The quote token address
        /// @param admin The initial admin address
        /// @return tokenId The ID of the created token
        function createToken(
            string calldata name,
            string calldata symbol,
            string calldata currency,
            address quoteToken,
            address admin
        ) external returns (uint64 tokenId);

        /// Get the total number of tokens created
        /// @return count The total token count
        function tokenCount() external view returns (uint64 count);

        /// Check if a token ID exists
        /// @param tokenId The token ID to check
        /// @return exists Whether the token exists
        function tokenExists(uint64 tokenId) external view returns (bool exists);

        /// Get token information by ID
        /// @param tokenId The token ID
        /// @return name The token name
        /// @return symbol The token symbol
        /// @return currency The currency denomination
        /// @return quoteToken The quote token address
        /// @return admin The admin address
        function getTokenInfo(uint64 tokenId) external view returns (
            string memory name,
            string memory symbol,
            string memory currency,
            address quoteToken,
            address admin
        );

        // Events
        event TokenCreated(
            uint64 indexed tokenId,
            address indexed creator,
            string name,
            string symbol,
            string currency,
            address quoteToken,
            address admin
        );

        // Errors
        error TokenAlreadyExists();
        error TokenDoesNotExist();
        error InvalidParameters();
        error Unauthorized();
    }
}