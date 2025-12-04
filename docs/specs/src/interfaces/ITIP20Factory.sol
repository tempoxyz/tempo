// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { ITIP20 } from "./ITIP20.sol";

/// @title The interface for TIP-20 token factory
/// @notice Factory contract for creating and deploying TIP-20 compliant tokens
interface ITIP20Factory {

    error InvalidQuoteToken();

    /// @notice Emitted when a new TIP-20 token is created
    /// @param token The address of the newly created token contract
    /// @param tokenId The unique identifier assigned to the token
    /// @param name The name of the created token
    /// @param symbol The symbol of the created token
    /// @param currency The currency identifier of the created token
    /// @param quoteToken The address of the quote token for the created token
    /// @param admin The address assigned as the admin of the new token
    event TokenCreated(
        address indexed token,
        uint256 indexed tokenId,
        string name,
        string symbol,
        string currency,
        ITIP20 quoteToken,
        address admin
    );

    /// @notice Returns the current token ID counter
    /// @return The next token ID that will be assigned to a newly created token
    function tokenIdCounter() external view returns (uint256);

    /// @notice Creates a new TIP-20 compliant token
    /// @param name The name for the new token
    /// @param symbol The symbol for the new token
    /// @param currency The currency identifier for the new token
    /// @param admin The address to be assigned as the admin of the new token
    /// @return The address of the newly created token contract
    function createToken(
        string memory name,
        string memory symbol,
        string memory currency,
        ITIP20 quoteToken,
        address admin
    ) external returns (address);

    /// @notice Checks if a given address is a TIP-20 compliant token
    /// @param token The address of the token to check
    /// @return True if the address is a TIP-20 token, false otherwise
    function isTIP20(address token) external view returns (bool);

}
