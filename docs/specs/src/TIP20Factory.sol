// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20 } from "./TIP20.sol";
import { TempoUtilities } from "./TempoUtilities.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";
import { ITIP20Factory } from "./interfaces/ITIP20Factory.sol";

contract TIP20Factory is ITIP20Factory {

    uint256 internal immutable reservedSize = 1024;

    function createToken(
        string memory name,
        string memory symbol,
        string memory currency,
        ITIP20 quoteToken,
        address admin,
        bytes32 salt
    ) external returns (address) {
        if (!TempoUtilities.isTIP20(address(quoteToken))) {
            revert InvalidQuoteToken();
        }

        // If token is USD, its quote token must also be USD
        if (keccak256(bytes(currency)) == keccak256(bytes("USD"))) {
            if (keccak256(bytes(quoteToken.currency())) != keccak256(bytes("USD"))) {
                revert InvalidQuoteToken();
            }
        }

        uint64 lowerBytes = uint64(bytes8(keccak256(abi.encode(msg.sender, salt))));
        if (lowerBytes < reservedSize) {
            revert AddressReserved();
        }

        // Calculate the deterministic address for this token
        address tokenAddr =
            address((uint160(0x20C000000000000000000000) << 64) | uint160(lowerBytes));

        if (tokenAddr.code.length != 0) {
            revert TokenAlreadyExists(tokenAddr);
        }

        // Deploy TIP20 contract using CREATE2 to the deterministic address
        TIP20 token = new TIP20{ salt: bytes32(uint256(lowerBytes)) }(
            name, symbol, currency, quoteToken, admin
        );
        require(address(token) == tokenAddr, "Address mismatch");

        emit TokenCreated(tokenAddr, name, symbol, currency, quoteToken, admin, salt);

        return tokenAddr;
    }

    function isTIP20(address token) external view returns (bool) {
        return TempoUtilities.isTIP20(token);
    }

    function getTokenAddress(address sender, bytes32 salt) external pure returns (address) {
        uint64 lowerBytes = uint64(bytes8(keccak256(abi.encode(sender, salt))));
        return address((uint160(0x20C000000000000000000000) << 64) | uint160(lowerBytes));
    }

}
