// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20 } from "./TIP20.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";
import { ITIP20Factory } from "./interfaces/ITIP20Factory.sol";
import { Vm } from "forge-std/Vm.sol";

contract TIP20Factory is ITIP20Factory {

    // Foundry cheatcode VM for deployCodeTo
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 public tokenIdCounter = 0;

    function createToken(
        string memory name,
        string memory symbol,
        string memory currency,
        ITIP20 quoteToken,
        address admin
    ) external returns (address) {
        // Determine the tokenId that will be assigned for this creation
        uint256 tokenId = tokenIdCounter;

        // For the first token, require quote token to be the zero address.
        // For all subsequent tokens, require a valid TIP20 quote token and enforce USD→USD quoting.
        if (tokenId == 0) {
            if (address(quoteToken) != address(0)) {
                revert InvalidQuoteToken();
            }
        } else {
            // Validate that quoteToken is a valid TIP20
            if (!isTIP20(address(quoteToken))) {
                revert InvalidQuoteToken();
            }

            // Prevent self-reference: quote token ID must be strictly less than the token being created
            uint64 quoteTokenId = uint64(uint160(address(quoteToken)));
            if (quoteTokenId >= tokenIdCounter) {
                revert InvalidQuoteToken();
            }

            // If token is USD, its quote token must also be USD
            if (keccak256(bytes(currency)) == keccak256(bytes("USD"))) {
                if (keccak256(bytes(quoteToken.currency())) != keccak256(bytes("USD"))) {
                    revert InvalidQuoteToken();
                }
            }
        }

        tokenIdCounter++;

        // Calculate the deterministic address for this token
        address tokenAddr =
            address(uint160(0x20C0000000000000000000000000000000000000) | uint160(tokenId));

        // Deploy TIP20 contract to the deterministic address using Foundry cheatcodes
        bytes memory creationCode = vm.getCode("TIP20.sol");
        vm.etch(
            tokenAddr,
            abi.encodePacked(creationCode, abi.encode(name, symbol, currency, quoteToken, admin))
        );
        (bool success, bytes memory runtimeBytecode) = tokenAddr.call("");
        require(success, "TIP20Factory: Failed to deploy TIP20");
        vm.etch(tokenAddr, runtimeBytecode);

        emit TokenCreated(tokenAddr, tokenId, name, symbol, currency, quoteToken, admin);

        return tokenAddr;
    }

    function isTIP20(address token) public view returns (bool) {
        return bytes12(bytes20(token)) == 0x20c000000000000000000000
            && uint64(uint160(token)) < tokenIdCounter;
    }

}
