// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20 } from "./TIP20.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";
import { ITIP20Factory } from "./interfaces/ITIP20Factory.sol";
import { Vm } from "forge-std/Vm.sol";

contract TIP20Factory is ITIP20Factory {

    // Foundry cheatcode VM for deployCodeTo

    mapping(address => bool) public tokens;

    function createToken(
        string memory name,
        string memory symbol,
        string memory currency,
        ITIP20 quoteToken,
        bytes32 salt,
        address admin
    ) external returns (address) {
        // For the first token, require quote token to be the zero address.
        // For all subsequent tokens, require a valid TIP20 quote token and enforce USD→USD quoting.

        // Validate that quoteToken is a valid TIP20
        if (!tokens[address(quoteToken)]) {
            revert InvalidQuoteToken();
        }

        // If token is USD, its quote token must also be USD
        if (keccak256(bytes(currency)) == keccak256(bytes("USD"))) {
            if (keccak256(bytes(quoteToken.currency())) != keccak256(bytes("USD"))) {
                revert InvalidQuoteToken();
            }
        }

        address tokenAddr = address(new TIP20{salt: keccak256(abi.encodePacked(msg.sender, salt))}(name, symbol, currency, quoteToken, admin));
        tokens[tokenAddr] = true;

        emit TokenCreated(tokenAddr, name, symbol, currency, quoteToken, admin);

        return tokenAddr;
    }

    function isTIP20(address token) public view returns (bool) {
        return tokens[token];
    }

}
