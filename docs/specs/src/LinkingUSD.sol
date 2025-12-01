// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20 } from "./TIP20.sol";
import { ILinkingUSD } from "./interfaces/ILinkingUSD.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";

contract LinkingUSD is ILinkingUSD, TIP20 {

    address private constant STABLECOIN_DEX = 0xDEc0000000000000000000000000000000000000;
    bytes32 public constant TRANSFER_ROLE = keccak256("TRANSFER_ROLE");
    bytes32 public constant RECEIVE_WITH_MEMO_ROLE = keccak256("RECEIVE_WITH_MEMO_ROLE");

    constructor(address admin)
        TIP20("linkingUSD", "linkingUSD", "USD", TIP20(address(0)), admin)
    { }

    function transfer(address to, uint256 amount) public override(ITIP20, TIP20) returns (bool) {
        if (msg.sender == STABLECOIN_DEX || hasRole[msg.sender][TRANSFER_ROLE]) {
            return super.transfer(to, amount);
        } else {
            revert TransfersDisabled();
        }
    }

    function transferFrom(address from, address to, uint256 amount)
        public
        override(ITIP20, TIP20)
        notPaused
        returns (bool)
    {
        if (msg.sender == STABLECOIN_DEX || hasRole[from][TRANSFER_ROLE]) {
            return super.transferFrom(from, to, amount);
        } else {
            revert TransfersDisabled();
        }
    }

    function transferWithMemo(address to, uint256 amount, bytes32 memo)
        public
        override(ITIP20, TIP20)
        notPaused
    {
        if (
            msg.sender == STABLECOIN_DEX || hasRole[msg.sender][TRANSFER_ROLE]
                || hasRole[to][RECEIVE_WITH_MEMO_ROLE]
        ) {
            super.transferWithMemo(to, amount, memo);
        } else {
            revert TransfersDisabled();
        }
    }

    function transferFromWithMemo(address from, address to, uint256 amount, bytes32 memo)
        public
        override(ITIP20, TIP20)
        notPaused
        returns (bool)
    {
        if (
            msg.sender == STABLECOIN_DEX || hasRole[from][TRANSFER_ROLE]
                || hasRole[to][RECEIVE_WITH_MEMO_ROLE]
        ) {
            return super.transferFromWithMemo(from, to, amount, memo);
        } else {
            revert TransfersDisabled();
        }
    }

}
