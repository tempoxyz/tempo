// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { ITIP20 } from "./ITIP20.sol";

interface ILinkingUSD is ITIP20 {

    error TransfersDisabled();

    function TRANSFER_ROLE() external view returns (bytes32);

    function RECEIVE_WITH_MEMO_ROLE() external view returns (bytes32);

}
