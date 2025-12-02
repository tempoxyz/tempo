// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { ITIP20 } from "./interfaces/ITIP20.sol";
import { ITIP20RewardsRegistry } from "./interfaces/ITIP20RewardsRegistry.sol";

contract TIP20RewardsRegistry is ITIP20RewardsRegistry {

    uint128 public lastUpdatedTimestamp;
    mapping(uint128 => address[]) public streamsEndingAt;
    mapping(bytes32 => uint256) public streamIndex; // streamKey => index in streamsEndingAt array

    constructor() {
        lastUpdatedTimestamp = uint128(block.timestamp);
    }

    // Register a stream at a specified end time
    function addStream(uint128 endTime) external {
        address token = msg.sender;
        require(isTIP20(token), "Caller is not TIP20");

        bytes32 streamKey = keccak256(abi.encode(token, endTime));
        uint256 index = streamsEndingAt[endTime].length;
        streamIndex[streamKey] = index;
        streamsEndingAt[endTime].push(token);
    }

    /// Remove a stream before it ends (for cancellation)
    function removeStream(uint128 endTime) external {
        address token = msg.sender;
        require(isTIP20(token), "Caller is not TIP20");

        bytes32 streamKey = keccak256(abi.encode(token, endTime));
        uint256 index = streamIndex[streamKey];
        address[] storage arr = streamsEndingAt[endTime];

        // Swap with last element and pop
        uint256 lastIndex = arr.length - 1;
        if (index != lastIndex) {
            address lastToken = arr[lastIndex];
            arr[index] = lastToken;
            bytes32 lastStreamKey = keccak256(abi.encode(lastToken, endTime));
            streamIndex[lastStreamKey] = index;
        }

        arr.pop();
        delete streamIndex[streamKey];
    }

    /// Finalize streams for all tokens ending from `lastUpdatedTimestamp` to current timestamp
    function finalizeStreams() external {
        require(msg.sender == address(0), "Only system tx");

        uint128 currentTimestamp = uint128(block.timestamp);
        uint128 lastUpdated = lastUpdatedTimestamp;

        if (currentTimestamp == lastUpdated) {
            return;
        }
        uint128 nextTimestamp = lastUpdated + 1;

        // Loop through all timestamps from last updated to current
        while (currentTimestamp >= nextTimestamp) {
            address[] memory tokens = streamsEndingAt[nextTimestamp];

            // Finalize streams for each token ending at nextTimestamp
            for (uint256 i = 0; i < tokens.length; i++) {
                address token = tokens[i];
                try ITIP20(token).finalizeStreams(uint64(nextTimestamp)) { } catch { }

                bytes32 streamKey = keccak256(abi.encode(token, nextTimestamp));
                delete streamIndex[streamKey];
            }
            delete streamsEndingAt[nextTimestamp];

            nextTimestamp += 1;
        }

        lastUpdatedTimestamp = currentTimestamp;
    }

    function isTIP20(address token) internal pure returns (bool) {
        return bytes12(bytes20(token)) == 0x20c000000000000000000000;
    }

}
