// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

contract AccessProbe {
    uint256 private value = 1;

    function read() external view returns (uint256) {
        return value;
    }
}

/// Bounded access-pattern fixtures. All state creation happens in the constructor.
/// Compiled without optimization so repeated SLOADs remain actual instructions.
contract AccessCalibration {
    uint256 private firstSlot = 1;
    uint256 private secondSlot = 1;
    AccessProbe private immutable firstProbe;
    AccessProbe private immutable secondProbe;

    constructor() {
        AccessProbe first = new AccessProbe();
        AccessProbe second = new AccessProbe();
        require(first.read() == 1 && second.read() == 1, "probe setup");
        require(firstSlot == 1 && secondSlot == 1, "slot setup");
        firstProbe = first;
        secondProbe = second;
    }

    function control() external pure returns (uint256) {
        return 2;
    }

    function slotOnce() external view returns (uint256 result) {
        assembly { result := sload(0) }
    }

    function slotTwiceWarm() external view returns (uint256 result) {
        assembly {
            let first := sload(0)
            let second := sload(0)
            result := add(first, second)
        }
    }

    function slotTwiceCold() external view returns (uint256 result) {
        assembly {
            let first := sload(0)
            let second := sload(1)
            result := add(first, second)
        }
    }

    function callOnce() external view returns (uint256) {
        return firstProbe.read();
    }

    function callTwiceWarm() external view returns (uint256) {
        return firstProbe.read() + firstProbe.read();
    }

    function callTwiceCold() external view returns (uint256) {
        return firstProbe.read() + secondProbe.read();
    }
}
