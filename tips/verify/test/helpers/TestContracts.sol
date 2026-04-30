// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/// @title SimpleStorage - A minimal contract for CREATE testing
contract SimpleStorage {

    uint256 public value;

    constructor(uint256 _value) {
        value = _value;
    }

    function setValue(uint256 _value) external {
        value = _value;
    }

}

/// @title RevertingContract - A contract that reverts in constructor
contract RevertingContract {

    constructor() {
        revert("Always reverts");
    }

}

/// @title SelfDestructor - A contract that can self-destruct
contract SelfDestructor {

    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function destroy() external {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(owner));
    }

}

/// @title Counter - A simple counter contract for testing state changes
contract Counter {

    uint256 public count;

    function increment() external returns (uint256) {
        return ++count;
    }

    function decrement() external returns (uint256) {
        require(count > 0, "Count is zero");
        return --count;
    }

    function reset() external {
        count = 0;
    }

}

/// @title GasConsumer - A contract for testing gas limits
contract GasConsumer {

    uint256[] public data;

    function consumeGas(uint256 iterations) external {
        for (uint256 i = 0; i < iterations; i++) {
            data.push(i);
        }
    }

}

/// @title InitcodeHelper - Library for generating initcode
library InitcodeHelper {

    /// @notice Get initcode for SimpleStorage with a given value
    function simpleStorageInitcode(uint256 value) internal pure returns (bytes memory) {
        return abi.encodePacked(type(SimpleStorage).creationCode, abi.encode(value));
    }

    /// @notice Get initcode for RevertingContract
    function revertingContractInitcode() internal pure returns (bytes memory) {
        return type(RevertingContract).creationCode;
    }

    /// @notice Get initcode for Counter
    function counterInitcode() internal pure returns (bytes memory) {
        return type(Counter).creationCode;
    }

    /// @notice Get initcode for SelfDestructor
    function selfDestructorInitcode() internal pure returns (bytes memory) {
        return type(SelfDestructor).creationCode;
    }

    /// @notice Generate large initcode for size limit testing
    function largeInitcode(uint256 size) internal pure returns (bytes memory) {
        bytes memory base = type(SimpleStorage).creationCode;
        bytes memory padding = new bytes(size > base.length ? size - base.length : 0);
        return abi.encodePacked(base, padding, abi.encode(uint256(42)));
    }

}
