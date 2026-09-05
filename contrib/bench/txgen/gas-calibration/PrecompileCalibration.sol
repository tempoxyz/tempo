// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// One ordinary precompile invocation per workload transaction.
/// Constructor fixture verification is outside the measured workload phase.
contract PrecompileCalibration {
    constructor(address target, bytes memory input, bytes memory expected) {
        require(keccak256(invoke(target, input)) == keccak256(expected), "fixture mismatch");
    }

    function invoke(address target, bytes memory input) public view returns (bytes memory output) {
        bool success;
        (success, output) = target.staticcall(input);
        require(success && output.length != 0, "precompile call failed");
    }
}
