// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// One ordinary precompile invocation per workload transaction.
/// Constructor fixture verification is outside the measured workload phase.
contract PrecompileCalibration {
    constructor(address[] memory targets, bytes[] memory inputs, bytes[] memory expected) {
        require(targets.length > 0 && targets.length <= 18, "bounded fixture set required");
        require(targets.length == inputs.length && targets.length == expected.length, "fixture lengths");
        for (uint256 i; i < targets.length; ++i) {
            require(keccak256(invoke(targets[i], inputs[i])) == keccak256(expected[i]), "fixture mismatch");
        }
    }

    function invoke(address target, bytes memory input) public view returns (bytes memory output) {
        bool success;
        (success, output) = target.staticcall(input);
        require(success && output.length != 0, "precompile call failed");
    }
}
