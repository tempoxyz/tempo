// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Small application-style calls for comparing execution and transaction overhead.
/// Each transaction performs one operation; setup deployment is outside the workload.
contract GasCalibration {
    constructor(bytes memory fixture, bytes32 expectedKeccak, bytes32 expectedSha, bytes32 expectedRipemd) {
        require(keccak256(fixture) == expectedKeccak, "keccak fixture");
        require(sha256(fixture) == expectedSha, "sha256 fixture");
        require(bytes32(ripemd160(fixture)) == expectedRipemd, "ripemd fixture");
        (bool success, bytes memory output) = address(4).staticcall(fixture);
        require(success && keccak256(output) == expectedKeccak, "identity fixture");
    }

    function hashControl(bytes calldata input) external pure returns (bytes32) {
        return bytes32(input.length);
    }

    function copy(bytes calldata input) external pure returns (bytes memory) {
        return input;
    }

    function keccakDigest(bytes calldata input) external pure returns (bytes32) {
        return keccak256(input);
    }

    function sha256Digest(bytes calldata input) external pure returns (bytes32) {
        return sha256(input);
    }

    function ripemdDigest(bytes calldata input) external pure returns (bytes32) {
        return bytes32(ripemd160(input));
    }

    function identityCopy(bytes calldata input) external view returns (bytes memory) {
        (bool success, bytes memory output) = address(4).staticcall(input);
        require(success && output.length == input.length, "identity call failed");
        return output;
    }

    function arithmetic(uint256 a, uint256 b) external pure returns (uint256) {
        unchecked {
            return ((a + b) * (a | 1)) ^ (b >> 1);
        }
    }
}
