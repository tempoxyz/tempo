// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Small application-style calls for comparing execution and transaction overhead.
/// Each transaction performs one operation; setup deployment is outside the workload.
contract GasCalibration {
    uint256 private stored = 1;
    event Value(bytes32 indexed tag, bytes data);

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

    function storageRead() external view returns (uint256) {
        return stored;
    }

    /// Update one existing nonzero slot; no growing mapping or account set.
    function storageWrite(uint256 value) external {
        require(value != 0, "nonzero value required");
        stored = value;
    }

    /// One round trip per transaction, not a cross-call transient-state pattern.
    function transientRoundTrip(uint256 value) external returns (uint256 output) {
        assembly {
            tstore(0, value)
            output := tload(0)
        }
    }

    function logValue(bytes32 tag, bytes calldata data) external {
        emit Value(tag, data);
    }

    function accountContext() external view returns (address, uint256, uint256, uint256, uint256) {
        return (msg.sender, address(this).balance, block.chainid, block.number, block.timestamp);
    }

    function echo(uint256 value) external pure returns (uint256) {
        return value;
    }

    /// The target is already warm; this is not a cold-account call baseline.
    function selfCall(uint256 value) external view returns (uint256) {
        (bool success, bytes memory output) = address(this).staticcall(abi.encodeCall(this.echo, (value)));
        require(success, "self call failed");
        return abi.decode(output, (uint256));
    }

    function branch(uint256 value) external pure returns (uint256) {
        unchecked {
            return value % 2 == 0 ? value / 2 : value * 3 + 1;
        }
    }
}
