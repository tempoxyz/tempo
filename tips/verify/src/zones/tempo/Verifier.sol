// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { BlockTransition, DepositQueueTransition, IVerifier } from "../interfaces/IZone.sol";

/// @title Verifier
/// @notice Enshrined verifier system contract for zone proof/attestation verification.
///         Deployed by ZoneFactory - all zones share the same verifier instance.
///         Stub implementation that always returns true for prototyping.
contract Verifier is IVerifier {

    /// @inheritdoc IVerifier
    function verify(
        uint64,
        uint64,
        bytes32,
        uint64,
        address,
        BlockTransition calldata,
        DepositQueueTransition calldata,
        bytes32,
        bytes calldata,
        bytes calldata
    )
        external
        pure
        override
        returns (bool)
    {
        return true;
    }

}
