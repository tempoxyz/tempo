// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    BlockTransition,
    DepositQueueTransition,
    TokenEnablementTransition
} from "../../src/runtime/interfaces/IZone.sol";
import { Verifier } from "../../src/runtime/tempo/Verifier.sol";
import { Test } from "forge-std/Test.sol";

contract VerifierTest is Test {

    /// @notice Verifies the stub verifier accepts arbitrary transition inputs.
    function test_verify_returnsTrue() public {
        // WIP stub: the reference verifier accepts all inputs while proof verification is defined.
        Verifier verifier = new Verifier();

        bool ok = verifier.verify(
            1,
            1,
            1,
            bytes32("anchor"),
            1,
            10,
            BlockTransition({ prevBlockHash: bytes32("prev"), nextBlockHash: bytes32("next") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32("deposits"),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            TokenEnablementTransition({ prevProcessedTokenCount: 0, nextProcessedTokenCount: 0 }),
            bytes32("withdrawals"),
            "config",
            "proof"
        );

        assertTrue(ok);
    }

}
