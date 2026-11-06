// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Capability, Role } from "../../src/runtime/interfaces/IZone.sol";
import { Test } from "forge-std/Test.sol";

/// @notice Portal storage keeps `Role` values in the role mapping and `Capability` values as
///         mapping keys. A hardfork that replaces the shared portal runtime upgrades every
///         existing portal in place, so reordering either enum would reinterpret stored state
///         (for example, turning allowed accounts into sequencers). New values must be appended.
contract PortalEnumEncodingTest is Test {

    function test_roleValuesArePinned() public pure {
        assertEq(uint8(Role.None), 0);
        assertEq(uint8(Role.Sequencer), 1);
        assertEq(uint8(Role.Account), 2);
        assertEq(uint8(Role.CallbackGateway), 3);
        assertEq(uint8(Role.PauseGuardian), 4);
        assertEq(uint8(type(Role).max), 4, "append new roles and pin them here");
    }

    function test_capabilityValuesArePinned() public pure {
        assertEq(uint8(Capability.PausePortal), 0);
        assertEq(uint8(Capability.AccessPolicy), 1);
        assertEq(uint8(type(Capability).max), 1, "append new capabilities and pin them here");
    }

}
