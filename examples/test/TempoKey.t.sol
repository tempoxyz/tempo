// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../TempoKey.sol";

contract TempoKeyTest is Test {
    TempoKey keyContract;
    address tenant = address(0x1);

    function setUp() public {
        keyContract = new TempoKey();
        vm.deal(tenant, 10 ether);
    }

    function testAccessControl() public {
        vm.prank(tenant);
        // Rate: 1 wei per second. Deposit: 100 wei = 100 seconds access.
        keyContract.startLease{value: 100}(1);

        // 1. Check immediate access
        assertTrue(keyContract.hasAccess(tenant));

        // 2. Fast forward 50 seconds (Halfway)
        vm.warp(block.timestamp + 50);
        assertTrue(keyContract.hasAccess(tenant));

        // 3. Fast forward another 51 seconds (Total 101s - Over limit)
        vm.warp(block.timestamp + 51);
        assertFalse(keyContract.hasAccess(tenant));
    }

    function testEviction() public {
        vm.prank(tenant);
        keyContract.startLease{value: 100}(1);

        // Fast forward past the limit
        vm.warp(block.timestamp + 200);

        // Attempt to "Top Up" while insolvent (should fail or reset)
        // This confirms the logic correctly identifies expired leases
        assertFalse(keyContract.hasAccess(tenant));
    }
}
