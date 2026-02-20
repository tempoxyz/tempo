// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../TempoVault.sol";

contract TempoVaultTest is Test {
    TempoVault vault;
    address owner = address(0x1);
    address heir = address(0x2);

    function setUp() public {
        vault = new TempoVault();
        vm.deal(owner, 10 ether);
    }

    function testInheritance() public {
        // 1. Owner creates vault with 10 day threshold
        vm.prank(owner);
        vault.createVault{value: 1 ether}(heir, 10 days);

        // 2. Fast forward 11 days (Owner is "Gone")
        vm.warp(block.timestamp + 11 days);

        // 3. Heir claims funds
        vm.prank(heir);
        vault.claim(owner);

        assertEq(heir.balance, 1 ether);
    }

    function testPingProtectsFunds() public {
        vm.prank(owner);
        vault.createVault{value: 1 ether}(heir, 10 days);

        // Fast forward 5 days and PING
        vm.warp(block.timestamp + 5 days);
        vm.prank(owner);
        vault.ping();

        // Fast forward another 6 days (Total 11 days since start, but only 6 since ping)
        vm.warp(block.timestamp + 6 days);

        // Heir tries to steal
        vm.prank(heir);
        vm.expectRevert("Owner is still active");
        vault.claim(owner);
    }
}
