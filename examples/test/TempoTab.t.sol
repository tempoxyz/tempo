// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../TempoTab.sol";

contract TempoTabTest is Test {
    TempoTab tabContract;
    address user = address(0xA);
    address merchant = address(0xB);

    function setUp() public {
        tabContract = new TempoTab();
        vm.deal(user, 50 ether);
    }

    function testOpenTab() public {
        vm.prank(user);
        // Open tab: 50 wei limit, 1 day period
        tabContract.openTab{value: 100 ether}(merchant, 50, 86400);

        (uint256 limit, uint256 period, uint256 usage, , bool active) = tabContract.tabs(user, merchant);
        
        assertEq(limit, 50);
        assertEq(period, 86400);
        assertEq(usage, 0);
        assertTrue(active);
    }

    function testChargeTab() public {
        vm.prank(user);
        tabContract.openTab{value: 100 ether}(merchant, 50, 86400);

        // Merchant charges 20 wei
        vm.prank(merchant);
        tabContract.chargeTab(user, 20);

        assertEq(merchant.balance, 20);
        
        // Verify usage updated
        (,, uint256 usage,,) = tabContract.tabs(user, merchant);
        assertEq(usage, 20);
    }

    function testLimitRejection() public {
        vm.prank(user);
        tabContract.openTab{value: 100 ether}(merchant, 50, 86400);

        vm.startPrank(merchant);
        tabContract.chargeTab(user, 50); // Max out
        
        // Should fail if they try to take 1 more wei
        vm.expectRevert("Daily limit exceeded");
        tabContract.chargeTab(user, 1);
        vm.stopPrank();
    }
}
