// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../TempoStream.sol";

contract TempoStreamTest is Test {
    TempoStream streamContract;
    address sender = address(0x1);
    address recipient = address(0x2);

    function setUp() public {
        streamContract = new TempoStream();
        vm.deal(sender, 10 ether);
    }

    function testCreateStream() public {
        vm.prank(sender);
        streamContract.createStream{value: 1 ether}(recipient, 1000);

        (address _sender, address _recipient, , uint256 _rate, , , bool _active) = streamContract.streams(0);
        assertEq(_sender, sender);
        assertEq(_recipient, recipient);
        assertEq(_rate, 1000);
        assertTrue(_active);
    }
}
