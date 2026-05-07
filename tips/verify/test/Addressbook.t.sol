// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Addressbook } from "../src/Addressbook.sol";
import { Test } from "forge-std/Test.sol";

/// @title Addressbook Tests
/// @notice Unit tests for the per-user Addressbook contract.
contract AddressbookTest is Test {

    Addressbook public book;

    address public alice = address(0x200);
    address public bob = address(0x300);
    address public target1 = address(0x1001);
    address public target2 = address(0x1002);
    address public target3 = address(0x1003);

    function setUp() public {
        book = new Addressbook();
    }

    /*//////////////////////////////////////////////////////////////
                            SET + GET
    //////////////////////////////////////////////////////////////*/

    function test_SetAndGet() public {
        vm.prank(alice);
        book.set("vault", target1);

        assertEq(book.get(alice, "vault"), target1);
    }

    function test_SetOverwrite() public {
        vm.startPrank(alice);
        book.set("vault", target1);
        book.set("vault", target2);
        vm.stopPrank();

        assertEq(book.get(alice, "vault"), target2);
        // Overwrite should not duplicate the name in the list.
        assertEq(book.count(alice), 1);
    }

    function test_SetEmptyNameReverts() public {
        vm.prank(alice);
        vm.expectRevert(Addressbook.EmptyName.selector);
        book.set("", target1);
    }

    function test_SetEmitsEvent() public {
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Addressbook.EntrySet(alice, "vault", target1);
        book.set("vault", target1);
    }

    /*//////////////////////////////////////////////////////////////
                            ISOLATION
    //////////////////////////////////////////////////////////////*/

    function test_IsolationBetweenUsers() public {
        vm.prank(alice);
        book.set("vault", target1);

        vm.prank(bob);
        book.set("vault", target2);

        assertEq(book.get(alice, "vault"), target1);
        assertEq(book.get(bob, "vault"), target2);
    }

    function test_GetNonexistentReturnsZero() public view {
        assertEq(book.get(alice, "nope"), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                              REMOVE
    //////////////////////////////////////////////////////////////*/

    function test_Remove() public {
        vm.startPrank(alice);
        book.set("vault", target1);
        book.remove("vault");
        vm.stopPrank();

        assertEq(book.get(alice, "vault"), address(0));
        assertEq(book.count(alice), 0);
    }

    function test_RemoveNonexistentReverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Addressbook.EntryNotFound.selector, "nope"));
        book.remove("nope");
    }

    function test_RemoveEmitsEvent() public {
        vm.startPrank(alice);
        book.set("vault", target1);

        vm.expectEmit(true, false, false, true);
        emit Addressbook.EntryRemoved(alice, "vault");
        book.remove("vault");
        vm.stopPrank();
    }

    function test_RemoveMiddleEntry() public {
        vm.startPrank(alice);
        book.set("a", target1);
        book.set("b", target2);
        book.set("c", target3);

        book.remove("b");
        vm.stopPrank();

        assertEq(book.count(alice), 2);
        assertEq(book.get(alice, "a"), target1);
        assertEq(book.get(alice, "b"), address(0));
        assertEq(book.get(alice, "c"), target3);

        // The remaining names should still enumerate without gaps.
        string[] memory names = book.listNames(alice);
        assertEq(names.length, 2);
    }

    /*//////////////////////////////////////////////////////////////
                          ENUMERATION
    //////////////////////////////////////////////////////////////*/

    function test_ListNamesAndListAll() public {
        vm.startPrank(alice);
        book.set("vault", target1);
        book.set("hot", target2);
        vm.stopPrank();

        string[] memory names = book.listNames(alice);
        assertEq(names.length, 2);

        (string[] memory allNames, address[] memory allAddrs) = book.listAll(alice);
        assertEq(allNames.length, 2);
        assertEq(allAddrs.length, 2);
    }

    function test_CountEmpty() public view {
        assertEq(book.count(alice), 0);
    }

    /*//////////////////////////////////////////////////////////////
                          RE-ADD AFTER REMOVE
    //////////////////////////////////////////////////////////////*/

    function test_ReAddAfterRemove() public {
        vm.startPrank(alice);
        book.set("vault", target1);
        book.remove("vault");
        book.set("vault", target3);
        vm.stopPrank();

        assertEq(book.get(alice, "vault"), target3);
        assertEq(book.count(alice), 1);
    }

}
