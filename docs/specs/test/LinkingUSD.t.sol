// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP403Registry } from "../src/TIP403Registry.sol";
import { ILinkingUSD } from "../src/interfaces/ILinkingUSD.sol";
import { ITIP20 } from "../src/interfaces/ITIP20.sol";
import { ITIP20Factory } from "../src/interfaces/ITIP20Factory.sol";
import { BaseTest } from "./BaseTest.t.sol";

contract LinkingUSDTest is BaseTest {

    function setUp() public override {
        super.setUp();

        // Setup roles and mint initial tokens
        // linkingUSDAdmin has DEFAULT_ADMIN_ROLE in both environments
        vm.startPrank(linkingUSDAdmin);
        linkingUSD.grantRole(_ISSUER_ROLE, linkingUSDAdmin);
        linkingUSD.mint(alice, 1000e18);
        linkingUSD.mint(bob, 500e18);
        linkingUSD.mint(_STABLECOIN_DEX, 10_000e18);
        vm.stopPrank();
    }

    function test_Metadata() public view {
        assertEq(linkingUSD.name(), "linkingUSD");
        assertEq(linkingUSD.symbol(), "linkingUSD");
        assertEq(linkingUSD.currency(), "USD");
        assertEq(address(linkingUSD.quoteToken()), address(0));
    }

    function test_Transfer_RevertIf_NoRoleAndNotStableDex(address sender, uint256 amount) public {
        vm.assume(sender != _STABLECOIN_DEX);
        vm.startPrank(sender);
        try linkingUSD.transfer(bob, amount) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ILinkingUSD.TransfersDisabled.selector));
        }
        vm.stopPrank();
    }

    function test_TransferFrom_RevertIf_NoRoleAndNotStableDex(address sender, uint256 amount)
        public
    {
        vm.assume(sender != _STABLECOIN_DEX);
        vm.startPrank(sender);
        try linkingUSD.transferFrom(alice, bob, amount) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ILinkingUSD.TransfersDisabled.selector));
        }
        vm.stopPrank();
    }

    function test_TransferWithMemo_RevertIf_NoRoleAndNotStableDex(address sender) public {
        vm.assume(sender != _STABLECOIN_DEX);
        vm.startPrank(sender);
        try linkingUSD.transferWithMemo(bob, 100, bytes32(0)) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ILinkingUSD.TransfersDisabled.selector));
        }
        vm.stopPrank();
    }

    function test_TransferFromWithMemo_RevertIf_NoRoleAndNotStableDex(address sender) public {
        vm.assume(sender != _STABLECOIN_DEX);
        vm.prank(sender);
        try linkingUSD.transferFromWithMemo(alice, bob, 100, bytes32(0)) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ILinkingUSD.TransfersDisabled.selector));
        }
    }

    function test_Mint(uint128 amount) public {
        vm.assume(amount > 0);

        uint256 currentSupply = linkingUSD.totalSupply();
        uint256 supplyCap = linkingUSD.supplyCap();
        uint256 balanceBefore = linkingUSD.balanceOf(alice);

        vm.startPrank(linkingUSDAdmin);

        if (currentSupply + amount > supplyCap) {
            // Expect SupplyCapExceeded if minting would exceed cap
            vm.expectRevert(ITIP20.SupplyCapExceeded.selector);
            linkingUSD.mint(alice, amount);
        } else {
            linkingUSD.mint(alice, amount);
            assertEq(linkingUSD.balanceOf(alice), balanceBefore + amount);
        }

        vm.stopPrank();
    }

    function test_Burn(uint128 amount) public {
        vm.assume(amount > 0);

        uint256 currentSupply = linkingUSD.totalSupply();
        uint256 supplyCap = linkingUSD.supplyCap();
        uint256 balanceBefore = linkingUSD.balanceOf(linkingUSDAdmin);

        vm.startPrank(linkingUSDAdmin);

        if (currentSupply + amount > supplyCap) {
            // Can't mint, so can't test burn
            vm.expectRevert(ITIP20.SupplyCapExceeded.selector);
            linkingUSD.mint(linkingUSDAdmin, amount);
        } else {
            linkingUSD.mint(linkingUSDAdmin, amount);
            assertEq(linkingUSD.balanceOf(linkingUSDAdmin), balanceBefore + amount);

            if (!isTempo) {
                vm.expectEmit(true, true, true, true);
                emit ITIP20.Burn(linkingUSDAdmin, amount);
            }
            linkingUSD.burn(amount);
            assertEq(linkingUSD.balanceOf(linkingUSDAdmin), balanceBefore);
        }

        vm.stopPrank();
    }

    function test_Approve(uint256 amount) public {
        vm.prank(alice);
        bool success = linkingUSD.approve(bob, amount);
        assertTrue(success);

        assertEq(linkingUSD.allowance(alice, bob), amount);
    }

    function test_Transfer(uint128 amount) public {
        vm.assume(amount > 0);

        uint256 currentSupply = linkingUSD.totalSupply();
        uint256 supplyCap = linkingUSD.supplyCap();

        vm.prank(linkingUSDAdmin);
        if (currentSupply + amount > supplyCap) {
            vm.expectRevert(ITIP20.SupplyCapExceeded.selector);
            linkingUSD.mint(_STABLECOIN_DEX, amount);
            return;
        }
        linkingUSD.mint(_STABLECOIN_DEX, amount);

        uint256 bobBalanceBefore = linkingUSD.balanceOf(bob);
        uint256 dexBalanceBefore = linkingUSD.balanceOf(_STABLECOIN_DEX);

        vm.startPrank(_STABLECOIN_DEX);
        bool success = linkingUSD.transfer(bob, amount);
        assertTrue(success);
        vm.stopPrank();

        assertEq(linkingUSD.balanceOf(bob), bobBalanceBefore + amount);
        assertEq(linkingUSD.balanceOf(_STABLECOIN_DEX), dexBalanceBefore - amount);
    }

    function test_TransferFrom(uint128 amount) public {
        vm.assume(amount > 0);

        uint256 currentSupply = linkingUSD.totalSupply();
        uint256 supplyCap = linkingUSD.supplyCap();

        vm.prank(linkingUSDAdmin);
        if (currentSupply + amount > supplyCap) {
            vm.expectRevert(ITIP20.SupplyCapExceeded.selector);
            linkingUSD.mint(alice, amount);
            return;
        }
        linkingUSD.mint(alice, amount);

        vm.prank(alice);
        linkingUSD.approve(_STABLECOIN_DEX, amount);

        uint256 aliceBalanceBefore = linkingUSD.balanceOf(alice);
        uint256 bobBalanceBefore = linkingUSD.balanceOf(bob);
        uint256 allowanceBefore = linkingUSD.allowance(alice, _STABLECOIN_DEX);

        vm.startPrank(_STABLECOIN_DEX);
        bool success = linkingUSD.transferFrom(alice, bob, amount);
        assertTrue(success);
        vm.stopPrank();

        assertEq(linkingUSD.balanceOf(alice), aliceBalanceBefore - amount);
        assertEq(linkingUSD.balanceOf(bob), bobBalanceBefore + amount);
        assertEq(linkingUSD.allowance(alice, _STABLECOIN_DEX), allowanceBefore - amount);
    }

    function test_TransferFrom_RevertIf_InsufficientAllowance() public {
        vm.startPrank(_STABLECOIN_DEX);
        try linkingUSD.transferFrom(alice, bob, 100) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InsufficientAllowance.selector));
        }
        vm.stopPrank();
    }

    function test_Transfer_RevertIf_InsufficientBalance() public {
        // DEX already has 10000e18 from setUp, try to transfer more than it has
        uint256 dexBalance = linkingUSD.balanceOf(_STABLECOIN_DEX);
        uint256 transferAmount = dexBalance + 1;

        vm.startPrank(_STABLECOIN_DEX);
        try linkingUSD.transfer(bob, transferAmount) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err,
                abi.encodeWithSelector(
                    ITIP20.InsufficientBalance.selector,
                    dexBalance,
                    transferAmount,
                    address(linkingUSD)
                )
            );
        }
        vm.stopPrank();
    }

    function test_Transfer_WithTransferRole(uint128 amount) public {
        vm.assume(amount > 0);
        amount = uint128(bound(amount, 1, 1e30));

        uint256 currentSupply = linkingUSD.totalSupply();
        uint256 supplyCap = linkingUSD.supplyCap();

        vm.startPrank(linkingUSDAdmin);
        if (currentSupply + amount > supplyCap) {
            vm.expectRevert(ITIP20.SupplyCapExceeded.selector);
            linkingUSD.mint(alice, amount);
            vm.stopPrank();
            return;
        }
        linkingUSD.mint(alice, amount);
        linkingUSD.grantRole(_TRANSFER_ROLE, alice);
        vm.stopPrank();

        uint256 aliceBalanceBefore = linkingUSD.balanceOf(alice);
        uint256 bobBalanceBefore = linkingUSD.balanceOf(bob);

        vm.startPrank(alice);
        bool success = linkingUSD.transfer(bob, amount);
        assertTrue(success);
        vm.stopPrank();

        assertEq(linkingUSD.balanceOf(alice), aliceBalanceBefore - amount);
        assertEq(linkingUSD.balanceOf(bob), bobBalanceBefore + amount);
    }

    function test_Transfer_WithReceiveWithMemoRole_Reverts(uint128 amount) public {
        vm.assume(amount > 0);
        amount = uint128(bound(amount, 1, 1e30));

        uint256 currentSupply = linkingUSD.totalSupply();
        uint256 supplyCap = linkingUSD.supplyCap();

        vm.startPrank(linkingUSDAdmin);
        if (currentSupply + amount > supplyCap) {
            vm.expectRevert(ITIP20.SupplyCapExceeded.selector);
            linkingUSD.mint(alice, amount);
            vm.stopPrank();
            return;
        }
        linkingUSD.mint(alice, amount);
        linkingUSD.grantRole(_RECEIVE_WITH_MEMO_ROLE, bob);
        vm.stopPrank();

        vm.startPrank(alice);
        try linkingUSD.transfer(bob, amount) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ILinkingUSD.TransfersDisabled.selector));
        }
        vm.stopPrank();
    }

    function test_TransferWithMemo_WithTransferRole(uint128 amount) public {
        vm.assume(amount > 0);
        amount = uint128(bound(amount, 1, 1e30));
        amount = uint128(bound(amount, 1, 1e30));

        vm.startPrank(linkingUSDAdmin);
        linkingUSD.mint(alice, amount);
        linkingUSD.grantRole(_TRANSFER_ROLE, alice);
        vm.stopPrank();

        uint256 aliceBalanceBefore = linkingUSD.balanceOf(alice);
        uint256 bobBalanceBefore = linkingUSD.balanceOf(bob);

        vm.startPrank(alice);
        linkingUSD.transferWithMemo(bob, amount, "test memo");
        vm.stopPrank();

        assertEq(linkingUSD.balanceOf(alice), aliceBalanceBefore - amount);
        assertEq(linkingUSD.balanceOf(bob), bobBalanceBefore + amount);
    }

    function test_TransferWithMemo_WithReceiveWithMemoRole(uint128 amount) public {
        vm.assume(amount > 0);
        amount = uint128(bound(amount, 1, 1e30));

        vm.startPrank(linkingUSDAdmin);
        linkingUSD.mint(alice, amount);
        linkingUSD.grantRole(_RECEIVE_WITH_MEMO_ROLE, bob);
        vm.stopPrank();

        uint256 aliceBalanceBefore = linkingUSD.balanceOf(alice);
        uint256 bobBalanceBefore = linkingUSD.balanceOf(bob);

        vm.startPrank(alice);
        linkingUSD.transferWithMemo(bob, amount, "test memo");
        vm.stopPrank();

        assertEq(linkingUSD.balanceOf(alice), aliceBalanceBefore - amount);
        assertEq(linkingUSD.balanceOf(bob), bobBalanceBefore + amount);
    }

    function test_TransferWithMemo_WithStablecoinDex(uint128 amount) public {
        vm.assume(amount > 0);
        amount = uint128(bound(amount, 1, 1e30));

        vm.prank(linkingUSDAdmin);
        linkingUSD.mint(_STABLECOIN_DEX, amount);

        uint256 dexBalanceBefore = linkingUSD.balanceOf(_STABLECOIN_DEX);
        uint256 bobBalanceBefore = linkingUSD.balanceOf(bob);

        vm.startPrank(_STABLECOIN_DEX);
        linkingUSD.transferWithMemo(bob, amount, "test memo");
        vm.stopPrank();

        assertEq(linkingUSD.balanceOf(_STABLECOIN_DEX), dexBalanceBefore - amount);
        assertEq(linkingUSD.balanceOf(bob), bobBalanceBefore + amount);
    }

    function test_TransferFrom_WithTransferRole(uint128 amount) public {
        vm.assume(amount > 0);
        amount = uint128(bound(amount, 1, 1e30));
        amount = uint128(bound(amount, 1, 1e30));

        vm.startPrank(linkingUSDAdmin);
        linkingUSD.mint(alice, amount);
        linkingUSD.grantRole(_TRANSFER_ROLE, alice);
        vm.stopPrank();

        vm.prank(alice);
        linkingUSD.approve(bob, amount);

        uint256 aliceBalanceBefore = linkingUSD.balanceOf(alice);
        uint256 bobBalanceBefore = linkingUSD.balanceOf(bob);
        uint256 allowanceBefore = linkingUSD.allowance(alice, bob);

        vm.startPrank(bob);
        bool success = linkingUSD.transferFrom(alice, bob, amount);
        assertTrue(success);
        vm.stopPrank();

        assertEq(linkingUSD.balanceOf(alice), aliceBalanceBefore - amount);
        assertEq(linkingUSD.balanceOf(bob), bobBalanceBefore + amount);
        assertEq(linkingUSD.allowance(alice, bob), allowanceBefore - amount);
    }

    function test_TransferFrom_WithReceiveWithMemoRole_Reverts(uint128 amount) public {
        vm.assume(amount > 0);
        amount = uint128(bound(amount, 1, 1e30));

        vm.startPrank(linkingUSDAdmin);
        linkingUSD.mint(alice, amount);
        linkingUSD.grantRole(_RECEIVE_WITH_MEMO_ROLE, bob);
        vm.stopPrank();

        vm.prank(alice);
        linkingUSD.approve(alice, amount);

        vm.startPrank(alice);
        try linkingUSD.transferFrom(alice, bob, amount) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ILinkingUSD.TransfersDisabled.selector));
        }
        vm.stopPrank();
    }

    function test_TransferFromWithMemo_WithTransferRole(uint128 amount) public {
        vm.assume(amount > 0);
        amount = uint128(bound(amount, 1, 1e30));
        amount = uint128(bound(amount, 1, 1e30));
        amount = uint128(bound(amount, 1, 1e30));

        vm.startPrank(linkingUSDAdmin);
        linkingUSD.mint(alice, amount);
        linkingUSD.grantRole(_TRANSFER_ROLE, alice);
        vm.stopPrank();

        vm.prank(alice);
        linkingUSD.approve(bob, amount);

        uint256 aliceBalanceBefore = linkingUSD.balanceOf(alice);
        uint256 bobBalanceBefore = linkingUSD.balanceOf(bob);
        uint256 allowanceBefore = linkingUSD.allowance(alice, bob);

        vm.startPrank(bob);
        bool success = linkingUSD.transferFromWithMemo(alice, bob, amount, "test memo");
        assertTrue(success);
        vm.stopPrank();

        assertEq(linkingUSD.balanceOf(alice), aliceBalanceBefore - amount);
        assertEq(linkingUSD.balanceOf(bob), bobBalanceBefore + amount);
        assertEq(linkingUSD.allowance(alice, bob), allowanceBefore - amount);
    }

    function test_TransferFromWithMemo_WithReceiveWithMemoRole(uint128 amount) public {
        vm.assume(amount > 0);
        amount = uint128(bound(amount, 1, 1e30));

        vm.startPrank(linkingUSDAdmin);
        linkingUSD.mint(alice, amount);
        linkingUSD.grantRole(_RECEIVE_WITH_MEMO_ROLE, bob);
        vm.stopPrank();

        vm.prank(alice);
        linkingUSD.approve(alice, amount);

        uint256 aliceBalanceBefore = linkingUSD.balanceOf(alice);
        uint256 bobBalanceBefore = linkingUSD.balanceOf(bob);
        uint256 allowanceBefore = linkingUSD.allowance(alice, alice);

        vm.startPrank(alice);
        bool success = linkingUSD.transferFromWithMemo(alice, bob, amount, "test memo");
        assertTrue(success);
        vm.stopPrank();

        assertEq(linkingUSD.balanceOf(alice), aliceBalanceBefore - amount);
        assertEq(linkingUSD.balanceOf(bob), bobBalanceBefore + amount);
        assertEq(linkingUSD.allowance(alice, alice), allowanceBefore - amount);
    }

    function test_TransferFromWithMemo_WithStablecoinDex(uint128 amount) public {
        vm.assume(amount > 0);
        amount = uint128(bound(amount, 1, 1e30));

        vm.prank(linkingUSDAdmin);
        linkingUSD.mint(alice, amount);

        vm.prank(alice);
        linkingUSD.approve(_STABLECOIN_DEX, amount);

        uint256 aliceBalanceBefore = linkingUSD.balanceOf(alice);
        uint256 bobBalanceBefore = linkingUSD.balanceOf(bob);
        uint256 allowanceBefore = linkingUSD.allowance(alice, _STABLECOIN_DEX);

        vm.startPrank(_STABLECOIN_DEX);
        bool success = linkingUSD.transferFromWithMemo(alice, bob, amount, "test memo");
        assertTrue(success);
        vm.stopPrank();

        assertEq(linkingUSD.balanceOf(alice), aliceBalanceBefore - amount);
        assertEq(linkingUSD.balanceOf(bob), bobBalanceBefore + amount);
        assertEq(linkingUSD.allowance(alice, _STABLECOIN_DEX), allowanceBefore - amount);
    }

    /*//////////////////////////////////////////////////////////////
                SECTION: ADDITIONAL COMPREHENSIVE TESTS
    //////////////////////////////////////////////////////////////*/

    /*==================== MORE UNIT TESTS ====================*/

    function test_UNIT_regularUserCannotTransferWithMemoStrict() public {
        bytes32 memo = keccak256("test");

        vm.prank(linkingUSDAdmin);
        linkingUSD.mint(alice, 100e18);

        vm.prank(alice);
        try linkingUSD.transferWithMemo(bob, 100e18, memo) {
            revert CallShouldHaveReverted();
        } catch (bytes memory reason) {
            bytes4 errorSelector = bytes4(reason);
            assertEq(errorSelector, ILinkingUSD.TransfersDisabled.selector, "Wrong error thrown");
        }
    }

    function test_UNIT_receiveWithMemoRoleCanReceive() public {
        vm.prank(linkingUSDAdmin);
        linkingUSD.grantRole(_RECEIVE_WITH_MEMO_ROLE, bob);

        // Alice already has 1000e18 from setUp, transfer 100e18 to Bob
        bytes32 memo = keccak256("payment");

        // Alice (regular user) can send to Bob (who has RECEIVE_WITH_MEMO_ROLE)
        vm.prank(alice);
        linkingUSD.transferWithMemo(bob, 100e18, memo);

        assertEq(linkingUSD.balanceOf(alice), 900e18); // 1000e18 - 100e18
        assertEq(linkingUSD.balanceOf(bob), 600e18); // 500e18 from setUp + 100e18
    }

    function test_UNIT_receiveWithMemoRoleOnlyWorksForMemoTransfers() public {
        vm.prank(linkingUSDAdmin);
        linkingUSD.grantRole(_RECEIVE_WITH_MEMO_ROLE, bob);

        vm.prank(linkingUSDAdmin);
        linkingUSD.mint(alice, 100e18);

        // Regular transfer still fails (even though Bob has RECEIVE_WITH_MEMO_ROLE)
        vm.prank(alice);
        try linkingUSD.transfer(bob, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory reason) {
            bytes4 errorSelector = bytes4(reason);
            assertEq(errorSelector, ILinkingUSD.TransfersDisabled.selector, "Wrong error thrown");
        }
    }

    function test_UNIT_receiveWithMemoRoleDoesNotAllowSending() public {
        vm.prank(linkingUSDAdmin);
        linkingUSD.grantRole(_RECEIVE_WITH_MEMO_ROLE, alice);

        vm.prank(linkingUSDAdmin);
        linkingUSD.mint(alice, 100e18);

        bytes32 memo = keccak256("payment");

        // Alice cannot send even with RECEIVE_WITH_MEMO_ROLE
        vm.prank(alice);
        try linkingUSD.transferWithMemo(bob, 100e18, memo) {
            revert CallShouldHaveReverted();
        } catch (bytes memory reason) {
            bytes4 errorSelector = bytes4(reason);
            assertEq(errorSelector, ILinkingUSD.TransfersDisabled.selector, "Wrong error thrown");
        }
    }

    function test_UNIT_transferRoleRevokedCannotTransfer() public {
        // Grant then revoke
        vm.startPrank(linkingUSDAdmin);
        linkingUSD.mint(alice, 100e18);
        linkingUSD.grantRole(_TRANSFER_ROLE, alice);
        linkingUSD.revokeRole(_TRANSFER_ROLE, alice);
        vm.stopPrank();

        // Alice can no longer transfer
        vm.prank(alice);
        try linkingUSD.transfer(bob, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory reason) {
            bytes4 errorSelector = bytes4(reason);
            assertEq(errorSelector, ILinkingUSD.TransfersDisabled.selector, "Wrong error thrown");
        }
    }

    /*==================== FUZZ: TRANSFER RESTRICTIONS ====================*/

    function testFuzz_regularUsersCannotTransferStrict(
        address user,
        address recipient,
        uint256 amount
    ) public {
        vm.assume(user != address(0) && recipient != address(0));
        vm.assume(user != _STABLECOIN_DEX);
        vm.assume((uint160(recipient) >> 64) != 0x20C000000000000000000000);
        amount = bound(amount, 1, 1000e18);

        // Ensure user doesn't have TRANSFER_ROLE
        assertFalse(linkingUSD.hasRole(user, _TRANSFER_ROLE));

        // Mint to user
        vm.prank(linkingUSDAdmin);
        linkingUSD.mint(user, amount);

        // User cannot transfer
        vm.prank(user);
        try linkingUSD.transfer(recipient, amount) {
            revert CallShouldHaveReverted();
        } catch (bytes memory reason) {
            bytes4 errorSelector = bytes4(reason);
            assertEq(errorSelector, ILinkingUSD.TransfersDisabled.selector, "Wrong error thrown");
        }
    }

    function testFuzz_dexCanAlwaysTransfer(address recipient, uint256 amount) public {
        vm.assume(recipient != address(0));
        vm.assume(recipient != _STABLECOIN_DEX);
        vm.assume(recipient != _LINKING_USD);
        vm.assume((uint160(recipient) >> 64) != 0x20C000000000000000000000);
        amount = bound(amount, 1, 10_000e18);

        vm.prank(linkingUSDAdmin);
        linkingUSD.mint(_STABLECOIN_DEX, amount);

        uint256 recipientBalanceBefore = linkingUSD.balanceOf(recipient);

        vm.prank(_STABLECOIN_DEX);
        linkingUSD.transfer(recipient, amount);

        assertEq(linkingUSD.balanceOf(recipient), recipientBalanceBefore + amount);
    }

    function testFuzz_transferRoleWorksCorrectly(address holder, address recipient, uint256 amount)
        public
    {
        vm.assume(holder != address(0) && recipient != address(0));
        vm.assume(holder != recipient);
        vm.assume(recipient != _LINKING_USD);
        vm.assume((uint160(holder) >> 64) != 0x20C000000000000000000000);
        vm.assume((uint160(recipient) >> 64) != 0x20C000000000000000000000);
        amount = bound(amount, 1, 1000e18);

        // Grant TRANSFER_ROLE to holder
        vm.prank(linkingUSDAdmin);
        linkingUSD.grantRole(_TRANSFER_ROLE, holder);

        // Mint to holder
        vm.prank(linkingUSDAdmin);
        linkingUSD.mint(holder, amount);

        // Holder can transfer
        uint256 holderBalanceBefore = linkingUSD.balanceOf(holder);
        uint256 recipientBalanceBefore = linkingUSD.balanceOf(recipient);

        vm.prank(holder);
        linkingUSD.transfer(recipient, amount);

        assertEq(linkingUSD.balanceOf(holder), holderBalanceBefore - amount);
        assertEq(linkingUSD.balanceOf(recipient), recipientBalanceBefore + amount);
    }

    function testFuzz_receiveWithMemoRoleWorksCorrectly(
        address sender,
        address receiver,
        uint256 amount,
        bytes32 memo
    ) public {
        vm.assume(sender != address(0) && receiver != address(0));
        vm.assume(sender != receiver);
        vm.assume(sender != _STABLECOIN_DEX);
        vm.assume(sender != alice && sender != bob && sender != charlie && sender != admin);
        vm.assume(receiver != alice && receiver != bob && receiver != charlie && receiver != admin);
        vm.assume(receiver != _LINKING_USD);
        vm.assume((uint160(sender) >> 64) != 0x20C000000000000000000000);
        vm.assume((uint160(receiver) >> 64) != 0x20C000000000000000000000);
        amount = bound(amount, 1, 1000e18);

        // Grant RECEIVE_WITH_MEMO_ROLE to receiver
        vm.prank(linkingUSDAdmin);
        linkingUSD.grantRole(_RECEIVE_WITH_MEMO_ROLE, receiver);

        // Mint to sender
        vm.prank(linkingUSDAdmin);
        linkingUSD.mint(sender, amount);

        uint256 senderBalanceBefore = linkingUSD.balanceOf(sender);
        uint256 receiverBalanceBefore = linkingUSD.balanceOf(receiver);

        // Sender can send to receiver via memo transfer
        vm.prank(sender);
        linkingUSD.transferWithMemo(receiver, amount, memo);

        // Verify balances
        assertEq(linkingUSD.balanceOf(sender), senderBalanceBefore - amount);
        assertEq(linkingUSD.balanceOf(receiver), receiverBalanceBefore + amount);
    }

    /*==================== CRITICAL INVARIANTS ====================*/

    /// @notice INVARIANT: Regular users never have TRANSFER_ROLE by default
    function test_INVARIANT_regularUsersHaveNoTransferRole() public view {
        assertFalse(linkingUSD.hasRole(alice, _TRANSFER_ROLE));
        assertFalse(linkingUSD.hasRole(bob, _TRANSFER_ROLE));
        assertFalse(linkingUSD.hasRole(charlie, _TRANSFER_ROLE));
    }

    /// @notice INVARIANT: Stablecoin DEX address is constant
    function test_INVARIANT_stablecoinDexAddressConstant() public pure {
        assertEq(_STABLECOIN_DEX, 0xDEc0000000000000000000000000000000000000);
    }

    /// @notice INVARIANT: Total supply conservation (same as ITIP20)
    function test_INVARIANT_supplyConservation() public view {
        address[] memory actors = new address[](5);
        actors[0] = alice;
        actors[1] = bob;
        actors[2] = charlie;
        actors[3] = admin;
        actors[4] = _STABLECOIN_DEX;

        uint256 sumBalances = 0;
        for (uint256 i = 0; i < actors.length; i++) {
            sumBalances += linkingUSD.balanceOf(actors[i]);
        }
        sumBalances += linkingUSD.balanceOf(address(linkingUSD));

        assertEq(sumBalances, linkingUSD.totalSupply(), "CRITICAL: Supply not conserved");
    }

    /*==================== EDGE CASES ====================*/

    function test_EDGE_dexCanTransferToSelf() public {
        vm.prank(linkingUSDAdmin);
        linkingUSD.mint(_STABLECOIN_DEX, 100e18);

        uint256 balanceBefore = linkingUSD.balanceOf(_STABLECOIN_DEX);

        vm.prank(_STABLECOIN_DEX);
        linkingUSD.transfer(_STABLECOIN_DEX, 100e18);

        assertEq(linkingUSD.balanceOf(_STABLECOIN_DEX), balanceBefore);
    }

    function test_EDGE_bothRolesCanCoexist() public {
        // Alice already has 1000e18 from setUp
        // Grant both roles to alice
        vm.startPrank(linkingUSDAdmin);
        linkingUSD.grantRole(_TRANSFER_ROLE, alice);
        linkingUSD.grantRole(_RECEIVE_WITH_MEMO_ROLE, alice);
        vm.stopPrank();

        // Alice can transfer
        vm.prank(alice);
        linkingUSD.transfer(bob, 100e18);

        assertEq(linkingUSD.balanceOf(alice), 900e18); // 1000e18 - 100e18
    }

    function test_EDGE_zeroAmountTransferWithRole() public {
        vm.prank(linkingUSDAdmin);
        linkingUSD.grantRole(_TRANSFER_ROLE, alice);

        vm.prank(alice);
        bool success = linkingUSD.transfer(bob, 0);

        assertTrue(success);
    }

    function test_EDGE_adminCanGrantAndRevokeRoles() public {
        vm.startPrank(linkingUSDAdmin);

        linkingUSD.grantRole(_TRANSFER_ROLE, alice);
        assertTrue(linkingUSD.hasRole(alice, _TRANSFER_ROLE));

        linkingUSD.revokeRole(_TRANSFER_ROLE, alice);
        assertFalse(linkingUSD.hasRole(alice, _TRANSFER_ROLE));

        vm.stopPrank();
    }

}
