// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20 } from "../src/TIP20.sol";
import { TIP20Controller } from "../src/TIP20Controller.sol";
import { ReserveStore } from "../src/ReserveStore.sol";
import { ITIP20 } from "../src/interfaces/ITIP20.sol";
import { ITIP20Controller } from "../src/interfaces/ITIP20Controller.sol";
import { ITIP20RolesAuth } from "../src/interfaces/ITIP20RolesAuth.sol";
import { BaseTest } from "./BaseTest.t.sol";

contract TIP20ControllerTest is BaseTest {

    TIP20Controller controller;
    TIP20 ledgerToken;
    TIP20 stablecoin1;
    TIP20 stablecoin2;
    ReserveStore reserveStore1;
    ReserveStore reserveStore2;

    bytes32 constant MINT_RATE_LIMIT_SETTER_ROLE = keccak256("MINT_RATE_LIMIT_SETTER_ROLE");
    bytes32 constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 constant UNWRAPPER_ROLE = keccak256("UNWRAPPER_ROLE");
    bytes32 constant BRIDGE_ECOSYSTEM_CONTRACT_ROLE = keccak256("BRIDGE_ECOSYSTEM_CONTRACT_ROLE");

    function setUp() public override {
        super.setUp();

        ledgerToken =
            TIP20(factory.createToken("Reserve Ledger USD", "RLUSD", "USD", TIP20(_PATH_USD), admin));
        stablecoin1 =
            TIP20(factory.createToken("Path USD", "pathUSD", "USD", TIP20(_PATH_USD), admin));
        stablecoin2 =
            TIP20(factory.createToken("Bridge USD", "bUSD", "USD", TIP20(_PATH_USD), admin));

        controller = new TIP20Controller(address(ledgerToken), admin);

        reserveStore1 =
            new ReserveStore(address(ledgerToken), address(controller), address(stablecoin1));
        reserveStore2 =
            new ReserveStore(address(ledgerToken), address(controller), address(stablecoin2));

        vm.startPrank(admin);
        controller.setReserveStore(address(stablecoin1), address(reserveStore1));
        controller.setReserveStore(address(stablecoin2), address(reserveStore2));

        stablecoin1.grantRole(_ISSUER_ROLE, address(controller));
        stablecoin2.grantRole(_ISSUER_ROLE, address(controller));

        controller.grantRole(MINT_RATE_LIMIT_SETTER_ROLE, admin);
        controller.setTxnMintLimit(address(stablecoin1), 1_000_000e6);
        controller.setTxnMintLimit(address(stablecoin2), 1_000_000e6);
        controller.setMinterAllowance(address(stablecoin1), alice, 10_000e6);
        controller.setMinterAllowance(address(stablecoin2), alice, 10_000e6);

        controller.grantRole(BURNER_ROLE, alice);

        ledgerToken.grantRole(_ISSUER_ROLE, admin);
        ledgerToken.mint(alice, 10_000e6);
        ledgerToken.mint(bob, 5_000e6);
        vm.stopPrank();
    }

    // ========== MINT FLOW TESTS ==========

    function test_mint_success() public {
        uint256 amount = 100e6;

        vm.prank(alice);
        ledgerToken.approve(address(controller), amount);

        uint256 aliceLedgerBefore = ledgerToken.balanceOf(alice);
        uint256 aliceStableBefore = stablecoin1.balanceOf(alice);
        uint256 reserveStoreBefore = ledgerToken.balanceOf(address(reserveStore1));

        vm.prank(alice);
        controller.mint(address(stablecoin1), alice, amount);

        assertEq(
            ledgerToken.balanceOf(alice),
            aliceLedgerBefore - amount,
            "Alice ledger balance should decrease"
        );
        assertEq(
            stablecoin1.balanceOf(alice),
            aliceStableBefore + amount,
            "Alice stablecoin balance should increase"
        );
        assertEq(
            ledgerToken.balanceOf(address(reserveStore1)),
            reserveStoreBefore + amount,
            "ReserveStore should hold ledger tokens"
        );
    }

    function test_mint_toAnotherRecipient() public {
        uint256 amount = 100e6;

        vm.prank(alice);
        ledgerToken.approve(address(controller), amount);

        vm.prank(alice);
        controller.mint(address(stablecoin1), bob, amount);

        assertEq(stablecoin1.balanceOf(bob), amount, "Bob should receive stablecoins");
    }

    function test_mint_revertsWithoutAllowance() public {
        uint256 amount = 100e6;

        vm.prank(bob);
        ledgerToken.approve(address(controller), amount);

        vm.prank(bob);
        try controller.mint(address(stablecoin1), bob, amount) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Controller.MinterAllowanceExceeded.selector));
        }
    }

    function test_mint_revertsExceedingTxnLimit() public {
        vm.prank(admin);
        controller.setMinterAllowance(address(stablecoin1), alice, 2_000_000e6);

        uint256 amount = 1_500_000e6;

        vm.prank(admin);
        ledgerToken.mint(alice, amount);

        vm.prank(alice);
        ledgerToken.approve(address(controller), amount);

        vm.prank(alice);
        try controller.mint(address(stablecoin1), alice, amount) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Controller.MintTxnLimitExceeded.selector));
        }
    }

    function test_mint_revertsWithZeroAmount() public {
        vm.prank(alice);
        try controller.mint(address(stablecoin1), alice, 0) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Controller.AmountCannotBeZero.selector));
        }
    }

    function test_mint_revertsWithoutReserveStore() public {
        TIP20 newStablecoin =
            TIP20(factory.createToken("New USD", "nUSD", "USD", TIP20(_PATH_USD), admin));

        vm.prank(admin);
        controller.setMinterAllowance(address(newStablecoin), alice, 1000e6);
        vm.prank(admin);
        controller.setTxnMintLimit(address(newStablecoin), 1000e6);

        vm.prank(alice);
        ledgerToken.approve(address(controller), 100e6);

        vm.prank(alice);
        try controller.mint(address(newStablecoin), alice, 100e6) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(ITIP20Controller.ReserveStoreNotConfigured.selector)
            );
        }
    }

    function test_mint_decrementsAllowance() public {
        uint256 amount = 100e6;

        uint256 allowanceBefore = controller.getMinterAllowance(address(stablecoin1), alice);

        vm.prank(alice);
        ledgerToken.approve(address(controller), amount);
        vm.prank(alice);
        controller.mint(address(stablecoin1), alice, amount);

        assertEq(
            controller.getMinterAllowance(address(stablecoin1), alice),
            allowanceBefore - amount,
            "Minter allowance should decrease"
        );
    }

    // ========== MINT BRIDGE ECOSYSTEM TESTS ==========

    function test_mintBridgeEcosystem_success() public {
        uint256 amount = 100e6;

        vm.prank(admin);
        controller.grantRole(BRIDGE_ECOSYSTEM_CONTRACT_ROLE, charlie);

        vm.prank(admin);
        ledgerToken.mint(charlie, amount);

        vm.prank(charlie);
        ledgerToken.approve(address(controller), amount);

        vm.prank(charlie);
        controller.mintBridgeEcosystem(address(stablecoin1), charlie, amount);

        assertEq(stablecoin1.balanceOf(charlie), amount, "Charlie should receive stablecoins");
    }

    function test_mintBridgeEcosystem_bypassesLimits() public {
        uint256 amount = 2_000_000e6;

        vm.prank(admin);
        controller.grantRole(BRIDGE_ECOSYSTEM_CONTRACT_ROLE, charlie);

        vm.prank(admin);
        ledgerToken.mint(charlie, amount);

        vm.prank(charlie);
        ledgerToken.approve(address(controller), amount);

        vm.prank(charlie);
        controller.mintBridgeEcosystem(address(stablecoin1), charlie, amount);

        assertEq(stablecoin1.balanceOf(charlie), amount);
    }

    function test_mintBridgeEcosystem_revertsWithoutRole() public {
        vm.prank(alice);
        ledgerToken.approve(address(controller), 100e6);

        vm.prank(alice);
        try controller.mintBridgeEcosystem(address(stablecoin1), alice, 100e6) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuth.Unauthorized.selector));
        }
    }

    // ========== BURN FLOW TESTS ==========

    function test_burn_success() public {
        uint256 mintAmount = 100e6;
        uint256 burnAmount = 50e6;

        vm.prank(alice);
        ledgerToken.approve(address(controller), mintAmount);
        vm.prank(alice);
        controller.mint(address(stablecoin1), alice, mintAmount);

        uint256 aliceLedgerBefore = ledgerToken.balanceOf(alice);
        uint256 aliceStableBefore = stablecoin1.balanceOf(alice);
        uint256 reserveStoreBefore = ledgerToken.balanceOf(address(reserveStore1));

        vm.prank(admin);
        stablecoin1.grantRole(_ISSUER_ROLE, alice);

        vm.prank(alice);
        stablecoin1.approve(address(controller), burnAmount);
        vm.prank(alice);
        controller.burn(address(stablecoin1), burnAmount);

        assertEq(
            ledgerToken.balanceOf(alice),
            aliceLedgerBefore + burnAmount,
            "Alice ledger balance should increase"
        );
        assertEq(
            stablecoin1.balanceOf(alice),
            aliceStableBefore - burnAmount,
            "Alice stablecoin balance should decrease"
        );
        assertEq(
            ledgerToken.balanceOf(address(reserveStore1)),
            reserveStoreBefore - burnAmount,
            "ReserveStore ledger balance should decrease"
        );
    }

    function test_burn_revertsWithoutBurnerRole() public {
        uint256 amount = 100e6;

        vm.prank(alice);
        ledgerToken.approve(address(controller), amount);
        vm.prank(alice);
        controller.mint(address(stablecoin1), alice, amount);

        vm.prank(bob);
        stablecoin1.approve(address(controller), amount);

        vm.prank(bob);
        try controller.burn(address(stablecoin1), amount) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuth.Unauthorized.selector));
        }
    }

    function test_burn_revertsWithoutReserveStore() public {
        TIP20 newStablecoin =
            TIP20(factory.createToken("New USD", "nUSD", "USD", TIP20(_PATH_USD), admin));

        vm.prank(alice);
        try controller.burn(address(newStablecoin), 100e6) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(ITIP20Controller.ReserveStoreNotConfigured.selector)
            );
        }
    }

    // ========== RATE LIMIT SETTER TESTS ==========

    function test_setTxnMintLimit_success() public {
        uint256 newLimit = 500_000e6;

        vm.prank(admin);
        controller.setTxnMintLimit(address(stablecoin1), newLimit);

        assertEq(controller.getStablecoinTxnMintLimit(address(stablecoin1)), newLimit);
    }

    function test_setTxnMintLimit_revertsWithoutRole() public {
        vm.prank(alice);
        try controller.setTxnMintLimit(address(stablecoin1), 500_000e6) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuth.Unauthorized.selector));
        }
    }

    function test_setMinterAllowance_success() public {
        uint256 newAllowance = 50_000e6;

        vm.prank(admin);
        controller.setMinterAllowance(address(stablecoin1), bob, newAllowance);

        assertEq(controller.getMinterAllowance(address(stablecoin1), bob), newAllowance);
    }

    function test_setMinterAllowance_revertsWithoutRole() public {
        vm.prank(alice);
        try controller.setMinterAllowance(address(stablecoin1), bob, 50_000e6) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuth.Unauthorized.selector));
        }
    }

    // ========== RESERVE STORE TESTS ==========

    function test_setReserveStore_success() public {
        TIP20 newStablecoin =
            TIP20(factory.createToken("New USD", "nUSD", "USD", TIP20(_PATH_USD), admin));
        ReserveStore newStore =
            new ReserveStore(address(ledgerToken), address(controller), address(newStablecoin));

        vm.prank(admin);
        controller.setReserveStore(address(newStablecoin), address(newStore));

        assertEq(controller.getReserveStore(address(newStablecoin)), address(newStore));
    }

    function test_setReserveStore_revertsWithoutAdmin() public {
        vm.prank(alice);
        try controller.setReserveStore(address(stablecoin1), address(0x123)) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuth.Unauthorized.selector));
        }
    }

    // ========== E2E FLOW TESTS ==========

    function test_e2e_mintAndBurnFullCycle() public {
        uint256 amount = 500e6;

        assertEq(ledgerToken.balanceOf(alice), 10_000e6, "Alice starts with 10000 ledger tokens");
        assertEq(stablecoin1.balanceOf(alice), 0, "Alice starts with 0 stablecoins");
        assertEq(
            ledgerToken.balanceOf(address(reserveStore1)), 0, "ReserveStore starts with 0 tokens"
        );

        vm.prank(alice);
        ledgerToken.approve(address(controller), amount);
        vm.prank(alice);
        controller.mint(address(stablecoin1), alice, amount);

        assertEq(ledgerToken.balanceOf(alice), 9500e6, "Alice has 9500 ledger tokens after mint");
        assertEq(stablecoin1.balanceOf(alice), 500e6, "Alice has 500 stablecoins after mint");
        assertEq(
            ledgerToken.balanceOf(address(reserveStore1)),
            500e6,
            "ReserveStore holds 500 ledger tokens"
        );

        vm.prank(admin);
        stablecoin1.grantRole(_ISSUER_ROLE, alice);

        vm.prank(alice);
        stablecoin1.approve(address(controller), amount);
        vm.prank(alice);
        controller.burn(address(stablecoin1), amount);

        assertEq(ledgerToken.balanceOf(alice), 10_000e6, "Alice has 10000 ledger tokens after burn");
        assertEq(stablecoin1.balanceOf(alice), 0, "Alice has 0 stablecoins after burn");
        assertEq(
            ledgerToken.balanceOf(address(reserveStore1)),
            0,
            "ReserveStore holds 0 ledger tokens"
        );
    }

    function test_e2e_multipleStablecoins() public {
        uint256 amount1 = 200e6;
        uint256 amount2 = 300e6;

        vm.prank(alice);
        ledgerToken.approve(address(controller), amount1 + amount2);

        vm.prank(alice);
        controller.mint(address(stablecoin1), alice, amount1);
        vm.prank(alice);
        controller.mint(address(stablecoin2), alice, amount2);

        assertEq(stablecoin1.balanceOf(alice), amount1);
        assertEq(stablecoin2.balanceOf(alice), amount2);
        assertEq(ledgerToken.balanceOf(address(reserveStore1)), amount1);
        assertEq(ledgerToken.balanceOf(address(reserveStore2)), amount2);
    }

    function test_e2e_multipleMintersCanOperate() public {
        vm.prank(admin);
        controller.setMinterAllowance(address(stablecoin1), bob, 5_000e6);

        vm.prank(alice);
        ledgerToken.approve(address(controller), 200e6);
        vm.prank(alice);
        controller.mint(address(stablecoin1), alice, 200e6);

        vm.prank(bob);
        ledgerToken.approve(address(controller), 300e6);
        vm.prank(bob);
        controller.mint(address(stablecoin1), bob, 300e6);

        assertEq(stablecoin1.balanceOf(alice), 200e6);
        assertEq(stablecoin1.balanceOf(bob), 300e6);
        assertEq(ledgerToken.balanceOf(address(reserveStore1)), 500e6);
    }

    // ========== ROLE MANAGEMENT TESTS ==========

    function test_adminCanGrantAndRevokeRoles() public {
        assertFalse(controller.hasRole(charlie, MINT_RATE_LIMIT_SETTER_ROLE));

        vm.prank(admin);
        controller.grantRole(MINT_RATE_LIMIT_SETTER_ROLE, charlie);
        assertTrue(controller.hasRole(charlie, MINT_RATE_LIMIT_SETTER_ROLE));

        vm.prank(admin);
        controller.revokeRole(MINT_RATE_LIMIT_SETTER_ROLE, charlie);
        assertFalse(controller.hasRole(charlie, MINT_RATE_LIMIT_SETTER_ROLE));
    }

    function test_nonAdminCannotGrantRoles() public {
        vm.prank(alice);
        try controller.grantRole(MINT_RATE_LIMIT_SETTER_ROLE, bob) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuth.Unauthorized.selector));
        }
    }

    // ========== WRAP/UNWRAP TESTS ==========

    function test_wrap_success() public {
        uint256 amount = 100e6;

        vm.prank(alice);
        ledgerToken.approve(address(controller), amount);

        uint256 aliceLedgerBefore = ledgerToken.balanceOf(alice);
        uint256 aliceStableBefore = stablecoin1.balanceOf(alice);
        uint256 reserveStoreBefore = ledgerToken.balanceOf(address(reserveStore1));

        vm.prank(alice);
        controller.wrap(address(stablecoin1), alice, amount);

        assertEq(
            ledgerToken.balanceOf(alice),
            aliceLedgerBefore - amount,
            "Alice ledger balance should decrease"
        );
        assertEq(
            stablecoin1.balanceOf(alice),
            aliceStableBefore + amount,
            "Alice stablecoin balance should increase"
        );
        assertEq(
            ledgerToken.balanceOf(address(reserveStore1)),
            reserveStoreBefore + amount,
            "ReserveStore should hold ledger tokens"
        );
    }

    function test_wrap_toAnotherRecipient() public {
        uint256 amount = 100e6;

        vm.prank(alice);
        ledgerToken.approve(address(controller), amount);

        vm.prank(alice);
        controller.wrap(address(stablecoin1), bob, amount);

        assertEq(stablecoin1.balanceOf(bob), amount, "Bob should receive stablecoins");
    }

    function test_wrap_doesNotRequireMinterAllowance() public {
        uint256 amount = 100e6;

        assertEq(controller.getMinterAllowance(address(stablecoin1), bob), 0);

        vm.prank(bob);
        ledgerToken.approve(address(controller), amount);

        vm.prank(bob);
        controller.wrap(address(stablecoin1), bob, amount);

        assertEq(stablecoin1.balanceOf(bob), amount);
    }

    function test_wrap_revertsWithZeroAmount() public {
        vm.prank(alice);
        try controller.wrap(address(stablecoin1), alice, 0) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Controller.AmountCannotBeZero.selector));
        }
    }

    function test_wrap_revertsWithoutReserveStore() public {
        TIP20 newStablecoin =
            TIP20(factory.createToken("New USD", "nUSD", "USD", TIP20(_PATH_USD), admin));

        vm.prank(alice);
        ledgerToken.approve(address(controller), 100e6);

        vm.prank(alice);
        try controller.wrap(address(newStablecoin), alice, 100e6) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(ITIP20Controller.ReserveStoreNotConfigured.selector)
            );
        }
    }

    function test_unwrap_success() public {
        uint256 wrapAmount = 100e6;
        uint256 unwrapAmount = 50e6;

        vm.prank(alice);
        ledgerToken.approve(address(controller), wrapAmount);
        vm.prank(alice);
        controller.wrap(address(stablecoin1), alice, wrapAmount);

        vm.prank(admin);
        controller.grantRole(UNWRAPPER_ROLE, alice);

        vm.prank(admin);
        stablecoin1.grantRole(_ISSUER_ROLE, alice);

        uint256 aliceLedgerBefore = ledgerToken.balanceOf(alice);
        uint256 aliceStableBefore = stablecoin1.balanceOf(alice);
        uint256 reserveStoreBefore = ledgerToken.balanceOf(address(reserveStore1));

        vm.prank(alice);
        stablecoin1.approve(address(controller), unwrapAmount);
        vm.prank(alice);
        controller.unwrap(address(stablecoin1), unwrapAmount);

        assertEq(
            ledgerToken.balanceOf(alice),
            aliceLedgerBefore + unwrapAmount,
            "Alice ledger balance should increase"
        );
        assertEq(
            stablecoin1.balanceOf(alice),
            aliceStableBefore - unwrapAmount,
            "Alice stablecoin balance should decrease"
        );
        assertEq(
            ledgerToken.balanceOf(address(reserveStore1)),
            reserveStoreBefore - unwrapAmount,
            "ReserveStore ledger balance should decrease"
        );
    }

    function test_unwrap_revertsWithoutUnwrapperRole() public {
        uint256 amount = 100e6;

        vm.prank(alice);
        ledgerToken.approve(address(controller), amount);
        vm.prank(alice);
        controller.wrap(address(stablecoin1), alice, amount);

        vm.prank(alice);
        stablecoin1.approve(address(controller), amount);

        vm.prank(alice);
        try controller.unwrap(address(stablecoin1), amount) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuth.Unauthorized.selector));
        }
    }

    function test_unwrap_revertsWithZeroAmount() public {
        vm.prank(admin);
        controller.grantRole(UNWRAPPER_ROLE, alice);

        vm.prank(alice);
        try controller.unwrap(address(stablecoin1), 0) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Controller.AmountCannotBeZero.selector));
        }
    }

    function test_e2e_wrapAndUnwrapFullCycle() public {
        uint256 amount = 500e6;

        vm.prank(admin);
        controller.grantRole(UNWRAPPER_ROLE, alice);
        vm.prank(admin);
        stablecoin1.grantRole(_ISSUER_ROLE, alice);

        assertEq(ledgerToken.balanceOf(alice), 10_000e6);
        assertEq(stablecoin1.balanceOf(alice), 0);
        assertEq(ledgerToken.balanceOf(address(reserveStore1)), 0);

        vm.prank(alice);
        ledgerToken.approve(address(controller), amount);
        vm.prank(alice);
        controller.wrap(address(stablecoin1), alice, amount);

        assertEq(ledgerToken.balanceOf(alice), 9500e6);
        assertEq(stablecoin1.balanceOf(alice), 500e6);
        assertEq(ledgerToken.balanceOf(address(reserveStore1)), 500e6);

        vm.prank(alice);
        stablecoin1.approve(address(controller), amount);
        vm.prank(alice);
        controller.unwrap(address(stablecoin1), amount);

        assertEq(ledgerToken.balanceOf(alice), 10_000e6);
        assertEq(stablecoin1.balanceOf(alice), 0);
        assertEq(ledgerToken.balanceOf(address(reserveStore1)), 0);
    }

    // ========== RESERVE STORE CONTRACT TESTS ==========

    function test_reserveStore_hasCorrectImmutables() public view {
        assertEq(address(reserveStore1.RESERVE_LEDGER()), address(ledgerToken));
        assertEq(reserveStore1.CONTROLLER(), address(controller));
        assertEq(address(reserveStore1.STABLECOIN()), address(stablecoin1));
    }

    function test_reserveStore_approvesController() public view {
        uint256 allowance = ledgerToken.allowance(address(reserveStore1), address(controller));
        assertEq(allowance, type(uint256).max);
    }

}
