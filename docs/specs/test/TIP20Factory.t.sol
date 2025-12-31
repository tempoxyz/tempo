// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20Factory } from "../src/TIP20Factory.sol";
import { TIP403Registry } from "../src/TIP403Registry.sol";
import { ITIP20 } from "../src/interfaces/ITIP20.sol";
import { ITIP20Factory } from "../src/interfaces/ITIP20Factory.sol";
import { BaseTest } from "./BaseTest.t.sol";
import { Test } from "forge-std/Test.sol";

contract TIP20FactoryTest is BaseTest {

    function testCreateUsdToken_RevertsIf_NonUsdQuoteToken() public {
        address nonUsdTokenAddr = factory.createToken(
            "Euro Token", "EUR", "EUR", ITIP20(_PATH_USD), admin, bytes32("eur")
        );
        ITIP20 nonUsdToken = ITIP20(nonUsdTokenAddr);

        try factory.createToken("USD Token", "USD", "USD", nonUsdToken, admin, bytes32("usd")) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Factory.InvalidQuoteToken.selector));
        }
    }

    function testCreateTokenCurrencyValidation() public {
        // Non-USD token with USD quote token should succeed
        bytes32 eurSalt = bytes32("eur_currency");
        address expectedAddr = address(
            uint160(0x20C0000000000000000000000000000000000000)
                | uint160(uint80(bytes10(keccak256(abi.encode(address(this), eurSalt)))))
        );

        if (!isTempo) {
            vm.expectEmit(true, true, false, true);
            emit ITIP20Factory.TokenCreated(
                expectedAddr, "Euro Token", "EUR", "EUR", ITIP20(_PATH_USD), admin, eurSalt
            );
        }

        address eurTokenAddr =
            factory.createToken("Euro Token", "EUR", "EUR", ITIP20(_PATH_USD), admin, eurSalt);
        ITIP20 eurToken = ITIP20(eurTokenAddr);
        assertEq(eurToken.currency(), "EUR");
        assertEq(address(eurToken.quoteToken()), _PATH_USD);

        // Non-USD token with non-USD quote token should succeed
        bytes32 testSalt = bytes32("test_currency");
        expectedAddr = address(
            uint160(0x20C0000000000000000000000000000000000000)
                | uint160(uint80(bytes10(keccak256(abi.encode(address(this), testSalt)))))
        );

        if (!isTempo) {
            vm.expectEmit(true, true, false, true);
            emit ITIP20Factory.TokenCreated(
                expectedAddr, "Test", "Test", "EUR", eurToken, admin, testSalt
            );
        }

        address tokenAddr = factory.createToken("Test", "Test", "EUR", eurToken, admin, testSalt);
        ITIP20 nonUSDToken = ITIP20(tokenAddr);
        assertEq(nonUSDToken.currency(), "EUR");
        assertEq(address(nonUSDToken.quoteToken()), eurTokenAddr);
    }

    function testCreateTokenWithValidQuoteToken() public {
        // Create token with PathUSD as the quote token
        address tokenAddr = factory.createToken(
            "Test Token", "TEST", "USD", ITIP20(_PATH_USD), admin, bytes32("valid")
        );

        ITIP20 token = ITIP20(tokenAddr);
        assertEq(token.name(), "Test Token");
        assertEq(token.symbol(), "TEST");
        assertEq(address(token.quoteToken()), _PATH_USD);
    }

    function testCreateTokenWithInvalidQuoteTokenReverts() public {
        // Try to create token with non-TIP20 address as quote token
        try factory.createToken(
            "Test Token",
            "TEST",
            "USD",
            ITIP20(address(0x1234)), // Invalid address
            admin,
            bytes32("invalid")
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Factory.InvalidQuoteToken.selector));
        }
    }

    function testCreateTokenWithZeroAddressReverts() public {
        // Try to create token with zero address as quote token
        try factory.createToken(
            "Test Token", "TEST", "USD", ITIP20(address(0)), admin, bytes32("zero")
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Factory.InvalidQuoteToken.selector));
        }
    }

    function testIsTIP20Function() public view {
        assertTrue(factory.isTIP20(_PATH_USD));
        assertTrue(factory.isTIP20(address(token1)));
        assertFalse(factory.isTIP20(0x20C0000000000000000000000000000000000001));
        assertFalse(factory.isTIP20(address(0)));
        assertFalse(factory.isTIP20(address(0x1234)));
        assertFalse(factory.isTIP20(0x21C0000000000000000000000000000000000000));
    }

    function testDeterministicAddressGeneration() public {
        // Test that same sender + salt produces same address
        bytes32 salt = bytes32("deterministic");
        address expectedAddr = address(
            uint160(0x20C0000000000000000000000000000000000000)
                | uint160(uint80(bytes10(keccak256(abi.encode(address(this), salt)))))
        );

        address tokenAddr =
            factory.createToken("Token 1", "TK1", "USD", ITIP20(_PATH_USD), admin, salt);
        assertEq(tokenAddr, expectedAddr, "Address should match deterministic calculation");

        // Different salts produce different addresses
        bytes32 salt2 = bytes32("different");
        address tokenAddr2 =
            factory.createToken("Token 2", "TK2", "USD", ITIP20(_PATH_USD), admin, salt2);
        assertTrue(tokenAddr != tokenAddr2, "Different salts should produce different addresses");
    }

    /*//////////////////////////////////////////////////////////////
                SECTION: ADDITIONAL FUZZ & EDGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test: Addresses without TIP20 prefix should be invalid
    function testFuzz_isTIP20WithInvalidPrefix(uint160 randomAddr) public view {
        // Ensure address doesn't have the TIP20 prefix
        vm.assume(bytes10(bytes20(address(randomAddr))) != 0x20c00000000000000000);

        assertFalse(factory.isTIP20(address(randomAddr)));
    }

    /// @notice Fuzz test: Creating token with invalid quote token should fail
    function testFuzz_createTokenWithInvalidQuoteToken(address invalidQuote) public {
        // Ensure it's not a valid TIP20 address
        vm.assume(!factory.isTIP20(invalidQuote));

        // Try-catch is better for precompiles than expectRevert
        try factory.createToken(
            "Token", "TK", "USD", ITIP20(invalidQuote), admin, bytes32("fuzz")
        ) returns (
            address
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory reason) {
            // Verify it's the correct error
            bytes4 errorSelector = bytes4(reason);
            assertEq(errorSelector, ITIP20Factory.InvalidQuoteToken.selector, "Wrong error thrown");
        }
    }

    /*==================== EDGE CASES ====================*/

    /// @notice Edge case: Zero address should not be valid TIP20
    function test_EDGE_zeroAddressNotValid() public view {
        assertFalse(factory.isTIP20(address(0)));
    }

    /// @notice Edge case: Factory address itself should not be valid TIP20
    function test_EDGE_factoryAddressNotValid() public view {
        assertFalse(factory.isTIP20(_TIP20FACTORY));
    }

    /// @notice Edge case: PathUSD address should always be valid
    function test_EDGE_pathUSDAlwaysValid() public view {
        assertTrue(factory.isTIP20(_PATH_USD));
    }

    /// @notice Edge case: Token cannot use itself as quote token
    function test_EDGE_cannotCreateSelfReferencingToken() public {
        bytes32 salt = bytes32("selfref");

        // Calculate what the token's address will be using the deterministic formula
        address nextTokenAddr = address(
            uint160(0x20C0000000000000000000000000000000000000)
                | uint160(uint80(bytes10(keccak256(abi.encode(address(this), salt)))))
        );

        // The address is not yet a valid TIP20 until it's deployed
        assertFalse(
            factory.isTIP20(nextTokenAddr), "isTIP20 should reject undeployed token address"
        );

        // Try to create a token that references itself as the quote token
        try factory.createToken("Self Ref", "SELF", "USD", ITIP20(nextTokenAddr), admin, salt) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Factory.InvalidQuoteToken.selector));
        }
    }

}
