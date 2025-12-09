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
        address nonUsdTokenAddr =
            factory.createToken("Euro Token", "EUR", "EUR", ITIP20(_PATH_USD), admin);
        ITIP20 nonUsdToken = ITIP20(nonUsdTokenAddr);

        try factory.createToken("USD Token", "USD", "USD", nonUsdToken, admin) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Factory.InvalidQuoteToken.selector));
        }
    }

    function testCreateTokenCurrencyValidation() public {
        // Non-USD token with USD quote token should succeed
        uint256 currentCounter = factory.tokenIdCounter();
        address expectedAddr =
            address(uint160(0x20C0000000000000000000000000000000000000) | uint160(currentCounter));

        if (!isTempo) {
            vm.expectEmit(true, true, false, true);
            emit ITIP20Factory.TokenCreated(
                expectedAddr, currentCounter, "Euro Token", "EUR", "EUR", ITIP20(_PATH_USD), admin
            );
        }

        address eurTokenAddr =
            factory.createToken("Euro Token", "EUR", "EUR", ITIP20(_PATH_USD), admin);
        ITIP20 eurToken = ITIP20(eurTokenAddr);
        assertEq(eurToken.currency(), "EUR");
        assertEq(address(eurToken.quoteToken()), _PATH_USD);

        // Non-USD token with non-USD quote token should succeed
        currentCounter = factory.tokenIdCounter();
        expectedAddr =
            address(uint160(0x20C0000000000000000000000000000000000000) | uint160(currentCounter));

        if (!isTempo) {
            vm.expectEmit(true, true, false, true);
            emit ITIP20Factory.TokenCreated(
                expectedAddr, currentCounter, "Test", "Test", "EUR", eurToken, admin
            );
        }

        address tokenAddr = factory.createToken("Test", "Test", "EUR", eurToken, admin);
        ITIP20 nonUSDToken = ITIP20(tokenAddr);
        assertEq(nonUSDToken.currency(), "EUR");
        assertEq(address(nonUSDToken.quoteToken()), eurTokenAddr);
    }

    function testCreateTokenWithValidQuoteToken() public {
        // Create token with PathUSD as the quote token
        address tokenAddr =
            factory.createToken("Test Token", "TEST", "USD", ITIP20(_PATH_USD), admin);

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
            admin
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Factory.InvalidQuoteToken.selector));
        }
    }

    function testCreateTokenWithZeroAddressReverts() public {
        // Try to create token with zero address as quote token
        try factory.createToken("Test Token", "TEST", "USD", ITIP20(address(0)), admin) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Factory.InvalidQuoteToken.selector));
        }
    }

    function testIsTIP20Function() public view {
        assertTrue(factory.isTIP20(_PATH_USD));
        assertTrue(factory.isTIP20(0x20C0000000000000000000000000000000000001));
        assertFalse(factory.isTIP20(address(0)));
        assertFalse(factory.isTIP20(address(0x1234)));
        assertFalse(factory.isTIP20(0x21C0000000000000000000000000000000000000));
    }

    function testTokenIdCounter() public {
        uint256 currCounter = factory.tokenIdCounter();

        factory.createToken("Token 1", "TK1", "USD", ITIP20(_PATH_USD), admin);
        assertEq(factory.tokenIdCounter(), currCounter + 1);

        factory.createToken("Token 2", "TK2", "USD", ITIP20(_PATH_USD), admin);
        assertEq(factory.tokenIdCounter(), currCounter + 2);
    }

    /*//////////////////////////////////////////////////////////////
                SECTION: ADDITIONAL FUZZ & EDGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test: Addresses without TIP20 prefix should be invalid
    function testFuzz_isTIP20WithInvalidPrefix(uint160 randomAddr) public view {
        // Ensure address doesn't have the TIP20 prefix
        vm.assume(bytes12(bytes20(address(randomAddr))) != 0x20c000000000000000000000);

        assertFalse(factory.isTIP20(address(randomAddr)));
    }

    /// @notice Fuzz test: Future tokenIds beyond counter should be invalid
    function testFuzz_isTIP20WithFutureTokenId(uint64 futureId) public view {
        uint256 currentCounter = factory.tokenIdCounter();

        // Create tokenId that's beyond current counter
        futureId = uint64(bound(futureId, currentCounter + 1, type(uint64).max));

        // Construct address with valid prefix but future tokenId
        address addr = address(uint160(0x20c000000000000000000000) | uint160(futureId));

        // Should be invalid because tokenId > counter
        assertFalse(factory.isTIP20(addr));
    }

    /// @notice Fuzz test: Creating token with invalid quote token should fail
    function testFuzz_createTokenWithInvalidQuoteToken(address invalidQuote) public {
        // Ensure it's not a valid TIP20 address
        vm.assume(!factory.isTIP20(invalidQuote));

        // Try-catch is better for precompiles than expectRevert
        try factory.createToken("Token", "TK", "USD", ITIP20(invalidQuote), admin) returns (address)
        {
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
        uint256 nextTokenId = factory.tokenIdCounter();

        // Calculate what the next token's address will be
        // TIP20 addresses have format: 0x20C0 (prefix) + 00...00 (padding) + tokenId (last 8 bytes)
        address nextTokenAddr =
            address(uint160(0x20C0000000000000000000000000000000000000) | uint160(nextTokenId));

        // isTIP20 correctly returns false because nextTokenId >= tokenIdCounter
        // This is caught by isTIP20's check: uint64(uint160(token)) < tokenIdCounter
        assertFalse(
            factory.isTIP20(nextTokenAddr), "isTIP20 should reject token with id >= tokenIdCounter"
        );

        // The explicit self-reference check provides defense in depth
        // Try to create a token that references itself as the quote token
        try factory.createToken("Self Ref", "SELF", "USD", ITIP20(nextTokenAddr), admin) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20Factory.InvalidQuoteToken.selector));
        }
    }

}
