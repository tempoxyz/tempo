// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { LinkingUSD } from "../src/LinkingUSD.sol";
import { TIP20Factory } from "../src/TIP20Factory.sol";
import { TIP403Registry } from "../src/TIP403Registry.sol";
import { ITIP20 } from "../src/interfaces/ITIP20.sol";
import { ITIP20Factory } from "../src/interfaces/ITIP20Factory.sol";
import { BaseTest } from "./BaseTest.t.sol";
import { Test } from "forge-std/Test.sol";

contract TIP20FactoryTest is BaseTest {

    LinkingUSD quoteToken;

    function testCreateTokenWithValidQuoteToken() public {
        // Create token with LinkingUSD as the quote token
        address tokenAddr =
            factory.createToken("Test Token", "TEST", "USD", ITIP20(_LINKING_USD), admin);

        ITIP20 token = ITIP20(tokenAddr);
        assertEq(token.name(), "Test Token");
        assertEq(token.symbol(), "TEST");
        assertEq(address(token.quoteToken()), _LINKING_USD);
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
        assertTrue(factory.isTIP20(_LINKING_USD));
        assertTrue(factory.isTIP20(0x20C0000000000000000000000000000000000001));
        assertFalse(factory.isTIP20(address(0)));
        assertFalse(factory.isTIP20(address(0x1234)));
        assertFalse(factory.isTIP20(0x21C0000000000000000000000000000000000000));
    }

    function testTokenIdCounter() public {
        uint256 currCounter = factory.tokenIdCounter();

        factory.createToken("Token 1", "TK1", "USD", ITIP20(_LINKING_USD), admin);
        assertEq(factory.tokenIdCounter(), currCounter + 1);

        factory.createToken("Token 2", "TK2", "USD", ITIP20(_LINKING_USD), admin);
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
        try factory.createToken(
            "Token", "TK", "USD", ITIP20(invalidQuote), admin
        ) returns (address) {
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

    /// @notice Edge case: LinkingUSD address should always be valid
    function test_EDGE_linkingUSDAlwaysValid() public view {
        assertTrue(factory.isTIP20(_LINKING_USD));
    }

    /*//////////////////////////////////////////////////////////////
            NOTE: COMMENTED OUT TESTS FROM fuzz-precompiles

        Many tests in the fuzz-precompiles branch are commented out
        because they require vanity address generation with CREATE2
        in production. In local Foundry tests, the standard `new`
        operator doesn't guarantee 0x20c0... prefixes.

        These tests can be re-enabled for integration testing on
        actual Tempo deployment where CREATE2 is used properly.

        Commented tests include:
        - testFuzz_createToken (vanity address generation)
        - testFuzz_createMultipleTokens (vanity address generation)
        - testFuzz_createTokenWithDifferentAdmins (vanity address)
        - testFuzz_isTIP20WithValidAddresses (vanity address)
        - testFuzz_isTIP20AfterMultipleCreations (vanity address)
        - testFuzz_createTokenWithValidQuoteToken (vanity address)
        - testFuzz_vanityAddressPrefixConsistency (vanity address)
        - testFuzz_tokenIdEmbeddedInAddress (vanity address)
        - All invariant tests (require handler contract setup)
        - test_EDGE_createMaxTokens (vanity address)
        - test_EDGE_linkingUSDQuotesItself (vanity address)
        - test_EDGE_createTokenQuotingNewerToken (vanity address)
        - test_EDGE_emptyStringParameters (vanity address)
        - test_EDGE_veryLongStringParameters (vanity address)
    //////////////////////////////////////////////////////////////*/


}
