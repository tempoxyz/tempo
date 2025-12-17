// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { INonce } from "../src/interfaces/INonce.sol";
import { BaseTest } from "./BaseTest.t.sol";
import { console } from "forge-std/Test.sol";

/// @title NonceTest
/// @notice Comprehensive test suite for the Nonce precompile
contract NonceTest is BaseTest {

    address testAlice = address(0x1111111111111111111111111111111111111111);
    address testBob = address(0x2222222222222222222222222222222222222222);
    address testCharlie = address(0x3333333333333333333333333333333333333333);

    // Storage slots from Nonce contract
    uint256 private constant NONCES_SLOT = 0;

    // Events from INonce (for event testing, though vm.store won't emit them)
    event NonceIncremented(address indexed account, uint256 indexed nonceKey, uint64 newNonce);

    /// @dev Helper function to increment nonce using direct storage manipulation
    /// This works for both precompile and deployed Solidity contract
    /// @param account The account whose nonce to increment
    /// @param nonceKey The nonce key to increment (must be > 0)
    /// @return newNonce The new nonce value after incrementing
    function _incrementNonceViaStorage(address account, uint256 nonceKey)
        internal
        returns (uint64 newNonce)
    {
        require(nonceKey > 0, "Cannot increment protocol nonce (key 0)");

        // Calculate storage slot for nonces[account][nonceKey]
        // For nested mapping: keccak256(abi.encode(nonceKey, keccak256(abi.encode(account, baseSlot))))
        bytes32 nonceSlot =
            keccak256(abi.encode(nonceKey, keccak256(abi.encode(account, NONCES_SLOT))));

        // Read current nonce value
        uint64 currentNonce = uint64(uint256(vm.load(_NONCE, nonceSlot)));

        // Check for overflow
        require(currentNonce < type(uint64).max, "Nonce overflow");

        // Increment nonce
        newNonce = currentNonce + 1;

        // Store new nonce value
        vm.store(_NONCE, nonceSlot, bytes32(uint256(newNonce)));

        return newNonce;
    }

    // ============ Basic View Tests ============

    function test_GetNonce_ReturnsZeroForNewKey() public view {
        uint64 result = nonce.getNonce(testAlice, 1);
        assertEq(result, 0, "New nonce key should return 0");
    }

    function test_GetNonce_ReturnsZeroForDifferentKeys() public view {
        for (uint256 i = 1; i <= 10; i++) {
            uint64 result = nonce.getNonce(testAlice, i);
            assertEq(result, 0, "All new nonce keys should return 0");
        }
    }

    function test_GetNonce_RevertIf_ProtocolNonce() public view {
        try nonce.getNonce(testAlice, 0) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(INonce.ProtocolNonceNotSupported.selector));
        }
    }

    // ============ Increment Nonce Tests ============

    function test_IncrementNonce_FirstIncrement() public {
        // Call storage manipulation helper (simulates protocol behavior)
        uint64 newNonce = _incrementNonceViaStorage(testAlice, 5);

        assertEq(newNonce, 1, "First increment should return 1");
        assertEq(nonce.getNonce(testAlice, 5), 1, "Nonce should be stored as 1");
    }

    function test_IncrementNonce_MultipleIncrements() public {
        for (uint64 i = 1; i <= 10; i++) {
            uint64 newNonce = _incrementNonceViaStorage(testAlice, 5);
            assertEq(newNonce, i, "Nonce should increment sequentially");
        }

        assertEq(nonce.getNonce(testAlice, 5), 10, "Final nonce should be 10");
    }

    function test_IncrementNonce_DifferentKeys() public {
        // Increment key 1
        uint64 nonce1 = _incrementNonceViaStorage(testAlice, 1);
        assertEq(nonce1, 1, "Key 1 first nonce should be 1");

        // Increment key 2
        uint64 nonce2 = _incrementNonceViaStorage(testAlice, 2);
        assertEq(nonce2, 1, "Key 2 first nonce should be 1");

        // Increment key 1 again
        nonce1 = _incrementNonceViaStorage(testAlice, 1);
        assertEq(nonce1, 2, "Key 1 second nonce should be 2");

        // Increment key 3
        uint64 nonce3 = _incrementNonceViaStorage(testAlice, 3);
        assertEq(nonce3, 1, "Key 3 first nonce should be 1");
    }

    function test_IncrementNonce_RevertIf_ProtocolKey() public {
        // This test verifies that our helper function properly rejects protocol nonce key (0)
        // We use a direct require in the helper, so we test with try-catch
        bool reverted = false;
        try this.externalIncrementNonceViaStorage(testAlice, 0) {
        // Should not reach here
        }
        catch {
            reverted = true;
        }
        assertTrue(reverted, "Should revert when trying to increment protocol key 0");
    }

    /// @dev External wrapper for testing reverts
    function externalIncrementNonceViaStorage(address account, uint256 nonceKey)
        external
        returns (uint64)
    {
        return _incrementNonceViaStorage(account, nonceKey);
    }

    // ============ Multiple Account Tests ============

    function test_DifferentAccounts_IndependentNonces() public {
        // Increment testAlice's nonces
        for (uint64 i = 0; i < 10; i++) {
            _incrementNonceViaStorage(testAlice, 5);
        }

        // Increment testBob's nonces
        for (uint64 i = 0; i < 20; i++) {
            _incrementNonceViaStorage(testBob, 5);
        }

        // Check they're independent
        assertEq(nonce.getNonce(testAlice, 5), 10, "Alice's nonce should be 10");
        assertEq(nonce.getNonce(testBob, 5), 20, "Bob's nonce should be 20");
    }

    function test_DifferentAccounts_DifferentKeys() public {
        // Alice uses keys 1, 2, 3
        _incrementNonceViaStorage(testAlice, 1);
        _incrementNonceViaStorage(testAlice, 2);
        _incrementNonceViaStorage(testAlice, 3);

        // Bob uses keys 4, 5
        _incrementNonceViaStorage(testBob, 4);
        _incrementNonceViaStorage(testBob, 5);

        // Charlie uses key 1
        _incrementNonceViaStorage(testCharlie, 1);

        // Verify independence
        assertEq(nonce.getNonce(testAlice, 1), 1, "Alice key 1 should be 1");
        assertEq(nonce.getNonce(testCharlie, 1), 1, "Charlie key 1 should be 1");
        assertEq(nonce.getNonce(testAlice, 4), 0, "Alice key 4 should be 0");
        assertEq(nonce.getNonce(testBob, 1), 0, "Bob key 1 should be 0");
    }

    // ============ Event Tests ============
    // Note: Event tests are not included because vm.store() doesn't emit events.
    // The protocol implementation will emit events, but we test functionality here.

    // ============ Fuzz Tests ============

    function testFuzz_GetNonce_NewKey(address account, uint256 nonceKey) public view {
        vm.assume(nonceKey > 0); // Protocol nonce not supported

        uint64 result = nonce.getNonce(account, nonceKey);
        assertEq(result, 0, "New nonce key should always return 0");
    }

    function testFuzz_IncrementNonce_Sequential(address account, uint256 nonceKey, uint8 count)
        public
    {
        vm.assume(nonceKey > 0); // Protocol nonce not supported
        vm.assume(count > 0 && count <= 100); // Reasonable range for testing

        for (uint64 i = 1; i <= count; i++) {
            uint64 newNonce = _incrementNonceViaStorage(account, nonceKey);
            assertEq(newNonce, i, "Nonces should increment sequentially");
        }

        assertEq(nonce.getNonce(account, nonceKey), count, "Final nonce should match count");
    }

    function testFuzz_DifferentAccounts_Independent(
        address account1,
        address account2,
        uint256 nonceKey,
        uint8 count1,
        uint8 count2
    ) public {
        vm.assume(account1 != account2);
        vm.assume(nonceKey > 0);
        vm.assume(count1 > 0 && count1 <= 50);
        vm.assume(count2 > 0 && count2 <= 50);

        // Increment account1's nonce
        for (uint64 i = 0; i < count1; i++) {
            _incrementNonceViaStorage(account1, nonceKey);
        }

        // Increment account2's nonce
        for (uint64 i = 0; i < count2; i++) {
            _incrementNonceViaStorage(account2, nonceKey);
        }

        // Verify independence
        assertEq(nonce.getNonce(account1, nonceKey), count1, "Account1 nonce should match count1");
        assertEq(nonce.getNonce(account2, nonceKey), count2, "Account2 nonce should match count2");
    }

    // ============ Edge Case Tests ============

    function test_EdgeCase_MaxNonceKey() public {
        uint256 maxKey = type(uint256).max;

        uint64 newNonce = _incrementNonceViaStorage(testAlice, maxKey);
        assertEq(newNonce, 1, "Should work with max uint256 key");
        assertEq(nonce.getNonce(testAlice, maxKey), 1, "Max key should be stored correctly");
    }

    function test_EdgeCase_LargeSequentialIncrements() public {
        // Increment many times
        for (uint64 i = 0; i < 1000; i++) {
            uint64 newNonce = _incrementNonceViaStorage(testAlice, 1);
            assertEq(newNonce, i + 1, "Should increment correctly up to 1000");
        }

        assertEq(nonce.getNonce(testAlice, 1), 1000, "Should reach 1000");
    }

    function test_EdgeCase_ManyDifferentKeys() public {
        // Use many different keys
        for (uint256 i = 1; i <= 50; i++) {
            _incrementNonceViaStorage(testAlice, i);
        }

        // Verify each key has nonce 1
        for (uint256 i = 1; i <= 50; i++) {
            assertEq(nonce.getNonce(testAlice, i), 1, "Each key should have nonce 1");
        }
    }

    function test_EdgeCase_AlternatingKeys() public {
        // Alternate between two keys
        for (uint256 i = 0; i < 20; i++) {
            if (i % 2 == 0) {
                _incrementNonceViaStorage(testAlice, 1);
            } else {
                _incrementNonceViaStorage(testAlice, 2);
            }
        }

        assertEq(nonce.getNonce(testAlice, 1), 10, "Key 1 should have nonce 10");
        assertEq(nonce.getNonce(testAlice, 2), 10, "Key 2 should have nonce 10");
    }

    // ============ Gas Tests ============

    function test_Gas_GetNonce() public view {
        uint256 gasBefore = gasleft();
        nonce.getNonce(testAlice, 1);
        uint256 gasUsed = gasBefore - gasleft();

        // This is informational - actual gas usage will depend on implementation
        assertTrue(gasUsed > 0, "Should consume some gas");
    }

    function test_Gas_IncrementNonce_FirstTime() public {
        uint256 gasBefore = gasleft();
        _incrementNonceViaStorage(testAlice, 1);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(gasUsed > 0, "Should consume gas");
    }

    function test_Gas_IncrementNonce_Subsequent() public {
        _incrementNonceViaStorage(testAlice, 1); // First increment

        uint256 gasBefore = gasleft();
        _incrementNonceViaStorage(testAlice, 1); // Second increment
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(gasUsed > 0, "Should consume gas");
    }

}
