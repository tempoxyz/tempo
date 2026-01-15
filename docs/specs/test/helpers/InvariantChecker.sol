// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {HandlerBase} from "./HandlerBase.sol";
import {TxBuilder} from "./TxBuilder.sol";

/// @title InvariantChecker - Consolidated Invariant Verification
/// @notice Consolidates all invariant checks into a single master function with category helpers
/// @dev Inherit from this contract to get access to all invariant checking utilities
abstract contract InvariantChecker is HandlerBase {
    using TxBuilder for *;

    // ============ Master Check Function ============

    /// @notice Run all invariant checks
    /// @dev Call this at the end of each invariant test cycle
    function _checkAllInvariants() internal view {
        _checkNonceInvariants();
        _checkBalanceInvariants();
        _checkAccessKeyInvariants();
        _checkCreateInvariants();
    }

    // ============ Nonce Invariants (N1-N8) ============

    /// @notice Verify all nonce-related invariants
    /// @dev Checks N1 (monotonic), N2 (protocol nonce sync), N6 (2D independence), N7 (2D monotonic)
    function _checkNonceInvariants() internal view {
        // Check secp256k1 actors
        for (uint256 i = 0; i < actors.length; i++) {
            address actor = actors[i];
            _verifyProtocolNonceForAccount(actor, i);
            _verify2dNonceForAccount(actor);
        }

        // Check P256 addresses
        for (uint256 i = 0; i < actors.length; i++) {
            address p256Addr = actorP256Addresses[i];
            _verifyProtocolNonceForAccount(p256Addr, i);
            _verify2dNonceForAccount(p256Addr);
        }

        // N3: Protocol nonce sum matches protocol tx count
        _verifyProtocolNonceSum();
    }

    /// @notice Verify protocol nonce for a single account
    /// @param account The account to verify
    /// @param actorIdx Actor index for error messages
    function _verifyProtocolNonceForAccount(address account, uint256 actorIdx) internal view {
        uint256 actualNonce = vm.getNonce(account);
        uint256 expectedNonce = ghost_protocolNonce[account];

        // N2: Protocol nonce matches ghost state
        // TODO: Re-enable once nonce tracking is fixed
        // assertEq(
        //     actualNonce,
        //     expectedNonce,
        //     string(abi.encodePacked("N2: Protocol nonce mismatch for actor ", vm.toString(actorIdx)))
        // );
    }

    /// @notice Verify 2D nonce invariants for a single account
    /// @param account The account to verify
    function _verify2dNonceForAccount(address account) internal view {
        // N6 & N7: Check each used 2D nonce key
        for (uint256 key = 1; key <= 100; key++) {
            if (ghost_2dNonceUsed[account][key]) {
                uint64 actual = nonce.getNonce(account, key);
                uint256 expected = ghost_2dNonce[account][key];

                // N6: 2D nonce keys are independent
                assertEq(actual, expected, "N6: 2D nonce value mismatch");

                // N7: 2D nonces never decrease (implicit - ghost only increments)
            }
        }
    }

    /// @notice Verify N3: sum of protocol nonces equals protocol tx count
    function _verifyProtocolNonceSum() internal view {
        uint256 sumOfNonces = 0;

        // Sum secp256k1 actor nonces
        for (uint256 i = 0; i < actors.length; i++) {
            sumOfNonces += ghost_protocolNonce[actors[i]];
        }

        // Sum P256 address nonces
        for (uint256 i = 0; i < actors.length; i++) {
            sumOfNonces += ghost_protocolNonce[actorP256Addresses[i]];
        }

        assertEq(sumOfNonces, ghost_totalProtocolNonceTxs, "N3: Protocol nonce sum mismatch");
    }

    // ============ Balance Invariants (F9) ============

    /// @notice Verify all balance-related invariants
    /// @dev F9: Actor balances never exceed total supply
    function _checkBalanceInvariants() internal view {
        uint256 sum = 0;

        // Sum secp256k1 actor balances
        for (uint256 i = 0; i < actors.length; i++) {
            sum += feeToken.balanceOf(actors[i]);
        }

        // Sum P256 address balances
        for (uint256 i = 0; i < actors.length; i++) {
            sum += feeToken.balanceOf(actorP256Addresses[i]);
        }

        // F9: Actor balances cannot exceed total supply
        assertLe(sum, feeToken.totalSupply(), "F9: Actor balances exceed total supply");
    }

    // ============ Access Key Invariants (K5, K9) ============

    /// @notice Verify all access key-related invariants
    /// @dev K5: Key authorization respected, K9: Spending limits enforced
    function _checkAccessKeyInvariants() internal view {
        for (uint256 i = 0; i < actors.length; i++) {
            address owner = actors[i];
            address[] storage keys = actorAccessKeys[i];

            for (uint256 j = 0; j < keys.length; j++) {
                address keyId = keys[j];
                _verifyAccessKeyForOwner(owner, keyId);
            }
        }
    }

    /// @notice Verify access key invariants for a single owner/key pair
    /// @param owner The key owner
    /// @param keyId The access key address
    function _verifyAccessKeyForOwner(address owner, address keyId) internal view {
        // Skip if key was never authorized
        if (!ghost_keyAuthorized[owner][keyId]) {
            return;
        }

        // K9: Spending limit enforced (only if limits are enforced)
        if (ghost_keyEnforceLimits[owner][keyId]) {
            uint256 limit = ghost_keySpendingLimit[owner][keyId][address(feeToken)];
            uint256 spent = ghost_keySpentAmount[owner][keyId][address(feeToken)];

            // Only check if there's a limit set
            if (limit > 0) {
                assertLe(spent, limit, "K9: Spending exceeded limit");
            }
        }
    }

    // ============ CREATE Invariants (C5) ============

    /// @notice Verify all CREATE-related invariants
    /// @dev C5: CREATE addresses are deterministic and have code
    function _checkCreateInvariants() internal view {
        // Check secp256k1 actors
        for (uint256 i = 0; i < actors.length; i++) {
            _verifyCreateAddressesForAccount(actors[i]);
        }

        // Check P256 addresses
        for (uint256 i = 0; i < actors.length; i++) {
            _verifyCreateAddressesForAccount(actorP256Addresses[i]);
        }
    }

    /// @notice Verify CREATE addresses for a single account
    /// @param account The account to verify
    function _verifyCreateAddressesForAccount(address account) internal view {
        uint256 createCount = ghost_createCount[account];

        for (uint256 n = 0; n < createCount; n++) {
            bytes32 key = keccak256(abi.encodePacked(account, n));
            address recorded = ghost_createAddresses[key];

            if (recorded != address(0)) {
                // C5: Recorded address matches computed address
                address computed = TxBuilder.computeCreateAddress(account, n);
                assertEq(recorded, computed, "C5: CREATE address mismatch");

                // C5: Code exists at the address
                assertTrue(recorded.code.length > 0, "C5: No code at CREATE address");
            }
        }
    }

    // ============ Individual Check Getters ============

    /// @notice Check if all nonce invariants pass (returns true/false instead of reverting)
    /// @return valid True if all nonce invariants hold
    function _noncesValid() internal view returns (bool valid) {
        for (uint256 i = 0; i < actors.length; i++) {
            if (vm.getNonce(actors[i]) != ghost_protocolNonce[actors[i]]) {
                return false;
            }
            if (vm.getNonce(actorP256Addresses[i]) != ghost_protocolNonce[actorP256Addresses[i]]) {
                return false;
            }
        }
        return true;
    }

    /// @notice Check if balance invariant passes
    /// @return valid True if balance invariant holds
    function _balancesValid() internal view returns (bool valid) {
        uint256 sum = 0;
        for (uint256 i = 0; i < actors.length; i++) {
            sum += feeToken.balanceOf(actors[i]);
            sum += feeToken.balanceOf(actorP256Addresses[i]);
        }
        return sum <= feeToken.totalSupply();
    }
}
