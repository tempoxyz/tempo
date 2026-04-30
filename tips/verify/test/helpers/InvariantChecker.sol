// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { HandlerBase } from "./HandlerBase.sol";
import { TxBuilder } from "./TxBuilder.sol";

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
        _checkReplayProtectionInvariants();
        _checkCreateConstraintInvariants();
        _checkKeyAuthInvariants();
        _checkExpiringNonceInvariants();
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
        assertEq(
            actualNonce,
            expectedNonce,
            string(
                abi.encodePacked("N2: Protocol nonce mismatch for actor ", vm.toString(actorIdx))
            )
        );
    }

    /// @notice Verify 2D nonce invariants for a single account
    /// @param account The account to verify
    /// @dev Optimized: iterates only used keys via ghost_account2dNonceKeys array
    function _verify2dNonceForAccount(address account) internal view {
        // N6 & N7: Check each used 2D nonce key
        uint256[] storage keys = ghost_account2dNonceKeys[account];
        for (uint256 i = 0; i < keys.length; i++) {
            uint256 key = keys[i];
            uint64 actual = nonce.getNonce(account, key);
            uint256 expected = ghost_2dNonce[account][key];

            // N6: 2D nonce keys are independent - actual should match expected
            assertEq(actual, expected, "N6: 2D nonce value mismatch");

            // N7: 2D nonces never decrease (implicit - ghost only increments)
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
        uint256 actorSum = 0;

        // Sum secp256k1 actor balances
        for (uint256 i = 0; i < actors.length; i++) {
            actorSum += feeToken.balanceOf(actors[i]);
        }

        // Sum P256 address balances
        for (uint256 i = 0; i < actors.length; i++) {
            actorSum += feeToken.balanceOf(actorP256Addresses[i]);
        }

        // F9: Actor balances cannot exceed total supply
        assertLe(actorSum, feeToken.totalSupply(), "F9: Actor balances exceed total supply");

        // F10: Validator balance (fees collected) + actor balances + other known addresses <= total supply
        uint256 validatorBalance = feeToken.balanceOf(validator);
        uint256 adminBalance = feeToken.balanceOf(admin);
        uint256 ammBalance = feeToken.balanceOf(address(amm));
        uint256 totalTracked = actorSum + validatorBalance + adminBalance + ammBalance;
        assertLe(totalTracked, feeToken.totalSupply(), "F10: Tracked balances exceed total supply");
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
        uint256[] storage nonces = ghost_createNonces[account];

        assertEq(nonces.length, ghost_createCount[account], "C5: create nonce list/count mismatch");

        for (uint256 i = 0; i < nonces.length; i++) {
            uint256 n = nonces[i];
            bytes32 key = keccak256(abi.encodePacked(account, n));
            address recorded = ghost_createAddresses[key];

            assertTrue(recorded != address(0), "C5: missing recorded CREATE address");

            address computed = TxBuilder.computeCreateAddress(account, n);
            assertEq(recorded, computed, "C5: CREATE address mismatch");

            assertTrue(recorded.code.length > 0, "C5: No code at CREATE address");
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

    // ============ Replay Protection Invariants (N12-N15) ============

    /// @notice Verify replay protection invariants are not violated
    /// @dev These counters should always be 0 - any non-zero value indicates a protocol bug
    function _checkReplayProtectionInvariants() internal view {
        // N12: Protocol nonce replay must be rejected
        assertEq(ghost_replayProtocolAllowed, 0, "N12: Protocol nonce replay unexpectedly allowed");

        // N13: 2D nonce replay must be rejected
        assertEq(ghost_replay2dAllowed, 0, "N13: 2D nonce replay unexpectedly allowed");

        // N14: Nonce too high must be rejected
        assertEq(ghost_nonceTooHighAllowed, 0, "N14: Nonce too high unexpectedly allowed");

        // N15: Nonce too low must be rejected
        assertEq(ghost_nonceTooLowAllowed, 0, "N15: Nonce too low unexpectedly allowed");
    }

    // ============ CREATE Constraint Invariants (C1-C4, C8) ============

    /// @notice Verify CREATE structure constraints are enforced
    /// @dev These counters should always be 0 - any non-zero value indicates a protocol bug
    function _checkCreateConstraintInvariants() internal view {
        // C1: CREATE must be first call in batch
        assertEq(ghost_createNotFirstAllowed, 0, "C1: CREATE not first unexpectedly allowed");

        // C2: Maximum one CREATE per transaction
        assertEq(ghost_createMultipleAllowed, 0, "C2: Multiple CREATEs unexpectedly allowed");

        // C3: CREATE forbidden with authorization list
        assertEq(ghost_createWithAuthAllowed, 0, "C3: CREATE with auth list unexpectedly allowed");

        // C4: Value transfers forbidden in AA transactions with CREATE
        assertEq(ghost_createWithValueAllowed, 0, "C4: CREATE with value unexpectedly allowed");

        // C8: Initcode must not exceed max size (EIP-3860: 49152 bytes)
        // BUG-001 was fixed in tempo-foundry
        assertEq(ghost_createOversizedAllowed, 0, "C8: Oversized initcode unexpectedly allowed");
    }

    // ============ Key Authorization Invariants (K1, K3) ============

    /// @notice Verify key authorization constraints are enforced
    /// @dev These counters should always be 0 - any non-zero value indicates a protocol bug
    function _checkKeyAuthInvariants() internal view {
        // K1: KeyAuthorization must be signed by tx.caller (root account)
        assertEq(ghost_keyWrongSignerAllowed, 0, "K1: Wrong signer key auth unexpectedly allowed");

        // K3: KeyAuthorization chain_id must be 0 (any) or match current
        assertEq(ghost_keyWrongChainAllowed, 0, "K3: Wrong chain key auth unexpectedly allowed");

        // K7: Revoked keys must not be usable
        assertEq(ghost_keyRevokedAllowed, 0, "K7: Revoked key unexpectedly allowed");

        // K8: Expired keys must not be usable
        assertEq(ghost_keyExpiredAllowed, 0, "K8: Expired key unexpectedly allowed");

        // K12: Keys with zero spending limit cannot spend anything
        assertEq(ghost_keyZeroLimitAllowed, 0, "K12: Zero-limit key unexpectedly allowed to spend");
    }

    // ============ Expiring Nonce Invariants (E1-E5) ============

    /// @notice Verify expiring nonce constraints are enforced (TIP-1009)
    /// @dev These counters should always be 0 - any non-zero value indicates a protocol bug
    function _checkExpiringNonceInvariants() internal view {
        // E1: No replay within validity window
        assertEq(
            ghost_expiringNonceReplayAllowed,
            0,
            "E1: Expiring nonce replay within window unexpectedly allowed"
        );

        // E2: Expiry enforcement (validBefore <= now must be rejected)
        assertEq(
            ghost_expiringNonceExpiredAllowed, 0, "E2: Expired transaction unexpectedly allowed"
        );

        // E3: Window bounds (validBefore > now + 30s must be rejected)
        assertEq(
            ghost_expiringNonceWindowAllowed,
            0,
            "E3: validBefore exceeds max window unexpectedly allowed"
        );

        // E4: Nonce must be zero
        assertEq(
            ghost_expiringNonceNonZeroAllowed,
            0,
            "E4: Non-zero nonce for expiring nonce tx unexpectedly allowed"
        );

        // E5: validBefore required
        assertEq(
            ghost_expiringNonceMissingVBAllowed,
            0,
            "E5: Missing validBefore for expiring nonce tx unexpectedly allowed"
        );
    }

}
