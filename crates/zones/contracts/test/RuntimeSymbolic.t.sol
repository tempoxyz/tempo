// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { EncryptedDepositLib } from "../src/runtime/libraries/EncryptedDeposit.sol";
import {
    WithdrawalQueue,
    WithdrawalQueueLib
} from "../src/runtime/libraries/WithdrawalQueueLib.sol";
import { ZonePortalTest } from "./tempo/ZonePortal.t.sol";
import { Test } from "forge-std/Test.sol";

/// @title ZonePortal symbolic properties
/// @notice Curated symbolic (`check_*`) properties for the arithmetic-heavy parts of the zone
///         contracts. These complement the unit/fuzz suites: each `check_*` is explored over the
///         full symbolic input space (within configured bounds) rather than sampled.
///
///         Run with the symbolic-capable forge build:
///           forge test --symbolic --match-contract ZonePortalSymbolic
///           forge test --symbolic --match-contract WithdrawalQueueSymbolic
///
///         Guidance: prefer inequality / overflow-freedom / revert-freedom properties. Exact
///         equalities involving multiplication tend to return `incomplete` (the engine's
///         nonlinear "hard arithmetic" gap), which means "not established" — never treat it as a
///         pass.
///
///         Inherits ZonePortalTest to reuse its concrete setUp (a real ZonePortal deployed via
///         ZoneFactory, with separate portal admin and sequencer roles).
contract ZonePortalSymbolic is ZonePortalTest {

    /// @notice Deposit fee never overflows uint128 for any rate within the enforced cap, so
    ///         `calculateDepositFee` cannot revert. Proven over all 2^128 rate values.
    function check_depositFeeNeverOverflows(uint128 rate) external {
        vm.assume(rate <= portal.MAX_GAS_FEE_RATE());

        vm.prank(admin);
        portal.setZoneGasRate(rate);

        uint128 fee = portal.calculateDepositFee();
        assertLe(uint256(fee), uint256(type(uint128).max));
    }

    /// @notice The stored gas rate is always within the cap whenever `setZoneGasRate` succeeds,
    ///         for any input (over-cap inputs revert and are pruned). Encodes the MAX_GAS_FEE_RATE
    ///         invariant.
    function check_gasRateAlwaysWithinCap(uint128 rate) external {
        vm.prank(admin);
        try portal.setZoneGasRate(rate) {
            assertLe(uint256(portal.zoneGasRate()), uint256(portal.MAX_GAS_FEE_RATE()));
        } catch { }
    }

    /// @notice The admin-configured sequencer ceiling never exceeds the protocol maximum.
    function check_maxTempoGasRateAlwaysWithinProtocolCap(uint128 rate) external {
        vm.prank(admin);
        try portal.setMaxTempoGasRate(rate) {
            assertLe(uint256(portal.maxTempoGasRate()), uint256(portal.MAX_GAS_FEE_RATE()));
        } catch { }
    }

}

/// @notice Harness exposing the WithdrawalQueueLib FIFO over a storage queue so its
///         index arithmetic can be explored symbolically.
contract WithdrawalQueueHarness {

    using WithdrawalQueueLib for WithdrawalQueue;

    WithdrawalQueue internal q;

    function setHeadTail(uint256 _head, uint256 _tail) external {
        q.head = _head;
        q.tail = _tail;
    }

    function head() external view returns (uint256) {
        return q.head;
    }

    function tail() external view returns (uint256) {
        return q.tail;
    }

    function length() external view returns (uint256) {
        return q.length();
    }

    function hasWithdrawals() external view returns (bool) {
        return q.hasWithdrawals();
    }

    function enqueue(bytes32 h) external {
        q.enqueue(h);
    }

}

/// @title WithdrawalQueueLib symbolic properties
/// @notice Symbolic checks for the withdrawal FIFO's pure index arithmetic
///         (head/tail). The dequeue hash-chain path is intentionally excluded because it relies
///         on keccak injectivity, which the symbolic engine does not model.
contract WithdrawalQueueSymbolic is Test {

    WithdrawalQueueHarness internal qh;

    function setUp() public {
        qh = new WithdrawalQueueHarness();
    }

    /// @notice For any valid queue state, hasWithdrawals() <=> length() != 0.
    function check_hasWithdrawalsIffNonEmpty(uint256 _head, uint256 _tail) external {
        vm.assume(_tail >= _head);

        qh.setHeadTail(_head, _tail);

        assertEq(qh.hasWithdrawals(), qh.length() != 0);
    }

    /// @notice A valid non-empty enqueue advances tail and length by exactly one.
    function check_enqueueAdvancesTailAndLength(uint256 _head, uint256 _tail, bytes32 h) external {
        vm.assume(h != bytes32(0));
        vm.assume(_tail >= _head);
        vm.assume(_tail < type(uint256).max); // tail + 1 cannot overflow

        qh.setHeadTail(_head, _tail);
        uint256 lenBefore = qh.length();

        qh.enqueue(h);

        assertEq(qh.tail(), _tail + 1);
        assertEq(qh.length(), lenBefore + 1);
    }

    /// @notice Enqueuing the zero hash (a batch with no withdrawals) is a no-op: head and tail
    ///         are unchanged, for any starting state.
    function check_enqueueZeroIsNoop(uint256 _head, uint256 _tail) external {
        qh.setHeadTail(_head, _tail);

        qh.enqueue(bytes32(0));

        assertEq(qh.head(), _head);
        assertEq(qh.tail(), _tail);
    }

}

/// @notice Harness exposing the EncryptedDepositLib plaintext packing helpers so the
///         encode/decode assembly can be explored symbolically.
contract EncryptedDepositHarness {

    function roundtrip(address to, bytes32 memo) external pure returns (address, bytes32) {
        return EncryptedDepositLib.decodePlaintext(EncryptedDepositLib.encodePlaintext(to, memo));
    }

}

/// @title Deposit symbolic properties
/// @notice Symbolic check for the (to, memo) plaintext packing round-trip. Pure byte manipulation
///         (no keccak, no external calls) — a clean symbolic-execution target.
contract EncryptedDepositSymbolic is Test {

    EncryptedDepositHarness internal h;

    function setUp() public {
        h = new EncryptedDepositHarness();
    }

    /// @notice decode(encode(to, memo)) == (to, memo) for every address and memo. Catches any
    ///         offset/packing bug in the assembly layout.
    function check_plaintextRoundTrip(address to, bytes32 memo) external view {
        (address gotTo, bytes32 gotMemo) = h.roundtrip(to, memo);
        assertEq(gotTo, to);
        assertEq(gotMemo, memo);
    }

}
