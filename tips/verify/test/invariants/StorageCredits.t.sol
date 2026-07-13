// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { InvariantBase } from "../helpers/InvariantBase.sol";
import { TxBuilder } from "../helpers/TxBuilder.sol";
import { StdPrecompiles as PC } from "tempo-std/StdPrecompiles.sol";
import { IStorageCredits } from "tempo-std/interfaces/IStorageCredits.sol";

error DelegateCallNotAllowed();
error StaticCallNotAllowed();
error UnknownFunctionSelector(bytes4 selector);

/// @dev Owns the storage exercised by the invariant. Storage credits belong to this contract,
///      irrespective of which externally-owned account submits the transaction.
contract StorageCreditsHarness {

    error ForcedRevert();

    IStorageCredits internal constant CREDITS = IStorageCredits(PC.STORAGE_CREDITS_ADDRESS);

    mapping(uint256 slot => uint256 value) public values;

    function mutate(
        uint256 slot,
        uint256 value,
        IStorageCredits.Mode mode,
        uint64 budget,
        bool useBudget,
        bool forceRevert
    )
        external
    {
        _setMode(mode, budget, useBudget);

        values[slot] = value;
        if (forceRevert) revert ForcedRevert();
    }

    /// @dev Exercises an x->0->y dirty recreation within one transaction. TIP-1060 accounting
    ///      intentionally depends on present/new values, not the transaction-original value.
    function recreate(
        uint256 slot,
        uint256 value,
        IStorageCredits.Mode mode,
        uint64 budget,
        bool useBudget
    )
        external
    {
        _setMode(mode, budget, useBudget);

        this.clear(slot);
        values[slot] = value;
    }

    function clear(uint256 slot) external {
        require(msg.sender == address(this), "only self");
        values[slot] = 0;
    }

    /// @dev Asserts every externally reachable Storage Credits revert/halt path. `OnlyDirectCall`
    ///      exists in the current SDK ABI but is not emitted by the implementation; the shared
    ///      precompile wrapper emits `DelegateCallNotAllowed` before dispatch instead.
    function assertKnownReverts() external {
        bytes memory result;
        bool success;

        (success, result) = address(CREDITS)
            .call(abi.encodeWithSelector(IStorageCredits.setMode.selector, uint256(3)));
        _assertRevert(success, result, abi.encodeWithSelector(IStorageCredits.InvalidMode.selector));

        (success, result) = address(CREDITS)
            .delegatecall(abi.encodeCall(IStorageCredits.balanceOf, (address(this))));
        _assertRevert(success, result, abi.encodeWithSelector(DelegateCallNotAllowed.selector));

        (success, result) =
            address(CREDITS).staticcall(abi.encodeCall(IStorageCredits.setBudget, (uint64(1))));
        _assertRevert(success, result, abi.encodeWithSelector(StaticCallNotAllowed.selector));

        bytes4 unknownSelector = 0xdeadbeef;
        (success, result) = address(CREDITS).call(abi.encodePacked(unknownSelector));
        _assertRevert(
            success,
            result,
            abi.encodeWithSelector(UnknownFunctionSelector.selector, unknownSelector)
        );

        (success, result) =
            address(CREDITS).call(abi.encodePacked(IStorageCredits.balanceOf.selector));
        _assertRevert(success, result, bytes(""));

        (success, result) = address(CREDITS).call(bytes(""));
        _assertRevert(success, result, bytes(""));

        (success, result) = address(CREDITS).call{ gas: 1 }(
            abi.encodeCall(IStorageCredits.balanceOf, (address(this)))
        );
        _assertRevert(success, result, bytes(""));
    }

    function assertAtomicRevert(
        uint256 slot,
        uint256 value,
        IStorageCredits.Mode mode,
        uint64 budget,
        bool useBudget
    )
        external
    {
        (bool success, bytes memory result) = address(this)
            .call(abi.encodeCall(this.mutate, (slot, value, mode, budget, useBudget, true)));
        _assertRevert(success, result, abi.encodeWithSelector(ForcedRevert.selector));
    }

    function _assertRevert(bool success, bytes memory actual, bytes memory expected) internal pure {
        require(!success, "expected Storage Credits call to revert");
        require(keccak256(actual) == keccak256(expected), "unexpected Storage Credits revert");
    }

    function _setMode(IStorageCredits.Mode mode, uint64 budget, bool useBudget) internal {
        bytes memory data = useBudget
            ? abi.encodeCall(IStorageCredits.setBudget, (budget))
            : abi.encodeCall(IStorageCredits.setMode, (mode));
        (bool success, bytes memory reason) = address(CREDITS).call(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(reason, 0x20), mload(reason))
            }
        }

        (success, data) =
            address(CREDITS).staticcall(abi.encodeCall(IStorageCredits.modeOf, (address(this))));
        require(success && data.length == 32, "modeOf failed after mode update");
        IStorageCredits.Mode expectedMode = useBudget ? IStorageCredits.Mode.Direct : mode;
        require(abi.decode(data, (IStorageCredits.Mode)) == expectedMode, "mode update not applied");

        (success, data) =
            address(CREDITS).staticcall(abi.encodeCall(IStorageCredits.budgetOf, (address(this))));
        require(success && data.length == 32, "budgetOf failed after mode update");
        uint64 expectedBudget =
            useBudget ? budget : mode == IStorageCredits.Mode.Direct ? type(uint64).max : 0;
        require(abi.decode(data, (uint64)) == expectedBudget, "budget update not applied");
    }

}

/// @title TIP-1060 Storage Credits Invariant Tests
/// @notice Stateful model-based tests for storage-credit conservation and account locality
contract StorageCreditsInvariantTest is InvariantBase {

    using TxBuilder for *;

    uint256 internal constant NUM_SLOTS = 16;
    uint64 internal constant TX_GAS_LIMIT = 1_500_000;

    IStorageCredits internal constant CREDITS = IStorageCredits(PC.STORAGE_CREDITS_ADDRESS);

    StorageCreditsHarness internal harness;
    StorageCreditsHarness internal untouchedHarness;

    mapping(uint256 slot => uint256 value) internal ghost_values;
    uint64 internal ghost_credits;

    function setUp() public override {
        super.setUp();

        harness = new StorageCreditsHarness();
        untouchedHarness = new StorageCreditsHarness();

        targetContract(address(this));
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = this.handler_mutate.selector;
        selectors[1] = this.handler_recreate.selector;
        selectors[2] = this.handler_revertingMutation.selector;
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));

    }

    /// @notice Asserts exact revert data for every reachable precompile error/halt path.
    function test_knownExpectedCustomErrors() public {
        harness.assertKnownReverts();
    }

    /*//////////////////////////////////////////////////////////////
                                HANDLERS
    //////////////////////////////////////////////////////////////*/

    function handler_mutate(
        uint256 actorSeed,
        uint256 slotSeed,
        uint256 valueSeed,
        uint256 modeSeed,
        uint256 budgetSeed
    )
        external
    {
        uint256 slot = slotSeed % NUM_SLOTS;
        uint256 oldValue = ghost_values[slot];
        uint256 newValue = valueSeed % 4 == 0 ? 0 : bound(valueSeed, 1, type(uint128).max);
        IStorageCredits.Mode mode = IStorageCredits.Mode(modeSeed % 3);
        bool useBudget = mode == IStorageCredits.Mode.Direct && budgetSeed % 2 == 0;
        uint64 budget = uint64(budgetSeed % 3);

        uint64 expectedCredits = _expectedAfterTransition(
            ghost_credits, oldValue, newValue, mode, useBudget ? budget : type(uint64).max
        );

        bytes memory data = abi.encodeCall(
            StorageCreditsHarness.mutate, (slot, newValue, mode, budget, useBudget, false)
        );
        _execute(actorSeed, data, true);

        ghost_values[slot] = newValue;
        ghost_credits = expectedCredits;
        _assertModel();
    }

    function handler_recreate(
        uint256 actorSeed,
        uint256 slotSeed,
        uint256 valueSeed,
        uint256 modeSeed,
        uint256 budgetSeed
    )
        external
    {
        uint256 slot = slotSeed % NUM_SLOTS;
        if (ghost_values[slot] == 0) return;

        uint256 newValue = bound(valueSeed, 1, type(uint128).max);
        IStorageCredits.Mode mode = IStorageCredits.Mode(modeSeed % 3);
        bool useBudget = mode == IStorageCredits.Mode.Direct && budgetSeed % 2 == 0;
        uint64 budget = uint64(budgetSeed % 3);

        // The clear first mints one credit. The following creation may consume it.
        uint64 expectedCredits = ghost_credits + 1;
        expectedCredits = _expectedAfterTransition(
            expectedCredits, 0, newValue, mode, useBudget ? budget : type(uint64).max
        );

        bytes memory data = abi.encodeCall(
            StorageCreditsHarness.recreate, (slot, newValue, mode, budget, useBudget)
        );
        _execute(actorSeed, data, true);

        ghost_values[slot] = newValue;
        ghost_credits = expectedCredits;
        _assertModel();
    }

    function handler_revertingMutation(
        uint256 actorSeed,
        uint256 slotSeed,
        uint256 valueSeed,
        uint256 modeSeed
    )
        external
    {
        uint256 slot = slotSeed % NUM_SLOTS;
        uint256 newValue = valueSeed % 2 == 0 ? 0 : bound(valueSeed, 1, type(uint128).max);
        IStorageCredits.Mode mode = IStorageCredits.Mode(modeSeed % 3);

        bytes memory data = abi.encodeCall(
            StorageCreditsHarness.assertAtomicRevert, (slot, newValue, mode, uint64(1), false)
        );
        _execute(actorSeed, data, true);

        // The storage transition, credit update, and transient mode change must all unwind.
        _assertModel();
    }

    /*//////////////////////////////////////////////////////////////
                               INVARIANT
    //////////////////////////////////////////////////////////////*/

    /// @notice Runs all TIP-1060 invariant checks from one Foundry invariant entrypoint.
    function invariant_storageCreditsGlobal() public view {
        _assertModel();
        _invariantAccountLocality();
        _invariantTransientStateReset();
    }

    function _assertModel() internal view {
        assertEq(
            CREDITS.balanceOf(address(harness)),
            ghost_credits,
            "TEMPO-SC1: persistent credit balance diverged from zero-crossing model"
        );

        for (uint256 slot = 0; slot < NUM_SLOTS; slot++) {
            assertEq(
                harness.values(slot),
                ghost_values[slot],
                "TEMPO-SC2: committed storage diverged from ghost state"
            );
        }
    }

    function _invariantAccountLocality() internal view {
        assertEq(
            CREDITS.balanceOf(address(untouchedHarness)),
            0,
            "TEMPO-SC4: credits escaped the storage-owning account"
        );
    }

    function _invariantTransientStateReset() internal view {
        assertEq(
            uint256(CREDITS.modeOf(address(harness))),
            uint256(IStorageCredits.Mode.Refund),
            "TEMPO-SC5: mode persisted across transactions"
        );
        assertEq(
            CREDITS.budgetOf(address(harness)),
            0,
            "TEMPO-SC5: direct budget persisted across transactions"
        );
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _expectedAfterTransition(
        uint64 credits,
        uint256 oldValue,
        uint256 newValue,
        IStorageCredits.Mode mode,
        uint64 budget
    )
        internal
        pure
        returns (uint64)
    {
        if (oldValue != 0 && newValue == 0) return credits + 1;
        if (oldValue == 0 && newValue != 0 && credits != 0) {
            if (mode == IStorageCredits.Mode.Refund) return credits - 1;
            if (mode == IStorageCredits.Mode.Direct && budget != 0) return credits - 1;
        }
        return credits;
    }

    function _execute(uint256 actorSeed, bytes memory data, bool expectSuccess) internal {
        uint256 actorIndex = actorSeed % actors.length;
        address actor = actors[actorIndex];
        uint64 nonce = uint64(vm.getNonce(actor));
        bytes memory signedTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(harness), data, nonce, TX_GAS_LIMIT, actorKeys[actorIndex]
        );

        vm.coinbase(validator);
        bool succeeded;
        try vmExec.executeTransaction(signedTx) {
            succeeded = true;
        } catch { }

        assertEq(succeeded, expectSuccess, "TIP-1060 transaction result differed from expectation");
    }

}
