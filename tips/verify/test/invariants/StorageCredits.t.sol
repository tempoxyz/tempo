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

    /// @dev Seeds occupied slots for deterministic clear/create scenarios.
    constructor(uint256 seededSlots) {
        for (uint256 slot = 0; slot < seededSlots; slot++) {
            values[slot] = slot + 1;
        }
    }

    /// @dev Applies one transition after verifying transaction-local state was reset.
    function mutate(
        uint256 slot,
        uint256 value,
        IStorageCredits.Mode mode,
        uint64 budget,
        bool useBudget
    )
        external
    {
        _assertDefaultTransientState();
        _setMode(mode, budget, useBudget);

        values[slot] = value;
    }

    /// @dev Keeps the transaction sender, intermediate caller, and storage owner distinct.
    function mutatePeer(
        StorageCreditsHarness peer,
        uint256 slot,
        uint256 value,
        IStorageCredits.Mode mode,
        uint64 budget,
        bool useBudget
    )
        external
    {
        _assertDefaultTransientState();
        peer.mutate(slot, value, mode, budget, useBudget);
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
        _assertDefaultTransientState();
        _setMode(mode, budget, useBudget);

        this.clear(slot);
        values[slot] = value;
    }

    /// @dev Starts with slot 0 occupied and slot 1 empty. Two clear/create cycles make the exact
    ///      number of Direct consumptions and the remaining budget independently observable.
    function exerciseDirectBudget(
        uint256 firstValue,
        uint256 secondValue,
        uint64 budget,
        bool useBudget
    )
        external
    {
        _assertDefaultTransientState();
        _setMode(IStorageCredits.Mode.Direct, budget, useBudget);

        values[0] = 0;
        values[1] = firstValue;
        values[1] = 0;
        values[0] = secondValue;

        uint64 expectedBudget = type(uint64).max;
        if (useBudget) expectedBudget = budget > 2 ? budget - 2 : 0;
        _assertTransientState(IStorageCredits.Mode.Direct, expectedBudget);
    }

    /// @dev Creates two slots before clearing two occupied slots. In default Refund mode the later
    ///      clears must fund both earlier creations during end-of-transaction settlement.
    function createThenClear(
        uint256 fromStart,
        uint256 toStart,
        uint256 firstValue,
        uint256 secondValue
    )
        external
    {
        _assertDefaultTransientState();

        values[toStart] = firstValue;
        values[toStart + 1] = secondValue;
        values[fromStart] = 0;
        values[fromStart + 1] = 0;
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

    /// @dev Reverts an inner mutation and verifies the outer mode and budget are restored.
    function assertAtomicRevert(
        uint256 slot,
        uint256 value,
        IStorageCredits.Mode mode,
        uint64 budget,
        bool useBudget
    )
        external
    {
        _assertDefaultTransientState();
        _setMode(IStorageCredits.Mode.Preserve, 0, false);

        (bool success, bytes memory result) = address(this)
            .call(abi.encodeCall(this.revertingMutation, (slot, value, mode, budget, useBudget)));
        _assertRevert(success, result, abi.encodeWithSelector(ForcedRevert.selector));
        _assertTransientState(IStorageCredits.Mode.Preserve, 0);
    }

    /// @dev Applies mode and storage changes that must unwind with this call frame.
    function revertingMutation(
        uint256 slot,
        uint256 value,
        IStorageCredits.Mode mode,
        uint64 budget,
        bool useBudget
    )
        external
    {
        require(msg.sender == address(this), "only self");
        _setMode(mode, budget, useBudget);
        values[slot] = value;
        revert ForcedRevert();
    }

    function _assertRevert(bool success, bytes memory actual, bytes memory expected) internal pure {
        require(!success, "expected Storage Credits call to revert");
        require(keccak256(actual) == keccak256(expected), "unexpected Storage Credits revert");
    }

    /// @dev Selects bounded or unbounded mode and verifies the resulting transient state.
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

        IStorageCredits.Mode expectedMode = useBudget ? IStorageCredits.Mode.Direct : mode;
        uint64 expectedBudget =
            useBudget ? budget : mode == IStorageCredits.Mode.Direct ? type(uint64).max : 0;
        _assertTransientState(expectedMode, expectedBudget);
    }

    /// @dev Checks the per-account mode and budget at the start of a production-path transaction.
    function _assertDefaultTransientState() internal view {
        _assertTransientState(IStorageCredits.Mode.Refund, 0);
    }

    /// @dev Asserts transient mode and budget for this storage-owning account.
    function _assertTransientState(
        IStorageCredits.Mode expectedMode,
        uint64 expectedBudget
    )
        internal
        view
    {
        require(CREDITS.modeOf(address(this)) == expectedMode, "unexpected transient mode");
        require(CREDITS.budgetOf(address(this)) == expectedBudget, "unexpected transient budget");
    }

}

/// @title TIP-1060 Storage Credits Invariant Tests
/// @notice Stateful model-based tests for storage-credit conservation and account locality
contract StorageCreditsInvariantTest is InvariantBase {

    using TxBuilder for *;

    uint256 internal constant NUM_SLOTS = 16;
    uint64 internal constant TX_GAS_LIMIT = 1_500_000;

    IStorageCredits internal constant CREDITS = IStorageCredits(PC.STORAGE_CREDITS_ADDRESS);

    // General transitions and revert atomicity.
    StorageCreditsHarness internal harness;
    // Nested-call account locality.
    StorageCreditsHarness internal peerHarness;
    // Bounded Direct budget consumption.
    StorageCreditsHarness internal budgetHarness;
    // Deferred Refund settlement.
    StorageCreditsHarness internal refundHarness;

    mapping(address owner => mapping(uint256 slot => uint256 value)) internal ghost_values;
    mapping(address owner => uint64 credits) internal ghost_credits;
    // Start of the currently occupied pair in refundHarness.
    uint256 internal refund_activeStart;

    function setUp() public override {
        super.setUp();

        harness = new StorageCreditsHarness(0);
        peerHarness = new StorageCreditsHarness(0);
        budgetHarness = new StorageCreditsHarness(1);
        refundHarness = new StorageCreditsHarness(2);

        ghost_values[address(budgetHarness)][0] = 1;
        ghost_values[address(refundHarness)][0] = 1;
        ghost_values[address(refundHarness)][1] = 2;

        targetContract(address(this));
        bytes4[] memory selectors = new bytes4[](6);
        selectors[0] = this.handler_mutate.selector;
        selectors[1] = this.handler_nestedMutation.selector;
        selectors[2] = this.handler_recreate.selector;
        selectors[3] = this.handler_directBudget.selector;
        selectors[4] = this.handler_refundCreateThenClear.selector;
        selectors[5] = this.handler_revertingMutation.selector;
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));
    }

    /// @notice Asserts exact revert data for every reachable precompile error/halt path.
    function test_knownExpectedCustomErrors() public {
        harness.assertKnownReverts();
    }

    /*//////////////////////////////////////////////////////////////
                                HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Fuzzes one top-level transition across every storage-credit mode.
    function handler_mutate(
        uint256 actorSeed,
        uint256 slotSeed,
        uint256 valueSeed,
        uint256 modeSeed,
        uint256 budgetSeed
    )
        external
    {
        _handlerMutation(harness, false, actorSeed, slotSeed, valueSeed, modeSeed, budgetSeed);
    }

    /// @dev Fuzzes the same transition through an intermediate caller to test account locality.
    function handler_nestedMutation(
        uint256 actorSeed,
        uint256 slotSeed,
        uint256 valueSeed,
        uint256 modeSeed,
        uint256 budgetSeed
    )
        external
    {
        _handlerMutation(peerHarness, true, actorSeed, slotSeed, valueSeed, modeSeed, budgetSeed);
    }

    /// @dev Executes a direct or nested mutation and advances the selected owner's ghost model.
    function _handlerMutation(
        StorageCreditsHarness owner,
        bool nested,
        uint256 actorSeed,
        uint256 slotSeed,
        uint256 valueSeed,
        uint256 modeSeed,
        uint256 budgetSeed
    )
        internal
    {
        address ownerAddress = address(owner);
        uint256 slot = slotSeed % NUM_SLOTS;
        uint256 oldValue = ghost_values[ownerAddress][slot];
        uint256 newValue = valueSeed % 4 == 0 ? 0 : bound(valueSeed, 1, type(uint128).max);
        IStorageCredits.Mode mode = IStorageCredits.Mode(modeSeed % 3);
        bool useBudget = mode == IStorageCredits.Mode.Direct && budgetSeed % 2 == 0;
        uint64 budget = uint64(budgetSeed % 3);

        uint64 expectedCredits = _expectedAfterTransition(
            ghost_credits[ownerAddress],
            oldValue,
            newValue,
            mode,
            useBudget ? budget : type(uint64).max
        );

        bytes memory data = nested
            ? abi.encodeCall(
                StorageCreditsHarness.mutatePeer, (owner, slot, newValue, mode, budget, useBudget)
            )
            : abi.encodeCall(
                StorageCreditsHarness.mutate, (slot, newValue, mode, budget, useBudget)
            );
        _execute(actorSeed, address(harness), data);

        ghost_values[ownerAddress][slot] = newValue;
        ghost_credits[ownerAddress] = expectedCredits;
        _assertModels();
    }

    /// @dev Fuzzes dirty x->0->y recreation accounting within one transaction.
    function handler_recreate(
        uint256 actorSeed,
        uint256 slotSeed,
        uint256 valueSeed,
        uint256 modeSeed,
        uint256 budgetSeed
    )
        external
    {
        address owner = address(harness);
        uint256 slot = slotSeed % NUM_SLOTS;
        if (ghost_values[owner][slot] == 0) return;

        uint256 newValue = bound(valueSeed, 1, type(uint128).max);
        IStorageCredits.Mode mode = IStorageCredits.Mode(modeSeed % 3);
        bool useBudget = mode == IStorageCredits.Mode.Direct && budgetSeed % 2 == 0;
        uint64 budget = uint64(budgetSeed % 3);

        // The clear first mints one credit. The following creation may consume it.
        uint64 expectedCredits = ghost_credits[owner] + 1;
        expectedCredits = _expectedAfterTransition(
            expectedCredits, 0, newValue, mode, useBudget ? budget : type(uint64).max
        );

        bytes memory data = abi.encodeCall(
            StorageCreditsHarness.recreate, (slot, newValue, mode, budget, useBudget)
        );
        _execute(actorSeed, owner, data);

        ghost_values[owner][slot] = newValue;
        ghost_credits[owner] = expectedCredits;
        _assertModels();
    }

    /// @dev Fuzzes two Direct consumptions to expose budget decrement and exhaustion.
    function handler_directBudget(
        uint256 actorSeed,
        uint256 valueSeed,
        uint256 budgetSeed
    )
        external
    {
        address owner = address(budgetHarness);
        uint256 firstValue = bound(valueSeed, 1, type(uint128).max);
        uint256 secondValue = firstValue == type(uint128).max ? 1 : firstValue + 1;
        bool useBudget = budgetSeed % 2 == 0;
        uint64 budget = uint64((budgetSeed / 2) % 4);
        uint64 coveredCreations = useBudget && budget < 2 ? budget : 2;

        bytes memory data = abi.encodeCall(
            StorageCreditsHarness.exerciseDirectBudget, (firstValue, secondValue, budget, useBudget)
        );
        _execute(actorSeed, owner, data);

        ghost_values[owner][0] = secondValue;
        ghost_values[owner][1] = 0;
        ghost_credits[owner] = ghost_credits[owner] + 2 - coveredCreations;
        _assertModels();
    }

    /// @dev Creates before clearing so Refund settlement must use credits minted later.
    function handler_refundCreateThenClear(uint256 actorSeed, uint256 valueSeed) external {
        address owner = address(refundHarness);
        uint256 fromStart = refund_activeStart;
        uint256 toStart = fromStart == 0 ? 2 : 0;
        uint256 firstValue = bound(valueSeed, 1, type(uint128).max);
        uint256 secondValue = firstValue == type(uint128).max ? 1 : firstValue + 1;

        bytes memory data = abi.encodeCall(
            StorageCreditsHarness.createThenClear, (fromStart, toStart, firstValue, secondValue)
        );
        _execute(actorSeed, owner, data);

        ghost_values[owner][toStart] = firstValue;
        ghost_values[owner][toStart + 1] = secondValue;
        ghost_values[owner][fromStart] = 0;
        ghost_values[owner][fromStart + 1] = 0;
        refund_activeStart = toStart;
        _assertModels();
    }

    /// @dev Forces a zero-boundary mutation in a reverted child frame and checks full rollback.
    function handler_revertingMutation(
        uint256 actorSeed,
        uint256 slotSeed,
        uint256 valueSeed,
        uint256 modeSeed,
        uint256 budgetSeed
    )
        external
    {
        uint256 slot = slotSeed % NUM_SLOTS;
        uint256 newValue =
            ghost_values[address(harness)][slot] == 0 ? bound(valueSeed, 1, type(uint128).max) : 0;
        bool useBudget = budgetSeed % 2 == 0;
        IStorageCredits.Mode mode =
            modeSeed % 2 == 0 ? IStorageCredits.Mode.Refund : IStorageCredits.Mode.Direct;
        uint64 budget = uint64((budgetSeed / 2) % 3 + 1);

        bytes memory data = abi.encodeCall(
            StorageCreditsHarness.assertAtomicRevert, (slot, newValue, mode, budget, useBudget)
        );
        _execute(actorSeed, address(harness), data);

        // The storage transition, credit update, and transient mode change must all unwind.
        _assertModels();
    }

    /*//////////////////////////////////////////////////////////////
                               INVARIANT
    //////////////////////////////////////////////////////////////*/

    /// @notice Runs all TIP-1060 invariant checks from one Foundry invariant entrypoint.
    function invariant_storageCreditsGlobal() public view {
        _assertModels();
        _invariantAccountLocality();
    }

    /// @dev Checks every independently exercised storage owner against its ghost state.
    function _assertModels() internal view {
        _assertModel(harness, NUM_SLOTS);
        _assertModel(peerHarness, NUM_SLOTS);
        _assertModel(budgetHarness, 2);
        _assertModel(refundHarness, 4);
    }

    /// @dev Compares one owner's persistent credit balance and storage with its ghost model.
    function _assertModel(StorageCreditsHarness owner, uint256 slots) internal view {
        address ownerAddress = address(owner);
        assertEq(
            CREDITS.balanceOf(ownerAddress),
            ghost_credits[ownerAddress],
            "TEMPO-SC1: persistent credit balance diverged from zero-crossing model"
        );

        for (uint256 slot = 0; slot < slots; slot++) {
            assertEq(
                owner.values(slot),
                ghost_values[ownerAddress][slot],
                "TEMPO-SC2: committed storage diverged from ghost state"
            );
        }
    }

    /// @dev Ensures transaction senders never receive credits for contract-owned storage.
    function _invariantAccountLocality() internal view {
        for (uint256 i = 0; i < actors.length; i++) {
            assertEq(
                CREDITS.balanceOf(actors[i]),
                0,
                "TEMPO-SC4: credits escaped to the transaction sender"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Models one present-to-new zero-boundary transition independently of the implementation.
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

    /// @dev Executes a signed actor call through the production transaction executor.
    function _execute(uint256 actorSeed, address target, bytes memory data) internal {
        uint256 actorIndex = actorSeed % actors.length;
        address actor = actors[actorIndex];
        uint64 nonce = uint64(vm.getNonce(actor));
        bytes memory signedTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, target, data, nonce, TX_GAS_LIMIT, actorKeys[actorIndex]
        );

        vm.coinbase(validator);
        bool succeeded;
        try vmExec.executeTransaction(signedTx) {
            succeeded = true;
        } catch { }

        assertTrue(succeeded, "TIP-1060 transaction unexpectedly reverted");
    }

}
