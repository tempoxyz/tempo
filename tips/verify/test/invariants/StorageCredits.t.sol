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

        values[slot] = 0;
        values[slot] = value;
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
    }

}

/// @title TIP-1060 Storage Credits Invariant Tests
/// @notice Stateful model-based tests for storage-credit conservation and account locality
/// forge-config: default.invariant.runs = 10
/// forge-config: default.invariant.depth = 100
contract StorageCreditsInvariantTest is InvariantBase {

    using TxBuilder for *;

    uint256 internal constant NUM_SLOTS = 16;
    uint64 internal constant TX_GAS_LIMIT = 1_500_000;
    string internal constant BRANCH_LOG = "storage-credits-branches.log";

    bytes32 internal constant BRANCH_CREATE_REFUND_EMPTY = keccak256("create/refund/no-credit");
    bytes32 internal constant BRANCH_CREATE_REFUND_CONSUME = keccak256("create/refund/consume");
    bytes32 internal constant BRANCH_CREATE_PRESERVE = keccak256("create/preserve");
    bytes32 internal constant BRANCH_CREATE_DIRECT_EMPTY = keccak256("create/direct/no-credit");
    bytes32 internal constant BRANCH_CREATE_DIRECT_ZERO = keccak256("create/direct/zero-budget");
    bytes32 internal constant BRANCH_CREATE_DIRECT_BOUNDED =
        keccak256("create/direct/consume-bounded");
    bytes32 internal constant BRANCH_CREATE_DIRECT_UNLIMITED =
        keccak256("create/direct/consume-unlimited");
    bytes32 internal constant BRANCH_CLEAR = keccak256("transition/clear");
    bytes32 internal constant BRANCH_NON_BOUNDARY = keccak256("transition/non-boundary");
    bytes32 internal constant BRANCH_RECREATE_REFUND = keccak256("recreate/refund");
    bytes32 internal constant BRANCH_RECREATE_PRESERVE = keccak256("recreate/preserve");
    bytes32 internal constant BRANCH_RECREATE_DIRECT_ZERO =
        keccak256("recreate/direct/zero-budget");
    bytes32 internal constant BRANCH_RECREATE_DIRECT_CONSUME = keccak256("recreate/direct/consume");
    bytes32 internal constant BRANCH_REVERT_ATOMICITY = keccak256("revert/atomicity");
    bytes32 internal constant BRANCH_KNOWN_ERRORS = keccak256("revert/known-errors");

    IStorageCredits internal constant CREDITS = IStorageCredits(PC.STORAGE_CREDITS_ADDRESS);

    StorageCreditsHarness internal harness;
    StorageCreditsHarness internal untouchedHarness;

    mapping(uint256 slot => uint256 value) internal ghost_values;
    uint64 internal ghost_credits;
    mapping(bytes32 branch => uint256 hits) internal branch_hits;
    bool internal branch_sweep_complete;

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

        vm.writeFile(BRANCH_LOG, "");
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
        _ensureBranchSweep(actorSeed);

        uint256 slot = slotSeed % NUM_SLOTS;
        uint256 oldValue = ghost_values[slot];
        uint256 newValue = valueSeed % 4 == 0 ? 0 : bound(valueSeed, 1, type(uint128).max);
        IStorageCredits.Mode mode = IStorageCredits.Mode(modeSeed % 3);
        bool useBudget = mode == IStorageCredits.Mode.Direct && budgetSeed % 2 == 0;
        uint64 budget = uint64(budgetSeed % 3);

        uint64 creditsBefore = ghost_credits;
        uint64 expectedCredits = _expectedAfterTransition(
            ghost_credits, oldValue, newValue, mode, useBudget ? budget : type(uint64).max
        );

        bytes memory data = abi.encodeCall(
            StorageCreditsHarness.mutate, (slot, newValue, mode, budget, useBudget, false)
        );
        _execute(actorSeed, data, true);

        ghost_values[slot] = newValue;
        ghost_credits = expectedCredits;
        _recordTransition(oldValue, newValue, mode, useBudget, budget, creditsBefore);
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
        _ensureBranchSweep(actorSeed);

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
        _hit(
            mode == IStorageCredits.Mode.Refund
                ? BRANCH_RECREATE_REFUND
                : mode == IStorageCredits.Mode.Preserve
                    ? BRANCH_RECREATE_PRESERVE
                    : (useBudget && budget == 0)
                        ? BRANCH_RECREATE_DIRECT_ZERO
                        : BRANCH_RECREATE_DIRECT_CONSUME,
            mode == IStorageCredits.Mode.Refund
                ? "recreate/refund"
                : mode == IStorageCredits.Mode.Preserve
                    ? "recreate/preserve"
                    : (useBudget && budget == 0)
                        ? "recreate/direct/zero-budget"
                        : "recreate/direct/consume"
        );
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
        _ensureBranchSweep(actorSeed);

        uint256 slot = slotSeed % NUM_SLOTS;
        uint256 newValue = valueSeed % 2 == 0 ? 0 : bound(valueSeed, 1, type(uint128).max);
        IStorageCredits.Mode mode = IStorageCredits.Mode(modeSeed % 3);

        bytes memory data = abi.encodeCall(
            StorageCreditsHarness.mutate, (slot, newValue, mode, uint64(1), false, true)
        );
        bytes memory reason = _execute(actorSeed, data, false);
        assertEq(
            bytes4(reason), StorageCreditsHarness.ForcedRevert.selector, "wrong revert selector"
        );
        _hit(BRANCH_REVERT_ATOMICITY, "revert/atomicity");

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

    function afterInvariant() public view {
        _assertHit(BRANCH_CREATE_REFUND_EMPTY, "create/refund/no-credit");
        _assertHit(BRANCH_CREATE_REFUND_CONSUME, "create/refund/consume");
        _assertHit(BRANCH_CREATE_PRESERVE, "create/preserve");
        _assertHit(BRANCH_CREATE_DIRECT_EMPTY, "create/direct/no-credit");
        _assertHit(BRANCH_CREATE_DIRECT_ZERO, "create/direct/zero-budget");
        _assertHit(BRANCH_CREATE_DIRECT_BOUNDED, "create/direct/consume-bounded");
        _assertHit(BRANCH_CREATE_DIRECT_UNLIMITED, "create/direct/consume-unlimited");
        _assertHit(BRANCH_CLEAR, "transition/clear");
        _assertHit(BRANCH_NON_BOUNDARY, "transition/non-boundary");
        _assertHit(BRANCH_RECREATE_REFUND, "recreate/refund");
        _assertHit(BRANCH_RECREATE_PRESERVE, "recreate/preserve");
        _assertHit(BRANCH_RECREATE_DIRECT_ZERO, "recreate/direct/zero-budget");
        _assertHit(BRANCH_RECREATE_DIRECT_CONSUME, "recreate/direct/consume");
        _assertHit(BRANCH_REVERT_ATOMICITY, "revert/atomicity");
        _assertHit(BRANCH_KNOWN_ERRORS, "revert/known-errors");
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

    function _ensureBranchSweep(uint256 actorSeed) internal {
        if (branch_sweep_complete) return;
        branch_sweep_complete = true;

        _sweepMutation(actorSeed, 0, 1, IStorageCredits.Mode.Preserve, 0, false);
        _sweepMutation(actorSeed, 0, 2, IStorageCredits.Mode.Preserve, 0, false);
        _sweepMutation(actorSeed, 1, 1, IStorageCredits.Mode.Direct, 1, true);
        _sweepMutation(actorSeed, 2, 1, IStorageCredits.Mode.Direct, 0, false);
        _sweepMutation(actorSeed, 3, 1, IStorageCredits.Mode.Refund, 0, false);

        _sweepMutation(actorSeed, 0, 0, IStorageCredits.Mode.Preserve, 0, false);
        _sweepMutation(actorSeed, 4, 1, IStorageCredits.Mode.Refund, 0, false);
        _sweepMutation(actorSeed, 1, 0, IStorageCredits.Mode.Preserve, 0, false);
        _sweepMutation(actorSeed, 5, 1, IStorageCredits.Mode.Preserve, 0, false);
        _sweepMutation(actorSeed, 5, 0, IStorageCredits.Mode.Preserve, 0, false);
        _sweepMutation(actorSeed, 6, 1, IStorageCredits.Mode.Direct, 0, true);
        _sweepMutation(actorSeed, 6, 0, IStorageCredits.Mode.Preserve, 0, false);
        _sweepMutation(actorSeed, 7, 1, IStorageCredits.Mode.Direct, 1, true);
        _sweepMutation(actorSeed, 7, 0, IStorageCredits.Mode.Preserve, 0, false);
        _sweepMutation(actorSeed, 8, 1, IStorageCredits.Mode.Direct, 0, false);

        _sweepRecreate(actorSeed, 8, 2, IStorageCredits.Mode.Refund, 0, false);
        _sweepRecreate(actorSeed, 8, 3, IStorageCredits.Mode.Preserve, 0, false);
        _sweepRecreate(actorSeed, 8, 4, IStorageCredits.Mode.Direct, 0, true);
        _sweepRecreate(actorSeed, 8, 5, IStorageCredits.Mode.Direct, 1, true);

        bytes memory knownErrorsData = abi.encodeCall(StorageCreditsHarness.assertKnownReverts, ());
        _execute(actorSeed, knownErrorsData, true);
        _hit(BRANCH_KNOWN_ERRORS, "revert/known-errors");

        bytes memory revertData = abi.encodeCall(
            StorageCreditsHarness.mutate,
            (uint256(9), uint256(1), IStorageCredits.Mode.Direct, uint64(1), true, true)
        );
        bytes memory reason = _execute(actorSeed, revertData, false);
        assertEq(
            bytes4(reason), StorageCreditsHarness.ForcedRevert.selector, "wrong revert selector"
        );
        _hit(BRANCH_REVERT_ATOMICITY, "revert/atomicity");
    }

    function _sweepMutation(
        uint256 actorSeed,
        uint256 slot,
        uint256 newValue,
        IStorageCredits.Mode mode,
        uint64 budget,
        bool useBudget
    )
        internal
    {
        uint256 oldValue = ghost_values[slot];
        uint64 creditsBefore = ghost_credits;
        uint64 expectedCredits = _expectedAfterTransition(
            creditsBefore, oldValue, newValue, mode, useBudget ? budget : type(uint64).max
        );
        bytes memory data = abi.encodeCall(
            StorageCreditsHarness.mutate, (slot, newValue, mode, budget, useBudget, false)
        );
        _execute(actorSeed, data, true);
        ghost_values[slot] = newValue;
        ghost_credits = expectedCredits;
        _recordTransition(oldValue, newValue, mode, useBudget, budget, creditsBefore);
        _assertModel();
    }

    function _sweepRecreate(
        uint256 actorSeed,
        uint256 slot,
        uint256 newValue,
        IStorageCredits.Mode mode,
        uint64 budget,
        bool useBudget
    )
        internal
    {
        uint64 expectedCredits = _expectedAfterTransition(
            ghost_credits + 1, 0, newValue, mode, useBudget ? budget : type(uint64).max
        );
        bytes memory data = abi.encodeCall(
            StorageCreditsHarness.recreate, (slot, newValue, mode, budget, useBudget)
        );
        _execute(actorSeed, data, true);
        ghost_values[slot] = newValue;
        ghost_credits = expectedCredits;

        if (mode == IStorageCredits.Mode.Refund) {
            _hit(BRANCH_RECREATE_REFUND, "recreate/refund");
        } else if (mode == IStorageCredits.Mode.Preserve) {
            _hit(BRANCH_RECREATE_PRESERVE, "recreate/preserve");
        } else if (useBudget && budget == 0) {
            _hit(BRANCH_RECREATE_DIRECT_ZERO, "recreate/direct/zero-budget");
        } else {
            _hit(BRANCH_RECREATE_DIRECT_CONSUME, "recreate/direct/consume");
        }
        _assertModel();
    }

    function _recordTransition(
        uint256 oldValue,
        uint256 newValue,
        IStorageCredits.Mode mode,
        bool useBudget,
        uint64 budget,
        uint64 creditsBefore
    )
        internal
    {
        if (oldValue != 0 && newValue == 0) {
            _hit(BRANCH_CLEAR, "transition/clear");
        } else if ((oldValue == 0) == (newValue == 0)) {
            _hit(BRANCH_NON_BOUNDARY, "transition/non-boundary");
        } else if (mode == IStorageCredits.Mode.Refund && creditsBefore == 0) {
            _hit(BRANCH_CREATE_REFUND_EMPTY, "create/refund/no-credit");
        } else if (mode == IStorageCredits.Mode.Refund) {
            _hit(BRANCH_CREATE_REFUND_CONSUME, "create/refund/consume");
        } else if (mode == IStorageCredits.Mode.Preserve) {
            _hit(BRANCH_CREATE_PRESERVE, "create/preserve");
        } else if (creditsBefore == 0) {
            _hit(BRANCH_CREATE_DIRECT_EMPTY, "create/direct/no-credit");
        } else if (useBudget && budget == 0) {
            _hit(BRANCH_CREATE_DIRECT_ZERO, "create/direct/zero-budget");
        } else if (useBudget) {
            _hit(BRANCH_CREATE_DIRECT_BOUNDED, "create/direct/consume-bounded");
        } else {
            _hit(BRANCH_CREATE_DIRECT_UNLIMITED, "create/direct/consume-unlimited");
        }
    }

    function _hit(bytes32 branch, string memory label) internal {
        branch_hits[branch]++;
        vm.writeLine(BRANCH_LOG, label);
    }

    function _assertHit(bytes32 branch, string memory label) internal view {
        assertGt(branch_hits[branch], 0, string.concat("unexercised branch: ", label));
    }

    function _execute(
        uint256 actorSeed,
        bytes memory data,
        bool expectSuccess
    )
        internal
        returns (bytes memory reason)
    {
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
        } catch (bytes memory revertData) {
            reason = revertData;
        }

        assertEq(succeeded, expectSuccess, "TIP-1060 transaction result differed from expectation");
    }

}
