// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Test } from "forge-std/Test.sol";

import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { InvariantBase } from "../helpers/InvariantBase.sol";
import { Counter, InitcodeHelper, SimpleStorage } from "../helpers/TestContracts.sol";
import { TxBuilder } from "../helpers/TxBuilder.sol";

import { VmExecuteTransaction, VmRlp } from "tempo-std/StdVm.sol";
import { LegacyTransaction, LegacyTransactionLib } from "tempo-std/tx/LegacyTransactionLib.sol";

/// @title TIP-1000 Gas Pricing Invariant Tests
/// @notice Fuzz-based invariant tests for Tempo's state creation gas costs
/// @dev Tests gas pricing invariants at the EVM opcode level using vmExec.executeTransaction()
///
/// TIP-1000 specifies:
/// - SSTORE to new slot: 250,000 gas (TEMPO-GAS1)
/// - CREATE base cost: 500,000 gas (TEMPO-GAS5)
/// - Code deposit: 1,000 gas per byte (TEMPO-GAS5)
/// - Account creation: 250,000 gas (part of TEMPO-GAS5)
/// - Multiple new slots: 250,000 gas each (TEMPO-GAS8)
///
/// Protocol-level invariants (tx gas cap, intrinsic gas) are tested in Rust.
contract GasPricingInvariantTest is InvariantBase {

    using TxBuilder for *;
    using LegacyTransactionLib for LegacyTransaction;

    /*//////////////////////////////////////////////////////////////
                            TIP-1000 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev SSTORE to new (zero) slot costs 250,000 gas
    uint256 internal constant SSTORE_SET_GAS = 250_000;

    /// @dev CREATE base cost (excludes code deposit and account creation)
    uint256 internal constant CREATE_BASE_GAS = 500_000;

    /// @dev Account creation cost (nonce 0 -> 1)
    uint256 internal constant ACCOUNT_CREATION_GAS = 250_000;

    /// @dev Code deposit cost per byte
    uint256 internal constant CODE_DEPOSIT_PER_BYTE = 1000;

    /// @dev Base transaction cost
    uint256 internal constant BASE_TX_GAS = 21_000;

    /// @dev Call overhead (cold account + call stipend)
    uint256 internal constant CALL_OVERHEAD = 15_000;

    /// @dev Gas tolerance for measurements (accounts for call overhead variance)
    uint256 internal constant GAS_TOLERANCE = 50_000;

    /*//////////////////////////////////////////////////////////////
                            TEST STATE
    //////////////////////////////////////////////////////////////*/

    /// @dev Storage contract for testing SSTORE costs
    GasTestStorage internal storageContract;

    /// @dev Unique slot counter for generating fresh slots
    uint256 internal slotCounter;

    /*//////////////////////////////////////////////////////////////
                            GHOST VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @dev TEMPO-GAS1: SSTORE new slot tracking
    uint256 public ghost_sstoreTests;
    uint256 public ghost_sstoreInsufficientGasFailed;
    uint256 public ghost_sstoreSufficientGasSucceeded;
    uint256 public ghost_sstoreViolations; // Succeeded with insufficient gas

    /// @dev TEMPO-GAS5: CREATE tracking
    uint256 public ghost_createTests;
    uint256 public ghost_createInsufficientGasFailed;
    uint256 public ghost_createSufficientGasSucceeded;
    uint256 public ghost_createViolations; // Succeeded with insufficient gas

    /// @dev TEMPO-GAS8: Multi-slot tracking
    uint256 public ghost_multiSlotTests;
    uint256 public ghost_multiSlotInsufficientGasFailed;
    uint256 public ghost_multiSlotSufficientGasSucceeded;
    uint256 public ghost_multiSlotViolations; // All slots written with insufficient gas

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        // Deploy storage contract for SSTORE tests
        storageContract = new GasTestStorage();

        // Register handlers
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = this.handler_sstoreNewSlot.selector;
        selectors[1] = this.handler_createContract.selector;
        selectors[2] = this.handler_multipleNewSlots.selector;
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));
    }

    /*//////////////////////////////////////////////////////////////
                        INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks
    function invariant_globalInvariants() public view {
        _invariantSstoreNewSlotCost();
        _invariantCreateCost();
        _invariantMultiSlotScaling();
    }

    /// @notice TEMPO-GAS1: SSTORE to new slot must cost ~250k gas
    /// @dev Violations occur if tx succeeds with gas clearly below threshold
    function _invariantSstoreNewSlotCost() internal view {
        assertEq(
            ghost_sstoreViolations,
            0,
            "TEMPO-GAS1: SSTORE to new slot succeeded with insufficient gas"
        );
    }

    /// @notice TEMPO-GAS5: CREATE must cost 500k base + code + account creation
    /// @dev Violations occur if tx succeeds with gas clearly below threshold
    function _invariantCreateCost() internal view {
        assertEq(ghost_createViolations, 0, "TEMPO-GAS5: CREATE succeeded with insufficient gas");
    }

    /// @notice TEMPO-GAS8: Multiple new slots must cost 250k each
    /// @dev Violations occur if all N slots written with gas for only 1
    function _invariantMultiSlotScaling() internal view {
        assertEq(
            ghost_multiSlotViolations,
            0,
            "TEMPO-GAS8: Multi-slot write succeeded with insufficient gas"
        );
    }

    /*//////////////////////////////////////////////////////////////
                            HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Test SSTORE to new slot gas requirement (TEMPO-GAS1)
    /// @param actorSeed Seed for selecting actor
    /// @param slotSeed Seed for generating unique slot
    function handler_sstoreNewSlot(uint256 actorSeed, uint256 slotSeed) external {
        // Skip when not on Tempo (vmExec.executeTransaction not available)
        if (!isTempo) return;

        ghost_sstoreTests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        // Generate unique slot
        bytes32 slot = keccak256(abi.encode(slotSeed, slotCounter++, block.timestamp));
        bytes memory callData = abi.encodeCall(GasTestStorage.storeValue, (slot, 1));

        uint64 nonce = uint64(vm.getNonce(sender));

        // Test 1: Insufficient gas (100k - way below 250k SSTORE cost)
        uint64 lowGas = 100_000;
        bytes memory lowGasTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(storageContract), callData, nonce, lowGas, privateKey
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(lowGasTx) {
            // Succeeded with low gas - check if slot was written
            if (storageContract.getValue(slot) != 0) {
                ghost_sstoreViolations++;
            }
            ghost_protocolNonce[sender]++;
        } catch {
            ghost_sstoreInsufficientGasFailed++;
        }

        // Test 2: Sufficient gas (350k - above 250k + overhead)
        nonce = uint64(vm.getNonce(sender));
        bytes32 slot2 = keccak256(abi.encode(slotSeed, slotCounter++, block.timestamp, "high"));
        callData = abi.encodeCall(GasTestStorage.storeValue, (slot2, 1));

        uint64 highGas = uint64(BASE_TX_GAS + CALL_OVERHEAD + SSTORE_SET_GAS + GAS_TOLERANCE);
        bytes memory highGasTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(storageContract), callData, nonce, highGas, privateKey
        );

        try vmExec.executeTransaction(highGasTx) {
            if (storageContract.getValue(slot2) != 0) {
                ghost_sstoreSufficientGasSucceeded++;
            }
            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
        } catch {
            // Unexpected failure with sufficient gas
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Test CREATE gas requirement (TEMPO-GAS5)
    /// @param actorSeed Seed for selecting actor
    function handler_createContract(uint256 actorSeed) external {
        // Skip when not on Tempo (vmExec.executeTransaction not available)
        if (!isTempo) return;

        ghost_createTests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        bytes memory initcode = InitcodeHelper.counterInitcode();

        // Expected gas: base tx + CREATE base + code deposit + account creation
        uint256 expectedGas = BASE_TX_GAS + CREATE_BASE_GAS
            + (initcode.length * CODE_DEPOSIT_PER_BYTE) + ACCOUNT_CREATION_GAS;

        uint64 nonce = uint64(vm.getNonce(sender));

        // Test 1: Insufficient gas (200k - way below ~800k expected)
        uint64 lowGas = 200_000;
        bytes memory lowGasTx =
            TxBuilder.buildLegacyCreateWithGas(vmRlp, vm, initcode, nonce, lowGas, privateKey);

        vm.coinbase(validator);
        address expectedAddr = TxBuilder.computeCreateAddress(sender, nonce);

        try vmExec.executeTransaction(lowGasTx) {
            // Check if contract was deployed
            if (expectedAddr.code.length > 0) {
                ghost_createViolations++;
            }
            ghost_protocolNonce[sender]++;
        } catch {
            ghost_createInsufficientGasFailed++;
        }

        // Test 2: Sufficient gas
        nonce = uint64(vm.getNonce(sender));
        uint64 highGas = uint64(expectedGas + GAS_TOLERANCE);
        bytes memory highGasTx =
            TxBuilder.buildLegacyCreateWithGas(vmRlp, vm, initcode, nonce, highGas, privateKey);

        expectedAddr = TxBuilder.computeCreateAddress(sender, nonce);

        try vmExec.executeTransaction(highGasTx) {
            if (expectedAddr.code.length > 0) {
                ghost_createSufficientGasSucceeded++;
            }
            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Test multiple SSTORE scaling (TEMPO-GAS8)
    /// @param actorSeed Seed for selecting actor
    /// @param numSlots Number of slots to write (2-5)
    function handler_multipleNewSlots(uint256 actorSeed, uint256 numSlots) external {
        // Skip when not on Tempo (vmExec.executeTransaction not available)
        if (!isTempo) return;

        numSlots = bound(numSlots, 2, 5);
        ghost_multiSlotTests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        // Generate unique slots
        bytes32[] memory slots = new bytes32[](numSlots);
        for (uint256 i = 0; i < numSlots; i++) {
            slots[i] = keccak256(abi.encode(actorSeed, slotCounter++, i));
        }

        bytes memory callData = abi.encodeCall(GasTestStorage.storeMultiple, (slots));
        uint64 nonce = uint64(vm.getNonce(sender));

        // Test 1: Gas sufficient for ~1 slot only (should fail for N>1)
        uint64 lowGas = uint64(BASE_TX_GAS + CALL_OVERHEAD + SSTORE_SET_GAS + GAS_TOLERANCE);
        bytes memory lowGasTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(storageContract), callData, nonce, lowGas, privateKey
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(lowGasTx) {
            // Count how many slots were written
            uint256 written = 0;
            for (uint256 i = 0; i < slots.length; i++) {
                if (storageContract.getValue(slots[i]) != 0) {
                    written++;
                }
            }

            // Violation: all slots written with gas for only 1
            if (written == numSlots) {
                ghost_multiSlotViolations++;
            } else {
                // Partial write is expected (reverted mid-execution)
                ghost_multiSlotInsufficientGasFailed++;
            }
            ghost_protocolNonce[sender]++;
        } catch {
            ghost_multiSlotInsufficientGasFailed++;
        }

        // Test 2: Sufficient gas for all slots
        nonce = uint64(vm.getNonce(sender));

        // Fresh slots for second test
        bytes32[] memory slots2 = new bytes32[](numSlots);
        for (uint256 i = 0; i < numSlots; i++) {
            slots2[i] = keccak256(abi.encode(actorSeed, slotCounter++, i, "high"));
        }
        callData = abi.encodeCall(GasTestStorage.storeMultiple, (slots2));

        uint64 highGas =
            uint64(BASE_TX_GAS + CALL_OVERHEAD + (SSTORE_SET_GAS * numSlots) + GAS_TOLERANCE);
        bytes memory highGasTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(storageContract), callData, nonce, highGas, privateKey
        );

        try vmExec.executeTransaction(highGasTx) {
            uint256 written = 0;
            for (uint256 i = 0; i < slots2.length; i++) {
                if (storageContract.getValue(slots2[i]) != 0) {
                    written++;
                }
            }
            if (written == numSlots) {
                ghost_multiSlotSufficientGasSucceeded++;
            }
            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
        } catch {
            ghost_totalTxReverted++;
        }
    }

}

/*//////////////////////////////////////////////////////////////
                        HELPER CONTRACTS
//////////////////////////////////////////////////////////////*/

/// @title GasTestStorage - Contract for testing SSTORE gas costs
contract GasTestStorage {

    mapping(bytes32 => uint256) private _storage;

    function storeValue(bytes32 slot, uint256 value) external {
        _storage[slot] = value;
    }

    function storeMultiple(bytes32[] calldata slots) external {
        for (uint256 i = 0; i < slots.length; i++) {
            _storage[slots[i]] = 1;
        }
    }

    function getValue(bytes32 slot) external view returns (uint256) {
        return _storage[slot];
    }

}
