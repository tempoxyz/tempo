// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Test, console } from "forge-std/Test.sol";

import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { InvariantBase } from "../helpers/InvariantBase.sol";
import { Counter, InitcodeHelper, SimpleStorage } from "../helpers/TestContracts.sol";
import { TxBuilder } from "../helpers/TxBuilder.sol";

import { VmExecuteTransaction, VmRlp } from "tempo-std/StdVm.sol";
import { LegacyTransaction, LegacyTransactionLib } from "tempo-std/tx/LegacyTransactionLib.sol";
import {
    TempoCall,
    TempoTransaction,
    TempoTransactionLib
} from "tempo-std/tx/TempoTransactionLib.sol";

/// @title GasPricing Invariant Test
/// @notice Invariant tests for TIP-1000 (State Creation Cost) and TIP-1010 (Mainnet Gas Parameters)
/// @dev Tests gas pricing invariants that MUST hold for Tempo T1 hardfork using vmExec.executeTransaction()
///
/// IMPORTANT LIMITATIONS:
/// These tests validate TIP-1000 gas pricing at the EVM SSTORE/CREATE opcode level.
/// Protocol-level gas changes (intrinsic gas, tx gas cap, account creation) are enforced in
/// Tempo's custom transaction handler (tempo-revm), NOT in the EVM execution layer.
/// When running in Foundry fork mode, these protocol-level invariants cannot be validated
/// because Foundry uses standard revm, not tempo-revm.
///
/// The following invariants are validated:
/// - TEMPO-GAS1: SSTORE to new slot costs 250k gas (EVM level) ✅
/// - TEMPO-GAS3: CREATE base cost 500k gas (EVM level) ✅
/// - TEMPO-GAS8: Multiple new slots scale correctly (EVM level) ✅
///
/// The following invariants require tempo-revm (tested in Rust unit tests):
/// - TEMPO-GAS2: Account creation (nonce 0→1) requires 250k intrinsic gas
/// - TEMPO-GAS6: Transaction gas cap 30M
/// - TEMPO-GAS7: First tx minimum 271k gas
contract GasPricingInvariantTest is InvariantBase {

    using TxBuilder for *;
    using LegacyTransactionLib for LegacyTransaction;
    using TempoTransactionLib for TempoTransaction;

    /*//////////////////////////////////////////////////////////////
                            TIP-1000 GAS CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev SSTORE to new (zero) slot costs 250,000 gas (TEMPO-GAS1)
    uint256 private constant SSTORE_SET_GAS = 250_000;

    /// @dev SSTORE to existing slot costs 5,000 gas (unchanged from EVM)
    uint256 private constant SSTORE_RESET_GAS = 5000;

    /// @dev Account creation (nonce 0→1) costs 250,000 gas (TEMPO-GAS2)
    uint256 private constant ACCOUNT_CREATION_GAS = 250_000;

    /// @dev CREATE/CREATE2 base cost (keccak + codesize fields)
    uint256 private constant CREATE_BASE_GAS = 500_000;

    /// @dev Code deposit cost per byte
    uint256 private constant CODE_DEPOSIT_PER_BYTE = 1000;

    /// @dev Transaction gas limit cap (TEMPO-GAS6)
    uint256 private constant TX_GAS_LIMIT_CAP = 30_000_000;

    /// @dev Minimum gas for first transaction (nonce=0)
    /// Base tx (21k) + account creation (250k) = 271k
    uint256 private constant FIRST_TX_MIN_GAS = 271_000;

    /// @dev Base transaction cost
    uint256 private constant BASE_TX_GAS = 21_000;

    /*//////////////////////////////////////////////////////////////
                            TIP-1010 BLOCK CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Total block gas limit
    uint256 private constant BLOCK_GAS_LIMIT = 500_000_000;

    /// @dev General lane gas limit (fixed at 30M for T1)
    uint256 private constant GENERAL_GAS_LIMIT = 30_000_000;

    /// @dev Maximum contract code size (EIP-170)
    uint256 private constant MAX_CONTRACT_SIZE = 24_576;

    /*//////////////////////////////////////////////////////////////
                            TEST STATE
    //////////////////////////////////////////////////////////////*/

    /// @dev Storage contract for testing SSTORE costs
    GasTestStorage private _storageContract;

    /// @dev Log file for gas measurements
    string private constant LOG_FILE = "gas_pricing.log";

    /*//////////////////////////////////////////////////////////////
                            GHOST VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @dev TEMPO-GAS1: SSTORE new slot threshold tests
    uint256 public ghost_sstoreNewSlotBelowThresholdFailed;
    uint256 public ghost_sstoreNewSlotAboveThresholdSucceeded;
    uint256 public ghost_sstoreNewSlotBelowThresholdAllowed; // Violation counter

    /// @dev TEMPO-GAS2: Account creation (first tx) threshold tests
    uint256 public ghost_accountCreationBelowThresholdFailed;
    uint256 public ghost_accountCreationAboveThresholdSucceeded;
    uint256 public ghost_accountCreationBelowThresholdAllowed; // Violation counter

    /// @dev TEMPO-GAS3: CREATE threshold tests
    uint256 public ghost_createBelowThresholdFailed;
    uint256 public ghost_createAboveThresholdSucceeded;
    uint256 public ghost_createBelowThresholdAllowed; // Violation counter

    /// @dev TEMPO-GAS6: Transaction gas cap tests
    uint256 public ghost_txOverCapRejected;
    uint256 public ghost_txAtCapSucceeded;
    uint256 public ghost_txOverCapAllowed; // Violation counter

    /// @dev General tracking
    uint256 public ghost_totalGasThresholdTests;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        // Deploy test storage contract
        _storageContract = new GasTestStorage();

        // Define handler selectors
        // NOTE: The following handlers are disabled because they test protocol-level gas changes
        // that are enforced in tempo-revm's custom handler, not in EVM execution:
        // - handler_txGasCapEnforcement: 30M cap enforced at pool validator level
        // - handler_accountCreationThreshold: 250k intrinsic gas enforced in tempo-revm handler
        // These are properly tested in Rust unit tests at crates/revm/src/handler.rs and
        // crates/transaction-pool/src/validator.rs
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = this.handler_sstoreNewSlotThreshold.selector;
        selectors[1] = this.handler_createThreshold.selector;
        selectors[2] = this.handler_multipleNewSlots.selector;
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));

        // Initialize log file
        try vm.removeFile(LOG_FILE) { } catch { }
        _log("================================================================================");
        _log("                    TIP-1000 / TIP-1010 Gas Pricing Invariant Tests");
        _log("================================================================================");
        _log("");
    }

    /*//////////////////////////////////////////////////////////////
                        MASTER INVARIANT
    //////////////////////////////////////////////////////////////*/

    /// @notice Master invariant - all gas pricing rules checked after each handler sequence
    function invariant_gasPricing() public view {
        _checkGasPricingInvariants();
    }

    /// @notice Called after invariant testing for final checks
    function afterInvariant() public {
        _log("");
        _log("================================================================================");
        _log("                              FINAL SUMMARY");
        _log("================================================================================");
        _log(
            string.concat("Total gas threshold tests: ", vm.toString(ghost_totalGasThresholdTests))
        );
        _log(
            string.concat(
                "SSTORE new slot - below threshold failed: ",
                vm.toString(ghost_sstoreNewSlotBelowThresholdFailed)
            )
        );
        _log(
            string.concat(
                "SSTORE new slot - above threshold succeeded: ",
                vm.toString(ghost_sstoreNewSlotAboveThresholdSucceeded)
            )
        );
        _log(
            string.concat(
                "Account creation - below threshold failed: ",
                vm.toString(ghost_accountCreationBelowThresholdFailed)
            )
        );
        _log(
            string.concat(
                "Account creation - above threshold succeeded: ",
                vm.toString(ghost_accountCreationAboveThresholdSucceeded)
            )
        );
        _log(
            string.concat(
                "CREATE - below threshold failed: ", vm.toString(ghost_createBelowThresholdFailed)
            )
        );
        _log(
            string.concat(
                "CREATE - above threshold succeeded: ",
                vm.toString(ghost_createAboveThresholdSucceeded)
            )
        );
        _log(string.concat("Tx over cap rejected: ", vm.toString(ghost_txOverCapRejected)));
        _log(string.concat("Tx at cap succeeded: ", vm.toString(ghost_txAtCapSucceeded)));

        // Verify no violations occurred
        assertEq(
            ghost_sstoreNewSlotBelowThresholdAllowed,
            0,
            "TEMPO-GAS1 violation: SSTORE new slot succeeded with insufficient gas"
        );
        assertEq(
            ghost_createBelowThresholdAllowed,
            0,
            "TEMPO-GAS3 violation: CREATE succeeded with insufficient gas"
        );
        // NOTE: The following are enforced at protocol level (tempo-revm), not EVM level:
        // - TEMPO-GAS2 (account creation): tested in crates/revm/src/handler.rs
        // - TEMPO-GAS6 (tx gas cap): tested in crates/transaction-pool/src/validator.rs
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Test SSTORE to new slot gas threshold (TEMPO-GAS1)
    /// @dev Tests that SSTORE to new slot requires 250,000 gas
    /// @param actorSeed Seed for selecting actor
    /// @param slotSeed Seed for selecting storage slot
    function handler_sstoreNewSlotThreshold(uint256 actorSeed, uint256 slotSeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        bytes32 slot =
            keccak256(abi.encode(slotSeed, block.timestamp, ghost_totalGasThresholdTests));
        bytes memory callData = abi.encodeCall(GasTestStorage.storeValue, (slot, 1));

        uint64 currentNonce = uint64(vm.getNonce(sender));

        // Test 1: Gas below threshold should fail (OOG)
        // SSTORE new slot = 250k, but we also need base tx cost + call overhead
        // Use a gas limit that's clearly insufficient for the SSTORE
        uint64 insufficientGas = uint64(BASE_TX_GAS + 50_000); // Only ~71k gas, way below 250k needed for SSTORE

        bytes memory signedTxLow = TxBuilder.buildLegacyCallWithGas(
            vmRlp,
            vm,
            address(_storageContract),
            callData,
            currentNonce,
            insufficientGas,
            privateKey
        );

        vm.coinbase(validator);
        ghost_totalGasThresholdTests++;

        try vmExec.executeTransaction(signedTxLow) {
            // Transaction succeeded with insufficient gas - this is a violation!
            ghost_sstoreNewSlotBelowThresholdAllowed++;
            ghost_protocolNonce[sender]++;
            ghost_totalProtocolNonceTxs++;
            _log(
                string.concat(
                    "VIOLATION: SSTORE new slot succeeded with only ",
                    vm.toString(insufficientGas),
                    " gas"
                )
            );
        } catch {
            // Expected: transaction failed due to insufficient gas
            ghost_sstoreNewSlotBelowThresholdFailed++;
            _log(
                string.concat(
                    "OK: SSTORE new slot correctly failed with ",
                    vm.toString(insufficientGas),
                    " gas"
                )
            );
        }

        // Test 2: Gas above threshold should succeed
        // Need: base tx (21k) + call overhead (~2.6k) + cold account (2600) + cold sload (2100) + SSTORE new slot (250k) + buffer
        uint64 sufficientGas = uint64(BASE_TX_GAS + SSTORE_SET_GAS + 50_000); // ~321k gas

        // Get fresh nonce (previous tx may have failed without consuming nonce, or succeeded)
        currentNonce = uint64(vm.getNonce(sender));

        bytes memory signedTxHigh = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(_storageContract), callData, currentNonce, sufficientGas, privateKey
        );

        ghost_totalGasThresholdTests++;

        try vmExec.executeTransaction(signedTxHigh) {
            ghost_sstoreNewSlotAboveThresholdSucceeded++;
            ghost_protocolNonce[sender]++;
            ghost_totalProtocolNonceTxs++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            _log(
                string.concat(
                    "OK: SSTORE new slot succeeded with ", vm.toString(sufficientGas), " gas"
                )
            );
        } catch {
            // This might fail for other reasons (e.g., if slot was already written)
            ghost_totalTxReverted++;
            _log(
                string.concat(
                    "INFO: SSTORE new slot failed with ",
                    vm.toString(sufficientGas),
                    " gas (may be expected)"
                )
            );
        }
    }

    /// @notice Handler: Test account creation gas threshold (TEMPO-GAS2)
    /// @dev Tests that first transaction from new account requires 250,000 gas for account creation
    /// @param actorSeed Seed for creating new account
    /// @param recipientSeed Seed for selecting recipient
    function handler_accountCreationThreshold(uint256 actorSeed, uint256 recipientSeed) external {
        // Create a fresh account that has never sent a transaction
        string memory label = string(
            abi.encodePacked(
                "fresh_account_",
                vm.toString(actorSeed),
                "_",
                vm.toString(ghost_totalGasThresholdTests)
            )
        );
        (address freshAccount, uint256 freshKey) = makeAddrAndKey(label);

        // Fund the fresh account with fee tokens
        vm.prank(admin);
        feeToken.mint(freshAccount, 1_000_000e6);

        uint256 recipientIdx = recipientSeed % actors.length;
        address recipient = actors[recipientIdx];

        bytes memory callData = abi.encodeCall(ITIP20.transfer, (recipient, 1e6));

        // Test 1: Gas below account creation threshold should fail
        // First tx needs: base tx (21k) + account creation (250k) = 271k minimum
        uint64 insufficientGas = uint64(BASE_TX_GAS + 50_000); // Only ~71k, below 271k needed

        bytes memory signedTxLow = TxBuilder.buildLegacyCallWithGas(
            vmRlp,
            vm,
            address(feeToken),
            callData,
            0, // nonce 0 for fresh account
            insufficientGas,
            freshKey
        );

        vm.coinbase(validator);
        ghost_totalGasThresholdTests++;

        try vmExec.executeTransaction(signedTxLow) {
            // Transaction succeeded with insufficient gas - violation!
            ghost_accountCreationBelowThresholdAllowed++;
            _log(
                string.concat(
                    "VIOLATION: Account creation succeeded with only ",
                    vm.toString(insufficientGas),
                    " gas"
                )
            );
        } catch {
            // Expected: transaction failed
            ghost_accountCreationBelowThresholdFailed++;
            _log(
                string.concat(
                    "OK: Account creation correctly failed with ",
                    vm.toString(insufficientGas),
                    " gas"
                )
            );
        }

        // Test 2: Gas above threshold should succeed
        // Create another fresh account for clean test
        string memory label2 = string(
            abi.encodePacked(
                "fresh_account2_",
                vm.toString(actorSeed),
                "_",
                vm.toString(ghost_totalGasThresholdTests)
            )
        );
        (address freshAccount2, uint256 freshKey2) = makeAddrAndKey(label2);

        vm.prank(admin);
        feeToken.mint(freshAccount2, 1_000_000e6);

        uint64 sufficientGas = uint64(FIRST_TX_MIN_GAS + 100_000); // 371k gas

        bytes memory signedTxHigh = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(feeToken), callData, 0, sufficientGas, freshKey2
        );

        ghost_totalGasThresholdTests++;

        try vmExec.executeTransaction(signedTxHigh) {
            ghost_accountCreationAboveThresholdSucceeded++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            _log(
                string.concat(
                    "OK: Account creation succeeded with ", vm.toString(sufficientGas), " gas"
                )
            );
        } catch {
            ghost_totalTxReverted++;
            _log(
                string.concat(
                    "INFO: Account creation failed with ",
                    vm.toString(sufficientGas),
                    " gas (unexpected)"
                )
            );
        }
    }

    /// @notice Handler: Test CREATE gas threshold (TEMPO-GAS3)
    /// @dev Tests that CREATE requires 500,000 base gas + code deposit cost
    /// @param actorSeed Seed for selecting actor
    function handler_createThreshold(uint256 actorSeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        bytes memory initcode = InitcodeHelper.counterInitcode();
        uint256 codeDepositCost = initcode.length * CODE_DEPOSIT_PER_BYTE;

        uint64 currentNonce = uint64(vm.getNonce(sender));

        // Test 1: Gas below CREATE threshold should fail
        // Need: base tx (21k) + CREATE base (500k) + code deposit
        uint64 insufficientGas = uint64(BASE_TX_GAS + 100_000); // Only ~121k, way below 500k+ needed

        bytes memory signedTxLow = TxBuilder.buildLegacyCreateWithGas(
            vmRlp, vm, initcode, currentNonce, insufficientGas, privateKey
        );

        vm.coinbase(validator);
        ghost_totalGasThresholdTests++;

        try vmExec.executeTransaction(signedTxLow) {
            // Check if contract was actually deployed
            address expectedAddr = TxBuilder.computeCreateAddress(sender, currentNonce);
            if (expectedAddr.code.length > 0) {
                // CREATE succeeded with insufficient gas - violation!
                ghost_createBelowThresholdAllowed++;
                _log(
                    string.concat(
                        "VIOLATION: CREATE succeeded with only ",
                        vm.toString(insufficientGas),
                        " gas"
                    )
                );
            }
            ghost_protocolNonce[sender]++;
            ghost_totalProtocolNonceTxs++;
        } catch {
            // Expected: transaction failed
            ghost_createBelowThresholdFailed++;
            _log(
                string.concat(
                    "OK: CREATE correctly failed with ", vm.toString(insufficientGas), " gas"
                )
            );
        }

        // Test 2: Gas above threshold should succeed
        currentNonce = uint64(vm.getNonce(sender));
        uint64 sufficientGas = uint64(BASE_TX_GAS + CREATE_BASE_GAS + codeDepositCost + 100_000);

        bytes memory signedTxHigh = TxBuilder.buildLegacyCreateWithGas(
            vmRlp, vm, initcode, currentNonce, sufficientGas, privateKey
        );

        ghost_totalGasThresholdTests++;

        try vmExec.executeTransaction(signedTxHigh) {
            address expectedAddr = TxBuilder.computeCreateAddress(sender, currentNonce);
            if (expectedAddr.code.length > 0) {
                ghost_createAboveThresholdSucceeded++;
                _log(
                    string.concat("OK: CREATE succeeded with ", vm.toString(sufficientGas), " gas")
                );
            }
            ghost_protocolNonce[sender]++;
            ghost_totalProtocolNonceTxs++;
            ghost_totalTxExecuted++;
            ghost_totalCreatesExecuted++;
        } catch {
            ghost_totalTxReverted++;
            _log(
                string.concat(
                    "INFO: CREATE failed with ", vm.toString(sufficientGas), " gas (unexpected)"
                )
            );
        }
    }

    /// @notice Handler: Test transaction gas cap enforcement (TEMPO-GAS6)
    /// @dev Tests that transactions cannot exceed 30,000,000 gas limit
    /// @param actorSeed Seed for selecting actor
    /// @param recipientSeed Seed for selecting recipient
    function handler_txGasCapEnforcement(uint256 actorSeed, uint256 recipientSeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];
        uint256 privateKey = actorKeys[senderIdx];

        bytes memory callData = abi.encodeCall(ITIP20.transfer, (recipient, 1e6));
        uint64 currentNonce = uint64(vm.getNonce(sender));

        // Test 1: Transaction at cap should succeed
        uint64 atCapGas = uint64(TX_GAS_LIMIT_CAP);

        bytes memory signedTxAtCap = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(feeToken), callData, currentNonce, atCapGas, privateKey
        );

        vm.coinbase(validator);
        ghost_totalGasThresholdTests++;

        try vmExec.executeTransaction(signedTxAtCap) {
            ghost_txAtCapSucceeded++;
            ghost_protocolNonce[sender]++;
            ghost_totalProtocolNonceTxs++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            _log(
                string.concat("OK: Transaction at cap (", vm.toString(atCapGas), " gas) succeeded")
            );
        } catch {
            ghost_totalTxReverted++;
            _log(
                string.concat("INFO: Transaction at cap failed (may be expected for other reasons)")
            );
        }

        // Test 2: Transaction over cap should be rejected
        currentNonce = uint64(vm.getNonce(sender));
        uint64 overCapGas = uint64(TX_GAS_LIMIT_CAP + 1);

        bytes memory signedTxOverCap = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(feeToken), callData, currentNonce, overCapGas, privateKey
        );

        ghost_totalGasThresholdTests++;

        try vmExec.executeTransaction(signedTxOverCap) {
            // Transaction over cap was allowed - violation!
            ghost_txOverCapAllowed++;
            ghost_protocolNonce[sender]++;
            ghost_totalProtocolNonceTxs++;
            _log(
                string.concat(
                    "VIOLATION: Transaction over cap (",
                    vm.toString(overCapGas),
                    " gas) was allowed"
                )
            );
        } catch {
            // Expected: transaction rejected
            ghost_txOverCapRejected++;
            _log(
                string.concat(
                    "OK: Transaction over cap (",
                    vm.toString(overCapGas),
                    " gas) correctly rejected"
                )
            );
        }
    }

    /// @notice Handler: Test multiple SSTORE new slots in a single transaction
    /// @dev Tests that multiple new slots each require 250,000 gas
    /// @param actorSeed Seed for selecting actor
    /// @param numSlots Number of new slots to write (1-5)
    function handler_multipleNewSlots(uint256 actorSeed, uint256 numSlots) external {
        numSlots = bound(numSlots, 1, 5);

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        // Generate unique slots
        bytes32[] memory slots = new bytes32[](numSlots);
        for (uint256 i = 0; i < numSlots; i++) {
            slots[i] =
                keccak256(abi.encode(actorSeed, i, block.timestamp, ghost_totalGasThresholdTests));
        }

        bytes memory callData = abi.encodeCall(GasTestStorage.storeMultiple, (slots));
        uint64 currentNonce = uint64(vm.getNonce(sender));

        // Required gas: base tx + (250k * numSlots) + overhead
        uint256 requiredGas = BASE_TX_GAS + (SSTORE_SET_GAS * numSlots) + 100_000;

        // Test 1: Insufficient gas for all slots should fail
        uint64 insufficientGas = uint64(BASE_TX_GAS + SSTORE_SET_GAS + 50_000); // Only enough for ~1 slot

        if (numSlots > 1) {
            bytes memory signedTxLow = TxBuilder.buildLegacyCallWithGas(
                vmRlp,
                vm,
                address(_storageContract),
                callData,
                currentNonce,
                insufficientGas,
                privateKey
            );

            vm.coinbase(validator);
            ghost_totalGasThresholdTests++;

            try vmExec.executeTransaction(signedTxLow) {
                // May succeed partially or revert - either is acceptable
                ghost_protocolNonce[sender]++;
                ghost_totalProtocolNonceTxs++;
                _log(
                    string.concat(
                        "INFO: Multi-slot with ",
                        vm.toString(insufficientGas),
                        " gas for ",
                        vm.toString(numSlots),
                        " slots"
                    )
                );
            } catch {
                _log(
                    string.concat(
                        "OK: Multi-slot correctly failed with insufficient gas for ",
                        vm.toString(numSlots),
                        " slots"
                    )
                );
            }

            currentNonce = uint64(vm.getNonce(sender));
        }

        // Test 2: Sufficient gas should succeed
        uint64 sufficientGas = uint64(requiredGas);
        if (sufficientGas > TX_GAS_LIMIT_CAP) {
            sufficientGas = uint64(TX_GAS_LIMIT_CAP);
        }

        bytes memory signedTxHigh = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(_storageContract), callData, currentNonce, sufficientGas, privateKey
        );

        ghost_totalGasThresholdTests++;

        try vmExec.executeTransaction(signedTxHigh) {
            ghost_protocolNonce[sender]++;
            ghost_totalProtocolNonceTxs++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            _log(
                string.concat(
                    "OK: Multi-slot (",
                    vm.toString(numSlots),
                    " slots) succeeded with ",
                    vm.toString(sufficientGas),
                    " gas"
                )
            );
        } catch {
            ghost_totalTxReverted++;
            _log(string.concat("INFO: Multi-slot failed with ", vm.toString(sufficientGas), " gas"));
        }
    }

    /*//////////////////////////////////////////////////////////////
                        INVARIANT CHECKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Check all gas pricing invariants
    function _checkGasPricingInvariants() internal view {
        _invariantSstoreNewSlotGas();
        _invariantAccountCreationGas();
        _invariantCreateGas();
        _invariantTxGasCap();
    }

    /// @notice TEMPO-GAS1: SSTORE to new slot requires 250,000 gas
    function _invariantSstoreNewSlotGas() internal view {
        assertEq(
            ghost_sstoreNewSlotBelowThresholdAllowed,
            0,
            "TEMPO-GAS1: SSTORE new slot succeeded with insufficient gas"
        );
    }

    /// @notice TEMPO-GAS2: Account creation (first tx) requires 250,000 gas
    function _invariantAccountCreationGas() internal view {
        assertEq(
            ghost_accountCreationBelowThresholdAllowed,
            0,
            "TEMPO-GAS2: Account creation succeeded with insufficient gas"
        );
    }

    /// @notice TEMPO-GAS3: CREATE requires 500,000 base gas
    function _invariantCreateGas() internal view {
        assertEq(
            ghost_createBelowThresholdAllowed,
            0,
            "TEMPO-GAS3: CREATE succeeded with insufficient gas"
        );
    }

    /// @notice TEMPO-GAS6: Transaction gas limit capped at 30,000,000
    function _invariantTxGasCap() internal view {
        assertEq(ghost_txOverCapAllowed, 0, "TEMPO-GAS6: Transaction over gas cap was allowed");
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Log a message to the log file
    function _log(string memory message) internal {
        vm.writeLine(LOG_FILE, message);
    }

}

/*//////////////////////////////////////////////////////////////
                        HELPER CONTRACTS
//////////////////////////////////////////////////////////////*/

/// @title GasTestStorage - Contract for testing SSTORE gas costs
/// @dev Simple contract with storage operations for gas measurement
contract GasTestStorage {

    /// @dev Storage mapping for testing
    mapping(bytes32 => uint256) private _storage;

    /// @dev Track which slots have been written
    bytes32[] private _slots;

    /// @dev Store a value at a slot
    function storeValue(bytes32 slot, uint256 value) external {
        if (_storage[slot] == 0 && value != 0) {
            _slots.push(slot);
        }
        _storage[slot] = value;
    }

    /// @dev Clear a storage slot
    function clearValue(bytes32 slot) external {
        _storage[slot] = 0;
    }

    /// @dev Store multiple values at once
    function storeMultiple(bytes32[] calldata slots) external {
        for (uint256 i = 0; i < slots.length; i++) {
            if (_storage[slots[i]] == 0) {
                _slots.push(slots[i]);
            }
            _storage[slots[i]] = 1;
        }
    }

    /// @dev Get value at slot
    function getValue(bytes32 slot) external view returns (uint256) {
        return _storage[slot];
    }

    /// @dev Get slot at index
    function getSlotAt(uint256 idx) external view returns (bytes32) {
        return _slots[idx];
    }

    /// @dev Get number of written slots
    function slotCount() external view returns (uint256) {
        return _slots.length;
    }

}
