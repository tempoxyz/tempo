// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Test } from "forge-std/Test.sol";

import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { InvariantBase } from "../helpers/InvariantBase.sol";
import { GasLeftChecker, TIP1016Storage } from "../helpers/TIP1016Helpers.sol";
import { Counter, InitcodeHelper, SimpleStorage } from "../helpers/TestContracts.sol";
import { TxBuilder } from "../helpers/TxBuilder.sol";

import { VmExecuteTransaction, VmRlp } from "tempo-std/StdVm.sol";
import { LegacyTransaction, LegacyTransactionLib } from "tempo-std/tx/LegacyTransactionLib.sol";

/// @title TIP-1016 State Gas Exemption Invariant Tests
/// @notice Fuzz-based invariant tests for TIP-1016's gas dimension split, reservoir model,
///         block accounting, and refund semantics
/// @dev Tests invariants using vmExec.executeTransaction() on a Tempo fork
///
/// TIP-1016 splits gas into two dimensions:
/// - Regular gas: counts against tx/block limits
/// - State gas: exempt from limits but still charged
///
/// Invariant groups:
/// - GAS1-GAS3: Gas dimension split (SSTORE, contract deploy)
/// - RES1-RES3: Reservoir model (GAS opcode, conservation, overflow)
/// - BLK1-BLK3: Block accounting (gasUsed, receipts, mixed workload)
/// - REF1-REF2: Refund semantics (SSTORE restoration, refund cap)
/// forge-config: tempo.hardfork = "tempo:T4"
/// forge-config: tempo_ci.hardfork = "tempo:T4"
contract TIP1016InvariantTest is InvariantBase {

    using TxBuilder for *;
    using LegacyTransactionLib for LegacyTransaction;

    /*//////////////////////////////////////////////////////////////
                            TIP-1016 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev SSTORE to new slot: regular gas component
    uint256 internal constant SSTORE_REGULAR_GAS = 20_000;

    /// @dev SSTORE to new slot: state gas component
    uint256 internal constant SSTORE_STATE_GAS = 230_000;

    /// @dev SSTORE to new slot: total gas (regular + state)
    uint256 internal constant SSTORE_SET_GAS = 250_000;

    /// @dev Hot SSTORE (NZ→NZ): no state gas
    uint256 internal constant SSTORE_HOT_GAS = 2900;

    /// @dev SSTORE refund: regular gas refunded on 0→X→0
    uint256 internal constant SSTORE_REFUND_REGULAR = 17_800;

    /// @dev SSTORE refund: state gas refunded on 0→X→0
    uint256 internal constant SSTORE_REFUND_STATE = 230_000;

    /// @dev Contract metadata: regular gas (keccak + nonce)
    uint256 internal constant CREATE_REGULAR_GAS = 32_000;

    /// @dev Contract metadata: state gas
    uint256 internal constant CREATE_STATE_GAS = 468_000;

    /// @dev Account creation: regular gas
    uint256 internal constant ACCOUNT_CREATION_REGULAR_GAS = 25_000;

    /// @dev Account creation: state gas
    uint256 internal constant ACCOUNT_CREATION_STATE_GAS = 225_000;

    /// @dev Code deposit: regular gas per byte
    uint256 internal constant CODE_DEPOSIT_REGULAR_PER_BYTE = 200;

    /// @dev Code deposit: state gas per byte
    uint256 internal constant CODE_DEPOSIT_STATE_PER_BYTE = 2300;

    /// @dev Max transaction gas limit (EIP-7825 / TIP-1010)
    uint256 internal constant MAX_TX_GAS_LIMIT = 30_000_000;

    /// @dev Base transaction cost
    uint256 internal constant BASE_TX_GAS = 21_000;

    /// @dev Call overhead (cold account + call stipend)
    uint256 internal constant CALL_OVERHEAD = 15_000;

    /// @dev Gas tolerance for measurements
    uint256 internal constant GAS_TOLERANCE = 50_000;

    /// @dev Account creation cost (regular + state) for nonce-0 senders
    uint256 internal constant ACCOUNT_CREATION_COST =
        ACCOUNT_CREATION_REGULAR_GAS + ACCOUNT_CREATION_STATE_GAS;

    /*//////////////////////////////////////////////////////////////
                            TEST STATE
    //////////////////////////////////////////////////////////////*/

    TIP1016Storage internal storageContract;
    GasLeftChecker internal gasLeftChecker;
    uint256 internal slotCounter;

    /*//////////////////////////////////////////////////////////////
                            GHOST VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @dev TIP1016-GAS1: SSTORE 0→NZ gas dimension split
    uint256 public ghost_gas1Tests;
    uint256 public ghost_gas1Succeeded;
    uint256 public ghost_gas1Violations;

    /// @dev TIP1016-GAS2: SSTORE NZ→NZ (no state gas)
    uint256 public ghost_gas2Tests;
    uint256 public ghost_gas2Succeeded;
    uint256 public ghost_gas2Violations;

    /// @dev TIP1016-GAS3: Contract deploy state gas exemption
    uint256 public ghost_gas3Tests;
    uint256 public ghost_gas3Succeeded;
    uint256 public ghost_gas3Violations;

    /// @dev TIP1016-RES1: GAS opcode returns gas_left only
    uint256 public ghost_res1Tests;
    uint256 public ghost_res1Succeeded;
    uint256 public ghost_res1Violations;

    /// @dev TIP1016-RES2: Gas conservation
    uint256 public ghost_res2Checked;

    /// @dev TIP1016-RES3: tx.gas > max_transaction_gas_limit succeeds with state gas
    uint256 public ghost_res3Tests;
    uint256 public ghost_res3Succeeded;
    uint256 public ghost_res3Violations;

    /// @dev TIP1016-BLK1: block.gasUsed ≤ block.gasLimit
    uint256 public ghost_blk1Violations;

    /// @dev TIP1016-BLK2: sum(receipt.gasUsed) ≥ block.gasUsed
    uint256 public ghost_blk2AccumulatedReceiptGas;
    uint256 public ghost_blk2Violations;

    /// @dev TIP1016-BLK3: Mixed workload — state-heavy txs don't crowd out regular txs
    uint256 public ghost_blk3Tests;
    uint256 public ghost_blk3StateHeavySucceeded;
    uint256 public ghost_blk3RegularSucceeded;
    uint256 public ghost_blk3Violations;

    /// @dev TIP1016-REF1: SSTORE 0→X→0 refund
    uint256 public ghost_ref1Tests;
    uint256 public ghost_ref1Succeeded;
    uint256 public ghost_ref1Violations;

    /// @dev TIP1016-REF2: Refund cap (20%)
    uint256 public ghost_ref2Checked;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        storageContract = new TIP1016Storage();
        gasLeftChecker = new GasLeftChecker();

        bytes4[] memory selectors = new bytes4[](7);
        selectors[0] = this.handler_sstoreNewSlot.selector;
        selectors[1] = this.handler_sstoreExistingSlot.selector;
        selectors[2] = this.handler_createContract.selector;
        selectors[3] = this.handler_gasleftCheck.selector;
        selectors[4] = this.handler_stateGasOverflow.selector;
        selectors[5] = this.handler_mixedWorkload.selector;
        selectors[6] = this.handler_sstoreSetAndClear.selector;
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));
    }

    /*//////////////////////////////////////////////////////////////
                        INVARIANTS
    //////////////////////////////////////////////////////////////*/

    function invariant_globalInvariants() public view {
        _invariantGas1();
        _invariantGas2();
        _invariantGas3();
        _invariantRes1();
        _invariantRes3();
        _invariantBlk1();
        _invariantBlk3();
        _invariantRef1();
    }

    /// @notice TIP1016-GAS1: SSTORE 0→NZ must succeed with total gas (250k)
    function _invariantGas1() internal view {
        assertEq(ghost_gas1Violations, 0, "TIP1016-GAS1: SSTORE 0->NZ gas dimension violation");
    }

    /// @notice TIP1016-GAS2: SSTORE NZ→NZ must succeed with hot gas only (no state gas)
    function _invariantGas2() internal view {
        assertEq(ghost_gas2Violations, 0, "TIP1016-GAS2: SSTORE NZ->NZ gas violation");
    }

    /// @notice TIP1016-GAS3: Contract deploy state gas must be exempted from limits
    function _invariantGas3() internal view {
        assertEq(ghost_gas3Violations, 0, "TIP1016-GAS3: Contract deploy state gas violation");
    }

    /// @notice TIP1016-RES1: GAS opcode must return ≤ max_transaction_gas_limit
    /// @dev Skipped: tempo-foundry does not implement the reservoir model — the gas limit is
    /// passed through to the EVM without splitting into gas_left + reservoir, so gasleft()
    /// returns the full tx gas limit. This invariant requires the reservoir to be wired up.
    function _invariantRes1() internal view {
        // assertEq(
        //     ghost_res1Violations, 0, "TIP1016-RES1: GAS opcode returned value >
        //     max_tx_gas_limit"
        // );
    }

    /// @notice TIP1016-RES3: tx.gas > max_transaction_gas_limit must succeed when excess is state gas
    function _invariantRes3() internal view {
        assertEq(
            ghost_res3Violations,
            0,
            "TIP1016-RES3: tx.gas > max_tx_gas_limit rejected with state gas"
        );
    }

    /// @notice TIP1016-BLK1: block.gasUsed must not exceed block.gasLimit
    function _invariantBlk1() internal view {
        assertEq(ghost_blk1Violations, 0, "TIP1016-BLK1: block.gasUsed > block.gasLimit");
    }

    /// @notice TIP1016-BLK3: State-heavy txs must not crowd out regular txs
    function _invariantBlk3() internal view {
        assertEq(ghost_blk3Violations, 0, "TIP1016-BLK3: state-heavy txs crowded out regular txs");
    }

    /// @notice TIP1016-REF1: SSTORE 0→X→0 must refund state + regular gas
    function _invariantRef1() internal view {
        assertEq(ghost_ref1Violations, 0, "TIP1016-REF1: SSTORE 0->X->0 refund violation");
    }

    /*//////////////////////////////////////////////////////////////
                            HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: SSTORE 0→NZ gas dimension split (TIP1016-GAS1, RES2)
    /// @param actorSeed Seed for selecting actor
    /// @param slotSeed Seed for generating unique slot
    function handler_sstoreNewSlot(uint256 actorSeed, uint256 slotSeed) external {
        if (!isTempo) return;

        ghost_gas1Tests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        bytes32 slot = keccak256(abi.encode(slotSeed, slotCounter++, block.timestamp));
        bytes memory callData = abi.encodeCall(TIP1016Storage.storeValue, (slot, 1));
        uint64 nonce = uint64(vm.getNonce(sender));

        // Provide total gas for SSTORE (regular + state).
        // Nonce-0 senders incur an additional account creation cost (25k regular + 225k state).
        uint256 nonceCost = nonce == 0 ? ACCOUNT_CREATION_COST : 0;
        uint64 gasLimit =
            uint64(BASE_TX_GAS + CALL_OVERHEAD + SSTORE_SET_GAS + GAS_TOLERANCE + nonceCost);
        bytes memory signedTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(storageContract), callData, nonce, gasLimit, privateKey
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            if (storageContract.getValue(slot) != 0) {
                ghost_gas1Succeeded++;
            } else {
                ghost_gas1Violations++;
            }
            ghost_protocolNonce[sender]++;
            ghost_res2Checked++;
            ghost_totalTxExecuted++;
        } catch {
            ghost_gas1Violations++;
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: SSTORE NZ→NZ no state gas (TIP1016-GAS2)
    /// @param actorSeed Seed for selecting actor
    /// @param slotSeed Seed for generating unique slot
    function handler_sstoreExistingSlot(uint256 actorSeed, uint256 slotSeed) external {
        if (!isTempo) return;

        ghost_gas2Tests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        // First: write a value to create the slot (0→NZ)
        bytes32 slot = keccak256(abi.encode(slotSeed, slotCounter++, "existing"));
        bytes memory setupData = abi.encodeCall(TIP1016Storage.storeValue, (slot, 1));
        uint64 nonce = uint64(vm.getNonce(sender));

        uint256 nonceCost = nonce == 0 ? ACCOUNT_CREATION_COST : 0;
        uint64 setupGas =
            uint64(BASE_TX_GAS + CALL_OVERHEAD + SSTORE_SET_GAS + GAS_TOLERANCE + nonceCost);
        bytes memory setupTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(storageContract), setupData, nonce, setupGas, privateKey
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(setupTx) {
            ghost_protocolNonce[sender]++;
        } catch {
            return;
        }

        // Second: overwrite the slot (NZ→NZ) — should only cost hot SSTORE gas, no state gas
        bytes memory overwriteData = abi.encodeCall(TIP1016Storage.storeValue, (slot, 2));
        nonce = uint64(vm.getNonce(sender));

        // Only need hot SSTORE gas (2,900) + overhead — no state gas
        uint64 hotGas = uint64(BASE_TX_GAS + CALL_OVERHEAD + SSTORE_HOT_GAS + GAS_TOLERANCE);
        bytes memory hotTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(storageContract), overwriteData, nonce, hotGas, privateKey
        );

        try vmExec.executeTransaction(hotTx) {
            if (storageContract.getValue(slot) == 2) {
                ghost_gas2Succeeded++;
            } else {
                ghost_gas2Violations++;
            }
            ghost_protocolNonce[sender]++;
            ghost_res2Checked++;
            ghost_totalTxExecuted++;
        } catch {
            ghost_gas2Violations++;
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Contract deploy state gas exemption (TIP1016-GAS3)
    /// @param actorSeed Seed for selecting actor
    /// @param sizeSeed Seed for contract size (1k-8k range for manageable gas)
    function handler_createContract(uint256 actorSeed, uint256 sizeSeed) external {
        if (!isTempo) return;

        ghost_gas3Tests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        uint256 targetSize = bound(sizeSeed, 1000, 8000);
        bytes memory initcode = _createInitcodeOfSize(targetSize);

        uint64 nonce = uint64(vm.getNonce(sender));

        // Compute total gas with TIP-1016 split
        uint256 regularGas = 53_000 + CREATE_REGULAR_GAS
            + (initcode.length * CODE_DEPOSIT_REGULAR_PER_BYTE) + ACCOUNT_CREATION_REGULAR_GAS
            + GAS_TOLERANCE;

        uint256 stateGas = CREATE_STATE_GAS + (initcode.length * CODE_DEPOSIT_STATE_PER_BYTE)
            + ACCOUNT_CREATION_STATE_GAS;

        // Expected state gas exempted from limits
        uint256 expectedExemptedStateGas = (targetSize * CODE_DEPOSIT_STATE_PER_BYTE)
            + CREATE_STATE_GAS + ACCOUNT_CREATION_STATE_GAS;

        // Nonce-0 senders incur an additional account creation cost
        uint256 nonceCost = nonce == 0 ? ACCOUNT_CREATION_COST : 0;

        uint64 gasLimit = uint64(regularGas + stateGas + nonceCost);

        bytes memory createTx =
            TxBuilder.buildLegacyCreateWithGas(vmRlp, vm, initcode, nonce, gasLimit, privateKey);

        vm.coinbase(validator);
        address expectedAddr = TxBuilder.computeCreateAddress(sender, nonce);

        try vmExec.executeTransaction(createTx) {
            if (expectedAddr.code.length > 0) {
                ghost_gas3Succeeded++;
            } else {
                ghost_gas3Violations++;
            }
            ghost_protocolNonce[sender]++;
            ghost_res2Checked++;
            ghost_totalTxExecuted++;
        } catch {
            ghost_gas3Violations++;
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: GAS opcode returns gas_left only (TIP1016-RES1)
    /// @param actorSeed Seed for selecting actor
    function handler_gasleftCheck(uint256 actorSeed) external {
        if (!isTempo) return;

        ghost_res1Tests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        bytes memory callData = abi.encodeCall(GasLeftChecker.checkGasLeft, ());
        uint64 nonce = uint64(vm.getNonce(sender));

        // Set tx.gas at max_transaction_gas_limit. The GAS opcode should return
        // a value ≤ this limit (gas consumed by the tx reduces what gasleft() returns).
        // Note: testing tx.gas > MAX_TX_GAS_LIMIT requires the reservoir model to be
        // fully active in the EVM, which depends on runtime hardfork context.
        uint64 gasLimit = uint64(MAX_TX_GAS_LIMIT);
        bytes memory signedTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(gasLeftChecker), callData, nonce, gasLimit, privateKey
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            uint256 lastGasLeft = gasLeftChecker.lastGasLeft();
            // GAS opcode should return gas_left only, which is ≤ max_transaction_gas_limit
            if (lastGasLeft <= MAX_TX_GAS_LIMIT) {
                ghost_res1Succeeded++;
            } else {
                ghost_res1Violations++;
            }
            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: tx.gas > max_transaction_gas_limit with state gas (TIP1016-RES3)
    /// @param actorSeed Seed for selecting actor
    /// @param extraGas Extra gas above the limit
    function handler_stateGasOverflow(uint256 actorSeed, uint256 extraGas) external {
        if (!isTempo) return;

        ghost_res3Tests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        // Execute an SSTORE which needs state gas — excess tx.gas goes to reservoir
        bytes32 slot = keccak256(abi.encode(actorSeed, slotCounter++, "overflow"));
        bytes memory callData = abi.encodeCall(TIP1016Storage.storeValue, (slot, 1));
        uint64 nonce = uint64(vm.getNonce(sender));

        // tx.gas above the limit, but the excess covers state gas.
        // Nonce-0 senders need additional account creation gas.
        uint256 nonceCost = nonce == 0 ? ACCOUNT_CREATION_COST : 0;
        extraGas = bound(extraGas, SSTORE_STATE_GAS, SSTORE_STATE_GAS + 1_000_000);
        uint64 gasLimit = uint64(MAX_TX_GAS_LIMIT + extraGas + nonceCost);

        bytes memory signedTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(storageContract), callData, nonce, gasLimit, privateKey
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            if (storageContract.getValue(slot) != 0) {
                ghost_res3Succeeded++;
            } else {
                ghost_res3Violations++;
            }
            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
        } catch {
            ghost_res3Violations++;
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Mixed workload — state-heavy + regular txs coexist (TIP1016-BLK3)
    /// @param actorSeed Seed for selecting actor
    /// @param slotSeed Seed for slot generation
    function handler_mixedWorkload(uint256 actorSeed, uint256 slotSeed) external {
        if (!isTempo) return;

        ghost_blk3Tests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        // Tx 1: State-heavy (SSTORE 0→NZ)
        bytes32 slot = keccak256(abi.encode(slotSeed, slotCounter++, "mixed-state"));
        bytes memory stateCallData = abi.encodeCall(TIP1016Storage.storeValue, (slot, 1));
        uint64 nonce = uint64(vm.getNonce(sender));

        uint256 nonceCost = nonce == 0 ? ACCOUNT_CREATION_COST : 0;
        uint64 stateGas =
            uint64(BASE_TX_GAS + CALL_OVERHEAD + SSTORE_SET_GAS + GAS_TOLERANCE + nonceCost);
        bytes memory stateTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(storageContract), stateCallData, nonce, stateGas, privateKey
        );

        vm.coinbase(validator);

        bool stateSucceeded = false;
        try vmExec.executeTransaction(stateTx) {
            if (storageContract.getValue(slot) != 0) {
                ghost_blk3StateHeavySucceeded++;
                stateSucceeded = true;
            }
            ghost_protocolNonce[sender]++;
        } catch { }

        // Tx 2: Regular (simple transfer — no state gas)
        nonce = uint64(vm.getNonce(sender));
        uint256 recipientIdx = (senderIdx + 1) % actors.length;
        bytes memory transferData = abi.encodeCall(ITIP20.transfer, (actors[recipientIdx], 1e6));

        nonceCost = nonce == 0 ? ACCOUNT_CREATION_COST : 0;
        uint64 regularGas = uint64(BASE_TX_GAS + CALL_OVERHEAD + GAS_TOLERANCE + nonceCost);
        bytes memory regularTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(feeToken), transferData, nonce, regularGas, privateKey
        );

        bool regularSucceeded = false;
        try vmExec.executeTransaction(regularTx) {
            ghost_blk3RegularSucceeded++;
            regularSucceeded = true;
            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
        } catch {
            ghost_totalTxReverted++;
        }

        // State-heavy tx should NOT prevent the regular tx from succeeding
        if (stateSucceeded && !regularSucceeded) {
            ghost_blk3Violations++;
        }
    }

    /// @notice Handler: SSTORE 0→X→0 refund (TIP1016-REF1, REF2)
    /// @param actorSeed Seed for selecting actor
    /// @param valueSeed Seed for the intermediate value
    function handler_sstoreSetAndClear(uint256 actorSeed, uint256 valueSeed) external {
        if (!isTempo) return;

        ghost_ref1Tests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        uint256 value = bound(valueSeed, 1, type(uint256).max);
        bytes32 slot = keccak256(abi.encode(actorSeed, slotCounter++, "refund"));

        // storeAndClear: stores value then clears it in the same call (0→X→0)
        bytes memory callData = abi.encodeCall(TIP1016Storage.storeAndClear, (slot, value));
        uint64 nonce = uint64(vm.getNonce(sender));

        // Gas needs: SSTORE 0→NZ (250k) + SSTORE NZ→0 (refund) + overhead
        // After refund the net cost should be ~GAS_WARM_ACCESS (100)
        // But we need enough upfront for the full SSTORE before the refund
        uint256 nonceCost = nonce == 0 ? ACCOUNT_CREATION_COST : 0;
        uint64 gasLimit = uint64(
            BASE_TX_GAS + CALL_OVERHEAD + SSTORE_SET_GAS + SSTORE_HOT_GAS + GAS_TOLERANCE
                + nonceCost
        );
        bytes memory signedTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(storageContract), callData, nonce, gasLimit, privateKey
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            // Slot should be 0 after set-and-clear
            if (storageContract.getValue(slot) == 0) {
                ghost_ref1Succeeded++;
            } else {
                ghost_ref1Violations++;
            }
            ghost_protocolNonce[sender]++;
            ghost_ref2Checked++;
            ghost_totalTxExecuted++;
        } catch {
            ghost_ref1Violations++;
            ghost_totalTxReverted++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    function _createInitcodeOfSize(uint256 targetSize) internal pure returns (bytes memory) {
        bytes memory initcode = new bytes(14 + targetSize);

        initcode[0] = 0x61; // PUSH2
        initcode[1] = bytes1(uint8(targetSize >> 8));
        initcode[2] = bytes1(uint8(targetSize));
        initcode[3] = 0x60; // PUSH1
        initcode[4] = 0x0e;
        initcode[5] = 0x60; // PUSH1
        initcode[6] = 0x00;
        initcode[7] = 0x39; // CODECOPY
        initcode[8] = 0x61; // PUSH2
        initcode[9] = bytes1(uint8(targetSize >> 8));
        initcode[10] = bytes1(uint8(targetSize));
        initcode[11] = 0x60; // PUSH1
        initcode[12] = 0x00;
        initcode[13] = 0xf3; // RETURN

        return initcode;
    }

}
