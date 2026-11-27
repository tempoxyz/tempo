// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Test } from "forge-std/Test.sol";

import { InvariantBase } from "../helpers/InvariantBase.sol";
import { TxBuilder } from "../helpers/TxBuilder.sol";
import { ITIP20 } from "tempo-std/interfaces/ITIP20.sol";

import { VmExecuteTransaction, VmRlp } from "tempo-std/StdVm.sol";
import { AccessListItem } from "tempo-std/tx/AccessListTypes.sol";
import { Eip1559Transaction, Eip1559TransactionLib } from "tempo-std/tx/Eip1559TransactionLib.sol";
import { LegacyTransaction, LegacyTransactionLib } from "tempo-std/tx/LegacyTransactionLib.sol";

/// @title TIP-1010 / TIP-1016 Block Gas Limits Invariant Tests
/// @notice Fuzz-based invariant tests for Tempo's block gas parameters
/// @dev Tests block gas limit invariants using vmExec.executeTransaction()
///
/// TIP-1010 specifies:
/// - Block gas limit: 500,000,000 (TEMPO-BLOCK1)
/// - General lane limit: 30,000,000 (TEMPO-BLOCK2)
/// - Before T15: total transaction gas cap of 30,000,000 (TEMPO-BLOCK3)
/// - From T15: execution gas cap of 16,777,216, with uncapped total gas (TIP-1016)
/// - T1 base fee: 20 gwei (TEMPO-BLOCK4)
/// - Payment lane minimum: 470,000,000 (TEMPO-BLOCK5)
/// - Max deployment fits in tx cap (TEMPO-BLOCK6)
///
/// Block-level lane enforcement (BLOCK7, BLOCK12) and shared gas limit
/// (BLOCK10) are tested in Rust (crates/evm/src/consensus/mod.rs).
contract BlockGasLimitsInvariantTest is InvariantBase {

    using TxBuilder for *;
    using LegacyTransactionLib for LegacyTransaction;
    using Eip1559TransactionLib for Eip1559Transaction;

    /*//////////////////////////////////////////////////////////////
                            TIP-1010 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Block gas limit (500M)
    uint256 internal constant BLOCK_GAS_LIMIT = 500_000_000;

    /// @dev General lane gas limit (30M)
    uint256 internal constant GENERAL_GAS_LIMIT = 30_000_000;

    /// @dev Pre-T15 total transaction gas cap (30M)
    uint256 internal constant TX_GAS_CAP = 30_000_000;

    /// @dev T15 execution gas cap (EIP-7825), excluding the state gas reservoir
    uint256 internal constant TX_EXECUTION_GAS_CAP = 16_777_216;

    /// @dev Runtime that returns GAS at entry (GAS itself costs two gas).
    address internal gasProbe;

    /// @dev T1 base fee (20 gwei)
    uint256 internal constant T1_BASE_FEE = 20 gwei;

    /// @dev T0 base fee (10 gwei)
    uint256 internal constant T0_BASE_FEE = 10 gwei;

    /// @dev Payment lane minimum (470M)
    uint256 internal constant PAYMENT_LANE_MIN = BLOCK_GAS_LIMIT - GENERAL_GAS_LIMIT;

    /// @dev Max contract size (24KB, EIP-170)
    uint256 internal constant MAX_CONTRACT_SIZE = 24_576;

    /// @dev TIP-1000: Code deposit per byte
    uint256 internal constant CODE_DEPOSIT_PER_BYTE = 1000;

    /// @dev TIP-1000: CREATE base gas
    uint256 internal constant CREATE_BASE_GAS = 500_000;

    /// @dev TIP-1000: Account creation gas
    uint256 internal constant ACCOUNT_CREATION_GAS = 250_000;

    /*//////////////////////////////////////////////////////////////
                            GHOST VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @dev TEMPO-BLOCK3: Tx gas cap enforcement
    uint256 public ghost_txGasCapTests;
    uint256 public ghost_txAtCapSucceeded;
    uint256 public ghost_txOverCapRejected;
    uint256 public ghost_txOverCapViolations; // Pre-T15 over-cap tx was accepted
    uint256 public ghost_txOverCapAccepted; // T15 total gas above 30M is valid

    /// @dev TEMPO-BLOCK6: Deployment fits in cap
    uint256 public ghost_deploymentTests;
    uint256 public ghost_maxDeploymentSucceeded;

    /// @dev General tracking
    uint256 public ghost_validTxExecuted;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        gasProbe = makeAddr("gasProbe");
        // GAS; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
        vm.etch(gasProbe, hex"5a60005260206000f3");

        targetContract(address(this));

        // Register handlers
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = this.handler_txGasCapEnforcement.selector;
        selectors[1] = this.handler_maxDeploymentFits.selector;
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));
    }

    /*//////////////////////////////////////////////////////////////
                        INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks
    function invariant_blockGasLimitsGlobal() public view {
        _invariantTxGasCap();
        _invariantMaxDeploymentFits();
    }

    /// @notice TEMPO-BLOCK3: Enforce the active fork's transaction gas dimension.
    function _invariantTxGasCap() internal view {
        assertEq(ghost_txAtCapSucceeded, ghost_txGasCapTests, "Tx at cap must succeed");
        assertEq(ghost_txOverCapViolations, 0, "TEMPO-BLOCK3: Pre-T15 total cap bypassed");
        if (_isTempoForkOrLater(15)) {
            assertEq(
                ghost_txOverCapAccepted, ghost_txGasCapTests, "TIP-1016: Total gas is not capped"
            );
        } else {
            assertEq(ghost_txOverCapRejected, ghost_txGasCapTests, "TEMPO-BLOCK3: Cap not enforced");
        }
    }

    /// @notice TEMPO-BLOCK6: Every tested deployment must fit in the fork's gas model.
    function _invariantMaxDeploymentFits() internal view {
        assertEq(
            ghost_maxDeploymentSucceeded, ghost_deploymentTests, "TEMPO-BLOCK6: Deployment failed"
        );
    }

    /*//////////////////////////////////////////////////////////////
                            HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Test tx gas cap enforcement (TEMPO-BLOCK3)
    /// @param actorSeed Seed for selecting actor
    /// @param gasMultiplier Multiplier to test various gas levels
    function handler_txGasCapEnforcement(uint256 actorSeed, uint256 gasMultiplier) external {
        ghost_txGasCapTests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];
        bool reservoir = _isTempoForkOrLater(15);

        bytes memory callData = abi.encodeCall(ITIP20.transfer, (actors[0], 1e6));
        uint64 nonce = uint64(vm.getNonce(sender));
        uint64 atCapGas = uint64(reservoir ? TX_EXECUTION_GAS_CAP : TX_GAS_CAP);
        bytes memory atCapTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(feeToken), callData, nonce, atCapGas, privateKey
        );

        vm.coinbase(validator);
        // No catch: a rejected/reverted control transaction must fail the handler.
        vmExec.executeTransaction(atCapTx);
        ghost_txAtCapSucceeded++;
        ghost_protocolNonce[sender]++;
        ghost_validTxExecuted++;

        nonce = uint64(vm.getNonce(sender));
        uint256 overAmount = bound(gasMultiplier, 1, 10_000_000);
        uint64 overCapGas = uint64(TX_GAS_CAP + overAmount);
        bytes memory overCapTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp,
            vm,
            reservoir ? gasProbe : address(feeToken),
            reservoir ? bytes("") : callData,
            nonce,
            overCapGas,
            privateKey
        );

        if (reservoir) {
            // The control tx above made the nonce nonzero. Empty calldata therefore has
            // exactly 21,000 intrinsic execution gas and no intrinsic state gas.
            bytes memory output = vmExec.executeTransaction(overCapTx);
            assertEq(
                abi.decode(output, (uint256)),
                TX_EXECUTION_GAS_CAP - 21_000 - 2,
                "TIP-1016: GAS must expose exactly the execution budget, not the reservoir"
            );
            ghost_txOverCapAccepted++;
            ghost_protocolNonce[sender]++;
            ghost_validTxExecuted++;
        } else {
            try vmExec.executeTransaction(overCapTx) {
                ghost_txOverCapViolations++;
                ghost_protocolNonce[sender]++;
            } catch (bytes memory reason) {
                assertTrue(_isGasCapRevert(reason), "Expected total gas cap validation error");
                ghost_txOverCapRejected++;
                assertEq(vm.getNonce(sender), nonce, "Rejected tx must not consume nonce");
            }
        }
    }

    /// @notice Handler: Test max contract deployment fits in cap (TEMPO-BLOCK6)
    /// @param actorSeed Seed for selecting actor
    /// @param sizeFraction Fraction of max size to deploy (50-100%)
    function handler_maxDeploymentFits(uint256 actorSeed, uint256 sizeFraction) external {
        ghost_deploymentTests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        // Create initcode for contract near max size
        // Size: 50% to 100% of max (12KB to 24KB)
        sizeFraction = bound(sizeFraction, 50, 100);
        uint256 targetSize = (MAX_CONTRACT_SIZE * sizeFraction) / 100;

        // Initcode copies and returns targetSize bytes of STOP opcodes.
        bytes memory initcode = _createInitcodeOfSize(targetSize);

        // T15 raises total code deposit pricing to 2,500 gas/byte. State gas is
        // exempt from the execution cap; do not clamp this total budget to 30M.
        bool reservoir = _isTempoForkOrLater(15);
        uint256 codeDepositPerByte = reservoir ? 2500 : CODE_DEPOSIT_PER_BYTE;
        uint256 requiredGas = 53_000 // CREATE tx base
            + CREATE_BASE_GAS + (initcode.length * codeDepositPerByte) + ACCOUNT_CREATION_GAS
            + 100_000; // Buffer for memory expansion etc.

        if (!reservoir) assertLe(requiredGas, TX_GAS_CAP);
        uint64 gasLimit = uint64(requiredGas);

        uint64 nonce = uint64(vm.getNonce(sender));
        bytes memory createTx =
            TxBuilder.buildLegacyCreateWithGas(vmRlp, vm, initcode, nonce, gasLimit, privateKey);

        vm.coinbase(validator);
        address expectedAddr = TxBuilder.computeCreateAddress(sender, nonce);

        vmExec.executeTransaction(createTx);
        assertEq(expectedAddr.code.length, targetSize, "TEMPO-BLOCK6: Incorrect deployed code size");
        ghost_maxDeploymentSucceeded++;
        ghost_protocolNonce[sender]++;
        ghost_validTxExecuted++;
    }

    /// @notice Always cover 30M + 1 and the full 24KB deployment, on both forks.
    function test_transactionGasAndDeploymentLimits() public {
        this.handler_txGasCapEnforcement(0, 1);
        this.handler_maxDeploymentFits(0, 100);
        invariant_blockGasLimitsGlobal();
    }

    /// @notice Intrinsic execution above the cap is rejected before runtime, not halted by OOG.
    function test_intrinsicExecutionGasOverCapRejected() public {
        vm.skip(!_isTempoForkOrLater(15));
        vm.setNonce(actors[0], 1);
        // Access-list entries are charged even when duplicated. Empty calldata keeps
        // its floor at 21k, isolating intrinsic execution gas: 21k + 2400 + 9000*1900.
        AccessListItem[] memory accessList = new AccessListItem[](1);
        accessList[0] = AccessListItem(gasProbe, new bytes32[](9000));
        Eip1559Transaction memory tx_ = Eip1559TransactionLib.create()
            .withNonce(1)
            .withMaxFeePerGas(100)
            .withGasLimit(40_000_000)
            .withTo(gasProbe)
            .withAccessList(accessList);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(actorKeys[0], keccak256(tx_.encode(vmRlp)));
        bytes memory signedTx = tx_.encodeWithSignature(vmRlp, v, r, s);
        try vmExec.executeTransaction(signedTx) {
            fail("Intrinsic execution gas above cap must be rejected");
        } catch (bytes memory reason) {
            assertEq(
                reason,
                abi.encodeWithSignature(
                    "CheatcodeError(string)",
                    "vm.executeTransaction: transaction execution failed: intrinsic gas exceeds cap: required 17123400, cap 16777216"
                )
            );
        }
        assertEq(vm.getNonce(actors[0]), 1, "Validation rejection must not consume nonce");
    }

    /// @notice T15 must allow exactly 16,777,216 execution gas, but not one gas more.
    function test_executionGasCapBoundary() public {
        vm.skip(!_isTempoForkOrLater(15));
        address sender = actors[0];
        // Remove the nonce-zero intrinsic surcharge from this exact boundary fixture.
        vm.setNonce(sender, 1);
        vm.coinbase(validator);

        // All runtime charges here are execution gas. The extra total budget is a
        // reservoir and must not rescue the second transaction from execution OOG.
        vm.etch(gasProbe, _executionGasBurner(TX_EXECUTION_GAS_CAP - 21_000));
        vmExec.executeTransaction(
            TxBuilder.buildLegacyCallWithGas(vmRlp, vm, gasProbe, "", 1, 40_000_000, actorKeys[0])
        );

        vm.etch(gasProbe, _executionGasBurner(TX_EXECUTION_GAS_CAP - 21_000 + 1));
        bytes memory overTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, gasProbe, "", 2, 40_000_000, actorKeys[0]
        );
        vm.expectRevert(
            abi.encodeWithSignature(
                "CheatcodeError(string)", "vm.executeTransaction: transaction halted: OutOfGas"
            )
        );
        vmExec.executeTransaction(overTx);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if revert reason indicates a gas cap violation
    function _isGasCapRevert(bytes memory reason) internal view returns (bool) {
        // Foundry wraps execution/validation failures in CheatcodeError(string),
        // not Solidity's Error(string).
        if (reason.length < 4 || bytes4(reason) != bytes4(keccak256("CheatcodeError(string)"))) {
            return false;
        }
        bytes memory payload = new bytes(reason.length - 4);
        for (uint256 i; i < payload.length; i++) {
            payload[i] = reason[i + 4];
        }
        return vm.contains(abi.decode(payload, (string)), "is greater than the cap");
    }

    /// @dev Burn an exact amount of execution gas without looping millions of times.
    ///      Two PUSHes + MSTORE cost 9 plus memory expansion (3*w + w*w/512).
    ///      Pad the remainder with JUMPDEST (one gas each), then STOP (zero gas).
    function _executionGasBurner(uint256 gasToBurn) internal pure returns (bytes memory) {
        uint256 words;
        uint256 high = gasToBurn / 3;
        while (words < high) {
            uint256 mid = (words + high + 1) / 2;
            if (9 + 3 * mid + mid * mid / 512 <= gasToBurn) {
                words = mid;
            } else {
                high = mid - 1;
            }
        }
        uint256 padding = gasToBurn - (9 + 3 * words + words * words / 512);
        bytes memory code = abi.encodePacked(hex"600062", bytes3(uint24((words - 1) * 32)), hex"52");
        bytes memory runtime = new bytes(code.length + padding + 1);
        for (uint256 i; i < code.length; i++) {
            runtime[i] = code[i];
        }
        for (uint256 i = code.length; i < runtime.length - 1; i++) {
            runtime[i] = 0x5b;
        }
        return runtime;
    }

    /// @notice Create initcode that deploys a contract of target runtime size
    /// @param targetSize Target runtime bytecode size
    /// @dev Optimized: new bytes() is zero-initialized, so we skip the O(n) loops
    function _createInitcodeOfSize(uint256 targetSize) internal pure returns (bytes memory) {
        // Initcode structure:
        // PUSH2 <size>   ; 3 bytes
        // PUSH1 0x0e     ; 2 bytes (offset where runtime starts = 14)
        // PUSH1 0x00     ; 2 bytes (memory destination)
        // CODECOPY       ; 1 byte
        // PUSH2 <size>   ; 3 bytes
        // PUSH1 0x00     ; 2 bytes
        // RETURN         ; 1 byte
        // <runtime>      ; targetSize bytes (zeros = STOP opcodes)

        // Allocate initcode directly - new bytes() is zero-initialized
        // so runtime portion is already 0x00 (STOP opcode)
        bytes memory initcode = new bytes(14 + targetSize);

        // PUSH2 size (big endian)
        initcode[0] = 0x61; // PUSH2
        initcode[1] = bytes1(uint8(targetSize >> 8));
        initcode[2] = bytes1(uint8(targetSize));

        // PUSH1 0x0e (14 = offset where runtime starts)
        initcode[3] = 0x60; // PUSH1
        initcode[4] = 0x0e;

        // PUSH1 0x00
        initcode[5] = 0x60;
        initcode[6] = 0x00;

        // CODECOPY
        initcode[7] = 0x39;

        // PUSH2 size
        initcode[8] = 0x61;
        initcode[9] = bytes1(uint8(targetSize >> 8));
        initcode[10] = bytes1(uint8(targetSize));

        // PUSH1 0x00
        initcode[11] = 0x60;
        initcode[12] = 0x00;

        // RETURN
        initcode[13] = 0xf3;

        // Runtime portion (bytes 14+) is already zero-initialized (0x00 = STOP)
        return initcode;
    }

}
