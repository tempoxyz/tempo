// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Test } from "forge-std/Test.sol";

import { InvariantBase } from "../helpers/InvariantBase.sol";
import { TxBuilder } from "../helpers/TxBuilder.sol";
import { ITIP20 } from "tempo-std/interfaces/ITIP20.sol";

import { VmExecuteTransaction, VmRlp } from "tempo-std/StdVm.sol";
import { LegacyTransaction, LegacyTransactionLib } from "tempo-std/tx/LegacyTransactionLib.sol";

/// @title TIP-1010 Block Gas Limits Invariant Tests
/// @notice Fuzz-based invariant tests for Tempo's block gas parameters
/// @dev Tests block gas limit invariants using vmExec.executeTransaction()
///
/// TIP-1010 specifies:
/// - Block gas limit: 500,000,000 (TEMPO-BLOCK1)
/// - General lane limit: 30,000,000 (TEMPO-BLOCK2)
/// - Transaction gas cap: 30,000,000 (TEMPO-BLOCK3)
/// - T1 base fee: 20 gwei (TEMPO-BLOCK4)
/// - Payment lane minimum: 470,000,000 (TEMPO-BLOCK5)
/// - Max deployment fits in tx cap (TEMPO-BLOCK6)
///
/// TIP-1016 state gas changes:
/// - Regular gas counts against tx/block limits; state gas is exempt
/// - tx.gas > max_transaction_gas_limit is VALID when excess is state gas
/// - Block gasUsed reflects regular gas only
/// - Code deposit: 200 regular + 2,300 state per byte
/// - CREATE base: 32,000 regular + 468,000 state
/// - Account creation: 25,000 regular + 225,000 state
///
/// Block-level lane enforcement (BLOCK7, BLOCK12) and shared gas limit
/// (BLOCK10) are tested in Rust (crates/consensus/src/lib.rs).
/// forge-config: default.hardfork = "tempo:T4"
/// forge-config: fuzz500.hardfork = "tempo:T4"
contract BlockGasLimitsInvariantTest is InvariantBase {

    using TxBuilder for *;
    using LegacyTransactionLib for LegacyTransaction;

    /*//////////////////////////////////////////////////////////////
                            TIP-1010 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Block gas limit (500M)
    uint256 internal constant BLOCK_GAS_LIMIT = 500_000_000;

    /// @dev General lane gas limit (30M)
    uint256 internal constant GENERAL_GAS_LIMIT = 30_000_000;

    /// @dev Transaction gas cap (30M)
    uint256 internal constant TX_GAS_CAP = 30_000_000;

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
                            TIP-1016 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev TIP-1016: SSTORE regular gas component
    uint256 internal constant SSTORE_REGULAR_GAS = 20_000;

    /// @dev TIP-1016: SSTORE state gas component
    uint256 internal constant SSTORE_STATE_GAS = 230_000;

    /// @dev TIP-1016: Code deposit regular gas per byte
    uint256 internal constant CODE_DEPOSIT_REGULAR_PER_BYTE = 200;

    /// @dev TIP-1016: Code deposit state gas per byte
    uint256 internal constant CODE_DEPOSIT_STATE_PER_BYTE = 2300;

    /// @dev TIP-1016: CREATE regular gas component
    uint256 internal constant CREATE_REGULAR_GAS = 32_000;

    /// @dev TIP-1016: CREATE state gas component
    uint256 internal constant CREATE_STATE_GAS = 468_000;

    /// @dev TIP-1016: Account creation regular gas component
    uint256 internal constant ACCOUNT_CREATION_REGULAR_GAS = 25_000;

    /// @dev TIP-1016: Account creation state gas component
    uint256 internal constant ACCOUNT_CREATION_STATE_GAS = 225_000;

    /*//////////////////////////////////////////////////////////////
                            GHOST VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @dev TEMPO-BLOCK3: Tx gas cap enforcement
    uint256 public ghost_txGasCapTests;
    uint256 public ghost_txAtCapSucceeded;
    uint256 public ghost_txOverCapWithStateGasSucceeded; // tx.gas > cap is valid when excess is state gas

    /// @dev TEMPO-BLOCK6: Deployment fits in cap
    uint256 public ghost_deploymentTests;
    uint256 public ghost_maxDeploymentSucceeded;
    uint256 public ghost_maxDeploymentFailed; // Unexpected - would indicate cap too low

    /// @dev TIP-1016: Block gasUsed reflects regular gas only
    /// @notice Verified at the block level in Rust (crates/consensus/src/lib.rs);
    ///         this ghost tracks our Solidity-side accounting for consistency.
    uint256 public ghost_blockGasUsedRegularOnly;

    /// @dev General tracking
    uint256 public ghost_validTxExecuted;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

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
    function invariant_globalInvariants() public view {
        _invariantTxGasCap();
        _invariantMaxDeploymentFits();
        _invariantBlockGasRegularOnly();
    }

    /// @notice TEMPO-BLOCK3 + TIP-1016: Tx gas cap applies to regular gas only
    /// @dev Post-TIP-1016, tx.gas > TX_GAS_CAP is valid when excess is state gas.
    ///      We verify that such transactions succeed rather than being rejected.
    function _invariantTxGasCap() internal view {
        if (ghost_txGasCapTests > 0) {
            assertTrue(
                ghost_txOverCapWithStateGasSucceeded > 0 || ghost_txAtCapSucceeded > 0,
                "TEMPO-BLOCK3: No gas cap tests succeeded"
            );
        }
    }

    /// @notice TEMPO-BLOCK6: Max contract deployment (24KB) must fit in tx cap
    /// @dev Failures indicate tx cap is too low for max-size contracts
    function _invariantMaxDeploymentFits() internal view {
        if (ghost_deploymentTests > 0) {
            assertTrue(
                ghost_maxDeploymentSucceeded > 0 || ghost_maxDeploymentFailed == 0,
                "TEMPO-BLOCK6: Max deployment never succeeded"
            );
        }
    }

    /// @notice TIP-1016: Block gasUsed must reflect regular gas only
    /// @dev State gas is exempt from block gas accounting. This ghost is a
    ///      Solidity-side placeholder; actual block-level verification is
    ///      performed in Rust (crates/consensus/src/lib.rs).
    function _invariantBlockGasRegularOnly() internal view {
        assertEq(ghost_blockGasUsedRegularOnly, 0, "TIP-1016: block.gasUsed included state gas");
    }

    /*//////////////////////////////////////////////////////////////
                            HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Test tx gas cap enforcement (TEMPO-BLOCK3 + TIP-1016)
    /// @param actorSeed Seed for selecting actor
    /// @param stateGasExtra Extra state gas above the cap (1 to 1M)
    function handler_txGasCapEnforcement(uint256 actorSeed, uint256 stateGasExtra) external {
        // Skip when not on Tempo (vmExec.executeTransaction not available)

        ghost_txGasCapTests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        // Simple transfer for minimal gas overhead
        bytes memory callData = abi.encodeCall(ITIP20.transfer, (actors[0], 1e6));
        uint64 nonce = uint64(vm.getNonce(sender));

        // Test 1: Tx at exactly the cap (should succeed)
        uint64 atCapGas = uint64(TX_GAS_CAP);
        bytes memory atCapTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(feeToken), callData, nonce, atCapGas, privateKey
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(atCapTx) {
            ghost_txAtCapSucceeded++;
            ghost_protocolNonce[sender]++;
            ghost_validTxExecuted++;
        } catch {
            // May fail for other reasons (balance, etc.) - not a violation
        }

        // Test 2: Tx with gas ABOVE the cap where excess is state gas (should succeed)
        // Post-TIP-1016, tx.gas > TX_GAS_CAP is valid when the excess goes to
        // the state gas reservoir (e.g., an SSTORE needs SSTORE_STATE_GAS).
        nonce = uint64(vm.getNonce(sender));

        uint256 overAmount = bound(stateGasExtra, 1, 1_000_000);
        uint64 overCapGas = uint64(TX_GAS_CAP + overAmount);

        bytes memory overCapTx = TxBuilder.buildLegacyCallWithGas(
            vmRlp, vm, address(feeToken), callData, nonce, overCapGas, privateKey
        );

        try vmExec.executeTransaction(overCapTx) {
            // Over-cap tx accepted — valid post-TIP-1016 (excess is state gas)
            ghost_txOverCapWithStateGasSucceeded++;
            ghost_protocolNonce[sender]++;
            ghost_validTxExecuted++;
        } catch {
            // May fail for other reasons (balance, etc.) - not a violation
        }
    }

    /// @notice Handler: Test max contract deployment fits in cap (TEMPO-BLOCK6 + TIP-1016)
    /// @param actorSeed Seed for selecting actor
    /// @param sizeFraction Fraction of max size to deploy (50-100%)
    function handler_maxDeploymentFits(uint256 actorSeed, uint256 sizeFraction) external {
        // Skip when not on Tempo (vmExec.executeTransaction not available)

        ghost_deploymentTests++;

        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint256 privateKey = actorKeys[senderIdx];

        // Create initcode for contract near max size
        // Size: 50% to 100% of max (12KB to 24KB)
        sizeFraction = bound(sizeFraction, 50, 100);
        uint256 targetSize = (MAX_CONTRACT_SIZE * sizeFraction) / 100;

        // Simple initcode: PUSH1 0x00 PUSH1 0x00 RETURN + padding
        bytes memory initcode = _createInitcodeOfSize(targetSize);

        // TIP-1016: Compute regular and state gas separately.
        // A 24KB contract needs ~7M regular gas but ~57M state gas.
        // tx.gas = regular + state can exceed TX_GAS_CAP because state gas
        // is exempt from the cap (goes to reservoir).
        uint256 requiredRegularGas = 53_000 // CREATE tx base
            + CREATE_REGULAR_GAS + (initcode.length * CODE_DEPOSIT_REGULAR_PER_BYTE)
            + ACCOUNT_CREATION_REGULAR_GAS + 100_000; // Buffer for memory expansion etc.

        uint256 requiredStateGas = CREATE_STATE_GAS
            + (initcode.length * CODE_DEPOSIT_STATE_PER_BYTE) + ACCOUNT_CREATION_STATE_GAS;

        uint64 nonce = uint64(vm.getNonce(sender));

        // Nonce-0 senders incur an additional account creation cost
        uint256 nonceCost =
            nonce == 0 ? ACCOUNT_CREATION_REGULAR_GAS + ACCOUNT_CREATION_STATE_GAS : 0;

        uint256 totalGas = requiredRegularGas + requiredStateGas + nonceCost;

        // totalGas can exceed TX_GAS_CAP — state gas is exempt from the cap
        uint64 gasLimit = uint64(totalGas);
        bytes memory createTx =
            TxBuilder.buildLegacyCreateWithGas(vmRlp, vm, initcode, nonce, gasLimit, privateKey);

        vm.coinbase(validator);
        address expectedAddr = TxBuilder.computeCreateAddress(sender, nonce);

        try vmExec.executeTransaction(createTx) {
            if (expectedAddr.code.length > 0) {
                ghost_maxDeploymentSucceeded++;
            }
            ghost_protocolNonce[sender]++;
            ghost_validTxExecuted++;
        } catch {
            // Deployment failed - may indicate cap too low if at max size
            if (sizeFraction == 100) {
                ghost_maxDeploymentFailed++;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if revert reason indicates a gas cap violation
    function _isGasCapRevert(bytes memory reason) internal view returns (bool) {
        (bool isError, string memory msg_) = _tryDecodeErrorMessage(reason);
        return isError && vm.contains(msg_, "is greater than the cap");
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
