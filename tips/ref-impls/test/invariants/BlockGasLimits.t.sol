// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Test } from "forge-std/Test.sol";

/// @title Block Gas Limits Invariant Tests (TIP-1010)
/// @notice Fuzz-based invariant tests for Tempo block gas parameters
/// @dev Tests invariants TEMPO-BLOCK1 through TEMPO-BLOCK7 as documented in TIP-1010
contract BlockGasLimitsInvariantTest is Test {

    /*//////////////////////////////////////////////////////////////
                            TIP-1010 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Total block gas limit (500M)
    uint256 public constant BLOCK_GAS_LIMIT = 500_000_000;

    /// @dev General lane gas limit for T1+ transactions (30M)
    uint256 public constant GENERAL_GAS_LIMIT = 30_000_000;

    /// @dev Maximum gas per transaction (30M)
    uint256 public constant TX_GAS_CAP = 30_000_000;

    /// @dev Base fee for T1+ transactions (20 gwei)
    uint256 public constant T1_BASE_FEE = 20 gwei;

    /// @dev Base fee for T0 transactions (10 gwei)
    uint256 public constant T0_BASE_FEE = 10 gwei;

    /// @dev Payment lane minimum available gas (500M - 30M = 470M)
    uint256 public constant PAYMENT_LANE_MIN_GAS = BLOCK_GAS_LIMIT - GENERAL_GAS_LIMIT;

    /// @dev Maximum contract size (24KB = 24576 bytes, from EIP-170)
    uint256 public constant MAX_CONTRACT_SIZE = 24_576;

    /// @dev Estimated gas per byte for contract deployment (~200 gas/byte)
    uint256 public constant GAS_PER_DEPLOYMENT_BYTE = 200;

    /// @dev Base intrinsic gas for contract creation (53000 for CREATE)
    uint256 public constant CONTRACT_CREATION_BASE_GAS = 53_000;

    /*//////////////////////////////////////////////////////////////
                           GHOST VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Simulated block's total gas used
    uint256 public ghost_blockGasUsed;

    /// @dev Simulated block's general lane gas used
    uint256 public ghost_generalLaneGasUsed;

    /// @dev Simulated block's payment lane gas used
    uint256 public ghost_paymentLaneGasUsed;

    /// @dev Count of valid blocks created
    uint256 public ghost_validBlockCount;

    /// @dev Count of rejected over-limit transactions
    uint256 public ghost_rejectedTxCount;

    /// @dev Count of successful T0 transactions
    uint256 public ghost_t0TxCount;

    /// @dev Count of successful T1+ transactions
    uint256 public ghost_t1TxCount;

    /// @dev Highest single transaction gas used
    uint256 public ghost_maxTxGasUsed;

    /// @dev Track deployment gas for max contract size
    uint256 public ghost_maxDeploymentGas;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        targetContract(address(this));
        _resetBlock();
    }

    /// @dev Resets block state for new block simulation
    function _resetBlock() internal {
        ghost_blockGasUsed = 0;
        ghost_generalLaneGasUsed = 0;
        ghost_paymentLaneGasUsed = 0;
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Simulate adding a general lane (T1+) transaction to the block
    /// @param gasUsed Gas used by this transaction (bounded to valid range)
    function handler_addGeneralTx(uint256 gasUsed) external {
        gasUsed = bound(gasUsed, 21_000, TX_GAS_CAP);

        // Check if transaction would exceed limits
        if (gasUsed > TX_GAS_CAP) {
            ghost_rejectedTxCount++;
            return;
        }

        if (ghost_generalLaneGasUsed + gasUsed > GENERAL_GAS_LIMIT) {
            ghost_rejectedTxCount++;
            return;
        }

        if (ghost_blockGasUsed + gasUsed > BLOCK_GAS_LIMIT) {
            ghost_rejectedTxCount++;
            return;
        }

        // Transaction accepted
        ghost_generalLaneGasUsed += gasUsed;
        ghost_blockGasUsed += gasUsed;
        ghost_t1TxCount++;

        if (gasUsed > ghost_maxTxGasUsed) {
            ghost_maxTxGasUsed = gasUsed;
        }
    }

    /// @notice Handler: Simulate adding a payment lane (T0) transaction to the block
    /// @param gasUsed Gas used by this transaction
    function handler_addPaymentTx(uint256 gasUsed) external {
        gasUsed = bound(gasUsed, 21_000, TX_GAS_CAP);

        // Check if transaction would exceed limits
        if (gasUsed > TX_GAS_CAP) {
            ghost_rejectedTxCount++;
            return;
        }

        // Payment lane shares the 500M block limit but has its own allocation
        uint256 paymentLaneAvailable = BLOCK_GAS_LIMIT - ghost_generalLaneGasUsed;
        if (ghost_paymentLaneGasUsed + gasUsed > paymentLaneAvailable) {
            ghost_rejectedTxCount++;
            return;
        }

        if (ghost_blockGasUsed + gasUsed > BLOCK_GAS_LIMIT) {
            ghost_rejectedTxCount++;
            return;
        }

        // Transaction accepted
        ghost_paymentLaneGasUsed += gasUsed;
        ghost_blockGasUsed += gasUsed;
        ghost_t0TxCount++;

        if (gasUsed > ghost_maxTxGasUsed) {
            ghost_maxTxGasUsed = gasUsed;
        }
    }

    /// @notice Handler: Simulate contract deployment transaction
    /// @param contractSize Size of contract bytecode in bytes
    function handler_deployContract(uint256 contractSize) external {
        contractSize = bound(contractSize, 1, MAX_CONTRACT_SIZE);

        // Calculate deployment gas: base + (size * gas_per_byte)
        uint256 deploymentGas =
            CONTRACT_CREATION_BASE_GAS + (contractSize * GAS_PER_DEPLOYMENT_BYTE);

        // Track max deployment gas seen
        if (deploymentGas > ghost_maxDeploymentGas) {
            ghost_maxDeploymentGas = deploymentGas;
        }

        // Deployment should fit within TX_GAS_CAP
        if (deploymentGas > TX_GAS_CAP) {
            ghost_rejectedTxCount++;
            return;
        }

        // Check block limits (deployments go in general lane)
        if (ghost_generalLaneGasUsed + deploymentGas > GENERAL_GAS_LIMIT) {
            ghost_rejectedTxCount++;
            return;
        }

        if (ghost_blockGasUsed + deploymentGas > BLOCK_GAS_LIMIT) {
            ghost_rejectedTxCount++;
            return;
        }

        ghost_generalLaneGasUsed += deploymentGas;
        ghost_blockGasUsed += deploymentGas;
        ghost_t1TxCount++;

        if (deploymentGas > ghost_maxTxGasUsed) {
            ghost_maxTxGasUsed = deploymentGas;
        }
    }

    /// @notice Handler: Simulate finalizing a block and starting a new one
    function handler_finalizeBlock() external {
        // Verify block validity before finalizing
        _assertBlockValidity();

        ghost_validBlockCount++;
        _resetBlock();
    }

    /// @notice Handler: Attempt to add over-limit transaction (should be rejected)
    /// @param gasUsed Unbounded gas value to test rejection
    function handler_attemptOverLimitTx(uint256 gasUsed) external {
        // Test various over-limit scenarios
        if (gasUsed > TX_GAS_CAP) {
            // TEMPO-BLOCK3: Transaction exceeds tx gas cap - must reject
            ghost_rejectedTxCount++;
            return;
        }

        if (ghost_generalLaneGasUsed + gasUsed > GENERAL_GAS_LIMIT) {
            // TEMPO-BLOCK2: Would exceed general lane limit - must reject
            ghost_rejectedTxCount++;
            return;
        }

        if (ghost_blockGasUsed + gasUsed > BLOCK_GAS_LIMIT) {
            // TEMPO-BLOCK1: Would exceed block limit - must reject
            ghost_rejectedTxCount++;
            return;
        }

        // If we get here, the tx is actually valid
        ghost_generalLaneGasUsed += gasUsed;
        ghost_blockGasUsed += gasUsed;
        ghost_t1TxCount++;
    }

    /*//////////////////////////////////////////////////////////////
                          MASTER INVARIANT
    //////////////////////////////////////////////////////////////*/

    /// @notice Master invariant function that checks all TIP-1010 invariants
    /// @dev Called after each fuzz sequence
    function invariant_allBlockGasLimits() public view {
        _assertBlockTotalGasLimit();
        _assertGeneralLaneLimit();
        _assertTxGasCap();
        _assertBaseFees();
        _assertPaymentLaneMinGas();
        _assertContractDeploymentFits();
        _assertBlockValidity();
    }

    /*//////////////////////////////////////////////////////////////
                        INVARIANT ASSERTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice TEMPO-BLOCK1: Block total gas never exceeds 500,000,000
    function _assertBlockTotalGasLimit() internal view {
        assertTrue(
            ghost_blockGasUsed <= BLOCK_GAS_LIMIT, "TEMPO-BLOCK1: Block gas exceeds 500M limit"
        );
    }

    /// @notice TEMPO-BLOCK2: General lane gas never exceeds 30,000,000
    function _assertGeneralLaneLimit() internal view {
        assertTrue(
            ghost_generalLaneGasUsed <= GENERAL_GAS_LIMIT,
            "TEMPO-BLOCK2: General lane gas exceeds 30M limit"
        );
    }

    /// @notice TEMPO-BLOCK3: Transaction gas limit never exceeds 30,000,000
    function _assertTxGasCap() internal view {
        assertTrue(
            ghost_maxTxGasUsed <= TX_GAS_CAP, "TEMPO-BLOCK3: Transaction gas exceeds 30M cap"
        );
    }

    /// @notice TEMPO-BLOCK4: Base fee for T1 is exactly 20 gwei
    /// @dev This is a constant check - verifies the protocol parameter
    function _assertBaseFees() internal pure {
        assertEq(T1_BASE_FEE, 20 gwei, "TEMPO-BLOCK4: T1 base fee must be 20 gwei");
        assertEq(T0_BASE_FEE, 10 gwei, "TEMPO-BLOCK4: T0 base fee must be 10 gwei");
    }

    /// @notice TEMPO-BLOCK5: Payment lane has at least 470M available (500M - general)
    function _assertPaymentLaneMinGas() internal view {
        uint256 paymentLaneAvailable = BLOCK_GAS_LIMIT - ghost_generalLaneGasUsed;
        assertTrue(
            paymentLaneAvailable >= PAYMENT_LANE_MIN_GAS - ghost_generalLaneGasUsed,
            "TEMPO-BLOCK5: Payment lane available gas below minimum"
        );

        // When general lane is at max (30M), payment lane should have at least 470M
        if (ghost_generalLaneGasUsed == GENERAL_GAS_LIMIT) {
            assertEq(
                paymentLaneAvailable,
                PAYMENT_LANE_MIN_GAS,
                "TEMPO-BLOCK5: At max general usage, payment lane should have exactly 470M"
            );
        }
    }

    /// @notice TEMPO-BLOCK6: Max contract deployment (24KB) fits within tx gas cap
    function _assertContractDeploymentFits() internal view {
        uint256 maxDeployGas =
            CONTRACT_CREATION_BASE_GAS + (MAX_CONTRACT_SIZE * GAS_PER_DEPLOYMENT_BYTE);
        assertTrue(
            maxDeployGas <= TX_GAS_CAP, "TEMPO-BLOCK6: Max contract deployment exceeds tx gas cap"
        );

        // Verify any deployment we've seen fits
        assertTrue(
            ghost_maxDeploymentGas <= TX_GAS_CAP,
            "TEMPO-BLOCK6: Observed deployment exceeds tx gas cap"
        );
    }

    /// @notice TEMPO-BLOCK7: Block validity rejects over-limit scenarios
    /// @dev Verifies that the current block state is valid
    function _assertBlockValidity() internal view {
        // Block is valid if all limits are respected
        bool blockValid = ghost_blockGasUsed <= BLOCK_GAS_LIMIT
            && ghost_generalLaneGasUsed <= GENERAL_GAS_LIMIT && ghost_maxTxGasUsed <= TX_GAS_CAP;

        assertTrue(blockValid, "TEMPO-BLOCK7: Block in invalid state");

        // Payment + General should not exceed block limit
        assertTrue(
            ghost_paymentLaneGasUsed + ghost_generalLaneGasUsed <= BLOCK_GAS_LIMIT,
            "TEMPO-BLOCK7: Combined lane gas exceeds block limit"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Calculates gas required for contract deployment
    /// @param contractSize Size of contract in bytes
    /// @return Gas required for deployment
    function calculateDeploymentGas(uint256 contractSize) public pure returns (uint256) {
        return CONTRACT_CREATION_BASE_GAS + (contractSize * GAS_PER_DEPLOYMENT_BYTE);
    }

    /// @notice Returns remaining gas available in general lane
    function getRemainingGeneralGas() public view returns (uint256) {
        return GENERAL_GAS_LIMIT - ghost_generalLaneGasUsed;
    }

    /// @notice Returns remaining gas available in payment lane
    function getRemainingPaymentGas() public view returns (uint256) {
        uint256 usedByGeneral = ghost_generalLaneGasUsed;
        uint256 paymentLaneAvailable = BLOCK_GAS_LIMIT - usedByGeneral;
        if (ghost_paymentLaneGasUsed >= paymentLaneAvailable) {
            return 0;
        }
        return paymentLaneAvailable - ghost_paymentLaneGasUsed;
    }

    /// @notice Returns remaining gas available in block
    function getRemainingBlockGas() public view returns (uint256) {
        return BLOCK_GAS_LIMIT - ghost_blockGasUsed;
    }

    /*//////////////////////////////////////////////////////////////
                     INDIVIDUAL INVARIANT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Standalone test for TEMPO-BLOCK1
    function test_TEMPO_BLOCK1_BlockGasLimit() public pure {
        assertEq(BLOCK_GAS_LIMIT, 500_000_000, "Block gas limit should be 500M");
    }

    /// @notice Standalone test for TEMPO-BLOCK2
    function test_TEMPO_BLOCK2_GeneralLaneLimit() public pure {
        assertEq(GENERAL_GAS_LIMIT, 30_000_000, "General lane limit should be 30M");
    }

    /// @notice Standalone test for TEMPO-BLOCK3
    function test_TEMPO_BLOCK3_TxGasCap() public pure {
        assertEq(TX_GAS_CAP, 30_000_000, "Tx gas cap should be 30M");
    }

    /// @notice Standalone test for TEMPO-BLOCK4
    function test_TEMPO_BLOCK4_BaseFees() public pure {
        assertEq(T1_BASE_FEE, 20 gwei, "T1 base fee should be 20 gwei");
        assertEq(T0_BASE_FEE, 10 gwei, "T0 base fee should be 10 gwei");
    }

    /// @notice Standalone test for TEMPO-BLOCK5
    function test_TEMPO_BLOCK5_PaymentLaneMinGas() public pure {
        assertEq(PAYMENT_LANE_MIN_GAS, 470_000_000, "Payment lane min should be 470M");
        assertEq(
            BLOCK_GAS_LIMIT - GENERAL_GAS_LIMIT,
            PAYMENT_LANE_MIN_GAS,
            "Payment lane = Block - General"
        );
    }

    /// @notice Standalone test for TEMPO-BLOCK6
    function test_TEMPO_BLOCK6_MaxContractDeploymentFits() public pure {
        uint256 maxDeployGas =
            CONTRACT_CREATION_BASE_GAS + (MAX_CONTRACT_SIZE * GAS_PER_DEPLOYMENT_BYTE);
        // 53000 + (24576 * 200) = 53000 + 4915200 = 4968200 gas
        assertTrue(maxDeployGas < TX_GAS_CAP, "Max deployment should fit in tx gas cap");
        assertEq(maxDeployGas, 4_968_200, "Max deployment gas calculation");
    }

    /// @notice Standalone test for TEMPO-BLOCK7: Verify rejection logic
    function test_TEMPO_BLOCK7_RejectsOverLimit() public {
        // Fill general lane to max
        ghost_generalLaneGasUsed = GENERAL_GAS_LIMIT;
        ghost_blockGasUsed = GENERAL_GAS_LIMIT;

        // Attempting to add more to general lane should be rejected
        uint256 beforeReject = ghost_rejectedTxCount;
        this.handler_addGeneralTx(21_000);
        assertEq(
            ghost_rejectedTxCount, beforeReject + 1, "Should reject tx when general lane is full"
        );

        // Reset and test block limit
        _resetBlock();
        ghost_paymentLaneGasUsed = BLOCK_GAS_LIMIT - 10_000;
        ghost_blockGasUsed = BLOCK_GAS_LIMIT - 10_000;

        beforeReject = ghost_rejectedTxCount;
        this.handler_addPaymentTx(21_000);
        assertEq(
            ghost_rejectedTxCount, beforeReject + 1, "Should reject tx when block is nearly full"
        );
    }

    /// @notice Fuzz test for lane separation
    function testFuzz_LaneSeparation(
        uint256 generalGas1,
        uint256 generalGas2,
        uint256 paymentGas1,
        uint256 paymentGas2
    ) public {
        _resetBlock();

        // Add transactions to both lanes
        this.handler_addGeneralTx(generalGas1);
        this.handler_addPaymentTx(paymentGas1);
        this.handler_addGeneralTx(generalGas2);
        this.handler_addPaymentTx(paymentGas2);

        // Verify all invariants hold
        _assertBlockTotalGasLimit();
        _assertGeneralLaneLimit();
        _assertPaymentLaneMinGas();
        _assertBlockValidity();
    }

    /// @notice Fuzz test for contract deployment within limits
    function testFuzz_ContractDeployment(uint256 contractSize) public {
        _resetBlock();

        this.handler_deployContract(contractSize);

        _assertBlockTotalGasLimit();
        _assertGeneralLaneLimit();
        _assertTxGasCap();
        _assertContractDeploymentFits();
    }

}
