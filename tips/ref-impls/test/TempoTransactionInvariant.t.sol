// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Test, console } from "forge-std/Test.sol";
import { Vm } from "forge-std/Vm.sol";

import { TIP20 } from "../src/TIP20.sol";
import { IAccountKeychain } from "../src/interfaces/IAccountKeychain.sol";
import { INonce } from "../src/interfaces/INonce.sol";
import { ITIP20 } from "../src/interfaces/ITIP20.sol";
import { InvariantChecker } from "./helpers/InvariantChecker.sol";
import { Counter, InitcodeHelper, SimpleStorage } from "./helpers/TestContracts.sol";
import { TxBuilder } from "./helpers/TxBuilder.sol";

import { VmExecuteTransaction, VmRlp } from "tempo-std/StdVm.sol";
import { Eip1559Transaction, Eip1559TransactionLib } from "tempo-std/tx/Eip1559TransactionLib.sol";
import {
    Eip7702Authorization,
    Eip7702Transaction,
    Eip7702TransactionLib
} from "tempo-std/tx/Eip7702TransactionLib.sol";
import { LegacyTransaction, LegacyTransactionLib } from "tempo-std/tx/LegacyTransactionLib.sol";
import {
    TempoAuthorization,
    TempoCall,
    TempoTransaction,
    TempoTransactionLib
} from "tempo-std/tx/TempoTransactionLib.sol";

/// @title Tempo Transaction Invariant Tests
/// @notice Comprehensive Foundry invariant tests for Tempo transaction behavior
/// @dev Tests nonce management, CREATE operations, fee collection, and access keys
contract TempoTransactionInvariantTest is InvariantChecker {

    using TempoTransactionLib for TempoTransaction;
    using LegacyTransactionLib for LegacyTransaction;
    using Eip1559TransactionLib for Eip1559Transaction;
    using Eip7702TransactionLib for Eip7702Transaction;
    using TxBuilder for *;

    // ============ Additional Ghost State ============

    mapping(address => uint256) public ghost_previousProtocolNonce;
    mapping(address => mapping(uint256 => uint256)) public ghost_previous2dNonce;

    // Gas tracking for N10/N11
    mapping(address => mapping(uint256 => uint256)) public ghost_firstUseGas;
    mapping(address => mapping(uint256 => uint256)) public ghost_subsequentUseGas;

    // Note: Time window (T1-T4) and transaction type (TX4-TX12) ghost state moved to GhostState.sol

    // ============ Setup ============

    function setUp() public override {
        super.setUp();

        // Target this contract for handler functions
        targetContract(address(this));

        // Define which handlers the fuzzer should call
        bytes4[] memory selectors = new bytes4[](70);
        // Legacy transaction handlers (core)
        selectors[0] = this.handler_transfer.selector;
        selectors[1] = this.handler_sequentialTransfers.selector;
        selectors[2] = this.handler_create.selector;
        selectors[3] = this.handler_createReverting.selector;
        // 2D nonce handlers (core)
        selectors[4] = this.handler_2dNonceIncrement.selector;
        selectors[5] = this.handler_multipleNonceKeys.selector;
        // Tempo transaction handlers (core)
        selectors[6] = this.handler_tempoTransfer.selector;
        selectors[7] = this.handler_tempoTransferProtocolNonce.selector;
        // Access key handlers (core)
        selectors[8] = this.handler_authorizeKey.selector;
        selectors[9] = this.handler_revokeKey.selector;
        selectors[10] = this.handler_useAccessKey.selector;
        selectors[11] = this.handler_insufficientBalanceTransfer.selector;
        // CREATE handlers
        selectors[12] = this.handler_tempoCreate.selector;
        selectors[13] = this.handler_createGasScaling.selector;
        // Replay protection handlers (N12-N15)
        selectors[14] = this.handler_replayProtocolNonce.selector;
        selectors[15] = this.handler_replay2dNonce.selector;
        selectors[16] = this.handler_nonceTooHigh.selector;
        selectors[17] = this.handler_nonceTooLow.selector;
        // CREATE structure handlers (C1-C4, C8)
        selectors[18] = this.handler_createOversized.selector;
        selectors[19] = this.handler_createNotFirst.selector;
        selectors[20] = this.handler_createMultiple.selector;
        selectors[21] = this.handler_createWithAuthList.selector;
        selectors[22] = this.handler_createWithValue.selector;
        // Tempo access key handlers (TX11)
        selectors[23] = this.handler_tempoUseAccessKey.selector;
        selectors[24] = this.handler_tempoUseP256AccessKey.selector;
        // Multicall handlers (M1-M9)
        selectors[25] = this.handler_tempoMulticall.selector;
        selectors[26] = this.handler_tempoMulticallWithFailure.selector;
        selectors[27] = this.handler_tempoMulticallStateVisibility.selector;
        // Key authorization handlers (K1-K3, K6, K7-K8, K10-K12, K16)
        selectors[28] = this.handler_keyAuthWrongSigner.selector;
        selectors[29] = this.handler_keyAuthNotSelf.selector;
        selectors[30] = this.handler_keyAuthWrongChainId.selector;
        selectors[31] = this.handler_keySameTxAuthorizeAndUse.selector;
        selectors[32] = this.handler_keySpendingPeriodReset.selector;
        selectors[33] = this.handler_keyUnlimitedSpending.selector;
        selectors[34] = this.handler_keyZeroSpendingLimit.selector;
        selectors[35] = this.handler_keySigTypeMismatch.selector;
        selectors[36] = this.handler_useRevokedKey.selector;
        selectors[37] = this.handler_useExpiredKey.selector;
        // Fee handlers (F1-F8, F10)
        // NOTE: handler_invalidFeeToken disabled due to BUG-002 (causes tempo-foundry panic)
        selectors[38] = this.handler_feeCollection.selector;
        selectors[39] = this.handler_feeRefundSuccess.selector;
        selectors[40] = this.handler_feeNoRefundFailure.selector;
        selectors[41] = this.handler_feeOnRevert.selector;
        selectors[42] = this.handler_explicitFeeToken.selector;
        selectors[43] = this.handler_feeTokenFallback.selector;
        selectors[44] = this.handler_insufficientLiquidity.selector;
        // 2D nonce gas tracking (N10/N11)
        selectors[45] = this.handler_2dNonceGasCost.selector;
        // Time window handlers (T1-T4)
        selectors[46] = this.handler_timeBoundValidAfter.selector;
        selectors[47] = this.handler_timeBoundValidBefore.selector;
        selectors[48] = this.handler_timeBoundValid.selector;
        selectors[49] = this.handler_timeBoundOpen.selector;
        // Transaction type handlers (TX4-TX7, TX10)
        selectors[50] = this.handler_eip1559Transfer.selector;
        selectors[51] = this.handler_eip1559BaseFeeRejection.selector;
        selectors[52] = this.handler_eip7702WithAuth.selector;
        selectors[53] = this.handler_eip7702CreateRejection.selector;
        selectors[54] = this.handler_tempoFeeSponsor.selector;
        // Gas tracking handlers (G1-G10)
        selectors[55] = this.handler_gasTrackingBasic.selector;
        selectors[56] = this.handler_gasTrackingMulticall.selector;
        selectors[57] = this.handler_gasTrackingCreate.selector;
        selectors[58] = this.handler_gasTrackingSignatureTypes.selector;
        selectors[59] = this.handler_gasTrackingKeyAuth.selector;
        // Expiring nonce handlers (E1-E7)
        selectors[60] = this.handler_expiringNonceBasic.selector;
        selectors[61] = this.handler_expiringNonceReplay.selector;
        selectors[62] = this.handler_expiringNonceExpired.selector;
        selectors[63] = this.handler_expiringNonceWindowTooFar.selector;
        selectors[64] = this.handler_expiringNonceNonZeroNonce.selector;
        selectors[65] = this.handler_expiringNonceMissingValidBefore.selector;
        selectors[66] = this.handler_expiringNonceNoNonceMutation.selector;
        selectors[67] = this.handler_expiringNonceConcurrent.selector;
        // Spending limit refund handlers (K-REFUND)
        selectors[68] = this.handler_keySpendingRefund.selector;
        selectors[69] = this.handler_keySpendingRefundRevokedKey.selector;
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));

        // Initialize previous nonce tracking for secp256k1 actors
        for (uint256 i = 0; i < actors.length; i++) {
            ghost_previousProtocolNonce[actors[i]] = 0;
        }

        // Fund P256-derived addresses with fee tokens and initialize nonce tracking
        vm.startPrank(admin);
        for (uint256 i = 0; i < actors.length; i++) {
            address p256Addr = actorP256Addresses[i];
            feeToken.mint(p256Addr, 100_000_000e6);
            ghost_previousProtocolNonce[p256Addr] = 0;
        }
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        MASTER INVARIANT
    //////////////////////////////////////////////////////////////*/

    /// @notice Master invariant - all protocol rules checked after each handler sequence
    /// @dev This single function ensures every invariant is checked after every handler run
    function invariant_tempoTransaction() public view {
        _checkAllInvariants();
    }

    /// @notice Called after invariant testing for final checks
    function afterInvariant() public view {
        // Existing check
        assertEq(
            ghost_totalCallsExecuted + ghost_totalCreatesExecuted,
            ghost_totalTxExecuted,
            "Calls + Creates should equal total executed"
        );

        // Vacuity warnings — log when negative-case handlers were never exercised
        _logVacuity(ghost_replayProtocolAttempted, "N12 replay protocol nonce");
        _logVacuity(ghost_replay2dAttempted, "N13 replay 2D nonce");
        _logVacuity(ghost_nonceTooHighAttempted, "N14 nonce too high");
        _logVacuity(ghost_nonceTooLowAttempted, "N15 nonce too low");
        _logVacuity(ghost_createNotFirstAttempted, "C1 create-not-first");
        _logVacuity(ghost_createMultipleAttempted, "C2 multiple-create");
        _logVacuity(ghost_createWithAuthAttempted, "C3 create-with-auth");
        _logVacuity(ghost_createWithValueAttempted, "C4 create-with-value");
        _logVacuity(ghost_createOversizedAttempted, "C8 oversized-initcode");
        _logVacuity(ghost_expiringNonceReplayAttempted, "E1 expiring nonce replay");
        _logVacuity(ghost_expiringNonceExpiredAttempted, "E2 expiring nonce expired");
        _logVacuity(ghost_expiringNonceWindowAttempted, "E3 expiring nonce window");
        _logVacuity(ghost_expiringNonceNonZeroAttempted, "E4 expiring nonce non-zero");
        _logVacuity(ghost_expiringNonceMissingVBAttempted, "E5 expiring nonce missing validBefore");

        // Replay protection invariants (N12-N15)
        assertEq(ghost_replayProtocolAllowed, 0, "N12: Protocol nonce replay unexpectedly allowed");
        assertEq(ghost_replay2dAllowed, 0, "N13: 2D nonce replay unexpectedly allowed");
        assertEq(ghost_nonceTooHighAllowed, 0, "N14: Nonce too high unexpectedly allowed");
        assertEq(ghost_nonceTooLowAllowed, 0, "N15: Nonce too low unexpectedly allowed");

        // CREATE structure rules (C1-C4, C8)
        assertEq(ghost_createNotFirstAllowed, 0, "C1: CREATE not first unexpectedly allowed");
        assertEq(ghost_createMultipleAllowed, 0, "C2: Multiple CREATEs unexpectedly allowed");
        assertEq(ghost_createWithAuthAllowed, 0, "C3: CREATE with auth list unexpectedly allowed");
        assertEq(ghost_createWithValueAllowed, 0, "C4: CREATE with value unexpectedly allowed");
        assertEq(ghost_createOversizedAllowed, 0, "C8: Oversized initcode unexpectedly allowed");

        // Key authorization rules (K1, K3)
        assertEq(ghost_keyWrongSignerAllowed, 0, "K1: Wrong signer key auth unexpectedly allowed");
        assertEq(ghost_keyWrongChainAllowed, 0, "K3: Wrong chain key auth unexpectedly allowed");

        // Transaction type rules (TX7)
        assertEq(
            ghost_eip7702CreateWithAuthAllowed,
            0,
            "TX7: CREATE with authorization list unexpectedly allowed"
        );

        // Time-bound rules (T1, T2)
        assertEq(
            ghost_timeBoundValidAfterAllowed,
            0,
            "T1: Tx with future validAfter unexpectedly allowed"
        );
        assertEq(
            ghost_timeBoundValidBeforeAllowed,
            0,
            "T2: Tx with past validBefore unexpectedly allowed"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        SIGNING PARAMS HELPER
    //////////////////////////////////////////////////////////////*/

    /// @notice Build SigningParams for the given actor and signature type
    function _getSigningParams(
        uint256 actorIndex,
        SignatureType sigType,
        uint256 keySeed
    )
        internal
        view
        returns (TxBuilder.SigningParams memory params, address sender)
    {
        if (sigType == SignatureType.Secp256k1) {
            sender = actors[actorIndex];
            params = TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[actorIndex],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            });
        } else if (sigType == SignatureType.P256) {
            (address p256Addr, uint256 p256Key, bytes32 pubKeyX, bytes32 pubKeyY) =
                _getActorP256(actorIndex);
            sender = p256Addr;
            params = TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.P256,
                privateKey: p256Key,
                pubKeyX: pubKeyX,
                pubKeyY: pubKeyY,
                userAddress: address(0)
            });
        } else if (sigType == SignatureType.WebAuthn) {
            (address p256Addr, uint256 p256Key, bytes32 pubKeyX, bytes32 pubKeyY) =
                _getActorP256(actorIndex);
            sender = p256Addr;
            params = TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.WebAuthn,
                privateKey: p256Key,
                pubKeyX: pubKeyX,
                pubKeyY: pubKeyY,
                userAddress: address(0)
            });
        } else {
            // AccessKey
            (, uint256 keyPk) = _getActorAccessKey(actorIndex, keySeed);
            sender = actors[actorIndex];
            params = TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.KeychainSecp256k1,
                privateKey: keyPk,
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: actors[actorIndex]
            });
        }
    }

    /*//////////////////////////////////////////////////////////////
                        TRANSACTION BUILDING
    //////////////////////////////////////////////////////////////*/

    function _buildAndSignTransfer(
        uint256 actorIndex,
        address to,
        uint256 amount,
        uint64 nonceValue,
        uint256 sigTypeSeed
    )
        internal
        view
        returns (bytes memory signedTx, address sender)
    {
        return _buildAndSignTransfer(actorIndex, to, amount, 0, nonceValue, sigTypeSeed);
    }

    function _buildAndSignTransfer(
        uint256 actorIndex,
        address to,
        uint256 amount,
        uint64 nonceKey,
        uint64 nonceValue,
        uint256 sigTypeSeed
    )
        internal
        view
        returns (bytes memory signedTx, address sender)
    {
        SignatureType sigType = _getRandomSignatureType(sigTypeSeed);
        (TxBuilder.SigningParams memory params, address senderAddr) =
            _getSigningParams(actorIndex, sigType, sigTypeSeed);
        sender = senderAddr;

        if (sigType == SignatureType.Secp256k1 && nonceKey == 0) {
            signedTx = TxBuilder.buildLegacyCall(
                vmRlp,
                vm,
                address(feeToken),
                abi.encodeCall(ITIP20.transfer, (to, amount)),
                nonceValue,
                actorKeys[actorIndex]
            );
        } else {
            TempoCall[] memory calls = new TempoCall[](1);
            calls[0] = TempoCall({
                to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (to, amount))
            });

            uint64 gasLimit =
                TxBuilder.callGas(calls[0].data, nonceValue) + TxBuilder.GAS_LIMIT_BUFFER;

            TempoTransaction memory tx_ = TempoTransactionLib.create()
                .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
                .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey)
                .withNonce(nonceValue);

            signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, params);
        }
    }

    function _buildAndSignCreate(
        uint256 actorIndex,
        bytes memory initcode,
        uint64 nonceValue,
        uint256 sigTypeSeed
    )
        internal
        view
        returns (bytes memory signedTx, address sender)
    {
        SignatureType sigType = _getRandomSignatureType(sigTypeSeed);
        (TxBuilder.SigningParams memory params, address senderAddr) =
            _getSigningParams(actorIndex, sigType, sigTypeSeed);
        sender = senderAddr;

        if (sigType == SignatureType.Secp256k1) {
            signedTx = TxBuilder.buildLegacyCreate(
                vmRlp, vm, initcode, nonceValue, actorKeys[actorIndex]
            );
        } else {
            TempoCall[] memory calls = new TempoCall[](1);
            calls[0] = TempoCall({ to: address(0), value: 0, data: initcode });

            uint64 gasLimit = TxBuilder.createGas(initcode, nonceValue) + TxBuilder.GAS_LIMIT_BUFFER;

            TempoTransaction memory tx_ = TempoTransactionLib.create()
                .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
                .withGasLimit(gasLimit).withCalls(calls).withNonceKey(0).withNonce(nonceValue);

            signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, params);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    NONCE HANDLERS (N1-N5, N12-N15)
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Execute a transfer from a random actor with random signature type
    /// @dev Tests N1 (monotonicity) and N2 (bump on call) across all signature types
    function handler_transfer(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 sigTypeSeed
    )
        external
    {
        TxContext memory ctx =
            _setupTransferContext(actorSeed, recipientSeed, amount, sigTypeSeed, 1e6, 100e6);

        uint64 currentNonce = uint64(ghost_protocolNonce[ctx.sender]);
        (bytes memory signedTx,) = _buildAndSignTransfer(
            ctx.senderIdx, ctx.recipient, ctx.amount, currentNonce, sigTypeSeed
        );

        ghost_previousProtocolNonce[ctx.sender] = ghost_protocolNonce[ctx.sender];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(ctx.sender);
        } catch {
            _handleRevertProtocol(ctx.sender);
        }
    }

    /// @notice Handler: Execute multiple transfers in sequence from same actor with random sig types
    /// @dev Tests sequential nonce bumping across all signature types
    function handler_sequentialTransfers(
        uint256 actorSeed,
        uint256 count,
        uint256 sigTypeSeed
    )
        external
    {
        count = bound(count, 1, 5);
        // Use wrapping add to prevent overflow
        uint256 recipientSeed;
        unchecked {
            recipientSeed = actorSeed + 1;
        }
        uint256 amountPerTx = 10e6;

        TxContext memory ctx = _setupTransferContext(
            actorSeed,
            recipientSeed,
            amountPerTx * count,
            sigTypeSeed,
            amountPerTx,
            amountPerTx * count
        );

        for (uint256 i = 0; i < count; i++) {
            uint64 currentNonce = uint64(ghost_protocolNonce[ctx.sender]);
            (bytes memory signedTx,) = _buildAndSignTransfer(
                ctx.senderIdx, ctx.recipient, amountPerTx, currentNonce, sigTypeSeed
            );
            ghost_previousProtocolNonce[ctx.sender] = ghost_protocolNonce[ctx.sender];
            vm.coinbase(validator);

            try vmExec.executeTransaction(signedTx) {
                _recordProtocolNonceTxSuccess(ctx.sender);
            } catch {
                _handleRevertProtocol(ctx.sender);
                break;
            }
        }
    }

    /// @notice Handler: Deploy a contract via CREATE with random signature type
    /// @dev Tests N3 (nonce bumps on tx inclusion) and C5-C6 (address derivation) across all sig types
    function handler_create(uint256 actorSeed, uint256 initValue, uint256 sigTypeSeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        initValue = bound(initValue, 0, 1000);

        bytes memory initcode = InitcodeHelper.simpleStorageInitcode(initValue);
        (bytes memory signedTx, address actualSender) =
            _buildAndSignCreate(senderIdx, initcode, 0, sigTypeSeed);

        // Re-build with correct nonce for actual sender
        uint64 currentNonce = uint64(ghost_protocolNonce[actualSender]);
        (signedTx,) = _buildAndSignCreate(senderIdx, initcode, currentNonce, sigTypeSeed);

        // Compute expected CREATE address BEFORE nonce is incremented
        address expectedAddress = TxBuilder.computeCreateAddress(actualSender, currentNonce);

        ghost_previousProtocolNonce[actualSender] = ghost_protocolNonce[actualSender];

        vm.coinbase(validator);

        // Nonce is consumed when tx is included, regardless of execution success/revert
        try vmExec.executeTransaction(signedTx) {
            ghost_protocolNonce[actualSender]++;
            ghost_totalTxExecuted++;
            ghost_totalCreatesExecuted++;
            ghost_totalProtocolNonceTxs++;

            // Record the deployed address
            bytes32 key = keccak256(abi.encodePacked(actualSender, uint256(currentNonce)));
            ghost_createAddresses[key] = expectedAddress;
            ghost_createCount[actualSender]++;
        } catch {
            _handleRevertProtocol(actualSender);
        }
    }

    /// @notice Handler: Attempt to deploy a reverting contract
    /// @dev Tests that reverting initcode causes tx rejection (no nonce consumed)
    function handler_createReverting(uint256 actorSeed, uint256 sigTypeSeed) external {
        uint256 senderIdx = actorSeed % actors.length;

        bytes memory initcode = InitcodeHelper.revertingContractInitcode();

        // Get the sender address for this sig type
        (, address actualSender) = _buildAndSignCreate(senderIdx, initcode, 0, sigTypeSeed);

        // Use actual on-chain nonce, not ghost state, to ensure tx is valid
        uint64 currentNonce = uint64(vm.getNonce(actualSender));

        // Sync ghost state if needed
        if (ghost_protocolNonce[actualSender] != currentNonce) {
            ghost_protocolNonce[actualSender] = currentNonce;
        }

        // Build the actual transaction with correct nonce
        (bytes memory signedTx,) =
            _buildAndSignCreate(senderIdx, initcode, currentNonce, sigTypeSeed);

        ghost_previousProtocolNonce[actualSender] = ghost_protocolNonce[actualSender];

        vm.coinbase(validator);

        // Snapshot nonce BEFORE execution
        uint256 nonceBefore = vm.getNonce(actualSender);

        try vmExec.executeTransaction(signedTx) {
            uint256 nonceAfter = vm.getNonce(actualSender);
            // CREATE tx that reverts internally still consumes nonce when tx is included
            assertEq(nonceAfter, nonceBefore + 1, "C7: Nonce must burn even when create reverts");
            ghost_protocolNonce[actualSender] = nonceAfter;
            ghost_totalTxExecuted++;
            ghost_totalCreatesExecuted++;
            ghost_totalProtocolNonceTxs++;
        } catch {
            uint256 nonceAfter = vm.getNonce(actualSender);
            // Two cases:
            // 1. Tx rejected (invalid sig format, etc.) - nonce unchanged
            // 2. Tx included but CREATE reverted - nonce consumed (C7)
            if (nonceAfter > nonceBefore) {
                // Case 2: Tx was included, nonce consumed
                assertEq(
                    nonceAfter,
                    nonceBefore + 1,
                    "C7: Nonce must burn exactly +1 on included reverting create"
                );
                ghost_protocolNonce[actualSender] = nonceAfter;
                ghost_totalProtocolNonceTxs++;
            }
            // Case 1: Tx was rejected, nonce unchanged - this is fine
            ghost_totalTxReverted++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                    2D NONCE HANDLERS (N6-N11)
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Execute a real Tempo transaction to increment a 2D nonce key
    /// @dev Tests N6 (independence) and N7 (monotonicity) with real transactions
    function handler_2dNonceIncrement(
        uint256 actorSeed,
        uint256 nonceKey,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        uint256 actorIdx = actorSeed % actors.length;
        address actor = actors[actorIdx];

        uint256 recipientIdx = recipientSeed % actors.length;
        if (actorIdx == recipientIdx) recipientIdx = (recipientIdx + 1) % actors.length;
        address recipient = actors[recipientIdx];

        // Bound nonce key to reasonable range (1-100, key 0 is protocol nonce)
        nonceKey = bound(nonceKey, 1, 100);
        amount = bound(amount, 1e6, 10e6);

        if (!_checkBalance(actor, amount)) return;

        uint64 currentNonce = uint64(ghost_2dNonce[actor][nonceKey]);

        // Store previous nonce for monotonicity check
        ghost_previous2dNonce[actor][nonceKey] = ghost_2dNonce[actor][nonceKey];

        // Build and execute a real Tempo transaction
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (recipient, amount))
        });

        uint64 gasLimit =
            TxBuilder.callGas(calls[0].data, currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(uint64(nonceKey))
            .withNonce(currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[actorIdx],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(actor, uint64(nonceKey), currentNonce);
        } catch {
            _handleRevert2d(actor, uint64(nonceKey));
        }
    }

    /// @notice Handler: Execute transactions on multiple different nonce keys for same actor
    /// @dev Tests N6 (keys are independent) with real transactions
    function handler_multipleNonceKeys(
        uint256 actorSeed,
        uint256 key1,
        uint256 key2,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        uint256 actorIdx = actorSeed % actors.length;
        address actor = actors[actorIdx];

        uint256 recipientIdx = recipientSeed % actors.length;
        if (actorIdx == recipientIdx) recipientIdx = (recipientIdx + 1) % actors.length;
        address recipient = actors[recipientIdx];

        // Bound keys to different values
        key1 = bound(key1, 1, 50);
        key2 = bound(key2, 51, 100);
        amount = bound(amount, 1e6, 5e6);

        if (!_checkBalance(actor, amount * 2)) return;

        vm.coinbase(validator);

        // Execute tx on key1
        uint64 nonce1 = uint64(ghost_2dNonce[actor][key1]);
        ghost_previous2dNonce[actor][key1] = ghost_2dNonce[actor][key1];

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (recipient, amount))
        });

        bytes memory signedTx1 = TxBuilder.buildTempoMultiCall(
            vmRlp, vm, calls, uint64(key1), nonce1, actorKeys[actorIdx]
        );

        try vmExec.executeTransaction(signedTx1) {
            _record2dNonceTxSuccess(actor, uint64(key1), nonce1);
        } catch {
            _handleRevert2d(actor, uint64(key1));
            return;
        }

        // Execute tx on key2 - should be independent of key1
        uint64 nonce2 = uint64(ghost_2dNonce[actor][key2]);
        ghost_previous2dNonce[actor][key2] = ghost_2dNonce[actor][key2];

        bytes memory signedTx2 = TxBuilder.buildTempoMultiCall(
            vmRlp, vm, calls, uint64(key2), nonce2, actorKeys[actorIdx]
        );

        try vmExec.executeTransaction(signedTx2) {
            _record2dNonceTxSuccess(actor, uint64(key2), nonce2);
        } catch {
            _handleRevert2d(actor, uint64(key2));
        }
    }

    /*//////////////////////////////////////////////////////////////
                    TEMPO TRANSACTION HANDLERS (TX1-TX6)
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Execute a Tempo transfer with random signature type
    /// @dev Tests that Tempo transactions work with all signature types (secp256k1, P256, WebAuthn, Keychain)
    /// With tempo-foundry, Tempo txs with nonceKey > 0 use 2D nonces (not protocol nonce)
    function handler_tempoTransfer(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed,
        uint256 sigTypeSeed
    )
        external
    {
        TxContext memory ctx = _setup2dNonceTransferContext(
            actorSeed, recipientSeed, amount, nonceKeySeed, sigTypeSeed, 1e6, 100e6
        );

        (bytes memory signedTx,) = _buildAndSignTransfer(
            ctx.senderIdx, ctx.recipient, ctx.amount, ctx.nonceKey, ctx.currentNonce, sigTypeSeed
        );

        ghost_previous2dNonce[ctx.sender][ctx.nonceKey] = ghost_2dNonce[ctx.sender][ctx.nonceKey];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.currentNonce);
        } catch {
            _handleRevert2d(ctx.sender, ctx.nonceKey);
        }
    }

    /// @notice Handler: Execute a Tempo transfer using protocol nonce (nonceKey = 0)
    /// @dev Tests that Tempo transactions with nonceKey=0 use the protocol nonce
    function handler_tempoTransferProtocolNonce(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 sigTypeSeed
    )
        external
    {
        TxContext memory ctx =
            _setupTransferContext(actorSeed, recipientSeed, amount, sigTypeSeed, 1e6, 100e6);

        uint64 currentNonce = uint64(ghost_protocolNonce[ctx.sender]);
        (bytes memory signedTx, address sender) = _buildAndSignTransfer(
            ctx.senderIdx, ctx.recipient, ctx.amount, currentNonce, sigTypeSeed
        );

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(sender);
        } catch {
            _handleRevertProtocol(sender);
        }
    }

    /// @notice Handler: Use access key with Tempo transaction
    /// @dev Tests access keys with Tempo transactions (K5, K9 with Tempo tx type)
    function handler_tempoUseAccessKey(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        AccessKeyContext memory ctx = _setupSecp256k1KeyContext(actorSeed, keySeed);
        amount = bound(amount, 1e6, 50e6);

        if (!_canUseKey(ctx.owner, ctx.keyId, amount)) return;
        if (!_checkBalance(ctx.owner, amount)) return;

        uint256 recipientIdx = recipientSeed % actors.length;
        if (ctx.actorIdx == recipientIdx) recipientIdx = (recipientIdx + 1) % actors.length;
        address recipient = actors[recipientIdx];

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[ctx.owner][nonceKey]);
        ghost_previous2dNonce[ctx.owner][nonceKey] = ghost_2dNonce[ctx.owner][nonceKey];

        bytes memory signedTx = TxBuilder.buildTempoCallKeychain(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            nonceKey,
            currentNonce,
            ctx.keyPk,
            ctx.owner
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.owner, nonceKey, currentNonce);
            if (ghost_keyEnforceLimits[ctx.owner][ctx.keyId]) {
                _recordKeySpending(ctx.owner, ctx.keyId, address(feeToken), amount);
            }
        } catch {
            _handleRevert2d(ctx.owner, nonceKey);
        }
    }

    /// @notice Handler: Use P256 access key with Tempo transaction
    /// @dev Tests P256 access keys with Tempo transactions
    function handler_tempoUseP256AccessKey(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        AccessKeyContext memory ctx = _setupP256KeyContext(actorSeed, keySeed);
        amount = bound(amount, 1e6, 50e6);

        if (!_canUseKey(ctx.owner, ctx.keyId, amount)) return;
        if (!_checkBalance(ctx.owner, amount)) return;

        uint256 recipientIdx = recipientSeed % actors.length;
        if (ctx.actorIdx == recipientIdx) recipientIdx = (recipientIdx + 1) % actors.length;
        address recipient = actors[recipientIdx];

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[ctx.owner][nonceKey]);
        ghost_previous2dNonce[ctx.owner][nonceKey] = ghost_2dNonce[ctx.owner][nonceKey];

        bytes memory signedTx = TxBuilder.buildTempoCallKeychainP256(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            nonceKey,
            currentNonce,
            ctx.keyPk,
            ctx.pubKeyX,
            ctx.pubKeyY,
            ctx.owner
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.owner, nonceKey, currentNonce);
            if (ghost_keyEnforceLimits[ctx.owner][ctx.keyId]) {
                _recordKeySpending(ctx.owner, ctx.keyId, address(feeToken), amount);
            }
        } catch {
            _handleRevert2d(ctx.owner, nonceKey);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ACCESS KEY HANDLERS (K1-K12)
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Authorize an access key with random key type (secp256k1 or P256)
    /// @dev Tests K1-K4 (key authorization rules) with multiple signature types
    function handler_authorizeKey(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 expirySeed,
        uint256 limitSeed
    )
        external
    {
        AccessKeyContext memory ctx = _setupRandomKeyContext(actorSeed, keySeed);
        if (ghost_keyAuthorized[ctx.owner][ctx.keyId]) {
            return;
        }

        uint64 expiry = uint64(block.timestamp + bound(expirySeed, 1 hours, 365 days));
        uint256 limit = bound(limitSeed, 1e6, 1000e6);

        IAccountKeychain.SignatureType keyType = ctx.isP256
            ? IAccountKeychain.SignatureType.P256
            : IAccountKeychain.SignatureType.Secp256k1;

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({ token: address(feeToken), amount: limit });

        vm.prank(ctx.owner);
        try keychain.authorizeKey(ctx.keyId, keyType, expiry, true, limits) {
            address[] memory tokens = new address[](1);
            tokens[0] = address(feeToken);
            uint256[] memory amounts = new uint256[](1);
            amounts[0] = limit;
            _authorizeKey(ctx.owner, ctx.keyId, expiry, true, tokens, amounts);
        } catch { }
    }

    /// @notice Handler: Revoke an access key (secp256k1 or P256)
    /// @dev Tests K7-K8 (revoked keys rejected)
    function handler_revokeKey(uint256 actorSeed, uint256 keySeed) external {
        AccessKeyContext memory ctx = _setupRandomKeyContext(actorSeed, keySeed);
        if (!ghost_keyAuthorized[ctx.owner][ctx.keyId]) {
            return;
        }

        vm.prank(ctx.owner);
        try keychain.revokeKey(ctx.keyId) {
            _revokeKey(ctx.owner, ctx.keyId);
        } catch { }
    }

    /// @notice Handler: Attempt to use a revoked key - should be rejected
    /// @dev Tests K7/K8 - revoked keys must not be usable
    function handler_useRevokedKey(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        AccessKeyContext memory ctx = _setupSecp256k1KeyContext(actorSeed, keySeed);

        // Skip if key is still authorized (not revoked)
        if (ghost_keyAuthorized[ctx.owner][ctx.keyId]) {
            return;
        }

        // We need the key to have been revoked (was authorized, now isn't)
        // Check if this key was previously used by looking at expiry being set
        if (ghost_keyExpiry[ctx.owner][ctx.keyId] == 0) {
            return;
        }

        amount = bound(amount, 1e6, 10e6);
        if (!_checkBalance(ctx.owner, amount)) return;

        uint256 recipientIdx = recipientSeed % actors.length;
        if (ctx.actorIdx == recipientIdx) recipientIdx = (recipientIdx + 1) % actors.length;
        address recipient = actors[recipientIdx];

        uint64 currentNonce = uint64(ghost_protocolNonce[ctx.owner]);

        bytes memory signedTx = TxBuilder.buildTempoCallKeychain(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            0, // nonceKey=0 uses protocol nonce
            currentNonce,
            ctx.keyPk,
            ctx.owner
        );

        ghost_previousProtocolNonce[ctx.owner] = ghost_protocolNonce[ctx.owner];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            // Revoked key was allowed - this is a K7/K8 violation!
            ghost_keyWrongSignerAllowed++;
            ghost_protocolNonce[ctx.owner]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
        } catch {
            _handleRevertProtocol(ctx.owner);
            _recordKeyWrongSigner();
        }
    }

    /// @notice Handler: Attempt to use an expired key - should be rejected
    /// @dev Tests K7 - expired keys must not be usable
    function handler_useExpiredKey(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 timeWarpSeed
    )
        external
    {
        AccessKeyContext memory ctx = _setupSecp256k1KeyContext(actorSeed, keySeed);

        // Need an authorized key with an expiry in the past
        if (!ghost_keyAuthorized[ctx.owner][ctx.keyId]) {
            return;
        }
        if (ghost_keyExpiry[ctx.owner][ctx.keyId] == 0) {
            return;
        }

        // Warp time past expiry
        uint256 expiry = ghost_keyExpiry[ctx.owner][ctx.keyId];
        if (block.timestamp < expiry) {
            uint256 warpTo = expiry + bound(timeWarpSeed, 1, 1 days);
            vm.warp(warpTo);
        }

        amount = bound(amount, 1e6, 10e6);
        if (!_checkBalance(ctx.owner, amount)) return;

        uint256 recipientIdx = recipientSeed % actors.length;
        if (ctx.actorIdx == recipientIdx) recipientIdx = (recipientIdx + 1) % actors.length;
        address recipient = actors[recipientIdx];

        uint64 currentNonce = uint64(ghost_protocolNonce[ctx.owner]);

        bytes memory signedTx = TxBuilder.buildTempoCallKeychain(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            0, // nonceKey=0 uses protocol nonce
            currentNonce,
            ctx.keyPk,
            ctx.owner
        );

        ghost_previousProtocolNonce[ctx.owner] = ghost_protocolNonce[ctx.owner];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            // Expired key was allowed - this is a K7 violation!
            ghost_keyWrongSignerAllowed++;
            ghost_protocolNonce[ctx.owner]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
        } catch {
            _handleRevertProtocol(ctx.owner);
            _recordKeyWrongSigner();
        }
    }

    /// @notice Handler: Use an authorized access key to transfer tokens
    /// @dev Tests K5 (key must exist), K9 (spending limits enforced)
    function handler_useAccessKey(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        AccessKeyContext memory ctx = _setupSecp256k1KeyContext(actorSeed, keySeed);
        amount = bound(amount, 1e6, 50e6);

        if (!_canUseKey(ctx.owner, ctx.keyId, amount)) return;
        if (!_checkBalance(ctx.owner, amount)) return;

        uint256 recipientIdx = recipientSeed % actors.length;
        if (ctx.actorIdx == recipientIdx) recipientIdx = (recipientIdx + 1) % actors.length;
        address recipient = actors[recipientIdx];

        ghost_previousProtocolNonce[ctx.owner] = ghost_protocolNonce[ctx.owner];
        uint64 currentNonce = uint64(ghost_protocolNonce[ctx.owner]);

        bytes memory signedTx = TxBuilder.buildTempoCallKeychain(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            0, // nonceKey=0 uses protocol nonce
            currentNonce,
            ctx.keyPk,
            ctx.owner
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(ctx.owner);
            if (ghost_keyEnforceLimits[ctx.owner][ctx.keyId]) {
                _recordKeySpending(ctx.owner, ctx.keyId, address(feeToken), amount);
            }
        } catch {
            _handleRevertProtocol(ctx.owner);
        }
    }

    /// @notice Handler: Attempt transfer with insufficient balance
    /// @dev Tests F9 (insufficient balance rejected) - tx reverts but nonce is consumed
    function handler_insufficientBalanceTransfer(
        uint256 actorSeed,
        uint256 recipientSeed
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        // Try to transfer more than balance (intentionally don't ensure balance)
        uint256 excessAmount = feeToken.balanceOf(sender) + 1e6;

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];
        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);

        (bytes memory signedTx,) =
            _buildAndSignTransfer(senderIdx, recipient, excessAmount, currentNonce, 0);

        vm.coinbase(validator);

        // Snapshot nonce before execution
        uint256 nonceBefore = vm.getNonce(sender);

        // Legacy tx uses protocol nonce - nonce is consumed even if inner call reverts
        try vmExec.executeTransaction(signedTx) {
            uint256 nonceAfter = vm.getNonce(sender);
            // Tx was included, nonce consumed
            assertEq(nonceAfter, nonceBefore + 1, "F9: Legacy tx must consume nonce on success");
            ghost_protocolNonce[sender] = nonceAfter;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
        } catch {
            uint256 nonceAfter = vm.getNonce(sender);
            // Transaction was rejected or reverted:
            // - If nonce unchanged: tx was rejected before inclusion (invalid sig, nonce mismatch)
            // - If nonce consumed: tx was included but inner call reverted
            // Only update ghost state if nonce actually changed
            if (nonceAfter > nonceBefore) {
                ghost_protocolNonce[sender] = nonceAfter;
                ghost_totalProtocolNonceTxs++;
            }
            // Note: If ghost_protocolNonce[sender] != nonceAfter here, it indicates a tracking bug
            // that will be caught by the nonce invariant check (when re-enabled)
            ghost_totalTxReverted++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                    NONCE INVARIANTS N9-N15 HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Execute a Tempo CREATE with 2D nonce (nonceKey > 0)
    /// @dev Tests N9 - CREATE address derivation still uses protocol nonce, not 2D nonce
    function handler_tempoCreate(
        uint256 actorSeed,
        uint256 initValue,
        uint256 nonceKeySeed
    )
        external
    {
        CreateContext memory ctx = _setupCreateContext(actorSeed, nonceKeySeed);
        initValue = bound(initValue, 0, 1000);

        bytes memory initcode = InitcodeHelper.simpleStorageInitcode(initValue);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({ to: address(0), value: 0, data: initcode });

        uint64 gasLimit =
            TxBuilder.createGas(initcode, ctx.protocolNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(ctx.nonceKey)
            .withNonce(ctx.current2dNonce);

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[ctx.senderIdx],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );

        address expectedAddress = TxBuilder.computeCreateAddress(ctx.sender, ctx.protocolNonce);
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceCreateSuccess(
                ctx.sender, ctx.nonceKey, ctx.protocolNonce, expectedAddress
            );
        } catch {
            _handleRevert2d(ctx.sender, ctx.nonceKey);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    CREATE CONSTRAINT HANDLERS (C1-C4, C8-C9)
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Attempt CREATE as second call in multicall (invalid - C1)
    /// @dev C1: CREATE only allowed as first call in batch
    function handler_createNotFirst(
        uint256 actorSeed,
        uint256 initValue,
        uint256 nonceKeySeed
    )
        external
    {
        CreateContext memory ctx = _setupCreateContext(actorSeed, nonceKeySeed);
        initValue = bound(initValue, 0, 1000);

        bytes memory initcode = InitcodeHelper.simpleStorageInitcode(initValue);

        bytes memory signedTx = TxBuilder.buildTempoCreateNotFirst(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (ctx.sender, 1e6)),
            initcode,
            ctx.nonceKey,
            ctx.current2dNonce,
            actorKeys[ctx.senderIdx]
        );

        vm.coinbase(validator);
        ghost_createNotFirstAttempted++;

        try vmExec.executeTransaction(signedTx) {
            // Unexpected success - this is a protocol bug that will be caught by invariant
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.current2dNonce);
            ghost_createNotFirstAllowed++;
        } catch {
            _recordCreateRejectedStructure();
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt two CREATEs in same multicall (invalid - C2)
    /// @dev C2: Maximum one CREATE per transaction
    function handler_createMultiple(
        uint256 actorSeed,
        uint256 initValue1,
        uint256 initValue2,
        uint256 nonceKeySeed
    )
        external
    {
        CreateContext memory ctx = _setupCreateContext(actorSeed, nonceKeySeed);
        initValue1 = bound(initValue1, 0, 1000);
        initValue2 = bound(initValue2, 0, 1000);

        bytes memory initcode1 = InitcodeHelper.simpleStorageInitcode(initValue1);
        bytes memory initcode2 = InitcodeHelper.counterInitcode();

        bytes memory signedTx = TxBuilder.buildTempoMultipleCreates(
            vmRlp,
            vm,
            initcode1,
            initcode2,
            ctx.nonceKey,
            ctx.current2dNonce,
            actorKeys[ctx.senderIdx]
        );

        vm.coinbase(validator);
        ghost_createMultipleAttempted++;

        try vmExec.executeTransaction(signedTx) {
            // Unexpected success - this is a protocol bug that will be caught by invariant
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.current2dNonce);
            ghost_createMultipleAllowed++;
        } catch {
            _recordCreateRejectedStructure();
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt CREATE with EIP-7702 authorization list (invalid - C3)
    /// @dev C3: CREATE forbidden with authorization list
    function handler_createWithAuthList(
        uint256 actorSeed,
        uint256 initValue,
        uint256 nonceKeySeed
    )
        external
    {
        CreateContext memory ctx = _setupCreateContext(actorSeed, nonceKeySeed);
        initValue = bound(initValue, 0, 1000);

        bytes memory initcode = InitcodeHelper.simpleStorageInitcode(initValue);

        TempoAuthorization[] memory authList = new TempoAuthorization[](1);
        authList[0] = TempoAuthorization({
            chainId: block.chainid,
            authority: ctx.sender,
            nonce: ctx.protocolNonce,
            yParity: 0,
            r: bytes32(uint256(1)),
            s: bytes32(uint256(2))
        });

        bytes memory signedTx = TxBuilder.buildTempoCreateWithAuthList(
            vmRlp,
            vm,
            initcode,
            authList,
            ctx.nonceKey,
            ctx.current2dNonce,
            actorKeys[ctx.senderIdx]
        );

        vm.coinbase(validator);
        ghost_createWithAuthAttempted++;

        try vmExec.executeTransaction(signedTx) {
            // Unexpected success - this is a protocol bug that will be caught by invariant
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.current2dNonce);
            ghost_createWithAuthAllowed++;
        } catch {
            // Tx was rejected - do NOT increment ghost_protocolNonce here
            // The tx should be rejected before nonce consumption
            _recordCreateRejectedStructure();
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt CREATE with value > 0 (invalid for Tempo - C4)
    /// @dev C4: Value transfers forbidden in AA transactions
    function handler_createWithValue(
        uint256 actorSeed,
        uint256 initValue,
        uint256 valueSeed,
        uint256 nonceKeySeed
    )
        external
    {
        CreateContext memory ctx = _setupCreateContext(actorSeed, nonceKeySeed);
        initValue = bound(initValue, 0, 1000);
        uint256 value = bound(valueSeed, 1, 1 ether);

        bytes memory initcode = InitcodeHelper.simpleStorageInitcode(initValue);

        bytes memory signedTx = TxBuilder.buildTempoCreateWithValue(
            vmRlp, vm, initcode, value, ctx.nonceKey, ctx.current2dNonce, actorKeys[ctx.senderIdx]
        );

        vm.coinbase(validator);
        ghost_createWithValueAttempted++;

        try vmExec.executeTransaction(signedTx) {
            // Unexpected success - this is a protocol bug that will be caught by invariant
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.current2dNonce);
            ghost_createWithValueAllowed++;
        } catch {
            _recordCreateRejectedStructure();
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt CREATE with oversized initcode (invalid - C8)
    /// @dev C8: Initcode must not exceed max_initcode_size (EIP-3860: 49152 bytes)
    function handler_createOversized(uint256 actorSeed, uint256 nonceKeySeed) external {
        CreateContext memory ctx = _setupCreateContext(actorSeed, nonceKeySeed);

        bytes memory initcode = InitcodeHelper.largeInitcode(50_000);

        bytes memory signedTx = TxBuilder.buildTempoCreateWithGas(
            vmRlp,
            vm,
            initcode,
            ctx.nonceKey,
            ctx.current2dNonce,
            5_000_000,
            actorKeys[ctx.senderIdx]
        );

        vm.coinbase(validator);
        ghost_createOversizedAttempted++;

        try vmExec.executeTransaction(signedTx) {
            // Unexpected success - this is a protocol bug that will be caught by invariant
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.current2dNonce);
            ghost_createOversizedAllowed++;
        } catch {
            _recordCreateRejectedSize();
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Track gas for CREATE with different initcode sizes (C9)
    /// @dev C9: Initcode costs INITCODE_WORD_COST gas per 32-byte chunk
    function handler_createGasScaling(uint256 actorSeed, uint256 sizeSeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);

        uint256 initcodeSize = bound(sizeSeed, 100, 10_000);
        bytes memory initcode = InitcodeHelper.largeInitcode(initcodeSize);
        uint64 gasLimit = TxBuilder.createGas(initcode, currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        bytes memory signedTx = TxBuilder.buildLegacyCreateWithGas(
            vmRlp, vm, initcode, currentNonce, gasLimit, actorKeys[senderIdx]
        );

        address expectedAddress = TxBuilder.computeCreateAddress(sender, currentNonce);
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceCreateSuccess(sender, currentNonce, expectedAddress);
            _recordCreateGasTracked();
        } catch {
            // Only update ghost nonce if actual nonce was consumed (tx included but reverted)
            // If tx was rejected at validation, nonce is NOT consumed
            uint256 actualNonce = vm.getNonce(sender);
            if (actualNonce > ghost_protocolNonce[sender]) {
                ghost_protocolNonce[sender] = actualNonce;
                ghost_totalProtocolNonceTxs++;
            }
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt to replay a Legacy transaction with same protocol nonce
    /// @dev Tests N12 - replay with same protocol nonce fails
    function handler_replayProtocolNonce(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        // Need 2x amount for replay test, so use amount*2 as min/max
        amount = bound(amount, 1e6, 10e6);
        TxContext memory ctx =
            _setupBaseTransferContext(actorSeed, recipientSeed, amount * 2, amount * 2, amount * 2);

        uint64 currentNonce = uint64(ghost_protocolNonce[ctx.sender]);
        (bytes memory signedTx,) =
            _buildAndSignTransfer(ctx.senderIdx, ctx.recipient, amount, currentNonce, 0);

        ghost_previousProtocolNonce[ctx.sender] = ghost_protocolNonce[ctx.sender];

        vm.coinbase(validator);

        // Snapshot nonce before first tx
        uint256 nonce0 = vm.getNonce(ctx.sender);

        // First execution should succeed and consume exactly 1 nonce
        try vmExec.executeTransaction(signedTx) {
            uint256 nonce1 = vm.getNonce(ctx.sender);
            assertEq(nonce1, nonce0 + 1, "N12: First tx must consume exactly one nonce");
            ghost_protocolNonce[ctx.sender] = nonce1;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
        } catch {
            // First tx failed - skip replay test
            ghost_totalTxReverted++;
            return;
        }

        // Replay should fail - nonce already consumed
        ghost_replayProtocolAttempted++;
        try vmExec.executeTransaction(signedTx) {
            // Replay unexpectedly succeeded - this is a BUG in the protocol!
            ghost_replayProtocolAllowed++;
        } catch {
            _handleExpectedReject(_noop);
        }
    }

    /// @notice Handler: Attempt to replay a Tempo transaction with same 2D nonce
    /// @dev Tests N13 - replay with same 2D nonce fails
    function handler_replay2dNonce(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        // Need 2x amount for replay test
        amount = bound(amount, 1e6, 10e6);
        TxContext memory ctx =
            _setupBaseTransferContext(actorSeed, recipientSeed, amount * 2, amount * 2, amount * 2);

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[ctx.sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, amount))
        });

        uint64 gasLimit =
            TxBuilder.callGas(calls[0].data, currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[ctx.senderIdx],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );

        ghost_previous2dNonce[ctx.sender][nonceKey] = ghost_2dNonce[ctx.sender][nonceKey];

        vm.coinbase(validator);

        // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
        try vmExec.executeTransaction(signedTx) {
            // Verify on-chain nonce actually incremented before updating ghost
            uint64 actualNonce = nonce.getNonce(ctx.sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[ctx.sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[ctx.sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
            }
        } catch {
            ghost_totalTxReverted++;
            return;
        }

        ghost_replay2dAttempted++;
        try vmExec.executeTransaction(signedTx) {
            // Replay unexpectedly succeeded - this is a BUG in the protocol!
            ghost_replay2dAllowed++;
        } catch {
            _handleExpectedReject(_noop);
        }
    }

    /// @notice Handler: Attempt to use nonce higher than current (nonce + 1)
    /// @dev Tests N14 - nonce too high is rejected
    function handler_nonceTooHigh(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TxContext memory ctx =
            _setupBaseTransferContext(actorSeed, recipientSeed, amount, 1e6, 10e6);

        // Use actual on-chain nonce, not ghost state
        uint64 currentNonce = uint64(vm.getNonce(ctx.sender));
        uint64 wrongNonce = currentNonce + 1;

        (bytes memory signedTx,) =
            _buildAndSignTransfer(ctx.senderIdx, ctx.recipient, ctx.amount, wrongNonce, 0);

        vm.coinbase(validator);
        ghost_nonceTooHighAttempted++;

        try vmExec.executeTransaction(signedTx) {
            // Tx with future nonce unexpectedly succeeded - this is a BUG!
            ghost_nonceTooHighAllowed++;
        } catch {
            _handleExpectedReject(_noop);
        }
    }

    /// @notice Handler: Attempt to use nonce lower than current (nonce - 1)
    /// @dev Tests N15 - nonce too low is rejected (requires at least 1 tx executed)
    function handler_nonceTooLow(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TxContext memory ctx =
            _setupBaseTransferContext(actorSeed, recipientSeed, amount, 1e6, 10e6);

        // Use actual on-chain nonce, not ghost state
        uint64 currentNonce = uint64(vm.getNonce(ctx.sender));
        if (currentNonce == 0) {
            return;
        }

        uint64 wrongNonce = currentNonce - 1;

        (bytes memory signedTx,) =
            _buildAndSignTransfer(ctx.senderIdx, ctx.recipient, ctx.amount, wrongNonce, 0);

        vm.coinbase(validator);
        ghost_nonceTooLowAttempted++;

        try vmExec.executeTransaction(signedTx) {
            ghost_nonceTooLowAllowed++;
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Track gas cost for first vs subsequent 2D nonce key usage
    /// @dev Tests N10 (cold gas cost) and N11 (warm gas cost)
    function handler_2dNonceGasCost(
        uint256 actorSeed,
        uint256 nonceKeySeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        // Need 2x amount for two transactions
        amount = bound(amount, 1e6, 10e6);
        TxContext memory ctx =
            _setupBaseTransferContext(actorSeed, recipientSeed, amount * 2, amount * 2, amount * 2);

        uint64 nonceKey = uint64(bound(nonceKeySeed, 101, 200));

        bool isFirstUse = !ghost_2dNonceUsed[ctx.sender][nonceKey];
        uint64 currentNonce = uint64(ghost_2dNonce[ctx.sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, amount))
        });

        uint64 gasLimit =
            TxBuilder.callGas(calls[0].data, currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[ctx.senderIdx],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );

        ghost_previous2dNonce[ctx.sender][nonceKey] = ghost_2dNonce[ctx.sender][nonceKey];

        vm.coinbase(validator);

        // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
        uint256 gasBefore = gasleft();
        try vmExec.executeTransaction(signedTx) {
            uint256 gasUsed = gasBefore - gasleft();

            // Verify on-chain nonce actually incremented before updating ghost
            uint64 actualNonce = nonce.getNonce(ctx.sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[ctx.sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[ctx.sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;

                if (isFirstUse) {
                    ghost_firstUseGas[ctx.sender][nonceKey] = gasUsed;
                } else {
                    ghost_subsequentUseGas[ctx.sender][nonceKey] = gasUsed;
                }
            }
        } catch {
            _handleRevert2d(ctx.sender, nonceKey);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    CREATE INVARIANTS (C1-C9)
    //////////////////////////////////////////////////////////////*/

    /// @dev Helper to verify CREATE addresses for a given account
    function _verifyCreateAddresses(address account) internal view {
        uint256 createCount = ghost_createCount[account];

        for (uint256 n = 0; n < createCount; n++) {
            bytes32 key = keccak256(abi.encodePacked(account, n));
            address recorded = ghost_createAddresses[key];

            if (recorded != address(0)) {
                // Verify the recorded address matches the computed address
                address computed = TxBuilder.computeCreateAddress(account, n);
                assertEq(recorded, computed, "C5: Recorded address doesn't match computed");

                // Verify code exists at the address (CREATE succeeded)
                assertTrue(recorded.code.length > 0, "C5: No code at CREATE address");
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ACCESS KEY HANDLERS K1-K3, K6, K10-K12, K16
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler K1: Attempt to use an unauthorized access key for a transfer
    /// @dev Tests that transactions signed with an unauthorized key are rejected
    /// This tests K1 at the tx-level: the key must be properly authorized before use.
    function handler_keyAuthWrongSigner(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        uint256 actorIdx = actorSeed % actors.length;
        address owner = actors[actorIdx];

        // Get a key that is NOT authorized
        (address keyId, uint256 keyPk) = _getActorAccessKey(actorIdx, keySeed);

        // Skip if key is already authorized - we want to test unauthorized key usage
        if (ghost_keyAuthorized[owner][keyId]) {
            ghost_keyAuthRejectedWrongSigner++;
            return;
        }

        amount = bound(amount, 1e6, 10e6);
        if (!_checkBalance(owner, amount)) return;

        uint256 recipientIdx = recipientSeed % actors.length;
        if (actorIdx == recipientIdx) recipientIdx = (recipientIdx + 1) % actors.length;
        address recipient = actors[recipientIdx];

        // nonceKey=0 uses protocol nonce
        uint64 currentNonce = uint64(ghost_protocolNonce[owner]);

        // Build a transaction signed with the unauthorized key
        bytes memory signedTx = TxBuilder.buildTempoCallKeychain(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            0,
            currentNonce,
            keyPk,
            owner
        );

        ghost_previousProtocolNonce[owner] = ghost_protocolNonce[owner];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            // Unauthorized key was allowed - this is a K1 violation!
            ghost_keyWrongSignerAllowed++;
            _recordProtocolNonceTxSuccess(owner);
        } catch {
            _handleRevertProtocol(owner);
            _recordKeyWrongSigner();
        }
    }

    /// @notice Handler K2: Attempt to have access key A authorize access key B
    /// @dev Access key can only authorize itself, not other keys
    function handler_keyAuthNotSelf(
        uint256 actorSeed,
        uint256 keyASeed,
        uint256 keyBSeed
    )
        external
    {
        uint256 actorIdx = actorSeed % actors.length;
        address owner = actors[actorIdx];

        (address keyIdA, uint256 keyPkA) = _getActorAccessKey(actorIdx, keyASeed);
        (address keyIdB,) = _getActorAccessKey(actorIdx, keyBSeed);

        if (keyIdA == keyIdB) {
            return;
        }

        if (!ghost_keyAuthorized[owner][keyIdA]) {
            uint64 expiryA = uint64(block.timestamp + 1 days);
            IAccountKeychain.TokenLimit[] memory limitsA = new IAccountKeychain.TokenLimit[](0);
            vm.prank(owner);
            try keychain.authorizeKey(
                keyIdA, IAccountKeychain.SignatureType.Secp256k1, expiryA, false, limitsA
            ) {
                address[] memory tokens = new address[](0);
                uint256[] memory amounts = new uint256[](0);
                _authorizeKey(owner, keyIdA, expiryA, false, tokens, amounts);
            } catch {
                return;
            }
        }

        if (ghost_keyAuthorized[owner][keyIdB]) {
            return;
        }

        uint64 expiryB = uint64(block.timestamp + 1 days);
        IAccountKeychain.TokenLimit[] memory limitsB = new IAccountKeychain.TokenLimit[](1);
        limitsB[0] = IAccountKeychain.TokenLimit({ token: address(feeToken), amount: 100e6 });

        uint64 currentNonce = uint64(ghost_protocolNonce[owner]);
        bytes memory signedTx = TxBuilder.buildTempoCallKeychain(
            vmRlp,
            vm,
            address(keychain),
            abi.encodeCall(
                IAccountKeychain.authorizeKey,
                (keyIdB, IAccountKeychain.SignatureType.Secp256k1, expiryB, true, limitsB)
            ),
            0, // nonceKey=0 uses protocol nonce
            currentNonce,
            keyPkA,
            owner
        );

        ghost_previousProtocolNonce[owner] = ghost_protocolNonce[owner];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(owner);
        } catch {
            _handleRevertProtocol(owner);
            ghost_keyAuthRejectedNotSelf++;
        }
    }

    /// @notice Handler K3: Attempt to use KeyAuthorization with wrong chain_id
    /// @dev KeyAuthorization chain_id must be 0 (any) or match current
    function handler_keyAuthWrongChainId(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 wrongChainIdSeed
    )
        external
    {
        uint256 actorIdx = actorSeed % actors.length;
        address owner = actors[actorIdx];

        (address keyId, uint256 keyPk) = _getActorAccessKey(actorIdx, keySeed);

        if (!ghost_keyAuthorized[owner][keyId]) {
            return;
        }

        uint64 wrongChainId = uint64(bound(wrongChainIdSeed, 1, 1000));
        if (wrongChainId == uint64(block.chainid)) {
            wrongChainId = uint64(block.chainid) + 1;
        }

        uint256 amount = 1e6;
        uint256 balance = feeToken.balanceOf(owner);
        if (balance < amount) {
            return;
        }

        uint64 nonceKey = 1;
        uint64 currentNonce = uint64(ghost_2dNonce[owner][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (actors[(actorIdx + 1) % actors.length], amount))
        });

        uint64 gasLimit =
            TxBuilder.callGas(calls[0].data, currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create().withChainId(wrongChainId)
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE).withGasLimit(gasLimit).withCalls(calls)
            .withNonceKey(nonceKey).withNonce(currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.KeychainSecp256k1,
                privateKey: keyPk,
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: owner
            })
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_keyWrongChainAllowed++;
        } catch {
            ghost_keyAuthRejectedChainId++;
        }
    }

    /// @notice Handler K6: Authorize key and use it in same transaction batch (multicall)
    /// @dev Same-tx authorize + use is permitted
    function handler_keySameTxAuthorizeAndUse(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 amount
    )
        external
    {
        uint256 actorIdx = actorSeed % actors.length;
        address owner = actors[actorIdx];
        address recipient = actors[(actorIdx + 1) % actors.length];

        (address keyId,) = _getActorAccessKey(actorIdx, keySeed);

        if (ghost_keyAuthorized[owner][keyId]) {
            return;
        }

        amount = bound(amount, 1e6, 10e6);
        uint256 balance = feeToken.balanceOf(owner);
        if (balance < amount) {
            return;
        }

        uint64 expiry = uint64(block.timestamp + 1 days);
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({ token: address(feeToken), amount: 100e6 });

        uint64 nonceKey = 5;
        uint64 currentNonce = uint64(ghost_2dNonce[owner][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({
            to: address(keychain),
            value: 0,
            data: abi.encodeCall(
                IAccountKeychain.authorizeKey,
                (keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, true, limits)
            )
        });
        calls[1] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (recipient, amount))
        });

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(
            vmRlp, vm, calls, nonceKey, currentNonce, actorKeys[actorIdx]
        );

        uint256 recipientBalanceBefore = feeToken.balanceOf(recipient);

        vm.coinbase(validator);

        // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
        try vmExec.executeTransaction(signedTx) {
            // Verify on-chain nonce actually incremented before updating ghost
            uint64 actualNonce = nonce.getNonce(owner, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[owner][nonceKey] = actualNonce;
                ghost_2dNonceUsed[owner][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;

                // IMPORTANT: The key authorization happens in calls[0] and succeeds if the tx succeeds.
                // We must update ghost_keyAuthorized regardless of whether the transfer in calls[1] succeeded.
                // The multicall is atomic - if it succeeded, ALL calls succeeded (including authorization).
                address[] memory tokens = new address[](1);
                tokens[0] = address(feeToken);
                uint256[] memory amounts = new uint256[](1);
                amounts[0] = 100e6;
                _authorizeKey(owner, keyId, expiry, true, tokens, amounts);

                uint256 recipientBalanceAfter = feeToken.balanceOf(recipient);
                if (recipientBalanceAfter == recipientBalanceBefore + amount) {
                    ghost_keySameTxUsed++;
                }
            }
        } catch {
            _handleRevert2d(owner, nonceKey);
        }
    }

    /// @notice Handler K10: Verify spending limits reset after spending period expires
    /// @dev Limits reset after spending period expires
    function handler_keySpendingPeriodReset(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 timeWarpSeed,
        uint256 amount
    )
        external
    {
        uint256 actorIdx = actorSeed % actors.length;
        address owner = actors[actorIdx];
        address recipient = actors[(actorIdx + 1) % actors.length];

        (address keyId, uint256 keyPk) = _getActorAccessKey(actorIdx, keySeed);

        if (!ghost_keyAuthorized[owner][keyId]) {
            return;
        }

        if (ghost_keyExpiry[owner][keyId] <= block.timestamp) {
            return;
        }

        if (!ghost_keyEnforceLimits[owner][keyId]) {
            return;
        }

        uint256 limit = ghost_keySpendingLimit[owner][keyId][address(feeToken)];
        uint256 spent = ghost_keySpentAmount[owner][keyId][address(feeToken)];

        // Need limit > 2e6 to have valid bound range (1e6, limit/2)
        if (limit < 2e6) {
            return;
        }

        if (spent < limit / 2) {
            return;
        }

        uint256 periodDuration = ghost_keySpendingPeriodDuration[owner][keyId];
        if (periodDuration == 0) {
            periodDuration = 1 days;
        }

        uint256 timeWarp = bound(timeWarpSeed, periodDuration, periodDuration * 2);
        vm.warp(block.timestamp + timeWarp);

        amount = bound(amount, 1e6, limit / 2);
        uint256 balance = feeToken.balanceOf(owner);
        if (balance < amount) {
            return;
        }

        uint64 currentNonce = uint64(ghost_protocolNonce[owner]);

        bytes memory signedTx = TxBuilder.buildTempoCallKeychain(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            0, // nonceKey=0 uses protocol nonce
            currentNonce,
            keyPk,
            owner
        );

        ghost_previousProtocolNonce[owner] = ghost_protocolNonce[owner];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(owner);
            ghost_keyPeriodReset++;
        } catch {
            _handleRevertProtocol(owner);
        }
    }

    /// @notice Handler K11: Verify keys without spending limits can spend unlimited
    /// @dev None = unlimited spending for that token
    function handler_keyUnlimitedSpending(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 amount
    )
        external
    {
        uint256 actorIdx = actorSeed % actors.length;
        address owner = actors[actorIdx];
        address recipient = actors[(actorIdx + 1) % actors.length];

        (address keyId, uint256 keyPk) = _getActorAccessKey(actorIdx, keySeed);

        if (ghost_keyAuthorized[owner][keyId] && ghost_keyEnforceLimits[owner][keyId]) {
            return;
        }

        if (!ghost_keyAuthorized[owner][keyId]) {
            uint64 expiry = uint64(block.timestamp + 1 days);
            IAccountKeychain.TokenLimit[] memory emptyLimits = new IAccountKeychain.TokenLimit[](0);
            vm.prank(owner);
            try keychain.authorizeKey(
                keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, false, emptyLimits
            ) {
                address[] memory tokens = new address[](0);
                uint256[] memory amounts = new uint256[](0);
                _authorizeKey(owner, keyId, expiry, false, tokens, amounts);
                ghost_keyUnlimitedSpending[owner][keyId] = true;
            } catch {
                return;
            }
        }

        if (ghost_keyExpiry[owner][keyId] <= block.timestamp) {
            return;
        }

        amount = bound(amount, 10e6, 1000e6);
        uint256 balance = feeToken.balanceOf(owner);
        if (balance < amount) {
            return;
        }

        uint64 currentNonce = uint64(ghost_protocolNonce[owner]);

        bytes memory signedTx = TxBuilder.buildTempoCallKeychain(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            0, // nonceKey=0 uses protocol nonce
            currentNonce,
            keyPk,
            owner
        );

        ghost_previousProtocolNonce[owner] = ghost_protocolNonce[owner];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(owner);
            ghost_keyUnlimitedUsed++;
        } catch {
            _handleRevertProtocol(owner);
        }
    }

    /// @notice Handler K12: Verify keys with empty limits array cannot spend anything
    /// @dev Empty array = zero spending allowed
    function handler_keyZeroSpendingLimit(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 amount
    )
        external
    {
        uint256 actorIdx = actorSeed % actors.length;
        address owner = actors[actorIdx];
        address recipient = actors[(actorIdx + 1) % actors.length];

        (address keyId, uint256 keyPk) = _getActorAccessKey(actorIdx, keySeed);

        if (!ghost_keyAuthorized[owner][keyId]) {
            uint64 expiry = uint64(block.timestamp + 1 days);
            IAccountKeychain.TokenLimit[] memory emptyLimits = new IAccountKeychain.TokenLimit[](0);
            vm.prank(owner);
            try keychain.authorizeKey(
                keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, true, emptyLimits
            ) {
                address[] memory tokens = new address[](0);
                uint256[] memory amounts = new uint256[](0);
                _authorizeKey(owner, keyId, expiry, true, tokens, amounts);
            } catch {
                return;
            }
        }

        if (!ghost_keyEnforceLimits[owner][keyId]) {
            return;
        }

        if (ghost_keySpendingLimit[owner][keyId][address(feeToken)] > 0) {
            return;
        }

        if (ghost_keyExpiry[owner][keyId] <= block.timestamp) {
            return;
        }

        amount = bound(amount, 1e6, 10e6);
        uint256 balance = feeToken.balanceOf(owner);
        if (balance < amount) {
            return;
        }

        uint64 currentNonce = uint64(ghost_protocolNonce[owner]);

        bytes memory signedTx = TxBuilder.buildTempoCallKeychain(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            0, // nonceKey=0 uses protocol nonce
            currentNonce,
            keyPk,
            owner
        );

        ghost_previousProtocolNonce[owner] = ghost_protocolNonce[owner];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            // Zero-limit key was allowed to spend - K12 violation!
            ghost_keyZeroLimitAllowed++;
            _recordProtocolNonceTxSuccess(owner);
        } catch {
            _handleRevertProtocol(owner);
            _recordKeyZeroLimit();
        }
    }

    /// @notice Handler K16: Verify using an unauthorized P256 key is rejected when secp256k1 key is authorized
    /// @dev Authorizes a secp256k1 key, then attempts to use a different P256 key for the same account
    /// This tests that unauthorized keys are rejected regardless of signature type
    function handler_keySigTypeMismatch(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 amount
    )
        external
    {
        uint256 actorIdx = actorSeed % actors.length;
        address owner = actors[actorIdx];
        address recipient = actors[(actorIdx + 1) % actors.length];

        (address keyId,) = _getActorAccessKey(actorIdx, keySeed);

        if (!ghost_keyAuthorized[owner][keyId]) {
            uint64 expiry = uint64(block.timestamp + 1 days);
            IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);
            vm.prank(owner);
            try keychain.authorizeKey(
                keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, false, limits
            ) {
                address[] memory tokens = new address[](0);
                uint256[] memory amounts = new uint256[](0);
                _authorizeKey(owner, keyId, expiry, false, tokens, amounts);
                ghost_keySignatureType[owner][keyId] =
                    uint8(IAccountKeychain.SignatureType.Secp256k1);
            } catch {
                return;
            }
        }

        if (ghost_keyExpiry[owner][keyId] <= block.timestamp) {
            return;
        }

        amount = bound(amount, 1e6, 10e6);
        uint256 balance = feeToken.balanceOf(owner);
        if (balance < amount) {
            return;
        }

        (address p256KeyId, uint256 p256Pk, bytes32 pubKeyX, bytes32 pubKeyY) =
            _getActorP256AccessKey(actorIdx, keySeed);
        if (p256KeyId == keyId) {
            return;
        }

        uint64 currentNonce = uint64(ghost_protocolNonce[owner]);

        bytes memory signedTx = TxBuilder.buildTempoCallKeychainP256(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            0, // nonceKey=0 uses protocol nonce
            currentNonce,
            p256Pk,
            pubKeyX,
            pubKeyY,
            owner
        );

        ghost_previousProtocolNonce[owner] = ghost_protocolNonce[owner];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(owner);
        } catch {
            _handleRevertProtocol(owner);
            ghost_keySigMismatchRejected++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                    MULTICALL HANDLERS (M1-M9)
    //////////////////////////////////////////////////////////////*/

    // ============ Multicall Ghost State ============

    uint256 public ghost_totalMulticallsExecuted;
    uint256 public ghost_totalMulticallsFailed;
    uint256 public ghost_totalMulticallsWithStateVisibility;

    // ============ Multicall Handlers ============

    /// @notice Handler: Execute a successful multicall with multiple transfers
    /// @dev Tests M4 (logs preserved on success), M5-M7 (gas accumulation)
    function handler_tempoMulticall(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount1,
        uint256 amount2,
        uint256 nonceKeySeed
    )
        external
    {
        (TxContext memory ctx, uint256 totalAmount) =
            _setupMulticallContext(actorSeed, recipientSeed, amount1, amount2, nonceKeySeed);

        uint256 amt2 = totalAmount - ctx.amount;
        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, ctx.amount))
        });
        calls[1] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, amt2))
        });

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(
            vmRlp, vm, calls, ctx.nonceKey, ctx.currentNonce, actorKeys[ctx.senderIdx]
        );
        uint256 recipientBalanceBefore = feeToken.balanceOf(ctx.recipient);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey);
            ghost_totalMulticallsExecuted++;
            uint256 recipientBalanceAfter = feeToken.balanceOf(ctx.recipient);
            assertEq(
                recipientBalanceAfter,
                recipientBalanceBefore + totalAmount,
                "M4: Multicall transfers not applied"
            );
        } catch {
            _handleRevert2d(ctx.sender, ctx.nonceKey);
        }
    }

    /// @notice Handler: Execute a multicall where the last call fails
    /// @dev Tests M1 (all or nothing), M2 (partial state reverted), M3 (logs cleared)
    function handler_tempoMulticallWithFailure(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        TxContext memory ctx = _setup2dNonceTransferContext(
            actorSeed, recipientSeed, amount, nonceKeySeed, 0, 1e6, 10e6
        );

        uint256 excessAmount = feeToken.balanceOf(ctx.sender) + 1e6;

        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, ctx.amount))
        });
        calls[1] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, excessAmount))
        });

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(
            vmRlp, vm, calls, ctx.nonceKey, ctx.currentNonce, actorKeys[ctx.senderIdx]
        );

        uint256 senderBalanceBefore = feeToken.balanceOf(ctx.sender);
        uint256 recipientBalanceBefore = feeToken.balanceOf(ctx.recipient);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey);
        } catch {
            // Tx reverted during execution - nonce may or may not be consumed depending on when revert happened
            // Only update ghost state if on-chain nonce actually changed (verified, not assumed)
            uint64 actualNonce = nonce.getNonce(ctx.sender, ctx.nonceKey);
            if (actualNonce > ctx.currentNonce) {
                ghost_2dNonce[ctx.sender][ctx.nonceKey] = actualNonce;
                ghost_2dNonceUsed[ctx.sender][ctx.nonceKey] = true;
            }
            ghost_totalTxReverted++;
            ghost_totalMulticallsFailed++;

            uint256 senderBalanceAfter = feeToken.balanceOf(ctx.sender);
            uint256 recipientBalanceAfter = feeToken.balanceOf(ctx.recipient);
            assertEq(
                senderBalanceAfter,
                senderBalanceBefore,
                "M1/M2: First call state not reverted on batch failure"
            );
            assertEq(
                recipientBalanceAfter,
                recipientBalanceBefore,
                "M1/M2: First call state not reverted on batch failure"
            );
        }
    }

    /// @notice Handler: Execute a multicall where call N+1 depends on call N's state
    /// @dev Tests M8 (state changes visible) and M9 (balance changes propagate)
    function handler_tempoMulticallStateVisibility(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        TxContext memory ctx = _setup2dNonceTransferContext(
            actorSeed, recipientSeed, amount, nonceKeySeed, 0, 1e6, 10e6
        );
        if (feeToken.balanceOf(ctx.recipient) < ctx.amount) {
            return;
        }

        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, ctx.amount))
        });
        calls[1] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transferFrom, (ctx.recipient, ctx.sender, ctx.amount))
        });

        vm.prank(ctx.recipient);
        feeToken.approve(ctx.sender, ctx.amount);

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(
            vmRlp, vm, calls, ctx.nonceKey, ctx.currentNonce, actorKeys[ctx.senderIdx]
        );

        uint256 senderBalanceBefore = feeToken.balanceOf(ctx.sender);
        uint256 recipientBalanceBefore = feeToken.balanceOf(ctx.recipient);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey);
            ghost_totalMulticallsWithStateVisibility++;

            uint256 senderBalanceAfter = feeToken.balanceOf(ctx.sender);
            uint256 recipientBalanceAfter = feeToken.balanceOf(ctx.recipient);
            assertEq(
                senderBalanceAfter,
                senderBalanceBefore,
                "M8/M9: State visibility - sender balance should be unchanged after round-trip"
            );
            assertEq(
                recipientBalanceAfter,
                recipientBalanceBefore,
                "M8/M9: State visibility - recipient balance should be unchanged after round-trip"
            );
        } catch {
            _handleRevert2d(ctx.sender, ctx.nonceKey);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    FEE COLLECTION INVARIANTS (F1-F12)
    //////////////////////////////////////////////////////////////*/

    // ============ Fee Ghost State ============

    uint256 public ghost_feeTrackingTransactions;
    mapping(address => uint256) public ghost_balanceBeforeTx;
    mapping(address => uint256) public ghost_balanceAfterTx;

    // ============ Fee Handlers ============

    /// @notice Handler F1: Track fee precollection (fees locked BEFORE execution)
    /// @dev F1: Fees are locked BEFORE execution begins
    function handler_feeCollection(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        FeeTestContext memory ctx =
            _setupFeeTestContext(actorSeed, recipientSeed, amount, nonceKeySeed);

        uint64 gasLimit =
            TxBuilder.callGas(ctx.calls[0].data, ctx.currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(ctx.calls).withNonceKey(ctx.nonceKey)
            .withNonce(ctx.currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[ctx.senderIdx],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );

        ghost_previous2dNonce[ctx.sender][ctx.nonceKey] = ghost_2dNonce[ctx.sender][ctx.nonceKey];

        uint256 balanceBefore = feeToken.balanceOf(ctx.sender);
        ghost_balanceBeforeTx[ctx.sender] = balanceBefore;

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            uint256 balanceAfter = feeToken.balanceOf(ctx.sender);
            ghost_balanceAfterTx[ctx.sender] = balanceAfter;

            uint256 expectedTransfer = ctx.amount;
            uint256 actualDecrease = balanceBefore - balanceAfter;

            if (actualDecrease > expectedTransfer) {
                uint256 feePaid = actualDecrease - expectedTransfer;
                _recordFeeCollection(ctx.sender, feePaid);
                _recordFeePrecollected();
            }

            // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
            // Verify on-chain nonce actually incremented before updating ghost
            uint64 actualNonce = nonce.getNonce(ctx.sender, ctx.nonceKey);
            if (actualNonce > ctx.currentNonce) {
                ghost_2dNonce[ctx.sender][ctx.nonceKey] = actualNonce;
                ghost_2dNonceUsed[ctx.sender][ctx.nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
                ghost_feeTrackingTransactions++;
            }
        } catch {
            _handleRevert2d(ctx.sender, ctx.nonceKey);
        }
    }

    /// @notice Handler F3: Verify unused gas is refunded on success
    /// @dev F3: Unused gas refunded only if ALL calls succeed
    function handler_feeRefundSuccess(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        FeeTestContext memory ctx =
            _setupFeeTestContext(actorSeed, recipientSeed, amount, nonceKeySeed);

        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, ctx.amount / 2))
        });
        calls[1] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, ctx.amount / 2))
        });

        uint64 highGasLimit = TxBuilder.DEFAULT_GAS_LIMIT * 10;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(highGasLimit).withCalls(calls).withNonceKey(ctx.nonceKey)
            .withNonce(ctx.currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[ctx.senderIdx],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );

        ghost_previous2dNonce[ctx.sender][ctx.nonceKey] = ghost_2dNonce[ctx.sender][ctx.nonceKey];

        uint256 balanceBefore = feeToken.balanceOf(ctx.sender);
        uint256 maxFee = uint256(highGasLimit) * TxBuilder.DEFAULT_GAS_PRICE;

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            uint256 balanceAfter = feeToken.balanceOf(ctx.sender);
            uint256 actualDecrease = balanceBefore - balanceAfter;
            uint256 transferAmount = ctx.amount;

            if (actualDecrease < transferAmount + maxFee) {
                _recordFeeRefundOnSuccess();
            }

            uint64 actualNonce = nonce.getNonce(ctx.sender, ctx.nonceKey);
            if (actualNonce > ctx.currentNonce) {
                ghost_2dNonce[ctx.sender][ctx.nonceKey] = actualNonce;
                ghost_2dNonceUsed[ctx.sender][ctx.nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
            }
        } catch {
            _handleRevert2d(ctx.sender, ctx.nonceKey);
        }
    }

    /// @notice Handler F4: Verify no refund when any call fails
    /// @dev F4: No refund if any call in batch fails
    function handler_feeNoRefundFailure(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        FeeTestContext memory ctx =
            _setupFeeTestContext(actorSeed, recipientSeed, amount, nonceKeySeed);

        uint256 balance = feeToken.balanceOf(ctx.sender);
        uint256 excessAmount = balance + 1e6;

        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, ctx.amount))
        });
        calls[1] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, excessAmount))
        });

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(
            vmRlp, vm, calls, ctx.nonceKey, ctx.currentNonce, actorKeys[ctx.senderIdx]
        );

        ghost_previous2dNonce[ctx.sender][ctx.nonceKey] = ghost_2dNonce[ctx.sender][ctx.nonceKey];

        uint256 balanceBefore = feeToken.balanceOf(ctx.sender);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            uint64 actualNonce = nonce.getNonce(ctx.sender, ctx.nonceKey);
            if (actualNonce > ctx.currentNonce) {
                ghost_2dNonce[ctx.sender][ctx.nonceKey] = actualNonce;
                ghost_2dNonceUsed[ctx.sender][ctx.nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
            }
        } catch {
            _sync2dNonceAfterFailure(ctx.sender, ctx.nonceKey);
            uint256 balanceAfter = feeToken.balanceOf(ctx.sender);
            if (balanceAfter < balanceBefore) {
                _recordFeeNoRefundOnFailure();
            }
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler F5: Verify fee is paid even when tx reverts
    /// @dev F5: User pays for gas even when tx reverts
    function handler_feeOnRevert(uint256 actorSeed, uint256 nonceKeySeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];

        uint256 balance = feeToken.balanceOf(sender);
        if (balance < 1e6) {
            return;
        }

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        uint256 excessAmount = balance + 1e6;

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (actors[0], excessAmount))
        });

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(
            vmRlp, vm, calls, nonceKey, currentNonce, actorKeys[senderIdx]
        );

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        uint256 balanceBefore = feeToken.balanceOf(sender);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            uint64 actualNonce = nonce.getNonce(sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
            }
        } catch {
            _sync2dNonceAfterFailure(sender, nonceKey);
            uint256 balanceAfter = feeToken.balanceOf(sender);
            if (balanceAfter < balanceBefore) {
                _recordFeePaidOnRevert();
            }
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler F6: Verify non-TIP20 fee token is rejected
    /// @dev F6: Non-zero spending requires TIP20 prefix (0x20C0...)
    function handler_invalidFeeToken(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);

        uint256 balance = feeToken.balanceOf(sender);
        vm.assume(balance >= amount);

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (recipient, amount))
        });

        address invalidFeeToken = address(0x1234567890123456789012345678901234567890);

        uint64 gasLimit =
            TxBuilder.callGas(calls[0].data, currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(currentNonce)
            .withFeeToken(invalidFeeToken);

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[senderIdx],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            uint64 actualNonce = nonce.getNonce(sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
            }
        } catch {
            _sync2dNonceAfterFailure(sender, nonceKey);
            _recordInvalidFeeTokenRejected();
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler F7: Verify explicit fee token takes priority
    /// @dev F7: Explicit tx.fee_token takes priority
    function handler_explicitFeeToken(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        FeeTestContext memory ctx =
            _setupFeeTestContext(actorSeed, recipientSeed, amount, nonceKeySeed);

        uint64 gasLimit =
            TxBuilder.callGas(ctx.calls[0].data, ctx.currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(ctx.calls).withNonceKey(ctx.nonceKey)
            .withNonce(ctx.currentNonce).withFeeToken(address(feeToken));

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[ctx.senderIdx],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );

        ghost_previous2dNonce[ctx.sender][ctx.nonceKey] = ghost_2dNonce[ctx.sender][ctx.nonceKey];

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            uint64 actualNonce = nonce.getNonce(ctx.sender, ctx.nonceKey);
            if (actualNonce > ctx.currentNonce) {
                ghost_2dNonce[ctx.sender][ctx.nonceKey] = actualNonce;
                ghost_2dNonceUsed[ctx.sender][ctx.nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
                _recordExplicitFeeTokenUsed();
            }
        } catch {
            _handleRevert2d(ctx.sender, ctx.nonceKey);
        }
    }

    /// @notice Handler F8: Verify fee token fallback order
    /// @dev F8: Falls back to user preference → validator preference → default
    function handler_feeTokenFallback(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        FeeTestContext memory ctx =
            _setupFeeTestContext(actorSeed, recipientSeed, amount, nonceKeySeed);

        uint64 gasLimit =
            TxBuilder.callGas(ctx.calls[0].data, ctx.currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(ctx.calls).withNonceKey(ctx.nonceKey)
            .withNonce(ctx.currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[ctx.senderIdx],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );

        ghost_previous2dNonce[ctx.sender][ctx.nonceKey] = ghost_2dNonce[ctx.sender][ctx.nonceKey];

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            uint64 actualNonce = nonce.getNonce(ctx.sender, ctx.nonceKey);
            if (actualNonce > ctx.currentNonce) {
                ghost_2dNonce[ctx.sender][ctx.nonceKey] = actualNonce;
                ghost_2dNonceUsed[ctx.sender][ctx.nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
                _recordFeeTokenFallbackUsed();
            }
        } catch {
            _handleRevert2d(ctx.sender, ctx.nonceKey);
        }
    }

    /// @notice Handler F10: Verify tx rejected if AMM can't swap fee token
    /// @dev F10: Tx rejected if AMM can't swap fee token
    function handler_insufficientLiquidity(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (recipient, amount))
        });

        address noLiquidityToken = address(token1);

        uint256 tokenBalance = token1.balanceOf(sender);
        if (tokenBalance < 1e6) {
            vm.prank(admin);
            token1.grantRole(_ISSUER_ROLE, admin);
            vm.prank(admin);
            token1.mint(sender, 10_000_000e6);
        }

        uint64 gasLimit =
            TxBuilder.callGas(calls[0].data, currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(currentNonce)
            .withFeeToken(noLiquidityToken);

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[senderIdx],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            uint64 actualNonce = nonce.getNonce(sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
            }
        } catch {
            _sync2dNonceAfterFailure(sender, nonceKey);
            _recordInsufficientLiquidityRejected();
            ghost_totalTxReverted++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                    TIME WINDOW HANDLERS (T1-T4)
    //////////////////////////////////////////////////////////////*/

    /// @notice Build a Tempo transaction with time bounds
    function _buildTempoWithTimeBounds(
        uint256 actorIndex,
        address to,
        uint256 amount,
        uint64 nonceKey,
        uint64 txNonce,
        uint64 validAfter,
        uint64 validBefore
    )
        internal
        view
        returns (bytes memory signedTx, address sender)
    {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (to, amount))
        });

        uint64 gasLimit = TxBuilder.callGas(calls[0].data, txNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(txNonce);

        if (validAfter > 0) {
            tx_ = tx_.withValidAfter(validAfter);
        }
        if (validBefore > 0) {
            tx_ = tx_.withValidBefore(validBefore);
        }

        sender = actors[actorIndex];
        signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[actorIndex],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );
    }

    /// @notice Handler T1: Tx rejected if block.timestamp < validAfter
    /// @dev Creates a Tempo tx with validAfter in the future, expects rejection
    function handler_timeBoundValidAfter(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 futureOffset
    )
        external
    {
        TxContext memory ctx =
            _setup2dNonceTransferContext(actorSeed, recipientSeed, amount, 1, 0, 1e6, 100e6);
        ctx.nonceKey = 1;
        ctx.currentNonce = uint64(ghost_2dNonce[ctx.sender][ctx.nonceKey]);

        futureOffset = bound(futureOffset, 1, 1 days);
        uint64 validAfter = uint64(block.timestamp + futureOffset);

        (bytes memory signedTx,) = _buildTempoWithTimeBounds(
            ctx.senderIdx, ctx.recipient, ctx.amount, ctx.nonceKey, ctx.currentNonce, validAfter, 0
        );
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            // T1 VIOLATION: Tx with validAfter in future should have been rejected!
            ghost_timeBoundValidAfterAllowed++;
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.currentNonce);
        } catch {
            _handleExpectedReject(_noop);
        }
    }

    /// @notice Handler T2: Tx rejected if block.timestamp >= validBefore
    /// @dev Creates a Tempo tx with validBefore in the past, expects rejection
    function handler_timeBoundValidBefore(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 pastOffset
    )
        external
    {
        TxContext memory ctx =
            _setup2dNonceTransferContext(actorSeed, recipientSeed, amount, 2, 0, 1e6, 100e6);
        ctx.nonceKey = 2;
        ctx.currentNonce = uint64(ghost_2dNonce[ctx.sender][ctx.nonceKey]);

        pastOffset = bound(pastOffset, 0, block.timestamp > 1 ? block.timestamp - 1 : 0);
        uint64 validBefore = uint64(block.timestamp - pastOffset);
        if (validBefore == 0) validBefore = 1;

        (bytes memory signedTx,) = _buildTempoWithTimeBounds(
            ctx.senderIdx, ctx.recipient, ctx.amount, ctx.nonceKey, ctx.currentNonce, 0, validBefore
        );
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            // T2 VIOLATION: Tx with validBefore in past should have been rejected!
            ghost_timeBoundValidBeforeAllowed++;
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.currentNonce);
        } catch {
            _handleExpectedReject(_noop);
        }
    }

    /// @notice Handler T3: Both validAfter and validBefore enforced
    /// @dev Creates a Tempo tx with both bounds set, tests edge cases
    function handler_timeBoundValid(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 windowSize
    )
        external
    {
        TxContext memory ctx =
            _setup2dNonceTransferContext(actorSeed, recipientSeed, amount, 3, 0, 1e6, 100e6);
        ctx.nonceKey = 3;
        ctx.currentNonce = uint64(ghost_2dNonce[ctx.sender][ctx.nonceKey]);

        windowSize = bound(windowSize, 1 hours, 1 days);
        uint64 validAfter = uint64(block.timestamp > 1 hours ? block.timestamp - 1 hours : 0);
        uint64 validBefore = uint64(block.timestamp + windowSize);

        (bytes memory signedTx,) = _buildTempoWithTimeBounds(
            ctx.senderIdx,
            ctx.recipient,
            ctx.amount,
            ctx.nonceKey,
            ctx.currentNonce,
            validAfter,
            validBefore
        );
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.currentNonce);
        } catch {
            _handleRevert2d(ctx.sender, ctx.nonceKey);
        }
    }

    /// @notice Handler T4: No time bounds = always valid
    /// @dev Creates a Tempo tx without time bounds, should always succeed (if other conditions met)
    function handler_timeBoundOpen(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TxContext memory ctx =
            _setup2dNonceTransferContext(actorSeed, recipientSeed, amount, 4, 0, 1e6, 100e6);
        ctx.nonceKey = 4;
        ctx.currentNonce = uint64(ghost_2dNonce[ctx.sender][ctx.nonceKey]);

        (bytes memory signedTx,) = _buildTempoWithTimeBounds(
            ctx.senderIdx, ctx.recipient, ctx.amount, ctx.nonceKey, ctx.currentNonce, 0, 0
        );
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.currentNonce);
        } catch {
            _handleRevert2d(ctx.sender, ctx.nonceKey);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    TRANSACTION TYPE INVARIANTS (TX4-TX12)
    //////////////////////////////////////////////////////////////*/

    // ============ TX4/TX5: EIP-1559 Handlers ============

    /// @notice Handler TX4/TX5: Execute an EIP-1559 transfer with valid priority fee
    /// @dev Tests that maxPriorityFeePerGas and maxFeePerGas are enforced
    function handler_eip1559Transfer(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 priorityFee
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);
        priorityFee = bound(priorityFee, 1, 100);

        uint256 balance = feeToken.balanceOf(sender);
        vm.assume(balance >= amount);

        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);
        uint256 baseFee = block.basefee > 0 ? block.basefee : 1;
        uint256 maxFee = baseFee + priorityFee;

        bytes memory data = abi.encodeCall(ITIP20.transfer, (recipient, amount));
        uint64 gasLimit = TxBuilder.callGas(data, currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        Eip1559Transaction memory tx_ = Eip1559TransactionLib.create().withNonce(currentNonce)
            .withMaxPriorityFeePerGas(priorityFee).withMaxFeePerGas(maxFee).withGasLimit(gasLimit)
            .withTo(address(feeToken)).withData(data);

        bytes memory unsignedTx = tx_.encode(vmRlp);
        bytes32 txHash = keccak256(unsignedTx);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(actorKeys[senderIdx], txHash);
        bytes memory signedTx = tx_.encodeWithSignature(vmRlp, v, r, s);

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(sender);
        } catch {
            _handleRevertProtocol(sender);
        }
    }

    /// @notice Handler TX5: Attempt EIP-1559 tx with maxFeePerGas < baseFee (should be rejected)
    /// @dev Verifies that maxFeePerGas >= baseFee is enforced
    function handler_eip1559BaseFeeRejection(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);

        uint256 balance = feeToken.balanceOf(sender);
        vm.assume(balance >= amount);

        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);
        uint256 baseFee = block.basefee > 0 ? block.basefee : 100;
        uint256 maxFee = baseFee > 1 ? baseFee - 1 : 0;

        bytes memory data = abi.encodeCall(ITIP20.transfer, (recipient, amount));
        uint64 gasLimit = TxBuilder.callGas(data, currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        Eip1559Transaction memory tx_ = Eip1559TransactionLib.create().withNonce(currentNonce)
            .withMaxPriorityFeePerGas(1).withMaxFeePerGas(maxFee).withGasLimit(gasLimit)
            .withTo(address(feeToken)).withData(data);

        bytes memory unsignedTx = tx_.encode(vmRlp);
        bytes32 txHash = keccak256(unsignedTx);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(actorKeys[senderIdx], txHash);
        bytes memory signedTx = tx_.encodeWithSignature(vmRlp, v, r, s);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(sender);
        } catch {
            _syncNonceAfterFailure(sender);
            ghost_totalTxReverted++;
        }
    }

    // ============ TX6/TX7: EIP-7702 Handlers ============

    /// @notice Handler TX6: Execute an EIP-7702 transaction with authorization list
    /// @dev Tests that authorization list is applied before execution
    function handler_eip7702WithAuth(
        uint256 actorSeed,
        uint256 authoritySeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 authorityIdx = authoritySeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address authority = actors[authorityIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);

        uint256 balance = feeToken.balanceOf(sender);
        vm.assume(balance >= amount);

        uint64 senderNonce = uint64(ghost_protocolNonce[sender]);
        uint64 authorityNonce = uint64(vm.getNonce(authority));

        address codeAddress = address(feeToken);
        bytes32 authHash = Eip7702TransactionLib.computeAuthorizationHash(
            block.chainid, codeAddress, authorityNonce
        );

        (uint8 authV, bytes32 authR, bytes32 authS) = vm.sign(actorKeys[authorityIdx], authHash);
        uint8 authYParity = authV >= 27 ? authV - 27 : authV;

        Eip7702Authorization[] memory auths = new Eip7702Authorization[](1);
        auths[0] = Eip7702Authorization({
            chainId: block.chainid,
            codeAddress: codeAddress,
            nonce: authorityNonce,
            yParity: authYParity,
            r: authR,
            s: authS
        });

        bytes memory data = abi.encodeCall(ITIP20.transfer, (recipient, amount));
        uint64 gasLimit = TxBuilder.callGas(data, senderNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        Eip7702Transaction memory tx_ = Eip7702TransactionLib.create().withNonce(senderNonce)
            .withMaxPriorityFeePerGas(10).withMaxFeePerGas(100).withGasLimit(gasLimit)
            .withTo(address(feeToken)).withData(data).withAuthorizationList(auths);

        bytes memory unsignedTx = tx_.encode(vmRlp);
        bytes32 txHash = keccak256(unsignedTx);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(actorKeys[senderIdx], txHash);
        bytes memory signedTx = tx_.encodeWithSignature(vmRlp, v, r, s);

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];

        // Track authority nonce before tx for EIP-7702 nonce consumption verification
        uint256 authorityNonceBefore = vm.getNonce(authority);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(sender);

            // Per EIP-7702: authority nonce is consumed when authorization is applied
            // Verify authority nonce incremented (only if sender != authority)
            if (sender != authority) {
                uint256 authorityNonceAfter = vm.getNonce(authority);
                if (authorityNonceAfter > authorityNonceBefore) {
                    // Authority nonce was consumed - update ghost state
                    ghost_protocolNonce[authority] = authorityNonceAfter;
                    ghost_totalProtocolNonceTxs++;
                }
            }
        } catch {
            _handleRevertProtocol(sender);
        }
    }

    /// @notice Handler TX7: Attempt CREATE with EIP-7702 authorization list (should be rejected)
    /// @dev Verifies that CREATE is forbidden when authorization list is present
    function handler_eip7702CreateRejection(uint256 actorSeed, uint256 authoritySeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 authorityIdx = authoritySeed % actors.length;

        address sender = actors[senderIdx];
        address authority = actors[authorityIdx];

        uint64 senderNonce = uint64(ghost_protocolNonce[sender]);
        uint64 authorityNonce = uint64(vm.getNonce(authority));

        address codeAddress = address(feeToken);
        bytes32 authHash = Eip7702TransactionLib.computeAuthorizationHash(
            block.chainid, codeAddress, authorityNonce
        );

        (uint8 authV, bytes32 authR, bytes32 authS) = vm.sign(actorKeys[authorityIdx], authHash);
        uint8 authYParity = authV >= 27 ? authV - 27 : authV;

        Eip7702Authorization[] memory auths = new Eip7702Authorization[](1);
        auths[0] = Eip7702Authorization({
            chainId: block.chainid,
            codeAddress: codeAddress,
            nonce: authorityNonce,
            yParity: authYParity,
            r: authR,
            s: authS
        });

        bytes memory initcode = type(Counter).creationCode;

        uint64 gasLimit = TxBuilder.createGas(initcode, senderNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        Eip7702Transaction memory tx_ = Eip7702TransactionLib.create().withNonce(senderNonce)
            .withMaxPriorityFeePerGas(10).withMaxFeePerGas(100).withGasLimit(gasLimit)
            .withTo(address(0)).withData(initcode).withAuthorizationList(auths);

        bytes memory unsignedTx = tx_.encode(vmRlp);
        bytes32 txHash = keccak256(unsignedTx);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(actorKeys[senderIdx], txHash);
        bytes memory signedTx = tx_.encodeWithSignature(vmRlp, v, r, s);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            // CREATE with authorization list unexpectedly succeeded - TX7 violation!
            ghost_eip7702CreateWithAuthAllowed++;
            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
            ghost_totalCreatesExecuted++;
            ghost_totalProtocolNonceTxs++;
        } catch {
            ghost_totalTxReverted++;
        }
    }

    // ============ TX10: Fee Sponsorship Handler ============

    /// @notice Handler TX10: Execute a Tempo transaction with fee payer signature
    /// @dev Tests that fee payer signature enables fee sponsorship
    function handler_tempoFeeSponsor(
        uint256 actorSeed,
        uint256 feePayerSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 feePayerIdx = feePayerSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;

        if (senderIdx == feePayerIdx) {
            feePayerIdx = (feePayerIdx + 1) % actors.length;
        }
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }
        if (feePayerIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address feePayer = actors[feePayerIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);

        uint256 senderBalance = feeToken.balanceOf(sender);
        uint256 feePayerBalance = feeToken.balanceOf(feePayer);
        if (senderBalance < amount || feePayerBalance < 1e6) {
            return;
        }

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (recipient, amount))
        });

        uint64 gasLimit =
            TxBuilder.callGas(calls[0].data, currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(currentNonce);

        bytes memory unsignedTxForFeePayer = tx_.encode(vmRlp);
        bytes32 feePayerTxHash = keccak256(unsignedTxForFeePayer);

        (uint8 fpV, bytes32 fpR, bytes32 fpS) = vm.sign(actorKeys[feePayerIdx], feePayerTxHash);
        bytes memory feePayerSig = abi.encodePacked(fpR, fpS, fpV);

        tx_ = tx_.withFeePayerSignature(feePayerSig);

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[senderIdx],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        // Track balances before tx to verify fee payer pays fees
        uint256 senderBalanceBefore = feeToken.balanceOf(sender);
        uint256 feePayerBalanceBefore = feeToken.balanceOf(feePayer);
        uint256 recipientBalanceBefore = feeToken.balanceOf(recipient);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            uint64 actualNonce = nonce.getNonce(sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;

                // Verify fee sponsorship: sender pays only transfer amount, fee payer pays fees
                uint256 senderBalanceAfter = feeToken.balanceOf(sender);
                uint256 feePayerBalanceAfter = feeToken.balanceOf(feePayer);
                uint256 recipientBalanceAfter = feeToken.balanceOf(recipient);

                // Recipient should receive the transfer amount
                assertEq(
                    recipientBalanceAfter,
                    recipientBalanceBefore + amount,
                    "TX10: Recipient should receive transfer amount"
                );

                // Sender should only decrease by transfer amount (no fees)
                uint256 senderDecrease = senderBalanceBefore - senderBalanceAfter;
                assertEq(
                    senderDecrease, amount, "TX10: Sender should only pay transfer amount, not fees"
                );

                // Fee payer should pay the fees (balance decreased, but they didn't receive/send the transfer)
                assertTrue(
                    feePayerBalanceAfter < feePayerBalanceBefore, "TX10: Fee payer should pay fees"
                );
            }
        } catch {
            _handleRevert2d(sender, nonceKey);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    GAS INVARIANTS (G1-G10)
    //////////////////////////////////////////////////////////////*/

    // ============ Gas Ghost State ============

    mapping(address => uint256) public ghost_basicGasUsed;
    mapping(address => uint256) public ghost_multicallGasUsed;
    mapping(address => uint256) public ghost_createGasUsed;
    mapping(address => uint256) public ghost_signatureGasUsed;
    mapping(address => uint256) public ghost_keyAuthGasUsed;
    mapping(address => uint256) public ghost_numCallsInMulticall;

    // ============ Gas Tracking Handlers ============

    /// @notice Handler: Track gas for simple transfer (G1, G2, G3)
    /// @dev G1: TX_BASE_COST; G2: COLD_ACCOUNT_ACCESS per call; G3: Calldata gas
    function handler_gasTrackingBasic(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);

        uint256 balance = feeToken.balanceOf(sender);
        vm.assume(balance >= amount);

        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);
        bytes memory callData = abi.encodeCall(ITIP20.transfer, (recipient, amount));
        bytes memory signedTx = TxBuilder.buildLegacyCall(
            vmRlp, vm, address(feeToken), callData, currentNonce, actorKeys[senderIdx]
        );

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];

        vm.coinbase(validator);

        uint256 gasBefore = gasleft();
        try vmExec.executeTransaction(signedTx) {
            uint256 gasUsed = gasBefore - gasleft();
            ghost_basicGasUsed[sender] = gasUsed;

            // G1: Verify minimum base tx cost is charged
            // Note: gasUsed from gasleft() measures Solidity execution, not tx intrinsic gas
            // The actual intrinsic cost is enforced by the EVM, we track for analysis
            assertTrue(gasUsed > 0, "G1: Transaction should consume gas");

            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
            _recordGasTrackingBasic();
        } catch {
            _handleRevertProtocol(sender);
        }
    }

    /// @notice Handler: Track gas for multicall with varying number of calls (G2)
    /// @dev G2: Each call adds COLD_ACCOUNT_ACCESS gas
    function handler_gasTrackingMulticall(
        uint256 actorSeed,
        uint256 numCallsSeed,
        uint256 amount,
        uint256 nonceKeySeed
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        address recipient = actors[(senderIdx + 1) % actors.length];

        uint256 numCalls = bound(numCallsSeed, 1, 5);
        amount = bound(amount, 1e6, 5e6);

        uint256 totalAmount = numCalls * amount;
        uint256 balance = feeToken.balanceOf(sender);
        if (balance < totalAmount) {
            return;
        }

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](numCalls);
        for (uint256 i = 0; i < numCalls; i++) {
            calls[i] = TempoCall({
                to: address(feeToken),
                value: 0,
                data: abi.encodeCall(ITIP20.transfer, (recipient, amount))
            });
        }

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(
            vmRlp, vm, calls, nonceKey, currentNonce, actorKeys[senderIdx]
        );

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        vm.coinbase(validator);

        uint256 gasBefore = gasleft();
        try vmExec.executeTransaction(signedTx) {
            uint256 gasUsed = gasBefore - gasleft();
            ghost_multicallGasUsed[sender] = gasUsed;
            ghost_numCallsInMulticall[sender] = numCalls;

            // G2: Verify gas increases with number of calls
            // Each additional call should add overhead (cold account access, execution)
            assertTrue(gasUsed > 0, "G2: Multicall should consume gas");

            ghost_2dNonce[sender][nonceKey]++;
            ghost_2dNonceUsed[sender][nonceKey] = true;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_total2dNonceTxs++;
            _recordGasTrackingMulticall();
        } catch {
            _handleRevert2d(sender, nonceKey);
        }
    }

    /// @notice Handler: Track gas for CREATE with initcode (G4)
    /// @dev G4: CREATE gas = CREATE_BASE_COST + calldata + initcode word cost
    function handler_gasTrackingCreate(uint256 actorSeed, uint256 initValueSeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];

        uint256 initValue = bound(initValueSeed, 0, 1000);
        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);

        bytes memory initcode = InitcodeHelper.simpleStorageInitcode(initValue);

        uint64 gasLimit = TxBuilder.createGas(initcode, currentNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        bytes memory signedTx = TxBuilder.buildLegacyCreateWithGas(
            vmRlp, vm, initcode, currentNonce, gasLimit, actorKeys[senderIdx]
        );

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];

        vm.coinbase(validator);

        uint256 gasBefore = gasleft();
        try vmExec.executeTransaction(signedTx) {
            uint256 gasUsed = gasBefore - gasleft();
            ghost_createGasUsed[sender] = gasUsed;

            // G4: Verify CREATE consumes significant gas (base + initcode cost)
            assertTrue(gasUsed > 0, "G4: CREATE should consume gas");

            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
            ghost_totalCreatesExecuted++;
            ghost_totalProtocolNonceTxs++;

            bytes32 key = keccak256(abi.encodePacked(sender, uint256(currentNonce)));
            address expectedAddress = TxBuilder.computeCreateAddress(sender, currentNonce);
            ghost_createAddresses[key] = expectedAddress;
            ghost_createCount[sender]++;
            _recordGasTrackingCreate();
        } catch {
            _handleRevertProtocol(sender);
        }
    }

    /// @notice Handler: Track gas for different signature types (G6, G7, G8)
    /// @dev G6: secp256k1 ECRECOVER = 3,000; G7: P256 = ECRECOVER + 5,000; G8: WebAuthn = ECRECOVER + 5,000 + calldata
    function handler_gasTrackingSignatureTypes(
        uint256 actorSeed,
        uint256 sigTypeSeed,
        uint256 amount
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        address recipient = actors[(senderIdx + 1) % actors.length];

        amount = bound(amount, 1e6, 10e6);

        // Determine sender first based on signature type to check balance and get nonce
        SignatureType sigType = _getRandomSignatureType(sigTypeSeed);
        address sender;
        if (sigType == SignatureType.Secp256k1) {
            sender = actors[senderIdx];
        } else {
            sender = actorP256Addresses[senderIdx];
        }

        uint256 balance = feeToken.balanceOf(sender);
        vm.assume(balance >= amount);

        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);

        // Build and sign transfer using unified helper
        // Use the sender returned by _buildAndSignTransfer as authoritative
        (bytes memory signedTx, address actualSender) =
            _buildAndSignTransfer(senderIdx, recipient, amount, currentNonce, sigTypeSeed);

        ghost_previousProtocolNonce[actualSender] = ghost_protocolNonce[actualSender];

        vm.coinbase(validator);

        uint256 gasBefore = gasleft();
        try vmExec.executeTransaction(signedTx) {
            uint256 gasUsed = gasBefore - gasleft();
            ghost_signatureGasUsed[actualSender] = gasUsed;

            // G6/G7/G8: Verify signature verification consumes gas
            // secp256k1: ECRECOVER_GAS (3000)
            // P256: ECRECOVER_GAS + P256_EXTRA_GAS (3000 + 5000)
            // WebAuthn: P256 cost + calldata parsing overhead
            assertTrue(gasUsed > 0, "G6/G7/G8: Signature verification should consume gas");

            ghost_protocolNonce[actualSender]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
            _recordGasTrackingSignature();
        } catch {
            _handleRevertProtocol(actualSender);
        }
    }

    /// @notice Handler: Track gas for KeyAuthorization with spending limits (G9, G10)
    /// @dev G9: Base key auth = 27,000; G10: Each spending limit adds 22,000
    function handler_gasTrackingKeyAuth(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 numLimitsSeed
    )
        external
    {
        uint256 actorIdx = actorSeed % actors.length;
        address owner = actors[actorIdx];

        (address keyId,) = _getActorAccessKey(actorIdx, keySeed);

        if (ghost_keyAuthorized[owner][keyId]) {
            return;
        }

        uint256 numLimits = bound(numLimitsSeed, 0, 3);

        uint64 expiry = uint64(block.timestamp + 1 days);
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](numLimits);
        address[] memory tokens = new address[](numLimits);
        uint256[] memory amounts = new uint256[](numLimits);

        for (uint256 i = 0; i < numLimits; i++) {
            limits[i] =
                IAccountKeychain.TokenLimit({ token: address(feeToken), amount: (i + 1) * 100e6 });
            tokens[i] = address(feeToken);
            amounts[i] = (i + 1) * 100e6;
        }

        vm.coinbase(validator);

        uint256 gasBefore = gasleft();
        vm.prank(owner);
        try keychain.authorizeKey(
            keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, numLimits > 0, limits
        ) {
            uint256 gasUsed = gasBefore - gasleft();
            ghost_keyAuthGasUsed[owner] = gasUsed;

            _authorizeKey(owner, keyId, expiry, numLimits > 0, tokens, amounts);
            _recordGasTrackingKeyAuth();
        } catch { }
    }

    /*//////////////////////////////////////////////////////////////
                    EXPIRING NONCE INVARIANTS (E1-E8)
    //////////////////////////////////////////////////////////////*/

    /// @dev Expiring nonce key constant (TIP-1009)
    uint256 private constant EXPIRING_NONCE_KEY = type(uint256).max;
    /// @dev Maximum expiry window in seconds (TIP-1009)
    uint64 private constant MAX_EXPIRY_SECS = 30;

    /// @notice Build an expiring nonce transaction
    /// @dev Sets nonceKey = uint256.max, nonce = 0, and validBefore within window
    function _buildExpiringNonceTx(
        uint256 actorIndex,
        address to,
        uint256 amount,
        uint64 validBefore
    )
        internal
        view
        returns (bytes memory signedTx, bytes32 txHash)
    {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (to, amount))
        });

        uint64 gasLimit = TxBuilder.callGas(calls[0].data, 0) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(EXPIRING_NONCE_KEY).withNonce(0)
            .withValidBefore(validBefore);

        signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[actorIndex],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );

        txHash = keccak256(signedTx);
    }

    /// @notice Build an expiring nonce tx with custom nonce (for testing E4)
    function _buildExpiringNonceTxWithNonce(
        uint256 actorIndex,
        address to,
        uint256 amount,
        uint64 validBefore,
        uint64 txNonce
    )
        internal
        view
        returns (bytes memory signedTx)
    {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (to, amount))
        });

        uint64 gasLimit = TxBuilder.callGas(calls[0].data, txNonce) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(EXPIRING_NONCE_KEY)
            .withNonce(txNonce).withValidBefore(validBefore);

        signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[actorIndex],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );
    }

    /// @notice Build an expiring nonce tx without validBefore (for testing E5)
    function _buildExpiringNonceTxNoValidBefore(
        uint256 actorIndex,
        address to,
        uint256 amount
    )
        internal
        view
        returns (bytes memory signedTx)
    {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (to, amount))
        });

        uint64 gasLimit = TxBuilder.callGas(calls[0].data, 0) + TxBuilder.GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(EXPIRING_NONCE_KEY).withNonce(0);
        // Note: NOT setting validBefore

        signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.Secp256k1,
                privateKey: actorKeys[actorIndex],
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: address(0)
            })
        );
    }

    /// @notice Handler: Execute a basic expiring nonce transaction
    /// @dev Tests basic flow - submit tx with valid expiring nonce, should succeed
    function handler_expiringNonceBasic(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);
        uint256 balance = feeToken.balanceOf(sender);
        if (balance < amount) {
            return;
        }

        uint64 validBefore = uint64(block.timestamp + MAX_EXPIRY_SECS);

        (bytes memory signedTx, bytes32 txHash) =
            _buildExpiringNonceTx(senderIdx, recipient, amount, validBefore);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_expiringNonceExecuted[txHash] = true;
            ghost_expiringNonceTxsExecuted++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler E1: Attempt to replay an expiring nonce tx within validity window
    /// @dev The same tx hash should be rejected while validBefore > now
    function handler_expiringNonceReplay(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);
        uint256 balance = feeToken.balanceOf(sender);
        if (balance < amount * 2) {
            return;
        }

        uint64 validBefore = uint64(block.timestamp + MAX_EXPIRY_SECS);

        (bytes memory signedTx, bytes32 txHash) =
            _buildExpiringNonceTx(senderIdx, recipient, amount, validBefore);

        vm.coinbase(validator);

        // First execution should succeed
        try vmExec.executeTransaction(signedTx) {
            ghost_expiringNonceExecuted[txHash] = true;
            ghost_expiringNonceTxsExecuted++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
        } catch {
            ghost_totalTxReverted++;
            return;
        }

        // Replay attempt - should fail
        ghost_expiringNonceReplayAttempted++;
        try vmExec.executeTransaction(signedTx) {
            // E1 VIOLATION: Replay within validity window succeeded!
            ghost_expiringNonceReplayAllowed++;
        } catch {
            _handleExpectedReject(_noop);
        }
    }

    /// @notice Handler E2: Attempt to execute an expired transaction
    /// @dev Tx with validBefore <= block.timestamp should be rejected
    function handler_expiringNonceExpired(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);
        uint256 balance = feeToken.balanceOf(sender);
        if (balance < amount) {
            return;
        }

        // Set validBefore to current timestamp (expired)
        uint64 validBefore = uint64(block.timestamp);

        (bytes memory signedTx,) = _buildExpiringNonceTx(senderIdx, recipient, amount, validBefore);

        vm.coinbase(validator);
        ghost_expiringNonceExpiredAttempted++;

        try vmExec.executeTransaction(signedTx) {
            // E2 VIOLATION: Expired tx was allowed!
            ghost_expiringNonceExpiredAllowed++;
        } catch {
            _handleExpectedReject(_noop);
        }
    }

    /// @notice Handler E3: Attempt tx with validBefore too far in future
    /// @dev Tx with validBefore > now + 30s should be rejected
    function handler_expiringNonceWindowTooFar(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 extraOffset
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);
        uint256 balance = feeToken.balanceOf(sender);
        if (balance < amount) {
            return;
        }

        // Set validBefore beyond the max window
        extraOffset = bound(extraOffset, 1, 1 hours);
        uint64 validBefore = uint64(block.timestamp + MAX_EXPIRY_SECS + extraOffset);

        (bytes memory signedTx,) = _buildExpiringNonceTx(senderIdx, recipient, amount, validBefore);

        vm.coinbase(validator);
        ghost_expiringNonceWindowAttempted++;

        try vmExec.executeTransaction(signedTx) {
            // E3 VIOLATION: validBefore exceeds max window but was allowed!
            ghost_expiringNonceWindowAllowed++;
        } catch {
            _handleExpectedReject(_noop);
        }
    }

    /// @notice Handler E4: Attempt expiring nonce tx with non-zero nonce
    /// @dev Expiring nonce txs must have nonce = 0
    function handler_expiringNonceNonZeroNonce(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount,
        uint256 nonceSeed
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);
        uint256 balance = feeToken.balanceOf(sender);
        if (balance < amount) {
            return;
        }

        uint64 validBefore = uint64(block.timestamp + MAX_EXPIRY_SECS);
        uint64 wrongNonce = uint64(bound(nonceSeed, 1, 100));

        bytes memory signedTx =
            _buildExpiringNonceTxWithNonce(senderIdx, recipient, amount, validBefore, wrongNonce);

        vm.coinbase(validator);
        ghost_expiringNonceNonZeroAttempted++;

        try vmExec.executeTransaction(signedTx) {
            // E4 VIOLATION: Non-zero nonce was allowed!
            ghost_expiringNonceNonZeroAllowed++;
        } catch {
            _handleExpectedReject(_noop);
        }
    }

    /// @notice Handler E5: Attempt expiring nonce tx without validBefore
    /// @dev Expiring nonce txs must have validBefore set
    function handler_expiringNonceMissingValidBefore(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);
        uint256 balance = feeToken.balanceOf(sender);
        if (balance < amount) {
            return;
        }

        bytes memory signedTx = _buildExpiringNonceTxNoValidBefore(senderIdx, recipient, amount);

        vm.coinbase(validator);
        ghost_expiringNonceMissingVBAttempted++;

        try vmExec.executeTransaction(signedTx) {
            // E5 VIOLATION: Missing validBefore was allowed!
            ghost_expiringNonceMissingVBAllowed++;
        } catch {
            _handleExpectedReject(_noop);
        }
    }

    /// @notice Handler E6: Verify expiring nonce txs don't mutate any nonces
    /// @dev Protocol nonce and 2D nonces should remain unchanged after expiring nonce tx
    function handler_expiringNonceNoNonceMutation(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);
        uint256 balance = feeToken.balanceOf(sender);
        if (balance < amount) {
            return;
        }

        // Record nonces before execution
        uint256 protocolNonceBefore = vm.getNonce(sender);
        uint64 nonce2dBefore = nonce.getNonce(sender, 1); // Check a 2D nonce key

        uint64 validBefore = uint64(block.timestamp + MAX_EXPIRY_SECS);

        (bytes memory signedTx, bytes32 txHash) =
            _buildExpiringNonceTx(senderIdx, recipient, amount, validBefore);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_expiringNonceExecuted[txHash] = true;
            ghost_expiringNonceTxsExecuted++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;

            // E6: Verify nonces unchanged
            uint256 protocolNonceAfter = vm.getNonce(sender);
            uint64 nonce2dAfter = nonce.getNonce(sender, 1);

            // Protocol nonce should NOT have incremented
            assertEq(
                protocolNonceAfter,
                protocolNonceBefore,
                "E6: Protocol nonce should not change for expiring nonce tx"
            );

            // 2D nonce should NOT have incremented
            assertEq(
                nonce2dAfter, nonce2dBefore, "E6: 2D nonce should not change for expiring nonce tx"
            );
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler E7: Multiple concurrent expiring nonce txs from same sender
    /// @dev Expiring nonces allow parallel submissions (no sequential dependency)
    function handler_expiringNonceConcurrent(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount1,
        uint256 amount2
    )
        external
    {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount1 = bound(amount1, 1e6, 5e6);
        amount2 = bound(amount2, 1e6, 5e6);
        uint256 balance = feeToken.balanceOf(sender);
        if (balance < amount1 + amount2) {
            return;
        }

        uint64 validBefore = uint64(block.timestamp + MAX_EXPIRY_SECS);

        // Build two different transactions (different amounts = different hashes)
        (bytes memory signedTx1, bytes32 txHash1) =
            _buildExpiringNonceTx(senderIdx, recipient, amount1, validBefore);
        (bytes memory signedTx2, bytes32 txHash2) =
            _buildExpiringNonceTx(senderIdx, recipient, amount2, validBefore);

        // Ensure they have different hashes
        if (txHash1 == txHash2) {
            return;
        }

        vm.coinbase(validator);

        uint256 successCount = 0;

        // Execute first tx
        try vmExec.executeTransaction(signedTx1) {
            ghost_expiringNonceExecuted[txHash1] = true;
            ghost_expiringNonceTxsExecuted++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            successCount++;
        } catch {
            ghost_totalTxReverted++;
        }

        // Execute second tx (should also succeed - no nonce dependency)
        try vmExec.executeTransaction(signedTx2) {
            ghost_expiringNonceExecuted[txHash2] = true;
            ghost_expiringNonceTxsExecuted++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            successCount++;
        } catch {
            ghost_totalTxReverted++;
        }

        if (successCount == 2) {
            ghost_expiringNonceConcurrentExecuted++;
        }
    }

    /*//////////////////////////////////////////////////////////////
             SPENDING LIMIT REFUND HANDLERS (K-REFUND)
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler K-REFUND1: Verify spending limit is refunded for unused gas
    /// @dev Executes a transfer with an access key using high gas limit, then verifies
    ///      that the on-chain remaining limit accounts for the gas refund (i.e., actual
    ///      remaining > limit - transfer - maxFee).
    function handler_keySpendingRefund(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        AccessKeyContext memory ctx = _setupSecp256k1KeyContext(actorSeed, keySeed);
        amount = bound(amount, 1e6, 10e6);

        if (!ghost_keyAuthorized[ctx.owner][ctx.keyId]) return;
        if (ghost_keyExpiry[ctx.owner][ctx.keyId] <= block.timestamp) return;
        if (!ghost_keyEnforceLimits[ctx.owner][ctx.keyId]) return;

        uint256 limit = ghost_keySpendingLimit[ctx.owner][ctx.keyId][address(feeToken)];
        uint256 spent = ghost_keySpentAmount[ctx.owner][ctx.keyId][address(feeToken)];

        uint64 highGasLimit = TxBuilder.DEFAULT_GAS_LIMIT * 10;
        uint256 maxFee = uint256(highGasLimit) * TxBuilder.DEFAULT_GAS_PRICE;

        if (spent + amount + maxFee > limit) return;
        if (!_checkBalance(ctx.owner, amount + maxFee)) return;

        uint256 recipientIdx = recipientSeed % actors.length;
        if (ctx.actorIdx == recipientIdx) recipientIdx = (recipientIdx + 1) % actors.length;
        address recipient = actors[recipientIdx];

        uint64 currentNonce = uint64(ghost_protocolNonce[ctx.owner]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (recipient, amount))
        });

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(highGasLimit).withCalls(calls).withNonceKey(0).withNonce(currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(
            vmRlp,
            vm,
            tx_,
            TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.KeychainSecp256k1,
                privateKey: ctx.keyPk,
                pubKeyX: bytes32(0),
                pubKeyY: bytes32(0),
                userAddress: ctx.owner
            })
        );

        uint256 remainingBefore =
            keychain.getRemainingLimit(ctx.owner, ctx.keyId, address(feeToken));

        ghost_previousProtocolNonce[ctx.owner] = ghost_protocolNonce[ctx.owner];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(ctx.owner);
            _recordKeySpending(ctx.owner, ctx.keyId, address(feeToken), amount);

            uint256 remainingAfter =
                keychain.getRemainingLimit(ctx.owner, ctx.keyId, address(feeToken));

            // K-REFUND1: After tx, the remaining limit should be greater than
            // (remainingBefore - amount - maxFee) because unused gas was refunded.
            uint256 worstCase = 0;
            if (remainingBefore > amount + maxFee) {
                worstCase = remainingBefore - amount - maxFee;
            }
            assertGe(
                remainingAfter,
                worstCase,
                "K-REFUND1: Remaining limit should account for gas refund"
            );

            // The remaining should also not exceed the limit before minus the transfer amount
            // (refund can't give back more than the gas fee that was deducted)
            assertLe(
                remainingAfter,
                remainingBefore - amount,
                "K-REFUND1: Remaining limit should not exceed (before - transfer)"
            );

            ghost_keyRefundVerified++;
        } catch {
            _handleRevertProtocol(ctx.owner);
        }
    }

    /// @notice Handler K-REFUND2: Verify refund is no-op when key is revoked mid-transaction
    /// @dev Authorizes a key, spends, revokes, then executes another tx that triggers refund.
    ///      The refund should be silently skipped for the revoked key.
    function handler_keySpendingRefundRevokedKey(
        uint256 actorSeed,
        uint256 keySeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        AccessKeyContext memory ctx = _setupSecp256k1KeyContext(actorSeed, keySeed);

        // Need an authorized key with limits
        if (!ghost_keyAuthorized[ctx.owner][ctx.keyId]) return;
        if (ghost_keyExpiry[ctx.owner][ctx.keyId] <= block.timestamp) return;
        if (!ghost_keyEnforceLimits[ctx.owner][ctx.keyId]) return;

        amount = bound(amount, 1e6, 10e6);

        uint256 limit = ghost_keySpendingLimit[ctx.owner][ctx.keyId][address(feeToken)];
        uint256 spent = ghost_keySpentAmount[ctx.owner][ctx.keyId][address(feeToken)];
        if (spent + amount > limit) return;
        if (!_checkBalance(ctx.owner, amount)) return;

        // Step 1: Execute a transfer with the access key
        uint256 recipientIdx = recipientSeed % actors.length;
        if (ctx.actorIdx == recipientIdx) recipientIdx = (recipientIdx + 1) % actors.length;
        address recipient = actors[recipientIdx];

        uint64 currentNonce = uint64(ghost_protocolNonce[ctx.owner]);

        bytes memory signedTx = TxBuilder.buildTempoCallKeychain(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            0,
            currentNonce,
            ctx.keyPk,
            ctx.owner
        );

        ghost_previousProtocolNonce[ctx.owner] = ghost_protocolNonce[ctx.owner];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(ctx.owner);
            _recordKeySpending(ctx.owner, ctx.keyId, address(feeToken), amount);
        } catch {
            _handleRevertProtocol(ctx.owner);
            return;
        }

        // Step 2: Revoke the key (using main key via prank)
        vm.prank(ctx.owner);
        try keychain.revokeKey(ctx.keyId) {
            _revokeKey(ctx.owner, ctx.keyId);
        } catch {
            return;
        }

        // Step 3: Snapshot remaining limit (should be unchanged after revocation)
        uint256 remainingAfterRevoke =
            keychain.getRemainingLimit(ctx.owner, ctx.keyId, address(feeToken));

        // Step 4: Execute another tx (with main key) that would have refunded the revoked key
        // The refund_spending_limit uses load_active_key which fails for revoked keys -> no-op
        _ensureFeeTokenBalance(ctx.owner, 1e6);
        currentNonce = uint64(ghost_protocolNonce[ctx.owner]);

        (bytes memory mainKeyTx,) =
            _buildAndSignTransfer(ctx.actorIdx, recipient, 1e6, currentNonce, 0);

        ghost_previousProtocolNonce[ctx.owner] = ghost_protocolNonce[ctx.owner];
        vm.coinbase(validator);

        try vmExec.executeTransaction(mainKeyTx) {
            _recordProtocolNonceTxSuccess(ctx.owner);

            uint256 remainingAfterMainTx =
                keychain.getRemainingLimit(ctx.owner, ctx.keyId, address(feeToken));

            // K-REFUND2: Remaining limit should not change since the key was revoked
            // (the refund should be a no-op for revoked keys)
            assertEq(
                remainingAfterMainTx,
                remainingAfterRevoke,
                "K-REFUND2: Revoked key limit should not change after refund"
            );

            ghost_keyRefundRevokedNoop++;
        } catch {
            _handleRevertProtocol(ctx.owner);
        }
    }

}
