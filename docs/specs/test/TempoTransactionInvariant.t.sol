// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

import {InvariantChecker} from "./helpers/InvariantChecker.sol";
import {TxBuilder} from "./helpers/TxBuilder.sol";
import {InitcodeHelper, SimpleStorage, Counter} from "./helpers/TestContracts.sol";
import {TIP20} from "../src/TIP20.sol";
import {INonce} from "../src/interfaces/INonce.sol";
import {IAccountKeychain} from "../src/interfaces/IAccountKeychain.sol";
import {ITIP20} from "../src/interfaces/ITIP20.sol";

import {VmRlp, VmExecuteTransaction} from "tempo-std/StdVm.sol";
import {TempoTransaction, TempoCall, TempoAuthorization, TempoTransactionLib} from "./helpers/tx/TempoTransactionLib.sol";
import {LegacyTransaction, LegacyTransactionLib} from "./helpers/tx/LegacyTransactionLib.sol";
import {Eip1559Transaction, Eip1559TransactionLib} from "./helpers/tx/Eip1559TransactionLib.sol";
import {Eip7702Transaction, Eip7702Authorization, Eip7702TransactionLib} from "./helpers/tx/Eip7702TransactionLib.sol";

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

    // Time window ghost state (T1-T4)
    uint256 public ghost_timeBoundTxsExecuted;
    uint256 public ghost_timeBoundTxsRejected;
    uint256 public ghost_validAfterRejections;
    uint256 public ghost_validBeforeRejections;
    uint256 public ghost_openWindowTxsExecuted;

    // Transaction type ghost state (TX4-TX12)
    uint256 public ghost_totalEip1559Txs;
    uint256 public ghost_totalEip1559BaseFeeRejected;
    uint256 public ghost_totalEip7702Txs;
    uint256 public ghost_totalEip7702AuthsApplied;
    uint256 public ghost_totalEip7702CreateRejected;
    uint256 public ghost_totalFeeSponsoredTxs;
    uint256 public ghost_totalMulticallTxsTracked;
    uint256 public ghost_totalTimeWindowTxsTracked;

    // Note: ghost_total2dNonceCreates is defined in GhostState.sol

    // ============ Setup ============

    function setUp() public override {
        super.setUp();

        // Target this contract for handler functions
        targetContract(address(this));

        // Define which handlers the fuzzer should call
        // NOTE: Core handlers only - additional handlers need ghost state sync fixes (see INVARIANT_TEST_PLAN.md)
        bytes4[] memory selectors = new bytes4[](23);
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
        // CREATE structure handlers (C1-C4)
        selectors[18] = this.handler_createNotFirst.selector;
        selectors[19] = this.handler_createMultiple.selector;
        // Tempo access key handlers (TX11)
        selectors[20] = this.handler_tempoUseAccessKey.selector;
        // Multicall handlers (M1-M9)
        selectors[21] = this.handler_tempoMulticall.selector;
        selectors[22] = this.handler_tempoMulticallWithFailure.selector;
        targetSelector(FuzzSelector({addr: address(this), selectors: selectors}));

        // Initialize previous nonce tracking for secp256k1 actors
        for (uint256 i = 0; i < actors.length; i++) {
            ghost_previousProtocolNonce[actors[i]] = 0;
        }

        // Fund P256-derived addresses with fee tokens and initialize nonce tracking
        vm.startPrank(admin);
        for (uint256 i = 0; i < actors.length; i++) {
            address p256Addr = actorP256Addresses[i];
            feeToken.mint(p256Addr, 100_000_000e6);
            ghost_feeTokenBalance[p256Addr] = 100_000_000e6;
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
    }

    /*//////////////////////////////////////////////////////////////
                        SIGNING PARAMS HELPER
    //////////////////////////////////////////////////////////////*/

    /// @notice Build SigningParams for the given actor and signature type
    function _getSigningParams(uint256 actorIndex, SignatureType sigType, uint256 keySeed)
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
            (address p256Addr, uint256 p256Key, bytes32 pubKeyX, bytes32 pubKeyY) = _getActorP256(actorIndex);
            sender = p256Addr;
            params = TxBuilder.SigningParams({
                strategy: TxBuilder.SigningStrategy.P256,
                privateKey: p256Key,
                pubKeyX: pubKeyX,
                pubKeyY: pubKeyY,
                userAddress: address(0)
            });
        } else if (sigType == SignatureType.WebAuthn) {
            (address p256Addr, uint256 p256Key, bytes32 pubKeyX, bytes32 pubKeyY) = _getActorP256(actorIndex);
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

    function _buildAndSignLegacyTransferWithSigType(
        uint256 actorIndex,
        address to,
        uint256 amount,
        uint64 txNonce,
        uint256 sigTypeSeed
    ) internal view returns (bytes memory signedTx, address sender) {
        SignatureType sigType = _getRandomSignatureType(sigTypeSeed);
        (TxBuilder.SigningParams memory params, address senderAddr) = _getSigningParams(actorIndex, sigType, sigTypeSeed);
        sender = senderAddr;

        LegacyTransaction memory tx_ = LegacyTransactionLib.create()
            .withNonce(txNonce)
            .withGasPrice(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withTo(address(feeToken))
            .withData(abi.encodeCall(ITIP20.transfer, (to, amount)));

        signedTx = TxBuilder.signLegacy(vmRlp, vm, tx_, params);
    }

    function _buildAndSignLegacyTransfer(uint256 actorIndex, address to, uint256 amount, uint64 txNonce)
        internal
        view
        returns (bytes memory)
    {
        return TxBuilder.buildLegacyCall(vmRlp, vm, address(feeToken), abi.encodeCall(ITIP20.transfer, (to, amount)), txNonce, actorKeys[actorIndex]);
    }

    function _buildAndSignLegacyCreateWithSigType(
        uint256 actorIndex,
        bytes memory initcode,
        uint64 txNonce,
        uint256 sigTypeSeed
    ) internal view returns (bytes memory signedTx, address sender) {
        SignatureType sigType = _getRandomSignatureType(sigTypeSeed);
        (TxBuilder.SigningParams memory params, address senderAddr) = _getSigningParams(actorIndex, sigType, sigTypeSeed);
        sender = senderAddr;

        LegacyTransaction memory tx_ = LegacyTransactionLib.create()
            .withNonce(txNonce)
            .withGasPrice(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_CREATE_GAS_LIMIT)
            .withTo(address(0))
            .withData(initcode);

        signedTx = TxBuilder.signLegacy(vmRlp, vm, tx_, params);
    }

    function _buildAndSignLegacyCreate(uint256 actorIndex, bytes memory initcode, uint64 txNonce)
        internal
        view
        returns (bytes memory)
    {
        return TxBuilder.buildLegacyCreate(vmRlp, vm, initcode, txNonce, actorKeys[actorIndex]);
    }

    function _buildAndSignTempoTransferWithSigType(
        uint256 actorIndex,
        address to,
        uint256 amount,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 sigTypeSeed
    ) internal view returns (bytes memory signedTx, address sender) {
        SignatureType sigType = _getRandomSignatureType(sigTypeSeed);
        (TxBuilder.SigningParams memory params, address senderAddr) = _getSigningParams(actorIndex, sigType, sigTypeSeed);
        sender = senderAddr;

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (to, amount))});

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid))
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withCalls(calls)
            .withNonceKey(nonceKey)
            .withNonce(txNonce);

        signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, params);
    }

    /*//////////////////////////////////////////////////////////////
                    NONCE HANDLERS (N1-N5, N12-N15)
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Execute a transfer from a random actor with random signature type
    /// @dev Tests N1 (monotonicity) and N2 (bump on call) across all signature types
    function handler_transfer(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 sigTypeSeed) external {
        (TxContext memory ctx, bool skip) = _setupTransferContext(actorSeed, recipientSeed, amount, sigTypeSeed, 1e6, 100e6);
        if (skip) return;

        uint64 currentNonce = uint64(ghost_protocolNonce[ctx.sender]);
        (bytes memory signedTx,) = _buildAndSignLegacyTransferWithSigType(ctx.senderIdx, ctx.recipient, ctx.amount, currentNonce, sigTypeSeed);

        ghost_previousProtocolNonce[ctx.sender] = ghost_protocolNonce[ctx.sender];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(ctx.sender);
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Execute multiple transfers in sequence from same actor with random sig types
    /// @dev Tests sequential nonce bumping across all signature types
    function handler_sequentialTransfers(uint256 actorSeed, uint256 count, uint256 sigTypeSeed) external {
        count = bound(count, 1, 5);
        // Use wrapping add to prevent overflow
        uint256 recipientSeed;
        unchecked { recipientSeed = actorSeed + 1; }
        uint256 amountPerTx = 10e6;

        (TxContext memory ctx, bool skip) = _setupTransferContext(actorSeed, recipientSeed, amountPerTx * count, sigTypeSeed, amountPerTx, amountPerTx * count);
        if (skip) return;

        for (uint256 i = 0; i < count; i++) {
            ghost_previousProtocolNonce[ctx.sender] = ghost_protocolNonce[ctx.sender];
            uint64 currentNonce = uint64(ghost_protocolNonce[ctx.sender]);

            (bytes memory signedTx,) = _buildAndSignLegacyTransferWithSigType(ctx.senderIdx, ctx.recipient, amountPerTx, currentNonce, sigTypeSeed);
            vm.coinbase(validator);

            try vmExec.executeTransaction(signedTx) {
                _recordProtocolNonceTxSuccess(ctx.sender);
            } catch {
                ghost_totalTxReverted++;
                break;
            }
        }
    }

    /// @notice Handler: Deploy a contract via CREATE with random signature type
    /// @dev Tests N3 (nonce bumps on tx inclusion) and C5-C6 (address derivation) across all sig types
    function handler_create(uint256 actorSeed, uint256 initValue, uint256 sigTypeSeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        SignatureType sigType = _getRandomSignatureType(sigTypeSeed);
        address sender = _getSenderForSigType(senderIdx, sigType);

        initValue = bound(initValue, 0, 1000);

        // Build tx first to get actual sender (may differ for P256/WebAuthn)
        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);
        bytes memory initcode = InitcodeHelper.simpleStorageInitcode(initValue);
        (bytes memory signedTx, address actualSender) = _buildAndSignLegacyCreateWithSigType(senderIdx, initcode, currentNonce, sigTypeSeed);

        // Re-check nonce with actual sender if different
        if (actualSender != sender) {
            currentNonce = uint64(ghost_protocolNonce[actualSender]);
            (signedTx,) = _buildAndSignLegacyCreateWithSigType(senderIdx, initcode, currentNonce, sigTypeSeed);
        }

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
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt to deploy a reverting contract
    /// @dev Tests that reverting initcode causes tx rejection (no nonce consumed)
    function handler_createReverting(uint256 actorSeed, uint256 sigTypeSeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        SignatureType sigType = _getRandomSignatureType(sigTypeSeed);
        address sender = _getSenderForSigType(senderIdx, sigType);

        // Get actual sender first by doing a dry-run build
        bytes memory initcode = InitcodeHelper.revertingContractInitcode();
        (, address actualSender) = _buildAndSignLegacyCreateWithSigType(senderIdx, initcode, 0, sigTypeSeed);

        // Use actual on-chain nonce, not ghost state, to ensure tx is valid
        uint64 currentNonce = uint64(vm.getNonce(actualSender));
        
        // Sync ghost state if needed
        if (ghost_protocolNonce[actualSender] != currentNonce) {
            ghost_protocolNonce[actualSender] = currentNonce;
        }

        // Build the actual transaction with correct nonce
        (bytes memory signedTx,) = _buildAndSignLegacyCreateWithSigType(senderIdx, initcode, currentNonce, sigTypeSeed);

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
                assertEq(nonceAfter, nonceBefore + 1, "C7: Nonce must burn exactly +1 on included reverting create");
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

    /// @notice Handler: Increment a 2D nonce key
    /// @dev Tests N6 (independence) and N7 (monotonicity)
    function handler_2dNonceIncrement(uint256 actorSeed, uint256 nonceKey) external {
        uint256 actorIdx = actorSeed % actors.length;
        address actor = actors[actorIdx];

        // Bound nonce key to reasonable range (1-100, key 0 is protocol nonce)
        nonceKey = bound(nonceKey, 1, 100);

        // Store previous nonce for monotonicity check
        ghost_previous2dNonce[actor][nonceKey] = ghost_2dNonce[actor][nonceKey];

        // Increment via storage manipulation (simulates protocol behavior)
        _incrementNonceViaStorage(actor, nonceKey);
    }

    /// @notice Handler: Increment multiple different nonce keys for same actor
    /// @dev Tests N6 (keys are independent)
    function handler_multipleNonceKeys(uint256 actorSeed, uint256 key1, uint256 key2, uint256 key3) external {
        uint256 actorIdx = actorSeed % actors.length;
        address actor = actors[actorIdx];

        // Bound keys to different values
        key1 = bound(key1, 1, 33);
        key2 = bound(key2, 34, 66);
        key3 = bound(key3, 67, 100);

        // Track previous values
        ghost_previous2dNonce[actor][key1] = ghost_2dNonce[actor][key1];
        ghost_previous2dNonce[actor][key2] = ghost_2dNonce[actor][key2];
        ghost_previous2dNonce[actor][key3] = ghost_2dNonce[actor][key3];

        // Increment each key
        _incrementNonceViaStorage(actor, key1);
        _incrementNonceViaStorage(actor, key2);
        _incrementNonceViaStorage(actor, key3);
    }

    /*//////////////////////////////////////////////////////////////
                    TEMPO TRANSACTION HANDLERS (TX1-TX6)
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Execute a Tempo transfer with random signature type
    /// @dev Tests that Tempo transactions work with all signature types (secp256k1, P256, WebAuthn, Keychain)
    /// With tempo-foundry, Tempo txs with nonceKey > 0 use 2D nonces (not protocol nonce)
    function handler_tempoTransfer(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed, uint256 sigTypeSeed) external {
        (TxContext memory ctx, bool skip) = _setup2dNonceTransferContext(actorSeed, recipientSeed, amount, nonceKeySeed, sigTypeSeed, 1e6, 100e6);
        if (skip) return;

        (bytes memory signedTx,) = _buildAndSignTempoTransferWithSigType(ctx.senderIdx, ctx.recipient, ctx.amount, ctx.nonceKey, ctx.currentNonce, sigTypeSeed);

        ghost_previous2dNonce[ctx.sender][ctx.nonceKey] = ghost_2dNonce[ctx.sender][ctx.nonceKey];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.currentNonce);
        } catch {
            // Sync ghost state if on-chain nonce changed (nonce consumed in pre-execution)
            uint64 actualNonce = nonce.getNonce(ctx.sender, ctx.nonceKey);
            if (actualNonce > ctx.currentNonce) {
                ghost_2dNonce[ctx.sender][ctx.nonceKey] = actualNonce;
                ghost_2dNonceUsed[ctx.sender][ctx.nonceKey] = true;
            }
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Execute a Tempo transfer using protocol nonce (nonceKey = 0)
    /// @dev Tests that Tempo transactions with nonceKey=0 use the protocol nonce
    function handler_tempoTransferProtocolNonce(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 sigTypeSeed) external {
        (TxContext memory ctx, bool skip) = _setupTransferContext(actorSeed, recipientSeed, amount, sigTypeSeed, 1e6, 100e6);
        if (skip) return;

        uint64 nonceKey = 0;
        uint64 currentNonce = uint64(ghost_protocolNonce[ctx.sender]);
        (bytes memory signedTx, address sender) = _buildAndSignTempoTransferWithSigType(ctx.senderIdx, ctx.recipient, ctx.amount, nonceKey, currentNonce, sigTypeSeed);

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(sender);
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Use access key with Tempo transaction
    /// @dev Tests access keys with Tempo transactions (K5, K9 with Tempo tx type)
    function handler_tempoUseAccessKey(uint256 actorSeed, uint256 keySeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
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
            vmRlp, vm, address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            nonceKey, currentNonce, ctx.keyPk, ctx.owner
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.owner, nonceKey, currentNonce);
            if (ghost_keyEnforceLimits[ctx.owner][ctx.keyId]) {
                _recordKeySpending(ctx.owner, ctx.keyId, address(feeToken), amount);
            }
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Use P256 access key with Tempo transaction
    /// @dev Tests P256 access keys with Tempo transactions
    function handler_tempoUseP256AccessKey(uint256 actorSeed, uint256 keySeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
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
            vmRlp, vm, address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            nonceKey, currentNonce, ctx.keyPk, ctx.pubKeyX, ctx.pubKeyY, ctx.owner
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.owner, nonceKey, currentNonce);
            if (ghost_keyEnforceLimits[ctx.owner][ctx.keyId]) {
                _recordKeySpending(ctx.owner, ctx.keyId, address(feeToken), amount);
            }
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ACCESS KEY HANDLERS (K1-K12)
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Authorize an access key with random key type (secp256k1 or P256)
    /// @dev Tests K1-K4 (key authorization rules) with multiple signature types
    function handler_authorizeKey(uint256 actorSeed, uint256 keySeed, uint256 expirySeed, uint256 limitSeed) external {
        AccessKeyContext memory ctx = _setupRandomKeyContext(actorSeed, keySeed);
        if (ghost_keyAuthorized[ctx.owner][ctx.keyId]) return;

        uint64 expiry = uint64(block.timestamp + bound(expirySeed, 1 hours, 365 days));
        uint256 limit = bound(limitSeed, 1e6, 1000e6);

        IAccountKeychain.SignatureType keyType = ctx.isP256
            ? IAccountKeychain.SignatureType.P256
            : IAccountKeychain.SignatureType.Secp256k1;

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({token: address(feeToken), amount: limit});

        vm.prank(ctx.owner);
        try keychain.authorizeKey(ctx.keyId, keyType, expiry, true, limits) {
            address[] memory tokens = new address[](1);
            tokens[0] = address(feeToken);
            uint256[] memory amounts = new uint256[](1);
            amounts[0] = limit;
            _authorizeKey(ctx.owner, ctx.keyId, expiry, true, tokens, amounts);
        } catch {}
    }

    /// @notice Handler: Revoke an access key (secp256k1 or P256)
    /// @dev Tests K7-K8 (revoked keys rejected)
    function handler_revokeKey(uint256 actorSeed, uint256 keySeed) external {
        AccessKeyContext memory ctx = _setupRandomKeyContext(actorSeed, keySeed);
        if (!ghost_keyAuthorized[ctx.owner][ctx.keyId]) return;

        vm.prank(ctx.owner);
        try keychain.revokeKey(ctx.keyId) {
            _revokeKey(ctx.owner, ctx.keyId);
        } catch {}
    }

    /// @notice Handler: Use an authorized access key to transfer tokens
    /// @dev Tests K5 (key must exist), K9 (spending limits enforced)
    function handler_useAccessKey(uint256 actorSeed, uint256 keySeed, uint256 recipientSeed, uint256 amount) external {
        AccessKeyContext memory ctx = _setupSecp256k1KeyContext(actorSeed, keySeed);
        amount = bound(amount, 1e6, 50e6);

        if (!_canUseKey(ctx.owner, ctx.keyId, amount)) return;
        if (!_checkBalance(ctx.owner, amount)) return;

        uint256 recipientIdx = recipientSeed % actors.length;
        if (ctx.actorIdx == recipientIdx) recipientIdx = (recipientIdx + 1) % actors.length;
        address recipient = actors[recipientIdx];

        ghost_previousProtocolNonce[ctx.owner] = ghost_protocolNonce[ctx.owner];
        uint64 currentNonce = uint64(ghost_protocolNonce[ctx.owner]);

        bytes memory signedTx = TxBuilder.buildLegacyCallKeychain(
            vmRlp, vm, address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            currentNonce, ctx.keyPk, ctx.owner
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceTxSuccess(ctx.owner);
            if (ghost_keyEnforceLimits[ctx.owner][ctx.keyId]) {
                _recordKeySpending(ctx.owner, ctx.keyId, address(feeToken), amount);
            }
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt transfer with insufficient balance
    /// @dev Tests F9 (insufficient balance rejected) - tx reverts but nonce is consumed
    function handler_insufficientBalanceTransfer(uint256 actorSeed, uint256 recipientSeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        // Try to transfer more than balance
        uint256 balance = feeToken.balanceOf(sender);
        uint256 excessAmount = balance + 1e6;

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];
        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);

        bytes memory signedTx = _buildAndSignLegacyTransfer(senderIdx, recipient, excessAmount, currentNonce);

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
            // Transaction was rejected - could be due to:
            // 1. Nonce mismatch (ghost out of sync) - nonce unchanged
            // 2. Insufficient balance for gas - nonce unchanged  
            // 3. Inner call revert after inclusion - nonce consumed
            // Sync ghost state to actual on-chain state to prevent cascading failures
            ghost_protocolNonce[sender] = nonceAfter;
            if (nonceAfter > nonceBefore) {
                ghost_totalProtocolNonceTxs++;
            }
            ghost_totalTxReverted++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                    NONCE INVARIANTS N9-N15 HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Execute a Tempo CREATE with 2D nonce (nonceKey > 0)
    /// @dev Tests N9 - CREATE address derivation still uses protocol nonce, not 2D nonce
    function handler_tempoCreate(uint256 actorSeed, uint256 initValue, uint256 nonceKeySeed) external {
        CreateContext memory ctx = _setupCreateContext(actorSeed, nonceKeySeed);
        initValue = bound(initValue, 0, 1000);

        bytes memory initcode = InitcodeHelper.simpleStorageInitcode(initValue);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({to: address(0), value: 0, data: initcode});

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid))
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_CREATE_GAS_LIMIT)
            .withCalls(calls)
            .withNonceKey(ctx.nonceKey)
            .withNonce(ctx.current2dNonce);

        bytes memory signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, TxBuilder.SigningParams({
            strategy: TxBuilder.SigningStrategy.Secp256k1,
            privateKey: actorKeys[ctx.senderIdx],
            pubKeyX: bytes32(0),
            pubKeyY: bytes32(0),
            userAddress: address(0)
        }));

        address expectedAddress = TxBuilder.computeCreateAddress(ctx.sender, ctx.protocolNonce);
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceCreateSuccess(ctx.sender, ctx.nonceKey, ctx.protocolNonce, expectedAddress);
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                    CREATE CONSTRAINT HANDLERS (C1-C4, C8-C9)
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler: Attempt CREATE as second call in multicall (invalid - C1)
    /// @dev C1: CREATE only allowed as first call in batch
    function handler_createNotFirst(uint256 actorSeed, uint256 initValue, uint256 nonceKeySeed) external {
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

        try vmExec.executeTransaction(signedTx) {
            // Unexpected success - sync ghost state to prevent false invariant failures
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.current2dNonce);
            ghost_createNotFirstAllowed++;
        } catch {
            _recordCreateRejectedStructure();
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt two CREATEs in same multicall (invalid - C2)
    /// @dev C2: Maximum one CREATE per transaction
    function handler_createMultiple(uint256 actorSeed, uint256 initValue1, uint256 initValue2, uint256 nonceKeySeed) external {
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

        try vmExec.executeTransaction(signedTx) {
            // Unexpected success - sync ghost state to prevent false invariant failures
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.current2dNonce);
            ghost_createMultipleAllowed++;
        } catch {
            _recordCreateRejectedStructure();
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt CREATE with EIP-7702 authorization list (invalid - C3)
    /// @dev C3: CREATE forbidden with authorization list
    function handler_createWithAuthList(uint256 actorSeed, uint256 initValue, uint256 nonceKeySeed) external {
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

        try vmExec.executeTransaction(signedTx) {
            // Unexpected success - sync ghost state to prevent false invariant failures
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.current2dNonce);
            ghost_createWithAuthAllowed++;
        } catch {
            ghost_protocolNonce[ctx.sender]++;
            ghost_totalProtocolNonceTxs++;
            _recordCreateRejectedStructure();
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt CREATE with value > 0 (invalid for Tempo - C4)
    /// @dev C4: Value transfers forbidden in AA transactions
    function handler_createWithValue(uint256 actorSeed, uint256 initValue, uint256 valueSeed, uint256 nonceKeySeed) external {
        CreateContext memory ctx = _setupCreateContext(actorSeed, nonceKeySeed);
        initValue = bound(initValue, 0, 1000);
        uint256 value = bound(valueSeed, 1, 1 ether);

        bytes memory initcode = InitcodeHelper.simpleStorageInitcode(initValue);

        bytes memory signedTx = TxBuilder.buildTempoCreateWithValue(
            vmRlp,
            vm,
            initcode,
            value,
            ctx.nonceKey,
            ctx.current2dNonce,
            actorKeys[ctx.senderIdx]
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            // Unexpected success - sync ghost state to prevent false invariant failures
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

        bytes memory initcode = InitcodeHelper.largeInitcode(50000);

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

        try vmExec.executeTransaction(signedTx) {
            // Unexpected success - sync ghost state to prevent false invariant failures
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.current2dNonce);
            ghost_createOversizedAllowed++;
        } catch {
            _recordCreateRejectedSize();
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Track gas for CREATE with different initcode sizes (C9)
    /// @dev C9: Initcode costs 2 gas per 32-byte chunk (INITCODE_WORD_COST)
    function handler_createGasScaling(uint256 actorSeed, uint256 sizeSeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];
        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);

        uint256 initcodeSize = bound(sizeSeed, 100, 10000);
        bytes memory initcode = InitcodeHelper.largeInitcode(initcodeSize);
        uint64 expectedWordCost = uint64((initcodeSize + 31) / 32 * 2);
        uint64 gasLimit = TxBuilder.DEFAULT_CREATE_GAS_LIMIT + expectedWordCost + 50000;

        bytes memory signedTx = TxBuilder.buildLegacyCreateWithGas(
            vmRlp, vm, initcode, currentNonce, gasLimit, actorKeys[senderIdx]
        );

        address expectedAddress = TxBuilder.computeCreateAddress(sender, currentNonce);
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _recordProtocolNonceCreateSuccess(sender, currentNonce, expectedAddress);
            _recordCreateGasTracked();
        } catch {
            ghost_protocolNonce[sender]++;
            ghost_totalProtocolNonceTxs++;
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt to replay a Legacy transaction with same protocol nonce
    /// @dev Tests N12 - replay with same protocol nonce fails
    function handler_replayProtocolNonce(uint256 actorSeed, uint256 recipientSeed, uint256 amount) external {
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

        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);
        bytes memory signedTx = _buildAndSignLegacyTransfer(senderIdx, recipient, amount, currentNonce);

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];

        vm.coinbase(validator);

        // Snapshot nonce before first tx
        uint256 nonce0 = vm.getNonce(sender);

        // First execution should succeed and consume exactly 1 nonce
        try vmExec.executeTransaction(signedTx) {
            uint256 nonce1 = vm.getNonce(sender);
            assertEq(nonce1, nonce0 + 1, "N12: First tx must consume exactly one nonce");
            ghost_protocolNonce[sender] = nonce1;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
        } catch {
            // First tx failed - skip replay test
            ghost_totalTxReverted++;
            return;
        }

        // Replay should fail - nonce already consumed
        try vmExec.executeTransaction(signedTx) {
            // Replay unexpectedly succeeded - this is a BUG in the protocol!
            ghost_replayProtocolAllowed++;
        } catch {
            // Expected: replay rejected
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt to replay a Tempo transaction with same 2D nonce
    /// @dev Tests N13 - replay with same 2D nonce fails
    function handler_replay2dNonce(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);
        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));

        uint256 balance = feeToken.balanceOf(sender);
        if (balance < amount * 2) {
            return;
        }

        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, amount))});

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid))
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withCalls(calls)
            .withNonceKey(nonceKey)
            .withNonce(currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, TxBuilder.SigningParams({
            strategy: TxBuilder.SigningStrategy.Secp256k1,
            privateKey: actorKeys[senderIdx],
            pubKeyX: bytes32(0),
            pubKeyY: bytes32(0),
            userAddress: address(0)
        }));

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        vm.coinbase(validator);

        // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
        try vmExec.executeTransaction(signedTx) {
            // Verify on-chain nonce actually incremented before updating ghost
            uint64 actualNonce = nonce.getNonce(sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
            }
        } catch {
            ghost_totalTxReverted++;
            return;
        }

        try vmExec.executeTransaction(signedTx) {
            // Replay unexpectedly succeeded - this is a BUG in the protocol!
            ghost_replay2dAllowed++;
        } catch {
            // Expected: replay rejected
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt to use nonce higher than current (nonce + 1)
    /// @dev Tests N14 - nonce too high is rejected
    function handler_nonceTooHigh(uint256 actorSeed, uint256 recipientSeed, uint256 amount) external {
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

        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);
        uint64 wrongNonce = currentNonce + 1;

        bytes memory signedTx = _buildAndSignLegacyTransfer(senderIdx, recipient, amount, wrongNonce);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            // Tx with future nonce unexpectedly succeeded - this is a BUG!
            ghost_nonceTooHighAllowed++;
        } catch {
            // Expected: tx rejected
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Attempt to use nonce lower than current (nonce - 1)
    /// @dev Tests N15 - nonce too low is rejected (requires at least 1 tx executed)
    function handler_nonceTooLow(uint256 actorSeed, uint256 recipientSeed, uint256 amount) external {
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

        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);
        if (currentNonce == 0) {
            return;
        }

        uint64 wrongNonce = currentNonce - 1;

        bytes memory signedTx = _buildAndSignLegacyTransfer(senderIdx, recipient, amount, wrongNonce);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_nonceTooLowAllowed++;
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Track gas cost for first vs subsequent 2D nonce key usage
    /// @dev Tests N10 (cold gas cost) and N11 (warm gas cost)
    function handler_2dNonceGasCost(uint256 actorSeed, uint256 nonceKeySeed, uint256 recipientSeed, uint256 amount) external {
        uint256 senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        address sender = actors[senderIdx];
        address recipient = actors[recipientIdx];

        amount = bound(amount, 1e6, 10e6);
        uint64 nonceKey = uint64(bound(nonceKeySeed, 101, 200));

        uint256 balance = feeToken.balanceOf(sender);
        if (balance < amount * 2) {
            return;
        }

        bool isFirstUse = !ghost_2dNonceUsed[sender][nonceKey];
        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, amount))});

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid))
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withCalls(calls)
            .withNonceKey(nonceKey)
            .withNonce(currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, TxBuilder.SigningParams({
            strategy: TxBuilder.SigningStrategy.Secp256k1,
            privateKey: actorKeys[senderIdx],
            pubKeyX: bytes32(0),
            pubKeyY: bytes32(0),
            userAddress: address(0)
        }));

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        vm.coinbase(validator);

        // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
        uint256 gasBefore = gasleft();
        try vmExec.executeTransaction(signedTx) {
            uint256 gasUsed = gasBefore - gasleft();

            // Verify on-chain nonce actually incremented before updating ghost
            uint64 actualNonce = nonce.getNonce(sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;

                if (isFirstUse) {
                    ghost_firstUseGas[sender][nonceKey] = gasUsed;
                } else {
                    ghost_subsequentUseGas[sender][nonceKey] = gasUsed;
                }
            }
        } catch {
            ghost_totalTxReverted++;
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

    /// @notice Handler K1: Attempt to authorize a key with a different signer (not root)
    /// @dev KeyAuthorization MUST be signed by tx.caller (root account)
    function handler_keyAuthWrongSigner(uint256 actorSeed, uint256 keySeed, uint256 wrongSignerSeed) external {
        uint256 actorIdx = actorSeed % actors.length;
        uint256 wrongSignerIdx = wrongSignerSeed % actors.length;
        if (actorIdx == wrongSignerIdx) {
            wrongSignerIdx = (wrongSignerIdx + 1) % actors.length;
        }

        address owner = actors[actorIdx];
        address wrongSigner = actors[wrongSignerIdx];

        (address keyId,) = _getActorAccessKey(actorIdx, keySeed);

        if (ghost_keyAuthorized[owner][keyId]) {
            return;
        }

        uint64 expiry = uint64(block.timestamp + 1 days);
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({token: address(feeToken), amount: 100e6});

        vm.prank(wrongSigner);
        try keychain.authorizeKey(keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, true, limits) {
            ghost_keyWrongSignerAllowed++;
        } catch {
            ghost_keyAuthRejectedWrongSigner++;
        }
    }

    /// @notice Handler K2: Attempt to have access key A authorize access key B
    /// @dev Access key can only authorize itself, not other keys
    function handler_keyAuthNotSelf(uint256 actorSeed, uint256 keyASeed, uint256 keyBSeed) external {
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
            try keychain.authorizeKey(keyIdA, IAccountKeychain.SignatureType.Secp256k1, expiryA, false, limitsA) {
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
        limitsB[0] = IAccountKeychain.TokenLimit({token: address(feeToken), amount: 100e6});

        uint64 currentNonce = uint64(ghost_protocolNonce[owner]);
        bytes memory signedTx = TxBuilder.buildLegacyCallKeychain(
            vmRlp,
            vm,
            address(keychain),
            abi.encodeCall(IAccountKeychain.authorizeKey, (keyIdB, IAccountKeychain.SignatureType.Secp256k1, expiryB, true, limitsB)),
            currentNonce,
            keyPkA,
            owner
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_protocolNonce[owner]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
        } catch {
            ghost_keyAuthRejectedNotSelf++;
        }
    }

    /// @notice Handler K3: Attempt to use KeyAuthorization with wrong chain_id
    /// @dev KeyAuthorization chain_id must be 0 (any) or match current
    function handler_keyAuthWrongChainId(uint256 actorSeed, uint256 keySeed, uint256 wrongChainIdSeed) external {
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
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (actors[(actorIdx + 1) % actors.length], amount))});

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(wrongChainId)
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withCalls(calls)
            .withNonceKey(nonceKey)
            .withNonce(currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, TxBuilder.SigningParams({
            strategy: TxBuilder.SigningStrategy.KeychainSecp256k1,
            privateKey: keyPk,
            pubKeyX: bytes32(0),
            pubKeyY: bytes32(0),
            userAddress: owner
        }));

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_keyWrongChainAllowed++;
        } catch {
            ghost_keyAuthRejectedChainId++;
        }
    }

    /// @notice Handler K6: Authorize key and use it in same transaction batch (multicall)
    /// @dev Same-tx authorize + use is permitted
    function handler_keySameTxAuthorizeAndUse(uint256 actorSeed, uint256 keySeed, uint256 amount) external {
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
        limits[0] = IAccountKeychain.TokenLimit({token: address(feeToken), amount: 100e6});

        uint64 nonceKey = 5;
        uint64 currentNonce = uint64(ghost_2dNonce[owner][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({
            to: address(keychain),
            value: 0,
            data: abi.encodeCall(IAccountKeychain.authorizeKey, (keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, true, limits))
        });
        calls[1] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (recipient, amount))
        });

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(vmRlp, vm, calls, nonceKey, currentNonce, actorKeys[actorIdx]);

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
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler K10: Verify spending limits reset after spending period expires
    /// @dev Limits reset after spending period expires
    function handler_keySpendingPeriodReset(uint256 actorSeed, uint256 keySeed, uint256 timeWarpSeed, uint256 amount) external {
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

        bytes memory signedTx = TxBuilder.buildLegacyCallKeychain(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            currentNonce,
            keyPk,
            owner
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_protocolNonce[owner]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
            ghost_keyPeriodReset++;
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler K11: Verify keys without spending limits can spend unlimited
    /// @dev None = unlimited spending for that token
    function handler_keyUnlimitedSpending(uint256 actorSeed, uint256 keySeed, uint256 amount) external {
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
            try keychain.authorizeKey(keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, false, emptyLimits) {
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

        bytes memory signedTx = TxBuilder.buildLegacyCallKeychain(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            currentNonce,
            keyPk,
            owner
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_protocolNonce[owner]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
            ghost_keyUnlimitedUsed++;
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler K12: Verify keys with empty limits array cannot spend anything
    /// @dev Empty array = zero spending allowed
    function handler_keyZeroSpendingLimit(uint256 actorSeed, uint256 keySeed, uint256 amount) external {
        uint256 actorIdx = actorSeed % actors.length;
        address owner = actors[actorIdx];
        address recipient = actors[(actorIdx + 1) % actors.length];

        (address keyId, uint256 keyPk) = _getActorAccessKey(actorIdx, keySeed);

        if (!ghost_keyAuthorized[owner][keyId]) {
            uint64 expiry = uint64(block.timestamp + 1 days);
            IAccountKeychain.TokenLimit[] memory emptyLimits = new IAccountKeychain.TokenLimit[](0);
            vm.prank(owner);
            try keychain.authorizeKey(keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, true, emptyLimits) {
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

        bytes memory signedTx = TxBuilder.buildLegacyCallKeychain(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            currentNonce,
            keyPk,
            owner
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_protocolNonce[owner]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
        } catch {
            ghost_keyZeroLimitRejected++;
        }
    }

    /// @notice Handler K16: Verify signature type mismatch is rejected
    /// @dev Try to use secp256k1-authorized key with P256 signature
    function handler_keySigTypeMismatch(uint256 actorSeed, uint256 keySeed, uint256 amount) external {
        uint256 actorIdx = actorSeed % actors.length;
        address owner = actors[actorIdx];
        address recipient = actors[(actorIdx + 1) % actors.length];

        (address keyId,) = _getActorAccessKey(actorIdx, keySeed);

        if (!ghost_keyAuthorized[owner][keyId]) {
            uint64 expiry = uint64(block.timestamp + 1 days);
            IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);
            vm.prank(owner);
            try keychain.authorizeKey(keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, false, limits) {
                address[] memory tokens = new address[](0);
                uint256[] memory amounts = new uint256[](0);
                _authorizeKey(owner, keyId, expiry, false, tokens, amounts);
                ghost_keySignatureType[owner][keyId] = uint8(IAccountKeychain.SignatureType.Secp256k1);
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

        (address p256KeyId, uint256 p256Pk, bytes32 pubKeyX, bytes32 pubKeyY) = _getActorP256AccessKey(actorIdx, keySeed);
        if (p256KeyId == keyId) {
            return;
        }

        uint64 currentNonce = uint64(ghost_protocolNonce[owner]);

        bytes memory signedTx = TxBuilder.buildLegacyCallKeychainP256(
            vmRlp,
            vm,
            address(feeToken),
            abi.encodeCall(ITIP20.transfer, (recipient, amount)),
            currentNonce,
            p256Pk,
            pubKeyX,
            pubKeyY,
            owner
        );

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_protocolNonce[owner]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
        } catch {
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
    function handler_tempoMulticall(uint256 actorSeed, uint256 recipientSeed, uint256 amount1, uint256 amount2, uint256 nonceKeySeed) external {
        (TxContext memory ctx, bool skip, uint256 totalAmount) = _setupMulticallContext(actorSeed, recipientSeed, amount1, amount2, nonceKeySeed);
        if (skip) return;

        uint256 amt2 = totalAmount - ctx.amount;
        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, ctx.amount))});
        calls[1] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, amt2))});

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(vmRlp, vm, calls, ctx.nonceKey, ctx.currentNonce, actorKeys[ctx.senderIdx]);
        uint256 recipientBalanceBefore = feeToken.balanceOf(ctx.recipient);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey);
            ghost_totalMulticallsExecuted++;
            uint256 recipientBalanceAfter = feeToken.balanceOf(ctx.recipient);
            assertEq(recipientBalanceAfter, recipientBalanceBefore + totalAmount, "M4: Multicall transfers not applied");
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Execute a multicall where the last call fails
    /// @dev Tests M1 (all or nothing), M2 (partial state reverted), M3 (logs cleared)
    function handler_tempoMulticallWithFailure(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
        (TxContext memory ctx, bool skip) = _setup2dNonceTransferContext(actorSeed, recipientSeed, amount, nonceKeySeed, 0, 1e6, 10e6);
        if (skip) return;

        uint256 excessAmount = feeToken.balanceOf(ctx.sender) + 1e6;

        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, ctx.amount))});
        calls[1] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, excessAmount))});

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(vmRlp, vm, calls, ctx.nonceKey, ctx.currentNonce, actorKeys[ctx.senderIdx]);

        uint256 senderBalanceBefore = feeToken.balanceOf(ctx.sender);
        uint256 recipientBalanceBefore = feeToken.balanceOf(ctx.recipient);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey);
        } catch {
            // Nonce is consumed even if tx reverts during execution (nonce incremented in pre-execution)
            // Sync ghost state if on-chain nonce changed
            uint64 actualNonce = nonce.getNonce(ctx.sender, ctx.nonceKey);
            if (actualNonce > ctx.currentNonce) {
                ghost_2dNonce[ctx.sender][ctx.nonceKey] = actualNonce;
                ghost_2dNonceUsed[ctx.sender][ctx.nonceKey] = true;
            }
            ghost_totalTxReverted++;
            ghost_totalMulticallsFailed++;

            uint256 senderBalanceAfter = feeToken.balanceOf(ctx.sender);
            uint256 recipientBalanceAfter = feeToken.balanceOf(ctx.recipient);
            assertEq(senderBalanceAfter, senderBalanceBefore, "M1/M2: First call state not reverted on batch failure");
            assertEq(recipientBalanceAfter, recipientBalanceBefore, "M1/M2: First call state not reverted on batch failure");
        }
    }

    /// @notice Handler: Execute a multicall where call N+1 depends on call N's state
    /// @dev Tests M8 (state changes visible) and M9 (balance changes propagate)
    function handler_tempoMulticallStateVisibility(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
        (TxContext memory ctx, bool skip) = _setup2dNonceTransferContext(actorSeed, recipientSeed, amount, nonceKeySeed, 0, 1e6, 10e6);
        if (skip) return;
        if (feeToken.balanceOf(ctx.recipient) < ctx.amount) return;

        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, ctx.amount))});
        calls[1] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transferFrom, (ctx.recipient, ctx.sender, ctx.amount))});

        vm.prank(ctx.recipient);
        feeToken.approve(ctx.sender, ctx.amount);

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(vmRlp, vm, calls, ctx.nonceKey, ctx.currentNonce, actorKeys[ctx.senderIdx]);

        uint256 senderBalanceBefore = feeToken.balanceOf(ctx.sender);
        uint256 recipientBalanceBefore = feeToken.balanceOf(ctx.recipient);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey);
            ghost_totalMulticallsWithStateVisibility++;

            uint256 senderBalanceAfter = feeToken.balanceOf(ctx.sender);
            uint256 recipientBalanceAfter = feeToken.balanceOf(ctx.recipient);
            assertEq(senderBalanceAfter, senderBalanceBefore, "M8/M9: State visibility - sender balance should be unchanged after round-trip");
            assertEq(recipientBalanceAfter, recipientBalanceBefore, "M8/M9: State visibility - recipient balance should be unchanged after round-trip");
        } catch {
            ghost_totalTxReverted++;
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
    function handler_feeCollection(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
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

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, amount))});

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid))
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withCalls(calls)
            .withNonceKey(nonceKey)
            .withNonce(currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, TxBuilder.SigningParams({
            strategy: TxBuilder.SigningStrategy.Secp256k1,
            privateKey: actorKeys[senderIdx],
            pubKeyX: bytes32(0),
            pubKeyY: bytes32(0),
            userAddress: address(0)
        }));

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        uint256 balanceBefore = feeToken.balanceOf(sender);
        ghost_balanceBeforeTx[sender] = balanceBefore;

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            uint256 balanceAfter = feeToken.balanceOf(sender);
            ghost_balanceAfterTx[sender] = balanceAfter;

            uint256 expectedTransfer = amount;
            uint256 actualDecrease = balanceBefore - balanceAfter;

            if (actualDecrease > expectedTransfer) {
                uint256 feePaid = actualDecrease - expectedTransfer;
                _recordFeeCollection(sender, feePaid);
                _recordFeePrecollected();
            }

            // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
            // Verify on-chain nonce actually incremented before updating ghost
            uint64 actualNonce = nonce.getNonce(sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
                ghost_feeTrackingTransactions++;
            }
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler F3: Verify unused gas is refunded on success
    /// @dev F3: Unused gas refunded only if ALL calls succeed
    function handler_feeRefundSuccess(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
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

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, amount / 2))});
        calls[1] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, amount / 2))});

        uint64 highGasLimit = TxBuilder.DEFAULT_GAS_LIMIT * 10;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid))
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(highGasLimit)
            .withCalls(calls)
            .withNonceKey(nonceKey)
            .withNonce(currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, TxBuilder.SigningParams({
            strategy: TxBuilder.SigningStrategy.Secp256k1,
            privateKey: actorKeys[senderIdx],
            pubKeyX: bytes32(0),
            pubKeyY: bytes32(0),
            userAddress: address(0)
        }));

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        uint256 balanceBefore = feeToken.balanceOf(sender);
        uint256 maxFee = uint256(highGasLimit) * TxBuilder.DEFAULT_GAS_PRICE;

        vm.coinbase(validator);

        // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
        try vmExec.executeTransaction(signedTx) {
            uint256 balanceAfter = feeToken.balanceOf(sender);
            uint256 actualDecrease = balanceBefore - balanceAfter;
            uint256 transferAmount = amount;

            if (actualDecrease < transferAmount + maxFee) {
                _recordFeeRefundOnSuccess();
            }

            // Verify on-chain nonce actually incremented before updating ghost
            uint64 actualNonce = nonce.getNonce(sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
            }
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler F4: Verify no refund when any call fails
    /// @dev F4: No refund if any call in batch fails
    function handler_feeNoRefundFailure(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
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

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        uint256 excessAmount = balance + 1e6;

        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, amount))});
        calls[1] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, excessAmount))});

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(vmRlp, vm, calls, nonceKey, currentNonce, actorKeys[senderIdx]);

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        uint256 balanceBefore = feeToken.balanceOf(sender);

        vm.coinbase(validator);

        // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
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
            uint256 balanceAfter = feeToken.balanceOf(sender);
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
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (actors[0], excessAmount))});

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(vmRlp, vm, calls, nonceKey, currentNonce, actorKeys[senderIdx]);

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        uint256 balanceBefore = feeToken.balanceOf(sender);

        vm.coinbase(validator);

        // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
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
            uint256 balanceAfter = feeToken.balanceOf(sender);
            if (balanceAfter < balanceBefore) {
                _recordFeePaidOnRevert();
            }
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler F6: Verify non-TIP20 fee token is rejected
    /// @dev F6: Non-zero spending requires TIP20 prefix (0x20C0...)
    function handler_invalidFeeToken(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
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

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, amount))});

        address invalidFeeToken = address(0x1234567890123456789012345678901234567890);

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid))
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withCalls(calls)
            .withNonceKey(nonceKey)
            .withNonce(currentNonce)
            .withFeeToken(invalidFeeToken);

        bytes memory signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, TxBuilder.SigningParams({
            strategy: TxBuilder.SigningStrategy.Secp256k1,
            privateKey: actorKeys[senderIdx],
            pubKeyX: bytes32(0),
            pubKeyY: bytes32(0),
            userAddress: address(0)
        }));

        vm.coinbase(validator);

        // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
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
            _recordInvalidFeeTokenRejected();
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler F7: Verify explicit fee token takes priority
    /// @dev F7: Explicit tx.fee_token takes priority
    function handler_explicitFeeToken(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
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

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, amount))});

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid))
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withCalls(calls)
            .withNonceKey(nonceKey)
            .withNonce(currentNonce)
            .withFeeToken(address(feeToken));

        bytes memory signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, TxBuilder.SigningParams({
            strategy: TxBuilder.SigningStrategy.Secp256k1,
            privateKey: actorKeys[senderIdx],
            pubKeyX: bytes32(0),
            pubKeyY: bytes32(0),
            userAddress: address(0)
        }));

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        vm.coinbase(validator);

        // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
        try vmExec.executeTransaction(signedTx) {
            uint64 actualNonce = nonce.getNonce(sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
                _recordExplicitFeeTokenUsed();
            }
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler F8: Verify fee token fallback order
    /// @dev F8: Falls back to user preference → validator preference → default
    function handler_feeTokenFallback(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
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

        uint64 nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        uint64 currentNonce = uint64(ghost_2dNonce[sender][nonceKey]);

        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, amount))});

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid))
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withCalls(calls)
            .withNonceKey(nonceKey)
            .withNonce(currentNonce);

        bytes memory signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, TxBuilder.SigningParams({
            strategy: TxBuilder.SigningStrategy.Secp256k1,
            privateKey: actorKeys[senderIdx],
            pubKeyX: bytes32(0),
            pubKeyY: bytes32(0),
            userAddress: address(0)
        }));

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        vm.coinbase(validator);

        // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
        try vmExec.executeTransaction(signedTx) {
            uint64 actualNonce = nonce.getNonce(sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
                _recordFeeTokenFallbackUsed();
            }
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler F10: Verify tx rejected if AMM can't swap fee token
    /// @dev F10: Tx rejected if AMM can't swap fee token
    function handler_insufficientLiquidity(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
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
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, amount))});

        address noLiquidityToken = address(token1);

        uint256 tokenBalance = token1.balanceOf(sender);
        if (tokenBalance < 1e6) {
            vm.prank(admin);
            token1.grantRole(_ISSUER_ROLE, admin);
            vm.prank(admin);
            token1.mint(sender, 10_000_000e6);
        }

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid))
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withCalls(calls)
            .withNonceKey(nonceKey)
            .withNonce(currentNonce)
            .withFeeToken(noLiquidityToken);

        bytes memory signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, TxBuilder.SigningParams({
            strategy: TxBuilder.SigningStrategy.Secp256k1,
            privateKey: actorKeys[senderIdx],
            pubKeyX: bytes32(0),
            pubKeyY: bytes32(0),
            userAddress: address(0)
        }));

        vm.coinbase(validator);

        // Tempo txs with nonceKey > 0 only increment 2D nonce, not protocol nonce
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
    ) internal view returns (bytes memory signedTx, address sender) {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (to, amount))});

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid))
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withCalls(calls)
            .withNonceKey(nonceKey)
            .withNonce(txNonce);

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
    function handler_timeBoundValidAfter(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 futureOffset) external {
        (TxContext memory ctx, bool skip) = _setup2dNonceTransferContext(actorSeed, recipientSeed, amount, 1, 0, 1e6, 100e6);
        ctx.nonceKey = 1;
        ctx.currentNonce = uint64(ghost_2dNonce[ctx.sender][ctx.nonceKey]);
        if (skip) return;

        futureOffset = bound(futureOffset, 1, 1 days);
        uint64 validAfter = uint64(block.timestamp + futureOffset);

        (bytes memory signedTx,) = _buildTempoWithTimeBounds(ctx.senderIdx, ctx.recipient, ctx.amount, ctx.nonceKey, ctx.currentNonce, validAfter, 0);
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.currentNonce);
            ghost_timeBoundTxsExecuted++;
        } catch {
            ghost_timeBoundTxsRejected++;
            ghost_validAfterRejections++;
        }
    }

    /// @notice Handler T2: Tx rejected if block.timestamp >= validBefore
    /// @dev Creates a Tempo tx with validBefore in the past, expects rejection
    function handler_timeBoundValidBefore(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 pastOffset) external {
        (TxContext memory ctx, bool skip) = _setup2dNonceTransferContext(actorSeed, recipientSeed, amount, 2, 0, 1e6, 100e6);
        ctx.nonceKey = 2;
        ctx.currentNonce = uint64(ghost_2dNonce[ctx.sender][ctx.nonceKey]);
        if (skip) return;

        pastOffset = bound(pastOffset, 0, block.timestamp > 1 ? block.timestamp - 1 : 0);
        uint64 validBefore = uint64(block.timestamp - pastOffset);
        if (validBefore == 0) validBefore = 1;

        (bytes memory signedTx,) = _buildTempoWithTimeBounds(ctx.senderIdx, ctx.recipient, ctx.amount, ctx.nonceKey, ctx.currentNonce, 0, validBefore);
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.currentNonce);
            ghost_timeBoundTxsExecuted++;
        } catch {
            ghost_timeBoundTxsRejected++;
            ghost_validBeforeRejections++;
        }
    }

    /// @notice Handler T3: Both validAfter and validBefore enforced
    /// @dev Creates a Tempo tx with both bounds set, tests edge cases
    function handler_timeBoundValid(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 windowSize) external {
        (TxContext memory ctx, bool skip) = _setup2dNonceTransferContext(actorSeed, recipientSeed, amount, 3, 0, 1e6, 100e6);
        ctx.nonceKey = 3;
        ctx.currentNonce = uint64(ghost_2dNonce[ctx.sender][ctx.nonceKey]);
        if (skip) return;

        windowSize = bound(windowSize, 1 hours, 1 days);
        uint64 validAfter = uint64(block.timestamp > 1 hours ? block.timestamp - 1 hours : 0);
        uint64 validBefore = uint64(block.timestamp + windowSize);

        (bytes memory signedTx,) = _buildTempoWithTimeBounds(ctx.senderIdx, ctx.recipient, ctx.amount, ctx.nonceKey, ctx.currentNonce, validAfter, validBefore);
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.currentNonce);
            ghost_timeBoundTxsExecuted++;
        } catch {
            ghost_timeBoundTxsRejected++;
        }
    }

    /// @notice Handler T4: No time bounds = always valid
    /// @dev Creates a Tempo tx without time bounds, should always succeed (if other conditions met)
    function handler_timeBoundOpen(uint256 actorSeed, uint256 recipientSeed, uint256 amount) external {
        (TxContext memory ctx, bool skip) = _setup2dNonceTransferContext(actorSeed, recipientSeed, amount, 4, 0, 1e6, 100e6);
        ctx.nonceKey = 4;
        ctx.currentNonce = uint64(ghost_2dNonce[ctx.sender][ctx.nonceKey]);
        if (skip) return;

        (bytes memory signedTx,) = _buildTempoWithTimeBounds(ctx.senderIdx, ctx.recipient, ctx.amount, ctx.nonceKey, ctx.currentNonce, 0, 0);
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _record2dNonceTxSuccess(ctx.sender, ctx.nonceKey, ctx.currentNonce);
            ghost_openWindowTxsExecuted++;
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                    TRANSACTION TYPE INVARIANTS (TX4-TX12)
    //////////////////////////////////////////////////////////////*/

    // ============ TX4/TX5: EIP-1559 Handlers ============

    /// @notice Handler TX4/TX5: Execute an EIP-1559 transfer with valid priority fee
    /// @dev Tests that maxPriorityFeePerGas and maxFeePerGas are enforced
    function handler_eip1559Transfer(uint256 actorSeed, uint256 recipientSeed, uint256 amount, uint256 priorityFee) external {
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
        if (balance < amount) {
            return;
        }

        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);
        uint256 baseFee = block.basefee > 0 ? block.basefee : 1;
        uint256 maxFee = baseFee + priorityFee;

        Eip1559Transaction memory tx_ = Eip1559TransactionLib.create()
            .withNonce(currentNonce)
            .withMaxPriorityFeePerGas(priorityFee)
            .withMaxFeePerGas(maxFee)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withTo(address(feeToken))
            .withData(abi.encodeCall(ITIP20.transfer, (recipient, amount)));

        bytes memory unsignedTx = tx_.encode(vmRlp);
        bytes32 txHash = keccak256(unsignedTx);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(actorKeys[senderIdx], txHash);
        bytes memory signedTx = tx_.encodeWithSignature(vmRlp, v, r, s);

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
            ghost_totalEip1559Txs++;
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler TX5: Attempt EIP-1559 tx with maxFeePerGas < baseFee (should be rejected)
    /// @dev Verifies that maxFeePerGas >= baseFee is enforced
    function handler_eip1559BaseFeeRejection(uint256 actorSeed, uint256 recipientSeed, uint256 amount) external {
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

        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);
        uint256 baseFee = block.basefee > 0 ? block.basefee : 100;
        uint256 maxFee = baseFee > 1 ? baseFee - 1 : 0;

        Eip1559Transaction memory tx_ = Eip1559TransactionLib.create()
            .withNonce(currentNonce)
            .withMaxPriorityFeePerGas(1)
            .withMaxFeePerGas(maxFee)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withTo(address(feeToken))
            .withData(abi.encodeCall(ITIP20.transfer, (recipient, amount)));

        bytes memory unsignedTx = tx_.encode(vmRlp);
        bytes32 txHash = keccak256(unsignedTx);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(actorKeys[senderIdx], txHash);
        bytes memory signedTx = tx_.encodeWithSignature(vmRlp, v, r, s);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
            ghost_totalEip1559Txs++;
        } catch {
            ghost_totalTxReverted++;
            ghost_totalEip1559BaseFeeRejected++;
        }
    }

    // ============ TX6/TX7: EIP-7702 Handlers ============

    /// @notice Handler TX6: Execute an EIP-7702 transaction with authorization list
    /// @dev Tests that authorization list is applied before execution
    function handler_eip7702WithAuth(uint256 actorSeed, uint256 authoritySeed, uint256 recipientSeed, uint256 amount) external {
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
        if (balance < amount) {
            return;
        }

        uint64 senderNonce = uint64(ghost_protocolNonce[sender]);
        uint64 authorityNonce = uint64(vm.getNonce(authority));

        address codeAddress = address(feeToken);
        bytes32 authHash = Eip7702TransactionLib.computeAuthorizationHash(
            block.chainid,
            codeAddress,
            authorityNonce
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

        Eip7702Transaction memory tx_ = Eip7702TransactionLib.create()
            .withNonce(senderNonce)
            .withMaxPriorityFeePerGas(10)
            .withMaxFeePerGas(100)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withTo(address(feeToken))
            .withData(abi.encodeCall(ITIP20.transfer, (recipient, amount)))
            .withAuthorizationList(auths);

        bytes memory unsignedTx = tx_.encode(vmRlp);
        bytes32 txHash = keccak256(unsignedTx);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(actorKeys[senderIdx], txHash);
        bytes memory signedTx = tx_.encodeWithSignature(vmRlp, v, r, s);

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
            ghost_totalEip7702Txs++;
            ghost_totalEip7702AuthsApplied++;
        } catch {
            ghost_totalTxReverted++;
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
            block.chainid,
            codeAddress,
            authorityNonce
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

        Eip7702Transaction memory tx_ = Eip7702TransactionLib.create()
            .withNonce(senderNonce)
            .withMaxPriorityFeePerGas(10)
            .withMaxFeePerGas(100)
            .withGasLimit(TxBuilder.DEFAULT_CREATE_GAS_LIMIT)
            .withTo(address(0))
            .withData(initcode)
            .withAuthorizationList(auths);

        bytes memory unsignedTx = tx_.encode(vmRlp);
        bytes32 txHash = keccak256(unsignedTx);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(actorKeys[senderIdx], txHash);
        bytes memory signedTx = tx_.encodeWithSignature(vmRlp, v, r, s);

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            revert("TX7: CREATE with authorization list should have failed");
        } catch {
            ghost_totalTxReverted++;
            ghost_totalEip7702CreateRejected++;
        }
    }

    // ============ TX10: Fee Sponsorship Handler ============

    /// @notice Handler TX10: Execute a Tempo transaction with fee payer signature
    /// @dev Tests that fee payer signature enables fee sponsorship
    function handler_tempoFeeSponsor(uint256 actorSeed, uint256 feePayerSeed, uint256 recipientSeed, uint256 amount, uint256 nonceKeySeed) external {
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
        calls[0] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, amount))});

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid))
            .withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withCalls(calls)
            .withNonceKey(nonceKey)
            .withNonce(currentNonce);

        bytes memory unsignedTxForFeePayer = tx_.encode(vmRlp);
        bytes32 feePayerTxHash = keccak256(unsignedTxForFeePayer);
        
        (uint8 fpV, bytes32 fpR, bytes32 fpS) = vm.sign(actorKeys[feePayerIdx], feePayerTxHash);
        bytes memory feePayerSig = abi.encodePacked(fpR, fpS, fpV);

        tx_ = tx_.withFeePayerSignature(feePayerSig);

        bytes memory signedTx = TxBuilder.signTempo(vmRlp, vm, tx_, TxBuilder.SigningParams({
            strategy: TxBuilder.SigningStrategy.Secp256k1,
            privateKey: actorKeys[senderIdx],
            pubKeyX: bytes32(0),
            pubKeyY: bytes32(0),
            userAddress: address(0)
        }));

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            uint64 actualNonce = nonce.getNonce(sender, nonceKey);
            if (actualNonce > currentNonce) {
                ghost_2dNonce[sender][nonceKey] = actualNonce;
                ghost_2dNonceUsed[sender][nonceKey] = true;
                ghost_totalTxExecuted++;
                ghost_totalCallsExecuted++;
                ghost_total2dNonceTxs++;
                ghost_totalFeeSponsoredTxs++;
            }
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                    GAS INVARIANTS (G1-G10)
    //////////////////////////////////////////////////////////////*/

    // ============ Gas Constants ============

    uint256 constant BASE_TX_GAS = 21000;
    uint256 constant COLD_ACCOUNT_ACCESS = 2600;
    uint256 constant CREATE_GAS = 32000;
    uint256 constant CALLDATA_ZERO_BYTE = 4;
    uint256 constant CALLDATA_NONZERO_BYTE = 16;
    uint256 constant INITCODE_WORD_COST = 2;
    uint256 constant ACCESS_LIST_ADDR_COST = 2400;
    uint256 constant ACCESS_LIST_SLOT_COST = 1900;
    uint256 constant ECRECOVER_GAS = 3000;
    uint256 constant P256_EXTRA_GAS = 5000;
    uint256 constant KEY_AUTH_BASE_GAS = 27000;
    uint256 constant KEY_AUTH_PER_LIMIT_GAS = 22000;

    // ============ Gas Ghost State ============

    mapping(address => uint256) public ghost_basicGasUsed;
    mapping(address => uint256) public ghost_multicallGasUsed;
    mapping(address => uint256) public ghost_createGasUsed;
    mapping(address => uint256) public ghost_signatureGasUsed;
    mapping(address => uint256) public ghost_keyAuthGasUsed;
    mapping(address => uint256) public ghost_numCallsInMulticall;

    // ============ Gas Helper Functions ============

    /// @notice Calculate gas cost for calldata
    /// @dev G3: 16 gas per non-zero byte, 4 gas per zero byte
    function _calldataGas(bytes memory data) internal pure returns (uint256 gas) {
        for (uint256 i = 0; i < data.length; i++) {
            gas += data[i] == 0 ? CALLDATA_ZERO_BYTE : CALLDATA_NONZERO_BYTE;
        }
    }

    /// @notice Calculate initcode gas cost
    /// @dev G4: 2 gas per 32-byte chunk (INITCODE_WORD_COST)
    function _initcodeGas(bytes memory initcode) internal pure returns (uint256) {
        return ((initcode.length + 31) / 32) * INITCODE_WORD_COST;
    }

    // ============ Gas Tracking Handlers ============

    /// @notice Handler: Track gas for simple transfer (G1, G2, G3)
    /// @dev G1: Base tx cost 21,000; G2: COLD_ACCOUNT_ACCESS per call; G3: Calldata gas
    function handler_gasTrackingBasic(uint256 actorSeed, uint256 recipientSeed, uint256 amount) external {
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

        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);
        bytes memory callData = abi.encodeCall(ITIP20.transfer, (recipient, amount));
        bytes memory signedTx = TxBuilder.buildLegacyCall(vmRlp, vm, address(feeToken), callData, currentNonce, actorKeys[senderIdx]);

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];

        vm.coinbase(validator);

        uint256 gasBefore = gasleft();
        try vmExec.executeTransaction(signedTx) {
            uint256 gasUsed = gasBefore - gasleft();
            ghost_basicGasUsed[sender] = gasUsed;

            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
            _recordGasTrackingBasic();
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Track gas for multicall with varying number of calls (G2)
    /// @dev G2: Each call adds COLD_ACCOUNT_ACCESS (2,600 gas)
    function handler_gasTrackingMulticall(uint256 actorSeed, uint256 numCallsSeed, uint256 amount, uint256 nonceKeySeed) external {
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
            calls[i] = TempoCall({to: address(feeToken), value: 0, data: abi.encodeCall(ITIP20.transfer, (recipient, amount))});
        }

        bytes memory signedTx = TxBuilder.buildTempoMultiCall(vmRlp, vm, calls, nonceKey, currentNonce, actorKeys[senderIdx]);

        ghost_previous2dNonce[sender][nonceKey] = ghost_2dNonce[sender][nonceKey];

        vm.coinbase(validator);

        uint256 gasBefore = gasleft();
        try vmExec.executeTransaction(signedTx) {
            uint256 gasUsed = gasBefore - gasleft();
            ghost_multicallGasUsed[sender] = gasUsed;
            ghost_numCallsInMulticall[sender] = numCalls;

            ghost_2dNonce[sender][nonceKey]++;
            ghost_2dNonceUsed[sender][nonceKey] = true;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_total2dNonceTxs++;
            _recordGasTrackingMulticall();
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Track gas for CREATE with initcode (G4)
    /// @dev G4: CREATE adds 32,000 gas + initcode cost (2 gas per 32-byte chunk)
    function handler_gasTrackingCreate(uint256 actorSeed, uint256 initValueSeed) external {
        uint256 senderIdx = actorSeed % actors.length;
        address sender = actors[senderIdx];

        uint256 initValue = bound(initValueSeed, 0, 1000);
        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);

        bytes memory initcode = InitcodeHelper.simpleStorageInitcode(initValue);

        uint256 initcodeGasCost = _initcodeGas(initcode);
        uint64 gasLimit = uint64(TxBuilder.DEFAULT_CREATE_GAS_LIMIT + initcodeGasCost + 50000);

        bytes memory signedTx = TxBuilder.buildLegacyCreateWithGas(
            vmRlp,
            vm,
            initcode,
            currentNonce,
            gasLimit,
            actorKeys[senderIdx]
        );

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];

        vm.coinbase(validator);

        uint256 gasBefore = gasleft();
        try vmExec.executeTransaction(signedTx) {
            uint256 gasUsed = gasBefore - gasleft();
            ghost_createGasUsed[sender] = gasUsed;

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
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Track gas for different signature types (G6, G7, G8)
    /// @dev G6: secp256k1 ECRECOVER = 3,000; G7: P256 = ECRECOVER + 5,000; G8: WebAuthn = ECRECOVER + 5,000 + calldata
    function handler_gasTrackingSignatureTypes(uint256 actorSeed, uint256 sigTypeSeed, uint256 amount) external {
        uint256 senderIdx = actorSeed % actors.length;
        address recipient = actors[(senderIdx + 1) % actors.length];

        uint256 sigTypeRaw = sigTypeSeed % 3;
        SignatureType sigType;
        if (sigTypeRaw == 0) {
            sigType = SignatureType.Secp256k1;
        } else if (sigTypeRaw == 1) {
            sigType = SignatureType.P256;
        } else {
            sigType = SignatureType.WebAuthn;
        }

        (TxBuilder.SigningParams memory params, address sender) = _getSigningParams(senderIdx, sigType, sigTypeSeed);

        amount = bound(amount, 1e6, 10e6);
        uint256 balance = feeToken.balanceOf(sender);
        if (balance < amount) {
            return;
        }

        uint64 currentNonce = uint64(ghost_protocolNonce[sender]);
        bytes memory callData = abi.encodeCall(ITIP20.transfer, (recipient, amount));

        LegacyTransaction memory tx_ = LegacyTransactionLib.create()
            .withNonce(currentNonce)
            .withGasPrice(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(TxBuilder.DEFAULT_GAS_LIMIT)
            .withTo(address(feeToken))
            .withData(callData);

        bytes memory signedTx = TxBuilder.signLegacy(vmRlp, vm, tx_, params);

        ghost_previousProtocolNonce[sender] = ghost_protocolNonce[sender];

        vm.coinbase(validator);

        uint256 gasBefore = gasleft();
        try vmExec.executeTransaction(signedTx) {
            uint256 gasUsed = gasBefore - gasleft();
            ghost_signatureGasUsed[sender] = gasUsed;

            ghost_protocolNonce[sender]++;
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_totalProtocolNonceTxs++;
            _recordGasTrackingSignature();
        } catch {
            ghost_totalTxReverted++;
        }
    }

    /// @notice Handler: Track gas for KeyAuthorization with spending limits (G9, G10)
    /// @dev G9: Base key auth = 27,000; G10: Each spending limit adds 22,000
    function handler_gasTrackingKeyAuth(uint256 actorSeed, uint256 keySeed, uint256 numLimitsSeed) external {
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
            limits[i] = IAccountKeychain.TokenLimit({token: address(feeToken), amount: (i + 1) * 100e6});
            tokens[i] = address(feeToken);
            amounts[i] = (i + 1) * 100e6;
        }

        vm.coinbase(validator);

        uint256 gasBefore = gasleft();
        vm.prank(owner);
        try keychain.authorizeKey(keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, numLimits > 0, limits) {
            uint256 gasUsed = gasBefore - gasleft();
            ghost_keyAuthGasUsed[owner] = gasUsed;

            _authorizeKey(owner, keyId, expiry, numLimits > 0, tokens, amounts);
            _recordGasTrackingKeyAuth();
        } catch {}
    }

}
