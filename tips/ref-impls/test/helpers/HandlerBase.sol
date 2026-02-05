// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { INonce } from "../../src/interfaces/INonce.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { InvariantBase } from "./InvariantBase.sol";
import { TxBuilder } from "./TxBuilder.sol";
import {
    TempoCall,
    TempoTransaction,
    TempoTransactionLib
} from "tempo-std/tx/TempoTransactionLib.sol";

/// @title HandlerBase - Common patterns for invariant test handlers
/// @notice Extracts duplicated handler logic into reusable functions
/// @dev Inherit from this contract to reduce boilerplate in handler implementations
abstract contract HandlerBase is InvariantBase {

    using TempoTransactionLib for TempoTransaction;
    using TxBuilder for *;

    // ============ Common Error Selectors ============

    bytes4 internal immutable ERR_INSUFFICIENT_BALANCE;
    bytes4 internal immutable ERR_POLICY_FORBIDS;
    bytes4 internal immutable ERR_NONCE_OVERFLOW;
    bytes4 internal immutable ERR_INVALID_NONCE_KEY;

    constructor() {
        ERR_INSUFFICIENT_BALANCE = ITIP20.InsufficientBalance.selector;
        ERR_POLICY_FORBIDS = ITIP20.PolicyForbids.selector;
        ERR_NONCE_OVERFLOW = INonce.NonceOverflow.selector;
        ERR_INVALID_NONCE_KEY = INonce.InvalidNonceKey.selector;
    }

    // ============ Context Structs ============

    /// @dev Context for fee test operations
    struct FeeTestContext {
        uint256 senderIdx;
        address sender;
        address recipient;
        uint256 amount;
        uint64 nonceKey;
        uint64 currentNonce;
        TempoCall[] calls;
    }

    /// @notice Context for transaction setup to reduce stack depth
    struct TxContext {
        uint256 senderIdx;
        address sender;
        address recipient;
        uint256 amount;
        uint64 nonceKey;
        uint64 currentNonce;
        SignatureType sigType;
    }

    /// @dev Context struct for access key operations
    struct AccessKeyContext {
        uint256 actorIdx;
        address owner;
        address keyId;
        uint256 keyPk;
        bool isP256;
        bytes32 pubKeyX;
        bytes32 pubKeyY;
    }

    // ============ Setup Helpers ============

    /// @notice Setup base transfer context (sender, recipient, amount) with guaranteed balance
    /// @param actorSeed Seed to select sender actor
    /// @param recipientSeed Seed to select recipient actor
    /// @param amountSeed Seed for amount randomization
    /// @param minAmount Minimum transfer amount
    /// @param maxAmount Maximum transfer amount
    /// @return ctx The populated transaction context with base fields set
    function _setupBaseTransferContext(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amountSeed,
        uint256 minAmount,
        uint256 maxAmount
    )
        internal
        returns (TxContext memory ctx)
    {
        ctx.senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (ctx.senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        ctx.sender = actors[ctx.senderIdx];
        ctx.recipient = actors[recipientIdx];
        ctx.amount = bound(amountSeed, minAmount, maxAmount);

        _ensureFeeTokenBalance(ctx.sender, ctx.amount);
    }

    /// @notice Setup a transfer context with signature type
    /// @param actorSeed Seed to select sender actor
    /// @param recipientSeed Seed to select recipient actor
    /// @param amountSeed Seed for amount randomization
    /// @param sigTypeSeed Seed for signature type selection
    /// @param minAmount Minimum transfer amount
    /// @param maxAmount Maximum transfer amount
    /// @return ctx The populated transaction context
    function _setupTransferContext(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amountSeed,
        uint256 sigTypeSeed,
        uint256 minAmount,
        uint256 maxAmount
    )
        internal
        returns (TxContext memory ctx)
    {
        ctx = _setupBaseTransferContext(actorSeed, recipientSeed, amountSeed, minAmount, maxAmount);
        ctx.sigType = _getRandomSignatureType(sigTypeSeed);
        ctx.sender = _getSenderForSigType(ctx.senderIdx, ctx.sigType);
        _ensureFeeTokenBalance(ctx.sender, ctx.amount);
    }

    /// @notice Setup a 2D nonce transfer context
    /// @param actorSeed Seed to select sender actor
    /// @param recipientSeed Seed to select recipient actor
    /// @param amountSeed Seed for amount randomization
    /// @param nonceKeySeed Seed for nonce key selection
    /// @param sigTypeSeed Seed for signature type selection
    /// @param minAmount Minimum transfer amount
    /// @param maxAmount Maximum transfer amount
    /// @return ctx The populated transaction context
    function _setup2dNonceTransferContext(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amountSeed,
        uint256 nonceKeySeed,
        uint256 sigTypeSeed,
        uint256 minAmount,
        uint256 maxAmount
    )
        internal
        returns (TxContext memory ctx)
    {
        ctx = _setupTransferContext(
            actorSeed, recipientSeed, amountSeed, sigTypeSeed, minAmount, maxAmount
        );
        ctx.nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        ctx.currentNonce = uint64(ghost_2dNonce[ctx.sender][ctx.nonceKey]);
    }

    // ============ Nonce Assertion Helpers ============

    /// @notice Assert protocol nonce matches ghost state (for debugging)
    function _assertProtocolNonceEq(address account, string memory context) internal view {
        uint256 actual = vm.getNonce(account);
        assertEq(
            actual,
            ghost_protocolNonce[account],
            string.concat("Protocol nonce mismatch: ", context)
        );
    }

    /// @notice Assert 2D nonce matches ghost state (for debugging)
    function _assert2dNonceEq(
        address account,
        uint64 nonceKey,
        string memory context
    )
        internal
        view
    {
        uint64 actual = nonce.getNonce(account, nonceKey);
        assertEq(
            actual, ghost_2dNonce[account][nonceKey], string.concat("2D nonce mismatch: ", context)
        );
    }

    /// @notice Update ghost state after successful 2D nonce transaction
    /// @param account The account that executed the transaction
    /// @param nonceKey The nonce key used
    /// @param previousNonce The nonce value before execution
    function _record2dNonceTxSuccess(
        address account,
        uint64 nonceKey,
        uint64 previousNonce
    )
        internal
    {
        uint64 actualNonce = nonce.getNonce(account, nonceKey);
        if (actualNonce > previousNonce) {
            ghost_2dNonce[account][nonceKey] = actualNonce;
            _mark2dNonceKeyUsed(account, nonceKey);
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_total2dNonceTxs++;
        }
    }

    /// @notice Update ghost state after successful protocol nonce transaction
    /// @param account The account that executed the transaction
    function _recordProtocolNonceTxSuccess(address account) internal {
        ghost_protocolNonce[account]++;
        ghost_totalProtocolNonceTxs++;
        ghost_totalTxExecuted++;
        ghost_totalCallsExecuted++;
    }

    // ============ Balance Helpers ============

    /// @notice Check if account has sufficient balance
    /// @param account The account to check
    /// @param required The required balance
    /// @return True if account has sufficient balance
    function _checkBalance(address account, uint256 required) internal view returns (bool) {
        return feeToken.balanceOf(account) >= required;
    }

    // ============ Access Key Helpers ============

    /// @notice Check if an access key can be used for a transfer
    /// @param owner The owner address
    /// @param keyId The access key ID
    /// @param amount The amount to transfer
    /// @return canUse True if the key is authorized, not expired, and within spending limit
    function _canUseKey(address owner, address keyId, uint256 amount) internal view returns (bool) {
        if (!ghost_keyAuthorized[owner][keyId]) return false;
        if (ghost_keyExpiry[owner][keyId] <= block.timestamp) return false;
        if (ghost_keyEnforceLimits[owner][keyId]) {
            uint256 limit = ghost_keySpendingLimit[owner][keyId][address(feeToken)];
            uint256 spent = ghost_keySpentAmount[owner][keyId][address(feeToken)];
            if (spent + amount > limit) return false;
        }
        return true;
    }

    /// @notice Setup context for using a secp256k1 access key
    function _setupSecp256k1KeyContext(
        uint256 actorSeed,
        uint256 keySeed
    )
        internal
        view
        returns (AccessKeyContext memory ctx)
    {
        ctx.actorIdx = actorSeed % actors.length;
        ctx.owner = actors[ctx.actorIdx];
        (ctx.keyId, ctx.keyPk) = _getActorAccessKey(ctx.actorIdx, keySeed);
        ctx.isP256 = false;
    }

    /// @notice Setup context for using a P256 access key
    function _setupP256KeyContext(
        uint256 actorSeed,
        uint256 keySeed
    )
        internal
        view
        returns (AccessKeyContext memory ctx)
    {
        ctx.actorIdx = actorSeed % actors.length;
        ctx.owner = actors[ctx.actorIdx];
        (ctx.keyId, ctx.keyPk, ctx.pubKeyX, ctx.pubKeyY) =
            _getActorP256AccessKey(ctx.actorIdx, keySeed);
        ctx.isP256 = true;
    }

    /// @notice Setup context for random key type (secp256k1 or P256) based on seed
    function _setupRandomKeyContext(
        uint256 actorSeed,
        uint256 keySeed
    )
        internal
        view
        returns (AccessKeyContext memory ctx)
    {
        ctx.actorIdx = actorSeed % actors.length;
        ctx.owner = actors[ctx.actorIdx];
        ctx.isP256 = keySeed % 2 == 0;
        if (ctx.isP256) {
            (ctx.keyId, ctx.keyPk, ctx.pubKeyX, ctx.pubKeyY) =
                _getActorP256AccessKey(ctx.actorIdx, keySeed);
        } else {
            (ctx.keyId, ctx.keyPk) = _getActorAccessKey(ctx.actorIdx, keySeed);
        }
    }

    /// @notice Ensure an account has sufficient fee token balance
    /// @param account The account to fund
    /// @param amount The minimum required balance
    function _ensureFeeTokenBalance(address account, uint256 amount) internal {
        if (feeToken.balanceOf(account) < amount) {
            vm.prank(admin);
            feeToken.mint(account, amount + 100_000_000e6);
        }
    }

    // ============ Error Assertion Helpers ============

    /// @notice Assert that a revert reason is a known transaction error
    /// @dev Fails the test if the error is not recognized
    /// @param reason The revert reason bytes
    function _assertKnownTxError(bytes memory reason) internal view {
        if (reason.length < 4) {
            return;
        }

        bytes4 selector = bytes4(reason);
        bool isKnown = selector == ERR_INSUFFICIENT_BALANCE || selector == ERR_POLICY_FORBIDS
            || selector == ERR_NONCE_OVERFLOW || selector == ERR_INVALID_NONCE_KEY
            || selector == bytes4(keccak256("InvalidSignature()"))
            || selector == bytes4(keccak256("InvalidNonce()"))
            || selector == bytes4(keccak256("ExpiredTransaction()"))
            || selector == bytes4(keccak256("InvalidFeeToken()"))
            || selector == bytes4(keccak256("InsufficientFee()"))
            || selector == bytes4(keccak256("KeyNotAuthorized()"))
            || selector == bytes4(keccak256("KeyExpired()"))
            || selector == bytes4(keccak256("SpendingLimitExceeded()"));

        assertTrue(isKnown, "Failed with unknown tx error");
    }

    /// @notice Check if a revert reason matches a specific error selector
    /// @param reason The revert reason bytes
    /// @param expected The expected error selector
    /// @return True if the reason matches the expected selector
    function _isError(bytes memory reason, bytes4 expected) internal pure returns (bool) {
        return reason.length >= 4 && bytes4(reason) == expected;
    }

    // ============ Bound Helpers ============

    /// @notice Bound a value to a range (wrapper for StdUtils.bound)
    /// @param x The value to bound
    /// @param min The minimum value
    /// @param max The maximum value
    /// @return The bounded value
    function bound(
        uint256 x,
        uint256 min,
        uint256 max
    )
        internal
        pure
        virtual
        override
        returns (uint256)
    {
        return super.bound(x, min, max);
    }

    // ============ Multicall Helpers ============

    /// @notice Setup context for multicall with two amounts
    /// @return ctx Transaction context
    /// @return totalAmount Combined amount needed
    function _setupMulticallContext(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amount1,
        uint256 amount2,
        uint256 nonceKeySeed
    )
        internal
        returns (TxContext memory ctx, uint256 totalAmount)
    {
        ctx = _setupBaseTransferContext(actorSeed, recipientSeed, amount1, 1e6, 10e6);
        totalAmount = ctx.amount + bound(amount2, 1e6, 10e6);
        ctx.nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        ctx.currentNonce = uint64(ghost_2dNonce[ctx.sender][ctx.nonceKey]);

        _ensureFeeTokenBalance(ctx.sender, totalAmount);
    }

    /// @notice Simplified record helper for 2D nonce success (overload without previousNonce)
    /// @dev Reads current nonce from ghost state
    function _record2dNonceTxSuccess(address account, uint64 nonceKey) internal {
        uint64 previousNonce = uint64(ghost_2dNonce[account][nonceKey]);
        uint64 actualNonce = nonce.getNonce(account, nonceKey);
        if (actualNonce > previousNonce) {
            ghost_2dNonce[account][nonceKey] = actualNonce;
            _mark2dNonceKeyUsed(account, nonceKey);
            ghost_totalTxExecuted++;
            ghost_totalCallsExecuted++;
            ghost_total2dNonceTxs++;
        }
    }

    // ============ Nonce Sync Helpers for Catch Blocks ============

    /// @notice Sync ghost protocol nonce with actual VM nonce after tx failure
    /// @dev Call this in catch blocks for protocol nonce transactions (legacy tx, tempo tx with nonceKey=0)
    function _syncNonceAfterFailure(address account) internal {
        uint256 actualNonce = vm.getNonce(account);
        if (actualNonce > ghost_protocolNonce[account]) {
            ghost_protocolNonce[account] = actualNonce;
            ghost_totalProtocolNonceTxs++;
        }
    }

    /// @notice Sync ghost 2D nonce with actual VM nonce after tx failure
    /// @dev Call this in catch blocks for 2D nonce transactions (tempo tx with nonceKey > 0)
    function _sync2dNonceAfterFailure(address account, uint64 nonceKey) internal {
        uint64 actualNonce = nonce.getNonce(account, nonceKey);
        if (actualNonce > ghost_2dNonce[account][nonceKey]) {
            ghost_2dNonce[account][nonceKey] = actualNonce;
            _mark2dNonceKeyUsed(account, nonceKey);
            ghost_total2dNonceTxs++;
        }
    }

    /// @notice Unified handler for protocol nonce transaction reverts
    /// @dev Syncs nonce and increments revert counter
    function _handleRevertProtocol(address account) internal {
        _syncNonceAfterFailure(account);
        ghost_totalTxReverted++;
    }

    /// @notice Unified handler for 2D nonce transaction reverts
    /// @dev Syncs 2D nonce and increments revert counter
    function _handleRevert2d(address account, uint64 nonceKey) internal {
        _sync2dNonceAfterFailure(account, nonceKey);
        ghost_totalTxReverted++;
    }

    // ============ Consolidated Catch Block Helpers ============

    /// @notice No-op function for expected rejections that don't need counter updates
    function _noop() internal { }

    /// @notice Handle expected rejection with optional counter update
    /// @param updateFn Counter update function (use _noop for no update)
    function _handleExpectedReject(function() internal updateFn) internal {
        updateFn();
    }

    // ============ CREATE Context Helpers ============

    /// @dev Context for CREATE operations
    struct CreateContext {
        uint256 senderIdx;
        address sender;
        uint64 nonceKey;
        uint64 current2dNonce;
        uint64 protocolNonce;
    }

    /// @notice Setup context for CREATE with 2D nonce
    function _setupCreateContext(
        uint256 actorSeed,
        uint256 nonceKeySeed
    )
        internal
        view
        returns (CreateContext memory ctx)
    {
        ctx.senderIdx = actorSeed % actors.length;
        ctx.sender = actors[ctx.senderIdx];
        ctx.nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        ctx.current2dNonce = uint64(ghost_2dNonce[ctx.sender][ctx.nonceKey]);
        ctx.protocolNonce = uint64(ghost_protocolNonce[ctx.sender]);
    }

    /// @notice Record CREATE success with protocol nonce (Legacy tx)
    /// @param sender The sender address
    /// @param usedNonce The protocol nonce used for CREATE address derivation
    /// @param expectedAddress The expected CREATE address
    function _recordProtocolNonceCreateSuccess(
        address sender,
        uint64 usedNonce,
        address expectedAddress
    )
        internal
    {
        ghost_protocolNonce[sender]++;
        ghost_totalTxExecuted++;
        ghost_totalCreatesExecuted++;
        ghost_totalProtocolNonceTxs++;

        bytes32 key = keccak256(abi.encodePacked(sender, uint256(usedNonce)));
        ghost_createAddresses[key] = expectedAddress;
        ghost_createCount[sender]++;
    }

    /// @notice Record CREATE success with 2D nonce (Tempo tx with nonceKey > 0)
    /// @param sender The sender address
    /// @param nonceKey The 2D nonce key
    /// @param protocolNonce The protocol nonce used for CREATE address derivation
    /// @param expectedAddress The expected CREATE address
    /// @dev CREATE operations also increment protocol nonce (for address derivation)
    function _record2dNonceCreateSuccess(
        address sender,
        uint64 nonceKey,
        uint64 protocolNonce,
        address expectedAddress
    )
        internal
    {
        uint64 previousNonce = uint64(ghost_2dNonce[sender][nonceKey]);
        uint64 actualNonce = nonce.getNonce(sender, nonceKey);
        if (actualNonce > previousNonce) {
            ghost_2dNonce[sender][nonceKey] = actualNonce;
            _mark2dNonceKeyUsed(sender, nonceKey);
            ghost_totalTxExecuted++;
            ghost_totalCreatesExecuted++;
            ghost_total2dNonceTxs++;

            // CREATE also consumes protocol nonce for address derivation
            // Verify on-chain protocol nonce actually changed
            uint256 actualProtocolNonce = vm.getNonce(sender);
            if (actualProtocolNonce > ghost_protocolNonce[sender]) {
                ghost_protocolNonce[sender] = actualProtocolNonce;
                ghost_totalProtocolNonceTxs++;
            }

            // Only record CREATE address tracking if code was actually deployed
            if (expectedAddress.code.length > 0) {
                ghost_total2dNonceCreates++;
                bytes32 key = keccak256(abi.encodePacked(sender, uint256(protocolNonce)));
                ghost_createAddresses[key] = expectedAddress;
                ghost_createCount[sender]++;
            }
        }
    }

    // ============ Transaction Building Helpers ============

    /// @notice Build and sign a Tempo transaction with default settings
    /// @param calls The calls to include in the transaction
    /// @param nonceKey The 2D nonce key (0 for protocol nonce)
    /// @param txNonce The nonce value
    /// @param actorIdx The actor index for signing
    /// @return signedTx The signed transaction bytes
    function _buildAndSignTempoTx(
        TempoCall[] memory calls,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 actorIdx
    )
        internal
        view
        returns (bytes memory signedTx)
    {
        // Calculate gas limit based on calls
        uint64 gasLimit = TxBuilder.DEFAULT_GAS_LIMIT;
        if (calls.length == 1) {
            gasLimit = TxBuilder.callGas(calls[0].data, txNonce) + TxBuilder.GAS_LIMIT_BUFFER;
        } else {
            // For multicalls, estimate based on all calls
            for (uint256 i = 0; i < calls.length; i++) {
                gasLimit += TxBuilder.callGas(calls[i].data, txNonce);
            }
            gasLimit += TxBuilder.GAS_LIMIT_BUFFER;
        }

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(TxBuilder.DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(txNonce);

        signedTx = TxBuilder.signTempo(
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
    }

    // ============ Fee Test Helpers ============

    /// @notice Setup context for fee-related tests
    /// @param actorSeed Seed for sender selection
    /// @param recipientSeed Seed for recipient selection
    /// @param amountSeed Amount seed
    /// @param nonceKeySeed Nonce key seed
    /// @return ctx The populated fee test context
    function _setupFeeTestContext(
        uint256 actorSeed,
        uint256 recipientSeed,
        uint256 amountSeed,
        uint256 nonceKeySeed
    )
        internal
        returns (FeeTestContext memory ctx)
    {
        ctx.senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (ctx.senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        ctx.sender = actors[ctx.senderIdx];
        ctx.recipient = actors[recipientIdx];
        ctx.amount = bound(amountSeed, 1e6, 10e6);

        uint256 balance = feeToken.balanceOf(ctx.sender);
        vm.assume(balance >= ctx.amount);

        ctx.nonceKey = uint64(bound(nonceKeySeed, 1, 100));
        ctx.currentNonce = uint64(ghost_2dNonce[ctx.sender][ctx.nonceKey]);

        ctx.calls = new TempoCall[](1);
        ctx.calls[0] = TempoCall({
            to: address(feeToken),
            value: 0,
            data: abi.encodeCall(ITIP20.transfer, (ctx.recipient, ctx.amount))
        });
    }

}
