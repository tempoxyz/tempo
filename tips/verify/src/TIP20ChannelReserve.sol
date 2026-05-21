// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ITIP20ChannelReserve } from "./interfaces/ITIP20ChannelReserve.sol";
import { ISignatureVerifier } from "tempo-std/interfaces/ISignatureVerifier.sol";
import { ITIP20 } from "tempo-std/interfaces/ITIP20.sol";

/// @title TIP20ChannelReserve
/// @notice Reference contract for the TIP-1034 channel model.
contract TIP20ChannelReserve is ITIP20ChannelReserve {

    error TransferFailed();

    address public constant TIP20_CHANNEL_RESERVE = 0x4d50500000000000000000000000000000000000;
    address public constant SIGNATURE_VERIFIER_PRECOMPILE =
        0x5165300000000000000000000000000000000000;

    bytes32 public constant VOUCHER_TYPEHASH =
        keccak256("Voucher(bytes32 channelId,uint96 cumulativeAmount)");

    uint64 public constant CLOSE_GRACE_PERIOD = 15 minutes;

    uint256 internal constant _DEPOSIT_OFFSET = 96;
    uint256 internal constant _CLOSE_REQUESTED_AT_OFFSET = 192;
    bytes12 internal constant _TIP20_TOKEN_PREFIX = 0x20c000000000000000000000;

    bytes32 internal constant _EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 internal constant _NAME_HASH = keccak256("TIP20 Channel Reserve");
    bytes32 internal constant _VERSION_HASH = keccak256("1");

    mapping(bytes32 => uint256) internal channelStates;
    bytes32 internal _expiringNonceHashContext;

    // Reference-contract-only approximation of the precompile's transient per-transaction guard.
    // The enshrined precompile should track `openedThisTx[channelId]` in transient storage and
    // clear it automatically at the end of the top-level transaction. That allows multiple `open`
    // calls in one AA batch when they derive distinct channel IDs, while preventing the same channel
    // ID from being reopened after a same-transaction terminal `close` or `withdraw` deletes the
    // persistent state slot.
    //
    // This Solidity reference uses persistent storage because tests cannot model precompile
    // transient storage directly. Since `channelId` includes the transaction-derived
    // `expiringNonceHash` context value, a real cross-transaction reopen has a different ID
    // and is not blocked by this persistent
    // approximation.
    mapping(bytes32 => bool) internal _openedChannelIdsForTest;

    /// @dev Reference-contract-only hook. The precompile derives this as
    /// `keccak256(abi.encodePacked(encodeForSigning, sender))` for every real transaction type.
    function setExpiringNonceHashForTest(bytes32 expiringNonceHash) external {
        _expiringNonceHashContext = expiringNonceHash;
    }

    function open(
        address payee,
        address operator,
        address token,
        uint96 deposit,
        bytes32 salt,
        address authorizedSigner
    )
        external
        returns (bytes32 channelId)
    {
        if (payee == address(0) || _isTip20Prefix(payee)) revert InvalidPayee();
        if (token == address(0)) revert InvalidToken();
        if (deposit == 0) revert ZeroDeposit();

        bytes32 expiringNonceHash = _consumeExpiringNonceHash();
        channelId = computeChannelId(
            msg.sender, payee, operator, token, salt, authorizedSigner, expiringNonceHash
        );

        // Reject ordinary duplicate opens while the channel is still active.
        if (channelStates[channelId] != 0) revert ChannelAlreadyExists();

        // Also reject same-top-level-transaction reopens of a channel ID that was opened earlier
        // and then terminally closed or withdrawn. Without this guard, terminal deletion would make
        // the persistent state slot look unused again even though the enclosing transaction-derived
        // context hash, and thus the derived channel ID, is unchanged for later calls in the same
        // top-level transaction.
        if (_openedChannelIdsForTest[channelId]) revert ChannelAlreadyExists();

        channelStates[channelId] = _encodeChannelState(
            ChannelState({ settled: 0, deposit: deposit, closeRequestedAt: 0 })
        );

        // The reference contract keeps ERC-20-style allowance flow for local verification.
        // The enshrined precompile should use TIP-20 `systemTransferFrom` semantics instead.
        bool success = ITIP20(token).transferFrom(msg.sender, address(this), deposit);
        if (!success) revert TransferFailed();

        // Mark after the reserve transfer succeeds so failed opens do not poison the guard. The real
        // precompile marker is transient and only protects the current top-level transaction.
        _openedChannelIdsForTest[channelId] = true;

        emit ChannelOpened(
            channelId,
            msg.sender,
            payee,
            operator,
            token,
            authorizedSigner,
            salt,
            expiringNonceHash,
            deposit
        );
    }

    function settle(
        ChannelDescriptor calldata descriptor,
        uint96 cumulativeAmount,
        bytes calldata signature
    )
        external
    {
        bytes32 channelId = _channelId(descriptor);
        ChannelState memory channel = _loadChannelState(channelId);

        if (
            msg.sender != descriptor.payee
                && (descriptor.operator == address(0) || msg.sender != descriptor.operator)
        ) {
            revert NotPayeeOrOperator();
        }
        if (cumulativeAmount > channel.deposit) revert AmountExceedsDeposit();
        if (cumulativeAmount <= channel.settled) revert AmountNotIncreasing();

        _validateVoucher(descriptor, channelId, cumulativeAmount, signature);

        uint96 delta = cumulativeAmount - channel.settled;
        channel.settled = cumulativeAmount;
        channelStates[channelId] = _encodeChannelState(channel);

        bool success = ITIP20(descriptor.token).transfer(descriptor.payee, delta);
        if (!success) revert TransferFailed();

        emit Settled(
            channelId, descriptor.payer, descriptor.payee, cumulativeAmount, delta, channel.settled
        );
    }

    function topUp(ChannelDescriptor calldata descriptor, uint96 additionalDeposit) external {
        bytes32 channelId = _channelId(descriptor);
        ChannelState memory channel = _loadChannelState(channelId);

        if (msg.sender != descriptor.payer) revert NotPayer();

        if (additionalDeposit > type(uint96).max - channel.deposit) revert DepositOverflow();

        if (additionalDeposit > 0) {
            channel.deposit += additionalDeposit;

            // The reference contract keeps ERC-20-style allowance flow for local verification.
            // The enshrined precompile should use TIP-20 `systemTransferFrom` semantics instead.
            bool success =
                ITIP20(descriptor.token).transferFrom(msg.sender, address(this), additionalDeposit);
            if (!success) revert TransferFailed();
        }

        if (channel.closeRequestedAt != 0) {
            channel.closeRequestedAt = 0;
            emit CloseRequestCancelled(channelId, descriptor.payer, descriptor.payee);
        }

        channelStates[channelId] = _encodeChannelState(channel);

        emit TopUp(
            channelId, descriptor.payer, descriptor.payee, additionalDeposit, channel.deposit
        );
    }

    function requestClose(ChannelDescriptor calldata descriptor) external {
        bytes32 channelId = _channelId(descriptor);
        ChannelState memory channel = _loadChannelState(channelId);

        if (msg.sender != descriptor.payer) revert NotPayer();

        if (channel.closeRequestedAt == 0) {
            channel.closeRequestedAt = uint32(block.timestamp);
            channelStates[channelId] = _encodeChannelState(channel);
            emit CloseRequested(
                channelId,
                descriptor.payer,
                descriptor.payee,
                uint256(block.timestamp) + CLOSE_GRACE_PERIOD
            );
        }
    }

    function close(
        ChannelDescriptor calldata descriptor,
        uint96 cumulativeAmount,
        uint96 captureAmount,
        bytes calldata signature
    )
        external
    {
        bytes32 channelId = _channelId(descriptor);
        ChannelState memory channel = _loadChannelState(channelId);

        if (
            msg.sender != descriptor.payee
                && (descriptor.operator == address(0) || msg.sender != descriptor.operator)
        ) {
            revert NotPayeeOrOperator();
        }

        uint96 previousSettled = channel.settled;
        if (captureAmount < previousSettled || captureAmount > cumulativeAmount) {
            revert CaptureAmountInvalid();
        }
        if (captureAmount > channel.deposit) revert AmountExceedsDeposit();

        if (captureAmount > previousSettled) {
            _validateVoucher(descriptor, channelId, cumulativeAmount, signature);
        }

        uint96 delta = captureAmount - previousSettled;
        uint96 refund = channel.deposit - captureAmount;

        delete channelStates[channelId];

        if (delta > 0) {
            bool payeeTransferSucceeded = ITIP20(descriptor.token).transfer(descriptor.payee, delta);
            if (!payeeTransferSucceeded) revert TransferFailed();
        }

        if (refund > 0) {
            bool payerTransferSucceeded =
                ITIP20(descriptor.token).transfer(descriptor.payer, refund);
            if (!payerTransferSucceeded) revert TransferFailed();
        }

        emit ChannelClosed(channelId, descriptor.payer, descriptor.payee, captureAmount, refund);
    }

    function withdraw(ChannelDescriptor calldata descriptor) external {
        bytes32 channelId = _channelId(descriptor);
        ChannelState memory channel = _loadChannelState(channelId);

        if (msg.sender != descriptor.payer) revert NotPayer();

        uint32 closeRequestedAt = channel.closeRequestedAt;
        bool closeGracePassed = closeRequestedAt != 0
            && block.timestamp >= uint256(closeRequestedAt) + CLOSE_GRACE_PERIOD;

        if (!closeGracePassed) revert CloseNotReady();

        uint96 refund = channel.deposit - channel.settled;
        delete channelStates[channelId];

        if (refund > 0) {
            bool success = ITIP20(descriptor.token).transfer(descriptor.payer, refund);
            if (!success) revert TransferFailed();
        }

        emit ChannelClosed(channelId, descriptor.payer, descriptor.payee, channel.settled, refund);
    }

    function getChannel(ChannelDescriptor calldata descriptor)
        external
        view
        returns (Channel memory channel)
    {
        channel.descriptor = ChannelDescriptor({
            payer: descriptor.payer,
            payee: descriptor.payee,
            operator: descriptor.operator,
            token: descriptor.token,
            salt: descriptor.salt,
            authorizedSigner: descriptor.authorizedSigner,
            expiringNonceHash: descriptor.expiringNonceHash
        });
        channel.state = _decodeChannelState(channelStates[_channelId(descriptor)]);
    }

    function getChannelState(bytes32 channelId) external view returns (ChannelState memory) {
        return _decodeChannelState(channelStates[channelId]);
    }

    function getChannelStatesBatch(bytes32[] calldata channelIds)
        external
        view
        returns (ChannelState[] memory states)
    {
        uint256 length = channelIds.length;
        states = new ChannelState[](length);

        for (uint256 i = 0; i < length; ++i) {
            states[i] = _decodeChannelState(channelStates[channelIds[i]]);
        }
    }

    function computeChannelId(
        address payer,
        address payee,
        address operator,
        address token,
        bytes32 salt,
        address authorizedSigner,
        bytes32 expiringNonceHash
    )
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                payer,
                payee,
                operator,
                token,
                salt,
                authorizedSigner,
                expiringNonceHash,
                TIP20_CHANNEL_RESERVE,
                block.chainid
            )
        );
    }

    function getVoucherDigest(
        bytes32 channelId,
        uint96 cumulativeAmount
    )
        external
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
        return _hashTypedData(structHash);
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    function _channelId(ChannelDescriptor calldata descriptor) internal view returns (bytes32) {
        return computeChannelId(
            descriptor.payer,
            descriptor.payee,
            descriptor.operator,
            descriptor.token,
            descriptor.salt,
            descriptor.authorizedSigner,
            descriptor.expiringNonceHash
        );
    }

    function _loadChannelState(bytes32 channelId) internal view returns (ChannelState memory) {
        uint256 packedState = channelStates[channelId];
        if (packedState == 0) revert ChannelNotFound();
        return _decodeChannelState(packedState);
    }

    function _decodeChannelState(uint256 packedState)
        internal
        pure
        returns (ChannelState memory state)
    {
        if (packedState == 0) {
            return state;
        }

        state.settled = uint96(packedState);
        state.deposit = uint96(packedState >> _DEPOSIT_OFFSET);
        state.closeRequestedAt = uint32(packedState >> _CLOSE_REQUESTED_AT_OFFSET);
    }

    function _encodeChannelState(ChannelState memory state)
        internal
        pure
        returns (uint256 packedState)
    {
        packedState = uint256(state.settled);
        packedState |= uint256(state.deposit) << _DEPOSIT_OFFSET;
        packedState |= uint256(state.closeRequestedAt) << _CLOSE_REQUESTED_AT_OFFSET;
    }

    function _validateVoucher(
        ChannelDescriptor calldata descriptor,
        bytes32 channelId,
        uint96 cumulativeAmount,
        bytes calldata signature
    )
        internal
        view
    {
        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
        bytes32 digest = _hashTypedData(structHash);
        address expectedSigner = descriptor.authorizedSigner != address(0)
            ? descriptor.authorizedSigner
            : descriptor.payer;

        bool isValid;
        try ISignatureVerifier(SIGNATURE_VERIFIER_PRECOMPILE)
            .verify(expectedSigner, digest, signature) returns (
            bool valid
        ) {
            isValid = valid;
        } catch {
            revert InvalidSignature();
        }

        if (!isValid) revert InvalidSignature();
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                _NAME_HASH,
                _VERSION_HASH,
                block.chainid,
                TIP20_CHANNEL_RESERVE
            )
        );
    }

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function _consumeExpiringNonceHash() internal returns (bytes32 expiringNonceHash) {
        expiringNonceHash = _expiringNonceHashContext;
        if (expiringNonceHash == bytes32(0)) revert ExpiringNonceHashNotSet();
        delete _expiringNonceHashContext;
    }

    function _isTip20Prefix(address account) internal pure returns (bool) {
        return bytes12(bytes20(account)) == _TIP20_TOKEN_PREFIX;
    }

}
