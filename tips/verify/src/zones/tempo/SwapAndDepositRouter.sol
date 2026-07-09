// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    EncryptedDepositPayload,
    IWithdrawalReceiver,
    IZoneFactory,
    IZonePortal
} from "../interfaces/IZone.sol";
import { IStablecoinDEX } from "tempo-std/interfaces/IStablecoinDEX.sol";
import { ITIP20 } from "tempo-std/interfaces/ITIP20.sol";

/// @title SwapAndDepositRouter
/// @notice Router contract for cross-zone transfers with optional token swap
/// @dev Receives withdrawal callbacks, swaps tokens if needed via StablecoinDEX, and deposits to target zone.
///      Handles both same-token (no swap) and different-token (swap) cross-zone transfers.
///      Supports both plaintext and encrypted deposits.
///      On any failure (swap or deposit), the entire callback reverts, causing the withdrawal
///      to bounce back to the fallbackRecipient on the source zone.
contract SwapAndDepositRouter is IWithdrawalReceiver {

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    IStablecoinDEX public immutable stablecoinDEX;
    IZoneFactory public immutable zoneFactory;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error UnauthorizedMessenger();
    error InvalidTargetPortal();
    error InvalidToken();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _stablecoinDEX, address _zoneFactory) {
        stablecoinDEX = IStablecoinDEX(_stablecoinDEX);
        zoneFactory = IZoneFactory(_zoneFactory);
    }

    /*//////////////////////////////////////////////////////////////
                         WITHDRAWAL CALLBACK
    //////////////////////////////////////////////////////////////*/

    /// @notice Receive a cross-zone withdrawal, optionally swap tokens, and deposit to target zone
    /// @dev Implements IWithdrawalReceiver. Only callable by registered zone messengers.
    ///      The messenger has already transferred tokens to this router.
    ///      On failure, the entire callback reverts, triggering bounce-back to source zone.
    /// @param tokenIn The TIP-20 token received from the source zone withdrawal
    /// @param amount The amount of tokens transferred
    /// @param data ABI-encoded callbackData (see format below)
    /// @return selector The function selector to confirm successful handling
    ///
    /// Plaintext format: (bool isEncrypted=false, address tokenOut, address targetPortal, address recipient, address bouncebackRecipient, bytes32 memo, uint128 minAmountOut)
    /// Encrypted format: (bool isEncrypted=true, address tokenOut, address targetPortal, uint256 keyIndex, EncryptedDepositPayload encrypted, address bouncebackRecipient, uint128 minAmountOut)
    ///
    /// Note: minAmountOut is ignored for same-token transfers (no swap)
    function onWithdrawalReceived(
        bytes32, /* senderTag */
        address tokenIn,
        uint128 amount,
        bytes calldata data
    )
        external
        returns (bytes4)
    {
        if (!zoneFactory.isZoneMessenger(msg.sender)) {
            revert UnauthorizedMessenger();
        }

        bool isEncrypted = abi.decode(data, (bool));

        if (isEncrypted) {
            (, // skip isEncrypted
                address tokenOut,
                address targetPortal,
                uint256 keyIndex,
                EncryptedDepositPayload memory encrypted,
                address bouncebackRecipient,
                uint128 minAmountOut
            ) = abi.decode(
                data, (bool, address, address, uint256, EncryptedDepositPayload, address, uint128)
            );

            _validateTarget(targetPortal, tokenOut);

            uint128 amountOut = _swapIfNeeded(tokenIn, tokenOut, amount, minAmountOut);

            ITIP20(tokenOut).approve(targetPortal, amountOut);
            IZonePortal(targetPortal)
                .depositEncrypted(tokenOut, amountOut, keyIndex, encrypted, bouncebackRecipient);
        } else {
            (, // skip isEncrypted
                address tokenOut,
                address targetPortal,
                address recipient,
                address bouncebackRecipient,
                bytes32 memo,
                uint128 minAmountOut
            ) = abi.decode(data, (bool, address, address, address, address, bytes32, uint128));

            _validateTarget(targetPortal, tokenOut);

            uint128 amountOut = _swapIfNeeded(tokenIn, tokenOut, amount, minAmountOut);

            ITIP20(tokenOut).approve(targetPortal, amountOut);
            IZonePortal(targetPortal)
                .deposit(tokenOut, recipient, amountOut, memo, bouncebackRecipient);
        }

        return IWithdrawalReceiver.onWithdrawalReceived.selector;
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validate the target portal is registered and the token is enabled on it
    function _validateTarget(address targetPortal, address tokenOut) internal view {
        if (!zoneFactory.isZonePortal(targetPortal)) {
            revert InvalidTargetPortal();
        }
        if (!IZonePortal(targetPortal).isTokenEnabled(tokenOut)) {
            revert InvalidToken();
        }
    }

    function _swapIfNeeded(
        address tokenIn,
        address tokenOut,
        uint128 amountIn,
        uint128 minAmountOut
    )
        internal
        returns (uint128 amountOut)
    {
        if (tokenIn == tokenOut) {
            return amountIn;
        }

        ITIP20(tokenIn).approve(address(stablecoinDEX), amountIn);
        amountOut = stablecoinDEX.swapExactAmountIn(tokenIn, tokenOut, amountIn, minAmountOut);
    }

}
