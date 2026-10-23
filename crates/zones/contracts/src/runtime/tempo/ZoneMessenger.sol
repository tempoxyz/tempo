// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    IWithdrawalReceiver,
    IZoneFactory,
    IZoneMessenger,
    IZonePortal,
    Role,
    ZONE_FACTORY_ADDRESS,
    ZoneInfo
} from "../interfaces/IZone.sol";
import { StdPrecompiles } from "tempo-std/StdPrecompiles.sol";
import { ITIP20 } from "tempo-std/interfaces/ITIP20.sol";

/// @title ZoneMessenger
/// @notice Shared withdrawal callback sender for all zones created by one ZoneFactory.
contract ZoneMessenger is IZoneMessenger {

    IZoneFactory public constant zoneFactory = IZoneFactory(ZONE_FACTORY_ADDRESS);

    uint256 internal _relayReentrancyStatus;

    error UnauthorizedPortal();
    error TransferFailed();
    error CallbackRejected();
    error InvalidCallbackTarget();
    error ReentrantRelay();

    modifier nonReentrantRelay() {
        if (_relayReentrancyStatus != 0) revert ReentrantRelay();
        _relayReentrancyStatus = 1;
        _;
        _relayReentrancyStatus = 0;
    }

    function relayMessage(
        uint32 zoneId,
        address token,
        bytes32 senderTag,
        address target,
        uint128 amount,
        uint64 gasLimit,
        bytes calldata data
    )
        external
        nonReentrantRelay
    {
        ZoneInfo memory zone = zoneFactory.zones(zoneId);
        if (zone.portal != msg.sender) revert UnauthorizedPortal();

        if (
            !IZonePortal(msg.sender).isGatewayOpen()
                && !IZonePortal(msg.sender).hasRole(target, Role.CallbackGateway)
        ) {
            revert InvalidCallbackTarget();
        }

        address effectiveRecipient = StdPrecompiles.ADDRESS_REGISTRY.resolveRecipient(target);
        (bool authorized,) = StdPrecompiles.TIP403_REGISTRY
            .validateReceivePolicy(token, address(this), effectiveRecipient);
        if (!authorized) revert TransferFailed();

        // Raw call is fine: `enableToken` only accepts native TIP-20s, which revert small.
        if (!ITIP20(token).transfer(target, amount)) {
            revert TransferFailed();
        }

        // The target is untrusted, so the empty `catch` drops its revert data. Copying it would
        // cost quadratic memory gas here and again in the portal, well past `gasLimit`.
        try IWithdrawalReceiver(target).onWithdrawalReceived{ gas: gasLimit }(
            zoneId, msg.sender, senderTag, token, amount, data
        ) returns (
            bytes4 selector
        ) {
            if (selector != IWithdrawalReceiver.onWithdrawalReceived.selector) {
                revert CallbackRejected();
            }
        } catch {
            revert CallbackRejected();
        }
    }

}
