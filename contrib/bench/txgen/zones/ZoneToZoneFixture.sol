// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IPortal} from "./PortalFixture.sol";

interface IZoneToZonePortal is IPortal {
    function isGatewayOpen() external view returns (bool);
    function hasRole(address account, uint8 role) external view returns (bool);
}

interface IZoneToZoneToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IWithdrawalReceiver {
    function onWithdrawalReceived(uint32, address, bytes32, address, uint128, bytes calldata) external returns (bytes4);
}

interface IAddressRegistry {
    function resolveRecipient(address to) external view returns (address);
}

interface ITIP403Receive {
    function validateReceivePolicy(address token, address sender, address receiver) external view returns (bool, uint8);
}

/// @notice Local zone -> zone benchmark only: a PortalFixture whose messenger, access mode and
/// roles are constructor arguments. Deploys the exact production ERC-1167 proxy runtime.
/// @dev Gateway mode is always on and `gateway` holds the CallbackGateway role. `closed` turns on
/// account access mode; `account` then holds the Account role (bounce-back refunds, plain
/// withdrawals). Storage layout: crates/precompiles/src/zone_factory/portal.rs.
contract CallbackPortalFixture {
    constructor(
        address admin,
        address token,
        address settlement,
        address messenger,
        address gateway,
        address account,
        bool closed
    ) {
        require(block.chainid == 1337, "local benchmark chain only");
        require(
            address(0x5AD1000000000000000000000000000000000000).code.length != 0,
            "ZonePortal runtime missing; enable T10 or later"
        );

        bytes32 tokenSlot = keccak256(abi.encode(token, uint256(6)));
        bytes32 tokensSlot = keccak256(abi.encode(uint256(7)));
        bytes32 settlementRole = keccak256(abi.encode(settlement, uint256(20)));
        bytes32 gatewayRole = keccak256(abi.encode(gateway, uint256(20)));
        bytes32 accountRole = keccak256(abi.encode(account, uint256(20)));
        bytes32 sequencersSlot = keccak256(abi.encode(uint256(18)));
        bytes32 keysSlot = keccak256(abi.encode(uint256(5)));
        // Slot 21: access enforcement in byte 0, gateway enforcement in byte 1.
        uint256 modes = closed ? 0x0101 : 0x0100;
        assembly {
            sstore(0, admin)
            sstore(tokenSlot, 0x0101)
            sstore(7, 1)
            sstore(tokensSlot, token)
            // Roles: 1 Sequencer, 2 Account, 3 CallbackGateway.
            sstore(settlementRole, 1)
            sstore(gatewayRole, 3)
            sstore(accountRole, 2)
            sstore(21, modes)
            sstore(18, 1)
            sstore(sequencersSlot, settlement)
            // Public, deterministic benchmark encryption key (private scalar 1).
            sstore(5, 1)
            sstore(keysSlot, 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)
            sstore(add(keysSlot, 1), or(2, shl(8, number())))
            // Zone ID 1 and the fixture messenger; dummy verifier, zero attestation threshold.
            sstore(15, or(1, shl(32, messenger)))
            sstore(16, or(settlement, shl(160, 1)))
            sstore(23, or(settlement, shl(160, 1)))
            sstore(24, number())
        }
        bytes memory proxy =
            hex"363d3d373d3d3d363d735ad10000000000000000000000000000000000005af43d82803e903d91602b57fd5bf3";
        assembly { return(add(proxy, 32), mload(proxy)) }
    }
}

/// @notice Local stand-in for the shared ZoneMessenger (crates/zones/contracts/src/runtime/tempo/
/// ZoneMessenger.sol). Fixture portals are not registered in the ZoneFactory, so the shared
/// messenger rejects their callbacks with UnauthorizedPortal. This copy keeps its reentrancy
/// guard, gateway check, recipient and receive-policy lookups, transfer and gas-capped callback,
/// and pays for the factory read without trusting it.
contract ZoneMessengerFixture {
    address internal constant ZONE_FACTORY = 0x5aF2000000000000000000000000000000000000;
    IAddressRegistry internal constant ADDRESS_REGISTRY = IAddressRegistry(0xfDC0000000000000000000000000000000000000);
    ITIP403Receive internal constant TIP403_REGISTRY = ITIP403Receive(0x403c000000000000000000000000000000000000);

    uint256 internal relayStatus;

    error InvalidCallbackTarget();
    error TransferFailed();
    error CallbackRejected();
    error ReentrantRelay();

    constructor() {
        require(block.chainid == 1337, "local benchmark chain only");
    }

    function relayMessage(
        uint32 zoneId,
        address token,
        bytes32 senderTag,
        address target,
        uint128 amount,
        uint64 gasLimit,
        bytes calldata data
    ) external {
        if (relayStatus != 0) revert ReentrantRelay();
        relayStatus = 1;

        _pay(zoneId, token, target, amount);

        try IWithdrawalReceiver(target).onWithdrawalReceived{gas: gasLimit}(
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
        relayStatus = 0;
    }

    function _pay(uint32 zoneId, address token, address target, uint128 amount) internal {
        // zones(uint32): same lookup cost as the shared messenger; fixture portals are unregistered.
        (bool found,) = ZONE_FACTORY.staticcall(abi.encodeWithSignature("zones(uint32)", zoneId));
        found;

        IZoneToZonePortal portal = IZoneToZonePortal(msg.sender);
        if (!portal.isGatewayOpen() && !portal.hasRole(target, 3)) revert InvalidCallbackTarget();

        address recipient = ADDRESS_REGISTRY.resolveRecipient(target);
        (bool authorized,) = TIP403_REGISTRY.validateReceivePolicy(token, address(this), recipient);
        if (!authorized) revert TransferFailed();
        if (!IZoneToZoneToken(token).transfer(target, amount)) revert TransferFailed();
    }
}

/// @notice Local zone -> zone gateway: receives a callback withdrawal from zone A and deposits it
/// into zone B's portal, optionally returning part of it to zone A.
/// @dev callbackData is abi.encode(address targetPortal, uint128 returnAmount). As each portal's
/// CallbackGateway it is exempt from closed portals' account allowlists. A closed source portal
/// accepts a callback only if it appends a source deposit, so a closed A needs returnAmount > 0;
/// otherwise the withdrawal bounces back to zone A.
contract ZoneToZoneGatewayFixture {
    address public immutable messenger;
    address public immutable refundRecipient;

    error UnauthorizedMessenger();

    constructor(address messenger_, address refundRecipient_) {
        require(block.chainid == 1337, "local benchmark chain only");
        messenger = messenger_;
        refundRecipient = refundRecipient_;
    }

    function onWithdrawalReceived(
        uint32,
        address sourcePortal,
        bytes32,
        address token,
        uint128 amount,
        bytes calldata data
    ) external returns (bytes4) {
        if (msg.sender != messenger) revert UnauthorizedMessenger();
        (address targetPortal, uint128 returnAmount) = abi.decode(data, (address, uint128));
        // Same synthetic payload as the zones preset: valid point and length, not decryptable.
        IPortal.DepositPayload memory payload = IPortal.DepositPayload(
            0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
            2,
            hex"11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            bytes12(0x111111111111111111111111),
            bytes16(0x11111111111111111111111111111111)
        );
        // Exact approvals per deposit, as a gateway holding no standing allowance would.
        _deposit(targetPortal, token, amount - returnAmount, payload);
        if (returnAmount > 0) _deposit(sourcePortal, token, returnAmount, payload);
        return IWithdrawalReceiver.onWithdrawalReceived.selector;
    }

    function _deposit(address portal, address token, uint128 amount, IPortal.DepositPayload memory payload) internal {
        IZoneToZoneToken(token).approve(portal, amount);
        IPortal(portal).deposit(token, amount, 0, payload, refundRecipient);
    }
}

/// @notice Local-only dummy verifier and synthetic batch submitter for zone -> zone transfers.
/// No zone or prover runs. Same settlement as SettlementFixture, plus callback withdrawals.
contract ZoneToZoneSettlementFixture {
    mapping(address => bytes32) private processedHash;

    /// @notice Marks a zone -> zone transfer receipt; its WithdrawalProcessed log says whether
    /// the callback delivered (callbackSuccess) or bounced back to zone A.
    event ZoneToZoneTransfer(address indexed source, address indexed target);

    constructor() {
        require(block.chainid == 1337, "local benchmark chain only");
    }

    // Accept either verifier ABI (before or after TIP-1096). No proof is checked.
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(true);
    }

    /// @notice Settle all pending deposits and optionally process one plain withdrawal.
    function settle(IPortal portal, address token, address recipient, bool withdraw) external {
        IPortal.Withdrawal[] memory items = new IPortal.Withdrawal[](withdraw ? 1 : 0);
        if (withdraw) {
            items[0] = IPortal.Withdrawal(token, bytes32(0), recipient, 1, bytes32(0), 0, 1, "", "");
        }
        _settle(portal, items);
    }

    /// @notice One zone -> zone transfer: zone A commits and processes a callback withdrawal to
    /// the gateway, which deposits into zone B; then zone B settles that deposit.
    /// @dev Moves 1 + returnAmount base units out of A. A failed callback bounces back to A
    /// (WithdrawalProcessed(callbackSuccess=false)) without reverting.
    function transfer(
        IPortal source,
        IPortal target,
        address token,
        address gateway,
        uint128 returnAmount,
        uint64 gasLimit
    ) external {
        IPortal.Withdrawal[] memory items = new IPortal.Withdrawal[](1);
        items[0] = IPortal.Withdrawal(
            token,
            bytes32(0),
            gateway,
            1 + returnAmount,
            bytes32(0),
            gasLimit,
            1,
            abi.encode(address(target), returnAmount),
            ""
        );
        _settle(source, items);
        _settle(target, new IPortal.Withdrawal[](0));
        emit ZoneToZoneTransfer(address(source), address(target));
    }

    function _settle(IPortal portal, IPortal.Withdrawal[] memory items) internal {
        bytes32 withdrawalRoot;
        if (items.length != 0) withdrawalRoot = keccak256(abi.encode(items[0], bytes32(0)));
        uint256 height = portal.zoneHeight() + 1;
        IPortal.BlockTransition memory blocks =
            IPortal.BlockTransition(portal.blockHash(), keccak256(abi.encode(address(portal), height)));
        IPortal.DepositQueueTransition memory deposits = IPortal.DepositQueueTransition(
            processedHash[address(portal)],
            portal.currentDepositQueueHash(),
            portal.lastProcessedDepositNumber(),
            portal.depositCount()
        );
        // The real portal authenticates a recent Tempo anchor even with a dummy verifier.
        uint64 anchor = uint64(block.number - 1);
        bytes[] memory signatures = new bytes[](0);
        // TIP-1096 adds the enabled-token cursor to the settlement ABI.
        try portal.lastProcessedEnabledTokenCount() returns (uint64 tokens) {
            portal.submitBatch(
                anchor,
                0,
                blocks,
                deposits,
                IPortal.TokenEnablementTransition(tokens, 1),
                withdrawalRoot,
                "",
                "",
                height,
                signatures
            );
        } catch {
            portal.submitBatch(anchor, 0, blocks, deposits, withdrawalRoot, "", "", height, signatures);
        }
        processedHash[address(portal)] = deposits.nextProcessedHash;
        if (items.length != 0) portal.processWithdrawals(items, bytes32(0));
    }
}

