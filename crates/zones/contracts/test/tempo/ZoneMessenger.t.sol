// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    IWithdrawalReceiver,
    IZonePortal,
    MAX_WITHDRAWAL_CALLBACK_GAS,
    Role,
    ZONE_FACTORY_ADDRESS,
    ZONE_MESSENGER_ADDRESS,
    ZoneInfo
} from "../../src/runtime/interfaces/IZone.sol";
import { ZoneMessenger } from "../../src/runtime/tempo/ZoneMessenger.sol";
import { BaseTest } from "../BaseTest.t.sol";
import {
    ACCEPTED_CALLBACK_WORD,
    DIRTY_PADDED_CALLBACK_WORD,
    MockRawReturnReceiver,
    MockRevertingReceiver
} from "../mocks/MockCallbackReceivers.sol";
import { MockZoneToken } from "../mocks/MockZoneToken.sol";
import { ITIP20 } from "tempo-std/interfaces/ITIP20.sol";

contract MockZoneFactoryForMessenger {

    mapping(uint32 => ZoneInfo) internal _zones;

    function setPortal(uint32 zoneId, address portal) external {
        _zones[zoneId].zoneId = zoneId;
        _zones[zoneId].portal = portal;
    }

    function zones(uint32 id) external view returns (ZoneInfo memory) {
        return _zones[id];
    }

}

contract AcceptingWithdrawalReceiver is IWithdrawalReceiver {

    uint32 public lastZoneId;
    address public lastSourcePortal;
    bytes32 public lastSenderTag;
    address public lastToken;
    uint128 public lastAmount;
    bytes public lastData;

    function onWithdrawalReceived(
        uint32 zoneId,
        address sourcePortal,
        bytes32 senderTag,
        address token,
        uint128 amount,
        bytes calldata callbackData
    )
        external
        returns (bytes4)
    {
        lastZoneId = zoneId;
        lastSourcePortal = sourcePortal;
        lastSenderTag = senderTag;
        lastToken = token;
        lastAmount = amount;
        lastData = callbackData;
        return IWithdrawalReceiver.onWithdrawalReceived.selector;
    }

}

contract RejectingWithdrawalReceiver is IWithdrawalReceiver {

    function onWithdrawalReceived(
        uint32,
        address,
        bytes32,
        address,
        uint128,
        bytes calldata
    )
        external
        pure
        returns (bytes4)
    {
        return bytes4(0xdeadbeef);
    }

}

contract ZoneMessengerTest is BaseTest {

    uint32 internal constant ZONE_ID = 1;
    uint32 internal constant OTHER_ZONE_ID = 2;
    uint64 internal constant CALLBACK_GAS_LIMIT = MAX_WITHDRAWAL_CALLBACK_GAS;

    /// @dev Oversized response used by the amplification bounds. Anything above ~100,000 bytes
    ///      discriminates an unbounded copy; the pass margin does not depend on the size.
    uint256 internal constant BOMB_SIZE = 900_000;

    /// @dev Headroom over the callee's own memory expansion, covering fixed relay overhead.
    uint256 internal constant AMPLIFICATION_SLACK = 30_000;

    MockZoneFactoryForMessenger public messengerFactory;
    ZoneMessenger public messenger;
    MockZoneToken public zoneToken;

    address public portal = address(0x700);
    address public otherPortal = address(0x702);
    address public token = address(0x701);

    function setUp() public override {
        super.setUp();
        vm.etch(ZONE_FACTORY_ADDRESS, type(MockZoneFactoryForMessenger).runtimeCode);
        messengerFactory = MockZoneFactoryForMessenger(ZONE_FACTORY_ADDRESS);
        messengerFactory.setPortal(ZONE_ID, portal);
        messengerFactory.setPortal(OTHER_ZONE_ID, otherPortal);

        vm.etch(ZONE_MESSENGER_ADDRESS, type(ZoneMessenger).runtimeCode);
        messenger = ZoneMessenger(ZONE_MESSENGER_ADDRESS);
        vm.mockCall(
            portal, abi.encodeWithSelector(IZonePortal.isGatewayOpen.selector), abi.encode(false)
        );
        zoneToken = new MockZoneToken("Zone USD", "zUSD");
        zoneToken.setMinter(address(this), true);
    }

    function _mockTransfer(address target, uint128 amount, bool result) internal {
        _allowGateway(target);
        vm.mockCall(
            token,
            abi.encodeWithSelector(ITIP20.transfer.selector, target, amount),
            abi.encode(result)
        );
    }

    function _allowGateway(address target) internal {
        vm.mockCall(
            portal,
            abi.encodeWithSelector(IZonePortal.hasRole.selector, target, Role.CallbackGateway),
            abi.encode(true)
        );
    }

    function _callback() internal pure returns (bytes memory) {
        return hex"010203";
    }

    /// @dev Setup kept out of `_relay` so a following `vm.expectRevert` binds to the relay.
    function _prepareRelay(address target) internal returns (address) {
        zoneToken.mint(address(messenger), 1);
        _allowGateway(target);
        return target;
    }

    /// @dev Relays one token to an already-prepared `target` at the maximum callback gas.
    function _relay(address target) internal {
        vm.prank(portal);
        messenger.relayMessage(
            ZONE_ID, address(zoneToken), bytes32("sender"), target, 1, CALLBACK_GAS_LIMIT, ""
        );
    }

    /// @dev Relays to `target` and reports the gas charged to the messenger's caller frame.
    function _relayCost(address target) internal returns (uint256 burned) {
        _prepareRelay(target);

        vm.prank(portal);
        uint256 before = gasleft();
        try messenger.relayMessage(
            ZONE_ID, address(zoneToken), bytes32("sender"), target, 1, CALLBACK_GAS_LIMIT, ""
        ) { }
            catch { }
        burned = before - gasleft();
    }

    /// @dev The callee pays its own memory expansion from the forwarded `gasLimit`; the messenger
    ///      must not pay to copy the same blob again. So one expansion is the whole allowance.
    function _assertNotAmplified(uint256 honest, uint256 bombed) internal pure {
        assertLt(bombed, honest + _memoryCost(BOMB_SIZE) + AMPLIFICATION_SLACK);
    }

    /// @dev EVM cost of expanding a fresh frame's memory to `size` bytes.
    function _memoryCost(uint256 size) internal pure returns (uint256) {
        uint256 words = (size + 31) / 32;
        return 3 * words + (words * words) / 512;
    }

    function test_zoneFactoryConstant() public view {
        assertEq(address(messenger.zoneFactory()), address(messengerFactory));
    }

    function test_relayMessage_revertsUnauthorizedPortalForNonPortalCaller() public {
        vm.expectRevert(ZoneMessenger.UnauthorizedPortal.selector);
        messenger.relayMessage(ZONE_ID, token, bytes32("sender"), alice, 1, 50_000, "");
    }

    function test_relayMessage_revertsUnauthorizedPortalForWrongZoneId() public {
        vm.prank(portal);
        vm.expectRevert(ZoneMessenger.UnauthorizedPortal.selector);
        messenger.relayMessage(OTHER_ZONE_ID, token, bytes32("sender"), alice, 1, 50_000, "");
    }

    function test_relayMessage_revertsTransferFailedWhenTransferReturnsFalse() public {
        AcceptingWithdrawalReceiver receiver = new AcceptingWithdrawalReceiver();
        _mockTransfer(address(receiver), 1, false);

        vm.prank(portal);
        vm.expectRevert(ZoneMessenger.TransferFailed.selector);
        messenger.relayMessage(
            ZONE_ID, token, bytes32("sender"), address(receiver), 1, 50_000, _callback()
        );
    }

    function test_relayMessage_revertsCallbackRejectedForWrongSelector() public {
        RejectingWithdrawalReceiver receiver = new RejectingWithdrawalReceiver();
        _mockTransfer(address(receiver), 1, true);

        vm.prank(portal);
        vm.expectRevert(ZoneMessenger.CallbackRejected.selector);
        messenger.relayMessage(
            ZONE_ID, token, bytes32("sender"), address(receiver), 1, 50_000, _callback()
        );
    }

    function test_relayMessage_revertsForEoaTarget() public {
        _mockTransfer(alice, 1, true);

        vm.prank(portal);
        vm.expectRevert();
        messenger.relayMessage(ZONE_ID, token, bytes32("sender"), alice, 1, 50_000, _callback());
    }

    function test_relayMessage_successWithFlattenedFactoryGetter() public {
        AcceptingWithdrawalReceiver receiver = new AcceptingWithdrawalReceiver();
        bytes32 senderTag = keccak256("sender");
        bytes memory data = _callback();
        zoneToken.mint(address(messenger), 123);
        _allowGateway(address(receiver));

        vm.prank(portal);
        messenger.relayMessage(
            ZONE_ID, address(zoneToken), senderTag, address(receiver), 123, CALLBACK_GAS_LIMIT, data
        );

        assertEq(zoneToken.balanceOf(address(receiver)), 123);
        assertEq(receiver.lastZoneId(), ZONE_ID);
        assertEq(receiver.lastSourcePortal(), portal);
        assertEq(receiver.lastSenderTag(), senderTag);
        assertEq(receiver.lastToken(), address(zoneToken));
        assertEq(receiver.lastAmount(), 123);
        assertEq(receiver.lastData(), data);
    }

    function testFuzz_relayMessage_success(uint128 amount, bool redeem) public {
        amount = uint128(bound(amount, 0, 1_000_000_000e6));
        bytes memory data = abi.encode(redeem);
        AcceptingWithdrawalReceiver receiver = new AcceptingWithdrawalReceiver();
        bytes32 senderTag = keccak256(abi.encode(amount, data));
        zoneToken.mint(address(messenger), amount);
        _allowGateway(address(receiver));

        vm.prank(portal);
        messenger.relayMessage(
            ZONE_ID,
            address(zoneToken),
            senderTag,
            address(receiver),
            amount,
            CALLBACK_GAS_LIMIT,
            data
        );

        assertEq(zoneToken.balanceOf(address(receiver)), amount);
    }

    function test_relayMessage_forwardsOpaqueData() public {
        AcceptingWithdrawalReceiver receiver = new AcceptingWithdrawalReceiver();
        bytes memory data = abi.encode(uint256(2));
        zoneToken.mint(address(messenger), 1);
        _allowGateway(address(receiver));

        vm.prank(portal);
        messenger.relayMessage(
            ZONE_ID,
            address(zoneToken),
            bytes32("sender"),
            address(receiver),
            1,
            CALLBACK_GAS_LIMIT,
            data
        );

        assertEq(zoneToken.balanceOf(address(receiver)), 1);
        assertEq(receiver.lastData(), data);
    }

    function test_relayMessage_revertsForUnregisteredGateway() public {
        AcceptingWithdrawalReceiver receiver = new AcceptingWithdrawalReceiver();
        vm.mockCall(
            portal,
            abi.encodeWithSelector(
                IZonePortal.hasRole.selector, address(receiver), Role.CallbackGateway
            ),
            abi.encode(false)
        );

        vm.prank(portal);
        vm.expectRevert(ZoneMessenger.InvalidCallbackTarget.selector);
        messenger.relayMessage(
            ZONE_ID,
            address(zoneToken),
            bytes32("sender"),
            address(receiver),
            1,
            50_000,
            _callback()
        );
    }

    /*//////////////////////////////////////////////////////////////
                        UNTRUSTED RETURN DATA BOUNDS
    //////////////////////////////////////////////////////////////*/

    /// A callback reverting with megabytes must not charge the copy to the messenger's frame,
    /// which is what lets one withdrawal outspend its `gasLimit` and starve the rest of a batch.
    function test_relayMessage_revertBombDoesNotAmplifyCallerGas() public {
        uint256 honest = _relayCost(address(new MockRevertingReceiver(4)));
        uint256 bombed = _relayCost(address(new MockRevertingReceiver(BOMB_SIZE)));

        _assertNotAmplified(honest, bombed);
    }

    /// The same bound for oversized success returns. This already held before the bounded
    /// `catch`, since a static `bytes4` decodes from a fixed window, not `returndatasize()`.
    /// Kept as a guard in case the return type ever becomes dynamic.
    function test_relayMessage_returnBombDoesNotAmplifyCallerGas() public {
        uint256 honest = _relayCost(address(new MockRawReturnReceiver(ACCEPTED_CALLBACK_WORD, 32)));
        uint256 bombed =
            _relayCost(address(new MockRawReturnReceiver(ACCEPTED_CALLBACK_WORD, BOMB_SIZE)));

        _assertNotAmplified(honest, bombed);
    }

    /// Trailing bytes beyond the selector word are ignored, dirty or not.
    function test_relayMessage_acceptsOverlongResponse() public {
        _relay(_prepareRelay(address(new MockRawReturnReceiver(ACCEPTED_CALLBACK_WORD, 64))));
    }

    /// Dirty low-order padding in the selector word must still be rejected.
    ///
    /// `catch` deliberately does not catch return-data decoding failures, so a malformed response
    /// reverts with empty data rather than `CallbackRejected`, unchanged from before this bound.
    /// Either way the portal catches the failure and bounces the withdrawal.
    function test_relayMessage_rejectsDirtyPaddedSelector() public {
        address target =
            _prepareRelay(address(new MockRawReturnReceiver(DIRTY_PADDED_CALLBACK_WORD, 32)));

        vm.expectRevert();
        _relay(target);
    }

    /// A response shorter than one word cannot decode to a `bytes4`.
    function test_relayMessage_rejectsShortResponse() public {
        address target =
            _prepareRelay(address(new MockRawReturnReceiver(ACCEPTED_CALLBACK_WORD, 4)));

        vm.expectRevert();
        _relay(target);
    }

    /// A reverting callback surfaces as `CallbackRejected`, never as the callee's own revert data.
    function test_relayMessage_revertingCallbackSurfacesAsCallbackRejected() public {
        address target = _prepareRelay(address(new MockRevertingReceiver(64)));

        vm.expectRevert(ZoneMessenger.CallbackRejected.selector);
        _relay(target);
    }

}
