// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    DepositPayload,
    IWithdrawalReceiver,
    IZoneFactory,
    IZonePortal,
    ZONE_MESSENGER_ADDRESS,
    ZoneInfo
} from "../../src/runtime/interfaces/IZone.sol";
import { SwapAndDepositRouter } from "../../src/runtime/tempo/SwapAndDepositRouter.sol";
import { BaseTest } from "../BaseTest.t.sol";
import { IStablecoinDEX } from "tempo-std/interfaces/IStablecoinDEX.sol";
import { ITIP20 } from "tempo-std/interfaces/ITIP20.sol";

contract MockStablecoinDEXForRouter {

    uint128 public nextAmountOut;
    bool public shouldRevert;

    function setNextAmountOut(uint128 _amountOut) external {
        nextAmountOut = _amountOut;
    }

    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function swapExactAmountIn(
        address tokenIn,
        address tokenOut,
        uint128 amountIn,
        uint128 minAmountOut
    )
        external
        returns (uint128 amountOut)
    {
        if (shouldRevert || nextAmountOut < minAmountOut) {
            revert IStablecoinDEX.InsufficientOutput();
        }
        ITIP20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        amountOut = nextAmountOut;
        ITIP20(tokenOut).mint(msg.sender, amountOut);
    }

}

contract MockZoneFactoryForRouter {

    mapping(address => bool) public portalMap;
    mapping(uint32 => ZoneInfo) internal _zones;

    function setPortal(address portal, bool registered) external {
        portalMap[portal] = registered;
    }

    function setSourcePortal(uint32 zoneId, address portal) external {
        _zones[zoneId].zoneId = zoneId;
        _zones[zoneId].portal = portal;
    }

    function isZonePortal(address portal) external view returns (bool) {
        return portalMap[portal];
    }

    function zones(uint32 id) external view returns (ZoneInfo memory) {
        return _zones[id];
    }

}

contract MockZonePortalForRouter {

    mapping(address => bool) public enabledTokens;

    uint128 public lastDepositAmount;
    uint256 public lastDepositKeyIndex;
    address public lastDepositBouncebackRecipient;
    bool public encryptedDepositCalled;

    function enableToken(address _token) external {
        enabledTokens[_token] = true;
    }

    function isTokenEnabled(address _token) external view returns (bool) {
        return enabledTokens[_token];
    }

    function deposit(
        address _token,
        uint128 amount,
        uint256 keyIndex,
        DepositPayload calldata,
        address tempoRefundRecipient
    )
        external
        returns (bytes32)
    {
        ITIP20(_token).transferFrom(msg.sender, address(this), amount);
        lastDepositAmount = amount;
        lastDepositKeyIndex = keyIndex;
        lastDepositBouncebackRecipient = tempoRefundRecipient;
        encryptedDepositCalled = true;
        return bytes32(0);
    }

}

contract SwapAndDepositRouterTest is BaseTest {

    SwapAndDepositRouter public router;
    MockStablecoinDEXForRouter public mockDEX;
    MockZoneFactoryForRouter public mockFactory;
    MockZonePortalForRouter public mockPortal;
    MockZonePortalForRouter public mockPortal2;

    uint32 public constant SOURCE_ZONE_ID = 7;
    bytes32 public senderTag = keccak256(abi.encodePacked(address(0x500)));
    address public sourcePortal = address(0x501);
    address public refundBurner = address(0xb000000000000000000000000000000000000123);
    uint128 public constant AMOUNT = 1000e6;

    function setUp() public override {
        super.setUp();

        mockDEX = new MockStablecoinDEXForRouter();
        mockFactory = new MockZoneFactoryForRouter();
        mockPortal = new MockZonePortalForRouter();
        mockPortal2 = new MockZonePortalForRouter();

        router = new SwapAndDepositRouter(address(mockDEX), address(mockFactory));

        mockFactory.setSourcePortal(SOURCE_ZONE_ID, sourcePortal);
        mockFactory.setPortal(address(mockPortal), true);
        mockFactory.setPortal(address(mockPortal2), true);

        mockPortal.enableToken(address(pathUSD));
        mockPortal2.enableToken(address(token1));

        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.mint(address(router), AMOUNT * 10);
        vm.stopPrank();

        vm.prank(sequencer);
        token1.grantRole(_ISSUER_ROLE, sequencer);
        vm.prank(sequencer);
        token1.mint(address(router), AMOUNT * 10);

        vm.prank(sequencer);
        token1.grantRole(_ISSUER_ROLE, address(mockDEX));
    }

    function _buildCallbackData(
        address tokenOut,
        address targetPortal,
        uint256 keyIndex,
        DepositPayload memory encrypted,
        address tempoRefundRecipient,
        uint128 minAmountOut
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            tokenOut, targetPortal, keyIndex, encrypted, tempoRefundRecipient, minAmountOut
        );
    }

    function _defaultDepositPayload() internal pure returns (DepositPayload memory) {
        return DepositPayload({
            ephemeralPubkeyX: bytes32(uint256(0x1234)),
            ephemeralPubkeyYParity: 0x02,
            ciphertext: hex"deadbeef",
            nonce: bytes12(uint96(42)),
            tag: bytes16(uint128(99))
        });
    }

    function test_revertUnauthorizedMessenger() public {
        bytes memory data = _buildCallbackData(
            address(pathUSD), address(mockPortal), 0, _defaultDepositPayload(), refundBurner, 0
        );

        vm.prank(alice);
        vm.expectRevert(SwapAndDepositRouter.UnauthorizedMessenger.selector);
        router.onWithdrawalReceived(
            SOURCE_ZONE_ID, sourcePortal, senderTag, address(pathUSD), AMOUNT, data
        );
    }

    function test_revertInvalidSourcePortal() public {
        bytes memory data = _buildCallbackData(
            address(pathUSD), address(mockPortal), 0, _defaultDepositPayload(), refundBurner, 0
        );

        vm.prank(ZONE_MESSENGER_ADDRESS);
        vm.expectRevert(SwapAndDepositRouter.InvalidSourcePortal.selector);
        router.onWithdrawalReceived(
            SOURCE_ZONE_ID, address(0xBAD), senderTag, address(pathUSD), AMOUNT, data
        );
    }

    function test_revertInvalidTargetPortal() public {
        address fakePortal = address(0xFAFAFA);
        bytes memory data = _buildCallbackData(
            address(pathUSD), fakePortal, 0, _defaultDepositPayload(), refundBurner, 0
        );

        vm.prank(ZONE_MESSENGER_ADDRESS);
        vm.expectRevert(SwapAndDepositRouter.InvalidTargetPortal.selector);
        router.onWithdrawalReceived(
            SOURCE_ZONE_ID, sourcePortal, senderTag, address(pathUSD), AMOUNT, data
        );
    }

    function test_revertInvalidToken() public {
        bytes memory data = _buildCallbackData(
            address(token1), address(mockPortal), 0, _defaultDepositPayload(), refundBurner, 0
        );

        vm.prank(ZONE_MESSENGER_ADDRESS);
        vm.expectRevert(SwapAndDepositRouter.InvalidToken.selector);
        router.onWithdrawalReceived(
            SOURCE_ZONE_ID, sourcePortal, senderTag, address(pathUSD), AMOUNT, data
        );
    }

    function test_deposit_sameToken() public {
        DepositPayload memory payload = _defaultDepositPayload();
        bytes memory data =
            _buildCallbackData(address(pathUSD), address(mockPortal), 0, payload, refundBurner, 0);

        vm.prank(ZONE_MESSENGER_ADDRESS);
        bytes4 ret = router.onWithdrawalReceived(
            SOURCE_ZONE_ID, sourcePortal, senderTag, address(pathUSD), AMOUNT, data
        );

        assertEq(ret, IWithdrawalReceiver.onWithdrawalReceived.selector);
        assertTrue(mockPortal.encryptedDepositCalled());
        assertEq(mockPortal.lastDepositAmount(), AMOUNT);
        assertEq(mockPortal.lastDepositKeyIndex(), 0);
        assertEq(mockPortal.lastDepositBouncebackRecipient(), refundBurner);
    }

    function test_deposit_withSwap() public {
        uint128 swapOut = 950e6;
        mockDEX.setNextAmountOut(swapOut);

        DepositPayload memory payload = _defaultDepositPayload();
        bytes memory data = _buildCallbackData(
            address(token1), address(mockPortal2), 1, payload, refundBurner, 900e6
        );

        vm.prank(ZONE_MESSENGER_ADDRESS);
        bytes4 ret = router.onWithdrawalReceived(
            SOURCE_ZONE_ID, sourcePortal, senderTag, address(pathUSD), AMOUNT, data
        );

        assertEq(ret, IWithdrawalReceiver.onWithdrawalReceived.selector);
        assertTrue(mockPortal2.encryptedDepositCalled());
        assertEq(mockPortal2.lastDepositAmount(), swapOut);
        assertEq(mockPortal2.lastDepositKeyIndex(), 1);
        assertEq(mockPortal2.lastDepositBouncebackRecipient(), refundBurner);
    }

    function test_swapSlippageReverts() public {
        mockDEX.setNextAmountOut(800e6);

        bytes memory data = _buildCallbackData(
            address(token1), address(mockPortal2), 0, _defaultDepositPayload(), refundBurner, 900e6
        );

        vm.prank(ZONE_MESSENGER_ADDRESS);
        vm.expectRevert(IStablecoinDEX.InsufficientOutput.selector);
        router.onWithdrawalReceived(
            SOURCE_ZONE_ID, sourcePortal, senderTag, address(pathUSD), AMOUNT, data
        );
    }

}
