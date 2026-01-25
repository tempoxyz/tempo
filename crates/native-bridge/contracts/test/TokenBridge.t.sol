// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {TokenBridge} from "../src/TokenBridge.sol";
import {MessageBridge} from "../src/MessageBridge.sol";
import {ITokenBridge} from "../src/interfaces/ITokenBridge.sol";
import {IMessageBridge} from "../src/interfaces/IMessageBridge.sol";

/// @notice Mock ERC20 token for testing home chain (lock/unlock)
contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function mint(address to, uint256 amount) external virtual {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @notice Mock TIP-20 style mintable/burnable token for testing remote chain
/// Uses burn(amount) which burns from msg.sender (Option B in spec)
contract MockMintableBurnable is MockERC20 {
    address public minter;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) MockERC20(_name, _symbol, _decimals) {}

    function setMinter(address _minter) external {
        minter = _minter;
    }

    function mint(address to, uint256 amount) external override {
        require(msg.sender == minter, "Not minter");
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    /// @notice TIP-20 style burn - burns from msg.sender
    function burn(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
    }
}

contract TokenBridgeTest is Test {
    TokenBridge public bridge;
    MessageBridge public messageBridge;
    MockERC20 public usdc;
    MockMintableBurnable public usdcT;

    address public owner = address(0x1);
    address public user = address(0x2);
    address public recipient = address(0x3);

    uint64 public constant ETH_CHAIN_ID = 1;
    uint64 public constant TEMPO_CHAIN_ID = 12345;

    bytes32 public usdcAssetId;

    // Dummy G2 public key (256 bytes) for MessageBridge initialization
    bytes public dummyPublicKey;

    function setUp() public {
        // Create dummy 256-byte G2 public key
        dummyPublicKey = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            dummyPublicKey[i] = bytes1(uint8(i % 256));
        }

        // Deploy on "Ethereum" (home chain for USDC)
        vm.chainId(ETH_CHAIN_ID);

        // Deploy real MessageBridge
        messageBridge = new MessageBridge(owner, 1, dummyPublicKey);
        bridge = new TokenBridge(owner, address(messageBridge));

        // Deploy mock USDC
        usdc = new MockERC20("USD Coin", "USDC", 6);

        // Compute asset ID
        usdcAssetId = keccak256(abi.encodePacked(uint64(ETH_CHAIN_ID), address(usdc)));

        // Register USDC (home chain)
        vm.prank(owner);
        bridge.registerAsset(usdcAssetId, ETH_CHAIN_ID, address(usdc), address(usdc), true);

        // Mint USDC to user
        usdc.mint(user, 1_000_000e6); // 1M USDC
    }

    /// @notice Helper to mock a message being received on the MessageBridge
    /// Uses vm.store to directly set the received mapping
    function _mockMessageReceived(uint64 originChainId, address sender, bytes32 messageHash) internal {
        _mockMessageReceivedOn(address(messageBridge), originChainId, sender, messageHash);
    }

    /// @notice Helper to mock a message being received on a specific MessageBridge
    function _mockMessageReceivedOn(
        address bridge_,
        uint64 originChainId,
        address sender,
        bytes32 messageHash
    ) internal {
        // Storage layout from `forge inspect MessageBridge storage`:
        // slot 0: owner (20 bytes) + paused (1 byte) + epoch (8 bytes)
        // slot 1: previousEpoch
        // slot 2: groupPublicKey (bytes)
        // slot 3: previousGroupPublicKey (bytes)
        // slot 4: sent mapping
        // slot 5: received mapping

        uint256 baseSlot = 5; // received mapping base slot

        // The received mapping is: mapping(uint64 => mapping(address => mapping(bytes32 => uint256)))
        // Slot calculation: keccak256(messageHash, keccak256(sender, keccak256(originChainId, baseSlot)))
        bytes32 slot1 = keccak256(abi.encode(originChainId, baseSlot));
        bytes32 slot2 = keccak256(abi.encode(sender, slot1));
        bytes32 finalSlot = keccak256(abi.encode(messageHash, slot2));

        // Store timestamp
        vm.store(bridge_, finalSlot, bytes32(block.timestamp));
    }

    //=============================================================
    //                      CONSTRUCTOR TESTS
    //=============================================================

    function test_constructor() public view {
        assertEq(bridge.owner(), owner);
        assertEq(address(bridge.messageBridge()), address(messageBridge));
        assertEq(bridge.chainId(), ETH_CHAIN_ID);
        assertEq(bridge.nonce(), 0);
        assertEq(bridge.paused(), false);
    }

    //=============================================================
    //                   ASSET REGISTRATION TESTS
    //=============================================================

    function test_registerAsset() public view {
        ITokenBridge.Asset memory asset = bridge.getAsset(usdcAssetId);
        assertEq(asset.homeChainId, ETH_CHAIN_ID);
        assertEq(asset.homeToken, address(usdc));
        assertEq(asset.localToken, address(usdc));
        assertTrue(asset.isHomeChain);
        assertTrue(asset.active);
    }

    function test_registerAsset_mismatchedId() public {
        bytes32 wrongId = keccak256("wrong");

        vm.prank(owner);
        vm.expectRevert(ITokenBridge.AssetIdMismatch.selector);
        bridge.registerAsset(wrongId, ETH_CHAIN_ID, address(usdc), address(usdc), true);
    }

    function test_registerAsset_unauthorized() public {
        vm.prank(user);
        vm.expectRevert(ITokenBridge.Unauthorized.selector);
        bridge.registerAsset(usdcAssetId, ETH_CHAIN_ID, address(usdc), address(usdc), true);
    }

    function test_computeAssetId() public view {
        bytes32 computed = bridge.computeAssetId(ETH_CHAIN_ID, address(usdc));
        assertEq(computed, usdcAssetId);
    }

    //=============================================================
    //                    BRIDGE TOKENS TESTS (LOCK)
    //=============================================================

    function test_bridgeTokens_lock() public {
        uint256 amount = 1000e6; // 1000 USDC

        // Approve bridge
        vm.prank(user);
        usdc.approve(address(bridge), amount);

        // Bridge tokens
        vm.prank(user);
        (bytes32 messageHash, uint256 transferNonce) =
            bridge.bridgeTokens(usdcAssetId, recipient, amount, TEMPO_CHAIN_ID);

        // Verify state
        assertEq(bridge.nonce(), 1);
        assertEq(transferNonce, 0);
        assertEq(usdc.balanceOf(address(bridge)), amount);
        assertEq(usdc.balanceOf(user), 1_000_000e6 - amount);

        // Verify message was sent to real MessageBridge
        assertTrue(messageBridge.isSent(address(bridge), messageHash));

        // Verify message hash
        bytes32 expectedHash = bridge.computeMessageHash(
            ETH_CHAIN_ID, TEMPO_CHAIN_ID, ETH_CHAIN_ID, address(usdc), recipient, amount, 0
        );
        assertEq(messageHash, expectedHash);
    }

    function test_bridgeTokens_multipleTransfers() public {
        uint256 amount = 100e6;

        vm.startPrank(user);
        usdc.approve(address(bridge), amount * 3);

        (, uint256 nonce1) = bridge.bridgeTokens(usdcAssetId, recipient, amount, TEMPO_CHAIN_ID);
        (, uint256 nonce2) = bridge.bridgeTokens(usdcAssetId, recipient, amount, TEMPO_CHAIN_ID);
        (, uint256 nonce3) = bridge.bridgeTokens(usdcAssetId, recipient, amount, TEMPO_CHAIN_ID);
        vm.stopPrank();

        assertEq(nonce1, 0);
        assertEq(nonce2, 1);
        assertEq(nonce3, 2);
        assertEq(bridge.nonce(), 3);
    }

    function test_bridgeTokens_zeroAmount() public {
        vm.prank(user);
        vm.expectRevert(ITokenBridge.InvalidAmount.selector);
        bridge.bridgeTokens(usdcAssetId, recipient, 0, TEMPO_CHAIN_ID);
    }

    function test_bridgeTokens_zeroRecipient() public {
        vm.prank(user);
        vm.expectRevert(ITokenBridge.InvalidRecipient.selector);
        bridge.bridgeTokens(usdcAssetId, address(0), 100e6, TEMPO_CHAIN_ID);
    }

    function test_bridgeTokens_unregisteredAsset() public {
        bytes32 fakeAssetId = keccak256("fake");

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ITokenBridge.AssetNotRegistered.selector, fakeAssetId));
        bridge.bridgeTokens(fakeAssetId, recipient, 100e6, TEMPO_CHAIN_ID);
    }

    function test_bridgeTokens_inactiveAsset() public {
        vm.prank(owner);
        bridge.setAssetActive(usdcAssetId, false);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ITokenBridge.AssetNotActive.selector, usdcAssetId));
        bridge.bridgeTokens(usdcAssetId, recipient, 100e6, TEMPO_CHAIN_ID);
    }

    function test_bridgeTokens_whenPaused() public {
        vm.prank(owner);
        bridge.pause();

        vm.prank(user);
        vm.expectRevert(ITokenBridge.ContractPaused.selector);
        bridge.bridgeTokens(usdcAssetId, recipient, 100e6, TEMPO_CHAIN_ID);
    }

    //=============================================================
    //                    CLAIM TOKENS TESTS (UNLOCK)
    //=============================================================

    function test_claimTokens_unlock() public {
        uint256 amount = 1000e6;

        // First, lock some tokens
        vm.startPrank(user);
        usdc.approve(address(bridge), amount);
        bridge.bridgeTokens(usdcAssetId, recipient, amount, TEMPO_CHAIN_ID);
        vm.stopPrank();

        // Simulate return journey: Tempo -> Ethereum
        bytes32 returnHash =
            bridge.computeMessageHash(TEMPO_CHAIN_ID, ETH_CHAIN_ID, ETH_CHAIN_ID, address(usdc), recipient, amount, 0);

        // Mock the message being received on real MessageBridge
        _mockMessageReceived(TEMPO_CHAIN_ID, address(bridge), returnHash);

        // Verify mock worked
        assertGt(messageBridge.receivedAt(TEMPO_CHAIN_ID, address(bridge), returnHash), 0);

        // Claim tokens
        uint256 recipientBalanceBefore = usdc.balanceOf(recipient);
        bridge.claimTokens(usdcAssetId, recipient, amount, 0, TEMPO_CHAIN_ID);

        // Verify recipient received tokens
        assertEq(usdc.balanceOf(recipient), recipientBalanceBefore + amount);

        // Verify claimed
        assertTrue(bridge.isClaimed(TEMPO_CHAIN_ID, returnHash));
    }

    function test_claimTokens_messageNotReceived() public {
        uint256 amount = 1000e6;

        // Try to claim without message being received
        vm.expectRevert(ITokenBridge.MessageNotReceived.selector);
        bridge.claimTokens(usdcAssetId, recipient, amount, 0, TEMPO_CHAIN_ID);
    }

    function test_claimTokens_alreadyClaimed() public {
        uint256 amount = 1000e6;

        // Lock tokens first
        vm.startPrank(user);
        usdc.approve(address(bridge), amount);
        bridge.bridgeTokens(usdcAssetId, recipient, amount, TEMPO_CHAIN_ID);
        vm.stopPrank();

        bytes32 returnHash =
            bridge.computeMessageHash(TEMPO_CHAIN_ID, ETH_CHAIN_ID, ETH_CHAIN_ID, address(usdc), recipient, amount, 0);

        _mockMessageReceived(TEMPO_CHAIN_ID, address(bridge), returnHash);

        // First claim succeeds
        bridge.claimTokens(usdcAssetId, recipient, amount, 0, TEMPO_CHAIN_ID);

        // Second claim fails
        vm.expectRevert(ITokenBridge.AlreadyClaimed.selector);
        bridge.claimTokens(usdcAssetId, recipient, amount, 0, TEMPO_CHAIN_ID);
    }

    function test_claimTokens_whenPaused() public {
        vm.prank(owner);
        bridge.pause();

        vm.expectRevert(ITokenBridge.ContractPaused.selector);
        bridge.claimTokens(usdcAssetId, recipient, 100e6, 0, TEMPO_CHAIN_ID);
    }

    //=============================================================
    //                 REMOTE CHAIN TESTS (MINT/BURN)
    //=============================================================

    function test_remoteChain_mint() public {
        // Deploy a new bridge on "Tempo" (remote chain)
        vm.chainId(TEMPO_CHAIN_ID);

        MessageBridge tempoMessageBridge = new MessageBridge(owner, 1, dummyPublicKey);
        TokenBridge remoteBridge = new TokenBridge(owner, address(tempoMessageBridge));

        // Deploy USDC.t (wrapped token)
        usdcT = new MockMintableBurnable("Bridged USDC", "USDC.t", 6);
        usdcT.setMinter(address(remoteBridge));

        // Register USDC.t as remote asset
        vm.prank(owner);
        remoteBridge.registerAsset(
            usdcAssetId,
            ETH_CHAIN_ID, // home chain is Ethereum
            address(usdc), // home token is USDC on Ethereum
            address(usdcT), // local token is USDC.t
            false // NOT home chain
        );

        // Simulate deposit from Ethereum being attested
        uint256 amount = 500e6;
        bytes32 messageHash = remoteBridge.computeMessageHash(
            ETH_CHAIN_ID, TEMPO_CHAIN_ID, ETH_CHAIN_ID, address(usdc), recipient, amount, 0
        );

        // Mock message received on Tempo's MessageBridge
        _mockMessageReceivedOn(address(tempoMessageBridge), ETH_CHAIN_ID, address(remoteBridge), messageHash);

        // Claim mints tokens
        remoteBridge.claimTokens(usdcAssetId, recipient, amount, 0, ETH_CHAIN_ID);

        assertEq(usdcT.balanceOf(recipient), amount);
    }

    function test_remoteChain_burn() public {
        // Deploy a new bridge on "Tempo"
        vm.chainId(TEMPO_CHAIN_ID);

        MessageBridge tempoMessageBridge = new MessageBridge(owner, 1, dummyPublicKey);
        TokenBridge remoteBridge = new TokenBridge(owner, address(tempoMessageBridge));

        usdcT = new MockMintableBurnable("Bridged USDC", "USDC.t", 6);
        usdcT.setMinter(address(remoteBridge));

        vm.prank(owner);
        remoteBridge.registerAsset(usdcAssetId, ETH_CHAIN_ID, address(usdc), address(usdcT), false);

        // First mint some tokens to user (simulate previous bridge in)
        bytes32 mintHash = remoteBridge.computeMessageHash(
            ETH_CHAIN_ID, TEMPO_CHAIN_ID, ETH_CHAIN_ID, address(usdc), user, 1000e6, 0
        );

        // Mock message received
        _mockMessageReceivedOn(address(tempoMessageBridge), ETH_CHAIN_ID, address(remoteBridge), mintHash);

        remoteBridge.claimTokens(usdcAssetId, user, 1000e6, 0, ETH_CHAIN_ID);

        assertEq(usdcT.balanceOf(user), 1000e6);

        // Now burn to bridge back to Ethereum
        uint256 burnAmount = 300e6;

        vm.startPrank(user);
        usdcT.approve(address(remoteBridge), burnAmount);
        (bytes32 messageHash, uint256 nonce) =
            remoteBridge.bridgeTokens(usdcAssetId, recipient, burnAmount, ETH_CHAIN_ID);
        vm.stopPrank();

        // Verify burn happened
        assertEq(usdcT.balanceOf(user), 1000e6 - burnAmount);
        assertEq(usdcT.totalSupply(), 1000e6 - burnAmount);

        // Verify message was sent to real MessageBridge
        assertTrue(tempoMessageBridge.isSent(address(remoteBridge), messageHash));
        assertEq(nonce, 0);
    }

    //=============================================================
    //                      ADMIN TESTS
    //=============================================================

    function test_pause_unpause() public {
        assertFalse(bridge.paused());

        vm.prank(owner);
        bridge.pause();
        assertTrue(bridge.paused());

        vm.prank(owner);
        bridge.unpause();
        assertFalse(bridge.paused());
    }

    function test_pause_unauthorized() public {
        vm.prank(user);
        vm.expectRevert(ITokenBridge.Unauthorized.selector);
        bridge.pause();
    }

    function test_transferOwnership() public {
        address newOwner = address(0x999);

        vm.prank(owner);
        bridge.transferOwnership(newOwner);

        assertEq(bridge.owner(), newOwner);
    }

    function test_setAssetActive() public {
        assertTrue(bridge.getAsset(usdcAssetId).active);

        vm.prank(owner);
        bridge.setAssetActive(usdcAssetId, false);

        assertFalse(bridge.getAsset(usdcAssetId).active);

        vm.prank(owner);
        bridge.setAssetActive(usdcAssetId, true);

        assertTrue(bridge.getAsset(usdcAssetId).active);
    }

    //=============================================================
    //                    MESSAGE HASH TESTS
    //=============================================================

    function test_messageHash_deterministic() public view {
        bytes32 hash1 = bridge.computeMessageHash(1, 2, 1, address(usdc), recipient, 100e6, 0);
        bytes32 hash2 = bridge.computeMessageHash(1, 2, 1, address(usdc), recipient, 100e6, 0);
        assertEq(hash1, hash2);
    }

    function test_messageHash_differentNonce() public view {
        bytes32 hash1 = bridge.computeMessageHash(1, 2, 1, address(usdc), recipient, 100e6, 0);
        bytes32 hash2 = bridge.computeMessageHash(1, 2, 1, address(usdc), recipient, 100e6, 1);
        assertNotEq(hash1, hash2);
    }

    function test_messageHash_differentDirection() public view {
        bytes32 hash1 = bridge.computeMessageHash(1, 2, 1, address(usdc), recipient, 100e6, 0);
        bytes32 hash2 = bridge.computeMessageHash(2, 1, 1, address(usdc), recipient, 100e6, 0);
        assertNotEq(hash1, hash2);
    }

    function test_messageHash_differentRecipient() public view {
        bytes32 hash1 = bridge.computeMessageHash(1, 2, 1, address(usdc), recipient, 100e6, 0);
        bytes32 hash2 = bridge.computeMessageHash(1, 2, 1, address(usdc), user, 100e6, 0);
        assertNotEq(hash1, hash2);
    }

    function test_messageHash_differentAmount() public view {
        bytes32 hash1 = bridge.computeMessageHash(1, 2, 1, address(usdc), recipient, 100e6, 0);
        bytes32 hash2 = bridge.computeMessageHash(1, 2, 1, address(usdc), recipient, 200e6, 0);
        assertNotEq(hash1, hash2);
    }
}
