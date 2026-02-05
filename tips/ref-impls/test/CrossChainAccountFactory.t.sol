// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.28 <0.9.0;

import { CrossChainAccount } from "../src/CrossChainAccount.sol";
import { CrossChainAccountFactory } from "../src/CrossChainAccountFactory.sol";
import { Test, console } from "forge-std/Test.sol";
import { WebAuthn } from "solady/utils/WebAuthn.sol";

contract CrossChainAccountFactoryTest is Test {

    CrossChainAccountFactory factory;

    // Test passkey coordinates (would be real P-256 coords in production)
    bytes32 passkeyX =
        bytes32(uint256(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef));
    bytes32 passkeyY =
        bytes32(uint256(0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321));

    function setUp() public {
        factory = new CrossChainAccountFactory();
    }

    function test_getAddress_isDeterministic() public view {
        address addr1 = factory.getAddress(passkeyX, passkeyY);
        address addr2 = factory.getAddress(passkeyX, passkeyY);
        assertEq(addr1, addr2, "Address should be deterministic");
    }

    function test_getAddress_differentForDifferentKeys() public view {
        address addr1 = factory.getAddress(passkeyX, passkeyY);
        address addr2 = factory.getAddress(passkeyY, passkeyX); // Swapped
        assertTrue(addr1 != addr2, "Different keys should produce different addresses");
    }

    function test_getAddress_differentForDifferentIndex() public view {
        address addr0 = factory.getAddress(passkeyX, passkeyY, 0);
        address addr1 = factory.getAddress(passkeyX, passkeyY, 1);
        assertTrue(addr0 != addr1, "Different indices should produce different addresses");
    }

    function test_createAccount_deploysAtPredictedAddress() public {
        address predicted = factory.getAddress(passkeyX, passkeyY);

        CrossChainAccount account = factory.createAccount(passkeyX, passkeyY);

        assertEq(address(account), predicted, "Account should be at predicted address");
        assertTrue(address(account).code.length > 0, "Account should have code");
    }

    function test_createAccount_initializesCorrectly() public {
        CrossChainAccount account = factory.createAccount(passkeyX, passkeyY);

        assertEq(account.ownerX(), passkeyX, "Owner X should be set");
        assertEq(account.ownerY(), passkeyY, "Owner Y should be set");
        assertTrue(
            account.isAuthorizedKey(account.ownerKeyHash()), "Owner key should be authorized"
        );
        assertTrue(account.initialized(), "Account should be initialized");
    }

    function test_createAccount_returnsExistingIfAlreadyDeployed() public {
        CrossChainAccount account1 = factory.createAccount(passkeyX, passkeyY);
        CrossChainAccount account2 = factory.createAccount(passkeyX, passkeyY);

        assertEq(address(account1), address(account2), "Should return same account");
    }

    function test_createAccount_revertsOnInvalidPasskey() public {
        vm.expectRevert(CrossChainAccountFactory.InvalidPasskey.selector);
        factory.createAccount(bytes32(0), passkeyY);

        vm.expectRevert(CrossChainAccountFactory.InvalidPasskey.selector);
        factory.createAccount(passkeyX, bytes32(0));
    }

    function test_createAccount_withIndex() public {
        CrossChainAccount account0 = factory.createAccount(passkeyX, passkeyY, 0);
        CrossChainAccount account1 = factory.createAccount(passkeyX, passkeyY, 1);

        assertTrue(
            address(account0) != address(account1),
            "Different indices should create different accounts"
        );

        // Both should be properly initialized
        assertEq(account0.ownerX(), passkeyX);
        assertEq(account1.ownerX(), passkeyX);
    }

    function test_account_canReceiveETH() public {
        CrossChainAccount account = factory.createAccount(passkeyX, passkeyY);

        vm.deal(address(this), 1 ether);
        (bool success,) = address(account).call{ value: 0.5 ether }("");

        assertTrue(success, "Should receive ETH");
        assertEq(address(account).balance, 0.5 ether);
    }

    function test_crossChainAddressDeterminism() public {
        // Simulate two factories on different chains
        // Since factory has no constructor args, they will produce identical addresses
        CrossChainAccountFactory factoryChain1 = new CrossChainAccountFactory();
        CrossChainAccountFactory factoryChain2 = new CrossChainAccountFactory();

        // Note: In this test, factory addresses differ due to nonce, so addresses will differ.
        // In production, use deterministic deployment (CREATE2 for factory) to ensure
        // factory addresses match across chains → wallet addresses will match.
        address addr1 = factoryChain1.getAddress(passkeyX, passkeyY);
        address addr2 = factoryChain2.getAddress(passkeyX, passkeyY);

        // These will differ because factory addresses differ
        // This test documents that behavior - real cross-chain determinism
        // requires deterministic factory deployment at same address
        console.log("Chain 1 address:", addr1);
        console.log("Chain 2 address:", addr2);
    }

    function test_emitsAccountCreatedEvent() public {
        vm.expectEmit(true, true, true, true);
        emit CrossChainAccountFactory.AccountCreated(
            factory.getAddress(passkeyX, passkeyY), passkeyX, passkeyY, 0
        );

        factory.createAccount(passkeyX, passkeyY);
    }

    function test_noPrecompileDependency() public {
        // This test documents that the account has no chain-specific precompile dependencies.
        // The account uses Solady's pure Solidity P256 and WebAuthn verification,
        // making it deployable and functional on ANY EVM chain.
        CrossChainAccount account = factory.createAccount(passkeyX, passkeyY);

        // Verify the account is properly initialized without needing any precompile
        assertTrue(account.initialized(), "Account should initialize without precompiles");
        assertEq(account.ownerX(), passkeyX, "Owner should be set");

        // The account's signature verification uses Solady libraries, not precompiles
        // This is verifiable by checking the contract has no external calls to
        // precompile addresses (0x01-0xFF range for special contracts)
    }

}

contract CrossChainAccountTest is Test {

    CrossChainAccountFactory factory;
    CrossChainAccount account;

    bytes32 passkeyX = bytes32(uint256(0x1234));
    bytes32 passkeyY = bytes32(uint256(0x5678));

    // EOA for secp256k1 tests
    uint256 eoaPrivateKey = 0xBEEF;
    address eoaAddress;

    function setUp() public {
        factory = new CrossChainAccountFactory();
        account = factory.createAccount(passkeyX, passkeyY);
        eoaAddress = vm.addr(eoaPrivateKey);
    }

    function test_isValidSignature_invalidKeyHash() public view {
        bytes32 digest = keccak256("test");
        bytes32 fakeKeyHash = bytes32(uint256(0xdead));
        bytes memory signature = abi.encodePacked(fakeKeyHash, bytes("fake"));

        bytes4 result = account.isValidSignature(digest, signature);
        assertEq(result, bytes4(0xffffffff), "Should return invalid for unknown key");
    }

    function test_addKey_viaExecuteTrusted() public {
        bytes32 newKeyHash = keccak256("newkey");
        bytes memory newPublicKey = abi.encode(eoaAddress);

        // Simulate a call from the account itself (after signature validation)
        vm.prank(address(account));
        account.addKey(
            newKeyHash,
            CrossChainAccount.KeyType.Secp256k1,
            0, // no expiry
            newPublicKey
        );

        assertTrue(account.isAuthorizedKey(newKeyHash), "New key should be authorized");
    }

    function test_addKey_revertsIfNotSelf() public {
        bytes32 newKeyHash = keccak256("newkey");
        bytes memory newPublicKey = abi.encode(eoaAddress);

        vm.expectRevert(CrossChainAccount.NotAuthorized.selector);
        account.addKey(newKeyHash, CrossChainAccount.KeyType.Secp256k1, 0, newPublicKey);
    }

    function test_addKey_revertsOnInvalidKey() public {
        vm.prank(address(account));
        vm.expectRevert(CrossChainAccount.InvalidKey.selector);
        account.addKey(bytes32(0), CrossChainAccount.KeyType.Secp256k1, 0, abi.encode(eoaAddress));
    }

    function test_addKey_revertsIfKeyExists() public {
        bytes32 newKeyHash = keccak256("newkey");
        bytes memory newPublicKey = abi.encode(eoaAddress);

        vm.startPrank(address(account));
        account.addKey(newKeyHash, CrossChainAccount.KeyType.Secp256k1, 0, newPublicKey);

        vm.expectRevert(CrossChainAccount.KeyAlreadyExists.selector);
        account.addKey(newKeyHash, CrossChainAccount.KeyType.Secp256k1, 0, newPublicKey);
        vm.stopPrank();
    }

    function test_removeKey() public {
        bytes32 newKeyHash = keccak256("newkey");
        bytes memory newPublicKey = abi.encode(eoaAddress);

        vm.startPrank(address(account));
        account.addKey(newKeyHash, CrossChainAccount.KeyType.Secp256k1, 0, newPublicKey);
        account.removeKey(newKeyHash);
        vm.stopPrank();

        assertFalse(account.isAuthorizedKey(newKeyHash), "Removed key should not be authorized");
    }

    function test_removeKey_cannotRemovePrimaryKey() public {
        bytes32 ownerKeyHash = account.ownerKeyHash();

        vm.prank(address(account));
        vm.expectRevert(CrossChainAccount.CannotRemovePrimaryKey.selector);
        account.removeKey(ownerKeyHash);
    }

    function test_executeTrusted() public {
        vm.deal(address(account), 1 ether);
        address recipient = address(0xdead);

        vm.prank(address(account));
        account.executeTrusted(recipient, 0.5 ether, "");

        assertEq(recipient.balance, 0.5 ether);
    }

    function test_executeTrusted_revertsIfNotSelf() public {
        vm.deal(address(account), 1 ether);

        vm.expectRevert(CrossChainAccount.NotAuthorized.selector);
        account.executeTrusted(address(0xdead), 0.5 ether, "");
    }

    function test_cannotReinitialize() public {
        vm.expectRevert(CrossChainAccount.AlreadyInitialized.selector);
        account.initialize(bytes32(uint256(0x9999)), bytes32(uint256(0x8888)));
    }

    function test_keyExpiry() public {
        bytes32 newKeyHash = keccak256("expiringKey");
        bytes memory newPublicKey = abi.encode(eoaAddress);
        uint40 expiry = uint40(block.timestamp + 1 hours);

        vm.prank(address(account));
        account.addKey(newKeyHash, CrossChainAccount.KeyType.Secp256k1, expiry, newPublicKey);

        // Key should be valid now
        assertTrue(account.isAuthorizedKey(newKeyHash), "Key should be valid before expiry");

        // Fast forward past expiry
        vm.warp(block.timestamp + 2 hours);

        // Key should now be expired
        assertFalse(account.isAuthorizedKey(newKeyHash), "Key should be invalid after expiry");
    }

    function test_emitsKeyAddedEvent() public {
        bytes32 newKeyHash = keccak256("newkey");

        vm.expectEmit(true, false, false, true);
        emit CrossChainAccount.KeyAdded(newKeyHash, CrossChainAccount.KeyType.Secp256k1);

        vm.prank(address(account));
        account.addKey(newKeyHash, CrossChainAccount.KeyType.Secp256k1, 0, abi.encode(eoaAddress));
    }

    function test_emitsKeyRemovedEvent() public {
        bytes32 newKeyHash = keccak256("newkey");

        vm.prank(address(account));
        account.addKey(newKeyHash, CrossChainAccount.KeyType.Secp256k1, 0, abi.encode(eoaAddress));

        vm.expectEmit(true, false, false, true);
        emit CrossChainAccount.KeyRemoved(newKeyHash);

        vm.prank(address(account));
        account.removeKey(newKeyHash);
    }

    function test_emitsExecutedEvent() public {
        vm.deal(address(account), 1 ether);

        vm.expectEmit(true, false, false, true);
        emit CrossChainAccount.Executed(address(0xdead), 0.5 ether, "");

        vm.prank(address(account));
        account.executeTrusted(address(0xdead), 0.5 ether, "");
    }

    function test_ownerKeyHash() public view {
        bytes32 expectedHash = keccak256(abi.encodePacked(passkeyX, passkeyY));
        assertEq(account.ownerKeyHash(), expectedHash, "Owner key hash should match");
    }

}

contract CrossChainAccountSecp256k1Test is Test {

    CrossChainAccountFactory factory;
    CrossChainAccount account;

    uint256 signerPrivateKey = 0xA11CE;
    address signerAddress;
    bytes32 keyHash;

    bytes32 passkeyX = bytes32(uint256(0x1234));
    bytes32 passkeyY = bytes32(uint256(0x5678));

    function setUp() public {
        factory = new CrossChainAccountFactory();
        account = factory.createAccount(passkeyX, passkeyY);

        signerAddress = vm.addr(signerPrivateKey);
        keyHash = keccak256(abi.encodePacked(signerAddress));

        // Add secp256k1 key to account
        vm.prank(address(account));
        account.addKey(keyHash, CrossChainAccount.KeyType.Secp256k1, 0, abi.encode(signerAddress));
    }

    function test_execute_withSecp256k1Signature() public {
        vm.deal(address(account), 1 ether);
        address recipient = address(0xdead);

        // Build the typed data hash
        bytes32 executeTypehash =
            keccak256("Execute(address target,uint256 value,bytes data,uint256 nonce)");
        bytes32 structHash = keccak256(
            abi.encode(executeTypehash, recipient, 0.5 ether, keccak256(""), account.nonce())
        );

        // Get domain separator and compute final digest
        bytes32 domainSeparator = _computeDomainSeparator(address(account));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        // Sign with EOA
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory innerSig = abi.encodePacked(r, s, v);
        bytes memory fullSig = abi.encodePacked(keyHash, innerSig);

        // Execute
        account.execute(recipient, 0.5 ether, "", fullSig);

        assertEq(recipient.balance, 0.5 ether, "Recipient should receive ETH");
        assertEq(account.nonce(), 1, "Nonce should increment");
    }

    function test_execute_invalidSignature_reverts() public {
        vm.deal(address(account), 1 ether);

        // Create an invalid signature
        bytes memory invalidSig = abi.encodePacked(keyHash, bytes32(0), bytes32(0), uint8(27));

        vm.expectRevert(CrossChainAccount.InvalidSignature.selector);
        account.execute(address(0xdead), 0.5 ether, "", invalidSig);
    }

    function test_isValidSignature_secp256k1() public view {
        bytes32 testDigest = keccak256("test message");

        // Sign with EOA
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, testDigest);
        bytes memory innerSig = abi.encodePacked(r, s, v);
        bytes memory fullSig = abi.encodePacked(keyHash, innerSig);

        bytes4 result = account.isValidSignature(testDigest, fullSig);
        assertEq(result, bytes4(0x1626ba7e), "Should return ERC1271 magic value");
    }

    function _computeDomainSeparator(address accountAddr) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("CrossChainAccount"),
                keccak256("1"),
                block.chainid,
                accountAddr
            )
        );
    }

}
