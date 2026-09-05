// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import {
    TempoMultisigRecoveryFactory,
    TempoMultisigRecoveryWallet
} from "../src/TempoMultisigRecovery.sol";
import { Test } from "forge-std/Test.sol";

contract TempoMultisigRecoveryHarness is TempoMultisigRecoveryWallet {

    function validateConfigExternal(InitMultisig calldata init) external view {
        validateConfig(init);
    }

}

contract TempoMultisigRecoveryTest is Test {

    struct RecoveryFixture {
        TempoMultisigRecoveryWallet.InitMultisig init;
        bytes32 accountSalt;
        TempoMultisigRecoveryWallet wallet;
    }

    TempoMultisigRecoveryFactory factory;

    uint256 ownerAKey = 0xA11CE;
    uint256 ownerBKey = 0xB0B;
    uint256 ownerCKey = 0xCA11;

    function setUp() public {
        factory = new TempoMultisigRecoveryFactory();
    }

    function testDeploysAtCreate2AddressAndSweepsPrefundedEth() public {
        TempoMultisigRecoveryWallet.InitMultisig memory init = _initConfig();
        bytes32 accountSalt = _deriveAccountSalt(init);
        address predicted = factory.walletAddress(accountSalt);
        address recipient = address(0xBEEF);

        vm.deal(predicted, 1 ether);
        assertEq(predicted.balance, 1 ether);

        address deployed = factory.deploy(accountSalt);
        assertEq(deployed, predicted);

        TempoMultisigRecoveryWallet wallet = TempoMultisigRecoveryWallet(payable(deployed));
        TempoMultisigRecoveryWallet.Call[] memory calls = new TempoMultisigRecoveryWallet.Call[](1);
        calls[0] = TempoMultisigRecoveryWallet.Call({ target: recipient, value: 1 ether, data: "" });

        bytes32 digest = wallet.recoveryDigest(accountSalt, calls);
        bytes[] memory signatures = _sortedSignatures(ownerAKey, ownerBKey, digest);

        wallet.recover(init, signatures, calls);

        assertEq(recipient.balance, 1 ether);
        assertEq(predicted.balance, 0);
        assertEq(wallet.nonce(), 1);
    }

    function testRejectsBelowThresholdRecovery() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();
        TempoMultisigRecoveryWallet.Call[] memory calls = new TempoMultisigRecoveryWallet.Call[](0);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _sign(ownerAKey, fixture.wallet.recoveryDigest(fixture.accountSalt, calls));

        vm.expectRevert(TempoMultisigRecoveryWallet.InvalidThreshold.selector);
        fixture.wallet.recover(fixture.init, signatures, calls);
    }

    function testRejectsRawRecoveryIds() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();
        TempoMultisigRecoveryWallet.Call[] memory calls = new TempoMultisigRecoveryWallet.Call[](0);
        bytes32 digest = fixture.wallet.recoveryDigest(fixture.accountSalt, calls);

        for (uint8 v = 0; v < 2; ++v) {
            bytes[] memory signatures = _sortedSignatures(ownerAKey, ownerBKey, digest);
            signatures[0][64] = bytes1(v);
            vm.expectRevert(TempoMultisigRecoveryWallet.InvalidSignature.selector);
            fixture.wallet.recover(fixture.init, signatures, calls);
        }
    }

    function testRejectsWalletAsOwner() public {
        TempoMultisigRecoveryHarness harness = new TempoMultisigRecoveryHarness();
        TempoMultisigRecoveryWallet.InitMultisig memory init;
        init.threshold = 1;
        init.owners = new TempoMultisigRecoveryWallet.Owner[](1);
        init.owners[0] = TempoMultisigRecoveryWallet.Owner({ owner: address(harness), weight: 1 });

        vm.expectRevert(TempoMultisigRecoveryWallet.InvalidOwner.selector);
        harness.validateConfigExternal(init);
    }

    function testRejectsSignatureAfterQuorum() public {
        TempoMultisigRecoveryWallet.InitMultisig memory init = _initConfig();
        init.threshold = 1;
        bytes32 accountSalt = _deriveAccountSalt(init);
        TempoMultisigRecoveryWallet wallet =
            TempoMultisigRecoveryWallet(payable(factory.deploy(accountSalt)));
        TempoMultisigRecoveryWallet.Call[] memory calls = new TempoMultisigRecoveryWallet.Call[](0);

        bytes[] memory signatures =
            _sortedSignatures(ownerAKey, ownerBKey, wallet.recoveryDigest(accountSalt, calls));

        vm.expectRevert(TempoMultisigRecoveryWallet.InvalidSignature.selector);
        wallet.recover(init, signatures, calls);
    }

    function testRejectsZeroValueEmptyCalldataCall() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();
        (TempoMultisigRecoveryWallet.Call[] memory calls, bytes[] memory signatures) =
            _signedSingleCall(fixture, address(0xBEEF), 0, "");

        vm.expectRevert(
            abi.encodeWithSelector(TempoMultisigRecoveryWallet.UnsupportedCall.selector, uint256(0))
        );
        fixture.wallet.recover(fixture.init, signatures, calls);
    }

    function testRejectsInitializationByNonFactory() public {
        TempoMultisigRecoveryWallet wallet = new TempoMultisigRecoveryWallet();

        vm.prank(address(0xBAD));
        vm.expectRevert(TempoMultisigRecoveryWallet.UnauthorizedFactory.selector);
        wallet.initialize(bytes32("salt"));
    }

    function testRejectsRecoveryWithMismatchedConfig() public {
        // Deploy the legitimate wallet (bound to `victim`'s config) and fund it.
        TempoMultisigRecoveryWallet.InitMultisig memory victim = _initConfig();
        bytes32 victimSalt = _deriveAccountSalt(victim);
        address walletAddr = factory.deploy(victimSalt);
        vm.deal(walletAddr, 1 ether);
        TempoMultisigRecoveryWallet wallet = TempoMultisigRecoveryWallet(payable(walletAddr));

        // Attacker supplies their own single-owner config and signs the wallet's real digest.
        uint256 attackerKey = 0xBAD;
        TempoMultisigRecoveryWallet.InitMultisig memory attacker;
        attacker.salt = bytes32("attacker");
        attacker.threshold = 1;
        attacker.owners = new TempoMultisigRecoveryWallet.Owner[](1);
        attacker.owners[0] =
            TempoMultisigRecoveryWallet.Owner({ owner: vm.addr(attackerKey), weight: 1 });

        TempoMultisigRecoveryWallet.Call[] memory calls = new TempoMultisigRecoveryWallet.Call[](1);
        calls[0] =
            TempoMultisigRecoveryWallet.Call({ target: address(0xBEEF), value: 1 ether, data: "" });

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _sign(attackerKey, wallet.recoveryDigest(wallet.accountSalt(), calls));

        // The config does not re-derive this wallet's deployment salt, so recovery is rejected and
        // the funds are untouched.
        vm.expectRevert(TempoMultisigRecoveryWallet.InvalidConfig.selector);
        wallet.recover(attacker, signatures, calls);
        assertEq(walletAddr.balance, 1 ether);
    }

    function testRejectsNonTransferCall() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();

        // A non-transfer call (here ERC-20 approve) is rejected even with a valid quorum, so a
        // compromised owner set cannot use the cross-chain address for approvals, governance, or
        // bridging — only asset transfers.
        (TempoMultisigRecoveryWallet.Call[] memory calls, bytes[] memory signatures) = _signedSingleCall(
            fixture,
            address(0xDEAD),
            0,
            abi.encodeWithSignature("approve(address,uint256)", address(0xBEEF), 1)
        );

        vm.expectRevert(
            abi.encodeWithSelector(TempoMultisigRecoveryWallet.UnsupportedCall.selector, uint256(0))
        );
        fixture.wallet.recover(fixture.init, signatures, calls);
    }

    function testSweepsErc20ViaTransfer() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();
        address walletAddr = address(fixture.wallet);

        MockERC20 token = new MockERC20();
        token.mint(walletAddr, 1000);
        address recipient = address(0xBEEF);

        (TempoMultisigRecoveryWallet.Call[] memory calls, bytes[] memory signatures) = _signedSingleCall(
            fixture,
            address(token),
            0,
            abi.encodeWithSignature("transfer(address,uint256)", recipient, 1000)
        );
        fixture.wallet.recover(fixture.init, signatures, calls);

        assertEq(token.balanceOf(recipient), 1000);
        assertEq(token.balanceOf(walletAddr), 0);
    }

    function testSweepsErc20WithNoReturnData() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();
        address walletAddr = address(fixture.wallet);
        MockNoReturnERC20 token = new MockNoReturnERC20();
        token.mint(walletAddr, 1000);
        address recipient = address(0xBEEF);

        (TempoMultisigRecoveryWallet.Call[] memory calls, bytes[] memory signatures) = _signedSingleCall(
            fixture,
            address(token),
            0,
            abi.encodeWithSignature("transfer(address,uint256)", recipient, 1000)
        );
        fixture.wallet.recover(fixture.init, signatures, calls);

        assertEq(token.balanceOf(recipient), 1000);
        assertEq(token.balanceOf(walletAddr), 0);
    }

    function testRejectsErc20TransferToNonContract() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();
        (TempoMultisigRecoveryWallet.Call[] memory calls, bytes[] memory signatures) = _signedSingleCall(
            fixture,
            address(0xDEAD),
            0,
            abi.encodeWithSignature("transfer(address,uint256)", address(0xBEEF), 1)
        );

        vm.expectRevert(
            abi.encodeWithSelector(TempoMultisigRecoveryWallet.UnsupportedCall.selector, uint256(0))
        );
        fixture.wallet.recover(fixture.init, signatures, calls);
    }

    function testAcceptsSafeNftMintsAndReportsReceiverInterfaces() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();
        address walletAddr = address(fixture.wallet);
        MockERC721 nft = new MockERC721();
        MockERC1155 multiToken = new MockERC1155();

        nft.safeMint(walletAddr, 1);
        multiToken.safeMint(walletAddr, 2, 3, "");

        assertEq(nft.ownerOf(1), walletAddr);
        assertEq(multiToken.balanceOf(2, walletAddr), 3);
        assertTrue(fixture.wallet.supportsInterface(0x01ffc9a7));
        assertTrue(fixture.wallet.supportsInterface(0x150b7a02));
        assertTrue(fixture.wallet.supportsInterface(0x4e2312e0));
        assertFalse(fixture.wallet.supportsInterface(0xffffffff));
    }

    function testRejectsRecoveryTransferFromThirdParty() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();
        address walletAddr = address(fixture.wallet);
        MockERC721 nft = new MockERC721();
        address victim = address(0xCAFE);
        nft.mint(victim, 1);
        vm.prank(victim);
        nft.approve(walletAddr, 1);

        (TempoMultisigRecoveryWallet.Call[] memory calls, bytes[] memory signatures) = _signedSingleCall(
            fixture,
            address(nft),
            0,
            abi.encodeWithSignature(
                "transferFrom(address,address,uint256)", victim, address(0xBEEF), 1
            )
        );

        vm.expectRevert(
            abi.encodeWithSelector(TempoMultisigRecoveryWallet.UnsupportedCall.selector, uint256(0))
        );
        fixture.wallet.recover(fixture.init, signatures, calls);
        assertEq(nft.ownerOf(1), victim);
    }

    function testRejectsThirdPartyFromForEverySafeNftSelector() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();
        MockERC721 target = new MockERC721();
        address victim = address(0xCAFE);
        address recipient = address(0xBEEF);

        _assertUnsupported(
            fixture,
            address(target),
            abi.encodeWithSignature(
                "safeTransferFrom(address,address,uint256)", victim, recipient, 1
            )
        );
        _assertUnsupported(
            fixture,
            address(target),
            abi.encodeWithSignature(
                "safeTransferFrom(address,address,uint256,bytes)", victim, recipient, 1, bytes("x")
            )
        );
        _assertUnsupported(
            fixture,
            address(target),
            abi.encodeWithSignature(
                "safeTransferFrom(address,address,uint256,uint256,bytes)",
                victim,
                recipient,
                1,
                2,
                bytes("x")
            )
        );
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 2;
        _assertUnsupported(
            fixture,
            address(target),
            abi.encodeWithSignature(
                "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
                victim,
                recipient,
                ids,
                amounts,
                bytes("x")
            )
        );
    }

    function testSweepsOwnedErc721ViaTransferFrom() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();
        address walletAddr = address(fixture.wallet);
        MockERC721 nft = new MockERC721();
        nft.mint(walletAddr, 1);

        (TempoMultisigRecoveryWallet.Call[] memory calls, bytes[] memory signatures) = _signedSingleCall(
            fixture,
            address(nft),
            0,
            abi.encodeWithSignature(
                "transferFrom(address,address,uint256)", walletAddr, address(0xBEEF), 1
            )
        );

        fixture.wallet.recover(fixture.init, signatures, calls);
        assertEq(nft.ownerOf(1), address(0xBEEF));
    }

    function testRejectsMalformedNftTransfer() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();
        address walletAddr = address(fixture.wallet);
        MockERC721 nft = new MockERC721();

        (TempoMultisigRecoveryWallet.Call[] memory calls, bytes[] memory signatures) = _signedSingleCall(
            fixture,
            address(nft),
            0,
            abi.encodePacked(bytes4(0x23b872dd), bytes32(uint256(uint160(walletAddr))))
        );

        vm.expectRevert();
        fixture.wallet.recover(fixture.init, signatures, calls);
    }

    function testRejectsFalseTokenReturn() public {
        RecoveryFixture memory fixture = _deployDefaultWallet();
        address walletAddr = address(fixture.wallet);
        MockFalseERC20 token = new MockFalseERC20();

        bytes[] memory payloads = new bytes[](2);
        payloads[0] = abi.encodeWithSignature("transfer(address,uint256)", address(0xBEEF), 1);
        payloads[1] = abi.encodeWithSignature(
            "transferFrom(address,address,uint256)", walletAddr, address(0xBEEF), 1
        );

        for (uint256 i = 0; i < payloads.length; ++i) {
            TempoMultisigRecoveryWallet.Call[] memory calls =
                _singleCall(address(token), 0, payloads[i]);
            bytes[] memory signatures = _quorumSignatures(fixture, calls);

            vm.expectRevert(
                abi.encodeWithSelector(
                    TempoMultisigRecoveryWallet.CallFailed.selector, uint256(0), abi.encode(false)
                )
            );
            fixture.wallet.recover(fixture.init, signatures, calls);
        }
    }

    function _initConfig()
        internal
        view
        returns (TempoMultisigRecoveryWallet.InitMultisig memory init)
    {
        init.salt = bytes32("native-multisig");
        init.threshold = 2;
        init.owners = new TempoMultisigRecoveryWallet.Owner[](3);
        init.owners[0] = TempoMultisigRecoveryWallet.Owner({ owner: vm.addr(ownerAKey), weight: 1 });
        init.owners[1] = TempoMultisigRecoveryWallet.Owner({ owner: vm.addr(ownerBKey), weight: 1 });
        init.owners[2] = TempoMultisigRecoveryWallet.Owner({ owner: vm.addr(ownerCKey), weight: 1 });

        for (uint256 i = 0; i < init.owners.length; ++i) {
            for (uint256 j = i + 1; j < init.owners.length; ++j) {
                if (init.owners[j].owner < init.owners[i].owner) {
                    TempoMultisigRecoveryWallet.Owner memory owner = init.owners[i];
                    init.owners[i] = init.owners[j];
                    init.owners[j] = owner;
                }
            }
        }

        for (uint256 i = 1; i < init.owners.length; ++i) {
            assertLt(uint160(init.owners[i - 1].owner), uint160(init.owners[i].owner));
        }
    }

    function _deriveAccountSalt(TempoMultisigRecoveryWallet.InitMultisig memory init)
        internal
        pure
        returns (bytes32)
    {
        bytes memory input = abi.encodePacked(
            "tempo:multisig:account", init.salt, init.threshold, uint8(init.owners.length)
        );
        for (uint256 i = 0; i < init.owners.length; ++i) {
            input = abi.encodePacked(input, init.owners[i].owner, init.owners[i].weight);
        }
        return keccak256(input);
    }

    function _deployDefaultWallet() internal returns (RecoveryFixture memory fixture) {
        fixture.init = _initConfig();
        fixture.accountSalt = _deriveAccountSalt(fixture.init);
        fixture.wallet = TempoMultisigRecoveryWallet(payable(factory.deploy(fixture.accountSalt)));
    }

    function _singleCall(
        address target,
        uint256 value,
        bytes memory data
    )
        internal
        pure
        returns (TempoMultisigRecoveryWallet.Call[] memory calls)
    {
        calls = new TempoMultisigRecoveryWallet.Call[](1);
        calls[0] = TempoMultisigRecoveryWallet.Call({ target: target, value: value, data: data });
    }

    function _quorumSignatures(
        RecoveryFixture memory fixture,
        TempoMultisigRecoveryWallet.Call[] memory calls
    )
        internal
        view
        returns (bytes[] memory)
    {
        return _sortedSignatures(
            ownerAKey, ownerBKey, fixture.wallet.recoveryDigest(fixture.accountSalt, calls)
        );
    }

    function _signedSingleCall(
        RecoveryFixture memory fixture,
        address target,
        uint256 value,
        bytes memory data
    )
        internal
        view
        returns (TempoMultisigRecoveryWallet.Call[] memory calls, bytes[] memory signatures)
    {
        calls = _singleCall(target, value, data);
        signatures = _quorumSignatures(fixture, calls);
    }

    function _assertUnsupported(
        RecoveryFixture memory fixture,
        address target,
        bytes memory data
    )
        internal
    {
        TempoMultisigRecoveryWallet.Call[] memory calls = _singleCall(target, 0, data);
        bytes[] memory signatures = _quorumSignatures(fixture, calls);
        vm.expectRevert(
            abi.encodeWithSelector(TempoMultisigRecoveryWallet.UnsupportedCall.selector, uint256(0))
        );
        fixture.wallet.recover(fixture.init, signatures, calls);
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sortedSignatures(
        uint256 leftKey,
        uint256 rightKey,
        bytes32 digest
    )
        internal
        pure
        returns (bytes[] memory signatures)
    {
        signatures = new bytes[](2);
        if (vm.addr(leftKey) < vm.addr(rightKey)) {
            signatures[0] = _sign(leftKey, digest);
            signatures[1] = _sign(rightKey, digest);
        } else {
            signatures[0] = _sign(rightKey, digest);
            signatures[1] = _sign(leftKey, digest);
        }
    }

}

contract MockERC20 {

    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

}

contract MockFalseERC20 {

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false;
    }

}

contract MockNoReturnERC20 {

    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

}

contract MockERC721 {

    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => address) public getApproved;

    function mint(address to, uint256 tokenId) external {
        ownerOf[tokenId] = to;
    }

    function safeMint(address to, uint256 tokenId) external {
        ownerOf[tokenId] = to;
        if (to.code.length != 0) {
            bytes4 result = TempoMultisigRecoveryWallet(payable(to))
                .onERC721Received(msg.sender, address(0), tokenId, "");
            require(result == TempoMultisigRecoveryWallet.onERC721Received.selector);
        }
    }

    function approve(address spender, uint256 tokenId) external {
        require(ownerOf[tokenId] == msg.sender);
        getApproved[tokenId] = spender;
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == from);
        require(msg.sender == from || getApproved[tokenId] == msg.sender);
        ownerOf[tokenId] = to;
        delete getApproved[tokenId];
    }

}

contract MockERC1155 {

    mapping(uint256 => mapping(address => uint256)) public balanceOf;

    function safeMint(address to, uint256 id, uint256 amount, bytes calldata data) external {
        balanceOf[id][to] += amount;
        if (to.code.length != 0) {
            bytes4 result = TempoMultisigRecoveryWallet(payable(to))
                .onERC1155Received(msg.sender, address(0), id, amount, data);
            require(result == TempoMultisigRecoveryWallet.onERC1155Received.selector);
        }
    }

}
