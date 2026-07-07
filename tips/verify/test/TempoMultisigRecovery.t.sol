// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import {
    TempoMultisigRecoveryFactory,
    TempoMultisigRecoveryWallet
} from "../src/TempoMultisigRecovery.sol";
import { Test } from "forge-std/Test.sol";

contract TempoMultisigRecoveryTest is Test {

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
        TempoMultisigRecoveryWallet.InitMultisig memory init = _initConfig();
        bytes32 accountSalt = _deriveAccountSalt(init);
        TempoMultisigRecoveryWallet wallet =
            TempoMultisigRecoveryWallet(payable(factory.deploy(accountSalt)));
        TempoMultisigRecoveryWallet.Call[] memory calls = new TempoMultisigRecoveryWallet.Call[](0);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _sign(ownerAKey, wallet.recoveryDigest(accountSalt, calls));

        vm.expectRevert(TempoMultisigRecoveryWallet.InvalidThreshold.selector);
        wallet.recover(init, signatures, calls);
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
        TempoMultisigRecoveryWallet.InitMultisig memory init = _initConfig();
        bytes32 accountSalt = _deriveAccountSalt(init);
        TempoMultisigRecoveryWallet wallet =
            TempoMultisigRecoveryWallet(payable(factory.deploy(accountSalt)));

        // A non-transfer call (here ERC-20 approve) is rejected even with a valid quorum, so a
        // compromised owner set cannot use the cross-chain address for approvals, governance, or
        // bridging — only asset transfers.
        TempoMultisigRecoveryWallet.Call[] memory calls = new TempoMultisigRecoveryWallet.Call[](1);
        calls[0] = TempoMultisigRecoveryWallet.Call({
            target: address(0xDEAD),
            value: 0,
            data: abi.encodeWithSignature("approve(address,uint256)", address(0xBEEF), 1)
        });

        bytes[] memory signatures =
            _sortedSignatures(ownerAKey, ownerBKey, wallet.recoveryDigest(accountSalt, calls));

        vm.expectRevert(
            abi.encodeWithSelector(TempoMultisigRecoveryWallet.UnsupportedCall.selector, uint256(0))
        );
        wallet.recover(init, signatures, calls);
    }

    function testSweepsErc20ViaTransfer() public {
        TempoMultisigRecoveryWallet.InitMultisig memory init = _initConfig();
        bytes32 accountSalt = _deriveAccountSalt(init);
        address walletAddr = factory.deploy(accountSalt);
        TempoMultisigRecoveryWallet wallet = TempoMultisigRecoveryWallet(payable(walletAddr));

        MockERC20 token = new MockERC20();
        token.mint(walletAddr, 1000);
        address recipient = address(0xBEEF);

        TempoMultisigRecoveryWallet.Call[] memory calls = new TempoMultisigRecoveryWallet.Call[](1);
        calls[0] = TempoMultisigRecoveryWallet.Call({
            target: address(token),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", recipient, 1000)
        });

        bytes[] memory signatures =
            _sortedSignatures(ownerAKey, ownerBKey, wallet.recoveryDigest(accountSalt, calls));
        wallet.recover(init, signatures, calls);

        assertEq(token.balanceOf(recipient), 1000);
        assertEq(token.balanceOf(walletAddr), 0);
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
