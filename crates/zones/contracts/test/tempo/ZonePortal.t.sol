// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { StdPrecompiles } from "tempo-std/StdPrecompiles.sol";
import { ISignatureVerifier } from "tempo-std/interfaces/ISignatureVerifier.sol";
import { ITIP20 } from "tempo-std/interfaces/ITIP20.sol";
import { ITIP403Registry } from "tempo-std/interfaces/ITIP403Registry.sol";

import {
    BlockTransition,
    Capability,
    Deposit,
    DepositPayload,
    DepositQueueTransition,
    DepositType,
    ENCRYPTION_KEY_GRACE_PERIOD,
    EncryptionKeyEntry,
    IVerifier,
    IWithdrawalReceiver,
    IZoneMessenger,
    IZonePortal,
    PORTAL_ENABLED_TOKENS_SLOT,
    PORTAL_ENCRYPTION_KEYS_SLOT,
    PORTAL_LEADER_ACTIVATION_TEMPO_BLOCK_SLOT,
    PORTAL_LEADER_SLOT,
    PORTAL_ROLE_SLOT,
    Role,
    TokenEnablementTransition,
    Withdrawal,
    WithdrawalBounceBackDeposit,
    ZONE_FACTORY_ADDRESS,
    ZONE_MESSENGER_ADDRESS,
    ZONE_PORTAL_IMPL_ADDRESS,
    ZONE_VERIFIER_ADDRESS
} from "../../src/runtime/interfaces/IZone.sol";
import { getBlockHash } from "../../src/runtime/libraries/BlockHashHistory.sol";
import { DepositQueueLib } from "../../src/runtime/libraries/DepositQueueLib.sol";
import {
    NO_QUEUE_INDEX,
    WithdrawalQueueLib
} from "../../src/runtime/libraries/WithdrawalQueueLib.sol";
import { ZoneMessenger } from "../../src/runtime/tempo/ZoneMessenger.sol";
import { ZonePortal } from "../../src/runtime/tempo/ZonePortal.sol";
import { BaseTest } from "../BaseTest.t.sol";
import { PortalRuntimeTest } from "../PortalRuntimeTest.sol";
import { MockRevertingReceiver } from "../mocks/MockCallbackReceivers.sol";
import { GatewayCallbackData, GatewayFlow, MockZoneGateway } from "../mocks/MockZoneGateway.sol";
import { Vm } from "forge-std/Vm.sol";

/// @notice Mock withdrawal receiver that accepts funds
contract MockWithdrawalReceiver is IWithdrawalReceiver {

    bool public shouldAccept = true;
    bool public shouldRevert = false;

    bytes32 public lastSenderTag;
    uint32 public lastZoneId;
    address public lastSourcePortal;
    address public lastToken;
    uint128 public lastAmount;
    bytes public lastCallbackData;
    address public expectedMessenger;

    function setExpectedMessenger(address _messenger) external {
        expectedMessenger = _messenger;
    }

    function setShouldAccept(bool _shouldAccept) external {
        shouldAccept = _shouldAccept;
    }

    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

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
        lastCallbackData = callbackData;

        if (expectedMessenger != address(0) && msg.sender != expectedMessenger) {
            revert("MockWithdrawalReceiver: unexpected messenger");
        }

        if (shouldRevert) {
            revert("MockWithdrawalReceiver: intentional revert");
        }

        if (shouldAccept) {
            return IWithdrawalReceiver.onWithdrawalReceived.selector;
        } else {
            return bytes4(0xdeadbeef); // Wrong selector
        }
    }

}

/// @notice Mock receiver that consumes all gas
contract GasConsumingReceiver is IWithdrawalReceiver {

    function onWithdrawalReceived(
        uint32,
        address,
        bytes32,
        address,
        uint128,
        bytes calldata
    )
        external
        returns (bytes4)
    {
        // Infinite loop to consume all gas
        while (true) { }
        return IWithdrawalReceiver.onWithdrawalReceived.selector;
    }

}

/// @notice Mock receiver that succeeds normally
contract SuccessfulReceiver is IWithdrawalReceiver {

    uint256 public callCount;

    function onWithdrawalReceived(
        uint32,
        address,
        bytes32,
        address,
        uint128,
        bytes calldata
    )
        external
        returns (bytes4)
    {
        callCount++;
        return IWithdrawalReceiver.onWithdrawalReceived.selector;
    }

}

/// @notice Sequencer-controlled receiver that attempts to process another withdrawal in callback.
contract ReentrantWithdrawalReceiver is IWithdrawalReceiver {

    bytes4 public nestedRevertSelector;
    bool public nestedCallSucceeded;

    function onWithdrawalReceived(
        uint32,
        address sourcePortal,
        bytes32,
        address,
        uint128,
        bytes calldata callbackData
    )
        external
        returns (bytes4)
    {
        (Withdrawal memory withdrawal, bytes32 remainingQueue) =
            abi.decode(callbackData, (Withdrawal, bytes32));
        Withdrawal[] memory withdrawals = new Withdrawal[](1);
        withdrawals[0] = withdrawal;

        try IZonePortal(sourcePortal).processWithdrawals(withdrawals, remainingQueue) {
            nestedCallSucceeded = true;
        } catch (bytes memory reason) {
            if (reason.length >= 4) {
                bytes4 selector;
                assembly ("memory-safe") {
                    selector := mload(add(reason, 0x20))
                }
                nestedRevertSelector = selector;
            }
        }

        return IWithdrawalReceiver.onWithdrawalReceived.selector;
    }

}

/// @dev Keeps the twelve-argument portal initializer encoder out of the already-large proxy test.
contract ZonePortalInitializationForwarder {

    function initialize(
        address target,
        uint32 id,
        address initialToken,
        address portalMessenger,
        address portalAdmin,
        address sequencer,
        address portalVerifier
    )
        external
    {
        address[] memory accounts = new address[](1);
        accounts[0] = portalAdmin;
        address[] memory gateways = new address[](1);
        gateways[0] = portalMessenger;
        address[] memory sequencers = new address[](1);
        sequencers[0] = sequencer;

        ZonePortal(target)
            .initialize(
                id,
                initialToken,
                true,
                true,
                accounts,
                gateways,
                portalMessenger,
                portalAdmin,
                sequencers,
                1,
                portalVerifier,
                ""
            );
    }

}

contract ZonePortalProxyStorageTest is PortalRuntimeTest {

    function _emptyAddresses() internal pure returns (address[] memory values) {
        values = new address[](0);
    }

    function test_initialize_revertsOnImplementationAddress() public {
        _installPortalRuntime();

        address[] memory sequencers = new address[](1);
        sequencers[0] = makeAddr("sequencer");

        vm.prank(ZONE_FACTORY_ADDRESS);
        vm.expectRevert(IZonePortal.MustDelegateCall.selector);
        ZonePortal(ZONE_PORTAL_IMPL_ADDRESS)
            .initialize(
                1,
                makeAddr("initial token"),
                true,
                true,
                _emptyAddresses(),
                _emptyAddresses(),
                ZONE_MESSENGER_ADDRESS,
                makeAddr("admin"),
                sequencers,
                1,
                ZONE_VERIFIER_ADDRESS,
                ""
            );
    }

    function test_initialize_rejectsMessengerAsAllowedAccount() public {
        address proxy = address(_newPortalProxy(1));

        address portalMessenger = makeAddr("messenger");
        address[] memory allowedAccounts = new address[](1);
        allowedAccounts[0] = portalMessenger;
        address[] memory sequencers = new address[](1);
        sequencers[0] = makeAddr("sequencer");

        vm.prank(ZONE_FACTORY_ADDRESS);
        vm.expectRevert();
        ZonePortal(proxy)
            .initialize(
                1,
                makeAddr("initial token"),
                true,
                true,
                allowedAccounts,
                _emptyAddresses(),
                portalMessenger,
                makeAddr("admin"),
                sequencers,
                1,
                makeAddr("verifier"),
                ""
            );
    }

    function test_proxyMetadataIsReadFromPortalStorage() public {
        address initialToken = makeAddr("initial token");
        address[] memory tokens = new address[](1);
        tokens[0] = initialToken;
        vm.mockCallRevert(
            StdPrecompiles.TIP403_REGISTRY_ADDRESS,
            abi.encodeCall(ITIP403Registry.migrateTransferPolicyIds, (tokens)),
            abi.encodeWithSignature("UnexpectedMigration()")
        );
        vm.mockCall(
            StdPrecompiles.TIP403_REGISTRY_ADDRESS,
            abi.encodeCall(ITIP403Registry.tokenTransferPolicyId, (initialToken)),
            abi.encode(true, uint64(1))
        );
        vm.mockCall(
            initialToken, abi.encodeWithSelector(ITIP20.name.selector), abi.encode("Initial Token")
        );
        vm.mockCall(
            initialToken, abi.encodeWithSelector(ITIP20.symbol.selector), abi.encode("INITIAL")
        );
        vm.mockCall(
            initialToken, abi.encodeWithSelector(ITIP20.currency.selector), abi.encode("USD")
        );
        address proxyA = address(_newPortalProxy(1));
        address proxyB = address(_newPortalProxy(2));
        ZonePortalInitializationForwarder forwarder = new ZonePortalInitializationForwarder();
        vm.etch(ZONE_FACTORY_ADDRESS, address(forwarder).code);

        address messengerA = makeAddr("messenger A");
        address messengerB = makeAddr("messenger B");
        address verifierA = makeAddr("verifier A");
        address verifierB = makeAddr("verifier B");
        _expectNotFactoryRevert(proxyA, initialToken, messengerA, verifierA);

        vm.startPrank(ZONE_FACTORY_ADDRESS);
        _expectInitializationEvents(proxyA, messengerA);
        _initializePortal(proxyA, initialToken, 1, messengerA, verifierA);
        _initializePortal(proxyB, initialToken, 2, messengerB, verifierB);

        vm.expectRevert(IZonePortal.AlreadyInitialized.selector);
        _initializePortal(proxyA, initialToken, 1, messengerA, verifierA);
        vm.stopPrank();

        assertEq(ZonePortal(proxyA).zoneId(), 1);
        assertEq(ZonePortal(proxyA).messenger(), messengerA);
        assertEq(ZonePortal(proxyA).verifier(), verifierA);
        assertEq(ZonePortal(proxyA).blockHash(), bytes32(0));
        assertEq(
            ZonePortal(proxyA).tokenEnablementHash(),
            keccak256(abi.encode(bytes32(0), initialToken, "Initial Token", "INITIAL", "USD"))
        );
        _assertTip1091Storage(proxyA, ZonePortal(proxyA).sequencerAt(0));

        assertEq(ZonePortal(proxyB).zoneId(), 2);
        assertEq(ZonePortal(proxyB).messenger(), messengerB);
        assertEq(ZonePortal(proxyB).verifier(), verifierB);
        assertEq(ZonePortal(proxyB).blockHash(), bytes32(0));
    }

    function _expectNotFactoryRevert(
        address proxy,
        address initialToken,
        address portalMessenger,
        address portalVerifier
    )
        internal
    {
        address[] memory sequencers = new address[](1);
        sequencers[0] = makeAddr("sequencer A");
        address[] memory noAccounts = new address[](0);
        address[] memory noGateways = new address[](0);
        address portalAdmin = makeAddr("admin A");
        vm.prank(makeAddr("not factory"));
        vm.expectRevert(IZonePortal.NotFactory.selector);
        ZonePortal(proxy)
            .initialize(
                1,
                initialToken,
                true,
                true,
                noAccounts,
                noGateways,
                portalMessenger,
                portalAdmin,
                sequencers,
                1,
                portalVerifier,
                ""
            );
    }

    function _expectInitializationEvents(address proxy, address portalMessenger) internal {
        address[] memory sequencers = new address[](1);
        sequencers[0] = makeAddr("sequencer 1");
        vm.expectEmit(false, false, false, true, proxy);
        emit IZonePortal.EnforcementModesUpdated(true, true);
        vm.expectEmit(true, false, false, true, proxy);
        emit IZonePortal.SequencerSetUpdated(0, 1, sequencers);
        vm.expectEmit(true, true, true, true, proxy);
        emit IZonePortal.LeaderUpdated(address(0), makeAddr("sequencer 1"), 1, uint64(block.number));
        vm.expectEmit(true, false, false, true, proxy);
        emit IZonePortal.RoleUpdated(portalMessenger, Role.None, Role.CallbackGateway);
        vm.expectEmit(true, false, false, true, proxy);
        emit IZonePortal.RoleUpdated(makeAddr("admin 1"), Role.None, Role.Account);
    }

    function test_initializeRevertsIfTokenPolicyBindingIsNotSet() public {
        address initialToken = makeAddr("unmigrated initial token");
        address[] memory tokens = new address[](1);
        tokens[0] = initialToken;
        vm.mockCall(
            initialToken, abi.encodeWithSelector(ITIP20.name.selector), abi.encode("Initial Token")
        );
        vm.mockCall(
            initialToken, abi.encodeWithSelector(ITIP20.symbol.selector), abi.encode("INITIAL")
        );
        vm.mockCall(
            initialToken, abi.encodeWithSelector(ITIP20.currency.selector), abi.encode("USD")
        );
        vm.mockCall(
            StdPrecompiles.TIP403_REGISTRY_ADDRESS,
            abi.encodeCall(ITIP403Registry.migrateTransferPolicyIds, (tokens)),
            abi.encode(0)
        );
        vm.mockCall(
            StdPrecompiles.TIP403_REGISTRY_ADDRESS,
            abi.encodeCall(ITIP403Registry.tokenTransferPolicyId, (initialToken)),
            abi.encode(false, uint64(1))
        );
        vm.expectCall(
            StdPrecompiles.TIP403_REGISTRY_ADDRESS,
            abi.encodeCall(ITIP403Registry.migrateTransferPolicyIds, (tokens))
        );
        vm.expectCall(
            StdPrecompiles.TIP403_REGISTRY_ADDRESS,
            abi.encodeCall(ITIP403Registry.tokenTransferPolicyId, (initialToken)),
            2
        );

        ZonePortal portal = _newPortalProxy(1);
        address[] memory sequencers = new address[](1);
        sequencers[0] = makeAddr("sequencer");
        vm.prank(ZONE_FACTORY_ADDRESS);
        vm.expectRevert(IZonePortal.TokenTransferPolicyNotSet.selector);
        address[] memory noAccounts = new address[](0);
        address[] memory noGateways = new address[](0);
        portal.initialize(
            1,
            initialToken,
            true,
            true,
            noAccounts,
            noGateways,
            makeAddr("messenger"),
            makeAddr("admin"),
            sequencers,
            1,
            makeAddr("verifier"),
            ""
        );
    }

    function _initializePortal(
        address target,
        address initialToken,
        uint32 id,
        address portalMessenger,
        address portalVerifier
    )
        internal
    {
        ZonePortalInitializationForwarder(ZONE_FACTORY_ADDRESS)
            .initialize(
                target,
                id,
                initialToken,
                portalMessenger,
                makeAddr(string.concat("admin ", vm.toString(id))),
                makeAddr(string.concat("sequencer ", vm.toString(id))),
                portalVerifier
            );
    }

    function _proxyAccounts(uint32 id) internal returns (address[] memory accounts) {
        accounts = new address[](1);
        accounts[0] = makeAddr(string.concat("admin ", vm.toString(id)));
    }

    function _proxyGateways(address gateway) internal pure returns (address[] memory gateways) {
        gateways = new address[](1);
        gateways[0] = gateway;
    }

    function _assertTip1091Storage(address target, address initialSequencer) internal view {
        bytes32 slot16 = vm.load(target, bytes32(uint256(16)));
        assertEq(uint8(uint256(slot16) >> 160), 1, "slot 16: initialized mismatch");
        assertEq(uint64(uint256(slot16) >> 168), 0, "slot 16: nonce mismatch");
        assertEq(uint8(uint256(slot16) >> 232), 1, "slot 16: threshold mismatch");
        assertEq(uint256(vm.load(target, bytes32(uint256(17)))), 0, "slot 17: height mismatch");
        assertEq(uint256(vm.load(target, bytes32(uint256(18)))), 1, "slot 18: length mismatch");

        bytes32 sequencerDataSlot = keccak256(abi.encode(uint256(18)));
        assertEq(
            address(uint160(uint256(vm.load(target, sequencerDataSlot)))),
            initialSequencer,
            "slot 18: sequencer mismatch"
        );
        assertEq(uint256(vm.load(target, bytes32(uint256(19)))), 0, "slot 19: reserved");
        bytes32 membershipSlot = keccak256(abi.encode(initialSequencer, PORTAL_ROLE_SLOT));
        assertEq(
            uint256(vm.load(target, membershipSlot)),
            uint8(Role.Sequencer),
            "slot 20: membership mismatch"
        );

        bytes32 slot23 = vm.load(target, bytes32(uint256(23)));
        assertEq(address(uint160(uint256(slot23))), initialSequencer, "slot 23: leader mismatch");
        assertEq(uint64(uint256(slot23) >> 160), 1, "slot 23: leaderEpoch mismatch");
        assertEq(
            uint64(uint256(vm.load(target, bytes32(uint256(24))))),
            uint64(block.number),
            "slot 24: leaderActivationTempoBlock mismatch"
        );
    }

}

/// @notice Tests for ZonePortal - simulating L1/zone interface
contract ZonePortalTest is BaseTest {

    uint256 internal constant TEST_QUEUE_LENGTH = 101;

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 internal constant SETTLEMENT_ATTESTATION_TYPEHASH = keccak256(
        "SettlementAttestation(uint32 zoneId,uint64 sequencerSetVersion,uint256 zoneHeight,uint256 withdrawalBatchIndex,address verifier,uint64 tempoBlockNumber,uint64 anchorBlockNumber,bytes32 anchorBlockHash,bytes32 blockTransitionHash,bytes32 depositQueueTransitionHash,bytes32 tokenEnablementTransitionHash,bytes32 withdrawalQueueHash,bytes32 verifierConfigHash)"
    );

    uint256 internal constant SIGNER_A_KEY = 2;
    uint256 internal constant SIGNER_B_KEY = 3;
    uint256 internal constant SIGNER_C_KEY = 1;
    uint64 internal constant REJECT_ALL_POLICY_ID = 0;
    uint64 internal constant ALLOW_ALL_POLICY_ID = 1;

    ZonePortal public portal;
    ZoneMessenger public messenger;
    MockWithdrawalReceiver public withdrawalReceiver;
    GasConsumingReceiver public gasConsumingReceiver;
    SuccessfulReceiver public successfulReceiver;

    uint32 public testZoneId;
    bytes32 public constant GENESIS_BLOCK_HASH = keccak256("genesis");
    bytes32 public constant GENESIS_TEMPO_BLOCK_HASH = keccak256("tempoGenesis");
    uint64 public genesisTempoBlockNumber;

    struct QuorumBatch {
        uint64 tempoBlockNumber;
        uint64 recentTempoBlockNumber;
        BlockTransition blockTransition;
        DepositQueueTransition depositQueueTransition;
        bytes32 withdrawalQueueHash;
        bytes verifierConfig;
        uint256 nextZoneHeight;
    }

    struct SettlementAttestationInput {
        uint32 zoneId;
        uint64 sequencerSetVersion;
        uint256 zoneHeight;
        uint256 withdrawalBatchIndex;
        address verifier;
        uint64 tempoBlockNumber;
        uint64 anchorBlockNumber;
        bytes32 anchorBlockHash;
        BlockTransition blockTransition;
        DepositQueueTransition depositQueueTransition;
        TokenEnablementTransition tokenEnablementTransition;
        bytes32 withdrawalQueueHash;
        bytes verifierConfig;
    }

    struct SettlementAttestationHashData {
        uint32 zoneId;
        uint64 sequencerSetVersion;
        uint256 zoneHeight;
        uint256 withdrawalBatchIndex;
        address verifier;
        uint64 tempoBlockNumber;
        uint64 anchorBlockNumber;
        bytes32 anchorBlockHash;
        bytes32 blockTransitionHash;
        bytes32 depositQueueTransitionHash;
        bytes32 tokenEnablementTransitionHash;
        bytes32 withdrawalQueueHash;
        bytes32 verifierConfigHash;
    }

    struct PortalSettlementState {
        bytes32 blockHash;
        uint256 zoneHeight;
        uint64 withdrawalBatchIndex;
        uint256 withdrawalQueueHead;
        uint256 withdrawalQueueTail;
        uint64 lastProcessedDepositNumber;
        uint64 lastSyncedTempoBlockNumber;
    }

    struct WithdrawalCapacityTestState {
        bytes32 processedDepositHash;
        Withdrawal withdrawal;
        uint256 reserve;
        Withdrawal[] withdrawals;
        Withdrawal successfulWithdrawal;
        bytes32 withdrawalHash;
        uint64 maximum;
        uint64 maximumPublicDeposits;
        bytes32 queueHashAtPublicCapacity;
        uint256 bobBalanceBefore;
        bytes32 successfulWithdrawalHash;
        bytes32 queueHashAtCapacity;
    }

    function setUp() public override {
        super.setUp();

        // Deploy zone infrastructure
        withdrawalReceiver = new MockWithdrawalReceiver();
        gasConsumingReceiver = new GasConsumingReceiver();
        successfulReceiver = new SuccessfulReceiver();

        // Grant issuer role and mint tokens for tests
        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.mint(sequencer, 1_000_000e6);
        pathUSD.mint(alice, 100_000e6);
        pathUSD.mint(bob, 100_000e6);
        vm.stopPrank();

        // Record genesis block number for Tempo
        genesisTempoBlockNumber = uint64(block.number);

        // Create a zone
        address[] memory initialSequencers = new address[](1);
        initialSequencers[0] = sequencer;
        testZoneId = 1;
        portal = _createZonePortal(
            testZoneId,
            address(pathUSD),
            admin,
            initialSequencers,
            1,
            "https://rpc.test-zone.example"
        );

        // Get the shared messenger
        messenger = ZoneMessenger(ZONE_MESSENGER_ADDRESS);

        // Set expected messenger for withdrawal receiver
        withdrawalReceiver.setExpectedMessenger(address(messenger));
    }

    function _senderTag(address sender) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(sender));
    }

    function _stringOfLength(uint256 length) internal pure returns (string memory value) {
        bytes memory data = new bytes(length);
        for (uint256 i; i < length; ++i) {
            data[i] = "x";
        }
        return string(data);
    }

    function _createEnablementToken(
        string memory name,
        string memory symbol,
        string memory currency,
        bytes32 salt
    )
        internal
        returns (address token)
    {
        token = address(
            factory.createToken(name, symbol, currency, ITIP20(_PATH_USD), sequencer, salt)
        );
        _mockTokenPolicyMigration(token, true);
    }

    function _submitTokenEnablementTransition(TokenEnablementTransition memory transition)
        internal
    {
        _submitTokenEnablementTransition(transition, bytes4(0));
    }

    function _initializeTokenCursor() internal {
        _submitTokenEnablementTransition(
            TokenEnablementTransition({ prevProcessedTokenCount: 0, nextProcessedTokenCount: 1 })
        );
    }

    function _submitTokenEnablementTransition(
        TokenEnablementTransition memory transition,
        bytes4 expectedRevert
    )
        internal
    {
        vm.roll(block.number + 1);
        uint64 tempoBlockNumber = uint64(block.number - 1);
        bytes32 previousBlockHash = portal.blockHash();
        uint256 nextZoneHeight = portal.zoneHeight() + 1;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = hex"01";
        vm.mockCall(
            address(StdPrecompiles.SIGNATURE_VERIFIER),
            abi.encodeWithSelector(ISignatureVerifier.recover.selector),
            abi.encode(sequencer)
        );
        if (expectedRevert != bytes4(0)) vm.expectRevert(expectedRevert);
        portal.submitBatch(
            tempoBlockNumber,
            0,
            BlockTransition({
                prevBlockHash: previousBlockHash,
                nextBlockHash: keccak256(abi.encode("token-cursor", nextZoneHeight))
            }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32(0),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            transition,
            bytes32(0),
            "",
            "",
            nextZoneHeight,
            signatures
        );
    }

    function _sequencerSet() internal returns (address[] memory signers) {
        signers = new address[](3);
        signers[0] = vm.addr(SIGNER_A_KEY);
        signers[1] = vm.addr(SIGNER_B_KEY);
        signers[2] = vm.addr(SIGNER_C_KEY);
    }

    function test_initializeInstallsFullQuorumAtVersionZero() public {
        address[] memory signers = _sequencerSet();
        ZonePortal quorumPortal =
            _createZonePortal(2, address(pathUSD), admin, signers, 2, "https://quorum.example");

        assertEq(quorumPortal.sequencerSetVersion(), 0);
        assertEq(quorumPortal.sequencerThreshold(), 2);
        assertEq(quorumPortal.sequencerCount(), 3);
        assertEq(quorumPortal.leader(), signers[0]);
        for (uint256 i; i < signers.length; ++i) {
            assertTrue(quorumPortal.isSequencer(signers[i]));
        }
    }

    function _activateSequencerSet(uint8 quorum) internal returns (address[] memory signers) {
        signers = _sequencerSet();
        _activateSequencerSet(portal, signers, quorum);
    }

    function _activateSequencerSet(
        ZonePortal target,
        address[] memory signers,
        uint8 quorum
    )
        internal
    {
        // The portal rejects a set that drops the active leader, so rotation is three steps:
        // add the replacements, transfer leadership, then remove the old leader.
        address[] memory joint = new address[](signers.length + 1);
        for (uint256 i; i < signers.length; ++i) {
            joint[i] = signers[i];
        }
        joint[signers.length] = sequencer;
        vm.prank(admin);
        target.setSequencerSet(joint, quorum);
        vm.roll(block.number + 1);
        vm.prank(sequencer);
        target.setLeader(signers[0], target.leaderEpoch());
        vm.prank(admin);
        target.setSequencerSet(signers, quorum);
    }

    function _attestationDigest(
        uint256 height,
        uint64 tempoBlockNumber,
        uint64 anchorBlockNumber,
        bytes32 anchorBlockHash,
        BlockTransition memory blockTransition,
        DepositQueueTransition memory depositQueueTransition,
        bytes32 withdrawalQueueHash,
        bytes memory verifierConfig
    )
        internal
        view
        returns (bytes32)
    {
        return _attestationDigestFor(
            portal,
            block.chainid,
            SettlementAttestationInput({
                zoneId: portal.zoneId(),
                sequencerSetVersion: portal.sequencerSetVersion(),
                zoneHeight: height,
                withdrawalBatchIndex: portal.withdrawalBatchIndex() + 1,
                verifier: portal.verifier(),
                tempoBlockNumber: tempoBlockNumber,
                anchorBlockNumber: anchorBlockNumber,
                anchorBlockHash: anchorBlockHash,
                blockTransition: blockTransition,
                depositQueueTransition: depositQueueTransition,
                tokenEnablementTransition: _currentTokenEnablementTransition(portal),
                withdrawalQueueHash: withdrawalQueueHash,
                verifierConfig: verifierConfig
            })
        );
    }

    function _attestationDigestFor(
        ZonePortal target,
        uint256 chainId,
        SettlementAttestationInput memory attestation
    )
        internal
        pure
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256("ZonePortal"),
                keccak256("1"),
                chainId,
                address(target)
            )
        );
        SettlementAttestationHashData memory hashData;
        hashData.zoneId = attestation.zoneId;
        hashData.sequencerSetVersion = attestation.sequencerSetVersion;
        hashData.zoneHeight = attestation.zoneHeight;
        hashData.withdrawalBatchIndex = attestation.withdrawalBatchIndex;
        hashData.verifier = attestation.verifier;
        hashData.tempoBlockNumber = attestation.tempoBlockNumber;
        hashData.anchorBlockNumber = attestation.anchorBlockNumber;
        hashData.anchorBlockHash = attestation.anchorBlockHash;
        hashData.blockTransitionHash = keccak256(abi.encode(attestation.blockTransition));
        hashData.depositQueueTransitionHash =
            keccak256(abi.encode(attestation.depositQueueTransition));
        hashData.tokenEnablementTransitionHash =
            keccak256(abi.encode(attestation.tokenEnablementTransition));
        hashData.withdrawalQueueHash = attestation.withdrawalQueueHash;
        hashData.verifierConfigHash = keccak256(attestation.verifierConfig);

        bytes32 structHash = keccak256(abi.encode(SETTLEMENT_ATTESTATION_TYPEHASH, hashData));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _sign(uint256 privateKey, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _quorumSignatures(bytes32 digest) internal returns (bytes[] memory signatures) {
        signatures = new bytes[](2);
        signatures[0] = _sign(SIGNER_A_KEY, digest);
        signatures[1] = _sign(SIGNER_B_KEY, digest);
    }

    function _quorumSignatures(
        bytes32 digest,
        uint256 firstSigner,
        uint256 secondSigner
    )
        internal
        returns (bytes[] memory signatures)
    {
        signatures = new bytes[](2);
        signatures[0] = _sign(firstSigner, digest);
        signatures[1] = _sign(secondSigner, digest);
    }

    function _highSSignature(uint256 privateKey, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        uint8 alternateV = v == 27 ? 28 : 27;
        return abi.encodePacked(r, bytes32(SECP256K1_ORDER - uint256(s)), alternateV);
    }

    function _quorumBatch() internal returns (QuorumBatch memory batch) {
        vm.roll(block.number + 1);
        uint64 tempoBlockNumber = uint64(block.number - 1);
        batch = QuorumBatch({
            tempoBlockNumber: tempoBlockNumber,
            recentTempoBlockNumber: 0,
            blockTransition: BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("certified-tip")
            }),
            depositQueueTransition: DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32(0),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            withdrawalQueueHash: bytes32(0),
            verifierConfig: "",
            nextZoneHeight: 10
        });
    }

    function _assertQuorumPairSettles(
        address caller,
        uint256 firstSigner,
        uint256 secondSigner
    )
        internal
    {
        QuorumBatch memory batch = _quorumBatch();
        SettlementAttestationInput memory attestation = _attestationFor(batch);
        bytes[] memory signatures = _quorumSignatures(
            _attestationDigestFor(portal, block.chainid, attestation), firstSigner, secondSigner
        );
        vm.expectCall(
            ZONE_VERIFIER_ADDRESS,
            abi.encodeWithSelector(
                IVerifier.verify.selector,
                attestation.zoneId,
                attestation.tempoBlockNumber,
                attestation.anchorBlockNumber,
                attestation.anchorBlockHash,
                attestation.withdrawalBatchIndex,
                batch.nextZoneHeight
            )
        );
        _submitQuorumBatch(portal, caller, batch, signatures);
        assertEq(portal.blockHash(), batch.blockTransition.nextBlockHash);
        assertEq(portal.zoneHeight(), batch.nextZoneHeight);
        assertEq(portal.withdrawalBatchIndex(), 1);
    }

    function _attestationFor(QuorumBatch memory batch)
        internal
        view
        returns (SettlementAttestationInput memory)
    {
        return SettlementAttestationInput({
            zoneId: portal.zoneId(),
            sequencerSetVersion: portal.sequencerSetVersion(),
            zoneHeight: batch.nextZoneHeight,
            withdrawalBatchIndex: portal.withdrawalBatchIndex() + 1,
            verifier: portal.verifier(),
            tempoBlockNumber: batch.tempoBlockNumber,
            anchorBlockNumber: batch.tempoBlockNumber,
            anchorBlockHash: getBlockHash(batch.tempoBlockNumber),
            blockTransition: batch.blockTransition,
            depositQueueTransition: batch.depositQueueTransition,
            tokenEnablementTransition: _currentTokenEnablementTransition(portal),
            withdrawalQueueHash: batch.withdrawalQueueHash,
            verifierConfig: batch.verifierConfig
        });
    }

    function _submitQuorumBatch(
        ZonePortal target,
        address caller,
        QuorumBatch memory batch,
        bytes[] memory signatures
    )
        internal
    {
        vm.prank(caller);
        target.submitBatch(
            batch.tempoBlockNumber,
            batch.recentTempoBlockNumber,
            batch.blockTransition,
            batch.depositQueueTransition,
            _currentTokenEnablementTransition(target),
            batch.withdrawalQueueHash,
            batch.verifierConfig,
            "",
            batch.nextZoneHeight,
            signatures
        );
    }

    function _snapshotSettlementState(ZonePortal target)
        internal
        view
        returns (PortalSettlementState memory)
    {
        return PortalSettlementState({
            blockHash: target.blockHash(),
            zoneHeight: target.zoneHeight(),
            withdrawalBatchIndex: target.withdrawalBatchIndex(),
            withdrawalQueueHead: target.withdrawalQueueHead(),
            withdrawalQueueTail: target.withdrawalQueueTail(),
            lastProcessedDepositNumber: target.lastProcessedDepositNumber(),
            lastSyncedTempoBlockNumber: target.lastSyncedTempoBlockNumber()
        });
    }

    function _assertSettlementStateUnchanged(
        ZonePortal target,
        PortalSettlementState memory before
    )
        internal
        view
    {
        assertEq(target.blockHash(), before.blockHash, "Portal block hash changed after rejection");
        assertEq(
            target.zoneHeight(), before.zoneHeight, "Portal zone height changed after rejection"
        );
        assertEq(
            target.withdrawalBatchIndex(),
            before.withdrawalBatchIndex,
            "Withdrawal batch index changed after rejection"
        );
        assertEq(
            target.withdrawalQueueHead(),
            before.withdrawalQueueHead,
            "Withdrawal queue head changed after rejection"
        );
        assertEq(
            target.withdrawalQueueTail(),
            before.withdrawalQueueTail,
            "Withdrawal queue tail changed after rejection"
        );
        assertEq(
            target.lastProcessedDepositNumber(),
            before.lastProcessedDepositNumber,
            "Processed deposit index changed after rejection"
        );
        assertEq(
            target.lastSyncedTempoBlockNumber(),
            before.lastSyncedTempoBlockNumber,
            "Tempo sync index changed after rejection"
        );
    }

    function _expectInvalidQuorumCertificate(
        ZonePortal target,
        address caller,
        QuorumBatch memory batch,
        bytes[] memory signatures
    )
        internal
    {
        PortalSettlementState memory before = _snapshotSettlementState(target);
        vm.expectRevert(IZonePortal.InvalidQuorumCertificate.selector);
        _submitQuorumBatch(target, caller, batch, signatures);
        _assertSettlementStateUnchanged(target, before);
    }

    function _mutatedAttestation(
        SettlementAttestationInput memory attestation,
        uint256 mutation
    )
        internal
        pure
        returns (SettlementAttestationInput memory)
    {
        if (mutation == 0) {
            attestation.zoneId += 1;
        } else if (mutation == 1) {
            attestation.sequencerSetVersion += 1;
        } else if (mutation == 2) {
            attestation.zoneHeight += 1;
        } else if (mutation == 3) {
            attestation.withdrawalBatchIndex += 1;
        } else if (mutation == 4) {
            attestation.verifier = address(0xBEEF);
        } else if (mutation == 5) {
            attestation.tempoBlockNumber += 1;
        } else if (mutation == 6) {
            attestation.anchorBlockNumber += 1;
        } else if (mutation == 7) {
            attestation.anchorBlockHash = keccak256("wrong-anchor-hash");
        } else if (mutation == 8) {
            attestation.blockTransition.nextBlockHash = keccak256("wrong-tip");
        } else if (mutation == 9) {
            attestation.depositQueueTransition.nextProcessedHash = keccak256("wrong-deposit-hash");
        } else if (mutation == 10) {
            attestation.withdrawalQueueHash = keccak256("wrong-withdrawal-hash");
        } else if (mutation == 11) {
            attestation.verifierConfig = hex"01";
        }
        return attestation;
    }

    function _withdrawal(
        address token,
        address sender,
        address to,
        uint128 amount,
        bytes32 memo,
        uint64 gasLimit,
        address zoneFallbackRecipient,
        bytes memory callbackData
    )
        internal
        pure
        returns (Withdrawal memory)
    {
        return Withdrawal({
            token: token,
            senderTag: _senderTag(sender),
            to: to,
            amount: amount,
            memo: memo,
            gasLimit: gasLimit,
            fallbackNonce: uint64(uint160(zoneFallbackRecipient)),
            callbackData: callbackData,
            encryptedSender: ""
        });
    }

    /*//////////////////////////////////////////////////////////////
                            ZONE CREATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_zoneCreation() public view {
        assertEq(portal.zoneId(), testZoneId);
        assertTrue(portal.isTokenEnabled(address(pathUSD)));
        assertEq(portal.admin(), admin);
        assertEq(portal.verifier(), ZONE_VERIFIER_ADDRESS);
        assertEq(portal.blockHash(), bytes32(0));
        assertEq(portal.withdrawalBatchIndex(), 0);
        assertEq(portal.messenger(), address(messenger));
        assertEq(portal.bouncebackGas(), 0);
        assertEq(portal.calculateBouncebackFee(), 0);
        assertEq(portal.sequencerSetVersion(), 0);
        assertEq(portal.sequencerThreshold(), 1);
        assertTrue(portal.isSequencer(sequencer));
    }

    /*//////////////////////////////////////////////////////////////
                         SEQUENCER QUORUM TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setSequencerSet_incrementsConfigurationNonce() public {
        address[] memory signers = _sequencerSet();
        // Keep the active leader in the set; dropping it is rejected (ActiveLeaderRemoved).
        address[] memory joint = new address[](4);
        joint[0] = signers[0];
        joint[1] = signers[1];
        joint[2] = signers[2];
        joint[3] = sequencer;

        vm.expectEmit(true, false, false, true);
        emit IZonePortal.SequencerSetUpdated(1, 2, joint);
        vm.prank(admin);
        portal.setSequencerSet(joint, 2);

        assertEq(portal.sequencerSetVersion(), 1);
        assertEq(portal.sequencerThreshold(), 2);
        assertEq(portal.sequencerCount(), 4);
        for (uint256 i; i < joint.length; ++i) {
            assertEq(portal.sequencerAt(i), joint[i]);
            assertTrue(portal.isSequencer(joint[i]));
        }
    }

    function test_setSequencerSet_revertsForNonAdminAndInvalidSets() public {
        address[] memory signers = _sequencerSet();

        vm.prank(alice);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.setSequencerSet(signers, 2);

        vm.prank(admin);
        vm.expectRevert(IZonePortal.InvalidSequencerSet.selector);
        portal.setSequencerSet(signers, 4);

        address[] memory tooMany = new address[](9);
        for (uint256 i; i < tooMany.length; ++i) {
            tooMany[i] = address(uint160(i + 1));
        }
        vm.prank(admin);
        vm.expectRevert(IZonePortal.InvalidSequencerSet.selector);
        portal.setSequencerSet(tooMany, 1);

        signers[1] = signers[0];
        vm.prank(admin);
        vm.expectRevert(IZonePortal.InvalidSequencerSet.selector);
        portal.setSequencerSet(signers, 2);
    }

    function test_setSequencerSet_rejectsAssignedRoles() public {
        address[] memory signers = new address[](2);
        signers[0] = sequencer;
        signers[1] = alice;
        vm.prank(admin);
        vm.expectRevert();
        portal.setSequencerSet(signers, 2);

        signers[1] = address(zoneGateway);
        vm.prank(admin);
        vm.expectRevert();
        portal.setSequencerSet(signers, 2);
    }

    function test_setSequencerSet_allowsAdminAsSequencer() public {
        address[] memory signers = new address[](2);
        signers[0] = sequencer;
        signers[1] = admin;

        vm.startPrank(admin);
        portal.setAllowedAccount(admin, false);
        portal.setSequencerSet(signers, 2);
        vm.stopPrank();

        assertTrue(portal.isSequencer(admin));
        assertTrue(portal.hasRole(admin, Role.Sequencer));
        assertEq(portal.admin(), admin);
    }

    function test_roleSetters_cannotModifySequencers() public {
        vm.startPrank(admin);
        vm.expectRevert();
        portal.setAllowedAccount(sequencer, true);
        vm.expectRevert();
        portal.setGateway(sequencer, true);
        vm.expectRevert();
        portal.setAllowedAccount(sequencer, false);
        vm.expectRevert();
        portal.setGateway(sequencer, false);
        vm.stopPrank();

        assertTrue(portal.isSequencer(sequencer));
        assertTrue(portal.hasRole(sequencer, Role.Sequencer));
    }

    function test_setSequencerSet_acceptsAnyOrderAndComparesMembership() public {
        address[] memory base = _sequencerSet();
        // Keep the active leader in the set; dropping it is rejected (ActiveLeaderRemoved).
        address[] memory signers = new address[](4);
        signers[0] = base[0];
        signers[1] = base[1];
        signers[2] = base[2];
        signers[3] = sequencer;
        (signers[0], signers[2]) = (signers[2], signers[0]);

        vm.prank(admin);
        portal.setSequencerSet(signers, 2);

        for (uint256 i; i < signers.length; ++i) {
            assertEq(portal.sequencerAt(i), signers[i]);
            assertTrue(portal.isSequencer(signers[i]));
        }

        (signers[0], signers[1]) = (signers[1], signers[0]);
        vm.prank(admin);
        vm.expectRevert(IZonePortal.SequencerConfigurationUnchanged.selector);
        portal.setSequencerSet(signers, 2);
    }

    function test_setSequencerSet_revertsIfUnchangedAndRotatesMembership() public {
        address[] memory signers = _activateSequencerSet(2);
        // _activateSequencerSet performs a leadership rotation: two set updates around a
        // setLeader, so the configuration nonce is already at 2 and signers[0] leads.
        assertEq(portal.sequencerSetVersion(), 2);
        assertEq(portal.leader(), signers[0]);

        vm.prank(admin);
        vm.expectRevert(IZonePortal.SequencerConfigurationUnchanged.selector);
        portal.setSequencerSet(signers, 2);

        address removed = signers[2];
        address[] memory replacement = new address[](2);
        replacement[0] = signers[0];
        replacement[1] = signers[1];
        vm.prank(admin);
        portal.setSequencerSet(replacement, 2);

        assertEq(portal.sequencerSetVersion(), 3);
        assertFalse(portal.isSequencer(removed));
        assertTrue(portal.hasRole(removed, Role.None));
    }

    function test_allSequencersCanCallSequencerConfigurationMethods() public {
        address[] memory signers = _activateSequencerSet(2);

        for (uint256 i = 0; i < signers.length; ++i) {
            vm.startPrank(signers[i]);
            portal.setRpcUrl(string.concat("https://sequencer-", vm.toString(i), ".example"));
            vm.stopPrank();
        }

        vm.prank(alice);
        vm.expectRevert(IZonePortal.NotSequencer.selector);
        portal.setRpcUrl("https://not-a-sequencer.example");
    }

    /*//////////////////////////////////////////////////////////////
                           LEADERSHIP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_initialize_bootstrapsFirstSequencerAsLeader() public view {
        assertEq(portal.leader(), sequencer, "initial leader should be first sequencer");
        assertEq(portal.leaderEpoch(), 1, "initial epoch should be 1");
        assertEq(
            portal.leaderActivationTempoBlock(),
            genesisTempoBlockNumber,
            "activation block should be the creation block"
        );
    }

    function test_setLeader_transitionsAndIncrementsEpochOnce() public {
        address[] memory signers = _activateSequencerSet(2);
        // Post-rotation state from the helper: leader = signers[0], epoch = 2.
        assertEq(portal.leaderEpoch(), 2);

        vm.roll(block.number + 1);
        vm.expectEmit(true, true, true, true);
        emit IZonePortal.LeaderUpdated(signers[0], signers[1], 3, uint64(block.number));
        vm.prank(signers[2]);
        portal.setLeader(signers[1], 2);

        assertEq(portal.leader(), signers[1]);
        assertEq(portal.leaderEpoch(), 3);
        assertEq(portal.leaderActivationTempoBlock(), uint64(block.number));
    }

    function test_setLeader_allowsAdminCaller() public {
        address[] memory signers = _activateSequencerSet(2);
        uint64 epoch = portal.leaderEpoch();

        vm.roll(block.number + 1);
        vm.prank(admin);
        portal.setLeader(signers[1], epoch);

        assertEq(portal.leader(), signers[1]);
        assertEq(portal.leaderEpoch(), epoch + 1);
        assertEq(portal.leaderActivationTempoBlock(), uint64(block.number));
    }

    function test_setLeader_revertsForUnauthorizedCaller() public {
        address[] memory signers = _activateSequencerSet(2);
        uint64 epoch = portal.leaderEpoch();

        vm.roll(block.number + 1);
        vm.prank(alice);
        vm.expectRevert(IZonePortal.NotSequencer.selector);
        portal.setLeader(signers[1], epoch);
    }

    function test_setLeader_revertsForNonMemberTarget() public {
        _activateSequencerSet(2);
        address activeLeader = portal.leader();
        uint64 epoch = portal.leaderEpoch();

        vm.roll(block.number + 1);
        vm.prank(activeLeader);
        vm.expectRevert(IZonePortal.InvalidLeader.selector);
        portal.setLeader(alice, epoch);
    }

    function test_setLeader_duplicateTargetIsNoOpWithoutEventOrEpochChange() public {
        address[] memory signers = _activateSequencerSet(2);
        uint64 epochBefore = portal.leaderEpoch();
        uint64 activationBefore = portal.leaderActivationTempoBlock();

        // Fanned-out duplicates succeed as no-ops even with a stale expected epoch.
        vm.roll(block.number + 1);
        vm.recordLogs();
        vm.prank(signers[1]);
        portal.setLeader(signers[0], epochBefore - 1);

        assertEq(vm.getRecordedLogs().length, 0, "duplicate must not emit");
        assertEq(portal.leader(), signers[0]);
        assertEq(portal.leaderEpoch(), epochBefore);
        assertEq(portal.leaderActivationTempoBlock(), activationBefore);
    }

    function test_setLeader_rejectsStaleEpochAfterLaterHandoff() public {
        address[] memory signers = _activateSequencerSet(2);
        uint64 epochAtB = portal.leaderEpoch();

        // signers[0] -> signers[1], then signers[1] -> signers[2].
        vm.roll(block.number + 1);
        vm.prank(signers[0]);
        portal.setLeader(signers[1], epochAtB);
        vm.roll(block.number + 1);
        vm.prank(signers[0]);
        portal.setLeader(signers[2], epochAtB + 1);

        // A delayed duplicate of the first handoff cannot move leadership back.
        vm.roll(block.number + 1);
        vm.prank(signers[0]);
        vm.expectRevert(
            abi.encodeWithSelector(
                IZonePortal.StaleLeadershipEpoch.selector, epochAtB, epochAtB + 2
            )
        );
        portal.setLeader(signers[1], epochAtB);

        assertEq(portal.leader(), signers[2]);
        assertEq(portal.leaderEpoch(), epochAtB + 2);
    }

    function test_setLeader_rejectsSecondDistinctTargetInOneBlock() public {
        address[] memory signers = _activateSequencerSet(2);
        uint64 epoch = portal.leaderEpoch();

        vm.roll(block.number + 1);
        vm.prank(signers[0]);
        portal.setLeader(signers[1], epoch);

        // Same target again in the same block: still a successful no-op.
        vm.prank(signers[2]);
        portal.setLeader(signers[1], epoch + 1);

        // A different target in the same Tempo block is ambiguous and rejected.
        vm.prank(signers[0]);
        vm.expectRevert(IZonePortal.LeaderAlreadyUpdatedThisBlock.selector);
        portal.setLeader(signers[2], epoch + 1);
    }

    function test_setLeader_bootstrapsLegacyZeroState() public {
        // Portals initialized before leadership landed read the appended slots as zero.
        vm.store(address(portal), PORTAL_LEADER_SLOT, bytes32(0));
        vm.store(address(portal), PORTAL_LEADER_ACTIVATION_TEMPO_BLOCK_SLOT, bytes32(0));
        assertEq(portal.leader(), address(0));
        assertEq(portal.leaderEpoch(), 0);

        vm.expectEmit(true, true, true, true);
        emit IZonePortal.LeaderUpdated(address(0), sequencer, 1, uint64(block.number));
        vm.prank(sequencer);
        portal.setLeader(sequencer, 0);

        assertEq(portal.leader(), sequencer);
        assertEq(portal.leaderEpoch(), 1);
    }

    function test_setSequencerSet_rejectsRemovingActiveLeader() public {
        address[] memory signers = _activateSequencerSet(2);
        assertEq(portal.leader(), signers[0]);

        address[] memory withoutLeader = new address[](2);
        withoutLeader[0] = signers[1];
        withoutLeader[1] = signers[2];
        vm.prank(admin);
        vm.expectRevert(IZonePortal.ActiveLeaderRemoved.selector);
        portal.setSequencerSet(withoutLeader, 2);
    }

    function test_submitBatch_acceptsEachRegisteredQuorumPair() public {
        address[] memory signers = _activateSequencerSet(2);
        uint256 snapshot = vm.snapshotState();

        _assertQuorumPairSettles(signers[0], SIGNER_A_KEY, SIGNER_B_KEY);
        assertTrue(vm.revertToState(snapshot));

        _assertQuorumPairSettles(signers[0], SIGNER_A_KEY, SIGNER_C_KEY);
        assertTrue(vm.revertToState(snapshot));

        _assertQuorumPairSettles(signers[0], SIGNER_B_KEY, SIGNER_C_KEY);
    }

    function test_submitBatch_rejectsCertificateForDifferentWithdrawalRoot() public {
        address[] memory signers = _activateSequencerSet(2);
        vm.roll(block.number + 1);

        uint64 tempoBlockNumber = uint64(block.number - 1);
        BlockTransition memory blockTransition = BlockTransition({
            prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("certified-tip")
        });
        DepositQueueTransition memory depositQueueTransition = DepositQueueTransition({
            prevProcessedHash: bytes32(0),
            nextProcessedHash: bytes32(0),
            prevDepositNumber: 0,
            nextDepositNumber: 0
        });
        bytes[] memory signatures = _quorumSignatures(
            _attestationDigest(
                10,
                tempoBlockNumber,
                tempoBlockNumber,
                getBlockHash(tempoBlockNumber),
                blockTransition,
                depositQueueTransition,
                bytes32(0),
                ""
            )
        );

        vm.prank(signers[0]);
        vm.expectRevert(IZonePortal.InvalidQuorumCertificate.selector);
        portal.submitBatch(
            tempoBlockNumber,
            0,
            blockTransition,
            depositQueueTransition,
            _currentTokenEnablementTransition(portal),
            keccak256("substituted-withdrawal-root"),
            "",
            "",
            10,
            signatures
        );
    }

    /// @notice Every condition below must fail at the certificate boundary, before a batch can
    /// mutate the Portal's tip or either queue index. The field substitutions use a valid call and
    /// alter exactly one EIP-712 attestation field, including fields not exposed in submitBatch
    /// calldata such as zoneId, sequencerSetVersion, and verifier.
    function test_submitBatch_rejectsQuorumCertificateMatrix() public {
        address[] memory signers = _activateSequencerSet(2);
        QuorumBatch memory batch = _quorumBatch();
        SettlementAttestationInput memory attestation = _attestationFor(batch);
        bytes32 digest = _attestationDigestFor(portal, block.chainid, attestation);
        bytes[] memory validSignatures = _quorumSignatures(digest, SIGNER_A_KEY, SIGNER_B_KEY);

        // A signature counts only once, must belong to a registered signer, and must use the
        // canonical format enforced by TIP-1020.
        bytes[] memory oneSignature = new bytes[](1);
        oneSignature[0] = _sign(SIGNER_A_KEY, digest);
        _expectInvalidQuorumCertificate(portal, signers[0], batch, oneSignature);

        bytes memory signerA = _sign(SIGNER_A_KEY, digest);
        bytes[] memory duplicateSignatures = new bytes[](2);
        duplicateSignatures[0] = signerA;
        duplicateSignatures[1] = signerA;
        _expectInvalidQuorumCertificate(portal, signers[0], batch, duplicateSignatures);

        bytes[] memory unregisteredSignatures = _quorumSignatures(digest, SIGNER_A_KEY, 4);
        _expectInvalidQuorumCertificate(portal, signers[0], batch, unregisteredSignatures);

        bytes[] memory malformedSignatures = new bytes[](2);
        malformedSignatures[0] = _sign(SIGNER_A_KEY, digest);
        malformedSignatures[1] = hex"00";
        _expectInvalidQuorumCertificate(portal, signers[0], batch, malformedSignatures);

        bytes[] memory highSSignatures = new bytes[](2);
        highSSignatures[0] = _sign(SIGNER_A_KEY, digest);
        highSSignatures[1] = _highSSignature(SIGNER_B_KEY, digest);
        _expectInvalidQuorumCertificate(portal, signers[0], batch, highSSignatures);

        // All twelve settlement-bound attestation fields are individually non-substitutable.
        for (uint256 mutation; mutation < 12; ++mutation) {
            SettlementAttestationInput memory altered = _mutatedAttestation(attestation, mutation);
            bytes[] memory alteredSignatures =
                _quorumSignatures(_attestationDigestFor(portal, block.chainid, altered));
            _expectInvalidQuorumCertificate(portal, signers[0], batch, alteredSignatures);
        }

        // EIP-712 additionally prevents a certificate from crossing L1 chains.
        uint256 originalChainId = block.chainid;
        vm.chainId(originalChainId + 1);
        _expectInvalidQuorumCertificate(portal, signers[0], batch, validSignatures);
        vm.chainId(originalChainId);

        // A matching Portal configuration cannot reuse a certificate intended for this Portal.
        address[] memory initialSequencers = new address[](1);
        initialSequencers[0] = sequencer;
        ZonePortal otherPortal = _createZonePortal(
            testZoneId + 1, address(pathUSD), admin, initialSequencers, 1, "https://quorum.example"
        );
        _activateSequencerSet(otherPortal, signers, 2);
        _expectInvalidQuorumCertificate(otherPortal, signers[0], batch, validSignatures);

        // Isolate the EIP-712 verifyingContract binding: every attestation field is unchanged,
        // but signatures collected for the other Portal cannot be used on this Portal.
        bytes[] memory otherPortalDomainSignatures =
            _quorumSignatures(_attestationDigestFor(otherPortal, block.chainid, attestation));
        _expectInvalidQuorumCertificate(portal, signers[0], batch, otherPortalDomainSignatures);

        // A certificate collected before a signer-set update cannot settle after it. Keep A and B
        // registered so this is a version regression rather than merely an unregistered-signer one.
        address[] memory rotatedSigners = new address[](3);
        rotatedSigners[0] = signers[0];
        rotatedSigners[1] = signers[1];
        rotatedSigners[2] = vm.addr(4);
        vm.prank(admin);
        portal.setSequencerSet(rotatedSigners, 2);
        _expectInvalidQuorumCertificate(portal, signers[0], batch, validSignatures);
    }

    function test_adminCanPauseAndResumeDeposits() public {
        vm.prank(admin);
        portal.pauseDeposits(address(pathUSD));
        assertFalse(portal.areDepositsActive(address(pathUSD)));

        vm.prank(admin);
        portal.resumeDeposits(address(pathUSD));
        assertTrue(portal.areDepositsActive(address(pathUSD)));
    }

    function test_pause_blocksDepositsAndWithdrawalProcessingButAllowsBatchSubmission() public {
        vm.prank(sequencer);
        portal.pause();

        assertTrue(portal.paused());
        assertEq(portal.pauseExpiry(), block.timestamp + 30 days);
        assertFalse(portal.areDepositsActive(address(pathUSD)));

        vm.prank(alice);
        vm.expectRevert(IZonePortal.PortalIsPaused.selector);
        portal.deposit(address(pathUSD), 1000e6, 0, _makeDepositPayload(), alice);

        vm.prank(sequencer);
        vm.expectRevert(IZonePortal.PortalIsPaused.selector);
        portal.processWithdrawals(new Withdrawal[](0), bytes32(0));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("paused-settlement")
            }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32(0),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            bytes32(0),
            "",
            ""
        );
        assertEq(portal.withdrawalBatchIndex(), 1);

        vm.warp(block.timestamp + 30 days);
        assertFalse(portal.paused());
        assertTrue(portal.areDepositsActive(address(pathUSD)));
    }

    function test_pauseRoleCanPause() public {
        address guardian = makeAddr("pause guardian");
        vm.prank(admin);
        portal.setPauseGuardian(guardian, true);

        vm.prank(guardian);
        portal.pause();
        assertTrue(portal.paused());
    }

    function test_setPauseGuardian_isIdempotent() public {
        address guardian = makeAddr("pause guardian");
        vm.startPrank(admin);

        portal.setPauseGuardian(guardian, true);
        portal.setPauseGuardian(guardian, true);
        assertTrue(portal.hasRole(guardian, Role.PauseGuardian));

        portal.setPauseGuardian(guardian, false);
        portal.setPauseGuardian(guardian, false);
        assertTrue(portal.hasRole(guardian, Role.None));

        vm.stopPrank();
    }

    function test_setPauseGuardian_cannotBeRemovedAfterCapabilityAbdication() public {
        address guardian = makeAddr("pause guardian");
        vm.startPrank(admin);
        portal.setPauseGuardian(guardian, true);
        portal.abdicate(Capability.PausePortal);
        vm.stopPrank();

        vm.warp(block.timestamp + 30 days);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(IZonePortal.CapabilityAbdicated.selector, Capability.PausePortal)
        );
        portal.setPauseGuardian(guardian, false);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(IZonePortal.CapabilityAbdicated.selector, Capability.PausePortal)
        );
        portal.setPauseGuardian(bob, true);

        assertTrue(portal.hasRole(guardian, Role.PauseGuardian));
    }

    function test_accessRoles_cannotBeRemovedAfterCapabilityAbdication() public {
        vm.prank(admin);
        portal.abdicate(Capability.AccessPolicy);
        vm.warp(block.timestamp + 30 days);

        vm.startPrank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IZonePortal.CapabilityAbdicated.selector, Capability.AccessPolicy
            )
        );
        portal.setAllowedAccount(alice, false);

        vm.expectRevert(
            abi.encodeWithSelector(
                IZonePortal.CapabilityAbdicated.selector, Capability.AccessPolicy
            )
        );
        portal.setGateway(address(zoneGateway), false);

        vm.stopPrank();

        assertTrue(portal.hasRole(alice, Role.Account));
        assertTrue(portal.hasRole(address(zoneGateway), Role.CallbackGateway));
    }

    function test_setPauseGuardian_cannotModifyAccessRoles() public {
        vm.startPrank(admin);

        vm.expectRevert();
        portal.setPauseGuardian(alice, false);

        vm.expectRevert();
        portal.setPauseGuardian(alice, true);

        vm.expectRevert();
        portal.setPauseGuardian(address(zoneGateway), false);

        vm.expectRevert();
        portal.setPauseGuardian(address(zoneGateway), true);

        vm.stopPrank();

        assertTrue(portal.hasRole(alice, Role.Account));
        assertTrue(portal.hasRole(address(zoneGateway), Role.CallbackGateway));
    }

    function test_pause_expiresAfterThirtyDays() public {
        vm.prank(sequencer);
        portal.pause();

        vm.warp(block.timestamp + 30 days);
        assertFalse(portal.paused());
    }

    function test_pause_adminCanResumeEarly() public {
        vm.prank(sequencer);
        portal.pause();

        vm.warp(block.timestamp + 1 days);
        vm.expectEmit(true, false, false, false);
        emit IZonePortal.PortalResumed(admin);
        vm.prank(admin);
        portal.resume();

        assertFalse(portal.paused());
        assertEq(portal.pauseExpiry(), 0);
    }

    function test_pause_onlyAdminCanResumeEarly() public {
        address guardian = makeAddr("pause guardian");
        vm.prank(admin);
        portal.setPauseGuardian(guardian, true);
        vm.prank(sequencer);
        portal.pause();

        vm.prank(sequencer);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.resume();

        vm.prank(guardian);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.resume();

        assertTrue(portal.paused());
    }

    function test_pause_resumeRemainsAvailableAfterAbdication() public {
        vm.prank(admin);
        portal.abdicate(Capability.PausePortal);

        vm.warp(block.timestamp + 29 days);
        vm.prank(sequencer);
        portal.pause();

        vm.warp(block.timestamp + 1 days);
        vm.prank(admin);
        portal.resume();

        assertFalse(portal.paused());
        assertEq(portal.pauseExpiry(), 0);
    }

    function test_pause_cannotExtendActivePause() public {
        vm.prank(sequencer);
        portal.pause();
        uint64 originalExpiry = portal.pauseExpiry();

        vm.warp(block.timestamp + 15 days);
        vm.prank(sequencer);
        vm.expectRevert(IZonePortal.PortalIsPaused.selector);
        portal.pause();

        assertEq(portal.pauseExpiry(), originalExpiry);
    }

    function test_abdicatePause_delaysPermanentDisable() public {
        uint64 effectiveAt = uint64(block.timestamp) + 30 days;
        vm.expectEmit(true, false, false, true);
        emit IZonePortal.AbdicationScheduled(Capability.PausePortal, effectiveAt);
        vm.prank(admin);
        portal.abdicate(Capability.PausePortal);
        assertEq(portal.abdicationEffectiveAt(Capability.PausePortal), effectiveAt);
        assertFalse(portal.paused());

        vm.warp(effectiveAt);
        vm.prank(sequencer);
        vm.expectRevert(
            abi.encodeWithSelector(IZonePortal.CapabilityAbdicated.selector, Capability.PausePortal)
        );
        portal.pause();
    }

    function test_abdicatePause_allowsStartingAPauseBeforeItTakesEffect() public {
        vm.prank(admin);
        portal.abdicate(Capability.PausePortal);

        vm.warp(block.timestamp + 29 days);
        vm.prank(sequencer);
        portal.pause();
        uint64 pauseExpiry = portal.pauseExpiry();

        vm.warp(block.timestamp + 1 days);
        assertTrue(portal.paused());

        vm.warp(pauseExpiry);
        vm.prank(sequencer);
        vm.expectRevert(
            abi.encodeWithSelector(IZonePortal.CapabilityAbdicated.selector, Capability.PausePortal)
        );
        portal.pause();
    }

    function test_abdicatePause_cannotBeRescheduled() public {
        vm.prank(admin);
        portal.abdicate(Capability.PausePortal);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IZonePortal.AbdicationAlreadyScheduled.selector, Capability.PausePortal
            )
        );
        portal.abdicate(Capability.PausePortal);
    }

    function test_pause_revertsWithoutAuthority() public {
        vm.prank(alice);
        vm.expectRevert(IZonePortal.NotPauseAuthority.selector);
        portal.pause();
    }

    function test_tokenGovernance_revertsIfNotAdmin() public {
        vm.startPrank(sequencer);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.pauseDeposits(address(pathUSD));

        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.resumeDeposits(address(pathUSD));

        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.enableToken(address(pathUSD));

        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.setZoneGasRate(1);

        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.setBouncebackGas(1);
        vm.stopPrank();
    }

    function test_enableToken_migratesPolicyBinding() public {
        _initializeTokenCursor();
        address token = address(token1);
        address[] memory tokens = new address[](1);
        tokens[0] = token;
        bytes[] memory lookupResults = new bytes[](2);
        lookupResults[0] = abi.encode(false, uint64(1));
        lookupResults[1] = abi.encode(true, uint64(1));
        vm.mockCalls(
            _TIP403REGISTRY,
            abi.encodeCall(ITIP403Registry.tokenTransferPolicyId, (token)),
            lookupResults
        );
        vm.mockCall(
            _TIP403REGISTRY,
            abi.encodeCall(ITIP403Registry.migrateTransferPolicyIds, (tokens)),
            abi.encode(1)
        );

        vm.expectCall(
            _TIP403REGISTRY, abi.encodeCall(ITIP403Registry.migrateTransferPolicyIds, (tokens))
        );
        vm.expectCall(
            _TIP403REGISTRY, abi.encodeCall(ITIP403Registry.tokenTransferPolicyId, (token)), 2
        );

        vm.prank(admin);
        portal.enableToken(token);

        assertTrue(portal.isTokenEnabled(token));
    }

    function test_enableToken_skipsMigrationIfPolicyBindingIsSet() public {
        _initializeTokenCursor();
        address token = address(token1);
        address[] memory tokens = new address[](1);
        tokens[0] = token;
        _mockTokenPolicyMigration(token, true);
        vm.mockCallRevert(
            _TIP403REGISTRY,
            abi.encodeCall(ITIP403Registry.migrateTransferPolicyIds, (tokens)),
            abi.encodeWithSignature("UnexpectedMigration()")
        );

        vm.expectCall(
            _TIP403REGISTRY, abi.encodeCall(ITIP403Registry.tokenTransferPolicyId, (token))
        );

        vm.prank(admin);
        portal.enableToken(token);

        assertTrue(portal.isTokenEnabled(token));
    }

    function test_enableToken_revertsIfPolicyBindingIsNotSet() public {
        _initializeTokenCursor();
        address token = address(token1);
        _mockTokenPolicyMigration(token, false);

        vm.prank(admin);
        vm.expectRevert(IZonePortal.TokenTransferPolicyNotSet.selector);
        portal.enableToken(token);
    }

    function test_enableToken_acceptsMaximumMetadataLengths() public {
        _initializeTokenCursor();
        uint256 maximum = portal.MAX_TOKEN_METADATA_BYTES();
        address token = _createEnablementToken(
            _stringOfLength(maximum),
            _stringOfLength(maximum),
            _stringOfLength(maximum),
            bytes32("max metadata")
        );

        vm.prank(admin);
        portal.enableToken(token);

        assertTrue(portal.isTokenEnabled(token));
    }

    function test_enableToken_rejectsOversizedName() public {
        _initializeTokenCursor();
        uint256 maximum = portal.MAX_TOKEN_METADATA_BYTES();
        address token =
            _createEnablementToken(_stringOfLength(maximum + 1), "T", "USD", bytes32("long name"));

        vm.prank(admin);
        vm.expectRevert(IZonePortal.TokenMetadataTooLong.selector);
        portal.enableToken(token);

        assertFalse(portal.isTokenEnabled(token));
    }

    function test_enableToken_rejectsOversizedSymbol() public {
        _initializeTokenCursor();
        uint256 maximum = portal.MAX_TOKEN_METADATA_BYTES();
        address token = _createEnablementToken(
            "Token", _stringOfLength(maximum + 1), "USD", bytes32("long symbol")
        );

        vm.prank(admin);
        vm.expectRevert(IZonePortal.TokenMetadataTooLong.selector);
        portal.enableToken(token);

        assertFalse(portal.isTokenEnabled(token));
    }

    function test_enableToken_rejectsOversizedCurrency() public {
        _initializeTokenCursor();
        uint256 maximum = portal.MAX_TOKEN_METADATA_BYTES();
        address token = _createEnablementToken(
            "Token", "T", _stringOfLength(maximum + 1), bytes32("long currency")
        );

        vm.prank(admin);
        vm.expectRevert(IZonePortal.TokenMetadataTooLong.selector);
        portal.enableToken(token);

        assertFalse(portal.isTokenEnabled(token));
    }

    function test_enableToken_enforcesOutstandingCapAcrossTempoBlocks() public {
        uint64 maximum = portal.MAX_UNPROCESSED_TOKEN_ENABLEMENTS();
        assertEq(maximum, 8);
        assertFalse(portal.tokenEnablementCursorInitialized());
        _submitTokenEnablementTransition(
            TokenEnablementTransition({ prevProcessedTokenCount: 0, nextProcessedTokenCount: 1 })
        );
        assertTrue(portal.tokenEnablementCursorInitialized());
        assertEq(portal.lastProcessedEnabledTokenCount(), 1);

        for (uint256 i; i < maximum; ++i) {
            address token = _createEnablementToken("Token", "T", "USD", bytes32(uint256(1000 + i)));
            vm.prank(admin);
            portal.enableToken(token);
        }
        assertEq(portal.enabledTokenCount(), maximum + 1);

        address overflowToken =
            _createEnablementToken("Overflow", "OVER", "USD", bytes32("overflow"));
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IZonePortal.TokenEnablementBlockCapacityExceeded.selector, maximum
            )
        );
        portal.enableToken(overflowToken);
        assertFalse(portal.isTokenEnabled(overflowToken));

        vm.roll(block.number + 1);
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IZonePortal.TokenEnablementBlockCapacityExceeded.selector, maximum
            )
        );
        portal.enableToken(overflowToken);
        assertFalse(portal.isTokenEnabled(overflowToken));
    }

    function test_enableToken_revertsUntilTokenCursorInitialized() public {
        assertFalse(portal.tokenEnablementCursorInitialized());
        address token = _createEnablementToken("Token", "T", "USD", bytes32("frozen"));

        vm.prank(admin);
        vm.expectRevert(IZonePortal.TokenEnablementCursorNotInitialized.selector);
        portal.enableToken(token);
        assertFalse(portal.isTokenEnabled(token));

        _submitTokenEnablementTransition(
            TokenEnablementTransition({ prevProcessedTokenCount: 0, nextProcessedTokenCount: 0 })
        );
        assertFalse(portal.tokenEnablementCursorInitialized());
        assertEq(portal.lastProcessedEnabledTokenCount(), 0);

        vm.prank(admin);
        vm.expectRevert(IZonePortal.TokenEnablementCursorNotInitialized.selector);
        portal.enableToken(token);

        _submitTokenEnablementTransition(
            TokenEnablementTransition({ prevProcessedTokenCount: 0, nextProcessedTokenCount: 1 })
        );
        assertTrue(portal.tokenEnablementCursorInitialized());

        vm.prank(admin);
        portal.enableToken(token);
        assertTrue(portal.isTokenEnabled(token));
    }

    function test_tokenCursorInitializationAcceptsHistoricalPrefix() public {
        vm.store(address(portal), PORTAL_ENABLED_TOKENS_SLOT, bytes32(uint256(2)));
        assertEq(portal.enabledTokenCount(), 2);

        _submitTokenEnablementTransition(
            TokenEnablementTransition({ prevProcessedTokenCount: 0, nextProcessedTokenCount: 1 })
        );
        assertTrue(portal.tokenEnablementCursorInitialized());
        assertEq(portal.lastProcessedEnabledTokenCount(), 1);

        _submitTokenEnablementTransition(
            TokenEnablementTransition({ prevProcessedTokenCount: 1, nextProcessedTokenCount: 2 })
        );
        assertEq(portal.lastProcessedEnabledTokenCount(), 2);
    }

    function test_tokenCursorInitializationRejectsOversizedHistoricalSuffix() public {
        uint64 maximum = portal.MAX_UNPROCESSED_TOKEN_ENABLEMENTS();
        vm.store(
            address(portal), PORTAL_ENABLED_TOKENS_SLOT, bytes32(uint256(maximum) + uint256(2))
        );

        _submitTokenEnablementTransition(
            TokenEnablementTransition({ prevProcessedTokenCount: 0, nextProcessedTokenCount: 1 }),
            IZonePortal.InvalidTokenEnablementTransition.selector
        );
        assertFalse(portal.tokenEnablementCursorInitialized());

        _submitTokenEnablementTransition(
            TokenEnablementTransition({ prevProcessedTokenCount: 0, nextProcessedTokenCount: 2 })
        );
        assertTrue(portal.tokenEnablementCursorInitialized());
        assertEq(portal.lastProcessedEnabledTokenCount(), 2);
    }

    function test_tokenCursorInitializationRejectsNonzeroPreviousCount() public {
        _submitTokenEnablementTransition(
            TokenEnablementTransition({ prevProcessedTokenCount: 1, nextProcessedTokenCount: 1 }),
            IZonePortal.InvalidTokenEnablementTransition.selector
        );
        assertFalse(portal.tokenEnablementCursorInitialized());
    }

    function test_sequencerGovernance_revertsIfAdminLacksSequencerRole() public {
        // Admin authority alone does not grant sequencer-only powers.
        Withdrawal memory w =
            _withdrawal(address(pathUSD), alice, bob, 500e6, bytes32(0), 0, alice, "");
        // Read state used as call args up front so the staticcall isn't mistaken
        // for the call expectRevert is guarding.
        bytes32 prevBlockHash = portal.blockHash();

        vm.startPrank(admin);

        vm.expectRevert(IZonePortal.NotSequencer.selector);
        portal.setRpcUrl("https://rpc.example");

        vm.expectRevert(IZonePortal.NotSequencer.selector);
        portal.submitBatch(
            uint64(block.number),
            0,
            BlockTransition({ prevBlockHash: prevBlockHash, nextBlockHash: keccak256("state") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32(0),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            _currentTokenEnablementTransition(portal),
            bytes32(0),
            "",
            "",
            1,
            new bytes[](0)
        );

        vm.expectRevert(IZonePortal.NotSequencer.selector);
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN TRANSFER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_transferAdmin_twoStep() public {
        assertEq(portal.admin(), admin);
        assertEq(portal.pendingAdmin(), address(0));

        // Step 1: current admin nominates a new admin.
        vm.expectEmit(true, true, false, true);
        emit IZonePortal.AdminTransferStarted(admin, alice);
        vm.prank(admin);
        portal.transferAdmin(alice);

        // Role does not move until acceptance.
        assertEq(portal.admin(), admin);
        assertEq(portal.pendingAdmin(), alice);

        // Step 2: pending admin accepts and the role hands over.
        vm.expectEmit(true, true, false, true);
        emit IZonePortal.AdminTransferred(admin, alice);
        vm.prank(alice);
        portal.acceptAdmin();

        assertEq(portal.admin(), alice);
        assertEq(portal.pendingAdmin(), address(0));
    }

    function test_transferAdmin_movesGovernancePowers() public {
        vm.prank(admin);
        portal.transferAdmin(alice);
        vm.prank(alice);
        portal.acceptAdmin();

        // New admin can exercise governance powers.
        vm.prank(alice);
        portal.pause();
        assertTrue(portal.paused());

        vm.prank(admin);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.abdicate(Capability.PausePortal);
    }

    function test_transferAdmin_revertsIfNotAdmin() public {
        vm.prank(alice);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.transferAdmin(alice);
    }

    function test_acceptAdmin_preservesAssignedRole() public {
        vm.startPrank(admin);
        portal.transferAdmin(alice);
        vm.stopPrank();

        vm.prank(alice);
        portal.acceptAdmin();

        assertEq(portal.admin(), alice);
        assertTrue(portal.hasRole(alice, Role.Account));
    }

    function test_acceptAdmin_revertsIfNotPendingAdmin() public {
        vm.prank(admin);
        portal.transferAdmin(alice);

        // Neither a random caller nor the current admin can accept.
        vm.prank(bob);
        vm.expectRevert(IZonePortal.NotPendingAdmin.selector);
        portal.acceptAdmin();

        vm.prank(admin);
        vm.expectRevert(IZonePortal.NotPendingAdmin.selector);
        portal.acceptAdmin();

        assertEq(portal.admin(), admin);
    }

    function test_acceptAdmin_revertsWhenNoPendingAdmin() public {
        // pendingAdmin defaults to address(0); acceptAdmin must never let anyone
        // (including a zero-address caller, which is unreachable in practice) take over.
        vm.prank(alice);
        vm.expectRevert(IZonePortal.NotPendingAdmin.selector);
        portal.acceptAdmin();
    }

    function test_transferAdmin_cancelViaZeroAddress() public {
        vm.prank(admin);
        portal.transferAdmin(alice);
        assertEq(portal.pendingAdmin(), alice);

        // Nominating address(0) cancels the pending transfer.
        vm.expectEmit(true, true, false, true);
        emit IZonePortal.AdminTransferStarted(admin, address(0));
        vm.prank(admin);
        portal.transferAdmin(address(0));
        assertEq(portal.pendingAdmin(), address(0));

        // The previously-pending admin can no longer accept.
        vm.prank(alice);
        vm.expectRevert(IZonePortal.NotPendingAdmin.selector);
        portal.acceptAdmin();
        assertEq(portal.admin(), admin);
    }

    function test_transferAdmin_renomination() public {
        vm.prank(admin);
        portal.transferAdmin(alice);

        // Re-nominating a different address overwrites the pending admin.
        vm.prank(admin);
        portal.transferAdmin(bob);
        assertEq(portal.pendingAdmin(), bob);

        // The stale nominee cannot accept; the current nominee can.
        vm.prank(alice);
        vm.expectRevert(IZonePortal.NotPendingAdmin.selector);
        portal.acceptAdmin();

        vm.prank(bob);
        portal.acceptAdmin();
        assertEq(portal.admin(), bob);
        assertEq(portal.pendingAdmin(), address(0));
    }

    function test_setZoneGateway_supportsLegacyAndReplacementTogether() public {
        address replacement = makeAddr("replacement gateway");

        vm.expectEmit(true, false, false, true);
        emit IZonePortal.RoleUpdated(replacement, Role.None, Role.CallbackGateway);
        vm.prank(admin);
        portal.setGateway(replacement, true);

        assertTrue(portal.hasRole(address(zoneGateway), Role.CallbackGateway));
        assertTrue(portal.hasRole(replacement, Role.CallbackGateway));

        vm.prank(admin);
        portal.setGateway(address(zoneGateway), false);
        assertTrue(portal.hasRole(address(zoneGateway), Role.None));
        assertTrue(portal.hasRole(replacement, Role.CallbackGateway));
    }

    function test_setGateway_cannotOverwriteAccountRole() public {
        vm.prank(admin);
        vm.expectRevert();
        portal.setGateway(alice, true);
        assertTrue(portal.hasRole(alice, Role.Account));
    }

    function test_setZoneGateway_enablesAndDisablesZeroAddress() public {
        vm.startPrank(admin);
        portal.setGateway(address(0), true);
        assertTrue(portal.hasRole(address(0), Role.CallbackGateway));
        portal.setGateway(address(0), false);
        vm.stopPrank();

        assertTrue(portal.hasRole(address(0), Role.None));
    }

    function test_setZoneGateway_revertsIfNotAdmin() public {
        vm.prank(alice);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.setGateway(makeAddr("replacement gateway"), true);
    }

    function test_setAccessMode_opensAndReclosesWithoutDiscardingMembership() public {
        address outsider = makeAddr("mutable mode outsider");
        address stagedAccount = makeAddr("staged account");

        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(IZonePortal.AccountNotAllowed.selector, outsider));
        _deposit(portal, address(pathUSD), outsider, 1, bytes32(0), outsider);

        vm.expectEmit(false, false, false, true);
        emit IZonePortal.EnforcementModesUpdated(false, true);
        vm.prank(admin);
        portal.setAccessMode(false);

        vm.prank(admin);
        portal.setAllowedAccount(stagedAccount, true);

        vm.prank(pathUSDAdmin);
        pathUSD.mint(outsider, 2);
        vm.startPrank(outsider);
        pathUSD.approve(address(portal), 2);
        _deposit(portal, address(pathUSD), outsider, 1, bytes32(0), outsider);
        vm.stopPrank();

        vm.prank(admin);
        portal.setAccessMode(true);

        assertTrue(portal.isAccessEnforced());
        assertTrue(portal.hasRole(stagedAccount, Role.Account));
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(IZonePortal.AccountNotAllowed.selector, outsider));
        _deposit(portal, address(pathUSD), outsider, 1, bytes32(0), outsider);
    }

    function test_setGatewayMode_makesGatewayMembershipInertWhileOpen() public {
        address gateway = makeAddr("mutable mode gateway");

        vm.prank(admin);
        portal.setGateway(gateway, true);
        vm.prank(pathUSDAdmin);
        pathUSD.mint(gateway, 2);
        vm.startPrank(gateway);
        pathUSD.approve(address(portal), 2);
        _deposit(portal, address(pathUSD), alice, 1, bytes32(0), alice);
        vm.stopPrank();

        vm.expectEmit(false, false, false, true);
        emit IZonePortal.EnforcementModesUpdated(true, false);
        vm.prank(admin);
        portal.setGatewayMode(false);

        assertTrue(portal.hasRole(gateway, Role.CallbackGateway));
        vm.prank(gateway);
        vm.expectRevert(abi.encodeWithSelector(IZonePortal.AccountNotAllowed.selector, gateway));
        _deposit(portal, address(pathUSD), alice, 1, bytes32(0), alice);
    }

    function test_setModes_revertIfNotAdmin() public {
        vm.startPrank(alice);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.setAccessMode(false);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.setGatewayMode(false);
        vm.stopPrank();
    }

    function test_setAllowedAccount_enablesAndDisablesMembership() public {
        address account = makeAddr("managed account");

        vm.expectEmit(true, false, false, true);
        emit IZonePortal.RoleUpdated(account, Role.None, Role.Account);
        vm.prank(admin);
        portal.setAllowedAccount(account, true);
        assertTrue(portal.hasRole(account, Role.Account));

        vm.prank(admin);
        portal.setAllowedAccount(account, false);
        assertTrue(portal.hasRole(account, Role.None));
    }

    function test_setAllowedAccount_cannotOverwriteGatewayRole() public {
        vm.prank(admin);
        vm.expectRevert();
        portal.setAllowedAccount(address(zoneGateway), true);
        assertTrue(portal.hasRole(address(zoneGateway), Role.CallbackGateway));
    }

    function test_setAllowedAccount_rejectsMessenger() public {
        vm.prank(admin);
        vm.expectRevert();
        portal.setAllowedAccount(address(messenger), true);

        assertTrue(portal.hasRole(address(messenger), Role.None));
    }

    function test_setAllowedAccount_removalEventIncludesPreviousRole() public {
        vm.expectEmit(true, false, false, true);
        emit IZonePortal.RoleUpdated(bob, Role.Account, Role.None);
        vm.prank(admin);
        portal.setAllowedAccount(bob, false);
    }

    function test_setAllowedAccount_enablesAndDisablesZeroAddress() public {
        vm.startPrank(admin);
        portal.setAllowedAccount(address(0), true);
        assertTrue(portal.hasRole(address(0), Role.Account));
        portal.setAllowedAccount(address(0), false);
        vm.stopPrank();

        assertTrue(portal.hasRole(address(0), Role.None));
    }

    function test_setAllowedAccount_revertsIfNotAdmin() public {
        vm.prank(alice);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.setAllowedAccount(makeAddr("managed account"), true);
    }
    /*//////////////////////////////////////////////////////////////
                         DEPOSIT TESTS (L1 -> ZONE)
    //////////////////////////////////////////////////////////////*/

    function test_deposit_revertsForUnallowedCaller() public {
        address outsider = makeAddr("outsider");
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(IZonePortal.AccountNotAllowed.selector, outsider));
        _deposit(portal, address(pathUSD), alice, 1, bytes32(0), alice);
    }

    function test_deposit_allowsUnlistedZoneRecipient() public {
        address outsider = makeAddr("outsider");
        assertTrue(portal.hasRole(outsider, Role.None));

        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1);
        _deposit(portal, address(pathUSD), outsider, 1, bytes32(0), alice);
        vm.stopPrank();

        assertEq(pathUSD.balanceOf(address(portal)), 1);
    }

    function test_deposit_allowsCallbackGateway() public {
        pathUSD.mint(address(zoneGateway), 1);

        vm.startPrank(address(zoneGateway));
        pathUSD.approve(address(portal), 1);
        _deposit(portal, address(pathUSD), alice, 1, bytes32(0), alice);
        vm.stopPrank();

        assertEq(pathUSD.balanceOf(address(portal)), 1);
    }

    function test_deposit_revertsForUnallowedBouncebackRecipient() public {
        address outsider = makeAddr("outsider");
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IZonePortal.AccountNotAllowed.selector, outsider));
        _deposit(portal, address(pathUSD), alice, 1, bytes32(0), outsider);
    }

    function test_deposit_updatesHashChain() public {
        uint128 depositAmount = 1000e6;

        // Approve and deposit
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        bytes32 hash1 =
            _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo1"), alice);
        vm.stopPrank();

        // Verify hash chain updated
        assertEq(portal.currentDepositQueueHash(), hash1);
        assertTrue(hash1 != bytes32(0));

        // Verify tokens escrowed
        assertEq(pathUSD.balanceOf(address(portal)), depositAmount);
    }

    function test_deposit_multipleDepositsChain() public {
        uint128 amount1 = 1000e6;
        uint128 amount2 = 2000e6;

        // First deposit from alice
        vm.startPrank(alice);
        pathUSD.approve(address(portal), amount1);
        bytes32 hash1 = _deposit(portal, address(pathUSD), alice, amount1, bytes32("memo1"), alice);
        vm.stopPrank();

        // Second deposit from bob
        vm.startPrank(bob);
        pathUSD.approve(address(portal), amount2);
        bytes32 hash2 = _deposit(portal, address(pathUSD), bob, amount2, bytes32("memo2"), bob);
        vm.stopPrank();

        // Hash chain should have updated
        assertEq(portal.currentDepositQueueHash(), hash2);
        assertTrue(hash2 != hash1);

        // Verify total escrow
        assertEq(pathUSD.balanceOf(address(portal)), amount1 + amount2);
    }

    function test_deposit_enforcesOutstandingCapAcrossDepositTypes() public {
        uint64 maximum = portal.MAX_UNPROCESSED_DEPOSITS();
        uint64 maximumPublicDeposits = maximum - 20;
        assertEq(maximum, 230);
        _setEncKeyWithPoP(ENC_KEY_1);

        uint128 amount = 1;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), uint256(maximum) + 2);
        for (uint256 i; i < maximumPublicDeposits - 1; ++i) {
            _deposit(portal, address(pathUSD), bob, amount, bytes32(i), bob);
        }
        portal.deposit(address(pathUSD), amount, 0, _makeDepositPayload(), alice);

        bytes32 queueHashAtCapacity = portal.currentDepositQueueHash();
        uint256 aliceBalanceAtCapacity = pathUSD.balanceOf(alice);
        uint256 portalBalanceAtCapacity = pathUSD.balanceOf(address(portal));
        assertEq(portal.depositCount(), maximumPublicDeposits);

        vm.expectRevert(
            abi.encodeWithSelector(
                IZonePortal.DepositBlockCapacityExceeded.selector, maximumPublicDeposits
            )
        );
        _deposit(portal, address(pathUSD), bob, amount, bytes32("over cap"), bob);

        assertEq(portal.currentDepositQueueHash(), queueHashAtCapacity);
        assertEq(portal.depositCount(), maximumPublicDeposits);
        assertEq(pathUSD.balanceOf(alice), aliceBalanceAtCapacity);
        assertEq(pathUSD.balanceOf(address(portal)), portalBalanceAtCapacity);

        vm.roll(block.number + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IZonePortal.DepositBlockCapacityExceeded.selector, maximumPublicDeposits
            )
        );
        _deposit(portal, address(pathUSD), bob, amount, bytes32("next block"), bob);
        vm.stopPrank();

        assertEq(portal.depositCount(), maximumPublicDeposits);
    }

    function test_processWithdrawals_preflightsRemainingDepositCapacity() public {
        WithdrawalCapacityTestState memory state;

        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);
        _deposit(portal, address(pathUSD), alice, 1000e6, bytes32("escrow"), alice);
        vm.stopPrank();

        state.processedDepositHash = portal.currentDepositQueueHash();
        state.withdrawal = _withdrawal(
            address(pathUSD),
            alice,
            address(gasConsumingReceiver),
            1,
            bytes32("failed"),
            50_000,
            bob,
            ""
        );
        state.reserve = 20;
        state.withdrawals = new Withdrawal[](state.reserve + 1);
        for (uint256 i; i < state.reserve; ++i) {
            state.withdrawals[i] = state.withdrawal;
        }
        state.successfulWithdrawal =
            _withdrawal(address(pathUSD), alice, bob, 1, bytes32("success"), 0, alice, "");
        state.withdrawals[state.reserve] = state.successfulWithdrawal;

        for (uint256 i = state.withdrawals.length; i > 0; --i) {
            state.withdrawalHash =
                keccak256(abi.encode(state.withdrawals[i - 1], state.withdrawalHash));
        }

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("bounce-back-cap")
            }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: state.processedDepositHash,
                prevDepositNumber: 0,
                nextDepositNumber: 1
            }),
            state.withdrawalHash,
            "",
            ""
        );

        state.maximum = portal.MAX_UNPROCESSED_DEPOSITS();
        state.maximumPublicDeposits = state.maximum - uint64(state.reserve);
        vm.startPrank(alice);
        pathUSD.approve(address(portal), state.maximum);
        for (uint256 i; i < state.maximumPublicDeposits; ++i) {
            _deposit(portal, address(pathUSD), bob, 1, bytes32(i), bob);
        }
        vm.stopPrank();

        state.queueHashAtPublicCapacity = portal.currentDepositQueueHash();
        state.bobBalanceBefore = pathUSD.balanceOf(bob);

        vm.expectRevert(
            abi.encodeWithSelector(IZonePortal.DepositBlockCapacityExceeded.selector, state.maximum)
        );
        portal.processWithdrawals(state.withdrawals, bytes32(0));

        assertEq(portal.currentDepositQueueHash(), state.queueHashAtPublicCapacity);
        assertEq(portal.depositCount(), state.maximumPublicDeposits + 1);
        assertEq(pathUSD.balanceOf(bob), state.bobBalanceBefore);
        assertEq(portal.withdrawalQueueHead(), 0);
        assertEq(portal.withdrawalQueueSlot(0), state.withdrawalHash);

        Withdrawal[] memory bounceBacks = new Withdrawal[](state.reserve);
        for (uint256 i; i < state.reserve; ++i) {
            bounceBacks[i] = state.withdrawal;
        }
        state.successfulWithdrawalHash =
            keccak256(abi.encode(state.successfulWithdrawal, bytes32(0)));
        portal.processWithdrawals(bounceBacks, state.successfulWithdrawalHash);

        state.queueHashAtCapacity = portal.currentDepositQueueHash();
        assertTrue(state.queueHashAtCapacity != state.queueHashAtPublicCapacity);
        assertEq(portal.depositCount(), state.maximum + 1);
        assertEq(pathUSD.balanceOf(bob), state.bobBalanceBefore);
        assertEq(portal.withdrawalQueueHead(), 0);
        assertEq(portal.withdrawalQueueSlot(0), state.successfulWithdrawalHash);

        vm.expectRevert(
            abi.encodeWithSelector(IZonePortal.DepositBlockCapacityExceeded.selector, state.maximum)
        );
        portal.processWithdrawals(_singleWithdrawal(state.successfulWithdrawal), bytes32(0));

        assertEq(portal.currentDepositQueueHash(), state.queueHashAtCapacity);
        assertEq(portal.depositCount(), state.maximum + 1);
        assertEq(pathUSD.balanceOf(bob), state.bobBalanceBefore);
        assertEq(portal.withdrawalQueueHead(), 0);
        assertEq(portal.withdrawalQueueSlot(0), state.successfulWithdrawalHash);

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("capacity-reopened")
            }),
            DepositQueueTransition({
                prevProcessedHash: state.processedDepositHash,
                nextProcessedHash: state.queueHashAtCapacity,
                prevDepositNumber: 1,
                nextDepositNumber: state.maximum + 1
            }),
            bytes32(0),
            "",
            ""
        );

        portal.processWithdrawals(_singleWithdrawal(state.successfulWithdrawal), bytes32(0));

        assertEq(pathUSD.balanceOf(bob), state.bobBalanceBefore + state.successfulWithdrawal.amount);
        assertEq(portal.withdrawalQueueHead(), 1);
        assertEq(portal.withdrawalQueueSlot(0), bytes32(0));
    }

    function test_deposit_hashChainStructure() public {
        // Verify the hash chain is built correctly: newest deposits wrap the outside
        uint128 amount = 1000e6;

        vm.startPrank(alice);
        pathUSD.approve(address(portal), amount * 3);

        // Initial state: currentDepositQueueHash = 0
        bytes32 initialHash = portal.currentDepositQueueHash();
        assertEq(initialHash, bytes32(0));

        // After deposit 1
        _deposit(portal, address(pathUSD), alice, amount, bytes32("d1"), alice);
        bytes32 hash1 = portal.currentDepositQueueHash();

        // After deposit 2: hash2 = keccak256(abi.encode(message2, hash1))
        _deposit(portal, address(pathUSD), alice, amount, bytes32("d2"), alice);
        bytes32 hash2 = portal.currentDepositQueueHash();

        // After deposit 3: hash3 = keccak256(abi.encode(message3, hash2))
        _deposit(portal, address(pathUSD), alice, amount, bytes32("d3"), alice);
        bytes32 hash3 = portal.currentDepositQueueHash();

        vm.stopPrank();

        // Each hash should be different (chain is growing)
        assertTrue(hash1 != hash2);
        assertTrue(hash2 != hash3);
        assertTrue(hash1 != hash3);
    }

    function test_deposit_doesNotInspectEncryptedMintRecipientPolicy() public {
        uint128 depositAmount = 1000e6;

        address[] memory senderAccounts = new address[](2);
        senderAccounts[0] = alice;
        senderAccounts[1] = address(portal);
        uint64 senderPolicyId = registry.createPolicyWithAccounts(
            sequencer, ITIP403Registry.PolicyType.WHITELIST, senderAccounts
        );

        address[] memory recipientAccounts = new address[](3);
        recipientAccounts[0] = alice;
        recipientAccounts[1] = address(portal);
        recipientAccounts[2] = bob;
        uint64 recipientPolicyId = registry.createPolicyWithAccounts(
            sequencer, ITIP403Registry.PolicyType.WHITELIST, recipientAccounts
        );

        address[] memory mintRecipientAccounts = new address[](1);
        mintRecipientAccounts[0] = charlie;
        uint64 mintRecipientPolicyId = registry.createPolicyWithAccounts(
            sequencer, ITIP403Registry.PolicyType.WHITELIST, mintRecipientAccounts
        );

        uint64 compoundPolicyId =
            registry.createCompoundPolicy(senderPolicyId, recipientPolicyId, mintRecipientPolicyId);
        vm.prank(pathUSDAdmin);
        pathUSD.changeTransferPolicyId(compoundPolicyId);

        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        bytes32 depositHash =
            _deposit(portal, address(pathUSD), bob, depositAmount, bytes32("memo"), bob);
        vm.stopPrank();

        // The mint recipient is encrypted, so its mint policy is enforced only after decryption
        // on the zone. The L1 portal can validate the public refund recipient but must enqueue the
        // opaque recipient payload.
        assertEq(portal.depositCount(), 1);
        assertEq(portal.currentDepositQueueHash(), depositHash);
        assertEq(pathUSD.balanceOf(address(portal)), depositAmount);
    }

    function test_deposit_revertsWhenBouncebackRecipientBlocked() public {
        uint128 depositAmount = 1000e6;

        address[] memory accounts = new address[](2);
        accounts[0] = alice;
        accounts[1] = address(portal);
        uint64 policyId = registry.createPolicyWithAccounts(
            sequencer, ITIP403Registry.PolicyType.WHITELIST, accounts
        );
        vm.prank(pathUSDAdmin);
        pathUSD.changeTransferPolicyId(policyId);

        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), bob);
        vm.stopPrank();
    }

    function test_deposit_allowsCompoundPolicyMintRecipient() public {
        uint128 depositAmount = 1000e6;

        address[] memory senderAccounts = new address[](2);
        senderAccounts[0] = alice;
        senderAccounts[1] = address(portal);
        uint64 senderPolicyId = registry.createPolicyWithAccounts(
            sequencer, ITIP403Registry.PolicyType.WHITELIST, senderAccounts
        );

        address[] memory recipientAccounts = new address[](3);
        recipientAccounts[0] = alice;
        recipientAccounts[1] = address(portal);
        recipientAccounts[2] = bob;
        uint64 recipientPolicyId = registry.createPolicyWithAccounts(
            sequencer, ITIP403Registry.PolicyType.WHITELIST, recipientAccounts
        );

        address[] memory mintRecipientAccounts = new address[](1);
        mintRecipientAccounts[0] = bob;
        uint64 mintRecipientPolicyId = registry.createPolicyWithAccounts(
            sequencer, ITIP403Registry.PolicyType.WHITELIST, mintRecipientAccounts
        );

        uint64 compoundPolicyId =
            registry.createCompoundPolicy(senderPolicyId, recipientPolicyId, mintRecipientPolicyId);
        vm.prank(pathUSDAdmin);
        pathUSD.changeTransferPolicyId(compoundPolicyId);

        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        bytes32 depositHash =
            _deposit(portal, address(pathUSD), bob, depositAmount, bytes32("memo"), bob);
        vm.stopPrank();

        assertEq(portal.currentDepositQueueHash(), depositHash);
        assertEq(pathUSD.balanceOf(address(portal)), depositAmount);
    }

    /*//////////////////////////////////////////////////////////////
                       BATCH SUBMISSION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_submitBatch_updatesState() public {
        // Setup: make a deposit
        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        bytes32 depositHash =
            _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), alice);
        vm.stopPrank();

        // Submit a batch (as sequencer)
        bytes32 newStateRoot = keccak256("newState");

        // Advance a block so the history precompile can return a hash
        vm.roll(block.number + 1);

        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: newStateRoot }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHash,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            bytes32(0),
            "",
            ""
        );

        // Verify state updated
        assertEq(portal.blockHash(), newStateRoot);
        assertEq(portal.withdrawalBatchIndex(), 1);
        assertEq(portal.lastSyncedTempoBlockNumber(), uint64(block.number - 1));
    }

    function test_submitBatch_emitsAssignedWithdrawalQueueIndex() public {
        vm.roll(block.number + 1);

        // Batch with no withdrawals: no queue slot consumed, sentinel emitted.
        vm.expectEmit(true, true, false, true);
        emit IZonePortal.BatchSubmitted(
            1, NO_QUEUE_INDEX, bytes32(0), keccak256("state1"), bytes32(0), 0, 0
        );
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state1")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: bytes32(0),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            bytes32(0),
            "",
            ""
        );

        // Batch with withdrawals: assigned the current logical tail (index 0).
        Withdrawal memory w =
            _withdrawal(address(pathUSD), alice, bob, 500e6, bytes32(0), 0, alice, "");
        bytes32 withdrawalHash = keccak256(abi.encode(w, bytes32(0)));

        vm.expectEmit(true, true, false, true);
        emit IZonePortal.BatchSubmitted(2, 0, bytes32(0), keccak256("state2"), withdrawalHash, 0, 0);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: keccak256("state1"), nextBlockHash: keccak256("state2")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: bytes32(0),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            withdrawalHash,
            "",
            ""
        );
        assertEq(portal.withdrawalQueueTail(), 1);
    }

    function test_submitBatch_emitsMonotonicLogicalWithdrawalQueueIndex() public {
        Withdrawal memory firstWithdrawal =
            _withdrawal(address(pathUSD), alice, bob, 0, bytes32(0), 0, alice, "");
        bytes32 firstHash = keccak256(abi.encode(firstWithdrawal, bytes32(0)));
        bytes32 previousState = portal.blockHash();

        vm.roll(block.number + 1);

        for (uint256 i = 0; i < TEST_QUEUE_LENGTH; i++) {
            bytes32 batchState = keccak256(abi.encode("state", i));
            bytes32 withdrawalHash = i == 0 ? firstHash : keccak256(abi.encode("batch", i));
            _submitBatch(
                portal,
                uint64(block.number - 1),
                0,
                BlockTransition({ prevBlockHash: previousState, nextBlockHash: batchState }),
                DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: bytes32(0),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
                withdrawalHash,
                "",
                ""
            );
            previousState = batchState;
        }

        portal.processWithdrawals(_singleWithdrawal(firstWithdrawal), bytes32(0));

        bytes32 nextState = keccak256("next-state");
        bytes32 nextHash = keccak256("next-batch");
        vm.expectEmit(true, true, false, true);
        emit IZonePortal.BatchSubmitted(
            uint64(TEST_QUEUE_LENGTH + 1), TEST_QUEUE_LENGTH, bytes32(0), nextState, nextHash, 0, 0
        );
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: previousState, nextBlockHash: nextState }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32(0),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            nextHash,
            "",
            ""
        );

        assertEq(portal.withdrawalQueueHead(), 1);
        assertEq(portal.withdrawalQueueTail(), TEST_QUEUE_LENGTH + 1);
        assertEq(portal.withdrawalQueueSlot(0), bytes32(0));
        assertEq(portal.withdrawalQueueSlot(TEST_QUEUE_LENGTH), nextHash);
    }

    function test_submitBatch_revertsOnPrevBlockHashMismatch() public {
        // Advance a block so the history precompile can return a hash
        vm.roll(block.number + 1);

        vm.expectRevert(IZonePortal.InvalidProof.selector);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: keccak256("wrong"), nextBlockHash: keccak256("state")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: bytes32(0),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            bytes32(0),
            "",
            ""
        );
    }

    function test_submitBatch_revertsIfNotSequencer() public {
        // Advance a block so the history precompile can return a hash
        vm.roll(block.number + 1);

        bytes32 prevBlockHash = portal.blockHash();
        bytes32 nextStateRoot = keccak256("state");
        vm.prank(alice); // Not sequencer
        vm.expectRevert(IZonePortal.NotSequencer.selector);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: prevBlockHash, nextBlockHash: nextStateRoot }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32(0),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            bytes32(0),
            "",
            ""
        );
    }

    function test_submitBatch_revertsOnInvalidProof() public {
        vm.mockCall(
            ZONE_VERIFIER_ADDRESS,
            abi.encodeWithSelector(IVerifier.verify.selector),
            abi.encode(false)
        );

        // Advance a block so the history precompile can return a hash
        vm.roll(block.number + 1);

        bytes32 prevBlockHash = portal.blockHash();
        bytes32 nextStateRoot = keccak256("state");
        vm.expectRevert(IZonePortal.InvalidProof.selector);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: prevBlockHash, nextBlockHash: nextStateRoot }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32(0),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            bytes32(0),
            "",
            ""
        );
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWAL QUEUE TESTS (ZONE -> TEMPO)
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalQueue_simpleWithdrawal() public {
        // Setup: deposit funds to portal for withdrawal
        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), alice);
        vm.stopPrank();

        // Create a withdrawal and add to queue via batch
        Withdrawal memory w =
            _withdrawal(address(pathUSD), alice, bob, 500e6, bytes32(0), 0, alice, "");

        // Build withdrawal hash (oldest = outermost, zero-terminated)
        bytes32 withdrawalHash = keccak256(abi.encode(w, bytes32(0)));

        // Advance a block so the history precompile can return a hash
        vm.roll(block.number + 1);

        // Submit batch that adds withdrawal to slot 0
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("stateWithWithdrawal")
            }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: portal.currentDepositQueueHash(),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            withdrawalHash,
            "",
            ""
        );

        // Slot 0 should now have the withdrawal, tail advanced to 1
        assertEq(portal.withdrawalQueueSlot(0), withdrawalHash);
        assertEq(portal.withdrawalQueueHead(), 0);
        assertEq(portal.withdrawalQueueTail(), 1);

        // Process the withdrawal
        uint256 bobBalanceBefore = pathUSD.balanceOf(bob);
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0)); // 0 means last item in slot

        // Bob should have received funds
        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore + 500e6);
        // Slot should be deleted and head advanced to 1.
        assertEq(portal.withdrawalQueueSlot(0), bytes32(0));
        assertEq(portal.withdrawalQueueHead(), 1);
    }

    function test_withdrawalQueue_multipleWithdrawalsInBatch() public {
        // Setup: deposit funds
        uint128 depositAmount = 2000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), alice);
        vm.stopPrank();

        // Create two withdrawals in the same batch
        Withdrawal memory w1 =
            _withdrawal(address(pathUSD), alice, bob, 300e6, bytes32(0), 0, alice, "");
        Withdrawal memory w2 =
            _withdrawal(address(pathUSD), alice, charlie, 400e6, bytes32(0), 0, alice, "");

        // Build queue: w1 is oldest (outermost), w2 is newest (innermost terminates at zero)
        bytes32 innerHash = keccak256(abi.encode(w2, bytes32(0)));
        bytes32 batchQueueHash = keccak256(abi.encode(w1, innerHash));

        // Advance a block so the history precompile can return a hash
        vm.roll(block.number + 1);

        // Submit batch adding both withdrawals to slot 0
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state1")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: portal.currentDepositQueueHash(),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            batchQueueHash,
            "",
            ""
        );
        assertEq(portal.withdrawalQueueSlot(0), batchQueueHash);
        assertEq(portal.withdrawalQueueTail(), 1);

        // Process w1 (oldest)
        uint256 bobBalanceBefore = pathUSD.balanceOf(bob);
        portal.processWithdrawals(_singleWithdrawal(w1), innerHash);
        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore + 300e6);

        // Slot 0 should now have w2's hash, head still at 0
        assertEq(portal.withdrawalQueueSlot(0), innerHash);
        assertEq(portal.withdrawalQueueHead(), 0);

        // Process w2 (last in slot)
        uint256 charlieBalanceBefore = pathUSD.balanceOf(charlie);
        portal.processWithdrawals(_singleWithdrawal(w2), bytes32(0)); // 0 = last item
        assertEq(pathUSD.balanceOf(charlie), charlieBalanceBefore + 400e6);

        // Slot 0 cleared, head advanced
        assertEq(portal.withdrawalQueueSlot(0), bytes32(0));
        assertEq(portal.withdrawalQueueHead(), 1);
    }

    function test_processWithdrawals_processesQueueInOrder() public {
        uint128 depositAmount = 1200e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), alice);
        vm.stopPrank();

        Withdrawal memory w1 =
            _withdrawal(address(pathUSD), alice, bob, 300e6, bytes32(0), 0, alice, "");
        Withdrawal memory w2 =
            _withdrawal(address(pathUSD), alice, charlie, 400e6, bytes32(0), 0, alice, "");
        Withdrawal memory w3 =
            _withdrawal(address(pathUSD), alice, bob, 500e6, bytes32(0), 0, alice, "");

        bytes32 remainingQueue = keccak256(abi.encode(w3, bytes32(0)));
        bytes32 innerHash = keccak256(abi.encode(w2, remainingQueue));
        bytes32 batchQueueHash = keccak256(abi.encode(w1, innerHash));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state1")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: portal.currentDepositQueueHash(),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            batchQueueHash,
            "",
            ""
        );

        Withdrawal[] memory withdrawals = new Withdrawal[](2);
        withdrawals[0] = w1;
        withdrawals[1] = w2;
        uint256 bobBalanceBefore = pathUSD.balanceOf(bob);
        uint256 charlieBalanceBefore = pathUSD.balanceOf(charlie);
        portal.processWithdrawals(withdrawals, remainingQueue);

        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore + 300e6);
        assertEq(pathUSD.balanceOf(charlie), charlieBalanceBefore + 400e6);
        assertEq(portal.withdrawalQueueSlot(0), remainingQueue);
        assertEq(portal.withdrawalQueueHead(), 0);

        portal.processWithdrawals(_singleWithdrawal(w3), bytes32(0));
        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore + 800e6);
        assertEq(portal.withdrawalQueueSlot(0), bytes32(0));
        assertEq(portal.withdrawalQueueHead(), 1);
    }

    function test_processWithdrawals_revertsIfNotSequencer() public {
        Withdrawal[] memory withdrawals = new Withdrawal[](0);

        vm.prank(alice);
        vm.expectRevert(IZonePortal.NotSequencer.selector);
        portal.processWithdrawals(withdrawals, bytes32(0));
    }

    function test_withdrawalQueue_multipleBatches() public {
        // Test that multiple batches get their own slots
        uint128 depositAmount = 3000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), alice);
        vm.stopPrank();

        // Batch 1: withdrawal to bob
        Withdrawal memory w1 =
            _withdrawal(address(pathUSD), alice, bob, 500e6, bytes32(0), 0, alice, "");
        bytes32 w1Hash = keccak256(abi.encode(w1, bytes32(0)));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state1")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: portal.currentDepositQueueHash(),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            w1Hash,
            "",
            ""
        );

        // Batch 2: withdrawal to charlie
        Withdrawal memory w2 =
            _withdrawal(address(pathUSD), alice, charlie, 600e6, bytes32(0), 0, alice, "");
        bytes32 w2Hash = keccak256(abi.encode(w2, bytes32(0)));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state2")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: portal.currentDepositQueueHash(),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            w2Hash,
            "",
            ""
        );

        // Verify slots
        assertEq(portal.withdrawalQueueSlot(0), w1Hash);
        assertEq(portal.withdrawalQueueSlot(1), w2Hash);
        assertEq(portal.withdrawalQueueHead(), 0);
        assertEq(portal.withdrawalQueueTail(), 2);

        // Process w1 from slot 0
        portal.processWithdrawals(_singleWithdrawal(w1), bytes32(0));
        assertEq(portal.withdrawalQueueHead(), 1);

        // Process w2 from slot 1
        portal.processWithdrawals(_singleWithdrawal(w2), bytes32(0));
        assertEq(portal.withdrawalQueueHead(), 2);
    }

    function test_withdrawalQueue_batchWithNoWithdrawals() public {
        // Test that batches with no withdrawals don't affect the queue
        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), alice);
        vm.stopPrank();

        uint256 tailBefore = portal.withdrawalQueueTail();

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state1")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: portal.currentDepositQueueHash(),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            bytes32(0), // No withdrawals
            "",
            ""
        );

        // Tail should not have advanced
        assertEq(portal.withdrawalQueueTail(), tailBefore);
    }

    /*//////////////////////////////////////////////////////////////
                     CALLBACK & BOUNCE-BACK TESTS
    //////////////////////////////////////////////////////////////*/

    function _callbackData(GatewayFlow flow) internal view returns (bytes memory) {
        return _callbackData(flow, alice, 0);
    }

    function _openPortalModes() internal {
        vm.startPrank(admin);
        portal.setAccessMode(false);
        portal.setGatewayMode(false);
        vm.stopPrank();
    }

    function test_withdrawal_withCallback() public {
        _openPortalModes();

        // Fund portal
        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), alice);
        vm.stopPrank();

        // Create withdrawal with callback
        Withdrawal memory w = _withdrawal(
            address(pathUSD),
            alice,
            address(withdrawalReceiver),
            500e6,
            bytes32(0),
            5_000_000,
            alice,
            "callback_data"
        );
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        // Advance a block so the history precompile can return a hash
        vm.roll(block.number + 1);

        // Submit batch adding withdrawal
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: portal.currentDepositQueueHash(),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            wHash,
            "",
            ""
        );

        // Process withdrawal (0 = last item in slot)
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        // Receiver should have gotten funds and callback
        assertEq(pathUSD.balanceOf(address(withdrawalReceiver)), 500e6);
        assertEq(withdrawalReceiver.lastSenderTag(), _senderTag(alice));
        assertEq(withdrawalReceiver.lastAmount(), 500e6);
        assertEq(withdrawalReceiver.lastCallbackData(), "callback_data");
    }

    function _callbackData(
        GatewayFlow flow,
        address tempoRefundRecipient,
        uint128 minOutputAmount
    )
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(
            GatewayCallbackData({
                flow: flow,
                outputToken: address(pathUSD),
                keyIndex: 0,
                encrypted: _makeDepositPayload(),
                minVaultAssets: 0,
                minVaultShares: 0,
                minOutputAmount: minOutputAmount,
                actionId: bytes32(0),
                tempoRefundRecipient: tempoRefundRecipient
            })
        );
    }

    function _unsupportedFlowCallback() internal view returns (bytes memory data) {
        data = _callbackData(GatewayFlow.Deposit);
        assembly {
            mstore(add(data, 0x40), 2)
        }
    }

    function test_zoneGateway_rejectsUnauthorizedMessenger() public {
        vm.expectRevert(MockZoneGateway.UnauthorizedMessenger.selector);
        zoneGateway.onWithdrawalReceived(
            testZoneId,
            address(portal),
            bytes32(0),
            address(pathUSD),
            1,
            _callbackData(GatewayFlow.Deposit)
        );
    }

    function test_zoneGateway_rejectsWhenNoLongerRegistered() public {
        vm.prank(admin);
        portal.setGateway(address(zoneGateway), false);

        vm.prank(address(messenger));
        vm.expectRevert(MockZoneGateway.UnregisteredGateway.selector);
        zoneGateway.onWithdrawalReceived(
            testZoneId,
            address(portal),
            bytes32(0),
            address(pathUSD),
            1,
            _callbackData(GatewayFlow.Deposit)
        );
    }

    function test_zoneGateway_rejectsMalformedCallback() public {
        vm.prank(address(messenger));
        vm.expectRevert();
        zoneGateway.onWithdrawalReceived(
            testZoneId, address(portal), bytes32(0), address(pathUSD), 1, hex"01"
        );
    }

    function test_zoneGateway_rejectsUnsupportedFlow() public {
        vm.prank(address(messenger));
        vm.expectRevert();
        zoneGateway.onWithdrawalReceived(
            testZoneId, address(portal), bytes32(0), address(pathUSD), 1, _unsupportedFlowCallback()
        );
    }

    function test_zoneGateway_rejectsUnallowedPayloadBounceback() public {
        address outsider = makeAddr("gateway bounceback outsider");
        vm.prank(address(messenger));
        vm.expectRevert(abi.encodeWithSelector(IZonePortal.AccountNotAllowed.selector, outsider));
        zoneGateway.onWithdrawalReceived(
            testZoneId,
            address(portal),
            bytes32(0),
            address(pathUSD),
            1,
            _callbackData(GatewayFlow.Deposit, outsider, 0)
        );
    }

    function test_zoneGateway_enforcesMinOutputAmount() public {
        vm.prank(address(messenger));
        vm.expectRevert(
            abi.encodeWithSelector(MockZoneGateway.InsufficientOutputAmount.selector, 1, 2)
        );
        zoneGateway.onWithdrawalReceived(
            testZoneId,
            address(portal),
            bytes32(0),
            address(pathUSD),
            1,
            _callbackData(GatewayFlow.Redeem, alice, 2)
        );
    }

    function _enqueueWithdrawal(Withdrawal memory withdrawal) internal {
        bytes32 withdrawalHash = keccak256(abi.encode(withdrawal, bytes32(0)));
        vm.roll(block.number + 1);

        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("callback state")
            }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: portal.currentDepositQueueHash(),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            withdrawalHash,
            "",
            ""
        );
    }

    function _fundCallbackWithdrawal(uint128 amount) internal {
        _setEncKeyWithPoP(ENC_KEY_1);
        vm.startPrank(alice);
        pathUSD.approve(address(portal), amount);
        _deposit(portal, address(pathUSD), alice, amount, bytes32("callback funds"), alice);
        vm.stopPrank();
    }

    function test_callbackWithdrawal_returnsFundsAndChangesDepositQueue() public {
        uint128 amount = 500e6;
        _fundCallbackWithdrawal(amount);
        assertTrue(portal.hasRole(address(zoneGateway), Role.CallbackGateway));

        Withdrawal memory withdrawal = _withdrawal(
            address(pathUSD),
            alice,
            address(zoneGateway),
            amount,
            bytes32(0),
            2_000_000,
            alice,
            _callbackData(GatewayFlow.Deposit)
        );
        _enqueueWithdrawal(withdrawal);
        bytes32 depositHashBefore = portal.currentDepositQueueHash();

        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));

        assertNotEq(portal.currentDepositQueueHash(), depositHashBefore);
        assertEq(portal.withdrawalQueueHead(), portal.withdrawalQueueTail());
        assertEq(pathUSD.balanceOf(address(zoneGateway)), 0);
        assertEq(pathUSD.balanceOf(address(portal)), amount);
    }

    function test_callbackWithdrawal_usesReservedCapacityAtPublicCap() public {
        uint128 amount = 500e6;
        _fundCallbackWithdrawal(amount);

        bytes memory callbackData = _callbackData(GatewayFlow.Deposit);
        Withdrawal memory withdrawal = _withdrawal(
            address(pathUSD),
            alice,
            address(zoneGateway),
            amount,
            bytes32(0),
            2_000_000,
            alice,
            callbackData
        );
        _enqueueWithdrawal(withdrawal);

        uint64 publicCapacity = portal.MAX_UNPROCESSED_DEPOSITS() - 20;
        uint64 outstanding = portal.depositCount() - portal.lastProcessedDepositNumber();

        vm.startPrank(alice);
        pathUSD.approve(address(portal), publicCapacity - outstanding);
        for (uint256 i; i < publicCapacity - outstanding; ++i) {
            _deposit(portal, address(pathUSD), bob, 1, bytes32(i), bob);
        }
        vm.stopPrank();

        assertEq(portal.depositCount() - portal.lastProcessedDepositNumber(), publicCapacity);

        bytes32 queueHashBefore = portal.currentDepositQueueHash();
        GatewayCallbackData memory callback = abi.decode(callbackData, (GatewayCallbackData));
        Deposit memory expectedDeposit = Deposit({
            token: address(pathUSD),
            sender: address(zoneGateway),
            amount: amount - portal.calculateDepositFee(),
            tempoRefundRecipient: alice,
            keyIndex: callback.keyIndex,
            encrypted: callback.encrypted
        });

        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));

        assertEq(
            portal.currentDepositQueueHash(),
            DepositQueueLib.enqueueDeposit(queueHashBefore, expectedDeposit)
        );
        assertEq(portal.depositCount() - portal.lastProcessedDepositNumber(), publicCapacity + 1);
    }

    function test_callbackWithdrawal_failureBouncesAndAdvancesQueue() public {
        uint128 amount = 500e6;
        _fundCallbackWithdrawal(amount);
        zoneGateway.setReturnToZone(false);

        Withdrawal memory withdrawal = _withdrawal(
            address(pathUSD),
            alice,
            address(zoneGateway),
            amount,
            bytes32(0),
            2_000_000,
            alice,
            _callbackData(GatewayFlow.Redeem)
        );
        _enqueueWithdrawal(withdrawal);
        bytes32 depositHashBefore = portal.currentDepositQueueHash();

        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));

        assertEq(portal.withdrawalQueueHead(), portal.withdrawalQueueTail());
        assertNotEq(portal.currentDepositQueueHash(), depositHashBefore);
        assertEq(pathUSD.balanceOf(address(zoneGateway)), 0);
        assertEq(pathUSD.balanceOf(address(portal)), amount);
    }

    function test_callbackWithdrawal_malformedPayloadBouncesAndAdvancesQueue() public {
        uint128 amount = 500e6;
        _fundCallbackWithdrawal(amount);
        Withdrawal memory withdrawal = _withdrawal(
            address(pathUSD),
            alice,
            address(zoneGateway),
            amount,
            bytes32(0),
            2_000_000,
            alice,
            hex"01"
        );
        _enqueueWithdrawal(withdrawal);
        bytes32 depositHashBefore = portal.currentDepositQueueHash();

        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));

        assertEq(portal.withdrawalQueueHead(), portal.withdrawalQueueTail());
        assertNotEq(portal.currentDepositQueueHash(), depositHashBefore);
    }

    function test_plainWithdrawal_bouncesAndAdvancesForCallbackTarget() public {
        uint128 amount = 500e6;
        _fundCallbackWithdrawal(amount);
        Withdrawal memory withdrawal = _withdrawal(
            address(pathUSD), alice, address(zoneGateway), amount, bytes32(0), 0, alice, ""
        );
        _enqueueWithdrawal(withdrawal);
        bytes32 depositHashBefore = portal.currentDepositQueueHash();

        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));

        assertEq(portal.withdrawalQueueHead(), portal.withdrawalQueueTail());
        assertNotEq(portal.currentDepositQueueHash(), depositHashBefore);
        assertEq(pathUSD.balanceOf(address(zoneGateway)), 0);
        assertEq(pathUSD.balanceOf(address(portal)), amount);
    }

    function test_plainWithdrawal_bouncesAndAdvancesWhenRecipientRevoked() public {
        uint128 amount = 500e6;
        _fundCallbackWithdrawal(amount);
        Withdrawal memory withdrawal =
            _withdrawal(address(pathUSD), alice, bob, amount, bytes32(0), 0, alice, "");
        _enqueueWithdrawal(withdrawal);
        bytes32 depositHashBefore = portal.currentDepositQueueHash();
        uint256 bobBalanceBefore = pathUSD.balanceOf(bob);
        vm.prank(admin);
        portal.setAllowedAccount(bob, false);

        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));

        assertEq(portal.withdrawalQueueHead(), portal.withdrawalQueueTail());
        assertNotEq(portal.currentDepositQueueHash(), depositHashBefore);
        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore);
        assertEq(pathUSD.balanceOf(address(portal)), amount);
    }

    function test_callbackWithdrawal_bouncesAndAdvancesWhenGatewayRevoked() public {
        uint128 amount = 500e6;
        _fundCallbackWithdrawal(amount);
        Withdrawal memory withdrawal = _withdrawal(
            address(pathUSD),
            alice,
            address(zoneGateway),
            amount,
            bytes32(0),
            2_000_000,
            alice,
            _callbackData(GatewayFlow.Deposit)
        );
        _enqueueWithdrawal(withdrawal);
        bytes32 depositHashBefore = portal.currentDepositQueueHash();
        vm.prank(admin);
        portal.setGateway(address(zoneGateway), false);

        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));

        assertEq(portal.withdrawalQueueHead(), portal.withdrawalQueueTail());
        assertNotEq(portal.currentDepositQueueHash(), depositHashBefore);
        assertEq(pathUSD.balanceOf(address(zoneGateway)), 0);
        assertEq(pathUSD.balanceOf(address(portal)), amount);
    }

    function test_depositBounceBack_parksRefundWhenRecipientRevoked() public {
        vm.fee(0);
        uint128 amount = 500e6;
        _fundCallbackWithdrawal(amount);
        Withdrawal memory withdrawal = Withdrawal({
            token: address(pathUSD),
            senderTag: keccak256(abi.encodePacked(address(0), bytes32(0))),
            to: alice,
            amount: amount,
            memo: bytes32(0),
            gasLimit: 0,
            fallbackNonce: 0,
            callbackData: "",
            encryptedSender: ""
        });
        _enqueueWithdrawal(withdrawal);
        vm.prank(admin);
        portal.setAllowedAccount(alice, false);

        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));

        assertEq(portal.withdrawalQueueHead(), portal.withdrawalQueueTail());
        assertEq(portal.refunds(address(pathUSD), alice), amount);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IZonePortal.AccountNotAllowed.selector, alice));
        portal.claimRefund(address(pathUSD));

        vm.prank(admin);
        portal.setAllowedAccount(alice, true);
        vm.prank(alice);
        assertEq(portal.claimRefund(address(pathUSD)), amount);
    }

    function test_withdrawal_bounceBackOnTransferRevert_noCallback() public {
        // Fund portal
        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), alice);
        vm.stopPrank();

        bytes32 depositHashBefore = portal.currentDepositQueueHash();
        uint256 portalBalanceBefore = pathUSD.balanceOf(address(portal));
        uint256 bobBalanceBefore = pathUSD.balanceOf(bob);

        // Pause token to force transfer revert
        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_PAUSE_ROLE, pathUSDAdmin);
        pathUSD.pause();
        vm.stopPrank();

        Withdrawal memory w =
            _withdrawal(address(pathUSD), alice, bob, 500e6, bytes32(0), 0, alice, "");
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        // Advance a block so the history precompile can return a hash
        vm.roll(block.number + 1);

        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: depositHashBefore,
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            wHash,
            "",
            ""
        );

        // Process withdrawal - should bounce back due to transfer revert
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        // No transfer should have happened
        assertEq(pathUSD.balanceOf(address(portal)), portalBalanceBefore);
        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore);
        assertTrue(portal.currentDepositQueueHash() != depositHashBefore);
    }

    /*//////////////////////////////////////////////////////////////
                     INVALID WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_processWithdrawal_revertsIfEmpty() public {
        Withdrawal memory w =
            _withdrawal(address(pathUSD), alice, bob, 100e6, bytes32(0), 0, alice, "");

        vm.expectRevert(WithdrawalQueueLib.InvalidWithdrawalProof.selector);
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));
    }

    function test_processWithdrawal_revertsIfInvalid() public {
        // Fund and create withdrawal
        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), alice);
        vm.stopPrank();

        Withdrawal memory w =
            _withdrawal(address(pathUSD), alice, bob, 500e6, bytes32(0), 0, alice, "");
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        // Advance a block so the history precompile can return a hash
        vm.roll(block.number + 1);

        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: portal.currentDepositQueueHash(),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            wHash,
            "",
            ""
        );

        // Try to process with wrong withdrawal data
        Withdrawal memory wrongW =
            _withdrawal(address(pathUSD), alice, charlie, 500e6, bytes32(0), 0, alice, "");

        vm.expectRevert(WithdrawalQueueLib.InvalidWithdrawalProof.selector);
        portal.processWithdrawals(_singleWithdrawal(wrongW), bytes32(0));
    }

    function test_processWithdrawal_revertsIfNotSequencer() public {
        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), alice);
        vm.stopPrank();

        Withdrawal memory w =
            _withdrawal(address(pathUSD), alice, bob, 500e6, bytes32(0), 0, alice, "");
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        // Advance a block so the history precompile can return a hash
        vm.roll(block.number + 1);

        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: portal.currentDepositQueueHash(),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            wHash,
            "",
            ""
        );

        vm.prank(alice); // Not sequencer
        vm.expectRevert(IZonePortal.NotSequencer.selector);
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));
    }

    function test_processWithdrawal_revertsOnSequencerCallbackReentrancy() public {
        _openPortalModes();

        ReentrantWithdrawalReceiver receiver = new ReentrantWithdrawalReceiver();

        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), alice);
        vm.stopPrank();

        Withdrawal memory nested =
            _withdrawal(address(pathUSD), alice, bob, 200e6, bytes32(0), 0, alice, "");
        Withdrawal memory outer = _withdrawal(
            address(pathUSD),
            alice,
            address(receiver),
            300e6,
            bytes32(0),
            500_000,
            alice,
            abi.encode(nested, bytes32(0))
        );

        bytes32 remainingQueue = keccak256(abi.encode(nested, bytes32(0)));
        bytes32 withdrawalQueue = keccak256(abi.encode(outer, remainingQueue));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("reentrancy")
            }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: portal.currentDepositQueueHash(),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            withdrawalQueue,
            "",
            ""
        );

        // Keep the active leader in the set; dropping it is rejected (ActiveLeaderRemoved).
        address[] memory receiverSet = new address[](2);
        receiverSet[0] = address(receiver);
        receiverSet[1] = sequencer;
        vm.prank(admin);
        portal.setSequencerSet(receiverSet, 1);

        uint256 bobBalanceBefore = pathUSD.balanceOf(bob);
        vm.prank(address(receiver));
        portal.processWithdrawals(_singleWithdrawal(outer), remainingQueue);

        assertFalse(receiver.nestedCallSucceeded());
        assertEq(receiver.nestedRevertSelector(), IZonePortal.ReentrantWithdrawal.selector);
        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore);
        assertEq(portal.withdrawalQueueSlot(0), remainingQueue);

        vm.prank(address(receiver));
        portal.processWithdrawals(_singleWithdrawal(nested), bytes32(0));
        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore + nested.amount);
    }

    /*//////////////////////////////////////////////////////////////
                         DEPOSIT CHAIN TESTS
    //////////////////////////////////////////////////////////////*/

    function test_depositChain_singleSlotDesign() public {
        // Test the simplified single-slot deposit design:
        // currentDepositQueueHash: head of chain (new deposits land here)
        // The zone tracks its own processedDepositQueueHash in EVM state.
        // The proof reads currentDepositQueueHash from Tempo state to validate equality.

        // Initial state: zero
        assertEq(portal.currentDepositQueueHash(), bytes32(0));

        // Make deposits
        vm.startPrank(alice);
        pathUSD.approve(address(portal), 3000e6);
        bytes32 h1 = _deposit(portal, address(pathUSD), alice, 1000e6, bytes32("d1"), alice);
        bytes32 h2 = _deposit(portal, address(pathUSD), alice, 1000e6, bytes32("d2"), alice);
        vm.stopPrank();

        // currentDepositQueueHash should be h2 (latest)
        assertEq(portal.currentDepositQueueHash(), h2);

        // Advance a block so the history precompile can return a hash
        vm.roll(block.number + 1);

        // Submit batch - portal no longer tracks processed, just updates lastSyncedTempoBlockNumber
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state1")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: h1,
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            bytes32(0),
            "",
            ""
        );

        // After batch: currentDepositQueueHash unchanged, lastSyncedTempoBlockNumber updated
        assertEq(portal.currentDepositQueueHash(), h2);
        assertEq(portal.lastSyncedTempoBlockNumber(), uint64(block.number - 1));

        // New deposit arrives
        vm.startPrank(alice);
        bytes32 h3 = _deposit(portal, address(pathUSD), alice, 1000e6, bytes32("d3"), alice);
        vm.stopPrank();

        // currentDepositQueueHash updated
        assertEq(portal.currentDepositQueueHash(), h3);
    }

    /*//////////////////////////////////////////////////////////////
                      BATCH SUBMISSION VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_submitBatch_revertsIfTempoBlockNumberInFuture() public {
        vm.roll(block.number + 10);

        bytes32 prevBlockHash = portal.blockHash();
        vm.expectRevert(IZonePortal.InvalidTempoBlockNumber.selector);
        _submitBatch(
            portal,
            uint64(block.number + 1), // In future
            0,
            BlockTransition({ prevBlockHash: prevBlockHash, nextBlockHash: keccak256("state") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32(0),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            bytes32(0),
            "",
            ""
        );
    }

    function test_submitBatch_revertsIfTempoBlockNumberTooOld() public {
        // Advance beyond the EIP-2935 history window
        vm.roll(block.number + BLOCKHASH_HISTORY_WINDOW + 1);

        bytes32 prevBlockHash = portal.blockHash();
        vm.expectRevert(IZonePortal.InvalidTempoBlockNumber.selector);
        _submitBatch(
            portal,
            genesisTempoBlockNumber, // Valid but beyond history window
            0,
            BlockTransition({ prevBlockHash: prevBlockHash, nextBlockHash: keccak256("state") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32(0),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            bytes32(0),
            "",
            ""
        );
    }

    function test_submitBatch_allowsHistoricalTempoBlockWithAncestryAnchor() public {
        // Advance beyond the EIP-2935 history window
        vm.roll(genesisTempoBlockNumber + BLOCKHASH_HISTORY_WINDOW + 100);

        uint64 oldTempoBlockNumber = genesisTempoBlockNumber;
        uint64 recentTempoBlockNumber = uint64(block.number - 1);

        _submitBatch(
            portal,
            oldTempoBlockNumber,
            recentTempoBlockNumber,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: bytes32(0),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            bytes32(0),
            "",
            ""
        );

        assertEq(portal.lastSyncedTempoBlockNumber(), oldTempoBlockNumber);
    }

    function test_submitBatch_revertsIfRecentTempoBlockNumberNotGreater() public {
        uint64 tempoBlockNumber = genesisTempoBlockNumber + 1;
        vm.roll(tempoBlockNumber + 1);

        bytes32 prevBlockHash = portal.blockHash();
        vm.expectRevert(IZonePortal.InvalidTempoBlockNumber.selector);
        _submitBatch(
            portal,
            tempoBlockNumber,
            tempoBlockNumber,
            BlockTransition({ prevBlockHash: prevBlockHash, nextBlockHash: keccak256("state") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32(0),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            bytes32(0),
            "",
            ""
        );
    }

    function test_submitBatch_revertsIfRecentTempoBlockNumberInFuture() public {
        uint64 tempoBlockNumber = genesisTempoBlockNumber + 1;
        vm.roll(tempoBlockNumber + 1);

        uint64 futureTempoBlockNumber = tempoBlockNumber + 2;

        bytes32 prevBlockHash = portal.blockHash();
        vm.expectRevert(IZonePortal.InvalidTempoBlockNumber.selector);
        _submitBatch(
            portal,
            tempoBlockNumber,
            futureTempoBlockNumber,
            BlockTransition({ prevBlockHash: prevBlockHash, nextBlockHash: keccak256("state") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32(0),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            bytes32(0),
            "",
            ""
        );
    }

    function test_submitBatch_succeedsAtHistoryWindowBoundary() public {
        // Advance exactly to the history window boundary
        vm.roll(genesisTempoBlockNumber + BLOCKHASH_HISTORY_WINDOW);

        // Should still work at the window boundary
        _submitBatch(
            portal,
            genesisTempoBlockNumber,
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: bytes32(0),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            bytes32(0),
            "",
            ""
        );

        assertEq(portal.withdrawalBatchIndex(), 1);
    }

    /*//////////////////////////////////////////////////////////////
               DEPOSIT QUEUE PREV HASH VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_submitBatch_usesInternalProcessedHash() public {
        // The implementation constructs prevProcessedHash from internal storage,
        // so the input prevProcessedHash is effectively ignored.
        // This test verifies the actual behavior: the portal uses its own tracked processed hash.

        // Make a deposit first
        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);
        _deposit(portal, address(pathUSD), alice, 1000e6, bytes32("memo"), alice);
        vm.stopPrank();

        bytes32 depositHash = portal.currentDepositQueueHash();

        vm.roll(block.number + 1);

        // Even though we pass a "wrong" prevProcessedHash, the implementation
        // constructs its own from _depositQueue.processed, so this will succeed
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state")
            }),
            DepositQueueTransition({
                    prevProcessedHash: keccak256("wrongHash"), // This is ignored by implementation
                    nextProcessedHash: depositHash,
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            bytes32(0),
            "",
            ""
        );

        // Verify batch was accepted
        assertEq(portal.withdrawalBatchIndex(), 1);
        // Portal no longer tracks processedDepositQueueHash - that's on the zone
    }

    function test_submitBatch_prevProcessedHashMustMatchPortalState() public {
        // Make deposits
        vm.startPrank(alice);
        pathUSD.approve(address(portal), 3000e6);
        bytes32 h1 = _deposit(portal, address(pathUSD), alice, 1000e6, bytes32("d1"), alice);
        bytes32 h2 = _deposit(portal, address(pathUSD), alice, 1000e6, bytes32("d2"), alice);
        vm.stopPrank();

        vm.roll(block.number + 1);

        // Process first deposit only
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state1")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: h1,
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            bytes32(0),
            "",
            ""
        );

        // Portal no longer tracks processedDepositQueueHash

        vm.roll(block.number + 1);

        // Submit second batch
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("state2")
            }),
            DepositQueueTransition({
                    prevProcessedHash: h1,
                    nextProcessedHash: h2,
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            bytes32(0),
            "",
            ""
        );

        assertEq(portal.withdrawalBatchIndex(), 2);
    }

    /*//////////////////////////////////////////////////////////////
                   WITHDRAWAL QUEUE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalQueue_emptyBatchDoesNotIncreaseTail() public {
        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);
        _deposit(portal, address(pathUSD), alice, 1000e6, bytes32(""), alice);
        vm.stopPrank();

        bytes32 depositHash = portal.currentDepositQueueHash();
        uint256 tailBefore = portal.withdrawalQueueTail();

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s1") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHash,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            bytes32(0), // No withdrawals
            "",
            ""
        );

        // Tail should not have advanced
        assertEq(portal.withdrawalQueueTail(), tailBefore);
    }

    /*//////////////////////////////////////////////////////////////
                  WITHDRAWAL PROCESSING ORDER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_processWithdrawal_mustProcessInOrder() public {
        // Fund portal
        vm.startPrank(alice);
        pathUSD.approve(address(portal), 10_000e6);
        _deposit(portal, address(pathUSD), alice, 10_000e6, bytes32(""), alice);
        vm.stopPrank();

        bytes32 depositHash = portal.currentDepositQueueHash();

        // Create two batches with different withdrawals
        Withdrawal memory w1 =
            _withdrawal(address(pathUSD), alice, bob, 100e6, bytes32("w1"), 0, alice, "");
        bytes32 w1Hash = keccak256(abi.encode(w1, bytes32(0)));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s1") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHash,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            w1Hash,
            "",
            ""
        );

        Withdrawal memory w2 =
            _withdrawal(address(pathUSD), alice, charlie, 200e6, bytes32("w2"), 0, alice, "");
        bytes32 w2Hash = keccak256(abi.encode(w2, bytes32(0)));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s2") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHash,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            w2Hash,
            "",
            ""
        );

        // Try to process w2 (slot 1) before w1 (slot 0) - should fail
        vm.expectRevert(WithdrawalQueueLib.InvalidWithdrawalProof.selector);
        portal.processWithdrawals(_singleWithdrawal(w2), bytes32(0));

        // Process w1 first
        portal.processWithdrawals(_singleWithdrawal(w1), bytes32(0));

        // Now w2 should work
        portal.processWithdrawals(_singleWithdrawal(w2), bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                     CALLBACK GAS LIMIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_withdrawal_callbackOutOfGas_bouncesBack() public {
        // Fund portal
        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);
        _deposit(portal, address(pathUSD), alice, 1000e6, bytes32(""), alice);
        vm.stopPrank();

        bytes32 depositHashBefore = portal.currentDepositQueueHash();

        // Create withdrawal with callback to gas-consuming receiver
        Withdrawal memory w = _withdrawal(
            address(pathUSD),
            alice,
            address(gasConsumingReceiver),
            500e6,
            bytes32(0),
            50_000,
            alice,
            ""
        );
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s1") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHashBefore,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            wHash,
            "",
            ""
        );

        // Process withdrawal - should bounce back
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        // Receiver should NOT have funds
        assertEq(pathUSD.balanceOf(address(gasConsumingReceiver)), 0);

        // Bounce-back deposit should have been created
        assertTrue(portal.currentDepositQueueHash() != depositHashBefore);
    }

    function test_withdrawal_maxGasCallbackOutOfGas_bouncesBackWithinProcessorLimit() public {
        uint64 callbackGasLimit = portal.MAX_WITHDRAWAL_GAS_LIMIT();
        uint256 processorGasLimit = uint256(callbackGasLimit) + 2_000_000;

        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);
        _deposit(portal, address(pathUSD), alice, 1000e6, bytes32(""), alice);
        vm.stopPrank();

        bytes32 depositHashBefore = portal.currentDepositQueueHash();
        Withdrawal memory w = _withdrawal(
            address(pathUSD),
            alice,
            address(gasConsumingReceiver),
            500e6,
            bytes32(0),
            callbackGasLimit,
            alice,
            ""
        );
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s1") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHashBefore,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            wHash,
            "",
            ""
        );

        vm.expectEmit(true, true, false, true);
        emit IZonePortal.WithdrawalProcessed(
            address(gasConsumingReceiver), w.senderTag, address(pathUSD), 500e6, false
        );
        (bool success,) = address(portal).call{ gas: processorGasLimit }(
            abi.encodeCall(IZonePortal.processWithdrawals, (_singleWithdrawal(w), bytes32(0)))
        );

        assertTrue(success);
        assertEq(pathUSD.balanceOf(address(gasConsumingReceiver)), 0);
        assertTrue(portal.currentDepositQueueHash() != depositHashBefore);
        assertEq(portal.withdrawalQueueHead(), 1);
        assertEq(portal.withdrawalQueueSlot(0), bytes32(0));
    }

    /// A reverting callback must not outspend its declared `gasLimit` plus fixed overhead.
    /// The blob used to be copied into the messenger frame and again into the portal's, so one
    /// attacker withdrawal could exhaust a batch sized from the queue's declared limits. The batch
    /// reverted, the dequeue rolled back, and since the sequencer rebuilds the same batch
    /// deterministically the FIFO stalled for good — TEMPO-ZONE-WITHDRAWAL-CALLBACK-BOUNDS.
    function test_withdrawal_revertBombDoesNotStallWithdrawalQueue() public {
        MockRevertingReceiver bomb = new MockRevertingReceiver(900_000);
        vm.prank(admin);
        portal.setGateway(address(bomb), true);

        vm.startPrank(alice);
        pathUSD.approve(address(portal), 2000e6);
        _deposit(portal, address(pathUSD), alice, 2000e6, bytes32(""), alice);
        vm.stopPrank();

        bytes32 depositHashBefore = portal.currentDepositQueueHash();

        uint64 bombGasLimit = 3_000_000;
        Withdrawal[] memory withdrawals = new Withdrawal[](2);
        withdrawals[0] = _withdrawal(
            address(pathUSD), alice, address(bomb), 500e6, bytes32(0), bombGasLimit, alice, ""
        );
        // A second, well-behaved withdrawal that must still be delivered.
        withdrawals[1] = _withdrawal(address(pathUSD), alice, bob, 500e6, bytes32(0), 0, alice, "");

        bytes32 tailHash = keccak256(abi.encode(withdrawals[1], bytes32(0)));
        bytes32 headHash = keccak256(abi.encode(withdrawals[0], tailHash));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s1") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHashBefore,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            headHash,
            "",
            ""
        );

        // Exactly what the sequencer's planner budgets for this pair, per its own allowances in
        // crates/sequenc../src/runtime/withdrawals.rs. The bomb must not push the batch past it.
        uint256 plannedGas = 500_000 + (1_750_000 + uint256(bombGasLimit)) + 1_000_000;

        uint256 bobBefore = pathUSD.balanceOf(bob);
        (bool success,) = address(portal).call{ gas: plannedGas }(
            abi.encodeCall(IZonePortal.processWithdrawals, (withdrawals, bytes32(0)))
        );

        assertTrue(success, "batch must not revert");
        assertEq(portal.withdrawalQueueHead(), 1, "the queue slot must be consumed");
        assertEq(portal.withdrawalQueueSlot(0), bytes32(0), "both items must have been dequeued");
        assertEq(pathUSD.balanceOf(address(bomb)), 0, "bomb must not keep the tokens");
        assertEq(
            pathUSD.balanceOf(bob) - bobBefore, 500e6, "honest withdrawal must still be delivered"
        );
        assertTrue(
            portal.currentDepositQueueHash() != depositHashBefore, "bomb must have bounced back"
        );
    }

    function test_withdrawal_zeroGasLimit_noCallback() public {
        // Fund portal
        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);
        _deposit(portal, address(pathUSD), alice, 1000e6, bytes32(""), alice);
        vm.stopPrank();

        bytes32 depositHash = portal.currentDepositQueueHash();

        // Create withdrawal with gasLimit = 0
        Withdrawal memory w =
            _withdrawal(address(pathUSD), alice, bob, 500e6, bytes32(0), 0, alice, "");
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s1") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHash,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            wHash,
            "",
            ""
        );

        uint256 callCountBefore = successfulReceiver.callCount();
        uint256 bobBalanceBefore = pathUSD.balanceOf(bob);

        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        // Funds should be transferred
        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore + 500e6);

        // But callback should NOT have been called
        assertEq(successfulReceiver.callCount(), callCountBefore);
    }

    function test_withdrawal_receivePolicyBlocked_enqueuesBounceBack() public {
        uint128 amount = 500e6;
        address master = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        bytes32 salt = bytes32(uint256(0xabf52baf));

        vm.prank(master);
        bytes4 masterId = StdPrecompiles.ADDRESS_REGISTRY.registerVirtualMaster(salt);
        address virtualRecipient = address(
            bytes20(abi.encodePacked(masterId, bytes10(type(uint80).max), bytes6(uint48(1))))
        );

        _fundCallbackWithdrawal(amount * 2);

        vm.prank(master);
        registry.setReceivePolicy(REJECT_ALL_POLICY_ID, ALLOW_ALL_POLICY_ID, address(0));

        address[2] memory recipients = [master, virtualRecipient];
        for (uint256 i; i < recipients.length; ++i) {
            Withdrawal memory withdrawal = _withdrawal(
                address(pathUSD), alice, recipients[i], amount, bytes32(0), 0, alice, ""
            );
            _enqueueWithdrawal(withdrawal);

            uint256 masterBalanceBefore = pathUSD.balanceOf(master);
            uint256 guardBalanceBefore =
                pathUSD.balanceOf(StdPrecompiles.RECEIVE_POLICY_GUARD_ADDRESS);
            uint256 portalBalanceBefore = pathUSD.balanceOf(address(portal));
            bytes32 depositHashBefore = portal.currentDepositQueueHash();
            uint64 depositCountBefore = portal.depositCount();

            portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));

            assertEq(pathUSD.balanceOf(master), masterBalanceBefore);
            assertEq(
                pathUSD.balanceOf(StdPrecompiles.RECEIVE_POLICY_GUARD_ADDRESS), guardBalanceBefore
            );
            assertEq(pathUSD.balanceOf(address(portal)), portalBalanceBefore);
            assertEq(portal.depositCount(), depositCountBefore + 1);
            assertNotEq(portal.currentDepositQueueHash(), depositHashBefore);
            assertEq(portal.withdrawalQueueHead(), portal.withdrawalQueueTail());
        }
    }

    function test_withdrawal_nonZeroGasLimit_callbackExecuted() public {
        _openPortalModes();

        // Fund portal
        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);
        _deposit(portal, address(pathUSD), alice, 1000e6, bytes32(""), alice);
        vm.stopPrank();

        bytes32 depositHash = portal.currentDepositQueueHash();

        // Create withdrawal with callback
        Withdrawal memory w = _withdrawal(
            address(pathUSD),
            alice,
            address(successfulReceiver),
            500e6,
            bytes32(0),
            5_000_000,
            alice,
            "test"
        );
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s1") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHash,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            wHash,
            "",
            ""
        );

        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        // Callback should have been called
        assertEq(successfulReceiver.callCount(), 1);
        assertEq(pathUSD.balanceOf(address(successfulReceiver)), 500e6);
    }

    /*//////////////////////////////////////////////////////////////
                     BOUNCE-BACK DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_bounceBack_depositsToFallbackRecipient() public {
        // Fund portal
        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);
        _deposit(portal, address(pathUSD), alice, 1000e6, bytes32(""), alice);
        vm.stopPrank();

        bytes32 depositHashBefore = portal.currentDepositQueueHash();

        // Create withdrawal with callback that will fail
        Withdrawal memory w = _withdrawal(
            address(pathUSD),
            alice,
            address(gasConsumingReceiver),
            500e6,
            bytes32("payment"),
            50_000,
            bob,
            ""
        );
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s1") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHashBefore,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            wHash,
            "",
            ""
        );

        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        // Verify bounce-back deposit was created
        bytes32 newDepositHash = portal.currentDepositQueueHash();
        assertTrue(newDepositHash != depositHashBefore);

        // The bounce-back deposit should be:
        // WithdrawalBounceBackDeposit { token: pathUSD, to: bob, amount: 500e6 }
        WithdrawalBounceBackDeposit memory expectedBounceBack =
            WithdrawalBounceBackDeposit({ token: address(pathUSD), to: bob, amount: 500e6 });
        bytes32 expectedHash = keccak256(
            abi.encode(DepositType.WithdrawalBounceBack, expectedBounceBack, depositHashBefore)
        );
        assertEq(newDepositHash, expectedHash);
    }

    /*//////////////////////////////////////////////////////////////
                      BATCH INDEX INCREMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalBatchIndex_incrementsOnEachBatch() public {
        vm.startPrank(alice);
        pathUSD.approve(address(portal), 3000e6);
        _deposit(portal, address(pathUSD), alice, 1000e6, bytes32(""), alice);
        vm.stopPrank();

        bytes32 depositHash = portal.currentDepositQueueHash();

        assertEq(portal.withdrawalBatchIndex(), 0);

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s1") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHash,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            bytes32(0),
            "",
            ""
        );
        assertEq(portal.withdrawalBatchIndex(), 1);

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s2") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHash,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            bytes32(0),
            "",
            ""
        );
        assertEq(portal.withdrawalBatchIndex(), 2);

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s3") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositHash,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            bytes32(0),
            "",
            ""
        );
        assertEq(portal.withdrawalBatchIndex(), 3);
    }

    /*//////////////////////////////////////////////////////////////
                        EVENT EMISSION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_processWithdrawal_emitsWithdrawalProcessedEvent_success() public {
        // Setup withdrawal
        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);
        _deposit(portal, address(pathUSD), alice, 1000e6, bytes32(""), alice);
        vm.stopPrank();

        Withdrawal memory w =
            _withdrawal(address(pathUSD), alice, bob, 500e6, bytes32(0), 0, alice, "");
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s1") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: portal.currentDepositQueueHash(),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            wHash,
            "",
            ""
        );

        vm.expectEmit(true, true, false, true);
        emit IZonePortal.WithdrawalProcessed(bob, w.senderTag, address(pathUSD), 500e6, true);

        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));
    }

    function test_processWithdrawal_emitsWithdrawalProcessedEvent_failure() public {
        // Setup withdrawal with failing callback
        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);
        _deposit(portal, address(pathUSD), alice, 1000e6, bytes32(""), alice);
        vm.stopPrank();

        Withdrawal memory w = _withdrawal(
            address(pathUSD),
            alice,
            address(gasConsumingReceiver),
            500e6,
            bytes32(0),
            50_000,
            alice,
            ""
        );
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({ prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("s1") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: portal.currentDepositQueueHash(),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            wHash,
            "",
            ""
        );

        vm.expectEmit(true, true, false, true);
        emit IZonePortal.WithdrawalProcessed(
            address(gasConsumingReceiver), w.senderTag, address(pathUSD), 500e6, false
        );

        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                          METADATA GETTER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_metadataGetters() public view {
        assertEq(portal.zoneId(), testZoneId);
        assertEq(portal.verifier(), ZONE_VERIFIER_ADDRESS);
        assertEq(portal.blockHash(), bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                    ENCRYPTION KEY MANAGEMENT TESTS
    //////////////////////////////////////////////////////////////*/

    // secp256k1 generator point X (known valid point on curve)
    bytes32 internal constant VALID_SECP256K1_X =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;

    // Well-known test private keys for secp256k1 PoP signatures
    uint256 internal constant ENC_KEY_1 = 1; // pubkey = G (generator point)
    uint256 internal constant ENC_KEY_2 = 2;
    uint256 internal constant ENC_KEY_3 = 3;

    /// @notice Helper: set encryption key with proof of possession using vm.createWallet + vm.sign
    function _setEncKeyWithPoP(uint256 privateKey) internal returns (bytes32 x, uint8 yParity) {
        Vm.Wallet memory w = vm.createWallet(privateKey);
        x = bytes32(w.publicKeyX);
        yParity = w.publicKeyY % 2 == 0 ? 0x02 : 0x03;
        bytes32 message = keccak256(abi.encode(address(portal), x, yParity));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(w.privateKey, message);
        portal.setSequencerEncryptionKey(x, yParity, v, r, s);
    }

    function test_sequencerEncryptionKey_revertsWhenEmpty() public {
        vm.expectRevert(IZonePortal.NoEncryptionKeySet.selector);
        portal.sequencerEncryptionKey();
    }

    function test_setSequencerEncryptionKey_success() public {
        (bytes32 x, uint8 yParity) = _setEncKeyWithPoP(ENC_KEY_1);

        (bytes32 storedX, uint8 storedYParity, address pubkey) = portal.sequencerEncryptionKey();
        assertEq(storedX, x);
        assertEq(storedYParity, yParity);
        assertEq(pubkey, vm.createWallet(ENC_KEY_1).addr);
        assertEq(portal.encryptionKeyCount(), 1);
    }

    function test_setSequencerEncryptionKey_revertsForCallerThatIsNeitherAdminNorSequencer()
        public
    {
        vm.prank(alice);
        vm.expectRevert(IZonePortal.NotSequencer.selector);
        portal.setSequencerEncryptionKey(bytes32(uint256(1)), 0x02, 27, bytes32(0), bytes32(0));
    }

    function test_setSequencerEncryptionKey_adminCanSet() public {
        Vm.Wallet memory w = vm.createWallet(ENC_KEY_1);
        bytes32 x = bytes32(w.publicKeyX);
        uint8 yParity = w.publicKeyY % 2 == 0 ? 0x02 : 0x03;
        bytes32 message = keccak256(abi.encode(address(portal), x, yParity));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(w.privateKey, message);

        vm.prank(admin);
        portal.setSequencerEncryptionKey(x, yParity, v, r, s);

        (bytes32 storedX, uint8 storedYParity, address pubkey) = portal.sequencerEncryptionKey();
        assertEq(storedX, x);
        assertEq(storedYParity, yParity);
        assertEq(pubkey, w.addr);
    }

    function test_setSequencerEncryptionKey_multipleKeys() public {
        _setEncKeyWithPoP(ENC_KEY_1);
        vm.roll(block.number + 100);
        (bytes32 x2, uint8 yParity2) = _setEncKeyWithPoP(ENC_KEY_2);

        assertEq(portal.encryptionKeyCount(), 2);

        // sequencerEncryptionKey returns the latest key
        (bytes32 storedX, uint8 storedYParity, address pubkey) = portal.sequencerEncryptionKey();
        assertEq(storedX, x2);
        assertEq(storedYParity, yParity2);
        assertEq(pubkey, vm.createWallet(ENC_KEY_2).addr);
    }

    function test_setSequencerEncryptionKey_emitsEvent() public {
        Vm.Wallet memory w = vm.createWallet(ENC_KEY_1);
        bytes32 x = bytes32(w.publicKeyX);
        uint8 yParity = w.publicKeyY % 2 == 0 ? 0x02 : 0x03;
        vm.expectEmit(true, true, true, true);
        emit IZonePortal.SequencerEncryptionKeyUpdated(x, yParity, w.addr, 0, uint64(block.number));
        // can't use helper since expectEmit must come before the call
        bytes32 message = keccak256(abi.encode(address(portal), x, yParity));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(w.privateKey, message);
        portal.setSequencerEncryptionKey(x, yParity, v, r, s);
    }

    function test_encryptionKeyAt_success() public {
        (bytes32 x1, uint8 yParity1) = _setEncKeyWithPoP(ENC_KEY_1);

        vm.roll(block.number + 50);
        (bytes32 x2, uint8 yParity2) = _setEncKeyWithPoP(ENC_KEY_2);

        EncryptionKeyEntry memory entry0 = portal.encryptionKeyAt(0);
        assertEq(entry0.x, x1);
        assertEq(entry0.yParity, yParity1);

        EncryptionKeyEntry memory entry1 = portal.encryptionKeyAt(1);
        assertEq(entry1.x, x2);
        assertEq(entry1.yParity, yParity2);
    }

    function test_encryptionKeyAt_revertsOnInvalidIndex() public {
        vm.expectRevert(abi.encodeWithSelector(IZonePortal.InvalidEncryptionKeyIndex.selector, 0));
        portal.encryptionKeyAt(0);
    }

    /// @notice Reverts with InvalidEncryptionKeyIndex when the index is strictly past the end.
    /// @dev With one key set, the empty-array test cannot tell `index >= length` from
    ///      `index == length`. Querying index 2 (length 1) distinguishes them: the `==` mutant
    ///      would fall through to an out-of-bounds array access (a panic, not this revert).
    function test_encryptionKeyAt_revertsWhenIndexAboveLength() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        vm.expectRevert(abi.encodeWithSelector(IZonePortal.InvalidEncryptionKeyIndex.selector, 2));
        portal.encryptionKeyAt(2);
    }

    function test_encryptionKeyAtBlock_binarySearch() public {
        // Set key1 at block 10
        vm.roll(10);
        (bytes32 x1, uint8 yParity1) = _setEncKeyWithPoP(ENC_KEY_1);

        // Set key2 at block 100
        vm.roll(100);
        (bytes32 x2,) = _setEncKeyWithPoP(ENC_KEY_2);

        // Set key3 at block 200
        vm.roll(200);
        (bytes32 x3,) = _setEncKeyWithPoP(ENC_KEY_3);

        // Query at block 10 -> key1
        (bytes32 rx, uint8 ry, uint256 ri) = portal.encryptionKeyAtBlock(10);
        assertEq(rx, x1);
        assertEq(ry, yParity1);
        assertEq(ri, 0);

        // Query at block 50 -> key1 (still active)
        (rx, ry, ri) = portal.encryptionKeyAtBlock(50);
        assertEq(rx, x1);
        assertEq(ri, 0);

        // Query at block 100 -> key2
        (rx, ry, ri) = portal.encryptionKeyAtBlock(100);
        assertEq(rx, x2);
        assertEq(ri, 1);

        // Query at block 150 -> key2
        (rx, ry, ri) = portal.encryptionKeyAtBlock(150);
        assertEq(rx, x2);
        assertEq(ri, 1);

        // Query at block 200 -> key3
        (rx, ry, ri) = portal.encryptionKeyAtBlock(200);
        assertEq(rx, x3);
        assertEq(ri, 2);

        // Query at block 500 -> key3
        (rx, ry, ri) = portal.encryptionKeyAtBlock(500);
        assertEq(rx, x3);
        assertEq(ri, 2);
    }

    function test_isEncryptionKeyValid_currentKeyNeverExpires() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        (bool valid, uint64 expiresAt) = portal.isEncryptionKeyValid(0);
        assertTrue(valid);
        assertEq(expiresAt, 0);

        // Still valid far in the future
        vm.roll(block.number + 1_000_000);
        (valid, expiresAt) = portal.isEncryptionKeyValid(0);
        assertTrue(valid);
        assertEq(expiresAt, 0);
    }

    function test_isEncryptionKeyValid_oldKeyValidDuringGrace() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        uint256 key2Block = block.number + 100;
        vm.roll(key2Block);
        _setEncKeyWithPoP(ENC_KEY_2);

        // Key 0 should be valid during grace period
        vm.roll(key2Block + ENCRYPTION_KEY_GRACE_PERIOD - 1);
        (bool valid,) = portal.isEncryptionKeyValid(0);
        assertTrue(valid);
    }

    function test_isEncryptionKeyValid_oldKeyExpiredAfterGrace() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        uint256 key2Block = block.number + 100;
        vm.roll(key2Block);
        _setEncKeyWithPoP(ENC_KEY_2);

        // Key 0 should be expired after grace period
        vm.roll(key2Block + ENCRYPTION_KEY_GRACE_PERIOD);
        (bool valid,) = portal.isEncryptionKeyValid(0);
        assertFalse(valid);
    }

    function test_isEncryptionKeyValid_invalidIndexReturnsFalse() public view {
        (bool valid,) = portal.isEncryptionKeyValid(0);
        assertFalse(valid);
        (valid,) = portal.isEncryptionKeyValid(999);
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                    PROOF-OF-POSSESSION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setSequencerEncryptionKey_revertsOnInvalidPoP() public {
        Vm.Wallet memory w = vm.createWallet(ENC_KEY_1);
        bytes32 x = bytes32(w.publicKeyX);
        uint8 yParity = w.publicKeyY % 2 == 0 ? 0x02 : 0x03;

        // Sign with a DIFFERENT private key (wrong PoP)
        bytes32 message = keccak256(abi.encode(address(portal), x, yParity));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ENC_KEY_2, message);

        vm.expectRevert(IZonePortal.InvalidProofOfPossession.selector);
        portal.setSequencerEncryptionKey(x, yParity, v, r, s);
    }

    function test_setSequencerEncryptionKey_revertsOnInvalidYParity() public {
        vm.expectRevert(IZonePortal.InvalidEphemeralPubkey.selector);
        portal.setSequencerEncryptionKey(bytes32(uint256(1)), 0x04, 27, bytes32(0), bytes32(0));
    }

    function test_setSequencerEncryptionKey_revertsOnInvalidX() public {
        vm.expectRevert(IZonePortal.InvalidEphemeralPubkey.selector);
        portal.setSequencerEncryptionKey(bytes32(0), 0x02, 27, bytes32(0), bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                       ENCRYPTED DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    function _makeDepositPayload() internal pure returns (DepositPayload memory) {
        return DepositPayload({
            ephemeralPubkeyX: VALID_SECP256K1_X,
            ephemeralPubkeyYParity: 0x02,
            ciphertext: new bytes(64),
            nonce: bytes12(0),
            tag: bytes16(0)
        });
    }

    function test_deposit_aliasMatchesDepositEncrypted() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        uint128 depositAmount = 1000e6;
        DepositPayload memory encrypted = _makeDepositPayload();

        vm.prank(alice);
        pathUSD.approve(address(portal), depositAmount);
        uint256 snapshotId = vm.snapshotState();

        vm.recordLogs();
        vm.prank(alice);
        bytes32 encryptedHash =
            portal.depositEncrypted(address(pathUSD), depositAmount, 0, encrypted, alice);
        Vm.Log[] memory encryptedLogs = vm.getRecordedLogs();
        uint256 encryptedAliceBalance = pathUSD.balanceOf(alice);
        uint256 encryptedAdminBalance = pathUSD.balanceOf(admin);
        uint256 encryptedPortalBalance = pathUSD.balanceOf(address(portal));
        uint64 encryptedDepositCount = portal.depositCount();

        assertTrue(vm.revertToState(snapshotId));

        vm.recordLogs();
        vm.prank(alice);
        bytes32 aliasHash = portal.deposit(address(pathUSD), depositAmount, 0, encrypted, alice);
        Vm.Log[] memory aliasLogs = vm.getRecordedLogs();

        assertEq(aliasHash, encryptedHash);
        assertEq(portal.currentDepositQueueHash(), encryptedHash);
        assertEq(pathUSD.balanceOf(alice), encryptedAliceBalance);
        assertEq(pathUSD.balanceOf(admin), encryptedAdminBalance);
        assertEq(pathUSD.balanceOf(address(portal)), encryptedPortalBalance);
        assertEq(portal.depositCount(), encryptedDepositCount);
        assertEq(keccak256(abi.encode(aliasLogs)), keccak256(abi.encode(encryptedLogs)));
    }

    function test_deposit_legacyPlaintextSelectorIsAbsent() public {
        bytes memory callData = abi.encodeWithSignature(
            "deposit(address,address,uint128,bytes32,address)",
            address(pathUSD),
            alice,
            uint128(1000e6),
            bytes32(0),
            alice
        );

        vm.prank(alice);
        (bool success,) = address(portal).call(callData);
        assertFalse(success);
    }

    function test_deposit_success() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        bytes32 hash =
            portal.deposit(address(pathUSD), depositAmount, 0, _makeDepositPayload(), alice);
        vm.stopPrank();

        assertEq(portal.currentDepositQueueHash(), hash);
        assertTrue(hash != bytes32(0));
    }

    function test_deposit_hashChainMatchesLibrary() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        uint128 depositAmount = 1000e6;
        uint128 fee = portal.calculateDepositFee();
        uint128 netAmount = depositAmount - fee;

        DepositPayload memory encrypted = _makeDepositPayload();

        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        bytes32 hash = portal.deposit(address(pathUSD), depositAmount, 0, encrypted, alice);
        vm.stopPrank();

        // Reconstruct expected hash using the same encoding as DepositQueueLib
        Deposit memory ed = Deposit({
            token: address(pathUSD),
            sender: alice,
            amount: netAmount,
            tempoRefundRecipient: alice,
            keyIndex: 0,
            encrypted: encrypted
        });
        bytes32 expectedHash = keccak256(abi.encode(DepositType.Deposit, ed, bytes32(0)));
        assertEq(hash, expectedHash);
    }

    function test_deposit_mixedQueue() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        uint128 amount = 1000e6;

        // Encrypted deposit from alice via the shared helper.
        vm.startPrank(alice);
        pathUSD.approve(address(portal), amount * 3);
        bytes32 h1 = _deposit(portal, address(pathUSD), alice, amount, bytes32("memo"), alice);

        // Encrypted deposit from alice
        bytes32 h2 = portal.deposit(address(pathUSD), amount, 0, _makeDepositPayload(), alice);
        vm.stopPrank();

        // Both should update the same queue
        assertEq(portal.currentDepositQueueHash(), h2);
        assertTrue(h1 != h2);
        assertTrue(h2 != bytes32(0));
    }

    function test_deposit_deductsFee() public {
        _setZoneGasRate(1); // 1 token per gas -> fee = 100_000
        _setEncKeyWithPoP(ENC_KEY_1);

        uint128 depositAmount = 1000e6;
        uint128 expectedFee = uint128(100_000) * 1; // FIXED_DEPOSIT_GAS * zoneGasRate
        uint256 aliceBefore = pathUSD.balanceOf(alice);
        uint256 adminBefore = pathUSD.balanceOf(admin);
        uint256 portalBefore = pathUSD.balanceOf(address(portal));

        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        portal.deposit(address(pathUSD), depositAmount, 0, _makeDepositPayload(), alice);
        vm.stopPrank();

        assertEq(pathUSD.balanceOf(alice), aliceBefore - depositAmount);
        assertEq(pathUSD.balanceOf(admin), adminBefore + expectedFee);
        assertEq(pathUSD.balanceOf(address(portal)), portalBefore + depositAmount - expectedFee);
    }

    function test_deposit_emitsDepositMade() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        uint128 depositAmount = 1000e6;
        uint128 fee = portal.calculateDepositFee();
        uint128 netAmount = depositAmount - fee;

        DepositPayload memory encrypted = _makeDepositPayload();

        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);

        // Build expected hash
        Deposit memory ed = Deposit({
            token: address(pathUSD),
            sender: alice,
            amount: netAmount,
            tempoRefundRecipient: alice,
            keyIndex: 0,
            encrypted: encrypted
        });
        bytes32 expectedHash = keccak256(abi.encode(DepositType.Deposit, ed, bytes32(0)));

        vm.expectEmit(true, true, false, true);
        emit IZonePortal.DepositMade(
            expectedHash,
            alice,
            address(pathUSD),
            netAmount,
            fee,
            0,
            VALID_SECP256K1_X,
            0x02,
            encrypted.ciphertext,
            encrypted.nonce,
            encrypted.tag,
            alice,
            1
        );
        portal.deposit(address(pathUSD), depositAmount, 0, encrypted, alice);
        vm.stopPrank();
    }

    function test_deposit_revertsOnExpiredKey() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        // Rotate to key2
        uint256 key2Block = block.number + 100;
        vm.roll(key2Block);
        _setEncKeyWithPoP(ENC_KEY_2);

        // Move past grace period for key1
        vm.roll(key2Block + ENCRYPTION_KEY_GRACE_PERIOD);

        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);

        // Should revert with EncryptionKeyExpired for key index 0
        vm.expectRevert();
        portal.deposit(address(pathUSD), depositAmount, 0, _makeDepositPayload(), alice);
        vm.stopPrank();
    }

    function test_deposit_revertsOnInvalidKeyIndex() public {
        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);

        // No keys set, index 0 is invalid
        vm.expectRevert(abi.encodeWithSelector(IZonePortal.InvalidEncryptionKeyIndex.selector, 0));
        portal.deposit(address(pathUSD), depositAmount, 0, _makeDepositPayload(), alice);
        vm.stopPrank();
    }

    function test_deposit_revertsOnInvalidYParity() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);

        DepositPayload memory encrypted = DepositPayload({
            ephemeralPubkeyX: VALID_SECP256K1_X,
            ephemeralPubkeyYParity: 0x04, // Invalid
            ciphertext: new bytes(64),
            nonce: bytes12(0),
            tag: bytes16(0)
        });

        vm.expectRevert(IZonePortal.InvalidEphemeralPubkey.selector);
        portal.deposit(address(pathUSD), depositAmount, 0, encrypted, alice);
        vm.stopPrank();
    }

    function test_deposit_revertsOnInvalidEphemeralX() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);

        DepositPayload memory encrypted = DepositPayload({
            ephemeralPubkeyX: bytes32(0), // Invalid: zero
            ephemeralPubkeyYParity: 0x02,
            ciphertext: new bytes(64),
            nonce: bytes12(0),
            tag: bytes16(0)
        });

        vm.expectRevert(IZonePortal.InvalidEphemeralPubkey.selector);
        portal.deposit(address(pathUSD), depositAmount, 0, encrypted, alice);
        vm.stopPrank();
    }

    function test_deposit_revertsOnDepositTooSmall() public {
        _setZoneGasRate(1); // fee = 100_000
        _setEncKeyWithPoP(ENC_KEY_1);

        vm.startPrank(alice);
        pathUSD.approve(address(portal), 99_999);

        vm.expectRevert(IZonePortal.DepositTooSmall.selector);
        portal.deposit(address(pathUSD), 99_999, 0, _makeDepositPayload(), alice);
        vm.stopPrank();
    }

    function test_deposit_revertsOnCiphertextTooShort() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        DepositPayload memory payload = _makeDepositPayload();
        payload.ciphertext = new bytes(63); // one byte too short

        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);

        vm.expectRevert(
            abi.encodeWithSelector(IZonePortal.InvalidCiphertextLength.selector, 63, 64)
        );
        portal.deposit(address(pathUSD), 1000e6, 0, payload, alice);
        vm.stopPrank();
    }

    function test_deposit_revertsOnCiphertextTooLong() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        DepositPayload memory payload = _makeDepositPayload();
        payload.ciphertext = new bytes(65); // one byte too long

        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);

        vm.expectRevert(
            abi.encodeWithSelector(IZonePortal.InvalidCiphertextLength.selector, 65, 64)
        );
        portal.deposit(address(pathUSD), 1000e6, 0, payload, alice);
        vm.stopPrank();
    }

    function test_deposit_revertsOnEmptyCiphertext() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        DepositPayload memory payload = _makeDepositPayload();
        payload.ciphertext = new bytes(0);

        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);

        vm.expectRevert(abi.encodeWithSelector(IZonePortal.InvalidCiphertextLength.selector, 0, 64));
        portal.deposit(address(pathUSD), 1000e6, 0, payload, alice);
        vm.stopPrank();
    }

    function test_deposit_revertsOnOversizedCiphertext() public {
        _setEncKeyWithPoP(ENC_KEY_1);

        DepositPayload memory payload = _makeDepositPayload();
        payload.ciphertext = new bytes(1024); // large ciphertext (DoS vector)

        vm.startPrank(alice);
        pathUSD.approve(address(portal), 1000e6);

        vm.expectRevert(
            abi.encodeWithSelector(IZonePortal.InvalidCiphertextLength.selector, 1024, 64)
        );
        portal.deposit(address(pathUSD), 1000e6, 0, payload, alice);
        vm.stopPrank();
    }

    function test_rpcUrl_setAtCreation() public view {
        // setUp() created the zone with this RPC URL
        assertEq(
            portal.rpcUrl(), "https://rpc.test-zone.example", "rpcUrl should be set at creation"
        );
    }

    function test_setRpcUrl_updates() public {
        string memory url = "https://rpc.new-endpoint.example";

        vm.expectEmit(false, false, false, true, address(portal));
        emit IZonePortal.RpcUrlUpdated(url);
        portal.setRpcUrl(url);

        assertEq(portal.rpcUrl(), url, "rpcUrl() mismatch after update");
    }

    function test_setRpcUrl_clearByEmptyValue() public {
        portal.setRpcUrl("");
        assertEq(bytes(portal.rpcUrl()).length, 0, "empty value should clear rpcUrl");
    }

    function test_setRpcUrl_revertsIfNotSequencer() public {
        vm.prank(alice); // Not sequencer
        vm.expectRevert(IZonePortal.NotSequencer.selector);
        portal.setRpcUrl("https://rpc.example");
    }

    /*//////////////////////////////////////////////////////////////
                    STORAGE LAYOUT VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify that the _encryptionKeys dynamic array uses the expected slot layout.
    /// @dev This ensures ZoneInbox both compute the correct storage slots
    ///      when reading encryption keys via readTempoStorageSlot().
    ///
    ///      For a dynamic array at slot S:
    ///        - slot S stores the array length
    ///        - element data starts at keccak256(abi.encode(S))
    ///        - each EncryptionKeyEntry occupies 2 slots:
    ///            base + (index * 2):     x (bytes32)
    ///            base + (index * 2) + 1: yParity (uint8) + activationBlock (uint64) [packed]
    function test_storageLayout_encryptionKeysArray() public {
        // Add two keys at different blocks
        (bytes32 keyX1, uint8 keyYParity1) = _setEncKeyWithPoP(ENC_KEY_1);

        vm.roll(block.number + 100);
        (bytes32 keyX2, uint8 keyYParity2) = _setEncKeyWithPoP(ENC_KEY_2);

        // Verify array length at the shared encryption keys slot
        uint256 arraySlot = uint256(PORTAL_ENCRYPTION_KEYS_SLOT);
        bytes32 lengthRaw = vm.load(address(portal), bytes32(arraySlot));
        assertEq(uint256(lengthRaw), 2, "encryption keys array length should be 2");

        // Compute the base slot for array data
        uint256 base = uint256(keccak256(abi.encode(arraySlot)));

        // --- Entry 0: verify raw storage matches the public getter ---
        EncryptionKeyEntry memory entry0 = portal.encryptionKeyAt(0);
        bytes32 loadedX1 = vm.load(address(portal), bytes32(base + 0));
        assertEq(loadedX1, keyX1, "entry 0: x mismatch");
        assertEq(loadedX1, entry0.x, "entry 0: x != getter");

        bytes32 meta1 = vm.load(address(portal), bytes32(base + 1));
        uint8 loadedYParity1 = uint8(uint256(meta1) & 0xff);
        uint64 loadedActivation1 = uint64(uint256(meta1) >> 8);
        assertEq(loadedYParity1, keyYParity1, "entry 0: yParity mismatch");
        assertEq(loadedActivation1, entry0.activationBlock, "entry 0: activationBlock mismatch");

        // --- Entry 1: verify raw storage matches the public getter ---
        EncryptionKeyEntry memory entry1 = portal.encryptionKeyAt(1);
        bytes32 loadedX2 = vm.load(address(portal), bytes32(base + 2));
        assertEq(loadedX2, keyX2, "entry 1: x mismatch");
        assertEq(loadedX2, entry1.x, "entry 1: x != getter");

        bytes32 meta2 = vm.load(address(portal), bytes32(base + 3));
        uint8 loadedYParity2 = uint8(uint256(meta2) & 0xff);
        uint64 loadedActivation2 = uint64(uint256(meta2) >> 8);
        assertEq(loadedYParity2, keyYParity2, "entry 1: yParity mismatch");
        assertEq(loadedActivation2, entry1.activationBlock, "entry 1: activationBlock mismatch");

        // Verify the two keys have different activation blocks (proves vm.roll worked)
        assertTrue(
            entry1.activationBlock > entry0.activationBlock, "key2 should be activated later"
        );
    }

    /*//////////////////////////////////////////////////////////////
                         ADDITIONAL COVERAGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Records that false token transferFrom returns do not block deposits.
    function test_deposit_tokenTransferFromReturnsFalse_currentlyNotChecked() public {
        vm.fee(0);
        uint128 amount = 500e6;

        vm.mockCall(
            address(pathUSD),
            abi.encodeWithSelector(ITIP20.transferFrom.selector, alice, address(portal), amount),
            abi.encode(false)
        );

        // Records current behavior: a false TIP-20 return value is not checked.
        vm.prank(alice);
        bytes32 depositHash = _deposit(portal, address(pathUSD), bob, amount, bytes32("memo"), bob);

        assertEq(portal.depositCount(), 1);
        assertEq(portal.currentDepositQueueHash(), depositHash);
    }

    /// @notice Admin updates the zone gas rate and emits the new value.
    function test_setZoneGasRate_updatesRateAndEmits() public {
        uint128 newRate = 42;

        vm.expectEmit(false, false, false, true, address(portal));
        emit IZonePortal.ZoneGasRateUpdated(newRate);
        _setZoneGasRate(newRate);

        assertEq(portal.zoneGasRate(), newRate);
    }

    /// @notice Rejects zone gas rates above the configured maximum.
    function test_setZoneGasRate_revertsWhenTooHigh() public {
        uint128 tooHigh = uint128(1e18) + 1;

        vm.prank(admin);
        vm.expectRevert(IZonePortal.GasFeeRateTooHigh.selector);
        portal.setZoneGasRate(tooHigh);
    }

    /// @notice A gas rate exactly at the maximum is accepted (the bound is inclusive).
    /// @dev Guards `_zoneGasRate > MAX` against a `>=` mutant, which would reject the maximum.
    function test_setZoneGasRate_acceptsExactMaximum() public {
        uint128 maxRate = portal.MAX_GAS_FEE_RATE();

        _setZoneGasRate(maxRate);
        assertEq(portal.zoneGasRate(), maxRate);
    }

    /// @notice Only the admin can update the zone gas rate.
    function test_setZoneGasRate_revertsIfNotAdmin() public {
        vm.prank(sequencer);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.setZoneGasRate(1);
    }

    function test_maxTempoGasRate_defaultsToZero() public view {
        assertEq(portal.maxTempoGasRate(), 0);
    }

    function test_setMaxTempoGasRate_updatesMaximumAndEmits() public {
        uint128 newMaximum = 42;

        vm.expectEmit(false, false, false, true, address(portal));
        emit IZonePortal.MaxTempoGasRateUpdated(newMaximum);
        _setMaxTempoGasRate(newMaximum);

        assertEq(portal.maxTempoGasRate(), newMaximum);
    }

    function test_setMaxTempoGasRate_revertsWhenTooHigh() public {
        uint128 tooHigh = portal.MAX_GAS_FEE_RATE() + 1;

        vm.prank(admin);
        vm.expectRevert(IZonePortal.GasFeeRateTooHigh.selector);
        portal.setMaxTempoGasRate(tooHigh);
    }

    function test_setMaxTempoGasRate_revertsIfNotAdmin() public {
        vm.prank(sequencer);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.setMaxTempoGasRate(1);
    }

    /// @notice Admin updates the gas amount used for bounce-back fees.
    function test_setBouncebackGas_updatesGasAndEmits() public {
        uint64 newBouncebackGas = 42;

        vm.expectEmit(false, false, false, true, address(portal));
        emit IZonePortal.BouncebackGasUpdated(newBouncebackGas);
        _setBouncebackGas(newBouncebackGas);

        assertEq(portal.bouncebackGas(), newBouncebackGas);
    }

    /// @notice Only the admin can update the bounce-back gas amount.
    function test_setBouncebackGas_revertsIfNotAdmin() public {
        vm.prank(sequencer);
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.setBouncebackGas(1);
    }

    /// @notice Claiming with no refund emits and returns zero without changing state.
    function test_claimRefund_zeroAmount() public {
        vm.expectEmit(true, true, false, true, address(portal));
        emit IZonePortal.RefundClaimed(alice, address(pathUSD), 0);

        vm.prank(alice);
        uint128 amount = portal.claimRefund(address(pathUSD));

        assertEq(amount, 0);
        assertEq(portal.refunds(address(pathUSD), alice), 0);
    }

    /// @notice Claiming pays out a refund parked by a failed bounced withdrawal.
    function test_claimRefund_successAfterDepositBounceBackPending() public {
        vm.fee(0);
        uint128 depositAmount = 1000e6;
        vm.startPrank(alice);
        pathUSD.approve(address(portal), depositAmount);
        _deposit(portal, address(pathUSD), alice, depositAmount, bytes32("memo"), alice);
        vm.stopPrank();

        Withdrawal memory w =
            _withdrawal(address(pathUSD), alice, bob, 250e6, bytes32(0), 0, address(0), "");
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("refund")
            }),
            DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: portal.currentDepositQueueHash(),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
            wHash,
            "",
            ""
        );

        vm.mockCall(
            address(pathUSD),
            abi.encodeWithSelector(ITIP20.transfer.selector, bob, w.amount),
            abi.encode(false)
        );
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        assertEq(portal.refunds(address(pathUSD), bob), w.amount);

        vm.clearMockedCalls();
        uint256 bobBalanceBefore = pathUSD.balanceOf(bob);

        vm.prank(bob);
        uint128 claimed = portal.claimRefund(address(pathUSD));

        assertEq(claimed, w.amount);
        assertEq(portal.refunds(address(pathUSD), bob), 0);
        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore + w.amount);
    }

    function test_depositBounceBack_receivePolicyBlocked_parksAndPreservesRefund() public {
        vm.fee(0);
        uint128 amount = 250e6;
        _fundCallbackWithdrawal(amount);

        Withdrawal memory withdrawal =
            _withdrawal(address(pathUSD), alice, bob, amount, bytes32(0), 0, address(0), "");
        _enqueueWithdrawal(withdrawal);

        vm.prank(bob);
        registry.setReceivePolicy(REJECT_ALL_POLICY_ID, ALLOW_ALL_POLICY_ID, address(0));

        uint256 bobBalanceBefore = pathUSD.balanceOf(bob);
        uint256 guardBalanceBefore = pathUSD.balanceOf(StdPrecompiles.RECEIVE_POLICY_GUARD_ADDRESS);

        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));

        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore);
        assertEq(pathUSD.balanceOf(StdPrecompiles.RECEIVE_POLICY_GUARD_ADDRESS), guardBalanceBefore);
        assertEq(portal.refunds(address(pathUSD), bob), amount);

        vm.prank(bob);
        vm.expectRevert(IZonePortal.CallbackRejected.selector);
        portal.claimRefund(address(pathUSD));

        assertEq(portal.refunds(address(pathUSD), bob), amount);
        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore);
        assertEq(pathUSD.balanceOf(StdPrecompiles.RECEIVE_POLICY_GUARD_ADDRESS), guardBalanceBefore);

        vm.prank(bob);
        registry.setReceivePolicy(ALLOW_ALL_POLICY_ID, ALLOW_ALL_POLICY_ID, address(0));
        vm.prank(bob);
        assertEq(portal.claimRefund(address(pathUSD)), amount);

        assertEq(portal.refunds(address(pathUSD), bob), 0);
        assertEq(pathUSD.balanceOf(bob), bobBalanceBefore + amount);
    }

    /// @notice A withdrawal backlog cannot prevent a batch from being submitted.
    function test_withdrawalQueue_acceptsBacklogBeyondFormerCapacity() public {
        vm.roll(genesisTempoBlockNumber + 1);
        for (uint256 i = 0; i < TEST_QUEUE_LENGTH; i++) {
            _submitBatch(
                portal,
                genesisTempoBlockNumber,
                0,
                BlockTransition({
                    prevBlockHash: portal.blockHash(), nextBlockHash: keccak256(abi.encode("s", i))
                }),
                DepositQueueTransition({
                    prevProcessedHash: bytes32(0),
                    nextProcessedHash: portal.currentDepositQueueHash(),
                    prevDepositNumber: 0,
                    nextDepositNumber: 0
                }),
                keccak256(abi.encode("w", i)),
                "",
                ""
            );
        }
        assertEq(portal.withdrawalQueueTail() - portal.withdrawalQueueHead(), TEST_QUEUE_LENGTH);

        bytes32 prevBlockHash = portal.blockHash();
        bytes32 depositQueueHash = portal.currentDepositQueueHash();
        _submitBatch(
            portal,
            genesisTempoBlockNumber,
            0,
            BlockTransition({ prevBlockHash: prevBlockHash, nextBlockHash: keccak256("full") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: depositQueueHash,
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            keccak256("overflow"),
            "",
            ""
        );
        assertEq(portal.withdrawalQueueTail() - portal.withdrawalQueueHead(), TEST_QUEUE_LENGTH + 1);
        assertEq(portal.withdrawalQueueSlot(TEST_QUEUE_LENGTH), keccak256("overflow"));
    }

    /// @notice Deposit fee equals fixed deposit gas multiplied by zone gas rate.
    function testFuzz_calculateDepositFee(uint128 zoneGasRate) public {
        zoneGasRate = uint128(bound(zoneGasRate, 0, portal.MAX_GAS_FEE_RATE()));

        _setZoneGasRate(zoneGasRate);

        uint128 fee = portal.calculateDepositFee();

        assertEq(fee, uint128(100_000) * zoneGasRate);
    }

    /// @notice Bounceback fee rounds basefee gas cost up to token units.
    function testFuzz_calculateBouncebackFee(uint64 bouncebackGas, uint256 basefee) public {
        basefee = bound(basefee, 0, 1e18);
        _setBouncebackGas(bouncebackGas);
        vm.fee(basefee);

        uint256 expected = (uint256(bouncebackGas) * basefee + 1e12 - 1) / 1e12;
        uint128 fee = portal.calculateBouncebackFee();

        assertEq(uint256(fee), expected);
    }

    /// @notice Deposits below fees revert and valid amounts enqueue the net amount.
    function testFuzz_deposit_amountBoundary(uint128 amount) public {
        amount = uint128(bound(amount, 0, 1000e6));
        vm.fee(1e12);
        _setZoneGasRate(1);
        _setBouncebackGas(300_000);
        uint128 minimum = portal.calculateDepositFee() + portal.calculateBouncebackFee();

        vm.startPrank(alice);
        pathUSD.approve(address(portal), amount);
        if (amount < minimum) {
            vm.expectRevert(IZonePortal.DepositTooSmall.selector);
            _deposit(portal, address(pathUSD), bob, amount, bytes32("memo"), bob);
        } else {
            bytes32 depositHash =
                _deposit(portal, address(pathUSD), bob, amount, bytes32("memo"), bob);
            Deposit memory depositData = Deposit({
                token: address(pathUSD),
                sender: alice,
                amount: amount - portal.calculateDepositFee(),
                tempoRefundRecipient: bob,
                keyIndex: portal.encryptionKeyCount() - 1,
                encrypted: _depositPayload(bob, bytes32("memo"))
            });
            assertEq(depositHash, DepositQueueLib.enqueueDeposit(bytes32(0), depositData));
        }
        vm.stopPrank();
    }

    /// @notice Multiple deposits update the queue hash chain and count in order.
    function testFuzz_deposit_hashChain(uint8 depositIterations) public {
        uint256 iterations = bound(depositIterations, 1, 10);
        uint128 amount = 1000e6;
        bytes32 expectedHash;

        vm.startPrank(alice);
        pathUSD.approve(address(portal), amount * iterations);
        for (uint256 i = 0; i < iterations; i++) {
            bytes32 memo = bytes32(i);
            bytes32 actualHash = _deposit(portal, address(pathUSD), bob, amount, memo, bob);
            Deposit memory depositData = Deposit({
                token: address(pathUSD),
                sender: alice,
                amount: amount - portal.calculateDepositFee(),
                tempoRefundRecipient: bob,
                keyIndex: portal.encryptionKeyCount() - 1,
                encrypted: _depositPayload(bob, memo)
            });
            expectedHash = DepositQueueLib.enqueueDeposit(expectedHash, depositData);
            assertEq(actualHash, expectedHash);
        }
        vm.stopPrank();

        assertEq(portal.currentDepositQueueHash(), expectedHash);
        assertEq(portal.depositCount(), iterations);
    }

    /// @notice Key lookup returns the latest encryption key active at the query block.
    function testFuzz_encryptionKeyAtBlock(
        uint16 gap1,
        uint16 gap2,
        uint16 gap3,
        uint16 queryOffset
    )
        public
    {
        uint64[3] memory activationBlocks;
        bytes32[3] memory xs;
        uint8[3] memory yParities;

        activationBlocks[0] = uint64(bound(gap1, 1, 100));
        vm.roll(activationBlocks[0]);
        (xs[0], yParities[0]) = _setEncKeyWithPoP(ENC_KEY_1);

        activationBlocks[1] = activationBlocks[0] + uint64(bound(gap2, 1, 100));
        vm.roll(activationBlocks[1]);
        (xs[1], yParities[1]) = _setEncKeyWithPoP(ENC_KEY_2);

        activationBlocks[2] = activationBlocks[1] + uint64(bound(gap3, 1, 100));
        vm.roll(activationBlocks[2]);
        (xs[2], yParities[2]) = _setEncKeyWithPoP(ENC_KEY_3);

        uint64 queryBlock = activationBlocks[0] + uint64(bound(queryOffset, 0, 300));
        uint256 expectedIndex;
        for (uint256 i = 0; i < activationBlocks.length; i++) {
            if (activationBlocks[i] <= queryBlock) {
                expectedIndex = i;
            }
        }

        (bytes32 x, uint8 yParity, uint256 keyIndex) = portal.encryptionKeyAtBlock(queryBlock);
        assertEq(x, xs[expectedIndex]);
        assertEq(yParity, yParities[expectedIndex]);
        assertEq(keyIndex, expectedIndex);
    }

    function _setZoneGasRate(uint128 rate) internal {
        vm.prank(admin);
        portal.setZoneGasRate(rate);
    }

    function _setMaxTempoGasRate(uint128 rate) internal {
        vm.prank(admin);
        portal.setMaxTempoGasRate(rate);
    }

    function _setBouncebackGas(uint64 gasAmount) internal {
        vm.prank(admin);
        portal.setBouncebackGas(gasAmount);
    }

}
