// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    BlockTransition,
    DepositPayload,
    DepositQueueTransition,
    IZoneFactory,
    IZonePortal,
    PORTAL_ENCRYPTION_KEYS_SLOT,
    TokenEnablementTransition,
    Withdrawal,
    ZONE_FACTORY_ADDRESS,
    ZONE_MESSENGER_ADDRESS,
    ZONE_VERIFIER_ADDRESS,
    ZoneInfo
} from "../src/runtime/interfaces/IZone.sol";
import { EIP2935 } from "../src/runtime/libraries/BlockHashHistory.sol";
import { Verifier } from "../src/runtime/tempo/Verifier.sol";
import { ZoneMessenger } from "../src/runtime/tempo/ZoneMessenger.sol";
import { ZonePortal } from "../src/runtime/tempo/ZonePortal.sol";
import { PortalRuntimeTest } from "./PortalRuntimeTest.sol";
import { MockZoneGateway } from "./mocks/MockZoneGateway.sol";
import { console } from "forge-std/Test.sol";
import { Vm } from "forge-std/Vm.sol";
import { StdPrecompiles } from "tempo-std/StdPrecompiles.sol";
import { IAccountKeychain } from "tempo-std/interfaces/IAccountKeychain.sol";
import { IFeeManager } from "tempo-std/interfaces/IFeeManager.sol";
import { INonce } from "tempo-std/interfaces/INonce.sol";
import { ISignatureVerifier } from "tempo-std/interfaces/ISignatureVerifier.sol";
import { IStablecoinDEX } from "tempo-std/interfaces/IStablecoinDEX.sol";
import { ITIP20 } from "tempo-std/interfaces/ITIP20.sol";
import { ITIP20Token } from "tempo-std/interfaces/ITIP20.sol";
import { ITIP20Factory } from "tempo-std/interfaces/ITIP20Factory.sol";
import { ITIP403Registry } from "tempo-std/interfaces/ITIP403Registry.sol";
import { IValidatorConfig } from "tempo-std/interfaces/IValidatorConfig.sol";

/// @notice Base test framework for all spec tests
/// pathUSD is just a TIP20 at a special address (0x20C0...) with token_id=0
contract BaseTest is PortalRuntimeTest {

    mapping(address portal => uint256 height) private _submittedZoneHeights;

    bytes32 private constant _PORTAL_TOKEN_ENABLEMENT_CURSOR_SLOT = bytes32(uint256(28));

    // Registry precompiles
    address internal constant _ACCOUNT_KEYCHAIN = StdPrecompiles.ACCOUNT_KEYCHAIN_ADDRESS;
    address internal constant _TIP403REGISTRY = StdPrecompiles.TIP403_REGISTRY_ADDRESS;
    address internal constant _TIP20FACTORY = StdPrecompiles.TIP20_FACTORY_ADDRESS;
    address internal constant _PATH_USD = 0x20C0000000000000000000000000000000000000;
    address internal constant _STABLECOIN_DEX = StdPrecompiles.STABLECOIN_DEX_ADDRESS;
    address internal constant _FEE_AMM = StdPrecompiles.TIP_FEE_MANAGER_ADDRESS;
    address internal constant _NONCE = StdPrecompiles.NONCE_ADDRESS;
    address internal constant _VALIDATOR_CONFIG = StdPrecompiles.VALIDATOR_CONFIG_ADDRESS;
    address internal constant _BLOCKHASH_HISTORY = EIP2935;
    address internal constant _ZONE_FACTORY = ZONE_FACTORY_ADDRESS;

    // EIP-2935 serve window: hashes for the most recent 8191 blocks are available
    // (block.number - 8191 ..= block.number - 1); reads outside that range return zero.
    uint256 internal constant BLOCKHASH_HISTORY_WINDOW = 8191;

    // Role constants
    bytes32 internal constant _ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 internal constant _PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 internal constant _UNPAUSE_ROLE = keccak256("UNPAUSE_ROLE");
    bytes32 internal constant _TRANSFER_ROLE = keccak256("TRANSFER_ROLE");
    bytes32 internal constant _RECEIVE_WITH_MEMO_ROLE = keccak256("RECEIVE_WITH_MEMO_ROLE");

    // Common test addresses
    address public admin = address(0x500);
    address public sequencer = address(this);
    address public alice = address(0x200);
    address public bob = address(0x300);
    address public charlie = address(0x400);
    address public pathUSDAdmin = address(0xb4c79daB8f259C7Aee6E5b2Aa729821864227e84);

    // Common test contracts
    IAccountKeychain public keychain = IAccountKeychain(_ACCOUNT_KEYCHAIN);
    ITIP20Factory public factory = ITIP20Factory(_TIP20FACTORY);
    ITIP20Token public pathUSD = ITIP20Token(_PATH_USD);
    IStablecoinDEX public exchange = IStablecoinDEX(_STABLECOIN_DEX);
    IFeeManager public amm = IFeeManager(_FEE_AMM);
    ITIP403Registry public registry = ITIP403Registry(_TIP403REGISTRY);
    INonce public nonce = INonce(_NONCE);
    IValidatorConfig public validatorConfig = IValidatorConfig(_VALIDATOR_CONFIG);
    ITIP20Token public token1;
    ITIP20Token public token2;
    MockZoneGateway public zoneGateway;

    error MissingPrecompile(string name, address addr);
    error CallShouldHaveReverted();

    function setUp() public virtual {
        zoneGateway = new MockZoneGateway();

        if (_ACCOUNT_KEYCHAIN.code.length == 0) {
            revert MissingPrecompile("AccountKeychain", _ACCOUNT_KEYCHAIN);
        }
        if (_TIP403REGISTRY.code.length == 0) {
            revert MissingPrecompile("TIP403Registry", _TIP403REGISTRY);
        }
        if (_TIP20FACTORY.code.length == 0) {
            revert MissingPrecompile("TIP20Factory", _TIP20FACTORY);
        }
        if (_PATH_USD.code.length == 0) {
            revert MissingPrecompile("pathUSD", _PATH_USD);
        }
        if (_STABLECOIN_DEX.code.length == 0) {
            revert MissingPrecompile("StablecoinDEX", _STABLECOIN_DEX);
        }
        if (_FEE_AMM.code.length == 0) {
            revert MissingPrecompile("FeeManager", _FEE_AMM);
        }
        if (_NONCE.code.length == 0) {
            revert MissingPrecompile("Nonce", _NONCE);
        }
        if (_VALIDATOR_CONFIG.code.length == 0) {
            revert MissingPrecompile("ValidatorConfig", _VALIDATOR_CONFIG);
        }

        if (_BLOCKHASH_HISTORY.code.length == 0) {
            revert MissingPrecompile("BlockHashHistory", _BLOCKHASH_HISTORY);
        }

        // Set ValidatorConfig owner to sequencer via direct storage write
        // owner is at slot 0 in ValidatorConfig
        vm.store(_VALIDATOR_CONFIG, bytes32(uint256(0)), bytes32(uint256(uint160(sequencer))));

        // Grant DEFAULT_ADMIN_ROLE to pathUSDAdmin
        bytes32 tempoAdminRoleSlot = keccak256(
            abi.encode(
                bytes32(0), // DEFAULT_ADMIN_ROLE
                keccak256(abi.encode(pathUSDAdmin, uint256(0)))
            )
        );
        vm.store(_PATH_USD, tempoAdminRoleSlot, bytes32(uint256(1)));

        token1 = ITIP20Token(
            factory.createToken(
                "TOKEN1", "T1", "USD", ITIP20(_PATH_USD), sequencer, bytes32("token1")
            )
        );
        token2 = ITIP20Token(
            factory.createToken(
                "TOKEN2", "T2", "USD", ITIP20(_PATH_USD), sequencer, bytes32("token2")
            )
        );

        _mockTokenPolicyMigration(_PATH_USD, true);
    }

    function _mockTokenPolicyMigration(address token, bool isSet) internal {
        address[] memory tokens = new address[](1);
        tokens[0] = token;
        vm.mockCall(
            _TIP403REGISTRY,
            abi.encodeCall(ITIP403Registry.migrateTransferPolicyIds, (tokens)),
            abi.encode(isSet ? 1 : 0)
        );
        vm.mockCall(
            _TIP403REGISTRY,
            abi.encodeCall(ITIP403Registry.tokenTransferPolicyId, (token)),
            abi.encode(isSet, uint64(1))
        );
    }

    function _zoneGateways() internal view returns (address[] memory gateways) {
        gateways = new address[](1);
        gateways[0] = address(zoneGateway);
    }

    function _closedLoopAccounts() internal view returns (address[] memory accounts) {
        accounts = new address[](4);
        accounts[0] = admin;
        accounts[1] = alice;
        accounts[2] = bob;
        accounts[3] = charlie;
    }

    /// @notice Installs the shared runtimes managed by the native TIP-1091 factory.
    function _installSharedZoneRuntimes() internal {
        vm.etch(ZONE_VERIFIER_ADDRESS, type(Verifier).runtimeCode);
        vm.etch(ZONE_MESSENGER_ADDRESS, type(ZoneMessenger).runtimeCode);
    }

    /// @notice Creates a canonical proxy with native-factory-equivalent storage.
    /// @dev Solidity initialize approximates the native factory's Rust storage writes;
    ///      native factory initialization is covered in Tempo integration tests.
    function _createZonePortal(
        uint32 zoneId,
        address initialToken,
        address portalAdmin,
        address[] memory sequencers,
        uint8 threshold,
        string memory rpcUrl
    )
        internal
        returns (ZonePortal portal)
    {
        _installSharedZoneRuntimes();
        portal = _newPortalProxy(zoneId);
        vm.prank(ZONE_FACTORY_ADDRESS);
        portal.initialize(
            zoneId,
            initialToken,
            true,
            true,
            _closedLoopAccounts(),
            _zoneGateways(),
            ZONE_MESSENGER_ADDRESS,
            portalAdmin,
            sequencers,
            threshold,
            ZONE_VERIFIER_ADDRESS,
            rpcUrl
        );

        vm.mockCall(
            ZONE_FACTORY_ADDRESS,
            abi.encodeCall(IZoneFactory.zones, (zoneId)),
            abi.encode(
                ZoneInfo({
                    zoneId: zoneId,
                    portal: address(portal),
                    accessMode: true,
                    gatewayMode: true,
                    admin: portalAdmin,
                    sequencers: sequencers,
                    threshold: threshold,
                    verifier: ZONE_VERIFIER_ADDRESS,
                    rpcUrl: rpcUrl
                })
            )
        );
    }

    /// @notice Submit the encrypted-only user deposit used by shared portal behavior tests.
    function _depositPayload(
        address to,
        bytes32 memo
    )
        internal
        pure
        returns (DepositPayload memory)
    {
        return DepositPayload({
            ephemeralPubkeyX: bytes32(
                0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
            ),
            ephemeralPubkeyYParity: 0x02,
            ciphertext: abi.encodePacked(to, memo, bytes12(0)),
            nonce: bytes12(0),
            tag: bytes16(0)
        });
    }

    /// @notice Submit the encrypted-only user deposit used by shared portal behavior tests.
    function _deposit(
        ZonePortal portal,
        address token,
        address to,
        uint128 amount,
        bytes32 memo,
        address tempoRefundRecipient
    )
        internal
        returns (bytes32)
    {
        uint256 keyCount = uint256(vm.load(address(portal), PORTAL_ENCRYPTION_KEYS_SLOT));
        if (keyCount == 0) {
            bytes32 entriesBase = keccak256(abi.encode(uint256(PORTAL_ENCRYPTION_KEYS_SLOT)));
            vm.store(address(portal), PORTAL_ENCRYPTION_KEYS_SLOT, bytes32(uint256(1)));
            vm.store(
                address(portal),
                entriesBase,
                bytes32(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
            );
            vm.store(
                address(portal),
                bytes32(uint256(entriesBase) + 1),
                bytes32((uint256(uint64(block.number)) << 8) | uint256(0x02))
            );
            keyCount = 1;
        }
        return portal.deposit(
            token, amount, keyCount - 1, _depositPayload(to, memo), tempoRefundRecipient
        );
    }

    function _singleWithdrawal(Withdrawal memory withdrawal)
        internal
        pure
        returns (Withdrawal[] memory withdrawals)
    {
        withdrawals = new Withdrawal[](1);
        withdrawals[0] = withdrawal;
    }

    /// @dev Read the packed cursor through a cheatcode so this helper does not consume a pending
    ///      `vm.prank` or `vm.expectRevert` before the portal call they are intended to guard.
    function _currentTokenEnablementTransition(IZonePortal portal)
        internal
        view
        returns (TokenEnablementTransition memory)
    {
        uint64 processedTokenCount =
            uint64(uint256(vm.load(address(portal), _PORTAL_TOKEN_ENABLEMENT_CURSOR_SLOT)));
        return TokenEnablementTransition({
            prevProcessedTokenCount: processedTokenCount,
            nextProcessedTokenCount: processedTokenCount
        });
    }

    /// @notice Submit through the TIP-1091 entrypoint while dedicated certificate tests exercise
    ///         the real signature precompile behavior independently.
    function _submitBatch(
        IZonePortal portal,
        uint64 tempoBlockNumber,
        uint64 recentTempoBlockNumber,
        BlockTransition memory blockTransition,
        DepositQueueTransition memory depositQueueTransition,
        bytes32 withdrawalQueueHash,
        bytes memory verifierConfig,
        bytes memory proof
    )
        internal
    {
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = hex"01";
        vm.mockCall(
            address(StdPrecompiles.SIGNATURE_VERIFIER),
            abi.encodeWithSelector(ISignatureVerifier.recover.selector),
            abi.encode(sequencer)
        );
        uint256 nextZoneHeight = _submittedZoneHeights[address(portal)] + 1;
        portal.submitBatch(
            tempoBlockNumber,
            recentTempoBlockNumber,
            blockTransition,
            depositQueueTransition,
            _currentTokenEnablementTransition(portal),
            withdrawalQueueHash,
            verifierConfig,
            proof,
            nextZoneHeight,
            signatures
        );
        _submittedZoneHeights[address(portal)] = nextZoneHeight;
    }

}
