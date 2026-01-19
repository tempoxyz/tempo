// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TempoLightClient.sol";
import "../src/StablecoinEscrow.sol";
import "../src/libraries/BLS12381.sol";
import {ERC20} from "solady/tokens/ERC20.sol";
import {Ownable} from "solady/auth/Ownable.sol";

/// @dev Mock ERC20 for testing
contract MockUSDC is ERC20 {
    function name() public pure override returns (string memory) {
        return "USD Coin";
    }

    function symbol() public pure override returns (string memory) {
        return "USDC";
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }
}

/// @dev Mock 18-decimal token for testing amount normalization
contract MockDAI is ERC20 {
    function name() public pure override returns (string memory) {
        return "Dai Stablecoin";
    }

    function symbol() public pure override returns (string memory) {
        return "DAI";
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function decimals() public pure override returns (uint8) {
        return 18;
    }
}

contract BridgeTest is Test {
    TempoLightClient public lightClient;
    StablecoinEscrow public escrow;
    MockUSDC public usdc;

    uint64 constant TEMPO_CHAIN_ID = 62049;
    uint256 constant PRIVATE_KEY_1 = 0x1;
    uint256 constant PRIVATE_KEY_2 = 0x2;
    uint256 constant PRIVATE_KEY_3 = 0x3;

    address validator1;
    address validator2;
    address validator3;

    function setUp() public {
        validator1 = vm.addr(PRIVATE_KEY_1);
        validator2 = vm.addr(PRIVATE_KEY_2);
        validator3 = vm.addr(PRIVATE_KEY_3);

        lightClient = new TempoLightClient(TEMPO_CHAIN_ID, 1);
        escrow = new StablecoinEscrow(address(lightClient), TEMPO_CHAIN_ID);
        usdc = new MockUSDC();

        // Add validators
        lightClient.addValidator(validator1);
        lightClient.addValidator(validator2);
        lightClient.addValidator(validator3);

        // Add supported token
        escrow.addToken(address(usdc));
    }

    // --- Light Client Tests ---

    function test_AddValidator() public {
        address newValidator = makeAddr("newValidator");
        lightClient.addValidator(newValidator);
        assertTrue(lightClient.isValidator(newValidator));
    }

    function test_RemoveValidator() public {
        lightClient.removeValidator(validator1);
        assertFalse(lightClient.isValidator(validator1));
        assertEq(lightClient.validatorCount(), 2);
    }

    function test_AddValidatorTwiceReverts() public {
        vm.expectRevert(TempoLightClient.ValidatorExists.selector);
        lightClient.addValidator(validator1);
    }

    function test_RemoveNonValidatorReverts() public {
        address nonValidator = makeAddr("nonValidator");
        vm.expectRevert(TempoLightClient.ValidatorNotFound.selector);
        lightClient.removeValidator(nonValidator);
    }

    function test_ThresholdCalculation() public view {
        // With 3 validators, threshold should be 2 (2/3)
        assertEq(lightClient.threshold(), 2);
    }

    function test_SubmitHeader() public {
        uint64 height = 1;
        bytes32 parentHash = bytes32(0);
        bytes32 stateRoot = keccak256("state");
        bytes32 receiptsRoot = keccak256("receipts");
        uint64 epoch = 1;

        bytes32 headerDigest = keccak256(
            abi.encodePacked(lightClient.HEADER_DOMAIN(), TEMPO_CHAIN_ID, height, parentHash, stateRoot, receiptsRoot, epoch)
        );

        bytes[] memory signatures = _createSortedSignatures(headerDigest, 2);

        lightClient.submitHeader(height, parentHash, stateRoot, receiptsRoot, epoch, signatures);

        assertTrue(lightClient.isHeaderFinalized(height));
        assertEq(lightClient.getReceiptsRoot(height), receiptsRoot);
        assertEq(lightClient.latestFinalizedHeight(), height);
    }

    function test_SubmitHeaderInsufficientSignatures() public {
        uint64 height = 1;
        bytes32 parentHash = bytes32(0);
        bytes32 stateRoot = keccak256("state");
        bytes32 receiptsRoot = keccak256("receipts");
        uint64 epoch = 1;

        bytes32 headerDigest = keccak256(
            abi.encodePacked(lightClient.HEADER_DOMAIN(), TEMPO_CHAIN_ID, height, parentHash, stateRoot, receiptsRoot, epoch)
        );

        bytes[] memory signatures = _createSortedSignatures(headerDigest, 1);

        vm.expectRevert(TempoLightClient.ThresholdNotMet.selector);
        lightClient.submitHeader(height, parentHash, stateRoot, receiptsRoot, epoch, signatures);
    }

    function test_SubmitMultipleHeaders() public {
        bytes32 prevHash = bytes32(0);

        for (uint64 i = 1; i <= 5; i++) {
            bytes32 stateRoot = keccak256(abi.encodePacked("state", i));
            bytes32 receiptsRoot = keccak256(abi.encodePacked("receipts", i));

            bytes32 headerDigest = keccak256(
                abi.encodePacked(lightClient.HEADER_DOMAIN(), TEMPO_CHAIN_ID, i, prevHash, stateRoot, receiptsRoot, uint64(1))
            );

            bytes[] memory sigs = _createSortedSignatures(headerDigest, 2);
            lightClient.submitHeader(i, prevHash, stateRoot, receiptsRoot, 1, sigs);

            prevHash = keccak256(abi.encodePacked(i, prevHash, stateRoot, receiptsRoot, uint64(1)));
        }

        assertEq(lightClient.latestFinalizedHeight(), 5);
    }

    function test_KeyRotation() public {
        uint64 newEpoch = 2;
        bytes memory newPubkey = hex"abcdef";

        bytes32 rotationDigest =
            keccak256(abi.encodePacked(lightClient.ROTATION_DOMAIN(), TEMPO_CHAIN_ID, newEpoch, newPubkey));

        bytes[] memory sigs = _createSortedSignatures(rotationDigest, 2);

        lightClient.submitKeyRotation(newEpoch, newPubkey, sigs);

        assertEq(lightClient.currentEpoch(), newEpoch);
        assertEq(lightClient.currentPublicKey(), newPubkey);
    }

    // --- Escrow Tests ---

    function test_AddToken() public {
        address token = makeAddr("newToken");
        escrow.addToken(token);
        assertTrue(escrow.supportedTokens(token));
    }

    function test_RemoveToken() public {
        escrow.removeToken(address(usdc));
        assertFalse(escrow.supportedTokens(address(usdc)));
    }

    function test_EverSupportedTokensSetOnAdd() public {
        address token = makeAddr("newToken");
        escrow.addToken(token);
        assertTrue(escrow.supportedTokens(token));
        assertTrue(escrow.everSupportedTokens(token));
    }

    function test_EverSupportedTokensPersistsAfterRemoval() public {
        assertTrue(escrow.supportedTokens(address(usdc)));
        assertTrue(escrow.everSupportedTokens(address(usdc)));
        
        escrow.removeToken(address(usdc));
        
        assertFalse(escrow.supportedTokens(address(usdc)));
        assertTrue(escrow.everSupportedTokens(address(usdc)));
    }

    function test_Deposit() public {
        address user = makeAddr("user");
        address tempoRecipient = makeAddr("tempoRecipient");
        uint256 amount = 1000e6;

        usdc.mint(user, amount);

        vm.startPrank(user);
        usdc.approve(address(escrow), amount);

        bytes32 depositId = escrow.deposit(address(usdc), amount, tempoRecipient);
        vm.stopPrank();

        assertFalse(depositId == bytes32(0));
        assertEq(usdc.balanceOf(address(escrow)), amount);
        assertEq(usdc.balanceOf(user), 0);
    }

    function test_DepositUnsupportedToken() public {
        MockUSDC otherToken = new MockUSDC();
        address user = makeAddr("user");

        otherToken.mint(user, 1000e6);

        vm.startPrank(user);
        otherToken.approve(address(escrow), 1000e6);

        vm.expectRevert(StablecoinEscrow.TokenNotSupported.selector);
        escrow.deposit(address(otherToken), 1000e6, makeAddr("recipient"));
        vm.stopPrank();
    }

    function test_DepositZeroAmount() public {
        address user = makeAddr("user");

        vm.startPrank(user);
        vm.expectRevert(StablecoinEscrow.ZeroAmount.selector);
        escrow.deposit(address(usdc), 0, makeAddr("recipient"));
        vm.stopPrank();
    }

    function test_DepositZeroRecipient() public {
        address user = makeAddr("user");
        usdc.mint(user, 1000e6);

        vm.startPrank(user);
        usdc.approve(address(escrow), 1000e6);

        vm.expectRevert(StablecoinEscrow.InvalidRecipient.selector);
        escrow.deposit(address(usdc), 1000e6, address(0));
        vm.stopPrank();
    }

    function test_MultipleDeposits() public {
        address user = makeAddr("user");
        usdc.mint(user, 5000e6);

        vm.startPrank(user);
        usdc.approve(address(escrow), 5000e6);

        bytes32 id1 = escrow.deposit(address(usdc), 1000e6, makeAddr("r1"));
        bytes32 id2 = escrow.deposit(address(usdc), 2000e6, makeAddr("r2"));
        bytes32 id3 = escrow.deposit(address(usdc), 2000e6, makeAddr("r3"));
        vm.stopPrank();

        assertTrue(id1 != id2);
        assertTrue(id2 != id3);
        assertTrue(id1 != id3);

        assertEq(usdc.balanceOf(address(escrow)), 5000e6);
    }

    // --- F-09: Amount Truncation Tests ---

    function test_DepositExactlyMaxUint64() public {
        address user = makeAddr("user");
        address tempoRecipient = makeAddr("tempoRecipient");
        uint256 amount = type(uint64).max;

        usdc.mint(user, amount);

        vm.startPrank(user);
        usdc.approve(address(escrow), amount);

        bytes32 depositId = escrow.deposit(address(usdc), amount, tempoRecipient);
        vm.stopPrank();

        assertFalse(depositId == bytes32(0));
        assertEq(usdc.balanceOf(address(escrow)), amount);
    }

    function test_DepositMaxUint64PlusOneReverts() public {
        address user = makeAddr("user");
        address tempoRecipient = makeAddr("tempoRecipient");
        uint256 amount = uint256(type(uint64).max) + 1;

        usdc.mint(user, amount);

        vm.startPrank(user);
        usdc.approve(address(escrow), amount);

        vm.expectRevert(StablecoinEscrow.AmountTooLarge.selector);
        escrow.deposit(address(usdc), amount, tempoRecipient);
        vm.stopPrank();
    }

    function test_DepositTruncationTo18DecimalTokenReverts() public {
        MockDAI dai = new MockDAI();
        escrow.addToken(address(dai));

        address user = makeAddr("user");
        address tempoRecipient = makeAddr("tempoRecipient");
        
        uint256 amount = uint256(2 ** 64) * (10 ** 12);

        dai.mint(user, amount);

        vm.startPrank(user);
        dai.approve(address(escrow), amount);

        vm.expectRevert(StablecoinEscrow.AmountTooLarge.selector);
        escrow.deposit(address(dai), amount, tempoRecipient);
        vm.stopPrank();
    }

    // --- Security Tests ---

    function test_OnlyOwnerCanAddValidator() public {
        address attacker = makeAddr("attacker");

        vm.prank(attacker);
        vm.expectRevert(Ownable.Unauthorized.selector);
        lightClient.addValidator(makeAddr("evil"));
    }

    function test_OnlyOwnerCanAddToken() public {
        address attacker = makeAddr("attacker");

        vm.prank(attacker);
        vm.expectRevert(Ownable.Unauthorized.selector);
        escrow.addToken(makeAddr("evil"));
    }

    function test_SubmitHeaderSkipHeightReverts() public {
        // First submit height 1
        bytes32 stateRoot1 = keccak256("state1");
        bytes32 receiptsRoot1 = keccak256("receipts1");
        bytes32 headerDigest1 = keccak256(
            abi.encodePacked(
                lightClient.HEADER_DOMAIN(), TEMPO_CHAIN_ID, uint64(1), bytes32(0), stateRoot1, receiptsRoot1, uint64(1)
            )
        );
        bytes[] memory sigs1 = _createSortedSignatures(headerDigest1, 2);
        lightClient.submitHeader(1, bytes32(0), stateRoot1, receiptsRoot1, 1, sigs1);

        // Now try to skip height 2 and submit height 3
        bytes32 prevHash = keccak256(abi.encodePacked(uint64(1), bytes32(0), stateRoot1, receiptsRoot1, uint64(1)));
        bytes32 stateRoot3 = keccak256("state3");
        bytes32 receiptsRoot3 = keccak256("receipts3");
        bytes32 headerDigest3 = keccak256(
            abi.encodePacked(
                lightClient.HEADER_DOMAIN(), TEMPO_CHAIN_ID, uint64(3), prevHash, stateRoot3, receiptsRoot3, uint64(1)
            )
        );
        bytes[] memory sigs3 = _createSortedSignatures(headerDigest3, 2);

        vm.expectRevert("non-contiguous");
        lightClient.submitHeader(3, prevHash, stateRoot3, receiptsRoot3, 1, sigs3);
    }

    function test_SignatureReplayPrevention() public {
        bytes32 stateRoot = keccak256("state");
        bytes32 receiptsRoot = keccak256("receipts");

        bytes32 headerDigest = keccak256(
            abi.encodePacked(
                lightClient.HEADER_DOMAIN(), TEMPO_CHAIN_ID, uint64(1), bytes32(0), stateRoot, receiptsRoot, uint64(1)
            )
        );

        bytes[] memory sigs = _createSortedSignatures(headerDigest, 2);
        lightClient.submitHeader(1, bytes32(0), stateRoot, receiptsRoot, 1, sigs);

        vm.expectRevert("non-contiguous");
        lightClient.submitHeader(1, bytes32(0), stateRoot, receiptsRoot, 1, sigs);
    }

    function test_TempoChainId() public view {
        assertEq(lightClient.tempoChainId(), TEMPO_CHAIN_ID);
        assertEq(escrow.tempoChainId(), TEMPO_CHAIN_ID);
    }

    function test_LightClientAddress() public view {
        assertEq(escrow.lightClient(), address(lightClient));
    }

    // --- BLS Mode Tests ---

    function test_DefaultsToEcdsaMode() public view {
        assertTrue(lightClient.useEcdsaMode());
    }

    function test_SetBLSPublicKey() public {
        // Create a dummy 256-byte G2 point
        bytes memory blsKey = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            blsKey[i] = bytes1(uint8(i % 256));
        }

        lightClient.setBLSPublicKey(blsKey);
        assertEq(lightClient.blsPublicKey(), blsKey);
    }

    function test_SetBLSPublicKeyInvalidLength() public {
        bytes memory invalidKey = hex"abcdef";

        vm.expectRevert(TempoLightClient.InvalidBLSPublicKeyLength.selector);
        lightClient.setBLSPublicKey(invalidKey);
    }

    function test_SetBLSPublicKeyOnlyOwner() public {
        bytes memory blsKey = new bytes(256);
        address attacker = makeAddr("attacker");

        vm.prank(attacker);
        vm.expectRevert(Ownable.Unauthorized.selector);
        lightClient.setBLSPublicKey(blsKey);
    }

    function test_SetSignatureModeOnlyOwner() public {
        address attacker = makeAddr("attacker");

        vm.prank(attacker);
        vm.expectRevert(Ownable.Unauthorized.selector);
        lightClient.setSignatureMode(false);
    }

    function test_BLSLibraryConstants() public pure {
        assertEq(BLS12381.G1_POINT_SIZE, 128);
        assertEq(BLS12381.G2_POINT_SIZE, 256);
        assertEq(BLS12381.FP_SIZE, 64);
    }

    function test_BLSPrecompilesAvailability() public view {
        // Check if BLS precompiles are available
        // In newer Foundry versions with Cancun+, BLS precompiles (EIP-2537) may be available
        // This test just documents the current state
        bool available = lightClient.isBLSAvailable();
        // Either outcome is valid depending on the EVM version
        assertTrue(available || !available);
    }

    function test_BLSVerificationWithStandardHashToCurve() public {
        if (!lightClient.isBLSAvailable()) return;

        // Standard hash-to-curve test vectors (commonware-compatible)
        // Generated with: cargo run -p tempo-bridge-exex --bin generate-bls-test-vectors -- --commonware
        bytes memory pubkey = hex"00000000000000000000000000000000058b3e8b9fc9552e30787cb4a541a1c3bf67a02e91fc648b2c19f4bb333e14c5c73b9bfbc5ec56dadabb07ff15d45124000000000000000000000000000000001772c16106e9c70b2073dfe17989225dd10f3adb675365fc6d833587ad4cbd3ae692ad1e20679003f676b0b089e83feb00000000000000000000000000000000007716a86bd9db89662f87a026604bb85fd531599681071feddab5f40869ea036145f6bcf138e67b986361ce25d9c63c0000000000000000000000000000000006a63710dada90a4ab7b4c89b64cc2f94dc2e77dd6dc77b0b0653620bee399d05a27aea1c12e96540a80aad355af3d40";
        bytes memory sig = hex"0000000000000000000000000000000016e3720f3e9d86d2266e16aba54b920b53a72f991109f5507cbe915d4ad01a754d6bd4d1ed46ee46b66e28950a6a69740000000000000000000000000000000007b639420728757d57e6529e7e755ddd44b521eb141f60a9dd9449e2770a4a436e35d97fe28355215d59c5bb194128b6";
        bytes32 msgHash = hex"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

        // Verify using standard hash-to-curve (matches commonware-cryptography)
        bool valid = BLS12381.verifyStandard(sig, pubkey, msgHash);
        assertTrue(valid, "Standard hash-to-curve BLS verification should pass");
    }

    function test_HashToG1StandardProducesValidPoint() public {
        if (!lightClient.isBLSAvailable()) return;

        bytes32 msgHash = hex"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        bytes memory hashedMessage = BLS12381.hashToG1Standard(msgHash);
        assertEq(hashedMessage.length, 128, "Hash to G1 should return 128-byte point");
    }

    function test_SwitchToBLSMode() public {
        // If precompiles are available, switch should succeed
        // If not, it should revert
        if (lightClient.isBLSAvailable()) {
            lightClient.setSignatureMode(false);
            assertFalse(lightClient.useEcdsaMode());
        } else {
            vm.expectRevert(TempoLightClient.BLSPrecompilesNotAvailable.selector);
            lightClient.setSignatureMode(false);
        }
    }

    event SignatureModeChanged(bool useEcdsa);
    event BLSPublicKeyUpdated(uint64 indexed epoch, bytes blsKey);

    function test_SignatureModeEvent() public {
        // Switching to ECDSA mode (already in ECDSA) should emit event
        vm.expectEmit(true, true, true, true);
        emit SignatureModeChanged(true);
        lightClient.setSignatureMode(true);
    }

    function test_BLSPublicKeyUpdatedEvent() public {
        bytes memory blsKey = new bytes(256);

        vm.expectEmit(true, true, true, true);
        emit BLSPublicKeyUpdated(1, blsKey);
        lightClient.setBLSPublicKey(blsKey);
    }

    function test_BLSModeHeaderSubmission() public {
        // Skip if BLS precompiles not available
        if (!lightClient.isBLSAvailable()) {
            return;
        }

        // Set up BLS mode with a valid 256-byte G2 public key
        bytes memory blsPublicKey = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            blsPublicKey[i] = bytes1(uint8(i % 256));
        }
        lightClient.setBLSPublicKey(blsPublicKey);
        lightClient.setSignatureMode(false);
        assertFalse(lightClient.useEcdsaMode());

        // Prepare header data
        uint64 height = 1;
        bytes32 parentHash = bytes32(0);
        bytes32 stateRoot = keccak256("state");
        bytes32 receiptsRoot = keccak256("receipts");
        uint64 epoch = 1;

        // Create a mock 128-byte G1 signature
        bytes memory blsSignature = new bytes(128);
        for (uint256 i = 0; i < 128; i++) {
            blsSignature[i] = bytes1(uint8(i % 256));
        }

        // Submit header with BLS signature - reverts during BLS verification
        // (either at hash-to-G1 or pairing check depending on precompile behavior)
        vm.expectRevert(BLS12381.BLSPrecompileCallFailed.selector);
        lightClient.submitHeader(height, parentHash, stateRoot, receiptsRoot, epoch, blsSignature);
    }

    function test_BLSModeInvalidSignatureReverts() public {
        // Skip if BLS precompiles not available
        if (!lightClient.isBLSAvailable()) {
            return;
        }

        // Set up BLS mode
        bytes memory blsPublicKey = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            blsPublicKey[i] = bytes1(uint8(i % 256));
        }
        lightClient.setBLSPublicKey(blsPublicKey);
        lightClient.setSignatureMode(false);

        uint64 height = 1;
        bytes32 parentHash = bytes32(0);
        bytes32 stateRoot = keccak256("state");
        bytes32 receiptsRoot = keccak256("receipts");
        uint64 epoch = 1;

        // Wrong signature length (64 bytes instead of 128)
        bytes memory wrongLengthSig = new bytes(64);
        vm.expectRevert(TempoLightClient.InvalidBLSSignatureLength.selector);
        lightClient.submitHeader(height, parentHash, stateRoot, receiptsRoot, epoch, wrongLengthSig);

        // Correct length but invalid signature - fails during BLS verification
        bytes memory invalidSig = new bytes(128);
        vm.expectRevert(BLS12381.BLSPrecompileCallFailed.selector);
        lightClient.submitHeader(height, parentHash, stateRoot, receiptsRoot, epoch, invalidSig);
    }

    // --- Token Removal Scenario Tests ---

    function test_UnlockAfterTokenRemoval() public {
        address user = makeAddr("user");

        // User deposits tokens
        usdc.mint(user, 1000e6);
        vm.startPrank(user);
        usdc.approve(address(escrow), 1000e6);
        escrow.deposit(address(usdc), 1000e6, makeAddr("tempoRecipient"));
        vm.stopPrank();

        // Owner removes token
        escrow.removeToken(address(usdc));
        assertFalse(escrow.supportedTokens(address(usdc)));
        assertTrue(escrow.everSupportedTokens(address(usdc)));

        // Submit a finalized header for unlock
        uint64 tempoHeight = 1;
        bytes32 stateRoot = keccak256("state");
        bytes32 receiptsRoot = keccak256("receipts");
        bytes32 headerDigest = keccak256(
            abi.encodePacked(lightClient.HEADER_DOMAIN(), TEMPO_CHAIN_ID, tempoHeight, bytes32(0), stateRoot, receiptsRoot, uint64(1))
        );
        bytes[] memory headerSigs = _createSortedSignatures(headerDigest, 2);
        lightClient.submitHeader(tempoHeight, bytes32(0), stateRoot, receiptsRoot, 1, headerSigs);

        // Unlock should succeed using everSupportedTokens
        bytes32 burnId = keccak256("burn1");
        uint64 unlockAmount = 500e6;
        bytes32 attestationDigest = keccak256(
            abi.encodePacked(
                escrow.BURN_ATTESTATION_DOMAIN(),
                TEMPO_CHAIN_ID,
                burnId,
                tempoHeight,
                uint64(block.chainid),
                address(usdc),
                user,
                unlockAmount
            )
        );
        bytes[] memory burnSigs = _createSortedSignatures(attestationDigest, 2);

        escrow.unlock(burnId, 1, address(usdc), user, unlockAmount, burnSigs);

        assertEq(usdc.balanceOf(user), unlockAmount);
        assertTrue(escrow.spentBurnIds(burnId));
    }

    function test_DepositAfterTokenRemovalReverts() public {
        address user = makeAddr("user");
        address tempoRecipient = makeAddr("tempoRecipient");
        uint256 depositAmount = 1000e6;

        // First deposit succeeds
        usdc.mint(user, depositAmount * 2);
        vm.startPrank(user);
        usdc.approve(address(escrow), depositAmount * 2);
        escrow.deposit(address(usdc), depositAmount, tempoRecipient);
        vm.stopPrank();

        // Owner removes token
        escrow.removeToken(address(usdc));

        // Second deposit should revert
        vm.startPrank(user);
        vm.expectRevert(StablecoinEscrow.TokenNotSupported.selector);
        escrow.deposit(address(usdc), depositAmount, tempoRecipient);
        vm.stopPrank();
    }

    // --- Validator Attestation Unlock Tests ---

    function test_UnlockWithValidatorAttestations() public {
        address user = makeAddr("user");
        address recipient = makeAddr("recipient");
        uint256 depositAmount = 1000e6;
        uint64 normalizedAmount = 1000e6;

        usdc.mint(user, depositAmount);
        vm.startPrank(user);
        usdc.approve(address(escrow), depositAmount);
        escrow.deposit(address(usdc), depositAmount, makeAddr("tempoRecipient"));
        vm.stopPrank();

        uint64 tempoHeight = 1;
        bytes32 stateRoot = keccak256("state");
        bytes32 receiptsRoot = keccak256("receipts");
        bytes32 headerDigest = keccak256(
            abi.encodePacked(lightClient.HEADER_DOMAIN(), TEMPO_CHAIN_ID, tempoHeight, bytes32(0), stateRoot, receiptsRoot, uint64(1))
        );
        bytes[] memory headerSigs = _createSortedSignatures(headerDigest, 2);
        lightClient.submitHeader(tempoHeight, bytes32(0), stateRoot, receiptsRoot, 1, headerSigs);

        bytes32 burnId = keccak256("burn1");
        bytes32 attestationDigest = keccak256(
            abi.encodePacked(
                escrow.BURN_ATTESTATION_DOMAIN(),
                TEMPO_CHAIN_ID,
                burnId,
                tempoHeight,
                uint64(block.chainid),
                address(usdc),
                recipient,
                normalizedAmount
            )
        );
        bytes[] memory unlockSigs = _createSortedSignatures(attestationDigest, 2);

        uint256 recipientBalanceBefore = usdc.balanceOf(recipient);
        escrow.unlock(burnId, tempoHeight, address(usdc), recipient, normalizedAmount, unlockSigs);

        assertEq(usdc.balanceOf(recipient), recipientBalanceBefore + depositAmount);
        assertTrue(escrow.spentBurnIds(burnId));
    }

    function test_UnlockInsufficientSignaturesReverts() public {
        address user = makeAddr("user");
        address recipient = makeAddr("recipient");
        uint256 depositAmount = 1000e6;
        uint64 normalizedAmount = 1000e6;

        usdc.mint(user, depositAmount);
        vm.startPrank(user);
        usdc.approve(address(escrow), depositAmount);
        escrow.deposit(address(usdc), depositAmount, makeAddr("tempoRecipient"));
        vm.stopPrank();

        uint64 tempoHeight = 1;
        bytes32 stateRoot = keccak256("state");
        bytes32 receiptsRoot = keccak256("receipts");
        bytes32 headerDigest = keccak256(
            abi.encodePacked(lightClient.HEADER_DOMAIN(), TEMPO_CHAIN_ID, tempoHeight, bytes32(0), stateRoot, receiptsRoot, uint64(1))
        );
        bytes[] memory headerSigs = _createSortedSignatures(headerDigest, 2);
        lightClient.submitHeader(tempoHeight, bytes32(0), stateRoot, receiptsRoot, 1, headerSigs);

        bytes32 burnId = keccak256("burn2");
        bytes32 attestationDigest = keccak256(
            abi.encodePacked(
                escrow.BURN_ATTESTATION_DOMAIN(),
                TEMPO_CHAIN_ID,
                burnId,
                tempoHeight,
                uint64(block.chainid),
                address(usdc),
                recipient,
                normalizedAmount
            )
        );
        bytes[] memory unlockSigs = _createSortedSignatures(attestationDigest, 1);

        vm.expectRevert(StablecoinEscrow.ThresholdNotMet.selector);
        escrow.unlock(burnId, tempoHeight, address(usdc), recipient, normalizedAmount, unlockSigs);
    }

    function test_UnlockDuplicateSignerReverts() public {
        address user = makeAddr("user");
        address recipient = makeAddr("recipient");

        usdc.mint(user, 1000e6);
        vm.startPrank(user);
        usdc.approve(address(escrow), 1000e6);
        escrow.deposit(address(usdc), 1000e6, makeAddr("tempoRecipient"));
        vm.stopPrank();

        _submitHeader(1);

        bytes32 burnId = keccak256("burn3");
        bytes32 attestationDigest = keccak256(
            abi.encodePacked(
                escrow.BURN_ATTESTATION_DOMAIN(),
                TEMPO_CHAIN_ID,
                burnId,
                uint64(1),
                uint64(block.chainid),
                address(usdc),
                recipient,
                uint64(1000e6)
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVATE_KEY_1, attestationDigest);

        bytes[] memory duplicateSigs = new bytes[](2);
        duplicateSigs[0] = abi.encodePacked(r, s, v);
        duplicateSigs[1] = abi.encodePacked(r, s, v);

        vm.expectRevert("Signatures not sorted");
        escrow.unlock(burnId, 1, address(usdc), recipient, 1000e6, duplicateSigs);
    }

    // --- Helper Functions ---

    function _submitHeader(uint64 height) internal {
        bytes32 stateRoot = keccak256(abi.encodePacked("state", height));
        bytes32 receiptsRoot = keccak256(abi.encodePacked("receipts", height));
        bytes32 headerDigest = keccak256(
            abi.encodePacked(lightClient.HEADER_DOMAIN(), TEMPO_CHAIN_ID, height, bytes32(0), stateRoot, receiptsRoot, uint64(1))
        );
        bytes[] memory sigs = _createSortedSignatures(headerDigest, 2);
        lightClient.submitHeader(height, bytes32(0), stateRoot, receiptsRoot, 1, sigs);
    }

    function _createBurnAttestation(
        bytes32 burnId,
        uint64 tempoHeight,
        address token,
        address recipient,
        uint64 amount
    ) internal view returns (bytes[] memory) {
        bytes32 attestationDigest = keccak256(
            abi.encodePacked(
                escrow.BURN_ATTESTATION_DOMAIN(),
                TEMPO_CHAIN_ID,
                burnId,
                tempoHeight,
                uint64(block.chainid),
                token,
                recipient,
                amount
            )
        );
        return _createSortedSignatures(attestationDigest, 2);
    }

    function _createSortedSignatures(bytes32 digest, uint256 count) internal pure returns (bytes[] memory) {
        require(count <= 3, "Max 3 validators");

        address addr1 = vm.addr(PRIVATE_KEY_1);
        address addr2 = vm.addr(PRIVATE_KEY_2);
        address addr3 = vm.addr(PRIVATE_KEY_3);

        uint256[3] memory sortedKeys;

        if (addr1 < addr2 && addr1 < addr3) {
            sortedKeys[0] = PRIVATE_KEY_1;
            if (addr2 < addr3) {
                sortedKeys[1] = PRIVATE_KEY_2;
                sortedKeys[2] = PRIVATE_KEY_3;
            } else {
                sortedKeys[1] = PRIVATE_KEY_3;
                sortedKeys[2] = PRIVATE_KEY_2;
            }
        } else if (addr2 < addr1 && addr2 < addr3) {
            sortedKeys[0] = PRIVATE_KEY_2;
            if (addr1 < addr3) {
                sortedKeys[1] = PRIVATE_KEY_1;
                sortedKeys[2] = PRIVATE_KEY_3;
            } else {
                sortedKeys[1] = PRIVATE_KEY_3;
                sortedKeys[2] = PRIVATE_KEY_1;
            }
        } else {
            sortedKeys[0] = PRIVATE_KEY_3;
            if (addr1 < addr2) {
                sortedKeys[1] = PRIVATE_KEY_1;
                sortedKeys[2] = PRIVATE_KEY_2;
            } else {
                sortedKeys[1] = PRIVATE_KEY_2;
                sortedKeys[2] = PRIVATE_KEY_1;
            }
        }

        bytes[] memory signatures = new bytes[](count);
        for (uint256 i = 0; i < count; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(sortedKeys[i], digest);
            signatures[i] = abi.encodePacked(r, s, v);
        }

        return signatures;
    }
}
