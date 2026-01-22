// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Test } from "forge-std/Test.sol";

/// @title ActorManager - Test Actor Management
/// @notice Manages test actors (accounts) with their keys and state
/// @dev Used by invariant tests to create and manage multiple test accounts
abstract contract ActorManager is Test {

    uint256 internal constant NUM_ACTORS = 5;
    uint256 internal constant ACCESS_KEYS_PER_ACTOR = 3;

    /// @notice Signature type enumeration (matches IAccountKeychain.SignatureType)
    enum SignatureType {
        Secp256k1,
        P256,
        WebAuthn,
        AccessKey
    }

    /// @dev Actor addresses
    address[] public actors;

    /// @dev Actor private keys for secp256k1 (indexed same as actors array)
    uint256[] internal actorKeys;

    /// @dev Actor P256 private keys (indexed same as actors array)
    uint256[] internal actorP256Keys;

    /// @dev Actor P256 public key X coordinates
    bytes32[] internal actorP256PubKeyX;

    /// @dev Actor P256 public key Y coordinates
    bytes32[] internal actorP256PubKeyY;

    /// @dev Actor P256-derived addresses
    address[] internal actorP256Addresses;

    /// @dev Access keys per actor: actor index => array of access key addresses
    mapping(uint256 => address[]) public actorAccessKeys;

    /// @dev Access key private keys: actor index => key address => private key
    mapping(uint256 => mapping(address => uint256)) internal actorAccessKeyPrivateKeys;

    /// @dev P256 access keys per actor: actor index => array of key addresses (derived from P256 pubkey)
    mapping(uint256 => address[]) public actorP256AccessKeys;

    /// @dev P256 access key private keys: actor index => key address => private key
    mapping(uint256 => mapping(address => uint256)) internal actorP256AccessKeyPrivateKeys;

    /// @dev P256 access key public key X: actor index => key address => pubKeyX
    mapping(uint256 => mapping(address => bytes32)) internal actorP256AccessKeyPubX;

    /// @dev P256 access key public key Y: actor index => key address => pubKeyY
    mapping(uint256 => mapping(address => bytes32)) internal actorP256AccessKeyPubY;

    /// @dev Mapping from address to actor index for quick lookup
    mapping(address => uint256) public actorIndex;

    /// @dev Whether an address is a known actor
    mapping(address => bool) public isActor;

    /// @notice Initialize all actors with their keys
    function _initActors() internal {
        for (uint256 i = 0; i < NUM_ACTORS; i++) {
            string memory label = string(abi.encodePacked("actor", vm.toString(i + 1)));
            (address actor, uint256 pk) = makeAddrAndKey(label);

            actors.push(actor);
            actorKeys.push(pk);
            actorIndex[actor] = i;
            isActor[actor] = true;

            // Generate P256 key for this actor
            uint256 p256Pk = uint256(keccak256(abi.encodePacked("p256_", label)))
                % 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550; // P256 order - 1
            if (p256Pk == 0) p256Pk = 1;
            actorP256Keys.push(p256Pk);

            (uint256 pubKeyX, uint256 pubKeyY) = vm.publicKeyP256(p256Pk);
            actorP256PubKeyX.push(bytes32(pubKeyX));
            actorP256PubKeyY.push(bytes32(pubKeyY));

            // Derive P256 address: keccak256(x || y)[12:]
            address p256Addr =
                address(uint160(uint256(keccak256(abi.encodePacked(pubKeyX, pubKeyY)))));
            actorP256Addresses.push(p256Addr);

            // Create secp256k1 access keys for each actor
            for (uint256 j = 0; j < ACCESS_KEYS_PER_ACTOR; j++) {
                string memory keyLabel = string(
                    abi.encodePacked("actor", vm.toString(i + 1), "_key", vm.toString(j + 1))
                );
                (address keyAddr, uint256 keyPk) = makeAddrAndKey(keyLabel);

                actorAccessKeys[i].push(keyAddr);
                actorAccessKeyPrivateKeys[i][keyAddr] = keyPk;
            }

            // Create P256 access keys for each actor
            for (uint256 j = 0; j < ACCESS_KEYS_PER_ACTOR; j++) {
                string memory keyLabel = string(
                    abi.encodePacked("actor", vm.toString(i + 1), "_p256key", vm.toString(j + 1))
                );
                uint256 keyP256Pk = uint256(keccak256(abi.encodePacked("p256_", keyLabel)))
                    % 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550;
                if (keyP256Pk == 0) keyP256Pk = 1;

                (uint256 keyPubX, uint256 keyPubY) = vm.publicKeyP256(keyP256Pk);
                address keyP256Addr =
                    address(uint160(uint256(keccak256(abi.encodePacked(keyPubX, keyPubY)))));

                actorP256AccessKeys[i].push(keyP256Addr);
                actorP256AccessKeyPrivateKeys[i][keyP256Addr] = keyP256Pk;
                actorP256AccessKeyPubX[i][keyP256Addr] = bytes32(keyPubX);
                actorP256AccessKeyPubY[i][keyP256Addr] = bytes32(keyPubY);
            }
        }
    }

    /// @notice Get actor address and private key by index
    function _getActor(uint256 index) internal view returns (address addr, uint256 privateKey) {
        require(index < actors.length, "Actor index out of bounds");
        return (actors[index], actorKeys[index]);
    }

    /// @notice Get actor P256 key info by index
    function _getActorP256(uint256 index)
        internal
        view
        returns (address p256Addr, uint256 privateKey, bytes32 pubKeyX, bytes32 pubKeyY)
    {
        require(index < actors.length, "Actor index out of bounds");
        return (
            actorP256Addresses[index],
            actorP256Keys[index],
            actorP256PubKeyX[index],
            actorP256PubKeyY[index]
        );
    }

    /// @notice Get actor by seed (for fuzzing)
    function _getActorBySeed(uint256 seed)
        internal
        view
        returns (uint256 index, address addr, uint256 privateKey)
    {
        index = seed % actors.length;
        (addr, privateKey) = _getActor(index);
    }

    /// @notice Get a different actor than the given one (for transfers)
    function _getDifferentActor(uint256 excludeIndex)
        internal
        view
        returns (uint256 index, address addr)
    {
        index = (excludeIndex + 1) % actors.length;
        addr = actors[index];
    }

    /// @notice Get secp256k1 access key for an actor
    function _getActorAccessKey(uint256 actorIdx, uint256 keySeed)
        internal
        view
        returns (address keyAddr, uint256 keyPk)
    {
        require(actorIdx < actors.length, "Actor index out of bounds");
        address[] storage keys = actorAccessKeys[actorIdx];
        require(keys.length > 0, "No access keys for actor");

        uint256 keyIdx = keySeed % keys.length;
        keyAddr = keys[keyIdx];
        keyPk = actorAccessKeyPrivateKeys[actorIdx][keyAddr];
    }

    /// @notice Get P256 access key for an actor
    function _getActorP256AccessKey(uint256 actorIdx, uint256 keySeed)
        internal
        view
        returns (address keyAddr, uint256 keyPk, bytes32 pubKeyX, bytes32 pubKeyY)
    {
        require(actorIdx < actors.length, "Actor index out of bounds");
        address[] storage keys = actorP256AccessKeys[actorIdx];
        require(keys.length > 0, "No P256 access keys for actor");

        uint256 keyIdx = keySeed % keys.length;
        keyAddr = keys[keyIdx];
        keyPk = actorP256AccessKeyPrivateKeys[actorIdx][keyAddr];
        pubKeyX = actorP256AccessKeyPubX[actorIdx][keyAddr];
        pubKeyY = actorP256AccessKeyPubY[actorIdx][keyAddr];
    }

    function _getRandomSignatureType(uint256 seed) internal pure returns (SignatureType) {
        return SignatureType(seed % 4);
    }

    function _actorCount() internal view returns (uint256) {
        return actors.length;
    }

    function _getAllActors() internal view returns (address[] memory) {
        return actors;
    }

    // ============ Transfer Context Helper ============

    struct TransferContext {
        uint256 senderIdx;
        address sender;
        address recipient;
        SignatureType sigType;
    }

    /// @notice Setup a transfer between two different actors
    function _setupTransfer(uint256 actorSeed, uint256 recipientSeed, uint256 sigTypeSeed)
        internal
        view
        returns (TransferContext memory ctx)
    {
        ctx.senderIdx = actorSeed % actors.length;
        uint256 recipientIdx = recipientSeed % actors.length;
        if (ctx.senderIdx == recipientIdx) {
            recipientIdx = (recipientIdx + 1) % actors.length;
        }

        ctx.sigType = _getRandomSignatureType(sigTypeSeed);
        ctx.sender = _getSenderForSigType(ctx.senderIdx, ctx.sigType);
        ctx.recipient = actors[recipientIdx];
    }

    function _getSenderForSigType(uint256 actorIdx, SignatureType sigType)
        internal
        view
        returns (address)
    {
        if (sigType == SignatureType.Secp256k1 || sigType == SignatureType.AccessKey) {
            return actors[actorIdx];
        } else {
            return actorP256Addresses[actorIdx];
        }
    }

}
