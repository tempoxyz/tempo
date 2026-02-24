// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { IValidatorConfig } from "../src/interfaces/IValidatorConfig.sol";
import { IValidatorConfigV2 } from "../src/interfaces/IValidatorConfigV2.sol";
import { BaseTest } from "./BaseTest.t.sol";

contract ValidatorConfigV2Test is BaseTest {

    error InvalidSignatureFormat();

    address public validator1 = address(0x2000);
    address public validator2 = address(0x3000);
    address public validator3 = address(0x4000);
    address public nonOwner = address(0x6000);

    // setUp V1 validators (distinct from test fixtures to avoid collisions)
    address public setupVal1 = address(0xA000);
    address public setupVal2 = address(0xB000);

    // Ed25519 keypairs — generated dynamically in setUp() via vm.createEd25519Key()
    bytes32 internal SETUP_PUB_KEY_A;
    bytes32 internal SETUP_PRIV_KEY_A;
    bytes32 internal SETUP_PUB_KEY_B;
    bytes32 internal SETUP_PRIV_KEY_B;

    bytes32 internal PUB_KEY_0;
    bytes32 internal PRIV_KEY_0;
    bytes32 internal PUB_KEY_1;
    bytes32 internal PRIV_KEY_1;
    bytes32 internal PUB_KEY_2;
    bytes32 internal PRIV_KEY_2;
    bytes32 internal PUB_KEY_3;
    bytes32 internal PRIV_KEY_3;

    string public ingress1 = "192.168.1.1:8000";
    string public egress1 = "192.168.1.1";
    string public ingress2 = "192.168.1.2:8000";
    string public egress2 = "192.168.1.2";
    string public ingress3 = "10.0.0.1:8000";
    string public egress3 = "10.0.0.1";

    function _signAdd(
        bytes32 privateKey,
        address validatorAddress,
        string memory ingress,
        string memory egress
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 message = keccak256(
            abi.encodePacked(
                uint64(block.chainid), address(validatorConfigV2), validatorAddress, ingress, egress
            )
        );
        // Forge's signEd25519 does simple concat(namespace, message), but the Rust
        // precompile uses commonware's union_unique: varint(len) || namespace || message.
        // Prepend uint8(len) to the namespace so Forge's concat matches commonware.
        bytes memory ns = bytes("TEMPO_VALIDATOR_CONFIG_V2_ADD_VALIDATOR");
        return vm.signEd25519(
            abi.encodePacked(uint8(ns.length), ns), abi.encodePacked(message), privateKey
        );
    }

    function _signRotate(
        bytes32 privateKey,
        address validatorAddress,
        string memory ingress,
        string memory egress
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 message = keccak256(
            abi.encodePacked(
                uint64(block.chainid), address(validatorConfigV2), validatorAddress, ingress, egress
            )
        );
        bytes memory ns = bytes("TEMPO_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR");
        return vm.signEd25519(
            abi.encodePacked(uint8(ns.length), ns), abi.encodePacked(message), privateKey
        );
    }

    function setUp() public override {
        super.setUp();

        // Generate Ed25519 keypairs deterministically
        (SETUP_PUB_KEY_A, SETUP_PRIV_KEY_A) = vm.createEd25519Key(keccak256("setup_key_a"));
        (SETUP_PUB_KEY_B, SETUP_PRIV_KEY_B) = vm.createEd25519Key(keccak256("setup_key_b"));
        (PUB_KEY_0, PRIV_KEY_0) = vm.createEd25519Key(keccak256("test_key_0"));
        (PUB_KEY_1, PRIV_KEY_1) = vm.createEd25519Key(keccak256("test_key_1"));
        (PUB_KEY_2, PRIV_KEY_2) = vm.createEd25519Key(keccak256("test_key_2"));
        (PUB_KEY_3, PRIV_KEY_3) = vm.createEd25519Key(keccak256("test_key_3"));

        // Add two V1 validators so _initializeV2() has something to migrate.
        // Migration copies V1's owner to V2, so no direct storage writes needed.
        validatorConfig.addValidator(
            setupVal1, SETUP_PUB_KEY_A, true, "10.0.0.100:8000", "10.0.0.100:9000"
        );
        validatorConfig.addValidator(
            setupVal2, SETUP_PUB_KEY_B, true, "10.0.0.101:8000", "10.0.0.101:9000"
        );
    }

    /// @dev Migrates all V1 validators to V2, then calls initializeIfMigrated().
    function _initializeV2() internal {
        IValidatorConfig.Validator[] memory v1Vals = validatorConfig.getValidators();
        for (uint64 i = 0; i < v1Vals.length; i++) {
            validatorConfigV2.migrateValidator(i);
        }
        validatorConfigV2.initializeIfMigrated();
    }

    /*//////////////////////////////////////////////////////////////
                           ADD VALIDATOR
    //////////////////////////////////////////////////////////////*/

    function test_addValidator_pass() public {
        _initializeV2();

        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );
        validatorConfigV2.addValidator(
            validator2,
            PUB_KEY_1,
            ingress2,
            egress2,
            _signAdd(PRIV_KEY_1, validator2, ingress2, egress2)
        );
        validatorConfigV2.addValidator(
            validator3,
            PUB_KEY_2,
            ingress3,
            egress3,
            _signAdd(PRIV_KEY_2, validator3, ingress3, egress3)
        );

        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();
        assertEq(vals.length, 5); // 2 setup + 3 added

        // First two are migrated setup validators
        assertEq(vals[0].validatorAddress, setupVal1);
        assertEq(vals[1].validatorAddress, setupVal2);

        // Newly added validators start at index 2
        assertEq(vals[2].validatorAddress, validator1);
        assertEq(vals[2].publicKey, PUB_KEY_0);
        assertEq(vals[2].index, 2);
        assertEq(vals[2].addedAtHeight, uint64(block.number));
        assertEq(vals[2].deactivatedAtHeight, 0);
        assertEq(keccak256(bytes(vals[2].ingress)), keccak256(bytes(ingress1)));
        assertEq(keccak256(bytes(vals[2].egress)), keccak256(bytes(egress1)));

        assertEq(vals[3].validatorAddress, validator2);
        assertEq(vals[3].index, 3);

        assertEq(vals[4].validatorAddress, validator3);
        assertEq(vals[4].index, 4);
    }

    function test_addValidator_fail() public {
        // 1. NotInitialized
        try validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, "") {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.NotInitialized.selector));
        }

        _initializeV2();

        // 2. Unauthorized
        vm.prank(nonOwner);
        try validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, "") {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }

        // 3. InvalidPublicKey (zero)
        try validatorConfigV2.addValidator(validator1, bytes32(0), ingress1, egress1, "") {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.InvalidPublicKey.selector));
        }

        // 4. AddressAlreadyHasValidator (setupVal1 already migrated)
        try validatorConfigV2.addValidator(setupVal1, PUB_KEY_1, ingress2, egress2, "") {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.AddressAlreadyHasValidator.selector)
            );
        }

        // 5. PublicKeyAlreadyExists (SETUP_PUB_KEY_A already migrated)
        try validatorConfigV2.addValidator(validator2, SETUP_PUB_KEY_A, ingress2, egress2, "") {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.PublicKeyAlreadyExists.selector)
            );
        }

        if (isTempo) {
            // 6. InvalidSignatureFormat (short — wrong length)
            try validatorConfigV2.addValidator(
                validator1, PUB_KEY_0, ingress1, egress1, hex"0000"
            ) {
                revert CallShouldHaveReverted();
            } catch (bytes memory err) {
                assertEq(err, abi.encodeWithSelector(InvalidSignatureFormat.selector));
            }

            // 7. InvalidSignature (valid length, wrong sig data)
            try validatorConfigV2.addValidator(
                validator1,
                PUB_KEY_0,
                ingress1,
                egress1,
                hex"0000000000000000000000000000000000000000000000000000000000000000"
                hex"0000000000000000000000000000000000000000000000000000000000000000"
            ) {
                revert CallShouldHaveReverted();
            } catch (bytes memory err) {
                assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.InvalidSignature.selector));
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                        DEACTIVATE VALIDATOR
    //////////////////////////////////////////////////////////////*/

    function test_deactivateValidator_pass() public {
        _initializeV2();
        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );
        validatorConfigV2.deactivateValidator(validator1);

        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(validator1);
        assertEq(v.deactivatedAtHeight, uint64(block.number));
    }

    function test_deactivateValidator_passByValidator() public {
        _initializeV2();
        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );

        vm.prank(validator1);
        validatorConfigV2.deactivateValidator(validator1);

        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(validator1);
        assertEq(v.deactivatedAtHeight, uint64(block.number));
    }

    function test_deactivateValidator_fail() public {
        _initializeV2();
        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );

        // 1. Unauthorized (third party, neither owner nor validator)
        vm.prank(nonOwner);
        try validatorConfigV2.deactivateValidator(validator1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }

        // 2. ValidatorNotFound
        try validatorConfigV2.deactivateValidator(validator2) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorNotFound.selector));
        }

        // 3. ValidatorAlreadyDeleted
        validatorConfigV2.deactivateValidator(validator1);
        try validatorConfigV2.deactivateValidator(validator1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorAlreadyDeleted.selector)
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                         ROTATE VALIDATOR
    //////////////////////////////////////////////////////////////*/

    function test_rotateValidator_pass() public {
        _initializeV2();
        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );

        // Owner rotates
        validatorConfigV2.rotateValidator(
            validator1,
            PUB_KEY_3,
            ingress2,
            egress2,
            _signRotate(PRIV_KEY_3, validator1, ingress2, egress2)
        );

        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();
        assertEq(vals.length, 4); // 2 setup + original (deactivated) + rotated
        assertEq(vals[2].deactivatedAtHeight, uint64(block.number));
        assertEq(vals[3].validatorAddress, validator1);
        assertEq(vals[3].publicKey, PUB_KEY_3);
        assertEq(vals[3].addedAtHeight, uint64(block.number));
        assertEq(vals[3].deactivatedAtHeight, 0);
    }

    function test_rotateValidator_passByValidator() public {
        _initializeV2();
        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );

        vm.prank(validator1);
        validatorConfigV2.rotateValidator(
            validator1,
            PUB_KEY_3,
            ingress2,
            egress2,
            _signRotate(PRIV_KEY_3, validator1, ingress2, egress2)
        );

        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();
        assertEq(vals.length, 4); // 2 setup + original (deactivated) + rotated
        assertEq(vals[3].publicKey, PUB_KEY_3);
    }

    function test_rotateValidator_fail() public {
        _initializeV2();
        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );
        validatorConfigV2.addValidator(
            validator2,
            PUB_KEY_1,
            ingress2,
            egress2,
            _signAdd(PRIV_KEY_1, validator2, ingress2, egress2)
        );

        // 1. Unauthorized
        vm.prank(nonOwner);
        try validatorConfigV2.rotateValidator(validator1, PUB_KEY_3, ingress2, egress2, "") {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }

        // 2. ValidatorNotFound
        try validatorConfigV2.rotateValidator(
            validator3,
            PUB_KEY_3,
            ingress2,
            egress2,
            _signRotate(PRIV_KEY_3, validator3, ingress2, egress2)
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorNotFound.selector));
        }

        // 3. InvalidPublicKey (zero)
        try validatorConfigV2.rotateValidator(
            validator1,
            bytes32(0),
            ingress2,
            egress2,
            _signRotate(PRIV_KEY_3, validator1, ingress2, egress2)
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.InvalidPublicKey.selector));
        }

        // 4. PublicKeyAlreadyExists
        try validatorConfigV2.rotateValidator(
            validator1,
            PUB_KEY_1,
            ingress2,
            egress2,
            _signRotate(PRIV_KEY_1, validator1, ingress2, egress2)
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.PublicKeyAlreadyExists.selector)
            );
        }

        // 5. ValidatorAlreadyDeleted
        validatorConfigV2.deactivateValidator(validator1);
        try validatorConfigV2.rotateValidator(
            validator1,
            PUB_KEY_3,
            ingress2,
            egress2,
            _signRotate(PRIV_KEY_3, validator1, ingress2, egress2)
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorAlreadyDeleted.selector)
            );
        }

        if (isTempo) {
            // 6. InvalidSignatureFormat (short — wrong length)
            validatorConfigV2.addValidator(
                validator3,
                PUB_KEY_2,
                ingress3,
                egress3,
                _signAdd(PRIV_KEY_2, validator3, ingress3, egress3)
            );
            try validatorConfigV2.rotateValidator(
                validator3, PUB_KEY_3, ingress2, egress2, hex"0000"
            ) {
                revert CallShouldHaveReverted();
            } catch (bytes memory err) {
                assertEq(err, abi.encodeWithSelector(InvalidSignatureFormat.selector));
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         SET IP ADDRESSES
    //////////////////////////////////////////////////////////////*/

    function test_setIpAddresses_pass() public {
        _initializeV2();
        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );

        // Owner updates
        validatorConfigV2.setIpAddresses(validator1, ingress2, egress2);
        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(validator1);
        assertEq(keccak256(bytes(v.ingress)), keccak256(bytes(ingress2)));
        assertEq(keccak256(bytes(v.egress)), keccak256(bytes(egress2)));

        // Validator updates own IPs
        vm.prank(validator1);
        validatorConfigV2.setIpAddresses(validator1, ingress3, egress3);
        v = validatorConfigV2.validatorByAddress(validator1);
        assertEq(keccak256(bytes(v.ingress)), keccak256(bytes(ingress3)));

        // IPv6 ingress
        validatorConfigV2.setIpAddresses(validator1, "[2001:db8::1]:8000", "192.168.1.2");
        v = validatorConfigV2.validatorByAddress(validator1);
        assertEq(keccak256(bytes(v.ingress)), keccak256(bytes("[2001:db8::1]:8000")));
    }

    function test_setIpAddresses_fail() public {
        _initializeV2();

        // 1. ValidatorNotFound
        try validatorConfigV2.setIpAddresses(validator1, ingress2, egress2) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorNotFound.selector));
        }

        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );

        // 2. Unauthorized
        vm.prank(nonOwner);
        try validatorConfigV2.setIpAddresses(validator1, ingress2, egress2) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }

        // 3. ValidatorAlreadyDeleted
        validatorConfigV2.deactivateValidator(validator1);
        try validatorConfigV2.setIpAddresses(validator1, ingress2, egress2) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorAlreadyDeleted.selector)
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                    TRANSFER VALIDATOR OWNERSHIP
    //////////////////////////////////////////////////////////////*/

    function test_transferValidatorOwnership_pass() public {
        _initializeV2();
        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );

        // Owner transfers
        validatorConfigV2.transferValidatorOwnership(validator1, validator2);
        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(validator2);
        assertEq(v.publicKey, PUB_KEY_0);
        assertEq(v.validatorAddress, validator2);

        // Old address no longer found
        try validatorConfigV2.validatorByAddress(validator1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorNotFound.selector));
        }
    }

    function test_transferValidatorOwnership_passByValidator() public {
        _initializeV2();
        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );

        vm.prank(validator1);
        validatorConfigV2.transferValidatorOwnership(validator1, validator2);

        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(validator2);
        assertEq(v.validatorAddress, validator2);
    }

    function test_transferValidatorOwnership_fail() public {
        _initializeV2();

        // 1. ValidatorNotFound
        try validatorConfigV2.transferValidatorOwnership(validator1, validator2) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorNotFound.selector));
        }

        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );
        validatorConfigV2.addValidator(
            validator2,
            PUB_KEY_1,
            ingress2,
            egress2,
            _signAdd(PRIV_KEY_1, validator2, ingress2, egress2)
        );

        // 2. InvalidValidatorAddress (address(0))
        try validatorConfigV2.transferValidatorOwnership(validator1, address(0)) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.InvalidValidatorAddress.selector)
            );
        }

        // 3. Unauthorized
        vm.prank(nonOwner);
        try validatorConfigV2.transferValidatorOwnership(validator1, validator3) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }

        // 4. AddressAlreadyHasValidator (target address occupied)
        try validatorConfigV2.transferValidatorOwnership(validator1, validator2) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.AddressAlreadyHasValidator.selector)
            );
        }

        // 5. ValidatorAlreadyDeleted
        validatorConfigV2.deactivateValidator(validator1);
        try validatorConfigV2.transferValidatorOwnership(validator1, validator3) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorAlreadyDeleted.selector)
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                        TRANSFER OWNER
    //////////////////////////////////////////////////////////////*/

    function test_transferOwnership_pass() public {
        _initializeV2();
        validatorConfigV2.transferOwnership(alice);
        assertEq(validatorConfigV2.owner(), alice);

        // New owner can transfer again; old owner cannot
        try validatorConfigV2.transferOwnership(bob) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }

        vm.prank(alice);
        validatorConfigV2.transferOwnership(bob);
        assertEq(validatorConfigV2.owner(), bob);
    }

    function test_transferOwnership_fail() public {
        _initializeV2();
        vm.prank(nonOwner);
        try validatorConfigV2.transferOwnership(alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }
    }

    /*//////////////////////////////////////////////////////////////
                      SET NEXT FULL DKG CEREMONY
    //////////////////////////////////////////////////////////////*/

    function test_setNextFullDkgCeremony_pass() public {
        _initializeV2();
        validatorConfigV2.setNextFullDkgCeremony(42);
        assertEq(validatorConfigV2.getNextFullDkgCeremony(), 42);
    }

    function test_setNextFullDkgCeremony_fail() public {
        // 1. NotInitialized
        try validatorConfigV2.setNextFullDkgCeremony(42) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.NotInitialized.selector));
        }

        _initializeV2();

        // 2. Unauthorized
        vm.prank(nonOwner);
        try validatorConfigV2.setNextFullDkgCeremony(42) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_getAllValidators_pass() public {
        _initializeV2();

        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();
        assertEq(vals.length, 2); // 2 setup validators migrated
        assertEq(vals[0].validatorAddress, setupVal1);
        assertEq(vals[1].validatorAddress, setupVal2);

        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );
        validatorConfigV2.addValidator(
            validator2,
            PUB_KEY_1,
            ingress2,
            egress2,
            _signAdd(PRIV_KEY_1, validator2, ingress2, egress2)
        );

        vals = validatorConfigV2.getAllValidators();
        assertEq(vals.length, 4); // 2 setup + 2 added
        assertEq(vals[2].validatorAddress, validator1);
        assertEq(vals[3].validatorAddress, validator2);
    }

    function test_getActiveValidators_pass() public {
        _initializeV2();
        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );
        validatorConfigV2.addValidator(
            validator2,
            PUB_KEY_1,
            ingress2,
            egress2,
            _signAdd(PRIV_KEY_1, validator2, ingress2, egress2)
        );
        validatorConfigV2.deactivateValidator(validator1);

        IValidatorConfigV2.Validator[] memory active = validatorConfigV2.getActiveValidators();
        assertEq(active.length, 3); // 2 setup + validator2 (validator1 deactivated)
        assertEq(active[0].validatorAddress, setupVal1);
        assertEq(active[1].validatorAddress, setupVal2);
        assertEq(active[2].validatorAddress, validator2);
    }

    function test_validatorCount_pass() public {
        _initializeV2();
        assertEq(validatorConfigV2.validatorCount(), 2); // 2 setup validators migrated

        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );
        assertEq(validatorConfigV2.validatorCount(), 3);

        validatorConfigV2.addValidator(
            validator2,
            PUB_KEY_1,
            ingress2,
            egress2,
            _signAdd(PRIV_KEY_1, validator2, ingress2, egress2)
        );
        assertEq(validatorConfigV2.validatorCount(), 4);

        validatorConfigV2.deactivateValidator(validator1);
        assertEq(validatorConfigV2.validatorCount(), 4);
    }

    function test_validatorByIndex_pass() public {
        _initializeV2();

        IValidatorConfigV2.Validator memory v0 = validatorConfigV2.validatorByIndex(0);
        assertEq(v0.validatorAddress, setupVal1);

        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );

        IValidatorConfigV2.Validator memory v2 = validatorConfigV2.validatorByIndex(2);
        assertEq(v2.validatorAddress, validator1);
    }

    function test_validatorByIndex_fail() public {
        try validatorConfigV2.validatorByIndex(0) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorNotFound.selector));
        }
    }

    function test_validatorByAddress_pass() public {
        _initializeV2();
        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );

        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(validator1);
        assertEq(v.publicKey, PUB_KEY_0);
    }

    function test_validatorByAddress_fail() public {
        try validatorConfigV2.validatorByAddress(validator1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorNotFound.selector));
        }
    }

    function test_validatorByPublicKey_pass() public {
        _initializeV2();
        validatorConfigV2.addValidator(
            validator1,
            PUB_KEY_0,
            ingress1,
            egress1,
            _signAdd(PRIV_KEY_0, validator1, ingress1, egress1)
        );

        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByPublicKey(PUB_KEY_0);
        assertEq(v.validatorAddress, validator1);
    }

    function test_validatorByPublicKey_fail() public {
        try validatorConfigV2.validatorByPublicKey(PUB_KEY_0) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorNotFound.selector));
        }
    }

    function test_isInitialized_pass() public {
        assertFalse(validatorConfigV2.isInitialized());

        _initializeV2();
        assertTrue(validatorConfigV2.isInitialized());
    }

    function test_getInitializedAtHeight_pass() public {
        assertEq(validatorConfigV2.getInitializedAtHeight(), 0);

        _initializeV2();
        assertEq(validatorConfigV2.getInitializedAtHeight(), uint64(block.number));
    }

    /*//////////////////////////////////////////////////////////////
                     MIGRATION (V1 -> V2)
    //////////////////////////////////////////////////////////////*/

    function test_migrateValidator_pass() public {
        // V2 starts uninitialized with owner=address(0) from deployment.
        // setUp already added 2 V1 validators (setupVal1, setupVal2).
        // Add one more inactive V1 validator to test both active/inactive migration.
        validatorConfig.addValidator(validator1, PUB_KEY_0, false, ingress1, "192.168.1.1:9000");

        // First call copies owner from V1
        validatorConfigV2.migrateValidator(0);
        assertEq(validatorConfigV2.owner(), validatorConfig.owner());

        validatorConfigV2.migrateValidator(1);
        validatorConfigV2.migrateValidator(2);
        assertEq(validatorConfigV2.validatorCount(), 3);

        // Active validator (setUp): addedAtHeight=block.number, deactivatedAtHeight=0
        IValidatorConfigV2.Validator memory v0 = validatorConfigV2.validatorByIndex(0);
        assertEq(v0.validatorAddress, setupVal1);
        assertEq(v0.addedAtHeight, block.number);
        assertEq(v0.deactivatedAtHeight, 0);

        IValidatorConfigV2.Validator memory v1 = validatorConfigV2.validatorByIndex(1);
        assertEq(v1.validatorAddress, setupVal2);
        assertEq(v1.addedAtHeight, block.number);
        assertEq(v1.deactivatedAtHeight, 0);

        // Inactive validator: addedAtHeight=block.number, deactivatedAtHeight=block.number
        IValidatorConfigV2.Validator memory v2 = validatorConfigV2.validatorByIndex(2);
        assertEq(v2.validatorAddress, validator1);
        assertEq(v2.addedAtHeight, block.number);
        assertEq(v2.deactivatedAtHeight, uint64(block.number));
    }

    function test_migrateValidator_fail() public {
        // setUp added 2 V1 validators (setupVal1, setupVal2). V1 has 2 total.

        // 1. InvalidMigrationIndex (skip idx 0, try idx 1 when V2 array is empty)
        try validatorConfigV2.migrateValidator(1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.InvalidMigrationIndex.selector));
        }

        // 2. Unauthorized (migrate idx 0 sets owner, then nonOwner tries idx 1)
        validatorConfigV2.migrateValidator(0);
        vm.prank(nonOwner);
        try validatorConfigV2.migrateValidator(1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }

        // 3. ValidatorNotFound (migrate idx 1, then try idx 2 beyond V1 length)
        validatorConfigV2.migrateValidator(1);
        try validatorConfigV2.migrateValidator(2) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorNotFound.selector));
        }

        // 4. AlreadyInitialized (finalize, then try migrating again)
        validatorConfigV2.initializeIfMigrated();
        try validatorConfigV2.migrateValidator(0) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.AlreadyInitialized.selector));
        }
    }

    /*//////////////////////////////////////////////////////////////
                      INITIALIZE IF MIGRATED
    //////////////////////////////////////////////////////////////*/

    function test_initializeIfMigrated_pass() public {
        // setUp added 2 active V1 validators. Set a DKG ceremony to verify it copies.
        validatorConfig.setNextFullDkgCeremony(99);

        validatorConfigV2.migrateValidator(0);
        validatorConfigV2.migrateValidator(1);
        validatorConfigV2.initializeIfMigrated();

        assertTrue(validatorConfigV2.isInitialized());
        assertEq(validatorConfigV2.getNextFullDkgCeremony(), 99);
    }

    function test_initializeIfMigrated_fail() public {
        // setUp added 2 V1 validators (setupVal1, setupVal2).

        // 1. MigrationNotComplete (only 1 of 2 migrated)
        validatorConfigV2.migrateValidator(0);
        try validatorConfigV2.initializeIfMigrated() {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.MigrationNotComplete.selector));
        }

        // 2. Unauthorized (all migrated, but nonOwner calls)
        validatorConfigV2.migrateValidator(1);
        vm.prank(nonOwner);
        try validatorConfigV2.initializeIfMigrated() {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }

        // 3. AlreadyInitialized (owner finalizes, then tries again)
        validatorConfigV2.initializeIfMigrated();
        try validatorConfigV2.initializeIfMigrated() {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.AlreadyInitialized.selector));
        }
    }

    // =========================================================================
    // IP Uniqueness Tests
    // =========================================================================

    function test_addValidator_rejectsDuplicateIngressIp() public {
        validatorConfigV2.migrateValidator(0);
        validatorConfigV2.migrateValidator(1);
        validatorConfigV2.initializeIfMigrated();

        address newAddr = address(0xDEAD);

        // Try to add validator with same ingress IP as setupVal1 (even with different port)
        try validatorConfigV2.addValidator(
            newAddr,
            PUB_KEY_0,
            "10.0.0.100:9000",
            "10.0.0.200",
            _signAdd(PRIV_KEY_0, newAddr, "10.0.0.100:9000", "10.0.0.200")
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                bytes4(err),
                IValidatorConfigV2.IngressAlreadyExists.selector,
                "Should revert with IngressAlreadyExists even with different port"
            );
        }
    }

    function test_ingressIpReuse_afterDeactivation() public {
        validatorConfigV2.migrateValidator(0);
        validatorConfigV2.migrateValidator(1);
        validatorConfigV2.initializeIfMigrated();

        // Deactivate setupVal1
        validatorConfigV2.deactivateValidator(setupVal1);

        // Should now allow reusing setupVal1's ingress IP
        address newAddr = address(0xDEAD);
        validatorConfigV2.addValidator(
            newAddr,
            PUB_KEY_0,
            "10.0.0.100:9999",
            "10.0.0.200",
            _signAdd(PRIV_KEY_0, newAddr, "10.0.0.100:9999", "10.0.0.200")
        );

        // Verify new validator has the reused ingress IP (different port is ok)
        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(newAddr);
        assertEq(v.ingress, "10.0.0.100:9999");
    }

    function test_ingressIpCollision_rejected() public {
        validatorConfigV2.migrateValidator(0);
        validatorConfigV2.migrateValidator(1);
        validatorConfigV2.initializeIfMigrated();

        // setIpAddresses: Try to set setupVal1's ingress IP to setupVal2's ingress IP
        try validatorConfigV2.setIpAddresses(setupVal1, "10.0.0.101:9999", "10.0.0.200") {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(bytes4(err), IValidatorConfigV2.IngressAlreadyExists.selector);
        }

        // rotateValidator: Try to rotate setupVal1 to setupVal2's ingress IP
        try validatorConfigV2.rotateValidator(
            setupVal1,
            PUB_KEY_0,
            "10.0.0.101:9999",
            "10.0.0.200",
            _signRotate(PRIV_KEY_0, setupVal1, "10.0.0.101:9999", "10.0.0.200")
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(bytes4(err), IValidatorConfigV2.IngressAlreadyExists.selector);
        }
    }

    function test_setIpAddresses_allowsSameIngressPort() public {
        validatorConfigV2.migrateValidator(0);
        validatorConfigV2.migrateValidator(1);
        validatorConfigV2.initializeIfMigrated();

        // Should allow changing port on same validator's IP
        validatorConfigV2.setIpAddresses(setupVal1, "10.0.0.100:9999", "10.0.0.100");

        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(setupVal1);
        assertEq(v.ingress, "10.0.0.100:9999", "Should allow port change on same IP");
    }

    // =========================================================================
    // Migration Port Stripping Tests
    // =========================================================================

    function test_migration_stripsPortFromV1Egress() public {
        // V1 stores egress as ip:port, V2 should strip the port
        validatorConfigV2.migrateValidator(0);

        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByIndex(0);
        // V1 had "10.0.0.100:9000", V2 should have just "10.0.0.100"
        assertEq(v.egress, "10.0.0.100", "Port should be stripped from V1 egress");
        // Ingress should remain unchanged
        assertEq(v.ingress, "10.0.0.100:8000", "Ingress should remain as ip:port");
    }

    // =========================================================================
    // Address Reusability Tests
    // =========================================================================

    function test_addValidator_allowsReusingDeactivatedAddress() public {
        validatorConfigV2.migrateValidator(0);
        validatorConfigV2.migrateValidator(1);
        validatorConfigV2.initializeIfMigrated();

        // Deactivate setupVal1
        validatorConfigV2.deactivateValidator(setupVal1);

        // Should allow reusing setupVal1's address with different IPs
        validatorConfigV2.addValidator(
            setupVal1,
            PUB_KEY_0,
            "10.0.0.200:8000",
            "10.0.0.200",
            _signAdd(PRIV_KEY_0, setupVal1, "10.0.0.200:8000", "10.0.0.200")
        );

        // Should have 3 validators total (2 original + 1 new)
        assertEq(validatorConfigV2.validatorCount(), 3);

        // Address lookup should return the NEW active validator
        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(setupVal1);
        assertEq(v.publicKey, PUB_KEY_0, "Should return new validator's pubkey");
        assertEq(v.deactivatedAtHeight, 0, "New validator should be active");
    }

    function test_addValidator_rejectsActiveAddress() public {
        validatorConfigV2.migrateValidator(0);
        validatorConfigV2.migrateValidator(1);
        validatorConfigV2.initializeIfMigrated();

        // Try to add with setupVal1's address (still active)
        try validatorConfigV2.addValidator(
            setupVal1,
            PUB_KEY_0,
            "10.0.0.200:8000",
            "10.0.0.200",
            _signAdd(PRIV_KEY_0, setupVal1, "10.0.0.200:8000", "10.0.0.200")
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                bytes4(err),
                IValidatorConfigV2.AddressAlreadyHasValidator.selector,
                "Should reject active address"
            );
        }
    }

    // =========================================================================
    // Pre-Initialization Tests
    // =========================================================================

    function test_deactivateValidator_worksBeforeInit() public {
        validatorConfigV2.migrateValidator(0);
        validatorConfigV2.migrateValidator(1);

        // Should work before initialization
        assertFalse(validatorConfigV2.isInitialized());
        validatorConfigV2.deactivateValidator(setupVal1);

        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByIndex(0);
        assertGt(v.deactivatedAtHeight, 0, "Should be deactivated");
    }

    function test_setIpAddresses_worksBeforeInit() public {
        validatorConfigV2.migrateValidator(0);
        validatorConfigV2.migrateValidator(1);

        // Should work before initialization
        assertFalse(validatorConfigV2.isInitialized());
        validatorConfigV2.setIpAddresses(setupVal1, "10.0.0.150:8000", "10.0.0.150");

        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(setupVal1);
        assertEq(v.ingress, "10.0.0.150:8000");
        assertEq(v.egress, "10.0.0.150");
    }

    function test_deactivateValidator_byValidator_worksBeforeInit() public {
        validatorConfigV2.migrateValidator(0);
        validatorConfigV2.migrateValidator(1);

        // Validator can deactivate themselves before initialization
        assertFalse(validatorConfigV2.isInitialized());
        vm.prank(setupVal1);
        validatorConfigV2.deactivateValidator(setupVal1);

        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByIndex(0);
        assertGt(v.deactivatedAtHeight, 0, "Should be deactivated");
    }

    function test_setIpAddresses_byValidator_worksBeforeInit() public {
        validatorConfigV2.migrateValidator(0);
        validatorConfigV2.migrateValidator(1);

        // Validator can update their own IPs before initialization
        assertFalse(validatorConfigV2.isInitialized());
        vm.prank(setupVal1);
        validatorConfigV2.setIpAddresses(setupVal1, "10.0.0.150:8000", "10.0.0.150");

        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(setupVal1);
        assertEq(v.ingress, "10.0.0.150:8000");
        assertEq(v.egress, "10.0.0.150");
    }

}
