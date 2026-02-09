// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { IValidatorConfig } from "../src/interfaces/IValidatorConfig.sol";
import { IValidatorConfigV2 } from "../src/interfaces/IValidatorConfigV2.sol";
import { BaseTest } from "./BaseTest.t.sol";

contract ValidatorConfigV2Test is BaseTest {

    address public validator1 = address(0x2000);
    address public validator2 = address(0x3000);
    address public validator3 = address(0x4000);
    address public nonOwner = address(0x6000);

    // setUp V1 validators (distinct from test fixtures to avoid collisions)
    address public setupVal1 = address(0xA000);
    address public setupVal2 = address(0xB000);
    bytes32 internal constant SETUP_PUB_KEY_A =
        0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 internal constant SETUP_PUB_KEY_B =
        0x2222222222222222222222222222222222222222222222222222222222222222;

    // Ed25519 public keys (deterministic, generated from sha256("test_key_N"))
    bytes32 internal constant PUB_KEY_0 =
        0xa6bcfb0a1c59cdea9b11d8857640350701eced80c3963ad6da42f8b227e7f5f7;
    bytes32 internal constant PUB_KEY_1 =
        0xe3f90db26854cc1c62c992fd1b402ccbf2eec2999e7ffd2a89766ba8d278bfc2;
    bytes32 internal constant PUB_KEY_2 =
        0x039abc7f554e4c872330720f75245b9a7c542b07cd8fd3792e54bbf6920bdf8b;
    bytes32 internal constant PUB_KEY_3 =
        0xd7038bea905041c2fec655d2295087aee137e0c8468f15a7f125b75576beabb2;

    // Pre-computed Ed25519 signatures over keccak256(abi.encodePacked(...)) messages.
    // chainid=31337, contract=0xCcCCCCcC00000000000000000000000000000001.
    //
    // ADD validator1 (0x2000) with PUB_KEY_0, ingress=192.168.1.1:8000, egress=192.168.1.1
    bytes internal constant SIG_ADD_V1 =
        hex"64ed8875cadaec7cb61649ba80c94e6e52088e715c210d469b7085bd52f1d8e2a9282d4121ab123444a1c6e61f51570859f7a03c353904220b407b9db38d800d";
    // ADD validator2 (0x3000) with PUB_KEY_1, ingress=192.168.1.2:8000, egress=192.168.1.2
    bytes internal constant SIG_ADD_V2 =
        hex"2e5710b90c5f5fd663edfda2733f754d2e992e4ad45862c621eae224035901f9acc12b0fac27eaef8715d6a43dbcf8be374117f91c565e8affd2c90c50b28f06";
    // ADD validator3 (0x4000) with PUB_KEY_2, ingress=10.0.0.1:8000, egress=10.0.0.1
    bytes internal constant SIG_ADD_V3 =
        hex"8d6971512450105361586518f03c975c1abad82da64c309c7a67c15284d1200026c83f85218a8d08ea680da8a55c6e61944bb01ee7b50ea9a129bbdc832d7403";
    // ROTATE validator1 (0x2000) with PUB_KEY_3, ingress=192.168.1.2:8000, egress=192.168.1.2
    bytes internal constant SIG_ROTATE_V1 =
        hex"4968e3846b6350cf4f393c877f87b8205440872485942432625206aca794eecda5a730ef666dc4471facf55bd3b63e9862f96d8a7debd2997b190dc1cdb29d06";

    string public ingress1 = "192.168.1.1:8000";
    string public egress1 = "192.168.1.1";
    string public ingress2 = "192.168.1.2:8000";
    string public egress2 = "192.168.1.2";
    string public ingress3 = "10.0.0.1:8000";
    string public egress3 = "10.0.0.1";

    function setUp() public override {
        super.setUp();
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

        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);
        validatorConfigV2.addValidator(validator2, PUB_KEY_1, ingress2, egress2, SIG_ADD_V2);
        validatorConfigV2.addValidator(validator3, PUB_KEY_2, ingress3, egress3, SIG_ADD_V3);

        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getValidators();
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
        try validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.NotInitialized.selector));
        }

        _initializeV2();

        // 2. Unauthorized
        vm.prank(nonOwner);
        try validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }

        // 3. InvalidPublicKey (zero)
        try validatorConfigV2.addValidator(validator1, bytes32(0), ingress1, egress1, SIG_ADD_V1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.InvalidPublicKey.selector));
        }

        // 4. InvalidSignature (short)
        try validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, hex"0000") {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.InvalidSignature.selector));
        }

        // 5. InvalidSignature (wrong sig data)
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

        // 6. ValidatorAlreadyExists (setupVal1 already migrated)
        try validatorConfigV2.addValidator(setupVal1, PUB_KEY_1, ingress2, egress2, SIG_ADD_V2) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorAlreadyExists.selector)
            );
        }

        // 7. PublicKeyAlreadyExists (SETUP_PUB_KEY_A already migrated)
        try validatorConfigV2.addValidator(
            validator2, SETUP_PUB_KEY_A, ingress2, egress2, SIG_ADD_V2
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.PublicKeyAlreadyExists.selector)
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                        DEACTIVATE VALIDATOR
    //////////////////////////////////////////////////////////////*/

    function test_deactivateValidator_pass() public {
        _initializeV2();
        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);
        validatorConfigV2.deactivateValidator(validator1);

        IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(validator1);
        assertEq(v.deactivatedAtHeight, uint64(block.number));
    }

    function test_deactivateValidator_fail() public {
        _initializeV2();
        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);

        // 1. Unauthorized
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
        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);

        // Owner rotates
        validatorConfigV2.rotateValidator(validator1, PUB_KEY_3, ingress2, egress2, SIG_ROTATE_V1);

        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getValidators();
        assertEq(vals.length, 4); // 2 setup + original (deactivated) + rotated
        assertEq(vals[2].deactivatedAtHeight, uint64(block.number));
        assertEq(vals[3].validatorAddress, validator1);
        assertEq(vals[3].publicKey, PUB_KEY_3);
        assertEq(vals[3].addedAtHeight, uint64(block.number));
        assertEq(vals[3].deactivatedAtHeight, 0);
    }

    function test_rotateValidator_passByValidator() public {
        _initializeV2();
        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);

        vm.prank(validator1);
        validatorConfigV2.rotateValidator(validator1, PUB_KEY_3, ingress2, egress2, SIG_ROTATE_V1);

        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getValidators();
        assertEq(vals.length, 4); // 2 setup + original (deactivated) + rotated
        assertEq(vals[3].publicKey, PUB_KEY_3);
    }

    function test_rotateValidator_fail() public {
        _initializeV2();
        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);
        validatorConfigV2.addValidator(validator2, PUB_KEY_1, ingress2, egress2, SIG_ADD_V2);

        // 1. Unauthorized
        vm.prank(nonOwner);
        try validatorConfigV2.rotateValidator(
            validator1, PUB_KEY_3, ingress2, egress2, SIG_ROTATE_V1
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }

        // 2. ValidatorNotFound
        try validatorConfigV2.rotateValidator(
            validator3, PUB_KEY_3, ingress2, egress2, SIG_ROTATE_V1
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorNotFound.selector));
        }

        // 3. InvalidPublicKey (zero)
        try validatorConfigV2.rotateValidator(
            validator1, bytes32(0), ingress2, egress2, SIG_ROTATE_V1
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.InvalidPublicKey.selector));
        }

        // 4. PublicKeyAlreadyExists
        try validatorConfigV2.rotateValidator(
            validator1, PUB_KEY_1, ingress2, egress2, SIG_ROTATE_V1
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.PublicKeyAlreadyExists.selector)
            );
        }

        // 5. InvalidSignature (short)
        try validatorConfigV2.rotateValidator(validator1, PUB_KEY_3, ingress2, egress2, hex"0000") {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.InvalidSignature.selector));
        }

        // 6. InvalidSignature (wrong sig data)
        try validatorConfigV2.rotateValidator(
            validator1,
            PUB_KEY_3,
            ingress2,
            egress2,
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.InvalidSignature.selector));
        }

        // 7. ValidatorAlreadyDeleted
        validatorConfigV2.deactivateValidator(validator1);
        try validatorConfigV2.rotateValidator(
            validator1, PUB_KEY_3, ingress2, egress2, SIG_ROTATE_V1
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorAlreadyDeleted.selector)
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                         SET IP ADDRESSES
    //////////////////////////////////////////////////////////////*/

    function test_setIpAddresses_pass() public {
        _initializeV2();
        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);

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

        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);

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
        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);

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
        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);

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

        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);
        validatorConfigV2.addValidator(validator2, PUB_KEY_1, ingress2, egress2, SIG_ADD_V2);

        // 2. Unauthorized
        vm.prank(nonOwner);
        try validatorConfigV2.transferValidatorOwnership(validator1, validator3) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfigV2.Unauthorized.selector));
        }

        // 3. ValidatorAlreadyExists (target address occupied)
        try validatorConfigV2.transferValidatorOwnership(validator1, validator2) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IValidatorConfigV2.ValidatorAlreadyExists.selector)
            );
        }

        // 4. ValidatorAlreadyDeleted
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

    function test_getValidators_pass() public {
        _initializeV2();

        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getValidators();
        assertEq(vals.length, 2); // 2 setup validators migrated
        assertEq(vals[0].validatorAddress, setupVal1);
        assertEq(vals[1].validatorAddress, setupVal2);

        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);
        validatorConfigV2.addValidator(validator2, PUB_KEY_1, ingress2, egress2, SIG_ADD_V2);

        vals = validatorConfigV2.getValidators();
        assertEq(vals.length, 4); // 2 setup + 2 added
        assertEq(vals[2].validatorAddress, validator1);
        assertEq(vals[3].validatorAddress, validator2);
    }

    function test_getActiveValidators_pass() public {
        _initializeV2();
        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);
        validatorConfigV2.addValidator(validator2, PUB_KEY_1, ingress2, egress2, SIG_ADD_V2);
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

        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);
        assertEq(validatorConfigV2.validatorCount(), 3);

        validatorConfigV2.addValidator(validator2, PUB_KEY_1, ingress2, egress2, SIG_ADD_V2);
        assertEq(validatorConfigV2.validatorCount(), 4);

        validatorConfigV2.deactivateValidator(validator1);
        assertEq(validatorConfigV2.validatorCount(), 4);
    }

    function test_validatorByIndex_pass() public {
        _initializeV2();

        IValidatorConfigV2.Validator memory v0 = validatorConfigV2.validatorByIndex(0);
        assertEq(v0.validatorAddress, setupVal1);

        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);

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
        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);

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
        validatorConfigV2.addValidator(validator1, PUB_KEY_0, ingress1, egress1, SIG_ADD_V1);

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

        // Active validator (setUp): addedAtHeight=0, deactivatedAtHeight=0
        IValidatorConfigV2.Validator memory v0 = validatorConfigV2.validatorByIndex(0);
        assertEq(v0.validatorAddress, setupVal1);
        assertEq(v0.addedAtHeight, 0);
        assertEq(v0.deactivatedAtHeight, 0);

        IValidatorConfigV2.Validator memory v1 = validatorConfigV2.validatorByIndex(1);
        assertEq(v1.validatorAddress, setupVal2);
        assertEq(v1.addedAtHeight, 0);
        assertEq(v1.deactivatedAtHeight, 0);

        // Inactive validator: addedAtHeight=deactivatedAtHeight=block.timestamp
        IValidatorConfigV2.Validator memory v2 = validatorConfigV2.validatorByIndex(2);
        assertEq(v2.validatorAddress, validator1);
        assertEq(v2.addedAtHeight, uint64(block.timestamp));
        assertEq(v2.deactivatedAtHeight, uint64(block.timestamp));
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

}
