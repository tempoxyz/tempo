// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { IValidatorConfig } from "../src/interfaces/IValidatorConfig.sol";
import { BaseTest } from "./BaseTest.t.sol";

contract ValidatorConfigTest is BaseTest {

    address public validator1 = address(0x2000);
    address public validator2 = address(0x3000);
    address public validator3 = address(0x4000);
    address public validator4 = address(0x5000);
    address public nonOwner = address(0x6000);

    bytes32 public publicKey1 = bytes32(uint256(0x1111));
    bytes32 public publicKey2 = bytes32(uint256(0x2222));
    bytes32 public publicKey3 = bytes32(uint256(0x3333));
    bytes32 public publicKey4 = bytes32(uint256(0x4444));

    string public inboundAddr1 = "192.168.1.1:8000";
    string public outboundAddr1 = "192.168.1.1:9000";
    string public inboundAddr2 = "192.168.1.2:8000";
    string public outboundAddr2 = "192.168.1.2:9000";
    string public inboundAddr3 = "10.0.0.1:8000";
    string public outboundAddr3 = "10.0.0.1:9000";

    /*//////////////////////////////////////////////////////////////
                           OWNER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Owner_InitialOwner() public view {
        address currentOwner = validatorConfig.owner();
        assertEq(currentOwner, admin, "Initial owner should be admin");
    }

    function test_ChangeOwner_Success() public {
        validatorConfig.changeOwner(alice);

        assertEq(validatorConfig.owner(), alice, "Owner should be changed to alice");
    }

    function test_ChangeOwner_Unauthorized() public {
        vm.prank(nonOwner);
        try validatorConfig.changeOwner(alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.Unauthorized.selector));
        }
    }

    function test_ChangeOwner_NewOwnerCanChangeOwner() public {
        // admin changes to alice
        validatorConfig.changeOwner(alice);

        // alice changes to bob
        vm.prank(alice);
        validatorConfig.changeOwner(bob);

        assertEq(validatorConfig.owner(), bob, "Owner should now be bob");

        // admin should no longer be able to change owner
        try validatorConfig.changeOwner(charlie) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.Unauthorized.selector));
        }
    }

    /*//////////////////////////////////////////////////////////////
                           ADD VALIDATOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_AddValidator_Success() public {
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);

        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertEq(validators.length, 1, "Should have 1 validator");
        assertEq(validators[0].validatorAddress, validator1);
        assertEq(validators[0].publicKey, publicKey1);
        assertTrue(validators[0].active);
        assertEq(validators[0].index, 0);
        assertEq(validators[0].inboundAddress, inboundAddr1);
        assertEq(validators[0].outboundAddress, outboundAddr1);
    }

    function test_AddValidator_MultipleValidators() public {
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);
        validatorConfig.addValidator(validator2, publicKey2, true, inboundAddr2, outboundAddr2);
        validatorConfig.addValidator(validator3, publicKey3, false, inboundAddr3, outboundAddr3);

        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertEq(validators.length, 3, "Should have 3 validators");

        assertEq(validators[0].validatorAddress, validator1);
        assertEq(validators[0].index, 0);
        assertTrue(validators[0].active);

        assertEq(validators[1].validatorAddress, validator2);
        assertEq(validators[1].index, 1);
        assertTrue(validators[1].active);

        assertEq(validators[2].validatorAddress, validator3);
        assertEq(validators[2].index, 2);
        assertFalse(validators[2].active);
    }

    function test_AddValidator_Unauthorized() public {
        vm.prank(nonOwner);
        try validatorConfig.addValidator(
            validator1, publicKey1, true, inboundAddr1, outboundAddr1
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.Unauthorized.selector));
        }
    }

    function test_AddValidator_DuplicateValidator() public {
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);

        try validatorConfig.addValidator(
            validator1, publicKey2, true, inboundAddr2, outboundAddr2
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.ValidatorAlreadyExists.selector));
        }
    }

    function test_AddValidator_InvalidInboundAddress() public {
        try validatorConfig.addValidator(validator1, publicKey1, true, "invalid", outboundAddr1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            // inboundAddress should revert with NotHostPort error
            bytes4 selector = bytes4(err);
            assertEq(
                selector,
                IValidatorConfig.NotHostPort.selector,
                "Should revert with NotHostPort error"
            );
        }
    }

    function test_AddValidator_InvalidOutboundAddress() public {
        try validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, "invalid") {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            // outboundAddress should revert with NotIpPort error
            bytes4 selector = bytes4(err);
            assertEq(
                selector, IValidatorConfig.NotIpPort.selector, "Should revert with NotIpPort error"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                           UPDATE VALIDATOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_UpdateValidator_Success() public {
        // Owner adds validator
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);

        // Validator updates their own info
        vm.prank(validator1);
        validatorConfig.updateValidator(validator1, publicKey2, inboundAddr2, outboundAddr2);

        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertEq(validators.length, 1, "Should still have 1 validator");
        assertEq(validators[0].validatorAddress, validator1);
        assertEq(validators[0].publicKey, publicKey2, "Public key should be updated");
        assertEq(validators[0].inboundAddress, inboundAddr2, "Inbound address should be updated");
        assertEq(validators[0].outboundAddress, outboundAddr2, "Outbound address should be updated");
        assertTrue(validators[0].active, "Active status should remain unchanged");
    }

    function test_UpdateValidator_RotateAddress() public {
        // Owner adds validator
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);

        // Validator rotates to new address
        vm.prank(validator1);
        validatorConfig.updateValidator(validator2, publicKey2, inboundAddr2, outboundAddr2);

        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertEq(validators.length, 1, "Should still have 1 validator");
        assertEq(validators[0].validatorAddress, validator2, "Validator address should be rotated");
        assertEq(validators[0].publicKey, publicKey2);
        assertEq(validators[0].index, 0, "Index should remain 0");
    }

    function test_UpdateValidator_RotateToExistingAddress() public {
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);
        validatorConfig.addValidator(validator2, publicKey2, true, inboundAddr2, outboundAddr2);

        // Validator1 tries to rotate to validator2's address
        vm.prank(validator1);
        try validatorConfig.updateValidator(validator2, publicKey3, inboundAddr3, outboundAddr3) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.ValidatorAlreadyExists.selector));
        }
    }

    function test_UpdateValidator_NotFound() public {
        vm.prank(nonOwner);
        try validatorConfig.updateValidator(validator1, publicKey1, inboundAddr1, outboundAddr1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.ValidatorNotFound.selector));
        }
    }

    function test_UpdateValidator_OwnerCannotUpdateValidator() public {
        // Owner adds validator
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);

        // Owner tries to update validator (should fail - only validator can update themselves)
        try validatorConfig.updateValidator(validator1, publicKey2, inboundAddr2, outboundAddr2) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.ValidatorNotFound.selector));
        }
    }

    /*//////////////////////////////////////////////////////////////
                           CHANGE VALIDATOR STATUS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ChangeValidatorStatus_Deactivate() public {
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);

        validatorConfig.changeValidatorStatus(validator1, false);

        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertFalse(validators[0].active, "Validator should be inactive");
    }

    function test_ChangeValidatorStatus_Activate() public {
        validatorConfig.addValidator(validator1, publicKey1, false, inboundAddr1, outboundAddr1);

        validatorConfig.changeValidatorStatus(validator1, true);

        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertTrue(validators[0].active, "Validator should be active");
    }

    function test_ChangeValidatorStatus_Unauthorized() public {
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);

        vm.prank(nonOwner);
        try validatorConfig.changeValidatorStatus(validator1, false) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.Unauthorized.selector));
        }
    }

    function test_ChangeValidatorStatus_NotFound() public {
        try validatorConfig.changeValidatorStatus(validator1, false) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.ValidatorNotFound.selector));
        }
    }

    function test_ChangeValidatorStatus_ValidatorCannotChangeOwnStatus() public {
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);

        // Validator tries to change their own status
        vm.prank(validator1);
        try validatorConfig.changeValidatorStatus(validator1, false) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.Unauthorized.selector));
        }
    }

    /*//////////////////////////////////////////////////////////////
                           GET VALIDATORS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetValidators_Empty() public view {
        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertEq(validators.length, 0, "Should have no validators initially");
    }

    function test_GetValidators_PreservesOrder() public {
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);
        validatorConfig.addValidator(validator2, publicKey2, true, inboundAddr2, outboundAddr2);
        validatorConfig.addValidator(validator3, publicKey3, true, inboundAddr3, outboundAddr3);

        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();

        assertEq(validators[0].validatorAddress, validator1);
        assertEq(validators[1].validatorAddress, validator2);
        assertEq(validators[2].validatorAddress, validator3);
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_AddValidator_Success(address validatorAddr, bytes32 pubKey, bool active)
        public
    {
        vm.assume(validatorAddr != address(0));
        vm.assume(pubKey != bytes32(0));

        validatorConfig.addValidator(validatorAddr, pubKey, active, inboundAddr1, outboundAddr1);

        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertEq(validators.length, 1);
        assertEq(validators[0].validatorAddress, validatorAddr);
        assertEq(validators[0].publicKey, pubKey);
        assertEq(validators[0].active, active);
    }

    function testFuzz_AddValidator_Unauthorized(address caller) public {
        vm.assume(caller != admin);

        vm.prank(caller);
        try validatorConfig.addValidator(
            validator1, publicKey1, true, inboundAddr1, outboundAddr1
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.Unauthorized.selector));
        }
    }

    function testFuzz_ChangeOwner_OnlyOwnerCanChange(address caller, address newOwner) public {
        vm.assume(caller != admin);

        vm.prank(caller);
        try validatorConfig.changeOwner(newOwner) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.Unauthorized.selector));
        }
    }

    function testFuzz_ChangeValidatorStatus_Unauthorized(address caller, bool status) public {
        vm.assume(caller != admin);

        // First add a validator
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);

        // Non-owner tries to change status
        vm.prank(caller);
        try validatorConfig.changeValidatorStatus(validator1, status) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.Unauthorized.selector));
        }
    }

    function testFuzz_UpdateValidator_OnlyValidatorCanUpdate(address caller) public {
        vm.assume(caller != validator1);

        // First add a validator
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);

        // Non-validator tries to update
        vm.prank(caller);
        try validatorConfig.updateValidator(validator1, publicKey2, inboundAddr2, outboundAddr2) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.ValidatorNotFound.selector));
        }
    }

    function testFuzz_MultipleValidators_IndependentStatus(uint8 numValidators) public {
        vm.assume(numValidators > 0 && numValidators <= 10);

        address[] memory validatorAddrs = new address[](numValidators);
        bytes32[] memory pubKeys = new bytes32[](numValidators);

        for (uint8 i = 0; i < numValidators; i++) {
            validatorAddrs[i] = address(uint160(0x10000 + i));
            pubKeys[i] = bytes32(uint256(0x20000 + i));

            string memory inbound =
                string(abi.encodePacked("192.168.1.", _uint8ToString(i + 1), ":8000"));
            string memory outbound =
                string(abi.encodePacked("192.168.1.", _uint8ToString(i + 1), ":9000"));

            validatorConfig.addValidator(validatorAddrs[i], pubKeys[i], true, inbound, outbound);
        }

        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertEq(validators.length, numValidators);

        // Deactivate every other validator
        for (uint8 i = 0; i < numValidators; i += 2) {
            validatorConfig.changeValidatorStatus(validatorAddrs[i], false);
        }

        // Verify statuses
        validators = validatorConfig.getValidators();
        for (uint8 i = 0; i < numValidators; i++) {
            if (i % 2 == 0) {
                assertFalse(validators[i].active, "Even-indexed validators should be inactive");
            } else {
                assertTrue(validators[i].active, "Odd-indexed validators should be active");
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                           COMPLEX SCENARIO TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ComplexScenario_ValidatorRotation() public {
        // Add multiple validators
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);
        validatorConfig.addValidator(validator2, publicKey2, true, inboundAddr2, outboundAddr2);

        // Validator1 rotates to validator3
        vm.prank(validator1);
        validatorConfig.updateValidator(validator3, publicKey3, inboundAddr3, outboundAddr3);

        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertEq(validators.length, 2);

        // First slot should now be validator3
        assertEq(validators[0].validatorAddress, validator3);
        assertEq(validators[0].publicKey, publicKey3);
        assertEq(validators[0].index, 0);

        // Second slot should still be validator2
        assertEq(validators[1].validatorAddress, validator2);
        assertEq(validators[1].publicKey, publicKey2);
        assertEq(validators[1].index, 1);
    }

    function test_ComplexScenario_OwnershipTransferChain() public {
        // Owner adds a validator
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);

        // Transfer ownership to alice
        validatorConfig.changeOwner(alice);

        // Alice adds another validator
        vm.prank(alice);
        validatorConfig.addValidator(validator2, publicKey2, true, inboundAddr2, outboundAddr2);

        // Original owner cannot add validators
        try validatorConfig.addValidator(
            validator3, publicKey3, true, inboundAddr3, outboundAddr3
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IValidatorConfig.Unauthorized.selector));
        }

        // Alice transfers to bob
        vm.prank(alice);
        validatorConfig.changeOwner(bob);

        // Bob can manage validators
        vm.prank(bob);
        validatorConfig.changeValidatorStatus(validator1, false);

        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertEq(validators.length, 2);
        assertFalse(validators[0].active);
        assertTrue(validators[1].active);
    }

    function test_ComplexScenario_ValidatorSelfUpdate() public {
        // Owner adds validator
        validatorConfig.addValidator(validator1, publicKey1, true, inboundAddr1, outboundAddr1);

        // Validator updates multiple times
        for (uint256 i = 0; i < 5; i++) {
            bytes32 newPubKey = bytes32(uint256(0x5000 + i));
            string memory newInbound =
                string(abi.encodePacked("10.0.0.", _uint8ToString(uint8(i + 1)), ":8000"));
            string memory newOutbound =
                string(abi.encodePacked("10.0.0.", _uint8ToString(uint8(i + 1)), ":9000"));

            vm.prank(validator1);
            validatorConfig.updateValidator(validator1, newPubKey, newInbound, newOutbound);
        }

        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertEq(validators.length, 1);
        assertEq(validators[0].publicKey, bytes32(uint256(0x5004)));
        assertEq(validators[0].inboundAddress, "10.0.0.5:8000");
    }

    /*//////////////////////////////////////////////////////////////
                           HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _uint8ToString(uint8 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }

        uint8 temp = value;
        uint8 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }

        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits--;
            buffer[digits] = bytes1(uint8(48 + value % 10));
            value /= 10;
        }

        return string(buffer);
    }

}
