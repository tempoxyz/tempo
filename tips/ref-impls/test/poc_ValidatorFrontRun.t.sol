// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "src/ValidatorConfig.sol";
import "src/interfaces/IValidatorConfig.sol";

contract ValidatorStatusFrontRunTest is Test {
    ValidatorConfig config;

    address admin = address(0xA11CE);
    address validator1 = address(0xB0B);
    address validator2 = address(0xC0C);

    function setUp() public {
        config = new ValidatorConfig(admin);

        vm.prank(admin);
        config.addValidator(
            validator1,
            bytes32(uint256(1)),
            true,
            "host:1234",
            "1.2.3.4:1234"
        );
    }

    /// @notice Regression test: admin can deactivate validator even after rotation
    function test_admin_can_deactivate_after_rotation() public {
        // Validator rotates to a new address
        vm.prank(validator1);
        config.updateValidator(
            validator2,
            bytes32(uint256(2)),
            "host:1234",
            "1.2.3.4:1234"
        );

        // Admin can still deactivate using the old address (resolved via index lookup)
        vm.prank(admin);
        config.changeValidatorStatus(validator1, false);

        // Validator is now deactivated at the new address
        (, bool active, , , , ) = config.validators(validator2);
        assertFalse(active, "validator should be deactivated after admin call");
    }
}
