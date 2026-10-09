// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { ZONE_PORTAL_IMPL_ADDRESS } from "../../src/runtime/interfaces/IZone.sol";
import { Verifier } from "../../src/runtime/tempo/Verifier.sol";
import { ZoneMessenger } from "../../src/runtime/tempo/ZoneMessenger.sol";
import { ZonePortal } from "../../src/runtime/tempo/ZonePortal.sol";
import { PortalRuntimeTest } from "../PortalRuntimeTest.sol";

contract PortalRuntimeTestCase is PortalRuntimeTest {

    /// @dev Protocol-installed runtimes bypass EIP-170, but retain a generous safety budget to
    ///      catch accidental bytecode growth. This is a Tempo policy limit, not an EVM limit.
    uint256 internal constant MAX_PROTOCOL_RUNTIME_SIZE = 64 * 1024;

    function test_protocolInstalledRuntimesStayWithinSizeBudget() public view {
        assertLe(
            vm.getDeployedCode("ZonePortal.sol:ZonePortal").length,
            MAX_PROTOCOL_RUNTIME_SIZE,
            "ZonePortal runtime exceeds 64 KiB"
        );
        assertLe(
            vm.getDeployedCode("ZoneMessenger.sol:ZoneMessenger").length,
            MAX_PROTOCOL_RUNTIME_SIZE,
            "ZoneMessenger runtime exceeds 64 KiB"
        );
        assertLe(
            vm.getDeployedCode("Verifier.sol:Verifier").length,
            MAX_PROTOCOL_RUNTIME_SIZE,
            "Verifier runtime exceeds 64 KiB"
        );
    }

    function test_installsExactArtifactAndNativeProxy() public {
        ZonePortal portal = _newPortalProxy(1);
        assertEq(ZONE_PORTAL_IMPL_ADDRESS.code, vm.getDeployedCode("ZonePortal.sol:ZonePortal"));
        assertEq(address(portal), address(0x5ad0000000000000000000000000000000000001));
        assertEq(
            address(portal).code,
            hex"363d3d373d3d3d363d735ad10000000000000000000000000000000000005af43d82803e903d91602b57fd5bf3"
        );
        assertEq(portal.MAX_UNPROCESSED_DEPOSITS(), 230);
    }

    function test_oversizedRuntimeExecutesAndUpgradePreservesProxyState() public {
        ZonePortal first = _newPortalProxy(1);
        bytes32 slot = bytes32(uint256(29));
        vm.store(address(first), slot, bytes32(uint256(123)));
        vm.deal(address(first), 1 ether);
        // Execute real portal code with unreachable padding, even if future builds shrink.
        bytes memory oversized = bytes.concat(ZONE_PORTAL_IMPL_ADDRESS.code, new bytes(24_577));
        vm.etch(ZONE_PORTAL_IMPL_ADDRESS, oversized);
        assertGt(ZONE_PORTAL_IMPL_ADDRESS.code.length, 24_576);
        assertEq(first.MAX_UNPROCESSED_DEPOSITS(), 230);
        ZonePortal second = _newPortalProxy(2);
        assertEq(ZONE_PORTAL_IMPL_ADDRESS.code, oversized);
        assertEq(second.MAX_UNPROCESSED_DEPOSITS(), 230);
        assertEq(vm.load(address(first), slot), bytes32(uint256(123)));
        assertEq(vm.load(address(second), slot), bytes32(0));
        assertEq(address(first).balance, 1 ether);
        _installPortalRuntime();
        _installPortalRuntime();
        assertEq(first.MAX_UNPROCESSED_DEPOSITS(), 230);
        assertEq(vm.load(address(first), slot), bytes32(uint256(123)));
    }

}
