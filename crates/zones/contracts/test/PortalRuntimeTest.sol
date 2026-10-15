// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { ZONE_PORTAL_IMPL_ADDRESS } from "../src/runtime/interfaces/IZone.sol";
import { ZonePortal } from "../src/runtime/tempo/ZonePortal.sol";
import { Test } from "forge-std/Test.sol";

/// Fixtures mirror Tempo's shared runtime and native factory's ERC-1167 proxies.
abstract contract PortalRuntimeTest is Test {

    function _installPortalRuntime() internal {
        vm.etch(ZONE_PORTAL_IMPL_ADDRESS, vm.getDeployedCode("ZonePortal.sol:ZonePortal"));
    }

    function _portalProxyRuntime() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"363d3d373d3d3d363d73", ZONE_PORTAL_IMPL_ADDRESS, hex"5af43d82803e903d91602b57fd5bf3"
        );
    }

    function _newPortalProxy(uint64 zoneId) internal returns (ZonePortal portal) {
        require(zoneId != 0, "zero zone ID");
        address target = address(uint160(0x5ad0) << 144 | uint160(zoneId));
        require(target.code.length == 0, "portal already exists");
        // Do not replace an upgraded implementation when creating another portal.
        if (ZONE_PORTAL_IMPL_ADDRESS.code.length == 0) _installPortalRuntime();
        vm.etch(target, _portalProxyRuntime());
        return ZonePortal(target);
    }

}
