// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// Helper contract containing constants and utility functions for Tempo precompiles
library TempoUtilities {

    // Registry precompiles
    address internal constant _TIP403REGISTRY = 0x403c000000000000000000000000000000000000;
    address internal constant _TIP20FACTORY = 0x20Fc000000000000000000000000000000000000;
    address internal constant _PATH_USD = 0x20C0000000000000000000000000000000000000;
    address internal constant _STABLECOIN_DEX = 0xDEc0000000000000000000000000000000000000;
    address internal constant _FEE_AMM = 0xfeEC000000000000000000000000000000000000;
    address internal constant _NONCE = 0x4e4F4E4345000000000000000000000000000000;
    address internal constant _VALIDATOR_CONFIG = 0xCccCcCCC00000000000000000000000000000000;

    function isTIP20(address token) internal view returns (bool) {
        // Check if address has TIP20 prefix and non-empty code
        return
            bytes12(bytes20(token)) == bytes12(0x20c000000000000000000000) && token.code.length > 0;
    }

}
