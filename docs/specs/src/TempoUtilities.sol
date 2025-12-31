// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// Helper contract containing constants and utility functions for Tempo precompiles
library TempoUtilities {

    function isTIP20(address token) internal view returns (bool) {
        return bytes10(bytes20(token)) == bytes10(0x20c00000000000000000) && token.code.length > 0;
    }

}
