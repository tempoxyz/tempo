// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

// Helper contract containing constants and utility functions for Tempo precompiles
library TempoUtilities {

    // Registry precompiles
    address internal constant _TIP403REGISTRY = 0x403c000000000000000000000000000000000000;
    address internal constant _ADDRESS_REGISTRY = 0xfDC0000000000000000000000000000000000000;
    address internal constant _TIP20FACTORY = 0x20Fc000000000000000000000000000000000000;
    address internal constant _PATH_USD = 0x20C0000000000000000000000000000000000000;
    address internal constant _STABLECOIN_DEX = 0xDEc0000000000000000000000000000000000000;
    address internal constant _FEE_AMM = 0xfeEC000000000000000000000000000000000000;
    address internal constant _NONCE = 0x4e4F4E4345000000000000000000000000000000;
    address internal constant _VALIDATOR_CONFIG = 0xCccCcCCC00000000000000000000000000000000;

    uint80 internal constant _VIRTUAL_MAGIC = 0xFDFDFDFDFDFDFDFDFDFD;

    bytes32 internal constant TRANSFER_EVENT = keccak256("Transfer(address,address,uint256)");
    bytes32 internal constant TRANSFER_WITH_MEMO_EVENT =
        keccak256("TransferWithMemo(address,address,uint256,bytes32)");
    bytes32 internal constant MINT_EVENT = keccak256("Mint(address,uint256)");

    function isTIP20Prefix(address token) internal pure returns (bool) {
        return bytes12(bytes20(token)) == bytes12(0x20c000000000000000000000);
    }

    function isTIP20(address token) internal view returns (bool) {
        // Check if address has TIP20 prefix and non-empty code
        return isTIP20Prefix(token) && token.code.length > 0;
    }

    function isVirtualAddress(address addr) internal pure returns (bool) {
        uint160 raw = uint160(addr);
        uint160 magic = (raw >> 48) & uint160(type(uint80).max);
        return uint80(magic) == _VIRTUAL_MAGIC;
    }

    function decodeVirtualAddress(address addr)
        internal
        pure
        returns (bool isVirtual, bytes4 masterId, bytes6 userTag)
    {
        if (!isVirtualAddress(addr)) {
            return (false, bytes4(0), bytes6(0));
        }

        uint160 raw = uint160(addr);
        return (true, bytes4(uint32(raw >> 128)), bytes6(uint48(raw)));
    }

    function isValidVirtualMaster(address master) internal pure returns (bool) {
        return master != address(0) && !isVirtualAddress(master) && !isTIP20Prefix(master);
    }

}
