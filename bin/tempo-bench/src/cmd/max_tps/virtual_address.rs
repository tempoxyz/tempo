use alloy::primitives::{Address, B256, address, hex_literal::hex};
use tempo_alloy::primitives::{MasterId, TempoAddressExt, UserTag};

/// Pre-mined TIP-1022 PoW salts for the first 7 anvil mnemonic accounts.
///
/// These match the `POW_SALTS` in `tips/ref-impls/test/invariants/VirtualAddresses.t.sol`
/// and the `VIRTUAL_SALT` in `crates/precompiles/src/test_util.rs`.
///
/// Mnemonic: `"test test test test test test test test test test test junk"`
pub(crate) const ANVIL_VIRTUAL_SALTS: [(Address, B256); 6] = [
    (
        address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
        B256::new(hex!(
            "00000000000000000000000000000000000000000000000000000000abf52baf"
        )),
    ),
    (
        address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
        B256::new(hex!(
            "0000000000000000000000000000000000000000000000000000000213f67626"
        )),
    ),
    (
        address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
        B256::new(hex!(
            "00000000000000000000000000000000000000000000000000000000490a6a7e"
        )),
    ),
    (
        address!("90F79bf6EB2c4f870365E785982E1f101E93b906"),
        B256::new(hex!(
            "00000000000000000000000000000000000000000000000000000000e9380f73"
        )),
    ),
    (
        address!("15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
        B256::new(hex!(
            "00000000000000000000000000000000000000000000000000000000bf34bdba"
        )),
    ),
    (
        address!("9965507D1a55bcC2695C58ba16FB37d819B0A4dc"),
        B256::new(hex!(
            "000000000000000000000000000000000000000000000000000000011e93c2f3"
        )),
    ),
];

/// Builds a virtual address from a `masterId` and a random `userTag`.
///
/// Layout: `[4-byte masterId][10-byte 0xFD MAGIC][6-byte random userTag]`.
pub(crate) fn make_virtual_address(master_id: MasterId) -> Address {
    Address::new_virtual(master_id, UserTag::random())
}
