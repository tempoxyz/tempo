//! Tempo's devp2p `eth` protocol configuration.

use reth_ethereum::network::eth_wire::EthVersion;

/// `eth` protocol versions Tempo advertises, newest first.
///
/// Pinned instead of reth's [`EthVersion::ALL_VERSIONS`] so a node never advertises a new
/// upstream version just by bumping reth. eth/71 (block access lists, EIP-8159) and eth/72
/// (sparse blobpool, EIP-8070) exchange data Tempo doesn't have.
pub const ETH_VERSIONS: [EthVersion; 5] = [
    EthVersion::Eth70,
    EthVersion::Eth69,
    EthVersion::Eth68,
    EthVersion::Eth67,
    EthVersion::Eth66,
];
