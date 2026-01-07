//! The non-reth/non-chainspec part of the node configuration.
//!
//! This is a verbatim copy of the alto config for now.
//!
//! It feels more apt to call this "config" rather than "genesis" as both
//! summit and the tempo node are doing: the validator set is
//! not coming to consensus over the information contained in this type,
//! and neither does this information feed into the genesis block generated
//! by the execution client/reth. This genesis block is entirely the domain
//! of the chainspec, which is separate from the config.

use std::num::NonZeroU32;

use governor::Quota;

// Hardcoded values to configure commonware's alto toy chain. These could be made into
// configuration variables at some point.
pub const PENDING_CHANNEL_IDENT: commonware_p2p::Channel = 0;
pub const RECOVERED_CHANNEL_IDENT: commonware_p2p::Channel = 1;
pub const RESOLVER_CHANNEL_IDENT: commonware_p2p::Channel = 2;
pub const BROADCASTER_CHANNEL_IDENT: commonware_p2p::Channel = 3;
pub const MARSHAL_CHANNEL_IDENT: commonware_p2p::Channel = 4;
pub const DKG_CHANNEL_IDENT: commonware_p2p::Channel = 5;
pub const SUBBLOCKS_CHANNEL_IDENT: commonware_p2p::Channel = 6;

pub(crate) const NUMBER_CONCURRENT_FETCHES: usize = 4;

pub(crate) const BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES: u32 = 2u32.pow(21); // 100MB

pub const BROADCASTER_LIMIT: Quota =
    Quota::per_second(NonZeroU32::new(8).expect("value is not zero"));
pub const DKG_LIMIT: Quota = Quota::per_second(NonZeroU32::new(128).expect("value is not zero"));
pub const MARSHAL_LIMIT: Quota = Quota::per_second(NonZeroU32::new(8).expect("value is not zero"));
pub const PENDING_LIMIT: Quota =
    Quota::per_second(NonZeroU32::new(128).expect("value is not zero"));
pub const RECOVERED_LIMIT: Quota =
    Quota::per_second(NonZeroU32::new(128).expect("value is not zero"));
pub const RESOLVER_LIMIT: Quota =
    Quota::per_second(NonZeroU32::new(128).expect("value is not zero"));
pub const SUBBLOCKS_LIMIT: Quota =
    Quota::per_second(NonZeroU32::new(128).expect("value is not zero"));

pub(crate) const NAMESPACE: &[u8] = b"TEMPO";

/// The number of peer sets that will be active in the lookup p2p network.
pub(crate) const PEERSETS_TO_TRACK: usize = 3;
