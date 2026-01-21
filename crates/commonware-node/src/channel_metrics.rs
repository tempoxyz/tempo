//! Per-peer consensus message metrics with human-readable channel names.
//!
//! This module provides metrics tracking for consensus network messages,
//! adding human-readable channel name labels to complement the numeric
//! channel identifiers used by the commonware p2p layer.
//!
//! # Channel Mapping
//!
//! | Channel ID | Name         | Description                                    |
//! |------------|--------------|------------------------------------------------|
//! | 0          | pending      | Pending votes before notarization              |
//! | 1          | recovered    | Recovered/notarized certificates               |
//! | 2          | resolver     | Block/data availability resolution             |
//! | 3          | broadcaster  | Gossip broadcast messages                      |
//! | 4          | marshal      | Marshal/sync messages                          |
//! | 5          | dkg          | Distributed key generation ceremony messages   |
//! | 6          | subblocks    | Subblock propagation messages                  |

use commonware_p2p::Channel;

use crate::config::{
    BROADCASTER_CHANNEL_IDENT, DKG_CHANNEL_IDENT, MARSHAL_CHANNEL_IDENT, PENDING_CHANNEL_IDENT,
    RECOVERED_CHANNEL_IDENT, RESOLVER_CHANNEL_IDENT, SUBBLOCKS_CHANNEL_IDENT,
};

/// Human-readable names for consensus network channels.
///
/// These names correspond to the channel identifiers exported from the crate root
/// (e.g., [`PENDING_CHANNEL_IDENT`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelName {
    /// Pending votes channel (channel 0) - used for votes before notarization.
    Pending,
    /// Recovered certificates channel (channel 1) - used for notarized certificates.
    Recovered,
    /// Resolver channel (channel 2) - used for block/data availability resolution.
    Resolver,
    /// Broadcaster channel (channel 3) - used for gossip broadcast.
    Broadcaster,
    /// Marshal channel (channel 4) - used for marshal/sync operations.
    Marshal,
    /// DKG channel (channel 5) - used for distributed key generation ceremony.
    Dkg,
    /// Subblocks channel (channel 6) - used for subblock propagation.
    Subblocks,
    /// Unknown channel - for any unrecognized channel ID.
    Unknown(Channel),
}

impl ChannelName {
    /// Convert a channel ID to its human-readable name.
    #[must_use]
    pub const fn from_channel_id(channel: Channel) -> Self {
        match channel {
            PENDING_CHANNEL_IDENT => Self::Pending,
            RECOVERED_CHANNEL_IDENT => Self::Recovered,
            RESOLVER_CHANNEL_IDENT => Self::Resolver,
            BROADCASTER_CHANNEL_IDENT => Self::Broadcaster,
            MARSHAL_CHANNEL_IDENT => Self::Marshal,
            DKG_CHANNEL_IDENT => Self::Dkg,
            SUBBLOCKS_CHANNEL_IDENT => Self::Subblocks,
            id => Self::Unknown(id),
        }
    }

    /// Get the string representation of this channel name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Recovered => "recovered",
            Self::Resolver => "resolver",
            Self::Broadcaster => "broadcaster",
            Self::Marshal => "marshal",
            Self::Dkg => "dkg",
            Self::Subblocks => "subblocks",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl std::fmt::Display for ChannelName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(id) => write!(f, "unknown_{id}"),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// Maps all known channel IDs to their human-readable names.
///
/// This is useful for documentation and tooling that needs to understand
/// the channel mapping.
///
/// # Example
///
/// ```ignore
/// for (id, name) in channel_id_to_name_mapping() {
///     println!("Channel {}: {}", id, name);
/// }
/// ```
#[must_use]
pub const fn channel_id_to_name_mapping() -> [(Channel, &'static str); 7] {
    [
        (PENDING_CHANNEL_IDENT, "pending"),
        (RECOVERED_CHANNEL_IDENT, "recovered"),
        (RESOLVER_CHANNEL_IDENT, "resolver"),
        (BROADCASTER_CHANNEL_IDENT, "broadcaster"),
        (MARSHAL_CHANNEL_IDENT, "marshal"),
        (DKG_CHANNEL_IDENT, "dkg"),
        (SUBBLOCKS_CHANNEL_IDENT, "subblocks"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_name_from_id() {
        assert_eq!(ChannelName::from_channel_id(0), ChannelName::Pending);
        assert_eq!(ChannelName::from_channel_id(1), ChannelName::Recovered);
        assert_eq!(ChannelName::from_channel_id(2), ChannelName::Resolver);
        assert_eq!(ChannelName::from_channel_id(3), ChannelName::Broadcaster);
        assert_eq!(ChannelName::from_channel_id(4), ChannelName::Marshal);
        assert_eq!(ChannelName::from_channel_id(5), ChannelName::Dkg);
        assert_eq!(ChannelName::from_channel_id(6), ChannelName::Subblocks);
        assert_eq!(ChannelName::from_channel_id(99), ChannelName::Unknown(99));
    }

    #[test]
    fn test_channel_name_as_str() {
        assert_eq!(ChannelName::Pending.as_str(), "pending");
        assert_eq!(ChannelName::Recovered.as_str(), "recovered");
        assert_eq!(ChannelName::Resolver.as_str(), "resolver");
        assert_eq!(ChannelName::Broadcaster.as_str(), "broadcaster");
        assert_eq!(ChannelName::Marshal.as_str(), "marshal");
        assert_eq!(ChannelName::Dkg.as_str(), "dkg");
        assert_eq!(ChannelName::Subblocks.as_str(), "subblocks");
        assert_eq!(ChannelName::Unknown(99).as_str(), "unknown");
    }

    #[test]
    fn test_channel_name_display() {
        assert_eq!(format!("{}", ChannelName::Pending), "pending");
        assert_eq!(format!("{}", ChannelName::Unknown(99)), "unknown_99");
    }

    #[test]
    fn test_mapping_consistency() {
        let mapping = channel_id_to_name_mapping();
        for (id, name) in mapping {
            assert_eq!(ChannelName::from_channel_id(id).as_str(), name);
        }
    }
}
