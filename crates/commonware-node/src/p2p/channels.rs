//! Consensus P2P channel definitions.

use crate::config::{
    BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT, CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT,
    DKG_CHANNEL_IDENT, DKG_LIMIT, MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, RESOLVER_CHANNEL_IDENT,
    RESOLVER_LIMIT, SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT, VOTES_CHANNEL_IDENT, VOTES_LIMIT,
};

/// All consensus P2P channel pairs.
///
/// Generic over sender and receiver types to support both production and test
/// network implementations.
pub struct Channels<S, R> {
    pub votes: (S, R),
    pub certificates: (S, R),
    pub resolver: (S, R),
    pub broadcaster: (S, R),
    pub marshal: (S, R),
    pub dkg: (S, R),
    pub subblocks: (S, R),
}

/// Channel configuration: (identifier, rate limit).
pub const CHANNEL_CONFIGS: [(u64, governor::Quota); 7] = [
    (VOTES_CHANNEL_IDENT, VOTES_LIMIT),
    (CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT),
    (RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT),
    (BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT),
    (MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT),
    (DKG_CHANNEL_IDENT, DKG_LIMIT),
    (SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT),
];
