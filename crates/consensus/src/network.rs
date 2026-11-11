//! The size limit of consensus p2p messages.
use std::num::NonZeroU32;

use commonware_consensus::{
    marshal::{self, standard::Standard},
    simplex::{self, scheme::bls12381_threshold::vrf::Scheme},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_p2p::utils::mux;

use crate::{
    consensus::{Digest, block::Block},
    dkg,
};

/// Returns the p2p payload limit admitting every message consensus sends for committees of at
/// most `max_participants`.
///
/// Finalized and notarized backfill responses carry a certificate with a full block, so the limit
/// exceeds the largest block. Simplex and DKG run on muxer subchannels, so their payloads carry a
/// subchannel prefix; marshal and broadcast do not.
///
/// # Panics
///
/// Panics if the limit does not fit in a `u32`. A limit above the transport maximum makes
/// starting the p2p network panic instead.
pub(crate) fn max_message_size(max_participants: NonZeroU32) -> u32 {
    commonware_p2p::max_message_size(&[
        mux::prefixed(
            simplex::max_payload_size::<Scheme<PublicKey, MinSig>, Digest>(max_participants.get()),
        ),
        marshal::max_payload_size::<Standard<Block>, Scheme<PublicKey, MinSig>>(
            max_participants.get(),
            &(),
        ),
        mux::prefixed(dkg::max_message_size(max_participants)),
    ])
}

#[cfg(test)]
mod tests {
    use super::max_message_size;

    /// Pins the derived limit so any change to it, from Tempo or a commonware upgrade, is
    /// reviewed: all peers must agree on it.
    #[test]
    fn max_message_size_for_20_validators_is_pinned() {
        assert_eq!(max_message_size(commonware_utils::NZU32!(20)), 8_388_780);
    }
}
