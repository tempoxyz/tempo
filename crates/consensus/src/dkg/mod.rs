use std::num::NonZeroU32;

use commonware_codec::FixedSize as _;
use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::{DealerPrivMsg, DealerPubMsg},
    primitives::variant::MinSig,
};

pub(crate) mod manager;

/// Returns an upper bound on the encoded size of a DKG p2p message for at most
/// `max_participants`.
pub(crate) fn max_message_size(max_participants: NonZeroU32) -> usize {
    // The tag byte, then the dealer message; an ack is a lone signature and always smaller.
    1 + DealerPubMsg::<MinSig>::max_encode_size(max_participants) + DealerPrivMsg::SIZE
}
