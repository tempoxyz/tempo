//! Stub implementations for running marshal in follow mode.
//!
//! The null broadcast stub satisfies marshal's type requirements but is never
//! actually used because the follower never broadcasts blocks.

use commonware_broadcast::buffered;
use commonware_codec::{FixedSize as _, ReadExt as _};
use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::utils::StaticProvider;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner};
use commonware_utils::ordered::Set;
use rand_08::SeedableRng as _;

use crate::consensus::block::Block;

/// Create a null broadcast mailbox
///
/// In follow mode, there are no consensus peers to broadcast state or
/// request information from. The FollowResolver is backed by the
/// execution node and upstream ws connection.
pub(super) fn null_broadcast<E: Clock + Spawner + Metrics + BufferPooler>(
    context: E,
    mailbox_size: usize,
) -> buffered::Mailbox<PublicKey, Block> {
    // Generate a random public key for the unused broadcast engine
    let mut rng = rand_08::rngs::StdRng::seed_from_u64(0);
    let private_key = {
        let mut bytes = [0u8; PrivateKey::SIZE];
        rand_08::RngCore::fill_bytes(&mut rng, &mut bytes);
        PrivateKey::read(&mut bytes.as_slice()).expect("valid ed25519 private key bytes")
    };
    let public_key = private_key.public_key();

    let config = buffered::Config {
        public_key,
        mailbox_size: std::num::NonZeroUsize::new(mailbox_size)
            .expect("follow broadcast mailbox size must be non-zero"),
        deque_size: 0,
        priority: false,
        codec_config: (),
        peer_provider: StaticProvider::new(0, Set::default()),
    };

    let (_engine, mailbox) = buffered::Engine::new(context, config);
    mailbox
}
