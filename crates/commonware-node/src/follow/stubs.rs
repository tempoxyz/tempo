//! Stub implementations for running marshal in follow mode.
//!
//! The null broadcast stub satisfies marshal's type requirements but is never
//! actually used because the follower never broadcasts blocks.

use commonware_broadcast::buffered;
use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_math::algebra::Random as _;
use commonware_runtime::{Clock, Metrics, Spawner};
use rand_08::SeedableRng as _;

use crate::consensus::block::Block;

/// Create a null broadcast mailbox that never returns blocks.
///
/// In follow mode, marshal never needs to request blocks from broadcast
/// because blocks arrive via the FollowResolver. The engine
/// is created but never started, so requests will hang which is fine
/// since they should never be made.
pub(super) fn null_broadcast<E: Clock + Spawner + Metrics>(
    context: E,
    mailbox_size: usize,
) -> buffered::Mailbox<PublicKey, Block> {
    // Generate a random public key for the unused broadcast engine
    let mut rng = rand_08::rngs::StdRng::seed_from_u64(0);
    let private_key = PrivateKey::random(&mut rng);
    let public_key = private_key.public_key();

    let config = buffered::Config {
        public_key,
        mailbox_size,
        deque_size: 0,
        priority: false,
        codec_config: (),
    };

    let (_engine, mailbox) = buffered::Engine::new(context, config);
    mailbox
}
