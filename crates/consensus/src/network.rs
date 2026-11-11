//! The consensus p2p network and the size limit of its messages.
use std::num::NonZeroU32;

use commonware_consensus::{
    marshal::{self, standard::Standard},
    simplex::{self, scheme::bls12381_threshold::vrf::Scheme},
};
use commonware_cryptography::{
    ChaCha20Poly1305,
    bls12381::primitives::variant::MinSig,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{authenticated::lookup, utils::mux};
use commonware_runtime::Supervisor as _;
use commonware_stream::{
    SakeCups,
    cups::{self, Cups},
    sake::{self, Sake},
};
use eyre::OptionExt as _;

use crate::{
    Args,
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

/// Pins the v2026.9.0 wire protocol (SAKE V0, CUPS V0) so that validators on
/// either commonware release can talk during a rolling upgrade. Versions are
/// not negotiated: moving to V1 needs every validator to switch together.
fn p2p_upgrader(
    signing_key: PrivateKey,
    synchrony_bound: std::time::Duration,
    max_handshake_age: std::time::Duration,
) -> SakeCups<PrivateKey, ChaCha20Poly1305> {
    Cups::new(
        Sake {
            signer: signing_key,
            synchrony_bound,
            max_handshake_age,
            version: sake::Version::V0,
        },
        cups::Version::V0,
    )
}

/// Starts the consensus p2p network with every message size limited to `max_message_size`.
pub(crate) async fn instantiate(
    context: &commonware_runtime::tokio::Context,
    config: &Args,
    signing_key: PrivateKey,
    max_message_size: u32,
) -> eyre::Result<(
    lookup::Network<commonware_runtime::tokio::Context, SakeCups<PrivateKey, ChaCha20Poly1305>>,
    lookup::Oracle<PublicKey>,
)> {
    // TODO: Find out why `union_unique` should be used. This is the only place
    // where `NAMESPACE` is used at all. We follow alto's example for now.
    let namespace = commonware_utils::union_unique(crate::config::NAMESPACE, b"_P2P");
    let cfg = lookup::Config {
        namespace,
        handshake: p2p_upgrader(
            signing_key,
            config.synchrony_bound.into_duration(),
            config.handshake_stale_after.into_duration(),
        ),
        listen: config.listen_address,
        max_message_size,
        mailbox_size: config.mailbox_size,
        send_batch_size: commonware_utils::NZUsize!(8),
        bypass_ip_check: config.bypass_ip_check,
        allow_private_ips: config.allow_private_ips,
        allow_dns: config.allow_dns,
        tracked_peer_sets: crate::config::PEERSETS_TO_TRACK,
        max_peers_per_set: config
            .max_peers_per_set
            .try_into()
            .expect("a u32 always fits in usize on supported targets"),
        handshake_timeout: config.handshake_timeout.into_duration(),
        dial_timeout: config.dial_timeout.into_duration(),
        max_concurrent_handshakes: config.max_concurrent_handshakes,
        block_duration: config.time_to_unblock_byzantine_peer.into_duration(),
        dial_frequency: config.wait_before_peers_redial.into_duration(),
        ping_frequency: config.wait_before_peers_reping.into_duration(),
        peer_connection_cooldown: config.connection_per_peer_min_period.into_duration(),
        allowed_handshake_rate_per_ip: commonware_runtime::Quota::with_period(
            config.handshake_per_ip_min_period.into_duration(),
        )
        .ok_or_eyre("handshake per ip min period must be non-zero")?,
        allowed_handshake_rate_per_subnet: commonware_runtime::Quota::with_period(
            config.handshake_per_subnet_min_period.into_duration(),
        )
        .ok_or_eyre("handshake per subnet min period must be non-zero")?,
    };

    Ok(lookup::Network::new(context.child("network"), cfg))
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
