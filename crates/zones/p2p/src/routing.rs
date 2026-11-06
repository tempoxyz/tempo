use std::collections::BTreeSet;

use commonware_cryptography::ed25519::PublicKey;

use crate::{LeadershipSchedule, ZoneManifest, manifest::AuthoritySnapshot};

/// Authenticated Commonware identity used to address one manifest peer.
pub type P2pPeerId = PublicKey;

/// Authenticated peers and the static settlement quorum derived from a validated manifest.
#[derive(Debug, Clone)]
pub(crate) struct RoutingMembership {
    peers: BTreeSet<PublicKey>,
    quorum: BTreeSet<PublicKey>,
}

impl RoutingMembership {
    pub(crate) fn from_manifest(manifest: &ZoneManifest) -> Self {
        let peers = manifest
            .nodes()
            .iter()
            .map(|node| node.ed25519_public_key().clone())
            .collect();
        let quorum = manifest
            .quorum_nodes()
            .map(|(node, _)| node.ed25519_public_key().clone())
            .collect();
        Self { peers, quorum }
    }

    pub(crate) fn contains(&self, peer: &PublicKey) -> bool {
        self.peers.contains(peer)
    }

    pub(crate) fn is_quorum_member(&self, peer: &PublicKey) -> bool {
        self.quorum.contains(peer)
    }

    pub(crate) fn other_peers(&self, local: &PublicKey) -> Vec<PublicKey> {
        self.peers
            .iter()
            .filter(|peer| *peer != local)
            .cloned()
            .collect()
    }

    pub(crate) fn other_quorum_peers(&self, local: &PublicKey) -> Vec<PublicKey> {
        self.quorum
            .iter()
            .filter(|peer| *peer != local)
            .cloned()
            .collect()
    }
}

/// Pure identity, membership, and retained-authority decisions for one routing operation.
pub(crate) struct RoutingPolicy<'a> {
    local: &'a PublicKey,
    membership: &'a RoutingMembership,
    authority: AuthoritySnapshot,
}

impl<'a> RoutingPolicy<'a> {
    pub(crate) fn new(
        local: &'a PublicKey,
        membership: &'a RoutingMembership,
        leadership: &LeadershipSchedule,
    ) -> Self {
        Self {
            local,
            membership,
            authority: leadership.authority_snapshot(),
        }
    }

    pub(crate) fn may_broadcast_block(&self) -> bool {
        self.authority.retained_leaders.contains(self.local)
    }

    pub(crate) fn am_i_retained_leader(&self) -> bool {
        self.may_broadcast_block()
    }

    pub(crate) fn am_i_quorum_member(&self) -> bool {
        self.membership.is_quorum_member(self.local)
    }

    pub(crate) fn other_peers(&self) -> Vec<PublicKey> {
        self.membership.other_peers(self.local)
    }

    pub(crate) fn other_quorum_peers(&self) -> Vec<PublicKey> {
        self.membership.other_quorum_peers(self.local)
    }

    pub(crate) fn may_broadcast_settlement_proposal(&self) -> bool {
        self.may_broadcast_block()
    }

    pub(crate) fn block_recipients(&self) -> Vec<PublicKey> {
        self.other_peers()
    }

    pub(crate) fn settlement_proposal_recipients(&self) -> Vec<PublicKey> {
        self.other_quorum_peers()
    }

    pub(crate) fn may_accept_settlement_proposal(&self, peer: &PublicKey) -> bool {
        self.am_i_quorum_member() && self.is_remote_retained_leader(peer)
    }

    pub(crate) fn may_send_settlement_signature(&self, leader: &PublicKey) -> bool {
        self.am_i_quorum_member()
            && leader != self.local
            && self.is_retained_leader(leader)
            && self.membership.contains(leader)
    }

    pub(crate) fn may_accept_settlement_signature(&self, peer: &PublicKey) -> bool {
        self.is_remote_quorum_peer(peer) && self.am_i_retained_leader()
    }

    pub(crate) fn preferred_backfill_leader(&self) -> Option<PublicKey> {
        let leader = self.authority.next_anchor_record.as_ref()?.leader.clone();
        (self.membership.is_quorum_member(&leader) && leader != *self.local).then_some(leader)
    }

    pub(crate) fn backfill_candidates(&self) -> Vec<PublicKey> {
        self.membership.other_quorum_peers(self.local)
    }

    pub(crate) fn is_remote_member(&self, peer: &PublicKey) -> bool {
        self.is_remote_peer(peer)
    }

    pub(crate) fn may_accept_backfill_response(&self, peer: &PublicKey) -> bool {
        self.is_remote_quorum_peer(peer)
    }

    /// `None` while leadership is uninitialized; otherwise whether this node may forward.
    pub(crate) fn transaction_forwarding_status(&self) -> Option<bool> {
        self.authority
            .next_anchor_record
            .as_ref()
            .map(|record| record.leader != *self.local)
    }

    pub(crate) fn transaction_recipients(&self) -> Vec<PublicKey> {
        self.membership.other_quorum_peers(self.local)
    }

    pub(crate) fn may_accept_transaction(&self, peer: &PublicKey) -> bool {
        self.is_remote_peer(peer) && self.membership.is_quorum_member(self.local)
    }

    fn is_retained_leader(&self, peer: &PublicKey) -> bool {
        self.authority.retained_leaders.contains(peer)
    }

    fn is_remote_retained_leader(&self, peer: &PublicKey) -> bool {
        peer != self.local && self.membership.contains(peer) && self.is_retained_leader(peer)
    }

    pub(crate) fn is_remote_peer(&self, peer: &PublicKey) -> bool {
        peer != self.local && self.membership.contains(peer)
    }

    pub(crate) fn is_remote_quorum_peer(&self, peer: &PublicKey) -> bool {
        self.is_remote_peer(peer) && self.membership.is_quorum_member(peer)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use alloy_primitives::B256;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    use super::{RoutingMembership, RoutingPolicy};
    use crate::{LeadershipSchedule, LeadershipState, ZoneManifest};

    fn key(seed: u64) -> crate::P2pPeerId {
        PrivateKey::from_seed(seed).public_key()
    }

    fn manifest() -> ZoneManifest {
        let mut input = format!("leader_ed25519_public_key = \"{}\"\n", hex(key(1)));
        for (seed, rpc_only) in [(1, false), (2, false), (3, false), (4, true)] {
            input.push_str(&format!(
                "\n[[nodes]]\nname = \"node-{seed}\"\ned25519_public_key = \"{}\"\naddress = \"127.0.0.1:{}\"\nrpc_only = {rpc_only}\n",
                hex(key(seed)),
                9000 + seed,
            ));
            if !rpc_only {
                input.push_str(&format!("secp256k1_address = \"0x{seed:040x}\"\n"));
            }
        }
        ZoneManifest::parse(&input).unwrap()
    }

    fn hex(key: crate::P2pPeerId) -> String {
        const_hex::encode_prefixed(key.as_ref())
    }

    #[test]
    fn membership_rejects_unknown_peers_as_quorum() {
        let membership = RoutingMembership::from_manifest(&manifest());
        assert!(membership.contains(&key(1)));
        assert!(membership.is_quorum_member(&key(1)));
        assert!(!membership.is_quorum_member(&key(99)));
        assert!(!membership.contains(&key(99)));
        assert!(!membership.is_quorum_member(&key(4)));
    }

    #[test]
    fn routing_policy_covers_roles_and_transaction_fanout() {
        let manifest = manifest();
        let membership = RoutingMembership::from_manifest(&manifest);
        let schedule = LeadershipSchedule::for_membership([key(4)].into_iter().collect());
        schedule
            .publish(LeadershipState::new(1, key(1), 0))
            .unwrap();
        schedule
            .publish(LeadershipState::new(2, key(2), 100))
            .unwrap();

        let leader_key = key(1);
        let leader = RoutingPolicy::new(&leader_key, &membership, &schedule);
        assert!(leader.may_broadcast_block());
        assert_eq!(
            leader
                .block_recipients()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            [key(2), key(3), key(4)].into_iter().collect()
        );
        assert_eq!(leader.transaction_forwarding_status(), Some(true));

        let follower_key = key(3);
        let follower = RoutingPolicy::new(&follower_key, &membership, &schedule);
        assert!(!follower.may_broadcast_block());
        assert_eq!(follower.preferred_backfill_leader(), Some(key(2)));
        assert_eq!(
            follower
                .backfill_candidates()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            [key(1), key(2)].into_iter().collect()
        );

        let rpc_key = key(4);
        let rpc = RoutingPolicy::new(&rpc_key, &membership, &schedule);
        assert!(!rpc.may_accept_settlement_proposal(&key(1)));
        assert!(!rpc.may_accept_transaction(&key(3)));
    }

    #[test]
    fn uninitialized_authority_does_not_authorize_dynamic_traffic() {
        let manifest = manifest();
        let membership = RoutingMembership::from_manifest(&manifest);
        let schedule = manifest.leadership_schedule();
        let local = key(2);
        let policy = RoutingPolicy::new(&local, &membership, &schedule);
        assert!(!policy.may_broadcast_block());
        assert_eq!(policy.transaction_forwarding_status(), None);
        assert_eq!(policy.preferred_backfill_leader(), None);
    }

    #[test]
    fn forced_recovery_leader_is_retained_for_block_broadcast_and_settlement_routing() {
        let manifest = manifest();
        let membership = RoutingMembership::from_manifest(&manifest);
        let outgoing = key(1);
        let recovery = key(2);
        let portal_successor = key(3);
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(1, outgoing, 0));
        schedule
            .install_forced_recovery(2, recovery.clone(), B256::repeat_byte(0x11), 51)
            .unwrap();
        schedule
            .publish(LeadershipState::new(2, portal_successor.clone(), 60))
            .unwrap();

        let recovery_policy = RoutingPolicy::new(&recovery, &membership, &schedule);
        assert!(recovery_policy.may_broadcast_block());
        assert!(recovery_policy.may_broadcast_settlement_proposal());
        assert!(
            recovery_policy.may_accept_settlement_signature(&portal_successor),
            "the recovery leader must accept quorum signatures"
        );
        let follower = RoutingPolicy::new(&portal_successor, &membership, &schedule);
        assert!(follower.may_accept_settlement_proposal(&recovery));
        assert!(follower.may_send_settlement_signature(&recovery));

        schedule.record_applied_anchor(60);
        let completed_recovery = RoutingPolicy::new(&recovery, &membership, &schedule);
        assert!(!completed_recovery.may_broadcast_block());
        let follower = RoutingPolicy::new(&portal_successor, &membership, &schedule);
        assert!(!follower.may_send_settlement_signature(&recovery));
    }
}
