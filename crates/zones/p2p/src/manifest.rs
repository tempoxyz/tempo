use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};

use alloy_primitives::{Address as EthereumAddress, B256};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{Address, Ingress};
use commonware_utils::Hostname;
use derive_more::{Display, FromStr};
use serde::Deserialize;

/// Minimum number of nodes that must be registered for the on-chain settlement quorum.
const MIN_QUORUM_NODES: usize = 3;

/// The role a node holds for a given Tempo anchor.
///
/// Which member *leads* comes from finalized L1 state; whether a member belongs to the
/// on-chain settlement quorum comes from the manifest and never changes at runtime.
///
/// `kebab-case` rather than `lowercase` so `RpcFollower` spells `rpc-follower` on the
/// `--sequencer.role` CLI flag instead of `rpcfollower`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, FromStr)]
#[display(rename_all = "kebab-case")]
#[from_str(rename_all = "kebab-case")]
pub enum Role {
    /// Builds blocks and runs the existing sequencer settlement tasks.
    Leader,
    /// Runs without block production, follows `Leader`s blocks, and signs settlement
    /// attestations for the on-chain quorum.
    Follower,
    /// Follows `Leader`s blocks without joining the on-chain quorum.
    ///
    /// A hot standby for operator RPC: it imports and serves the same chain and forwards
    /// transactions to the leader, but never signs a settlement attestation and holds no
    /// individual secp256k1 key. That keeps the leader and the quorum followers off the
    /// internet without changing the quorum.
    RpcFollower,
}

/// One finalized leadership transition.
///
/// A record authorizes `leader` for every Tempo anchor with
/// `anchor >= activation_tempo_block`, until a later transition's activation boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeadershipState {
    /// Monotonically increasing fencing epoch.
    pub epoch: u64,
    /// Ed25519 identity of the selected leader.
    pub leader: PublicKey,
    /// Tempo (L1) block number at which this leader's authorization begins.
    pub activation_tempo_block: u64,
}

/// Dynamic leadership authority captured from one schedule read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthoritySnapshot {
    /// Leaders retained by the observed portal schedule or forced recovery directive.
    pub(crate) retained_leaders: BTreeSet<PublicKey>,
    /// Authority governing the next anchor this node will consume.
    pub(crate) next_anchor_record: Option<LeadershipState>,
}

impl LeadershipState {
    /// Creates a leadership record.
    pub const fn new(epoch: u64, leader: PublicKey, activation_tempo_block: u64) -> Self {
        Self {
            epoch,
            leader,
            activation_tempo_block,
        }
    }

    /// Monotonically increasing fencing epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// First Tempo anchor governed by this record.
    pub const fn activation_tempo_block(&self) -> u64 {
        self.activation_tempo_block
    }

    /// Leader selected by this record.
    pub const fn leader(&self) -> &PublicKey {
        &self.leader
    }
}

/// Operator-declared crashed-leader recovery configuration.
///
/// Every node loads this directive before starting its role controller. The selected block hash
/// pins the shared canonical tip and its embedded Tempo anchor identifies the portal leadership
/// state that recovery temporarily overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForcedRecoveryConfig {
    /// Ed25519 identity selected as the temporary runtime leader.
    leader: PublicKey,
    /// Exact canonical zone block hash selected by the operator.
    recovery_block_hash: B256,
}

impl ForcedRecoveryConfig {
    /// Ed25519 identity selected as the temporary runtime leader.
    pub const fn leader(&self) -> &PublicKey {
        &self.leader
    }

    /// Exact canonical zone block hash selected by the operator.
    pub const fn recovery_block_hash(&self) -> B256 {
        self.recovery_block_hash
    }
}

/// Forced-recovery authority attached to the finalized leadership schedule.
///
/// The manifest directive immediately assigns the replacement leader from
/// `recovery_start_tempo_block`, allowing it to consume the L1 backlog. The range is open-ended
/// until the next finalized portal transition, whose activation boundary restores ordinary portal
/// authority regardless of which leader it selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForcedRecoveryState {
    /// Epoch expected for the next portal transition.
    pub epoch: u64,
    /// Ed25519 identity selected as the replacement leader.
    pub leader: PublicKey,
    /// Exact canonical zone block hash selected in the manifest.
    pub recovery_block_hash: B256,
    /// First Tempo anchor governed by the recovery override.
    pub recovery_start_tempo_block: u64,
    /// Activation anchor from the next finalized portal transition.
    pub portal_activation_tempo_block: Option<u64>,
}

impl ForcedRecoveryState {
    /// Whether finalized L1 has bounded this runtime override.
    pub const fn is_bounded(&self) -> bool {
        self.portal_activation_tempo_block.is_some()
    }

    fn leadership_record_for(&self, tempo_anchor: u64) -> Option<LeadershipState> {
        if tempo_anchor < self.recovery_start_tempo_block
            || self
                .portal_activation_tempo_block
                .is_some_and(|activation| tempo_anchor >= activation)
        {
            return None;
        }
        Some(LeadershipState::new(
            self.epoch,
            self.leader.clone(),
            self.recovery_start_tempo_block,
        ))
    }
}

#[derive(Debug, Default)]
struct LeadershipScheduleState {
    /// Retained transitions indexed by activation Tempo block.
    transitions: std::collections::BTreeMap<u64, LeadershipState>,
    /// Highest Tempo anchor embedded in a locally canonical zone block.
    applied_anchor: Option<u64>,
    /// Optional manifest-declared forced recovery.
    forced_recovery: Option<ForcedRecoveryState>,
}

impl LeadershipScheduleState {
    fn is_retained_leader(&self, peer: &PublicKey) -> bool {
        self.transitions
            .values()
            .any(|record| &record.leader == peer)
            || self
                .forced_recovery
                .as_ref()
                .is_some_and(|recovery| &recovery.leader == peer)
    }

    fn leader_for(&self, tempo_anchor: u64) -> Option<LeadershipState> {
        let scheduled = self
            .transitions
            .range(..=tempo_anchor)
            .next_back()
            .map(|(_, record)| record.clone());
        let recovery = self
            .forced_recovery
            .as_ref()
            .and_then(|recovery| recovery.leadership_record_for(tempo_anchor));
        recovery.or(scheduled)
    }

    fn next_anchor_record(&self) -> Option<LeadershipState> {
        let next_anchor = self
            .applied_anchor
            .map_or(u64::MAX, |applied| applied.saturating_add(1));
        self.leader_for(next_anchor)
    }

    fn maybe_bound_forced_recovery(&mut self) -> bool {
        let Some(recovery) = self.forced_recovery.as_ref() else {
            return false;
        };
        if recovery.is_bounded() {
            return false;
        }
        let Some(record) = self
            .transitions
            .values()
            .find(|record| record.epoch >= recovery.epoch)
        else {
            return false;
        };
        let activation = record.activation_tempo_block;
        self.forced_recovery
            .as_mut()
            .expect("recovery was read above")
            .portal_activation_tempo_block = Some(activation);
        metrics::counter!("zone_forced_recovery_transitions_total", "state" => "bounded")
            .increment(1);
        true
    }
}

/// Activation-indexed schedule of finalized leadership transitions.
///
/// Every observed leadership transition is kept
/// until the applied Tempo checkpoint passes activation boundary. A watch notifier announces
/// changes, but consumers re-read and index by anchor.
///
/// An empty schedule represents the "uninitialized" state: no portal leader has been
/// observed at the local Tempo checkpoint and block production must stay off.
///
/// The schedule also carries the manifest's static quorum membership, so one handle answers
/// every role question: the transitions say *who leads* a given anchor, `rpc_followers` says
/// which members are outside the on-chain quorum for every anchor.
#[derive(Debug, Clone)]
pub struct LeadershipSchedule {
    inner: std::sync::Arc<std::sync::RwLock<LeadershipScheduleState>>,
    /// Members that replicate the chain without joining the on-chain quorum.
    ///
    /// Immutable: quorum membership is manifest-derived and a leadership transition only
    /// changes who leads. Promoting a standby means provisioning a secp256k1 key, registering
    /// it with `ZonePortal`, and updating the manifest — never a runtime transition.
    rpc_followers: std::sync::Arc<BTreeSet<PublicKey>>,
    changed: tokio::sync::watch::Sender<()>,
}

impl Default for LeadershipSchedule {
    fn default() -> Self {
        Self::uninitialized()
    }
}

impl LeadershipSchedule {
    /// Creates an empty (fenced, uninitialized) schedule with an all-quorum membership.
    pub fn uninitialized() -> Self {
        Self::for_membership(BTreeSet::new())
    }

    /// Creates an empty (fenced, uninitialized) schedule whose `rpc_followers` never settle.
    pub fn for_membership(rpc_followers: BTreeSet<PublicKey>) -> Self {
        let (changed, _) = tokio::sync::watch::channel(());
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(LeadershipScheduleState::default())),
            rpc_followers: std::sync::Arc::new(rpc_followers),
            changed,
        }
    }

    /// Creates a schedule seeded with one record.
    pub fn seeded(initial: LeadershipState) -> Self {
        let schedule = Self::uninitialized();
        schedule
            .publish(initial)
            .expect("seeding an empty schedule cannot conflict");
        schedule
    }

    /// Returns whether any leadership record has been observed.
    pub fn is_initialized(&self) -> bool {
        !self.inner.read().expect("poisoned").transitions.is_empty()
    }

    /// Publish a transition observed from verified finalized receipts (or a startup snapshot).
    ///
    /// Publication is checked: an identical re-observation (subscriber replay) is an `Ok`
    /// no-op, while a conflicting record at an observed activation, a non-monotonic epoch, or
    /// a non-monotonic activation is an error that must fence ingestion in the caller.
    /// Returns whether a new transition was appended.
    pub fn publish(&self, record: LeadershipState) -> eyre::Result<bool> {
        let mut state = self.inner.write().expect("poisoned");
        // The first observed record is the earliest known authority and governs from anchor
        // zero: a fresh zone's genesis anchors precede the portal creation block, and no
        // other producer can exist before the first transition.
        let record = if state.transitions.is_empty() {
            LeadershipState {
                activation_tempo_block: 0,
                ..record
            }
        } else {
            record
        };
        if let Some(existing) = state.transitions.get(&record.activation_tempo_block) {
            eyre::ensure!(
                *existing == record,
                "conflicting leadership transition at activation {}: existing epoch {} leader \
                 {}, new epoch {} leader {}",
                record.activation_tempo_block,
                existing.epoch,
                existing.leader,
                record.epoch,
                record.leader,
            );
            return Ok(false);
        }
        if let Some((&last_activation, last)) = state.transitions.last_key_value() {
            if record.epoch == last.epoch {
                // A re-observation of the clamped initial record at its true activation is
                // the same authority; anything else with a duplicate epoch is corrupt.
                if record.leader == last.leader
                    && last_activation == 0
                    && state.transitions.len() == 1
                {
                    return Ok(false);
                }
                eyre::bail!(
                    "duplicate leadership epoch {} at a different activation: retained {}, new {}",
                    record.epoch,
                    last_activation,
                    record.activation_tempo_block,
                );
            }
            eyre::ensure!(
                record.epoch == last.epoch + 1,
                "non-contiguous leadership epoch: retained {}, new {}",
                last.epoch,
                record.epoch,
            );
            eyre::ensure!(
                record.activation_tempo_block > last_activation,
                "leadership activation moved backwards: retained {}, new {}",
                last_activation,
                record.activation_tempo_block,
            );
        }
        state
            .transitions
            .insert(record.activation_tempo_block, record);
        state.maybe_bound_forced_recovery();
        drop(state);
        self.changed.send_replace(());
        Ok(true)
    }

    /// Returns the operational authority for `tempo_anchor`.
    ///
    /// An optimistic forced recovery overrides the earlier portal schedule from its recovery
    /// boundary until the next finalized portal transition, regardless of which leader that
    /// transition selects. Returns `None` while uninitialized or for an anchor no retained
    /// transition governs.
    pub fn leader_for(&self, tempo_anchor: u64) -> Option<LeadershipState> {
        self.inner
            .read()
            .expect("poisoned")
            .leader_for(tempo_anchor)
    }

    /// Returns the most recently observed record (status only, never a production permit).
    pub fn latest(&self) -> Option<LeadershipState> {
        self.inner
            .read()
            .expect("poisoned")
            .transitions
            .last_key_value()
            .map(|(_, record)| record.clone())
    }

    /// Returns the record governing the next anchor this node will consume
    /// (`applied_anchor + 1`), falling back to the most recent record while no applied
    /// anchor has been recorded yet.
    ///
    /// This is the outbound routing authority for anchor-bound traffic such as transaction
    /// forwarding: between observing a transition and reaching its activation boundary, the
    /// outgoing leader — not the most recently observed one — still produces. Routing only,
    /// never a production permit.
    pub fn next_anchor_record(&self) -> Option<LeadershipState> {
        self.inner.read().expect("poisoned").next_anchor_record()
    }

    /// Captures routing authority from one atomic schedule read.
    pub(crate) fn authority_snapshot(&self) -> AuthoritySnapshot {
        let state = self.inner.read().expect("poisoned");
        let mut retained_leaders = state
            .transitions
            .values()
            .map(|record| record.leader.clone())
            .collect::<BTreeSet<_>>();
        if let Some(recovery) = state.forced_recovery.as_ref() {
            retained_leaders.insert(recovery.leader.clone());
        }
        AuthoritySnapshot {
            retained_leaders,
            next_anchor_record: state.next_anchor_record(),
        }
    }

    /// Install a manifest-declared forced recovery.
    ///
    /// Reinstalling the identical directive is an idempotent no-op. A different outstanding
    /// directive is rejected. The caller must validate the exact local canonical recovery tip
    /// first. The directive immediately governs the next anchor and remains in force until the
    /// next finalized portal transition.
    pub fn install_forced_recovery(
        &self,
        recovery_epoch: u64,
        leader: PublicKey,
        recovery_block_hash: B256,
        recovery_start_tempo_block: u64,
    ) -> eyre::Result<bool> {
        let requested = ForcedRecoveryState {
            epoch: recovery_epoch,
            leader,
            recovery_block_hash,
            recovery_start_tempo_block,
            portal_activation_tempo_block: None,
        };

        let mut state = self.inner.write().expect("poisoned");
        if let Some(existing) = &state.forced_recovery {
            eyre::ensure!(
                existing.epoch == requested.epoch
                    && existing.leader == requested.leader
                    && existing.recovery_block_hash == requested.recovery_block_hash
                    && existing.recovery_start_tempo_block == requested.recovery_start_tempo_block,
                "conflicting forced recovery directive is already installed"
            );
            return Ok(false);
        }
        state.forced_recovery = Some(requested);
        state.maybe_bound_forced_recovery();
        drop(state);
        self.changed.send_replace(());
        metrics::counter!("zone_forced_recovery_directives_total", "result" => "installed")
            .increment(1);
        metrics::counter!("zone_forced_recovery_transitions_total", "state" => "active")
            .increment(1);
        Ok(true)
    }

    /// Return the current forced-recovery directive, if any.
    pub fn forced_recovery(&self) -> Option<ForcedRecoveryState> {
        self.inner.read().expect("poisoned").forced_recovery.clone()
    }

    /// Highest epoch finalized L1 has shown us.
    ///
    /// Derived: `publish` requires `epoch == last.epoch + 1` and pruning never drops the last
    /// entry, so the highest observed epoch is always the last retained transition's.
    pub fn latest_observed_epoch(&self) -> Option<u64> {
        self.latest().map(|record| record.epoch)
    }

    /// Epoch whose activation boundary the locally applied checkpoint has crossed.
    ///
    /// Observability only — promotion keys off `leader_for(next anchor)`, never this value.
    pub fn locally_applied_epoch(&self) -> Option<u64> {
        let state = self.inner.read().expect("poisoned");
        let applied = state.applied_anchor?;
        state
            .transitions
            .range(..=applied)
            .next_back()
            .map(|(_, record)| record.epoch)
    }

    /// Number of observed transitions whose activation the applied checkpoint has not crossed.
    pub fn pending_transitions(&self) -> usize {
        let state = self.inner.read().expect("poisoned");
        let applied = state.applied_anchor.unwrap_or(0);
        state.transitions.range(applied + 1..).count()
    }

    /// Record that the zone block embedding `tempo_anchor` is locally canonical, pruning
    /// entries whose boundary the checkpoint has passed.
    ///
    /// The entry governing the next anchor is always retained, along with its immediate
    /// predecessor: the promotion barrier distinguishes a planned handoff from same-identity
    /// recovery by asking who governed the previous anchor.
    pub fn record_applied_anchor(&self, tempo_anchor: u64) {
        let mut state = self.inner.write().expect("poisoned");
        // Which record governs the next anchor before this advance, compared against the
        // same value afterwards so the notify below fires only when the advance actually
        // changes the controller-visible schedule.
        let previous_next_anchor_record = state.next_anchor_record();
        state.applied_anchor = Some(
            state
                .applied_anchor
                .map_or(tempo_anchor, |applied| applied.max(tempo_anchor)),
        );
        let applied = state.applied_anchor.expect("just set");
        // The entry governing the next anchor is the greatest activation <= applied + 1.
        if let Some((&active, _)) = state
            .transitions
            .range(..=applied.saturating_add(1))
            .next_back()
        {
            let keep_from = state
                .transitions
                .range(..active)
                .next_back()
                .map_or(active, |(&predecessor, _)| predecessor);
            state
                .transitions
                .retain(|&activation, _| activation >= keep_from);
        }
        let recovery_completed = state.forced_recovery.as_ref().is_some_and(|recovery| {
            recovery
                .portal_activation_tempo_block
                .is_some_and(|activation| applied >= activation)
        });
        if recovery_completed {
            state.forced_recovery = None;
        }
        let governing_record_changed = state.next_anchor_record() != previous_next_anchor_record;
        drop(state);
        // A plain advance stays silent, but forced-recovery completion must wake the role
        // controller even when the ordinary governing record is unchanged.
        if governing_record_changed || recovery_completed {
            self.changed.send_replace(());
        }
        if recovery_completed {
            metrics::counter!("zone_forced_recovery_transitions_total", "state" => "complete")
                .increment(1);
        }
    }

    /// Subscribe to schedule-change notifications. The watch is a wakeup, not the schedule:
    /// consumers re-read via [`Self::leader_for`].
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<()> {
        self.changed.subscribe()
    }

    /// Returns the role of `ed25519_public_key` for `tempo_anchor`, when governed.
    pub fn role_for(&self, ed25519_public_key: &PublicKey, tempo_anchor: u64) -> Option<Role> {
        let record = self.leader_for(tempo_anchor)?;
        Some(role_of(
            ed25519_public_key,
            &record.leader,
            &self.rpc_followers,
        ))
    }

    /// Whether `ed25519_public_key` replicates the chain without joining the on-chain quorum.
    pub fn is_rpc_only(&self, ed25519_public_key: &PublicKey) -> bool {
        self.rpc_followers.contains(ed25519_public_key)
    }

    /// Whether `ed25519_public_key` is registered with `ZonePortal` for settlement.
    ///
    /// Membership is static, so this holds for every anchor: it is the authority for who may
    /// be asked for a settlement signature and whose signature is accepted.
    pub fn is_quorum_member(&self, ed25519_public_key: &PublicKey) -> bool {
        !self.is_rpc_only(ed25519_public_key)
    }

    /// The subset of `peers` that belongs to the on-chain settlement quorum.
    pub fn quorum_peers(&self, peers: &[PublicKey]) -> Vec<PublicKey> {
        peers
            .iter()
            .filter(|peer| self.is_quorum_member(peer))
            .cloned()
            .collect()
    }
    /// Returns whether `ed25519_public_key` leads any retained portal transition or forced
    /// recovery range.
    ///
    /// A transport-level acceptance check for live blocks: a lagging follower must keep
    /// accepting the rightful producer of in-between anchors after a later transition is
    /// observed. The exact per-anchor fence lives in the import path.
    pub fn is_scheduled_leader(&self, ed25519_public_key: &PublicKey) -> bool {
        let state = self.inner.read().expect("poisoned");
        state.is_retained_leader(ed25519_public_key)
    }
}

/// Classifies `ed25519_public_key` from the two independent authorities: who leads, and which
/// members the manifest keeps out of the on-chain quorum.
///
/// Non-membership is deliberately not a fallback: a caller that cannot supply `rpc_followers`
/// would silently enrol every standby into the quorum.
fn role_of(
    ed25519_public_key: &PublicKey,
    leader: &PublicKey,
    rpc_followers: &BTreeSet<PublicKey>,
) -> Role {
    if ed25519_public_key == leader {
        Role::Leader
    } else if rpc_followers.contains(ed25519_public_key) {
        Role::RpcFollower
    } else {
        Role::Follower
    }
}

/// A validated P2P address from the manifest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManifestAddress {
    /// A literal IP address and port.
    Socket(SocketAddr),
    /// A DNS hostname and port.
    Dns { host: Hostname, port: u16 },
}

impl ManifestAddress {
    pub(crate) fn to_commonware(&self) -> Address {
        match self {
            Self::Socket(address) => Address::Symmetric(*address),
            Self::Dns { host, port } => Address::Asymmetric {
                ingress: Ingress::Dns {
                    host: host.clone(),
                    port: *port,
                },
                // DNS-only manifests cannot know a pod's egress IP ahead of time.
                // The network enables authenticated-key-only ingress filtering when
                // DNS addresses are present, so this placeholder is never consulted.
                egress: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            },
        }
    }

    pub(crate) const fn is_dns(&self) -> bool {
        matches!(self, Self::Dns { .. })
    }
}

impl fmt::Display for ManifestAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(address) => address.fmt(f),
            Self::Dns { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

impl std::str::FromStr for ManifestAddress {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = value.parse::<SocketAddr>() {
            if address.port() == 0 {
                return Err("port must be non-zero".to_owned());
            }
            return Ok(Self::Socket(address));
        }

        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| "expected `host:port`".to_owned())?;
        if host.is_empty() || host.contains(':') {
            return Err("expected a DNS hostname or bracketed IP followed by a port".to_owned());
        }
        let host = Hostname::new(host).map_err(|err| format!("invalid DNS hostname: {err}"))?;
        let port = port
            .parse::<u16>()
            .map_err(|err| format!("invalid port: {err}"))?;
        if port == 0 {
            return Err("port must be non-zero".to_owned());
        }
        Ok(Self::Dns { host, port })
    }
}

/// One node in a zone's static multi-sequencer topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestNode {
    name: String,
    ed25519_public_key: PublicKey,
    secp256k1_address: Option<EthereumAddress>,
    address: ManifestAddress,
    rpc_only: bool,
}

impl ManifestNode {
    /// Human-readable node name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Node's Ed25519 public key used to authenticate Commonware traffic.
    pub const fn ed25519_public_key(&self) -> &PublicKey {
        &self.ed25519_public_key
    }

    /// Address derived from this node's individual secp256k1 key.
    ///
    /// `None` for an `rpc_only` node: it never signs a settlement attestation, so it holds no
    /// individual key and has nothing registered with `ZonePortal`.
    pub const fn secp256k1_address(&self) -> Option<EthereumAddress> {
        self.secp256k1_address
    }

    /// Node's advertised P2P address.
    pub const fn address(&self) -> &ManifestAddress {
        &self.address
    }

    /// Whether this node replicates the chain without joining the on-chain quorum.
    pub const fn is_rpc_only(&self) -> bool {
        self.rpc_only
    }
}

/// A parsed and intrinsically validated zone manifest.
#[derive(Debug, Clone)]
pub struct ZoneManifest {
    leader_ed25519_public_key: PublicKey,
    forced_recovery: Option<ForcedRecoveryConfig>,
    nodes: Vec<ManifestNode>,
    /// Identity-only address mappings retained to resolve finalized leadership history.
    ///
    /// Historical leaders are deliberately not manifest nodes: they have no network address, do
    /// not join the settlement quorum, and cannot be selected for forced recovery or a new leader
    /// update.
    historical_leaders: BTreeMap<EthereumAddress, PublicKey>,
}

impl ZoneManifest {
    /// Parses and validates a TOML manifest.
    pub fn parse(input: &str) -> Result<Self, ManifestError> {
        let raw: RawManifest = toml::from_str(input).map_err(ManifestError::Toml)?;

        let leader_ed25519_public_key =
            parse_ed25519_public_key("leader_ed25519_public_key", &raw.leader_ed25519_public_key)?;
        let mut names = BTreeSet::new();
        let mut ed25519_public_keys = BTreeSet::new();
        let mut secp256k1_addresses = BTreeSet::new();
        let mut nodes = Vec::with_capacity(raw.nodes.len());

        for raw_node in raw.nodes {
            if raw_node.name.trim().is_empty() {
                return Err(ManifestError::EmptyNodeName);
            }
            if !names.insert(raw_node.name.clone()) {
                return Err(ManifestError::DuplicateNodeName(raw_node.name));
            }

            let ed25519_public_key = parse_ed25519_public_key(
                &format!("nodes.{}.ed25519_public_key", raw_node.name),
                &raw_node.ed25519_public_key,
            )?;
            if !ed25519_public_keys.insert(ed25519_public_key.clone()) {
                return Err(ManifestError::DuplicateEd25519PublicKey(
                    ed25519_public_key.to_string(),
                ));
            }

            // An `rpc_only` node never signs, so it must not carry an individual key: an address
            // in the manifest is either dead weight or, worse, registered with `ZonePortal` and
            // counted towards a threshold the zone can never reach.
            let secp256k1_address = match (raw_node.secp256k1_address, raw_node.rpc_only) {
                (Some(address), false) => {
                    let address = address.parse::<EthereumAddress>().map_err(|source| {
                        ManifestError::InvalidSecp256k1Address {
                            node: raw_node.name.clone(),
                            address,
                            reason: source.to_string(),
                        }
                    })?;
                    if !secp256k1_addresses.insert(address) {
                        return Err(ManifestError::DuplicateSecp256k1Address(address));
                    }
                    Some(address)
                }
                (None, true) => None,
                (None, false) => {
                    return Err(ManifestError::MissingSecp256k1Address(raw_node.name));
                }
                (Some(_), true) => {
                    return Err(ManifestError::RpcOnlySecp256k1Address(raw_node.name));
                }
            };

            let address =
                raw_node
                    .address
                    .parse()
                    .map_err(|reason| ManifestError::InvalidAddress {
                        node: raw_node.name.clone(),
                        address: raw_node.address.clone(),
                        reason,
                    })?;
            if raw_node.rpc_only && ed25519_public_key == leader_ed25519_public_key {
                return Err(ManifestError::RpcOnlyLeader(raw_node.name));
            }
            nodes.push(ManifestNode {
                name: raw_node.name,
                ed25519_public_key,
                secp256k1_address,
                address,
                rpc_only: raw_node.rpc_only,
            });
        }

        let mut historical_leaders = BTreeMap::new();
        for (index, raw_leader) in raw.historical_leaders.into_iter().enumerate() {
            let ed25519_public_key = parse_ed25519_public_key(
                &format!("historical_leaders.{index}.ed25519_public_key"),
                &raw_leader.ed25519_public_key,
            )?;
            if let Some(node) = nodes
                .iter()
                .find(|node| node.rpc_only && node.ed25519_public_key == ed25519_public_key)
            {
                return Err(ManifestError::RpcOnlyHistoricalLeader(node.name.clone()));
            }
            let secp256k1_address = raw_leader
                .secp256k1_address
                .parse::<EthereumAddress>()
                .map_err(
                    |source| ManifestError::InvalidHistoricalLeaderSecp256k1Address {
                        address: raw_leader.secp256k1_address,
                        reason: source.to_string(),
                    },
                )?;
            if !secp256k1_addresses.insert(secp256k1_address) {
                return Err(ManifestError::DuplicateSecp256k1Address(secp256k1_address));
            }
            historical_leaders.insert(secp256k1_address, ed25519_public_key);
        }

        if !ed25519_public_keys.contains(&leader_ed25519_public_key) {
            return Err(ManifestError::LeaderEd25519PublicKeyNotFound(
                leader_ed25519_public_key.to_string(),
            ));
        }

        // RPC-only members are not registered with `ZonePortal`, so they cannot make up for a
        // quorum that is too small to settle.
        let quorum_node_count = nodes.iter().filter(|node| !node.rpc_only).count();
        if quorum_node_count < MIN_QUORUM_NODES {
            return Err(ManifestError::TooFewQuorumNodes(quorum_node_count));
        }

        let forced_recovery = if let Some(recovery) = raw.forced_recovery {
            let node = nodes
                .iter()
                .find(|node| node.name == recovery.leader)
                .ok_or_else(|| {
                    ManifestError::ForcedRecoveryLeaderNotFound(recovery.leader.clone())
                })?;
            if node.rpc_only {
                return Err(ManifestError::RpcOnlyForcedRecoveryLeader(recovery.leader));
            }
            let recovery_block_hash =
                recovery
                    .recovery_block_hash
                    .parse::<B256>()
                    .map_err(|source| ManifestError::InvalidRecoveryBlockHash {
                        hash: recovery.recovery_block_hash,
                        reason: source.to_string(),
                    })?;
            Some(ForcedRecoveryConfig {
                leader: node.ed25519_public_key.clone(),
                recovery_block_hash,
            })
        } else {
            None
        };

        Ok(Self {
            leader_ed25519_public_key,
            forced_recovery,
            nodes,
            historical_leaders,
        })
    }

    /// Reads, parses, and validates a TOML manifest from disk.
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self, ManifestError> {
        let path = path.as_ref();
        let input = std::fs::read_to_string(path).map_err(|source| ManifestError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&input)
    }

    /// Validates node-specific invariants and returns the manifest-derived bootstrap role.
    ///
    /// `local_secp256k1_address` must be `None` exactly when this node is `rpc_only`: an
    /// internet-facing standby is not supposed to be provisioned with quorum key material, and
    /// a quorum member without it could never settle.
    pub fn validate_node(
        &self,
        local_ed25519_public_key: &PublicKey,
        local_secp256k1_address: Option<EthereumAddress>,
        asserted_role: Option<Role>,
    ) -> Result<Role, ManifestError> {
        let local_node = self
            .node_by_ed25519_public_key(local_ed25519_public_key)
            .ok_or_else(|| {
                ManifestError::LocalNodeNotFound(local_ed25519_public_key.to_string())
            })?;
        match (local_node.secp256k1_address, local_secp256k1_address) {
            (Some(manifest), Some(local)) if manifest != local => {
                return Err(ManifestError::LocalSecp256k1AddressMismatch { manifest, local });
            }
            (Some(_), None) => {
                return Err(ManifestError::LocalSecp256k1KeyMissing(
                    local_node.name.clone(),
                ));
            }
            (None, Some(_)) => {
                return Err(ManifestError::LocalSecp256k1KeyUnexpected(
                    local_node.name.clone(),
                ));
            }
            (Some(_), Some(_)) | (None, None) => {}
        }
        let role = self.bootstrap_role_of(local_ed25519_public_key);
        if let Some(asserted) = asserted_role
            && asserted != role
        {
            return Err(ManifestError::RoleMismatch {
                asserted,
                manifest: role,
            });
        }
        Ok(role)
    }

    /// Ed25519 Commonware public key of the configured initial leader.
    pub const fn leader_ed25519_public_key(&self) -> &PublicKey {
        &self.leader_ed25519_public_key
    }

    /// Manifest-derived initial leadership record (epoch 0, active from genesis).
    pub fn bootstrap_leadership(&self) -> LeadershipState {
        LeadershipState::new(0, self.leader_ed25519_public_key.clone(), 0)
    }

    /// Optional operator-declared crashed-leader recovery directive.
    pub const fn forced_recovery(&self) -> Option<&ForcedRecoveryConfig> {
        self.forced_recovery.as_ref()
    }

    /// Role of `ed25519_public_key` under the manifest's bootstrap leader.
    pub fn bootstrap_role_of(&self, ed25519_public_key: &PublicKey) -> Role {
        role_of(
            ed25519_public_key,
            &self.leader_ed25519_public_key,
            &self.rpc_follower_keys(),
        )
    }

    /// An empty schedule carrying this manifest's static quorum membership.
    pub fn leadership_schedule(&self) -> LeadershipSchedule {
        LeadershipSchedule::for_membership(self.rpc_follower_keys())
    }

    /// All nodes in the static peer set.
    pub fn nodes(&self) -> &[ManifestNode] {
        &self.nodes
    }

    /// Nodes registered with `ZonePortal` for the on-chain settlement quorum, each with the
    /// address its settlement signatures must recover to.
    ///
    /// Filtering on the address rather than on `!rpc_only` is what lets this yield the address
    /// directly: [`Self::parse`] accepts one exactly when the other holds, so no caller has to
    /// re-discharge that invariant.
    pub fn quorum_nodes(&self) -> impl Iterator<Item = (&ManifestNode, EthereumAddress)> {
        self.nodes
            .iter()
            .filter_map(|node| Some((node, node.secp256k1_address?)))
    }

    /// Digest of the settlement-relevant membership, logged at startup.
    ///
    /// Covers each member's Ed25519 identity, quorum standing, and the address its signatures must
    /// recover to — everything two nodes must agree on to derive the same roles. Compare it across
    /// nodes to diagnose a manifest mismatch. Addresses are excluded so relocating a node does not
    /// change it. Sorted, so file order does not matter.
    pub fn membership_digest(&self) -> B256 {
        let mut members = self
            .nodes
            .iter()
            .map(|node| {
                (
                    node.ed25519_public_key.as_ref().to_vec(),
                    node.rpc_only,
                    node.secp256k1_address,
                )
            })
            .collect::<Vec<_>>();
        members.sort();

        let mut preimage = Vec::with_capacity(members.len() * 64);
        for (ed25519_public_key, rpc_only, secp256k1_address) in members {
            preimage.extend_from_slice(&ed25519_public_key);
            preimage.push(u8::from(rpc_only));
            // Distinguish "no address" from a real one rather than substituting zero.
            match secp256k1_address {
                Some(address) => {
                    preimage.push(1);
                    preimage.extend_from_slice(address.as_slice());
                }
                None => preimage.push(0),
            }
        }
        alloy_primitives::keccak256(&preimage)
    }

    /// Ed25519 keys of the members that replicate without joining the on-chain quorum.
    pub fn rpc_follower_keys(&self) -> BTreeSet<PublicKey> {
        self.nodes
            .iter()
            .filter(|node| node.rpc_only)
            .map(|node| node.ed25519_public_key.clone())
            .collect()
    }

    /// Returns whether an Ed25519 key belongs to the manifest's static peer set.
    pub fn contains_ed25519_public_key(&self, ed25519_public_key: &PublicKey) -> bool {
        self.node_by_ed25519_public_key(ed25519_public_key)
            .is_some()
    }

    /// Returns the manifest node registered with an Ed25519 public key.
    pub fn node_by_ed25519_public_key(
        &self,
        ed25519_public_key: &PublicKey,
    ) -> Option<&ManifestNode> {
        self.nodes
            .iter()
            .find(|node| node.ed25519_public_key() == ed25519_public_key)
    }

    /// Returns the quorum node registered with an individual secp256k1 address.
    pub fn node_by_secp256k1_address(
        &self,
        secp256k1_address: EthereumAddress,
    ) -> Option<&ManifestNode> {
        self.nodes
            .iter()
            .find(|node| node.secp256k1_address() == Some(secp256k1_address))
    }

    /// Resolves a finalized Portal leader address to its Ed25519 block-author identity.
    ///
    /// Unlike [`Self::node_by_secp256k1_address`], this also consults identity-only historical
    /// entries. Callers deciding current quorum membership, networking, routing, recovery, or a
    /// new leader target must continue to use the active-node lookup.
    pub fn leader_ed25519_by_secp256k1_address(
        &self,
        secp256k1_address: EthereumAddress,
    ) -> Option<&PublicKey> {
        self.node_by_secp256k1_address(secp256k1_address)
            .map(ManifestNode::ed25519_public_key)
            .or_else(|| self.historical_leaders.get(&secp256k1_address))
    }

    pub(crate) fn has_dns_addresses(&self) -> bool {
        self.nodes.iter().any(|node| node.address.is_dns())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    /// Deprecated compatibility field. Zone identity comes from the genesis chain ID.
    #[serde(default, rename = "zone_id")]
    _legacy_zone_id: Option<u32>,
    /// Deprecated compatibility field. The signer-set version comes from `ZonePortal`.
    #[serde(default, rename = "sequencer_set_version")]
    _legacy_sequencer_set_version: Option<u64>,
    leader_ed25519_public_key: String,
    #[serde(default)]
    forced_recovery: Option<RawForcedRecovery>,
    #[serde(default)]
    historical_leaders: Vec<RawHistoricalLeaderIdentity>,
    nodes: Vec<RawManifestNode>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawForcedRecovery {
    /// Manifest node name selected as the temporary runtime leader.
    leader: String,
    /// Exact canonical zone block hash shared by every restarting node.
    recovery_block_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHistoricalLeaderIdentity {
    ed25519_public_key: String,
    secp256k1_address: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifestNode {
    name: String,
    ed25519_public_key: String,
    /// Omitted exactly for `rpc_only` nodes, which never sign a settlement attestation.
    #[serde(default)]
    secp256k1_address: Option<String>,
    address: String,
    /// Serve RPC as a hot standby without joining the on-chain settlement quorum.
    #[serde(default)]
    rpc_only: bool,
}

fn parse_ed25519_public_key(field: &str, encoded: &str) -> Result<PublicKey, ManifestError> {
    let bytes =
        const_hex::decode(encoded).map_err(|source| ManifestError::InvalidEd25519PublicKey {
            field: field.to_owned(),
            reason: source.to_string(),
        })?;
    PublicKey::decode(&bytes[..]).map_err(|source| ManifestError::InvalidEd25519PublicKey {
        field: field.to_owned(),
        reason: source.to_string(),
    })
}

/// Manifest parsing and validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("failed reading sequencer manifest `{path}`")]
    Read {
        path: std::path::PathBuf,

        #[source]
        source: std::io::Error,
    },

    #[error("invalid sequencer manifest TOML")]
    Toml(#[source] toml::de::Error),

    #[error(
        "sequencer manifest must contain at least {MIN_QUORUM_NODES} quorum nodes (nodes without `rpc_only`), found {0}"
    )]
    TooFewQuorumNodes(usize),

    #[error("sequencer manifest leader `{0}` cannot be `rpc_only`")]
    RpcOnlyLeader(String),

    #[error("forced recovery leader `{0}` does not match any manifest node name")]
    ForcedRecoveryLeaderNotFound(String),

    #[error("forced recovery leader `{0}` cannot be `rpc_only`")]
    RpcOnlyForcedRecoveryLeader(String),

    #[error("historical leader identity cannot alias `rpc_only` manifest node `{0}`")]
    RpcOnlyHistoricalLeader(String),

    #[error("invalid forced recovery block hash `{hash}`: {reason}")]
    InvalidRecoveryBlockHash { hash: String, reason: String },

    #[error("sequencer manifest node `{0}` must declare a secp256k1_address")]
    MissingSecp256k1Address(String),

    #[error(
        "`rpc_only` sequencer manifest node `{0}` must not declare a secp256k1_address: it never signs a settlement attestation, and registering the address with `ZonePortal` would add a signer the zone never collects a signature from"
    )]
    RpcOnlySecp256k1Address(String),

    #[error("sequencer manifest node names must not be empty")]
    EmptyNodeName,

    #[error("duplicate sequencer manifest node name `{0}`")]
    DuplicateNodeName(String),

    #[error("duplicate sequencer manifest Ed25519 public key `{0}`")]
    DuplicateEd25519PublicKey(String),

    #[error("duplicate sequencer manifest secp256k1 address `{0}`")]
    DuplicateSecp256k1Address(EthereumAddress),

    #[error("invalid Ed25519 public key in `{field}`: {reason}")]
    InvalidEd25519PublicKey { field: String, reason: String },

    #[error("invalid secp256k1 address `{address}` for node `{node}`: {reason}")]
    InvalidSecp256k1Address {
        node: String,
        address: String,
        reason: String,
    },

    #[error("invalid historical leader secp256k1 address `{address}`: {reason}")]
    InvalidHistoricalLeaderSecp256k1Address { address: String, reason: String },

    #[error("invalid address `{address}` for node `{node}`: {reason}")]
    InvalidAddress {
        node: String,
        address: String,
        reason: String,
    },

    #[error("manifest leader Ed25519 public key `{0}` does not match any node")]
    LeaderEd25519PublicKeyNotFound(String),

    #[error("this node's Ed25519 public key `{0}` is not present in the sequencer manifest")]
    LocalNodeNotFound(String),

    #[error(
        "this node's secp256k1 address `{local}` does not match its manifest address `{manifest}`"
    )]
    LocalSecp256k1AddressMismatch {
        manifest: EthereumAddress,
        local: EthereumAddress,
    },

    #[error(
        "manifest node `{0}` is a quorum member, so --secp256k1.key is required to sign settlement attestations"
    )]
    LocalSecp256k1KeyMissing(String),

    #[error(
        "manifest node `{0}` is `rpc_only`, so --secp256k1.key must not be provided: the key would never be used and must not be registered with `ZonePortal`"
    )]
    LocalSecp256k1KeyUnexpected(String),

    #[error("--sequencer.role asserts `{asserted}`, but the manifest assigns `{manifest}`")]
    RoleMismatch { asserted: Role, manifest: Role },
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256};
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    use super::{
        LeadershipSchedule, LeadershipState, MIN_QUORUM_NODES, ManifestError, Role, ZoneManifest,
    };

    fn public_key(seed: u64) -> commonware_cryptography::ed25519::PublicKey {
        PrivateKey::from_seed(seed).public_key()
    }

    fn recovery_block_hash() -> B256 {
        B256::repeat_byte(0x11)
    }

    #[test]
    fn uninitialized_schedule_stays_fenced() {
        let schedule = LeadershipSchedule::uninitialized();
        assert!(!schedule.is_initialized());
        assert_eq!(schedule.leader_for(0), None);
        assert_eq!(schedule.leader_for(u64::MAX), None);
        assert_eq!(schedule.latest(), None);
        assert_eq!(schedule.latest_observed_epoch(), None);
        assert_eq!(schedule.locally_applied_epoch(), None);
    }

    #[test]
    fn schedule_retains_skipped_intermediate_transitions() {
        // A -> B at anchor 100 and B -> C at anchor 200 both observed while the engine is
        // still before 100. leader_for over the retained timeline must name B for the
        // in-between anchors, and A below the first boundary it retains.
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(1, public_key(1), 0));
        assert!(
            schedule
                .publish(LeadershipState::new(2, public_key(2), 100))
                .unwrap()
        );
        assert!(
            schedule
                .publish(LeadershipState::new(3, public_key(3), 200))
                .unwrap()
        );

        assert_eq!(schedule.leader_for(99).unwrap().leader, public_key(1));
        assert_eq!(schedule.leader_for(100).unwrap().leader, public_key(2));
        assert_eq!(schedule.leader_for(199).unwrap().leader, public_key(2));
        assert_eq!(schedule.leader_for(200).unwrap().leader, public_key(3));
        assert_eq!(schedule.leader_for(u64::MAX).unwrap().leader, public_key(3));
        assert_eq!(schedule.latest_observed_epoch(), Some(3));
        assert_eq!(schedule.pending_transitions(), 2);
    }

    #[test]
    fn forced_recovery_is_optimistic_until_next_transition_bounds_it() {
        let outgoing = public_key(1);
        let incoming = public_key(2);
        let portal_leader = public_key(3);
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(7, outgoing.clone(), 0));
        schedule.record_applied_anchor(50);

        assert!(
            schedule
                .install_forced_recovery(8, incoming.clone(), recovery_block_hash(), 51)
                .unwrap()
        );
        assert_eq!(schedule.leader_for(50).unwrap().leader, outgoing);
        assert_eq!(schedule.leader_for(51).unwrap().leader, incoming);
        assert_eq!(schedule.leader_for(u64::MAX).unwrap().leader, incoming);
        assert!(!schedule.forced_recovery().unwrap().is_bounded());

        schedule
            .publish(LeadershipState::new(8, portal_leader.clone(), 60))
            .unwrap();
        assert!(schedule.forced_recovery().unwrap().is_bounded());
        assert_eq!(schedule.leader_for(50).unwrap().leader, outgoing);
        assert_eq!(schedule.leader_for(51).unwrap().leader, incoming);
        assert_eq!(schedule.leader_for(59).unwrap().leader, incoming);
        assert_eq!(
            schedule.leader_for(60).unwrap().leader,
            portal_leader,
            "ordinary portal authority must take over at the activation boundary"
        );
        schedule
            .publish(LeadershipState::new(9, public_key(4), 70))
            .unwrap();
        assert_eq!(schedule.leader_for(69).unwrap().leader, public_key(3));
        assert_eq!(schedule.leader_for(70).unwrap().leader, public_key(4));
    }

    #[test]
    fn forced_recovery_atomically_reconciles_a_transition_published_first() {
        let incoming = public_key(2);
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(7, public_key(1), 0));
        schedule
            .publish(LeadershipState::new(8, incoming.clone(), 60))
            .unwrap();

        schedule
            .install_forced_recovery(8, incoming.clone(), recovery_block_hash(), 51)
            .unwrap();

        assert!(schedule.forced_recovery().unwrap().is_bounded());
        assert_eq!(schedule.leader_for(51).unwrap().leader, incoming);
    }

    #[test]
    fn forced_recovery_respects_a_different_transition_published_first() {
        let incoming = public_key(2);
        let portal_leader = public_key(3);
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(7, public_key(1), 0));
        schedule
            .publish(LeadershipState::new(8, portal_leader.clone(), 60))
            .unwrap();

        schedule
            .install_forced_recovery(8, incoming.clone(), recovery_block_hash(), 51)
            .unwrap();

        assert!(schedule.forced_recovery().unwrap().is_bounded());
        assert_eq!(schedule.leader_for(51).unwrap().leader, incoming);
        assert_eq!(schedule.leader_for(59).unwrap().leader, public_key(2));
        assert_eq!(schedule.leader_for(60).unwrap().leader, portal_leader);
    }

    #[test]
    fn forced_recovery_respects_a_different_transition_published_later() {
        let incoming = public_key(2);
        let portal_leader = public_key(3);
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(7, public_key(1), 0));
        schedule
            .install_forced_recovery(8, incoming.clone(), recovery_block_hash(), 51)
            .unwrap();

        schedule
            .publish(LeadershipState::new(8, portal_leader.clone(), 60))
            .unwrap();
        let recovery = schedule.forced_recovery().unwrap();
        assert!(recovery.is_bounded());
        assert_eq!(schedule.leader_for(51).unwrap().leader, incoming);
        assert_eq!(schedule.leader_for(59).unwrap().leader, public_key(2));
        assert_eq!(schedule.leader_for(60).unwrap().leader, portal_leader);
    }

    #[test]
    fn forced_recovery_clears_after_portal_activation_is_applied() {
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(7, public_key(1), 0));
        schedule.record_applied_anchor(50);
        schedule
            .install_forced_recovery(8, public_key(2), recovery_block_hash(), 51)
            .unwrap();
        schedule
            .publish(LeadershipState::new(8, public_key(2), 60))
            .unwrap();

        schedule.record_applied_anchor(59);
        assert!(schedule.forced_recovery().is_some());
        schedule.record_applied_anchor(60);
        assert!(schedule.forced_recovery().is_none());
    }

    #[test]
    fn forced_recovery_leader_is_scheduled_until_recovery_completes() {
        let recovery_leader = public_key(2);
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(7, public_key(1), 0));
        schedule.record_applied_anchor(50);

        assert!(!schedule.is_scheduled_leader(&recovery_leader));
        schedule
            .install_forced_recovery(8, recovery_leader.clone(), recovery_block_hash(), 51)
            .unwrap();
        assert!(schedule.is_scheduled_leader(&recovery_leader));

        schedule
            .publish(LeadershipState::new(8, public_key(3), 60))
            .unwrap();
        assert!(schedule.is_scheduled_leader(&recovery_leader));

        schedule.record_applied_anchor(60);
        assert!(!schedule.is_scheduled_leader(&recovery_leader));
    }

    #[test]
    fn empty_recovery_window_is_bounded_by_portal_transition() {
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(7, public_key(1), 0));
        schedule
            .install_forced_recovery(8, public_key(2), recovery_block_hash(), 60)
            .unwrap();
        schedule
            .publish(LeadershipState::new(8, public_key(3), 60))
            .unwrap();

        assert!(schedule.forced_recovery().unwrap().is_bounded());
        assert_eq!(schedule.leader_for(60).unwrap().leader, public_key(3));
    }

    #[test]
    fn forced_recovery_directive_is_idempotent_and_rejects_conflict() {
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(7, public_key(1), 0));
        assert!(
            schedule
                .install_forced_recovery(8, public_key(2), recovery_block_hash(), 51)
                .unwrap()
        );
        assert!(
            !schedule
                .install_forced_recovery(8, public_key(2), recovery_block_hash(), 51)
                .unwrap()
        );
        assert!(
            schedule
                .install_forced_recovery(8, public_key(3), recovery_block_hash(), 51)
                .is_err()
        );
    }

    #[test]
    fn publish_is_idempotent_and_rejects_conflicts() {
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(1, public_key(1), 0));
        let transition = LeadershipState::new(2, public_key(2), 100);
        assert!(schedule.publish(transition.clone()).unwrap());
        // Subscriber replay of the same finalized block re-observes the same event.
        assert!(!schedule.publish(transition).unwrap());

        // A different leader at an observed activation is corrupt.
        assert!(
            schedule
                .publish(LeadershipState::new(2, public_key(3), 100))
                .is_err()
        );
        // Skipped epochs cannot be published: replay is contiguous.
        assert!(
            schedule
                .publish(LeadershipState::new(4, public_key(3), 200))
                .is_err()
        );
        // Activation boundaries are strictly increasing.
        assert!(
            schedule
                .publish(LeadershipState::new(3, public_key(3), 50))
                .is_err()
        );
    }

    #[test]
    fn prunes_only_past_the_applied_boundary() {
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(1, public_key(1), 0));
        schedule
            .publish(LeadershipState::new(2, public_key(2), 100))
            .unwrap();
        schedule
            .publish(LeadershipState::new(3, public_key(3), 200))
            .unwrap();

        // Applying anchors below the first boundary keeps every transition queryable.
        schedule.record_applied_anchor(98);
        assert_eq!(schedule.leader_for(99).unwrap().leader, public_key(1));
        assert_eq!(schedule.locally_applied_epoch(), Some(1));

        // Applying 99 makes the next anchor 100. Epoch 1 has served its last anchor, but it
        // is retained as the active entry's predecessor for the promotion-mode decision.
        schedule.record_applied_anchor(99);
        assert_eq!(schedule.leader_for(99).unwrap().leader, public_key(1));
        assert_eq!(schedule.leader_for(100).unwrap().leader, public_key(2));
        assert_eq!(schedule.leader_for(199).unwrap().leader, public_key(2));

        // The applied cursor never moves backwards.
        schedule.record_applied_anchor(50);
        assert_eq!(schedule.leader_for(100).unwrap().leader, public_key(2));

        schedule.record_applied_anchor(250);
        // Epoch 3 is active for anchor 251; epoch 2 is its retained predecessor; epoch 1 is
        // finally pruned.
        assert_eq!(schedule.leader_for(99), None);
        assert_eq!(schedule.leader_for(199).unwrap().leader, public_key(2));
        assert_eq!(schedule.leader_for(251).unwrap().leader, public_key(3));
        assert_eq!(schedule.locally_applied_epoch(), Some(3));
        assert_eq!(schedule.pending_transitions(), 0);
        // The active entry is always retained.
        assert!(schedule.latest().is_some());
    }

    #[test]
    fn first_record_governs_from_genesis() {
        // The creation transition activates at the portal creation block, but the zone's
        // first blocks embed earlier anchors (zone genesis anchors before createZone). The
        // earliest known authority governs them.
        let schedule = LeadershipSchedule::uninitialized();
        assert!(
            schedule
                .publish(LeadershipState::new(1, public_key(1), 500))
                .unwrap()
        );
        assert_eq!(schedule.leader_for(1).unwrap().leader, public_key(1));
        assert_eq!(schedule.leader_for(499).unwrap().leader, public_key(1));

        // Re-observing the same initial record at its true activation is idempotent.
        assert!(
            !schedule
                .publish(LeadershipState::new(1, public_key(1), 500))
                .unwrap()
        );
        // A different leader with the same epoch is still corrupt.
        assert!(
            schedule
                .publish(LeadershipState::new(1, public_key(2), 500))
                .is_err()
        );

        // Later transitions activate exactly at their boundary.
        schedule
            .publish(LeadershipState::new(2, public_key(2), 700))
            .unwrap();
        assert_eq!(schedule.leader_for(699).unwrap().leader, public_key(1));
        assert_eq!(schedule.leader_for(700).unwrap().leader, public_key(2));
    }

    #[test]
    fn schedule_watch_announces_effective_changes() {
        let schedule = LeadershipSchedule::uninitialized();
        let mut watcher = schedule.subscribe();
        assert!(!watcher.has_changed().unwrap());
        schedule
            .publish(LeadershipState::new(1, public_key(1), 0))
            .unwrap();
        assert!(watcher.has_changed().unwrap());
        watcher.borrow_and_update();

        // Seed the applied cursor while only epoch 1 is known.
        schedule.record_applied_anchor(98);
        assert!(!watcher.has_changed().unwrap());

        schedule
            .publish(LeadershipState::new(2, public_key(2), 100))
            .unwrap();
        assert!(watcher.has_changed().unwrap());
        watcher.borrow_and_update();

        // Advancing within one leadership record (or backwards) is silent.
        schedule.record_applied_anchor(98);
        assert!(!watcher.has_changed().unwrap());
        schedule.record_applied_anchor(50);
        assert!(!watcher.has_changed().unwrap());

        // Applying anchor 99 moves the next anchor to epoch 2's activation boundary.
        schedule.record_applied_anchor(99);
        assert!(watcher.has_changed().unwrap());
        watcher.borrow_and_update();

        schedule.record_applied_anchor(150);
        assert!(!watcher.has_changed().unwrap());
    }

    fn ed25519_public_key(seed: u64) -> String {
        let key = PrivateKey::from_seed(seed).public_key();
        const_hex::encode_prefixed(key.as_ref())
    }

    fn secp256k1_address(seed: u64) -> String {
        format!("0x{seed:040x}")
    }

    fn manifest(leader: u64, nodes: &[(u64, &str, &str)]) -> String {
        let quorum = nodes
            .iter()
            .map(|(key, name, address)| (*key, *name, *address, false))
            .collect::<Vec<_>>();
        manifest_with_rpc_only(leader, &quorum)
    }

    fn with_forced_recovery(manifest: &str, leader: &str, recovery_block_hash: &str) -> String {
        manifest.replacen(
            "\n[[nodes]]",
            &format!(
                "\n[forced_recovery]\nleader = \"{leader}\"\nrecovery_block_hash = \
                 \"{recovery_block_hash}\"\n\n[[nodes]]"
            ),
            1,
        )
    }

    fn with_historical_leader(manifest: &str, secp256k1_seed: u64, ed25519_seed: u64) -> String {
        format!(
            "{manifest}\n[[historical_leaders]]\ned25519_public_key = \"{}\"\nsecp256k1_address = \"{}\"\n",
            ed25519_public_key(ed25519_seed),
            secp256k1_address(secp256k1_seed),
        )
    }

    /// Builds a manifest where the fourth tuple element marks a node `rpc_only`. An `rpc_only`
    /// node declares no `secp256k1_address`, exactly as the loader requires.
    fn manifest_with_rpc_only(leader: u64, nodes: &[(u64, &str, &str, bool)]) -> String {
        let mut value = format!(
            "leader_ed25519_public_key = \"{}\"\n",
            ed25519_public_key(leader)
        );
        for (key, name, address, rpc_only) in nodes {
            value.push_str(&format!(
                "\n[[nodes]]\nname = \"{name}\"\ned25519_public_key = \"{}\"\naddress = \"{address}\"\nrpc_only = {rpc_only}\n",
                ed25519_public_key(*key),
            ));
            if !rpc_only {
                value.push_str(&format!(
                    "secp256k1_address = \"{}\"\n",
                    secp256k1_address(*key)
                ));
            }
        }
        value
    }

    #[test]
    fn parses_and_derives_roles() {
        let input = manifest(
            1,
            &[
                (1, "leader", "127.0.0.1:9200"),
                (2, "follower-a", "follower-a.zone.local:9200"),
                (3, "follower-b", "127.0.0.1:9202"),
            ],
        );
        let manifest = ZoneManifest::parse(&input).unwrap();
        let leader = PrivateKey::from_seed(1).public_key();
        let follower = PrivateKey::from_seed(2).public_key();
        let leadership = manifest.bootstrap_leadership();

        assert_eq!(leadership.epoch(), 0);
        assert_eq!(leadership.activation_tempo_block(), 0);
        let schedule = manifest.leadership_schedule();
        schedule.publish(leadership).unwrap();
        assert_eq!(schedule.role_for(&leader, 0), Some(Role::Leader));
        assert_eq!(schedule.role_for(&follower, 0), Some(Role::Follower));
        assert_eq!(manifest.bootstrap_role_of(&leader), Role::Leader);
        assert_eq!(manifest.bootstrap_role_of(&follower), Role::Follower);

        assert_eq!(
            schedule.leader_for(0).map(|record| record.leader),
            Some(leader.clone())
        );
        assert_eq!(
            schedule.leader_for(u64::MAX).map(|record| record.leader),
            Some(leader.clone())
        );
        assert_eq!(
            manifest
                .validate_node(&leader, Some(secp256k1_address(1).parse().unwrap()), None)
                .unwrap(),
            Role::Leader
        );
        assert_eq!(
            manifest
                .validate_node(
                    &follower,
                    Some(secp256k1_address(2).parse().unwrap()),
                    Some(Role::Follower),
                )
                .unwrap(),
            Role::Follower
        );
    }

    #[test]
    fn resolves_historical_leader_without_adding_an_active_node() {
        let base = manifest(
            1,
            &[
                (1, "leader", "127.0.0.1:9200"),
                (2, "follower-a", "127.0.0.1:9201"),
                (3, "follower-b", "127.0.0.1:9202"),
            ],
        );
        let baseline_digest = ZoneManifest::parse(&base).unwrap().membership_digest();
        let manifest = ZoneManifest::parse(&with_historical_leader(&base, 9, 8)).unwrap();
        let historical_address = secp256k1_address(9).parse().unwrap();

        assert_eq!(manifest.nodes().len(), 3);
        assert_eq!(manifest.quorum_nodes().count(), 3);
        assert_eq!(manifest.membership_digest(), baseline_digest);
        assert!(
            manifest
                .node_by_secp256k1_address(historical_address)
                .is_none(),
            "historical identity must not become an active quorum or network node"
        );
        assert_eq!(
            manifest.leader_ed25519_by_secp256k1_address(historical_address),
            Some(&public_key(8))
        );
        assert_eq!(
            manifest.leader_ed25519_by_secp256k1_address(secp256k1_address(2).parse().unwrap()),
            Some(&public_key(2)),
            "the leadership resolver must still resolve active nodes"
        );
    }

    #[test]
    fn rejects_ambiguous_historical_leader_addresses() {
        let base = manifest(
            1,
            &[
                (1, "leader", "127.0.0.1:9200"),
                (2, "follower-a", "127.0.0.1:9201"),
                (3, "follower-b", "127.0.0.1:9202"),
            ],
        );

        let duplicates_active = with_historical_leader(&base, 1, 8);
        assert!(matches!(
            ZoneManifest::parse(&duplicates_active),
            Err(ManifestError::DuplicateSecp256k1Address(address))
                if address == secp256k1_address(1).parse::<Address>().unwrap()
        ));

        let duplicates_history = with_historical_leader(&with_historical_leader(&base, 9, 8), 9, 7);
        assert!(matches!(
            ZoneManifest::parse(&duplicates_history),
            Err(ManifestError::DuplicateSecp256k1Address(address))
                if address == secp256k1_address(9).parse::<Address>().unwrap()
        ));
    }

    #[test]
    fn rejects_historical_leader_aliasing_rpc_only_node() {
        let base = manifest_with_rpc_only(
            1,
            &[
                (1, "leader", "127.0.0.1:9200", false),
                (2, "follower-a", "127.0.0.1:9201", false),
                (3, "follower-b", "127.0.0.1:9202", false),
                (4, "operator-rpc", "127.0.0.1:9203", true),
            ],
        );
        let aliased = with_historical_leader(&base, 9, 4);

        assert!(matches!(
            ZoneManifest::parse(&aliased),
            Err(ManifestError::RpcOnlyHistoricalLeader(node)) if node == "operator-rpc"
        ));
    }

    #[test]
    fn accepts_ignored_legacy_identity_fields() {
        let input = format!(
            "zone_id = 7\nsequencer_set_version = 42\n{}",
            manifest(
                1,
                &[
                    (1, "leader", "127.0.0.1:9200"),
                    (2, "follower-a", "127.0.0.1:9201"),
                    (3, "follower-b", "127.0.0.1:9202"),
                ],
            )
        );

        let manifest = ZoneManifest::parse(&input).unwrap();

        assert_eq!(manifest.bootstrap_role_of(&public_key(1)), Role::Leader);
    }

    #[test]
    fn parses_forced_recovery_directive() {
        let input = with_forced_recovery(
            &manifest(
                1,
                &[
                    (1, "leader", "127.0.0.1:9200"),
                    (2, "follower-a", "127.0.0.1:9201"),
                    (3, "follower-b", "127.0.0.1:9202"),
                ],
            ),
            "follower-a",
            &recovery_block_hash().to_string(),
        );
        let manifest = ZoneManifest::parse(&input).unwrap();
        let recovery = manifest.forced_recovery().unwrap();

        assert_eq!(recovery.leader(), &public_key(2));
        assert_eq!(recovery.recovery_block_hash(), recovery_block_hash());
    }

    #[test]
    fn forced_recovery_leader_must_be_a_quorum_manifest_node() {
        let base = manifest_with_rpc_only(
            1,
            &[
                (1, "leader", "127.0.0.1:9200", false),
                (2, "follower-a", "127.0.0.1:9201", false),
                (3, "follower-b", "127.0.0.1:9202", false),
                (4, "public-rpc", "127.0.0.1:9203", true),
            ],
        );
        let unknown = with_forced_recovery(&base, "missing", &recovery_block_hash().to_string());
        assert!(matches!(
            ZoneManifest::parse(&unknown),
            Err(ManifestError::ForcedRecoveryLeaderNotFound(name)) if name == "missing"
        ));

        let rpc_only =
            with_forced_recovery(&base, "public-rpc", &recovery_block_hash().to_string());
        assert!(matches!(
            ZoneManifest::parse(&rpc_only),
            Err(ManifestError::RpcOnlyForcedRecoveryLeader(name)) if name == "public-rpc"
        ));
    }

    #[test]
    fn readme_manifest_example_has_expected_shape() {
        let (_, after_fence) = include_str!("../README.md")
            .split_once("```toml\n")
            .expect("README contains a TOML manifest example");
        let (example, _) = after_fence
            .split_once("\n```")
            .expect("README closes the TOML manifest example");

        // The example uses placeholder keys, so only its shape can be checked.
        let manifest: super::RawManifest = toml::from_str(example).unwrap();
        assert_eq!(manifest.nodes.len(), 4);
        assert_eq!(manifest.historical_leaders.len(), 1);
        assert_eq!(
            manifest.nodes.iter().filter(|node| !node.rpc_only).count(),
            MIN_QUORUM_NODES
        );
        // An `rpc_only` entry carries no individual key.
        assert!(
            manifest
                .nodes
                .iter()
                .all(|node| node.rpc_only != node.secp256k1_address.is_some())
        );
    }

    #[test]
    fn rpc_only_nodes_replicate_without_joining_the_quorum() {
        let input = manifest_with_rpc_only(
            1,
            &[
                (1, "leader", "127.0.0.1:9200", false),
                (2, "follower-a", "127.0.0.1:9201", false),
                (3, "follower-b", "127.0.0.1:9202", false),
                (4, "operator-rpc", "127.0.0.1:9203", true),
            ],
        );
        let manifest = ZoneManifest::parse(&input).unwrap();
        let leader = public_key(1);
        let follower = public_key(2);
        let rpc_follower = public_key(4);

        assert_eq!(manifest.bootstrap_role_of(&leader), Role::Leader);
        assert_eq!(manifest.bootstrap_role_of(&follower), Role::Follower);
        assert_eq!(manifest.bootstrap_role_of(&rpc_follower), Role::RpcFollower);

        // The standby replicates, but the on-chain quorum is unchanged by its presence, and it
        // carries no address that could be registered with `ZonePortal`.
        assert_eq!(manifest.nodes().len(), 4);
        assert_eq!(manifest.quorum_nodes().count(), MIN_QUORUM_NODES);
        assert!(
            manifest
                .quorum_nodes()
                .all(|(node, _)| node.ed25519_public_key() != &rpc_follower)
        );
        let standby = manifest
            .node_by_ed25519_public_key(&rpc_follower)
            .expect("the standby is a manifest member");
        assert!(standby.is_rpc_only());
        assert_eq!(standby.secp256k1_address(), None);

        // The schedule carries the membership, so classification survives a leader rotation.
        let schedule = manifest.leadership_schedule();
        assert!(schedule.is_rpc_only(&rpc_follower));
        assert!(!schedule.is_quorum_member(&rpc_follower));
        assert!(schedule.is_quorum_member(&follower));
        assert_eq!(
            schedule.quorum_peers(&[leader.clone(), follower.clone(), rpc_follower.clone()]),
            vec![leader, follower.clone()]
        );
        schedule
            .publish(LeadershipState::new(1, follower.clone(), 0))
            .unwrap();
        assert_eq!(schedule.role_for(&follower, 0), Some(Role::Leader));
        assert_eq!(schedule.role_for(&rpc_follower, 0), Some(Role::RpcFollower));

        // Its role assertion must name the standby role, not `follower`.
        assert_eq!(
            manifest
                .validate_node(&rpc_follower, None, Some(Role::RpcFollower))
                .unwrap(),
            Role::RpcFollower
        );
        assert!(matches!(
            manifest.validate_node(&rpc_follower, None, Some(Role::Follower)),
            Err(ManifestError::RoleMismatch { .. })
        ));
    }

    #[test]
    fn rejects_topologies_that_would_shrink_or_miskey_the_quorum() {
        // Four nodes, but only two of them can sign a settlement.
        let thin_quorum = manifest_with_rpc_only(
            1,
            &[
                (1, "leader", "127.0.0.1:9200", false),
                (2, "follower", "127.0.0.1:9201", false),
                (3, "operator-rpc-a", "127.0.0.1:9202", true),
                (4, "operator-rpc-b", "127.0.0.1:9203", true),
            ],
        );
        assert!(matches!(
            ZoneManifest::parse(&thin_quorum),
            Err(ManifestError::TooFewQuorumNodes(2))
        ));

        // A leader cannot opt out of the quorum it settles for.
        let rpc_only_leader = manifest_with_rpc_only(
            1,
            &[
                (1, "leader", "127.0.0.1:9200", true),
                (2, "follower-a", "127.0.0.1:9201", false),
                (3, "follower-b", "127.0.0.1:9202", false),
            ],
        );
        assert!(matches!(
            ZoneManifest::parse(&rpc_only_leader),
            Err(ManifestError::RpcOnlyLeader(_))
        ));

        let quorum_nodes = [
            (1, "leader", "127.0.0.1:9200", false),
            (2, "follower-a", "127.0.0.1:9201", false),
            (3, "follower-b", "127.0.0.1:9202", false),
        ];

        // A quorum node without an individual address could never settle.
        let missing_address = manifest_with_rpc_only(1, &quorum_nodes).replace(
            &format!("secp256k1_address = \"{}\"\n", secp256k1_address(3)),
            "",
        );
        assert!(matches!(
            ZoneManifest::parse(&missing_address),
            Err(ManifestError::MissingSecp256k1Address(node)) if node == "follower-b"
        ));

        // An address on a standby is at best dead weight and at worst a registered signer the
        // zone never collects a signature from.
        let mut standby_with_address = manifest_with_rpc_only(
            1,
            &[
                (1, "leader", "127.0.0.1:9200", false),
                (2, "follower-a", "127.0.0.1:9201", false),
                (3, "follower-b", "127.0.0.1:9202", false),
                (4, "operator-rpc", "127.0.0.1:9203", true),
            ],
        );
        standby_with_address.push_str(&format!(
            "secp256k1_address = \"{}\"\n",
            secp256k1_address(4)
        ));
        assert!(matches!(
            ZoneManifest::parse(&standby_with_address),
            Err(ManifestError::RpcOnlySecp256k1Address(node)) if node == "operator-rpc"
        ));
    }

    #[test]
    fn membership_digest_tracks_quorum_standing_not_addresses_or_order() {
        let nodes = [
            (1, "leader", "127.0.0.1:9200", false),
            (2, "follower-a", "127.0.0.1:9201", false),
            (3, "follower-b", "127.0.0.1:9202", false),
            (4, "operator-rpc", "127.0.0.1:9203", true),
        ];
        let baseline = ZoneManifest::parse(&manifest_with_rpc_only(1, &nodes))
            .unwrap()
            .membership_digest();

        // File order is not part of the identity.
        let mut reordered = nodes;
        reordered.swap(0, 3);
        assert_eq!(
            ZoneManifest::parse(&manifest_with_rpc_only(1, &reordered))
                .unwrap()
                .membership_digest(),
            baseline
        );

        // Addresses are excluded.
        let moved = [
            (1, "leader", "127.0.0.1:9200", false),
            (2, "follower-a", "follower-a.zone.local:9300", false),
            (3, "follower-b", "127.0.0.1:9202", false),
            (4, "operator-rpc", "127.0.0.1:9203", true),
        ];
        assert_eq!(
            ZoneManifest::parse(&manifest_with_rpc_only(1, &moved))
                .unwrap()
                .membership_digest(),
            baseline
        );

        // Quorum standing changes it.
        let promoted = [
            (1, "leader", "127.0.0.1:9200", false),
            (2, "follower-a", "127.0.0.1:9201", false),
            (3, "follower-b", "127.0.0.1:9202", false),
            (4, "operator-rpc", "127.0.0.1:9203", false),
        ];
        assert_ne!(
            ZoneManifest::parse(&manifest_with_rpc_only(1, &promoted))
                .unwrap()
                .membership_digest(),
            baseline
        );

        // So does the address a member's signatures must recover to.
        let rekeyed = manifest_with_rpc_only(1, &nodes).replace(
            &format!("secp256k1_address = \"{}\"", secp256k1_address(3)),
            &format!("secp256k1_address = \"{}\"", secp256k1_address(9)),
        );
        assert_ne!(
            ZoneManifest::parse(&rekeyed).unwrap().membership_digest(),
            baseline
        );
    }

    #[test]
    fn role_round_trips_through_its_cli_and_manifest_spelling() {
        for role in [Role::Leader, Role::Follower, Role::RpcFollower] {
            assert_eq!(role.to_string().parse::<Role>().unwrap(), role);
        }
        assert_eq!("rpc-follower".parse::<Role>().unwrap(), Role::RpcFollower);
        assert!("rpc_follower".parse::<Role>().is_err());
    }

    #[test]
    fn local_key_presence_must_match_the_manifest_entry() {
        let manifest = ZoneManifest::parse(&manifest_with_rpc_only(
            1,
            &[
                (1, "leader", "127.0.0.1:9200", false),
                (2, "follower-a", "127.0.0.1:9201", false),
                (3, "follower-b", "127.0.0.1:9202", false),
                (4, "operator-rpc", "127.0.0.1:9203", true),
            ],
        ))
        .unwrap();

        // A quorum member started without --secp256k1.key cannot sign.
        assert!(matches!(
            manifest.validate_node(&public_key(2), None, None),
            Err(ManifestError::LocalSecp256k1KeyMissing(node)) if node == "follower-a"
        ));
        // A standby started with one holds key material it must not have.
        assert!(matches!(
            manifest.validate_node(
                &public_key(4),
                Some(secp256k1_address(4).parse().unwrap()),
                None
            ),
            Err(ManifestError::LocalSecp256k1KeyUnexpected(node)) if node == "operator-rpc"
        ));
    }

    #[test]
    fn rejects_invalid_topologies_and_node_assertions() {
        let too_small = manifest(
            1,
            &[
                (1, "leader", "127.0.0.1:9200"),
                (2, "follower", "127.0.0.1:9201"),
            ],
        );
        assert!(matches!(
            ZoneManifest::parse(&too_small),
            Err(ManifestError::TooFewQuorumNodes(2))
        ));

        let duplicate = manifest(
            1,
            &[
                (1, "leader", "127.0.0.1:9200"),
                (2, "follower", "127.0.0.1:9201"),
                (2, "follower-2", "127.0.0.1:9202"),
            ],
        );
        assert!(matches!(
            ZoneManifest::parse(&duplicate),
            Err(ManifestError::DuplicateEd25519PublicKey(_))
        ));

        let valid = ZoneManifest::parse(&manifest(
            1,
            &[
                (1, "leader", "127.0.0.1:9200"),
                (2, "follower-a", "127.0.0.1:9201"),
                (3, "follower-b", "127.0.0.1:9202"),
            ],
        ))
        .unwrap();
        let follower = PrivateKey::from_seed(2).public_key();
        assert!(matches!(
            valid.validate_node(
                &follower,
                Some(secp256k1_address(2).parse().unwrap()),
                Some(Role::Leader),
            ),
            Err(ManifestError::RoleMismatch { .. })
        ));
        let unknown = PrivateKey::from_seed(99).public_key();
        assert!(matches!(
            valid.validate_node(&unknown, Some(secp256k1_address(99).parse().unwrap()), None,),
            Err(ManifestError::LocalNodeNotFound(_))
        ));

        assert!(matches!(
            valid.validate_node(&follower, Some(secp256k1_address(3).parse().unwrap()), None,),
            Err(ManifestError::LocalSecp256k1AddressMismatch { .. })
        ));
    }
}
