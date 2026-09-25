# DKG configuration and recovery

TIP-1123 is implemented behind the unscheduled `Tip1123` hardfork. Custom genesis
files may set `config.tip1123Time`; existing network schedules do not activate it.
`cargo xtask generate-genesis --tip1123-time <timestamp>` generates the matching
genesis artifact, including the compact format when active at genesis.

For epoch E, the preceding finalized boundary B(E-1) selects both the artifact
format and configuration rules by its timestamp. Activation during an epoch does
not change that epoch's ceremony. The first ceremony using the new rules begins
after an activated boundary, or at genesis if the fork is already active there.

After activation, epoch initialization requires the execution post-state of
B(E-1), including all boundary transactions and system calls. Genesis is the
trusted boundary for epoch zero. Players and the network-identity rotation
schedule are read at that exact block hash and persisted with the DKG state.
The ceremony is full exactly when that schedule equals E, including schedule zero
at genesis; any other value selects resharing.
When consensus finality arrives before execution catches up, the node waits for
execution to finalize that boundary before attempting the configuration reads.
Later validator changes do not affect an initialized ceremony; a restart with
intact, current DKG state reuses its configuration.

Peer discovery and `tempo consensus info` still need the current epoch's starting
boundary post-state to resolve its players, even when the DKG journal is intact.
Retain that snapshot until the epoch is no longer current.

When pruning or preparing recovery snapshots, retain:

- The boundary header and its execution post-state B(E-1) for every epoch E that
  the node may need to initialize without persisted DKG state.
- To recover a share from revealed dealings in epoch E-1, the post-state of its
  starting boundary B(E-2), its boundary header, and the finalized dealer-log
  headers from E-1. For recovery from epoch zero, use genesis instead of B(E-2).
- The normal trusted network identity and consensus finalization data needed to
  authenticate startup. Configuration snapshots do not replace that trust anchor.

Pre-activation ceremonies obtain their configuration from the legacy boundary
artifact and do not require these historical execution snapshots. Failed
ceremonies can carry older outputs forward; recovery does not search an unbounded
number of previous epochs for a share.

The consensus journal's retention policy does not retain execution state. Ensure
execution pruning and snapshot retention preserve these boundary states before
removing DKG metadata or rebuilding a node. An archive containing only headers and
dealer logs is insufficient for post-activation share reconstruction.

An invalid artifact is reported as an invalid on-chain DKG outcome. Unavailable
configuration is reported separately with the epoch, boundary height, and block
hash, and prevents initialization instead of selecting resharing by default.
Restore the required execution post-state before retrying initialization.

`tempo consensus info` lists current dealers, players selected at the starting
boundary, and validators currently active for the following epoch. The
`is_next_dkg_player` field identifies the last set; each entry includes its current
ingress and egress addresses for firewall allowlists. These prospective players
may change again before the next boundary is finalized.
