# Zone test environment

A multi-sequencer zone in Docker Compose, for fault-injection testing of the L1 and zone nodes built with
`--features fuzz` (Antithesis SDK assertions enabled). `docker-compose.yaml` describes the topology.
This guide assumes familiarity with Tempo zones and Antithesis test scheduling.

The topology has a Tempo L1 node, three sequencers (`zone-0..2`, a 2-of-3 signing quorum),
and one RPC-only follower (`zone-rpc`): “all four nodes” means those four zone nodes.
Each `proxy-0..2` forwards its sequencer's L1 WebSocket and peer traffic, allowing the workload
to pause those links. The workload container submits transactions and checks their outcomes.

The ZonePortal contract on L1 records the leader and a monotonically increasing leadership
epoch (term). A handoff calls `setLeader` with the expected epoch; after one succeeds, a second
call using that old epoch reverts. The authorized admin can submit it directly or ask a zone
node to relay it through `zone_setLeader`. A zone block's Tempo anchor is the L1 block height used for its execution. A handoff event
names the new term's activation anchor: the L1 height from which that term applies. The successor
activates after importing the prior leader's required blocks through that boundary; an
L1-finalized handoff alone does not establish activation. A canary is a fresh probe transaction, and settlement means
its zone checkpoint is recorded on finalized L1.

The Dockerfile builds the nodes and provisioners with Antithesis [coverage instrumentation](https://antithesis.com/docs/reference/sdk/rust/instrumentation/)
(`--features antithesis-coverage` and its sancov `RUSTFLAGS`, in the `antithesis` profile: no LTO, one codegen unit)
and links them into `/symbols`. Coverage guides the exploration, and Antithesis only pauses threads in
instrumented processes. Outside Antithesis the shim finds no `libvoidstar` and does nothing.

Build the images from the repository root, with the contract submodules checked out:

```bash
docker build -f contrib/antithesis/zones/Dockerfile -t tempo-zones-antithesis:latest \
    --build-arg VERGEN_GIT_SHA="$(git rev-parse HEAD)" .
docker build -f contrib/antithesis/zones/Dockerfile --target workload -t tempo-zones-antithesis-workload:latest \
    --build-arg VERGEN_GIT_SHA="$(git rev-parse HEAD)" .
docker build -f contrib/antithesis/zones/Dockerfile.config -t tempo-zones-antithesis-config:latest contrib/antithesis/zones
```

Run it locally:

```bash
docker compose -f contrib/antithesis/zones/docker-compose.yaml up
```

`ZONES_IMAGE` overrides the image the L1, provisioner and zone nodes run, and `WORKLOAD_IMAGE` the
`workload` container's. The three transparent fault proxies use the uninstrumented workload
binary included in `ZONES_IMAGE`; they do not report node coverage.

## Antithesis registry

[`antithesis-zones.yml`](../../../.github/workflows/antithesis-zones.yml) builds the node, workload and config images on every push to `main`
that touches the node or this directory, and on a manual dispatch of any branch, and pushes them to
`us-central1-docker.pkg.dev/molten-verve-216720/tempo-repository` as `<branch>-<sha>` and `<branch>`. The
config image adds an `.env` that pins `ZONES_IMAGE` and `WORKLOAD_IMAGE` to the digests just built. It needs the registry's JSON
key in the `ANTITHESIS_REGISTRY_KEY` repository secret. The default profile mixes direct admin and node-relayed handoffs. Workflow input
`direct_handoffs=true` selects direct admin handoffs only; that build appends
`-direct` to both config tags so it cannot replace the default profile. The workflow logs and
summary publish the immutable config digest and the selected profile.

To check an already-published config without rebuilding, manually dispatch the same workflow with
`validate_config_digest` set to its `sha256:...` digest. It pulls the config and its pinned images
using the existing registry secret, then runs `snouty validate` to check startup and the test template.
This does not launch a paid Antithesis run.

## Test template

`test/v1/zone_payments` ships at `/opt/antithesis/test/v1` in the workload image only (the Dockerfile's
`workload` target), so only the `workload` container offers it. The test platform finds templates in the
images it is given, so they must be in the image rather than copied in when a container starts. Each command in the table below invokes a subcommand of `tempo-zones-antithesis` ([`xtask/zones-antithesis`](../../../xtask/zones-antithesis)), built without coverage instrumentation so only the nodes report coverage:

| Command | What it does |
|---|---|
| `first_seed` | Approves the portal for the L1 funders and funds the first zone accounts |
| `parallel_driver_deposit` | Deposits from a funder or a new L1 account to a new or existing zone account |
| `parallel_driver_transfer` | TIP-20 transfer inside the zone to a new or existing account |
| `parallel_driver_withdraw` | Withdraws to a new or existing L1 address |
| `parallel_driver_fanout` | Funds 5 to 20 new zone accounts from one sender |
| `parallel_driver_rotate_leader` | Hands leadership to another sequencer, through the admin or a zone node's `zone_setLeader` relay, then observes production and settlement if its term is not superseded |
| `serial_driver_single_sequencer_outage` | In a quiet window, checks availability during a non-leader crash or recovery after a crashed leader restarts, then catch-up and renewed quorum participation; leader recovery includes an explicit portal handoff |
| `serial_driver_quorum_loss_recovery` | Holds both followers down, proves a newly executed canary cannot settle at 1-of-3, then restores one follower and requires its fresh quorum participation |
| `serial_driver_handoff_campaign` | Rotates to a stopped, lagging successor, optionally returns A→B→A before B can activate, then requires fresh final-term settlement and exact predecessor preservation |
| `serial_driver_competing_handoffs` | Submits two durable admin requests for different successors at the same epoch, proves one succeeds and the stale request reverts, then requires fresh winner-term settlement |
| `serial_driver_asymmetric_handoff` | Gates the old leader's L1 connection and the successor's P2P traffic, proves signed transactions remain pending across the Portal handoff, then heals and requires fresh settlement |
| `serial_driver_recovery` | Pauses faults for 600 seconds, then proves a fresh canary settles on finalized L1 and all nodes preserve its receipt and the prior settled prefix within 300 seconds |
| `anytime_consistency` | Nodes that reached the height L1 settled agree on its hash and on balances there, settled workload transactions stay final, and every zone block comes from the leader the portal names at its Tempo anchor; reconciles persistent handoff history |
| `eventually_settled` | After faults stop, resolves every durable signed intent first, then every confirmed deposit is credited or refunded and every confirmed withdrawal is paid or returned, and all nodes converge |
| `finally_ledger` | The same, then compares independently expected principal effects from signed intents with exact bridge/token event multisets, and checks every workload account's balance against Transfer logs |

Half of all recipients are accounts nobody has used before, so the L1 and zone state tries keep
growing during a run. Account keys are hashes of their index, counting from 1000, and are
recorded in an append-only ledger in `/state`, which also holds a lock file per account so
only one command sends from an account at a time. Payment and direct admin-handoff drivers
durably journal signed transaction bytes before broadcasting, then record their exact
receipt outcome and confirmed deposit, withdrawal or transfer obligations. A killed driver or
ambiguous RPC error leaves a pending intent: reconciliation rebroadcasts the identical bytes and
never replaces the nonce or creates a second payment. Unknown intents cannot be omitted from
`eventually_settled`, even when a replay is rejected by one node: another node may already have
accepted the bytes. If the workload signs an invalid transaction that cannot be included,
diagnose and fix its generation rather than silently removing it from the inclusion check.
Terminal checks and serial episodes take an exclusive episode lock; payment drivers take a
shared lock before reconciliation, retaining their normal concurrency while excluding controlled
episodes. Antithesis scheduling also supplies a quiet window. Direct local invocations must stop
continuously launched writers so terminal checks can acquire the lock. Leadership requests and observed updates survive driver cancellation;
consistency and recovery check their history and activation boundaries.

### Mid-run recovery

`serial_driver_recovery` invokes the binary at `ANTITHESIS_STOP_FAULTS`, if nonempty, with `600`
seconds. The platform restores killed containers and network connectivity and resumes faults
automatically when the window expires. Locally, with the variable unset, the same check runs
without requesting a pause. There is no external-faults toggle.

After releasing any intentional holds (bounded separately), the recovery probe has one
300-second async deadline covering startup, reconciliation, sends and reads;
individual HTTP requests are also bounded. It first requires every configured node, including
the RPC-only follower, to answer and agree with a baseline portal settlement read at a single
**finalized L1 block hash**. After resolving old signed intents it journals a new canary before sending it. A lost send
reply is reconciled by that exact transaction ID and bytes, never a replacement canary.
Success requires a newer finalized portal settlement at or beyond that canary, the portal's
exact block hash on every node at that same checkpoint, the unchanged baseline prefix, and the
canary's unchanged successful receipt/block hash everywhere. The producer must be the eligible
leader at the zone block's L1 anchor. The settled checkpoint must also anchor at or beyond
the baseline L1 height: old-leader catch-up below that anchor is not recovery progress. The
canary itself may precede that anchor; a superseded intermediate leader need not produce.
Agreement on an old tip, an unfinalized settlement, a missing follower, an error or a timeout
cannot pass. Cancellation of the probe leaves its signed canary in the journal for the next
reconciliation; the platform quiet window still expires automatically.

Run a command against the local stack the way the platform does:

```bash
docker compose -f contrib/antithesis/zones/docker-compose.yaml exec workload \
    /opt/antithesis/test/v1/zone_payments/first_seed
```

## Zone-only faults

Run `bash contrib/antithesis/zones/launch.sh CONFIG_IMAGE@sha256:DIGEST COMPUTE_HOURS`
to print the exact launch command. Add `--launch` only after approving its paid compute budget.
The script requires a digest-pinned config and uses the `custom_faults` launcher. It sends
only a compute budget and a five-minute setup timeout, never a duration as well. Confirm
that the deployed custom launcher supports the budget and its billing/teardown semantics
before submitting: CLI validation alone does not prove a hard spending cap. Inspect accepted
settings and actual usage, and do not reuse an earlier run's approval.

Only `zone-0`, `zone-1` and `zone-2` are selected for container termination; the explicit node
allowlist excludes the proxies. Network faults, node hangs, node throttling, clock jitter and
CPU modulation are disabled in the focused profile.

With `--network-faults`, both sequencers and proxies are eligible for network faults. Keeping
proxies in the global fault exclusions could shield their sequencer links too. Tempo `l1`, the
provisioner, workload and RPC-only follower remain excluded. Eligible sequencer/proxy hops carry
both P2P and quorum L1 traffic, not just P2P; faults there can also delay the RPC follower's
replication through a proxy. File-based fault controls do not traverse those links. These selectors
request fault scope, not proof of packet loss: verify the custom launcher's accepted settings and
actual fault events in each run. Quiet serial episodes still suspend unrelated platform faults
while checking their controlled cases.
The custom launcher reports `legacy` internally; do not pass `antithesis.fault_tolerance`.
Machine-wide thread pausing cannot be excluded per container. Target selection does not enforce
one simultaneous failure across different nodes; the controlled probe below does.

No service has a Compose restart policy: Antithesis owns recovery from platform container
termination. An unconditional restart policy could bring a killed container back prematurely.

## Controlled single-sequencer outage

The serial outage driver first requests a 1,800-second platform quiet window. Its Rust episode
has a 1,200-second deadline, with a 1,500-second process timeout as a backstop. During this
window a test-only supervisor SIGKILLs and reaps the selected `tempo-zone` process, retains its
datadir, and holds it down until the workload requests a restart. This is a **process crash**,
not a container restart: container/network namespace and supervisor remain alive. Outside the
probe, the launcher independently exercises real zone-container termination.

The shared `/fault-control` volume carries only commands and generation-matched acknowledgements;
it is not evidence of replication, recovery or settlement. Only the workload, three sequencer containers and three test-only proxy containers mount it. No Docker socket or production RPC control endpoint is exposed. The
supervisor exits on an unexpected child failure rather than hiding crashes in a restart loop.
An abandoned intentional hold expires after 180 seconds; an early expiry cannot pass an outage
assertion. Terminal checks release outstanding holds after a cancelled driver.

Before choosing a victim, the probe drains previously submitted handoffs to canonical,
finalized receipts, including reverted transactions and signed admin intents whose driver died
before recording a handoff request. Tempo relay receipts use their own transaction type;
receipt checks accept that type without relaxing canonical-block or finality validation. A
relay's reverted-transaction error preserves its transaction ID for that same receipt barrier.
A connection refusal before any HTTP submission is a definitive rejection; automatic HTTP retries
and redirects are disabled so this classification cannot hide an earlier send. A lost reply, client timeout or confirmation timeout without a transaction ID cannot be proved
quiescent: every later episode on that timeline remains inconclusive before any kill, without
reporting availability or recovery success. Neither an unrelated same-target event nor equal
pending/finalized nonce observations prove that a delayed submission cannot still arrive.
Report actual completed-case coverage separately from these skipped episodes.

Before starting an outage, every zone node must have imported a block from the current
finalized portal leader at or beyond the activation anchor of that leadership term. L1 finality alone is not proof of
activation: the outgoing leader can still be producing pre-activation blocks. The workload
rechecks portal membership after observing the zone tips.

The two cases have different progress requirements:

- **Non-leader availability (`--case backup`):** the leader stays alive. A new canary must be
  signed after the victim is confirmed down and finalized on L1 while it remains down. After
  restart, the victim must catch up to that exact finalized checkpoint and canary receipt.
- **Leader restart recovery (`--case leader`):** the leader is killed, then an explicit admin
  handoff to a surviving sequencer finalizes while the old leader stays down. The old leader
  is restored before a new canary is signed. Fresh settlement and all-node receipt/hash
  agreement are required after restart, not while the leader is down.

Each case has independent episode, phase and reachability properties. Neither claims automatic
leader election. RPC readiness or agreement on an old tip alone cannot satisfy recovery.

To prove that the recovered sequencer attests again, the test then holds the other backup down
and creates another fresh canary. The configured signer set and 2-of-3 threshold must remain
unchanged. Finalizing this canary with only the leader and recovered sequencer alive requires
both to sign; a certificate produced before this second outage cannot contain the new canary.
The other backup is restored and all-node convergence is checked before returning. All waits
are bounded; timeouts, premature restarts and changed quorum/leadership fail the check.

**Scope:** this tests uninterrupted availability for a non-leader crash, but only recovery
following restart for a leader crash. Ordinary handoff can wait for the outgoing leader's
pre-activation block even after `setLeader` finalizes; restoring that leader lets it supply
that block before the successor activates. The probe does not require uninterrupted service
while the leader is stopped. The [operator forced-recovery procedure](../../../crates/zones/p2p/README.md) is a different scenario
and is not implemented by this probe.

Run the local harness fixtures without contacting Antithesis:

```bash
bash contrib/antithesis/zones/tests/test-launch.sh
bash contrib/antithesis/zones/tests/test-compose.sh
bash contrib/antithesis/zones/tests/test-config-profile.sh
bash contrib/antithesis/zones/tests/test-zone-supervisor.sh
cargo test -p tempo-zones-antithesis --locked
```

Against the local Compose stack, seed accounts once, then exercise both cases explicitly:

```bash
docker compose -f contrib/antithesis/zones/docker-compose.yaml exec -T workload tempo-zones-antithesis seed
docker compose -f contrib/antithesis/zones/docker-compose.yaml exec -T workload tempo-zones-antithesis single-sequencer-outage --case backup
docker compose -f contrib/antithesis/zones/docker-compose.yaml exec -T workload tempo-zones-antithesis single-sequencer-outage --case leader
```

Omitting `--case` lets Antithesis choose through SDK randomness. The global `--fault-control-dir`
option (`FAULT_CONTROL_DIR`) selects the workload's control path; supervisors use
`ZONE_FAULT_CONTROL_DIR`. Both default to `/fault-control`. Do not shorten the supervisor's
180-second hold watchdog below the workload's 150-second held-down deadline in a real run.

## Controlled quorum and overlapping handoffs

The quorum-loss and handoff-campaign commands request the same 1,800-second quiet window and use a 1,500-second
process backstop. Their internal deadlines include restart readiness, catch-up and settlement;
reaching the new term or becoming RPC-ready is an outcome, not a condition for starting the
recovery clock. Each executed episode has an `always` completion check and independent
reachability properties. A pre-fault skip is not successful case coverage.

- `quorum-loss-recovery` keeps the leader healthy and holds **both** followers down. It signs
  a fresh canary after both matching DOWN acknowledgements, requires execution, and checks
  that neither latest nor finalized L1 settlement includes that canary during the observation
  interval. Old certificates may legitimately settle older batches. It restores one follower
  while the other remains held, then requires exact canary settlement with unchanged 2-of-3
  membership. This forces a fresh signature from the restarted follower. Finally it releases
  both holds and checks all four nodes' receipts and the canonical prefix.
- `handoff-campaign --case lagging-successor` holds B down while A creates a durable tail,
  submits another signed canary without waiting for inclusion, and finalizes A→B. A fast
  leader may include that transaction before the handoff; this does not guarantee a transaction
  remains in flight across activation. It restores B and
  requires a fresh B-term canary to settle, with predecessor and in-flight receipts intact.
- `handoff-campaign --case overlapping-handoffs` adds B→A before B is restarted. There is no
  independent fresh-work demand for superseded B, but B must still supply any missing blocks
  in its historical activation interval. The final stable A term must make fresh progress
  and preserve the prefix. The old leader remains available to provide its legitimate tail.

For a focused campaign, build the config with workflow input `direct_handoffs=true` (locally,
`ZONE_HANDOFF_DIRECT_ONLY=true`). This pins the workload's random rotation driver to durable
signed admin transactions so a lost relay reply cannot make every subsequent controlled
case inconclusive. The default is `false`, retaining relay coverage. This does not clear old
unknown requests: use fresh state for a new profile. Direct local callers can also pass
`rotate-leader --direct-only`.

These scenarios complement the existing leader crash/restart probe and randomized platform
faults. They do not inject a crash at an exact persistence instruction or implement operator
forced recovery when a predecessor prefix never existed. Do not interpret them as proof of
those scenarios or as automatic leader election. Use fresh genesis/state and a baseline containing the [checkpoint metering fix](https://github.com/tempoxyz/tempo/pull/9273)
for the T14 Tempo protocol fork; historical pre-T14 gas behavior is deliberately unchanged.


## Competing same-epoch handoffs

`competing-handoffs` acquires the exclusive episode lock and drains prior handoffs before
signing the two other configured sequencers from membership and epoch reads pinned to one L1 block hash.
Both admin transactions are journaled before either is broadcast. They use consecutive nonces
from one sender, so nonce order determines the winner: this tests stale-epoch fencing, not a
race between independently authorized senders.

The first exact transaction must succeed and the second must revert without a leadership event.
Both receipts must be canonical and finalized, and the winning event must match the signed
request. Recovery then requires all four nodes to reach the winning term and preserve the
baseline while a fresh winner-term canary settles. It also records the existing coverage assertion that two different targets were requested at
the same epoch. A prior relay whose submission outcome cannot be determined prevents the
episode from starting or signing; an error after the episode is admitted is a failure, never a skip.

Run it after `seed`:

```bash
docker compose -f contrib/antithesis/zones/docker-compose.yaml exec -T workload tempo-zones-antithesis competing-handoffs
```

The competing-handoffs template requests a 1,500-second quiet window and uses a 1,300-second process backstop.
The whole Rust episode is bounded by 1,200 seconds; submission/finality and final-term recovery
each have a 180-second deadline.

## Asymmetric handoff with pending traffic

`asymmetric-handoff` combines two different views of the same transition without killing either
sequencer. It holds the exclusive episode lock so rotation and terminal reconciliation cannot
silently release the deliberately withheld transaction. Run it after `seed`:

```bash
docker compose -f contrib/antithesis/zones/docker-compose.yaml exec -T workload tempo-zones-antithesis asymmetric-handoff
```

1. Label the current leader A, its chosen successor B, and the remaining sequencer C.
   Block B's P2P traffic and settle new A-term blocks (the predecessor tail) through A+C.
2. While A's L1 connection is still open, sign and durably journal four consecutive transactions
   from a reused funded account. Keep the sender's exclusive account lease and withhold every broadcast. Then block
   A's L1 connection, retain nonce `n`, and submit only `n+1..n+3` through different ingress nodes. The nonce
   gap prevents execution; exact hash/sender/nonce RPC observations must show pending entries
   both before and after the journaled A→B Portal transition finalizes.
3. Read the nodes themselves: A must still observe the old leadership epoch and apply an
   L1 anchor older than the transition, while B must observe the new epoch but lack the predecessor tail. Proxy acknowledgements alone do not prove either
   condition, and the finalized Portal event does not claim B has activated.
4. Heal both gates, release the account lease and reconcile the identical signed transactions,
   including nonce `n`. Within one recovery deadline, require all-node receipt agreement,
   preservation of the settled predecessor prefix, and a fresh final-term canary settled on L1.

The proxies pause real TCP traffic on existing and new connections; they never synthesize node
responses. P2P gates cover both the source and destination sequencer. Bytes already queued in
OS/network buffers can arrive after a gate acknowledgement, hence the separate node-state
witnesses. Test nodes bypass the P2P source-IP check because the proxy rewrites that IP;
cryptographic peer authentication remains enabled. Use **fresh shared volumes** so provisioning
writes the proxy addresses into the peer manifest.

Controls use unique generations, per-proxy boot identities, fresh acknowledgements and absolute
expiry plus an independent 180-second monotonic watchdog. Normal exit/cancellation releases the
gates; terminal checks and subsequent controlled episodes also release abandoned holds. Early
expiry, stale acknowledgements or a restarted proxy cannot prove a held condition. Unobserved
pending traffic is explicitly inconclusive, not a passing asymmetric episode; recovery is still
required. The template requests a 1,800-second platform quiet window and has a 1,500-second process
backstop, while the Rust episode and each held/recovery phase have shorter deadlines.

Errors identify the preparation, held-fault or recovery stage. If a held stage fails, bounded
cleanup still releases the gates and reconciles durable work, but the episode retains its original
failure. The full exact-receipt/fresh-settlement recovery proof is reported as not run when the held
stage did not produce its required evidence; cleanup alone cannot satisfy it.

## Independent principal-effect checks

`finally_ledger` retains the balance-versus-Transfer-log check and adds a different oracle:
expected payment principal comes from the durable signed intent, not from summing the same logs
being tested. It compares complete multisets, retaining duplicate events rather than overwriting
them in a map. Checks cover deposit credit versus refund exclusivity, transfer recipient/amount,
withdrawal payouts or returns, and the corresponding mint/burn/portal token movements. Withdrawal
sender tags and deposit queue IDs identify obligations; indistinguishable refund events are
checked as per-sender multisets, not falsely attributed to individual identical payments.

Gas charges use the receipt's fee token and payer, with the amount derived from gas used and
price; bridge fees use explicit protocol events. Fee-token selection, gas execution and escrow
storage are not independently verified. Reverted or unknown intents
are not required to have successful payment effects. Canonical-but-unsettled receipt hashes are
not assumed immutable. Terminal checks require quiescent drivers and reconcile first; the new
oracle is bounded by both a history-size limit and a 300-second deadline and never samples away
extra history. Unit mutations exercise missing, duplicate and wrong-value effects as well as
valid fees, bounces and refunds.
